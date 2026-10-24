# ============================================================================
# ALPHA SENTINEL - dashboard account manager
# ============================================================================
# Creates and maintains the accounts AlphaSentinel uses for the dashboard login.
# Accounts live in sentinel-users.json next to the script, stored as PBKDF2
# (per-user 16-byte salt, 150000 iterations) - only salt, hash and iteration
# count are written. A plaintext password is NEVER written to disk by anything.
#
#   .\New-SentinelAdmin.ps1                            # create "admin", random password
#   .\New-SentinelAdmin.ps1 -Username maty             # your own username, random password
#   .\New-SentinelAdmin.ps1 -Username maty -Reset      # new random password for an existing user
#   .\New-SentinelAdmin.ps1 -Username maty -PromptPassword   # type your own (min 12 chars)
#   .\New-SentinelAdmin.ps1 -Username maty -Password '...'   # non-interactive (min 12 chars)
#   .\New-SentinelAdmin.ps1 -List                      # usernames + created date
#   .\New-SentinelAdmin.ps1 -Username maty -Remove     # delete an account
#
# The generated password is printed ONCE. Save it in your password manager
# before closing the window; it cannot be recovered from the file afterwards
# (that is the point) - use -Reset to set a new one.
#
# The ACL on sentinel-users.json is set so only Administrators and SYSTEM can
# read it, which is why this tool is best run from an elevated prompt.
# ============================================================================

[CmdletBinding()]
param(
  [string]$Username = '',
  [switch]$Reset,
  [switch]$PromptPassword,
  [switch]$List,
  [switch]$Remove,
  [string]$UsersFile = '',
  [int]$Iterations = 150000,
  [int]$Length = 20,
  [string]$Password = ''
)

$ErrorActionPreference = 'Stop'

if (-not $UsersFile) {
  $UsersFile = if ($PSScriptRoot) { Join-Path $PSScriptRoot 'sentinel-users.json' } else { 'sentinel-users.json' }
}

# ============================================================================
# CREDENTIALS (shared format with AlphaSentinel.ps1)
# ============================================================================
# AlphaSentinel.ps1 carries the same four functions. The record format - hex
# salt, hex hash, iteration count, PBKDF2-HMAC-SHA1 - has to match exactly, or a
# password written here will not verify there. The test suite cross-checks a
# hash written by this file against the verifier in AlphaSentinel.ps1.
function ConvertTo-Hex([byte[]]$Bytes) {
  return (($Bytes | ForEach-Object { $_.ToString('x2') }) -join '')
}

function ConvertFrom-Hex([string]$Hex) {
  if (-not $Hex) { return $null }
  $clean = "$Hex" -replace '[^0-9a-fA-F]', ''
  if ($clean.Length -eq 0 -or ($clean.Length % 2) -ne 0) { return $null }
  $bytes = New-Object byte[] ($clean.Length / 2)
  for ($i = 0; $i -lt $bytes.Length; $i++) {
    $bytes[$i] = [Convert]::ToByte($clean.Substring($i * 2, 2), 16)
  }
  return $bytes
}

# (string, byte[], int) is the Rfc2898DeriveBytes overload that exists on
# .NET 4.x; the HashAlgorithmName overloads need 4.7.2+ and would throw on
# Server 2012 R2.
function Get-PasswordHash([string]$Password, [byte[]]$Salt, [int]$Iterations) {
  # New-Object rather than [Type]::new(): ::new() is PowerShell 5.0+ syntax and
  # this has to run on anything from 5.1 up. Same constructor, same output -
  # pinned by the RFC 6070 vectors in the test suite.
  $kdf = New-Object -TypeName System.Security.Cryptography.Rfc2898DeriveBytes -ArgumentList @([string]$Password, [byte[]]$Salt, [int]$Iterations)
  try { return $kdf.GetBytes(32) } finally { $kdf.Dispose() }
}

function New-PasswordSalt {
  $salt = New-Object byte[] 16
  $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
  try { $rng.GetBytes($salt) } finally { $rng.Dispose() }
  return $salt
}

# ============================================================================
# PASSWORD GENERATION
# ============================================================================
# Uniform index from the CSPRNG. Plain modulo would bias the first characters
# when the range does not divide 256 evenly, so values from the ragged top of
# the byte range are rejected and redrawn.
function Get-CryptoIndex($Rng, [int]$ExclusiveMax) {
  if ($ExclusiveMax -le 1) { return 0 }
  $limit = [int][Math]::Floor(256.0 / $ExclusiveMax) * $ExclusiveMax
  $one = New-Object byte[] 1
  while ($true) {
    $Rng.GetBytes($one)
    if ([int]$one[0] -lt $limit) { return ([int]$one[0] % $ExclusiveMax) }
  }
}

function New-RandomPassword([int]$Length = 20) {
  # These get read off a console and typed by hand, so every glyph that is
  # ambiguous in common fonts is left out - in BOTH cases, because O vs o and
  # I vs l are the same shape at a glance: 0, O, o, 1, I, l, i.
  # The symbol set deliberately omits the ones that fight with the shell
  # ($, backtick, quotes, backslash).
  $upper   = 'ABCDEFGHJKLMNPQRSTUVWXYZ'      # no I, no O
  $lower   = 'abcdefghjkmnpqrstuvwxyz'       # no i, no l, no o
  $digits  = '23456789'                      # no 0, no 1
  $symbols = '!@#%^&*()-_=+[]{}:,.?'
  $all     = $upper + $lower + $digits + $symbols
  if ($Length -lt 4) { $Length = 4 }

  $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
  try {
    # one from each class first, so the mix is guaranteed whatever happens next
    $chars = New-Object System.Collections.ArrayList
    foreach ($set in @($upper, $lower, $digits, $symbols)) {
      [void]$chars.Add($set[(Get-CryptoIndex $rng $set.Length)])
    }
    while ($chars.Count -lt $Length) {
      [void]$chars.Add($all[(Get-CryptoIndex $rng $all.Length)])
    }
    # Fisher-Yates, again from the CSPRNG: without this the first four positions
    # would always be one-of-each in a fixed order
    for ($i = $chars.Count - 1; $i -gt 0; $i--) {
      $j = Get-CryptoIndex $rng ($i + 1)
      $tmp = $chars[$i]
      $chars[$i] = $chars[$j]
      $chars[$j] = $tmp
    }
    return (-join $chars)
  } finally { $rng.Dispose() }
}

# ============================================================================
# USER STORE
# ============================================================================
function Read-UserStore {
  if (-not (Test-Path $UsersFile)) {
    return [PSCustomObject]@{ version = 1; users = @() }
  }
  try {
    $raw = Get-Content -Raw $UsersFile
    if (-not $raw) { return [PSCustomObject]@{ version = 1; users = @() } }
    $store = $raw | ConvertFrom-Json
    if (-not $store.users) { $store = [PSCustomObject]@{ version = 1; users = @() } }
    return $store
  } catch {
    throw "could not read $UsersFile ($($_.Exception.Message)). Fix or delete it and run again."
  }
}

function Find-User($Store, [string]$Name) {
  if (-not $Store -or -not $Store.users) { return $null }
  foreach ($u in @($Store.users)) {
    if ("$($u.user)" -eq $Name) { return $u }
  }
  return $null
}

function Save-UserStore($Store) {
  # ASCII content, UTF-8 with BOM - same encoding rule as the scripts.
  $json = $Store | ConvertTo-Json -Depth 5
  $utf8Bom = New-Object System.Text.UTF8Encoding($true)
  [System.IO.File]::WriteAllText($UsersFile, $json, $utf8Bom)
}

# Only Administrators (S-1-5-32-544) and SYSTEM (S-1-5-18) may read the file.
# SIDs are used rather than names because "Administrators" is localised on
# non-English Windows. Not fatal if it fails (a non-elevated run), but it is
# reported loudly.
function Set-UserFileAcl([string]$Path) {
  try {
    $acl = Get-Acl -Path $Path
    $acl.SetAccessRuleProtection($true, $false)   # stop inheriting, drop inherited
    foreach ($rule in @($acl.Access)) { [void]$acl.RemoveAccessRule($rule) }

    $adminSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $systemSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
    $inherit = [System.Security.AccessControl.InheritanceFlags]'None'
    $prop = [System.Security.AccessControl.PropagationFlags]'None'
    $allow = [System.Security.AccessControl.AccessControlType]'Allow'
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($adminSid, 'FullControl', $inherit, $prop, $allow)))
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($systemSid, 'FullControl', $inherit, $prop, $allow)))
    Set-Acl -Path $Path -AclObject $acl
    return $true
  } catch {
    Write-Warning "could not tighten the ACL on $Path ($($_.Exception.Message)). Re-run this script from an elevated prompt."
    return $false
  }
}

function Read-ConfirmedPassword([string]$Name) {
  while ($true) {
    $secure = Read-Host -AsSecureString "New password for '$Name' (min 12 characters)"
    $confirm = Read-Host -AsSecureString "Repeat the password"
    $plain = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
    $again = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($confirm))
    if ($plain.Length -lt 12) {
      Write-Host "  too short - use at least 12 characters." -ForegroundColor Yellow
      continue
    }
    if ($plain -ne $again) {
      Write-Host "  the two entries did not match - try again." -ForegroundColor Yellow
      continue
    }
    return $plain
  }
}

# ============================================================================
# MAIN
# ============================================================================
Write-Host ""
Write-Host "  ALPHA SENTINEL - dashboard accounts" -ForegroundColor Red
Write-Host "  file: $UsersFile"
Write-Host ""

$store = Read-UserStore

if ($List) {
  $users = @($store.users)
  if ($users.Count -eq 0) {
    Write-Host "  no accounts yet - create one with:  .\New-SentinelAdmin.ps1" -ForegroundColor Yellow
  } else {
    Write-Host ("  {0,-24} {1,-22} {2}" -f 'USERNAME', 'CREATED (UTC)', 'ITERATIONS')
    foreach ($u in $users) {
      $created = "$($u.created)"
      if (-not $created) { $created = 'unknown' }
      Write-Host ("  {0,-24} {1,-22} {2}" -f "$($u.user)", $created, "$($u.iterations)")
    }
    Write-Host ""
    Write-Host "  (hashes are never printed - reset a password with -Reset instead)" -ForegroundColor DarkGray
  }
  Write-Host ""
  exit 0
}

if (-not $Username) { $Username = 'admin' }

if ($Username -notmatch '^[A-Za-z0-9._-]{1,32}$') {
  Write-Host "  invalid username '$Username' - use 1-32 characters from letters, digits, dot, underscore or dash." -ForegroundColor Red
  exit 1
}

$existing = Find-User $store $Username

if ($Remove) {
  if (-not $existing) {
    Write-Host "  no such user: $Username" -ForegroundColor Yellow
    exit 1
  }
  $kept = @(@($store.users) | Where-Object { "$($_.user)" -ne $Username })
  $store = [PSCustomObject]@{ version = 1; users = @($kept) }
  Save-UserStore $store
  [void](Set-UserFileAcl $UsersFile)
  Write-Host "  removed account '$Username'." -ForegroundColor Green
  Write-Host ""
  exit 0
}

if ($existing -and -not $Reset) {
  Write-Host "  account '$Username' already exists - refusing to overwrite." -ForegroundColor Yellow
  Write-Host "  use -Reset to set a new password, -List to see the accounts, or -Remove to delete it." -ForegroundColor Yellow
  Write-Host ""
  exit 1
}

$generated = $false
$plain = $null
if ($Password) {
  # Non-interactive mode: password passed via parameter
  $plain = $Password
  if ($plain.Length -lt 12) {
    Write-Host "  password must be at least 12 characters long." -ForegroundColor Red
    exit 1
  }
} elseif ($PromptPassword) {
  $plain = Read-ConfirmedPassword $Username
} else {
  $plain = New-RandomPassword $Length
  $generated = $true
}

$salt = New-PasswordSalt
$hash = Get-PasswordHash $plain $salt $Iterations
$now = (Get-Date).ToUniversalTime().ToString("o")

$record = [PSCustomObject]@{
  user       = $Username
  salt       = (ConvertTo-Hex $salt)
  hash       = (ConvertTo-Hex $hash)
  iterations = $Iterations
  created    = if ($existing -and "$($existing.created)") { "$($existing.created)" } else { $now }
  updated    = $now
}

$others = @(@($store.users) | Where-Object { "$($_.user)" -ne $Username })
$store = [PSCustomObject]@{ version = 1; users = @(@($record) + $others) }
Save-UserStore $store
$aclOk = Set-UserFileAcl $UsersFile

Write-Host ""
if ($existing) {
  Write-Host "  password RESET for '$Username'." -ForegroundColor Green
} else {
  Write-Host "  account '$Username' created." -ForegroundColor Green
}
Write-Host "  stored as PBKDF2-HMAC-SHA1, $Iterations iterations, 16-byte salt (no plaintext is stored)." -ForegroundColor DarkGray
if ($aclOk) {
  Write-Host "  ACL set: only Administrators and SYSTEM can read the file." -ForegroundColor DarkGray
}
Write-Host ""

if ($generated) {
  Write-Host "  ============================================================" -ForegroundColor Yellow
  Write-Host "   PASSWORD (shown once - save it now, it is not recoverable):" -ForegroundColor Yellow
  Write-Host ""
  Write-Host "     $plain" -ForegroundColor White
  Write-Host ""
  Write-Host "  ============================================================" -ForegroundColor Yellow
  Write-Host "   Sign in at http://localhost:8443 with user '$Username'." -ForegroundColor Yellow
  Write-Host "   Lost it later? .\New-SentinelAdmin.ps1 -Username $Username -Reset" -ForegroundColor DarkGray
} else {
  Write-Host "  sign in at http://localhost:8443 with user '$Username'." -ForegroundColor DarkGray
}
Write-Host ""
