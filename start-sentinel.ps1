<#
.SYNOPSIS  Alpha Sentinel entry point with admin credential collection
# This wrapper prompts for admin username/password on first run, creates the
# config, then launches the main monitor script.
# Place this file alongside AlphaSentinel.ps1 and run: powershell -File .\start-sentinel.ps1
#--------------------------------------------------------------------------------#
#>
# Configuration paths
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$scriptFile = Join-Path $scriptDir 'AlphaSentinel.ps1'
$usersFile = Join-Path $scriptDir 'sentinel-users.json'
$adminBackup = Join-Path $scriptDir 'sentinel-audit-backup-*.csv'

# Read the real version from AlphaSentinel.ps1
$alphaRaw = Get-Content -Raw $scriptFile
if ($alphaRaw -match '\$Script:SentinelVersion\s*=\s*''([^'']+)''') {
    $sentinelVersion = $matches[1]
} else {
    $sentinelVersion = '2.6.0'
}

# Check if this is first run (no users file)
if (-not (Test-Path $usersFile)) {
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host "  ALPHA Sentinel - First Run Setup" -ForegroundColor Cyan
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "This is your first time running Alpha Sentinel."
    Write-Host "We need to create an administrator account."
    Write-Host ""

    # Prompt for username
    $adminName = Read-Host -Prompt "Enter administrator username (3-32 chars, A-Z a-z 0-9 . _ -)"

    # Validate username format
    if ($adminName -notmatch '^[A-Za-z0-9._-]{3,32}$') {
        Write-Host "Invalid username format. Must be 3-32 characters of A-Z, a-z, 0-9, dot, underscore, or hyphen." -ForegroundColor Red
        exit 1
    }

    # Prompt for password (twice)
    $adminPass1 = Read-Host -AsSecureString -Prompt "Enter administrator password (minimum 12 characters)"
    $adminPass2 = Read-Host -AsSecureString -Prompt "Confirm administrator password"

    # Compare passwords using SecureString-to-plain conversion
    function Convert-SSToPlain {
        param([System.Security.SecureString]$ss)
        if (-not $ss) { return '' }
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($ss)
        try {
            return [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
        } finally {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
    }

    $p1 = Convert-SSToPlain $adminPass1
    $p2 = Convert-SSToPlain $adminPass2

    # Zero the SecureStrings
    $adminPass1.Dispose()
    $adminPass2.Dispose()

    if ($p1 -ne $p2) {
        Write-Host "Passwords do not match." -ForegroundColor Red
        exit 1
    }

    if ($p1.Length -lt 12) {
        Write-Host "Password must be at least 12 characters long." -ForegroundColor Red
        exit 1
    }

    # Delegate account creation to New-SentinelAdmin.ps1 so the hash format can never drift
    $adminScript = Join-Path $scriptDir 'New-SentinelAdmin.ps1'
    $result = & $adminScript -Username $adminName -PromptPassword -UsersFile $usersFile -Password $p1 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Failed to create administrator account:" -ForegroundColor Red
        Write-Host $result -ForegroundColor Red
        exit 1
    }

    # Zero the plaintext password strings
    $p1 = $null
    $p2 = $null
    [GC]::Collect()

    Write-Host ""
    Write-Host "The main monitor will now start..." -ForegroundColor Cyan
    Write-Host ""
} else {
    # Users file exists - just start the monitor
    Write-Host "Starting Alpha Sentinel monitor..." -ForegroundColor Cyan
    Write-Host ""
}

# Now launch the main monitor
Write-Host "Launching Alpha Sentinel v$sentinelVersion monitor..." -ForegroundColor White
Write-Host "=================================================" -ForegroundColor White

# Launch the main script - use -NoProfile to avoid loading user profiles
# and -ExecutionPolicy Bypass. Every argument given to this wrapper is forwarded.
$fwd = @($args)
$argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"' + $scriptFile + '"'))
foreach ($a in $fwd) {
    if ("$a" -match '\s') { $argList += ('"' + $a + '"') } else { $argList += "$a" }
}
$process = Start-Process -FilePath 'powershell.exe' -ArgumentList $argList -PassThru -WindowStyle Hidden

Write-Host "Alpha Sentinel process started with PID: $($process.Id)" -ForegroundColor DarkGray
Write-Host "Check the process is running: Get-Process -Id $($process.Id)" -ForegroundColor DarkGray

# Print dashboard URL
$bind = 'localhost'
$port = 8443
for ($i = 0; $i -lt $fwd.Count; $i++) {
    if ("$($fwd[$i])" -eq '-Bind' -and ($i + 1) -lt $fwd.Count) { $bind = "$($fwd[$i + 1])" }
    if ("$($fwd[$i])" -eq '-Port' -and ($i + 1) -lt $fwd.Count) { $port = [int]$fwd[$i + 1] }
}
$dispBind = if ($bind -eq '0.0.0.0' -or $bind -eq '+' -or $bind -eq '*') { '0.0.0.0' } else { 'localhost' }
Write-Host "Dashboard: http://${dispBind}:$port" -ForegroundColor Cyan
