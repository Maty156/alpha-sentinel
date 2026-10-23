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
        return [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    }
    
    $p1 = Convert-SSToPlain $adminPass1
    $p2 = Convert-SSToPlain $adminPass2
    
    if ($p1 -ne $p2) {
        Write-Host "Passwords do not match." -ForegroundColor Red
        exit 1
    }
    
    if ($p1.Length -lt 12) {
        Write-Host "Password must be at least 12 characters long." -ForegroundColor Red
        exit 1
    }
    
    # Create the users file with PBKDF2 hash
    $iterations = 150000
    $salt = New-Object byte[] 16
    [System.Security.Cryptography.RandomNumberGenerator]::GetBytes($salt) | Out-Null
    $kdf = New-Object System.Security.Cryptography.Rfc2898DeriveBytes -ArgumentList @($p1, $salt, $iterations)
    $hashBytes = $kdf.GetBytes(32)
    $kdf.Dispose()
    $saltHex = ($salt | ForEach-Object { $_.ToString('x2') }) -join ''
    $hashHex = ($hashBytes | ForEach-Object { $_.ToString('x2') }) -join ''
    $now = (Get-Date).ToUniversalTime().ToString("o")
    $usersJson = @{
        version = 1
        users = @(
            @{
                user = $adminName
                salt = $saltHex
                hash = $hashHex
                iterations = $iterations
                created = $now
                updated = $now
                avatarColor = ''
                avatarInitials = ''
            }
        )
    } | ConvertTo-Json -Depth 5
    $utf8Bom = New-Object System.Text.UTF8Encoding($true)
    [System.IO.File]::WriteAllText($usersFile, $usersJson, $utf8Bom)
    Write-Host ""
    Write-Host "Administrator account created successfully!" -ForegroundColor Green
    Write-Host "Username: $adminName" -ForegroundColor DarkGray
    Write-Host "Password: [saved securely]" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "The main monitor will now start..." -ForegroundColor Cyan
    Write-Host ""
} else {
    # Users file exists - just start the monitor
    Write-Host "Starting Alpha Sentinel monitor..." -ForegroundColor Cyan
    Write-Host ""
}

# Now launch the main monitor
Write-Host "Launching Alpha Sentinel v2.5.0 monitor..." -ForegroundColor White
Write-Host "================================================" -ForegroundColor White

# Launch the main script - use -NoProfile to avoid loading user profiles
# and -ExecutionPolicy Bypass
$process = Start-Process -FilePath 'powershell.exe' -ArgumentList "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $scriptFile -PassThru -WindowStyle Hidden

Write-Host "Alpha Sentinel process started with PID: $($process.Id)" -ForegroundColor DarkGray
Write-Host "Check the process is running: Get-Process -Id $process.Id" -ForegroundColor DarkGray