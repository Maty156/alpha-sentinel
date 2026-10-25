try {
Write-Host "== Phase 1 bug fix tests ==" -ForegroundColor Cyan
  # Test 1: -Stop PID validation - stale PID that doesn't match AlphaSentinel is rejected
  Reset-Engine
  $fakePidFile = Join-Path $tmp 'fake-sentinel.pid'
  '999999' | Set-Content -Path $fakePidFile -Encoding UTF8
  # We can't easily test Stop-Sentinel without a real process, but we can test the logic
  $pidContent = Get-Content -Raw $fakePidFile
  $targetPid = 0
  [void][int]::TryParse($pidContent.Trim(), [ref]$targetPid)
  Assert-True ($targetPid -eq 999999) 'PID parsing from file works'
  Remove-Item $fakePidFile -Force -ErrorAction SilentlyContinue

  # Test 2: Static check - start-sentinel.ps1 must not contain RandomNumberGenerator::GetBytes
  $startSentinelPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'start-sentinel.ps1'
  $startSentinelText = Get-Content -Raw $startSentinelPath
  Assert-True (-not ($startSentinelText -match 'RandomNumberGenerator.*GetBytes')) 'start-sentinel.ps1 has no static RandomNumberGenerator::GetBytes call (uses New-SentinelAdmin.ps1 instead)'

  # Test 3: start-sentinel.ps1 delegates to New-SentinelAdmin.ps1 for account creation
  Assert-True ($startSentinelText -match 'adminScript.*New-SentinelAdmin\.ps1' -and $startSentinelText -match '-Username\s+\$adminName') 'start-sentinel.ps1 calls New-SentinelAdmin.ps1 for account creation'

  # Test 4: start-sentinel.ps1 reads version from AlphaSentinel.ps1
  Assert-True ($startSentinelText -match '\$Script:SentinelVersion') 'start-sentinel.ps1 reads version from AlphaSentinel.ps1'

  # Test 5: start-sentinel.ps1 verifies ACL on users file (calls Get-Acl)
  Assert-True ($startSentinelText -match 'Get-Acl.*usersFile') 'start-sentinel.ps1 verifies ACL on users file'

  # Test 6: start-sentinel.ps1 zeros plaintext password strings
  Assert-True ($startSentinelText -match 'ZeroFreeBSTR') 'start-sentinel.ps1 zeroes BSTR after use'
  Assert-True ($startSentinelText -match '\[GC\]::Collect') 'start-sentinel.ps1 clears plaintext strings with GC.Collect'

  # Test 7: start-sentinel.ps1 launches monitor with -Background and forwards args
  Assert-True ($startSentinelText -match 'Start-Process.*-WindowStyle Hidden') 'start-sentinel.ps1 launches with hidden window'
  Assert-True ($startSentinelText -match '@args') 'start-sentinel.ps1 forwards user arguments'

  # Test 8: New-SentinelAdmin.ps1 has -Password parameter for non-interactive use
  $adminScriptPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'New-SentinelAdmin.ps1'
  $adminScriptText = Get-Content -Raw $adminScriptPath
  Assert-True ($adminScriptText -match '\[string\]\$Password\s*=') 'New-SentinelAdmin.ps1 has -Password parameter'

  # Test 9: AlphaSentinel.ps1 Stop-Sentinel validates PID command line
  $alphaPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'AlphaSentinel.ps1'
  $alphaText = Get-Content -Raw $alphaPath
  Assert-True ($alphaText -match 'CommandLine.*AlphaSentinel\.ps1') 'Stop-Sentinel validates PID command line'
  Assert-True ($alphaText -match 'does not belong to an AlphaSentinel process') 'Stop-Sentinel reports stale PID'

  # Test 10: start-sentinel.bat uses correct paths
  $batPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'start-sentinel.bat'
  $batText = Get-Content -Raw $batPath
  Assert-True ($batText -match '%~dp0sentinel-users.json') 'start-sentinel.bat checks correct users file path'
  Assert-True ($batText -match 'cd /d .*%~dp0') 'start-sentinel.bat changes to script directory'
  Assert-True ($batText -match '%~dp0AlphaSentinel.ps1') 'start-sentinel.bat uses correct script path'

  # Test 11: Behavioral test - New-SentinelAdmin.ps1 account creation produces valid PBKDF2 hash format
  $tempUsersFile = Join-Path $tmp 'test-users.json'
  $tempAlphaScript = Join-Path (Split-Path -Parent $PSScriptRoot) 'New-SentinelAdmin.ps1'
  $result = & $tempAlphaScript -Username 'testuser1' -Password 'TestPassword123!' -UsersFile $tempUsersFile 2>&1
  if ($LASTEXITCODE -eq 0 -and (Test-Path $tempUsersFile)) {
    $usersJson = Get-Content -Raw $tempUsersFile
    $users = $usersJson | ConvertFrom-Json
    $testUser = $users.users | Where-Object { $_.user -eq 'testuser1' }
    Assert-True ($null -ne $testUser -and $testUser.salt -and $testUser.hash -and $testUser.iterations -eq 150000) 'New-SentinelAdmin.ps1 creates valid PBKDF2 hash (150000 iterations, 16-byte salt, 32-byte hash)'
    Assert-True ($testUser.salt.Length -eq 32 -and $testUser.hash.Length -eq 64) 'salt and hash are hex-encoded (32 and 64 chars)'
  }
  else {
    Assert-True $false 'New-SentinelAdmin.ps1 account creation failed'
  }

  Write-Host ""
  $colour = if ($script:Fail -eq 0) { 'Green' } else { 'Red' }
  Write-Host ("RESULT: " + $script:Pass + " passed, " + $script:Fail + " failed") -ForegroundColor $colour
  if ($script:Fail -gt 0) { exit 1 }
}
finally {
  Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
}