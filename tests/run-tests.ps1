<#
tests/run-tests.ps1 - rule-engine test suite for AlphaSentinel.

Runs two suites with NO Windows event log, NO dashboard and NO network:

  1. behaviour assertions   - each detection fix from v2.1 is asserted in both
                              directions (fires when it should, silent when it
                              should not), plus dedupe-per-entity, the
                              audit-policy preflight logic, state persistence
                              and the CSV-injection guard.
  2. fixture replay         - every tests/fixtures/*.xml is pushed through the
                              real Get-NormalizedEvent + Evaluate-Event path and
                              compared with tests/fixtures/expected.json.

How it works: the script under test is split at its own section markers and the
pure-logic parts are dot-sourced here, so the test drives the SAME functions the
live monitor uses (no reimplementation to drift). Needs PowerShell 5.1+ or 7.

    .\tests\run-tests.ps1
#>
[CmdletBinding()]
param(
  [string]$Script = (Join-Path (Split-Path -Parent $PSScriptRoot) 'AlphaSentinel.ps1'),
  [string]$Fixtures = (Join-Path $PSScriptRoot 'fixtures')
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path $Script)) { throw "cannot find $Script" }
$raw = Get-Content -Raw $Script

# Section markers are matched as plain text (not with a leading separator line)
# so this works whether the script is checked out with LF or CRLF endings. Each
# must be unique, or the slice boundaries would drift silently.
$mAlert   = '# ALERT STORE: history persistence, CSV export, coverage catalog'
$mWeb     = '# EMBEDDED WEB SERVER (dashboard + JSON API)'
$mProbes  = '# SELF-TEST PROBES'
$mForward = '# OPTIONAL WEB FORWARDING'
foreach ($m in @($mAlert, $mWeb, $mProbes, $mForward)) {
  $first = $raw.IndexOf($m)
  if ($first -lt 0) { throw "section marker not found (was $Script restructured?): $m" }
  if ($first -ne $raw.LastIndexOf($m)) { throw "section marker is not unique: $m" }
}

$engineText = $raw.Substring(0, $raw.IndexOf($mAlert))
$logicText  = $raw.Substring($raw.IndexOf($mAlert), $raw.IndexOf($mWeb) - $raw.IndexOf($mAlert))
$probeText  = $raw.Substring($raw.IndexOf($mProbes), $raw.IndexOf($mForward) - $raw.IndexOf($mProbes))

# strip the parts that belong to a live run: the elevation requirement and the
# parameter block (this harness sets those variables itself)
$engineText = $engineText -replace '(?m)^#Requires -RunAsAdministrator\s*$', ''
$engineText = [regex]::Replace($engineText, '(?s)param\(.*?\r?\n\)\r?\n', @"
`$Port = 8451
`$Bind = 'localhost'
`$ApiToken = ''
`$PollSeconds = 15
`$MaxEventsPerPoll = 500
`$Background = `$false
`$Stop = `$false
`$ForwardUrl = ''
`$ForwardKey = ''
`$HistoryFile = ''
`$StateFile = ''
`$ReplayPath = ''
"@, 1)

$tmp = [IO.Path]::Combine([IO.Path]::GetTempPath(), "sentinel-tests-$PID")
$null = New-Item -ItemType Directory -Path $tmp -Force
try {
  $enginePath = Join-Path $tmp 'engine.ps1'
  $logicPath  = Join-Path $tmp 'logic.ps1'
  $probePath  = Join-Path $tmp 'probes.ps1'
  Set-Content -Path $enginePath -Value $engineText -Encoding UTF8
  Set-Content -Path $logicPath  -Value $logicText  -Encoding UTF8
  Set-Content -Path $probePath  -Value $probeText  -Encoding UTF8

  . $enginePath
  . $probePath
  . $logicPath

  $script:Pass = 0
  $script:Fail = 0
  $script:Raised = @()

  function Reset-Engine {
    $Script:RecentAlertTimes = @{}
    $Script:Windows = @{}
    $Script:DedupeAlertId = @{}
    $Script:Alerts = New-Object System.Collections.Generic.List[object]
    $Script:NextAlertId = 1
    $Script:AlertsDirty = $true
    $script:Raised = @()
  }

  # feed one event the way the poll loop does: evaluate it, and keep the alert so
  # in-window dedupe lookups behave exactly as they do in production
  function Feed($id, $fields) {
    $shim = New-EventShim @{ ruleKey = ''; id = $id; fields = $fields }
    $alert = Evaluate-Event $shim
    if ($alert) { $Script:Alerts.Add($alert); $script:Raised += $alert }
    return $alert
  }

  function Ok($name)  { $script:Pass++; Write-Host ("  PASS  " + $name) -ForegroundColor Green }
  function Bad($name) { $script:Fail++; Write-Host ("  FAIL  " + $name) -ForegroundColor Red }
  function Assert-Fired($ruleKey, $name) {
    if (@($script:Raised | Where-Object { $_.RuleKey -eq $ruleKey }).Count -ge 1) { Ok $name } else { Bad ($name + "  (nothing fired, expected " + $ruleKey + ")") }
  }
  function Assert-Silent($ruleKey, $name) {
    $n = @($script:Raised | Where-Object { $_.RuleKey -eq $ruleKey }).Count
    if ($n -eq 0) { Ok $name } else { Bad ($name + "  (" + $ruleKey + " fired " + $n + "x)") }
  }
  function Assert-Count($ruleKey, $expected, $name) {
    $n = @($script:Raised | Where-Object { $_.RuleKey -eq $ruleKey }).Count
    if ($n -eq $expected) { Ok $name } else { Bad ($name + "  (expected " + $expected + " x " + $ruleKey + ", got " + $n + ")") }
  }
  function Assert-True($cond, $name) { if ($cond) { Ok $name } else { Bad $name } }

  Write-Host ""
  Write-Host "== detection behaviour ==" -ForegroundColor Cyan

  Reset-Engine
  for ($i = 0; $i -lt 8; $i++) { $null = Feed 4776 @{ TargetUserName = 'jsmith'; Workstation = 'WKS01'; Status = '0x0' } }
  Assert-Silent 'ntlm_failed_auth' '8x 4776 Status 0x0 (successful validations) is not a failure burst'
  Reset-Engine
  for ($i = 0; $i -lt 8; $i++) { $null = Feed 4776 @{ TargetUserName = 'jsmith'; Workstation = 'WKS01'; Status = '0xC000006A' } }
  Assert-Fired 'ntlm_failed_auth' '8x 4776 Status 0xC000006A still fires'

  Reset-Engine
  $null = Feed 4662 @{ SubjectUserName = 'attacker'; ObjectType = 'domainDNS'; ObjectName = 'DC=corp,DC=local'; Properties = 'Replicating Directory Changes All: {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}'; AccessMask = '0x100' }
  Assert-Fired 'dcsync_replication' 'real 4662 (GUID in Properties, ObjectType=domainDNS) fires DCSync'
  Reset-Engine
  $null = Feed 4662 @{ SubjectUserName = 'DC01$'; ObjectType = 'domainDNS'; ObjectName = 'DC=corp,DC=local'; Properties = 'Replicating Directory Changes All: {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}' }
  Assert-Silent 'dcsync_replication' 'DC machine account replicating is not DCSync'
  Assert-Silent 'ldap_recon' 'DC machine account replicating is not enumeration noise'

  Reset-Engine
  $null = Feed 4738 @{ TargetUserName = 'jdoe'; SubjectUserName = 'administrator'; OldUacValue = '0x400200'; NewUacValue = '0x400200' }
  Assert-Silent 'account_control_changed' '4738 with no net UAC change'
  Reset-Engine
  $null = Feed 4738 @{ TargetUserName = 'svc-old'; SubjectUserName = 'administrator'; OldUacValue = '0x202'; NewUacValue = '0x202' }
  Assert-Silent 'account_control_changed' '4738 on an already-disabled account, nothing changed'
  Reset-Engine
  $a = Feed 4738 @{ TargetUserName = 'jdoe'; SubjectUserName = 'administrator'; OldUacValue = '0x200'; NewUacValue = '0x400200' }
  Assert-Fired 'account_control_changed' '4738 gaining DONT_REQ_PREAUTH fires'
  Assert-True ($a -and $a.Severity -eq 'Critical') '  ...at Critical severity'
  Reset-Engine
  $null = Feed 4738 @{ TargetUserName = 'jdoe'; SubjectUserName = 'administrator'; OldUacValue = '0x202'; NewUacValue = '0x200' }
  Assert-Fired 'account_control_changed' '4738 clearing ACCOUNTDISABLE (re-enable) fires'

  Reset-Engine
  $null = Feed 4769 @{ TargetUserName = 'jsmith'; ServiceName = 'krbtgt'; TicketEncryptionType = '0x17'; Status = '0x0' }
  Assert-Silent 'kerberoasting' '4769 RC4 for krbtgt is excluded'
  Reset-Engine
  $null = Feed 4769 @{ TargetUserName = 'jsmith'; ServiceName = 'HOST/PC01$'; TicketEncryptionType = '0x17'; Status = '0x0' }
  Assert-Silent 'kerberoasting' '4769 RC4 for a machine SPN is excluded'
  Reset-Engine
  $null = Feed 4769 @{ TargetUserName = 'DC01$'; ServiceName = 'MSSQLSvc/sql01'; TicketEncryptionType = '0x17'; Status = '0x0' }
  Assert-Silent 'kerberoasting' '4769 RC4 requested by a machine account is excluded'
  Reset-Engine
  $null = Feed 4769 @{ TargetUserName = 'jsmith'; ServiceName = 'MSSQLSvc/sql01:1433'; TicketEncryptionType = '0x17'; Status = '0x6' }
  Assert-Silent 'kerberoasting' '4769 RC4 on a FAILED request is excluded'
  Reset-Engine
  $null = Feed 4769 @{ TargetUserName = 'jsmith'; ServiceName = 'MSSQLSvc/sql01:1433'; TicketEncryptionType = '0x17'; Status = '0x0' }
  $null = Feed 4769 @{ TargetUserName = 'jsmith'; ServiceName = 'HTTP/intranet'; TicketEncryptionType = '0x17'; Status = '0x0' }
  $null = Feed 4769 @{ TargetUserName = 'jsmith'; ServiceName = 'CIFS/file01'; TicketEncryptionType = '0x17'; Status = '0x0' }
  Assert-Count 'kerberoasting' 1 'three distinct RC4 SPNs by one account -> one escalating alert'
  Assert-True (@($script:Raised | Where-Object { $_.RuleKey -eq 'kerberoasting' })[0].Severity -eq 'Critical') '  ...escalated to Critical at 3 distinct SPNs'

  Reset-Engine
  $null = Feed 4768 @{ TargetUserName = 'svc-legacy'; PreAuthType = '0'; Status = '0x0' }
  Assert-Fired 'asrep_roasting' 'a SINGLE no-preauth TGT request fires'
  Reset-Engine
  $null = Feed 4768 @{ TargetUserName = 'jsmith'; PreAuthType = '2'; Status = '0x0' }
  Assert-Silent 'asrep_roasting' '4768 with pre-auth required does not fire'

  Reset-Engine
  $null = Feed 4720 @{ TargetUserName = 'WKS07$'; SubjectUserName = 'WKS07$' }
  Assert-Silent 'account_created' '4720 computer account (domain join) is ignored'
  Reset-Engine
  $null = Feed 4720 @{ TargetUserName = 'attacker1'; SubjectUserName = 'administrator' }
  Assert-Fired 'account_created' '4720 user account still fires'

  Reset-Engine
  $null = Feed 4624 @{ TargetUserName = 'svc-backup'; IpAddress = '10.0.0.7'; LogonType = '3' }
  Assert-Silent 'suspicious_remote_logon' '4624 type 3 by a service account is ignored'
  Reset-Engine
  $null = Feed 4624 @{ TargetUserName = 'DA_john'; IpAddress = '10.0.0.7'; LogonType = '3' }
  Assert-Fired 'suspicious_remote_logon' '4624 type 3 by an admin-style account fires'
  Reset-Engine
  $null = Feed 4624 @{ TargetUserName = 'administrator'; IpAddress = '10.0.0.7'; LogonType = '10' }
  Assert-Fired 'suspicious_remote_logon' '4624 RDP (type 10) fires'
  Reset-Engine
  $null = Feed 4624 @{ TargetUserName = 'WKS01$'; IpAddress = '10.0.0.7'; LogonType = '10' }
  Assert-Silent 'suspicious_remote_logon' '4624 type 10 by a machine account is ignored'
  Reset-Engine
  $null = Feed 4624 @{ TargetUserName = 'SYSTEM'; IpAddress = '-'; LogonType = '3' }
  Assert-Silent 'suspicious_remote_logon' '4624 type 3 by SYSTEM is ignored'
  Reset-Engine
  $null = Feed 4672 @{ SubjectUserName = 'SYSTEM'; PrivilegeList = 'SeDebugPrivilege' }
  Assert-Silent 'special_privileges_assigned' '4672 for SYSTEM is ignored'
  Reset-Engine
  $null = Feed 4672 @{ SubjectUserName = 'admin1'; PrivilegeList = 'SeDebugPrivilege SeChangeNotifyPrivilege' }
  Assert-Fired 'special_privileges_assigned' '4672 for a human admin fires'

  Write-Host ""
  Write-Host "== dedupe is per entity, not per rule ==" -ForegroundColor Cyan
  Reset-Engine
  $null = Feed 4728 @{ MemberName = 'userA'; TargetUserName = 'Domain Admins'; SubjectUserName = 'administrator' }
  $null = Feed 4728 @{ MemberName = 'userB'; TargetUserName = 'Domain Admins'; SubjectUserName = 'administrator' }
  Assert-Count 'privilege_escalation' 2 'two DIFFERENT accounts added to Domain Admins -> two alerts'
  $before = @($script:Raised).Count
  $null = Feed 4728 @{ MemberName = 'userA'; TargetUserName = 'Domain Admins'; SubjectUserName = 'administrator' }
  Assert-True (@($script:Raised).Count -eq $before) '  ...a repeat add of the SAME account is still deduped'
  Reset-Engine
  foreach ($ip in @('10.0.0.5', '10.0.0.9')) {
    foreach ($acct in @('u1', 'u2', 'u3', 'u4', 'u5')) { $null = Feed 4625 @{ TargetUserName = $acct; IpAddress = $ip; Status = '0xC000006A' } }
  }
  Assert-Count 'password_spraying' 2 'two spraying sources -> two alerts'
  Reset-Engine
  foreach ($ip in @('10.0.0.5', '10.0.0.9')) {
    foreach ($acct in @('u1', 'u2', 'u3', 'u4', 'u5', 'u6', 'u7', 'u8')) { $null = Feed 4776 @{ TargetUserName = $acct; Workstation = $ip; Status = '0xC000006A' } }
  }
  Assert-Count 'ntlm_failed_auth' 2 'two NTLM failure sources -> two alerts'

  Write-Host ""
  Write-Host "== self-test coverage ==" -ForegroundColor Cyan
  Reset-Engine
  $firedKeys = @()
  foreach ($p in (New-SelfTestProbes)) {
    $shim = New-EventShim $p
    $a = Evaluate-Event $shim
    if ($a) { $firedKeys += $a.RuleKey; $Script:Alerts.Add($a) }
  }
  $distinct = @($firedKeys | Select-Object -Unique)
  $missing = @($RuleMeta.Keys | Where-Object { $distinct -notcontains $_ })
  Assert-True ($distinct.Count -eq $RuleMeta.Count) ('self-test fires ' + $distinct.Count + ' of ' + $RuleMeta.Count + ' rule families (missing: ' + ($missing -join ', ') + ')')
  Assert-True ($RuleMeta.Count -eq 28) ('rule catalog has exactly 28 families (actual: ' + $RuleMeta.Count + ')')
  $auditMissing = @($RuleMeta.Keys | Where-Object { -not $RuleAudit.ContainsKey($_) })
  $auditExtra = @($RuleAudit.Keys | Where-Object { -not $RuleMeta.ContainsKey($_) })
  Assert-True ($auditMissing.Count -eq 0 -and $auditExtra.Count -eq 0) ('preflight map covers every rule family (missing: ' + ($auditMissing -join ',') + ' extra: ' + ($auditExtra -join ',') + ')')

  Write-Host ""
  Write-Host "== audit-policy preflight logic ==" -ForegroundColor Cyan
  Reset-Engine
  $Script:AuditState = $null
  Assert-True ((Get-RuleAuditState 'password_spraying').state -eq 'unknown') 'unreadable policy -> unknown, never blind'
  Assert-True ((Get-RuleAuditState 'log_tampering').state -eq 'n/a') '1102 (Eventlog service) is not policy-gated -> n/a'
  $Script:AuditState = @{
    'logon' = 'No Auditing'
    'security group management' = 'Success'
    'kerberos authentication service' = 'Failure'
    'user account management' = 'Success'
    'directory service access' = 'Success'
    'mpssvc rule-level policy change' = 'Success'
    'security state change' = 'Success'
    'credential validation' = 'No Auditing'
  }
  Assert-True ((Get-RuleAuditState 'password_spraying').state -eq 'blind') 'Logon=No Auditing -> password_spraying is blind'
  Assert-True ((Get-RuleAuditState 'suspicious_remote_logon').state -eq 'blind') 'Logon=No Auditing -> suspicious_remote_logon is blind'
  Assert-True ((Get-RuleAuditState 'ntlm_failed_auth').state -eq 'blind') 'Credential Validation=No Auditing -> ntlm_failed_auth is blind'
  Assert-True ((Get-RuleAuditState 'privilege_escalation').state -eq 'ok') 'Security Group Management=Success -> ok'
  Assert-True ((Get-RuleAuditState 'kerberos_preauth_spraying').state -eq 'ok') 'Kerberos Auth Service=Failure satisfies the Failure need'
  Assert-True ((Get-RuleAuditState 'asrep_roasting').state -eq 'blind') 'Kerberos Auth Service=Failure does NOT satisfy the Success need'
  Assert-True ((Get-RuleAuditState 'firewall_rule_modified').state -eq 'ok') 'MPSSVC Rule-Level Policy Change=Success -> ok'
  Assert-True ((Get-RuleAuditState 'system_time_changed').state -eq 'ok') 'Security State Change=Success -> ok'
  Assert-True ((Get-RuleAuditState 'scheduled_task_created').state -eq 'blind') 'missing subcategory -> blind'
  $rep = Get-PreflightReport
  Assert-True ($rep.blindCount -gt 0) ('preflight report lists ' + $rep.blindCount + ' blind families')
  Assert-True (@($rep.fix | Where-Object { $_ -match 'auditpol /set /subcategory:' }).Count -eq @($rep.fix).Count) 'every remediation line is a runnable auditpol command'

  Write-Host ""
  Write-Host "== state + export ==" -ForegroundColor Cyan
  $StateFile = Join-Path $tmp 'test-state.json'
  Reset-Engine
  $Script:LastCheck = (Get-Date).AddMinutes(-7)
  Save-State
  Reset-Engine
  $Script:LastCheck = (Get-Date)
  Assert-True (Restore-State) 'Save-State / Restore-State round-trips'
  Assert-True ([Math]::Abs(((Get-Date) - $Script:LastCheck).TotalMinutes - 7) -lt 0.5) 'the watermark keeps its value (no 2-minute re-alert on restart)'

  Assert-True ((Protect-CsvCell '=cmd|calc') -eq "'=cmd|calc") 'CSV cell starting with = is neutralised'
  Assert-True ((Protect-CsvCell '+1+1') -eq "'+1+1") 'CSV cell starting with + is neutralised'
  Assert-True ((Protect-CsvCell '-2+3') -eq "'-2+3") 'CSV cell starting with - is neutralised'
  Assert-True ((Protect-CsvCell '@SUM(A1)') -eq "'@SUM(A1)") 'CSV cell starting with @ is neutralised'
  Assert-True ((Protect-CsvCell 'jsmith') -eq 'jsmith') 'a normal account name is untouched'
  Assert-True ((Protect-CsvCell '2026-01-01T00:00:00Z') -eq '2026-01-01T00:00:00Z') 'an ISO timestamp is untouched'

  Reset-Engine
  $live = New-Alert 'account_created' '=cmd|calc by attacker1' $null @{ hostname = 'DC01'; accountName = '=cmd|calc'; eventId = '4720' }
  $Script:Alerts.Add($live)
  $demo = New-Alert 'account_created' '[SELF-TEST] demo' $null @{ hostname = 'DC01'; accountName = 'demo'; eventId = '4720' }
  $demo.SelfTest = $true
  $Script:Alerts.Add($demo)
  $csv = Join-Path $tmp 'test-export.csv'
  $n = Export-AlertsCsv $csv $false
  $text = Get-Content -Raw $csv
  Assert-True ($n -eq 1) ('export excludes self-test rows (' + $n + ' row)')
  Assert-True ($text -notmatch 'SELF-TEST') 'self-test alert does not reach the engagement CSV'
  Assert-True ($text -match "'=cmd") 'a hostile account name is prefixed in the CSV'
  $catalog = @(Get-RuleCatalog)
  Assert-True ($catalog.Count -eq 28) 'rule catalog returns 28 entries'
  Assert-True (@($catalog | Where-Object { $_.key -eq 'account_created' })[0].fired -eq 1) 'coverage fired-count excludes the self-test row'
  Assert-True (@($catalog | Where-Object { -not $_.PSObject.Properties['auditState'] }).Count -eq 0) 'every catalog row carries an auditState'

  Write-Host ""
  Write-Host "== fixture replay ==" -ForegroundColor Cyan
  $manifestPath = Join-Path $Fixtures 'expected.json'
  if (-not (Test-Path $manifestPath)) { throw "cannot find $manifestPath" }
  $manifest = Get-Content -Raw $manifestPath | ConvertFrom-Json
  foreach ($name in ($manifest.PSObject.Properties.Name | Sort-Object)) {
    $exp = $manifest.$name
    $path = Join-Path $Fixtures $name
    Reset-Engine
    $fired = @()
    foreach ($en in @(Get-ReplayShims $path | Sort-Object Time)) {
      $a = Evaluate-Event $en.Shim
      if ($a) { $Script:Alerts.Add($a); $fired += $a.RuleKey }
    }
    $problems = @()
    foreach ($k in @($exp.expect)) { if ($fired -notcontains $k) { $problems += "expected $k to fire" } }
    foreach ($k in @($exp.forbid)) { if ($fired -contains $k) { $problems += "$k must NOT fire" } }
    if ($exp.PSObject.Properties['expectCount'] -and @($exp.expect).Count -gt 0) {
      $c = @($fired | Where-Object { $_ -eq $exp.expect[0] }).Count
      if ($c -ne [int]$exp.expectCount) { $problems += "expected $($exp.expectCount)x $($exp.expect[0]), got $c" }
    }
    if ($problems.Count -eq 0) { Ok ($name + "  -> [" + (@($fired | Select-Object -Unique) -join ', ') + "]") }
    else { Bad ($name + "  -> " + ($problems -join '; ')) }
  }

  Write-Host ""
  $colour = if ($script:Fail -eq 0) { 'Green' } else { 'Red' }
  Write-Host ("RESULT: " + $script:Pass + " passed, " + $script:Fail + " failed") -ForegroundColor $colour
  if ($script:Fail -gt 0) { exit 1 }
} finally {
  Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
