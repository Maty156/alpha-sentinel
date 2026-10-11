<#
tests/run-tests.ps1 - AlphaSentinel test suite.

Runs offline - no Windows event log, no HTTP, no network - by splitting the tool
at its own section markers and dot-sourcing the pure-logic parts, so the tests
drive the SAME functions the running monitor uses rather than a reimplementation
that can drift.

Covered:
  1. detection behaviour (every v2.1 fix, in both directions) + dedupe per entity
  2. self-test coverage and the audit-policy preflight logic
  3. state persistence, CSV-injection guard, export self-test exclusion
  4. v2.2 rules: 4738 delegation flags, kerberoasting severity ladder
  5. authentication: PBKDF2 format cross-checked with New-SentinelAdmin.ps1,
     sessions + timeouts, login rate limiting, users-file gating, Host guard
  6. the lost-event fix: per-event error isolation, per-channel watermarks that
     only advance when a channel completed
  7. backlog catch-up: a 5000-event backlog drains without loss or duplicates
  8. the XPath pre-filter: well-formed, a superset of what the engine needs,
     and the fallback when the provider rejects it
  9. v2.3 part 1: the stalled-body watchdog (C# SentinelBody reader, 2s limit,
     abort, stall counter, per-address block)
  10. v2.3 part 2: the dashboard backend - events ring buffer, hosts seen, hourly
     buckets, deltas, coverage/health, the four GET endpoints and the alert
     object's status/ack/mitre/first-last-seen/contributing-events shape
  11. v2.2 hardening: the request-body DoS guard (411/413 before any read), the
     idle-vs-catching-up verdict, sessions ending with their account, the
     public-health/authenticated-status split, the 5s watermark overlap, paged
     oldest-first polls, and New-Object PBKDF2 pinned to RFC 6070 vectors
  9. fixture replay against tests/fixtures/expected.json

    .\tests\run-tests.ps1
#>
[CmdletBinding()]
param(
  [string]$Script = (Join-Path (Split-Path -Parent $PSScriptRoot) 'AlphaSentinel.ps1'),
  [string]$AdminScript = (Join-Path (Split-Path -Parent $PSScriptRoot) 'New-SentinelAdmin.ps1'),
  [string]$Fixtures = (Join-Path $PSScriptRoot 'fixtures')
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path $Script)) { throw "cannot find $Script" }
if (-not (Test-Path $AdminScript)) { throw "cannot find $AdminScript" }
$raw = Get-Content -Raw $Script
$adminRaw = Get-Content -Raw $AdminScript

# Section markers are plain text (not tied to LF/CRLF) and must be unique, or a
# slice boundary would drift silently.
$mAlert   = '# ALERT STORE: history persistence, CSV export, coverage catalog'
$mWeb     = '# EMBEDDED WEB SERVER (dashboard + JSON API)'
$mProbes  = '# SELF-TEST PROBES'
$mForward = '# OPTIONAL WEB FORWARDING'
$mPoll    = '# EVENT-LOG POLLING LOOP'
$mMain    = '# MAIN - start web server, single-threaded request/poll loop'
$mCred    = '# CREDENTIALS (shared format with AlphaSentinel.ps1)'
$mPwd     = '# PASSWORD GENERATION'
$mStore   = '# USER STORE'

foreach ($m in @($mAlert, $mWeb, $mProbes, $mForward, $mPoll, $mMain)) {
  $first = $raw.IndexOf($m)
  if ($first -lt 0) { throw "section marker not found (was $Script restructured?): $m" }
  if ($first -ne $raw.LastIndexOf($m)) { throw "section marker is not unique: $m" }
}
foreach ($m in @($mCred, $mPwd, $mStore)) {
  $first = $adminRaw.IndexOf($m)
  if ($first -lt 0) { throw "section marker not found in $AdminScript : $m" }
  if ($first -ne $adminRaw.LastIndexOf($m)) { throw "section marker is not unique in $AdminScript : $m" }
}

function Get-Section([string]$text, [string]$from, [string]$to) {
  $a = $text.IndexOf($from)
  $b = if ($to) { $text.IndexOf($to) } else { $text.Length }
  return $text.Substring($a, $b - $a)
}

$engineText = $raw.Substring(0, $raw.IndexOf($mAlert))
$logicText  = Get-Section $raw $mAlert $mWeb
$probeText  = Get-Section $raw $mProbes $mForward
$fwdText    = Get-Section $raw $mForward $mPoll
$pollText   = Get-Section $raw $mPoll $mMain
$credText   = Get-Section $adminRaw $mCred $mPwd
$pwdText    = Get-Section $adminRaw $mPwd $mStore

# strip the elevation requirement and the parameter block (this harness sets
# those variables itself)
$engineText = $engineText -replace '(?m)^#Requires -RunAsAdministrator\s*$', ''
$engineText = [regex]::Replace($engineText, '(?s)param\(.*?\r?\n\)\r?\n', @"
`$Port = 8443
`$Bind = 'localhost'
`$PollSeconds = 15
`$MaxEventsPerPoll = 500
`$CatchUpMilliseconds = 200
`$Background = `$false
`$Stop = `$false
`$ForwardUrl = ''
`$ForwardKey = ''
`$HistoryFile = ''
`$StateFile = ''
`$UsersFile = ''
`$AuthFile = ''
`$ReplayPath = ''
"@, 1)

$tmp = [IO.Path]::Combine([IO.Path]::GetTempPath(), "sentinel-tests-$PID")
$null = New-Item -ItemType Directory -Path $tmp -Force
try {
  Set-Content -Path (Join-Path $tmp 'engine.ps1') -Value $engineText -Encoding UTF8
  Set-Content -Path (Join-Path $tmp 'logic.ps1')  -Value $logicText  -Encoding UTF8
  Set-Content -Path (Join-Path $tmp 'probes.ps1') -Value $probeText  -Encoding UTF8
  Set-Content -Path (Join-Path $tmp 'fwd.ps1')    -Value $fwdText    -Encoding UTF8
  Set-Content -Path (Join-Path $tmp 'poll.ps1')   -Value $pollText   -Encoding UTF8
  Set-Content -Path (Join-Path $tmp 'cred.ps1')   -Value $credText   -Encoding UTF8
  Set-Content -Path (Join-Path $tmp 'pwd.ps1')    -Value $pwdText    -Encoding UTF8

  . (Join-Path $tmp 'engine.ps1')
  . (Join-Path $tmp 'probes.ps1')
  . (Join-Path $tmp 'logic.ps1')
  . (Join-Path $tmp 'fwd.ps1')
  . (Join-Path $tmp 'poll.ps1')
  . (Join-Path $tmp 'cred.ps1')
  . (Join-Path $tmp 'pwd.ps1')

  # ---- test files, pointed somewhere disposable ----
  $HistoryFile = Join-Path $tmp 'history.csv'
  $StateFile = Join-Path $tmp 'state.json'
  $UsersFile = Join-Path $tmp 'users.json'
  $AuthFile = Join-Path $tmp 'auth.csv'
  $ForwardUrl = ''
  $ForwardKey = ''
  $Bind = 'localhost'
  $PollSeconds = 15
  $MaxEventsPerPoll = 500
  $CatchUpMilliseconds = 200

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
    $Script:SeenRecords = @{}
    $Script:ChannelMarks = @{}
    $Script:ChannelLastSuccess = @{}
    $Script:ChannelLastError = @{}
    $Script:XPathFallback = @{}
    $Script:EvalErrors = 0
    $Script:LastEvalError = ''
    $Script:PollErrors = 0
    $Script:LastPollError = ''
    $Script:ProcessedCount = 0
    $Script:Sessions = @{}
    $Script:LoginFailures = @{}
    $Script:UsersStamp = $null
    $Script:UsersUpdated = @{}
    $Script:UsersRevoked = 0
    $Script:BodyRejections = 0
    $Script:BodyTimeouts = 0
    $Script:BodyTimedOut = $false
    $Script:BodyStalls = @{}
    $Script:ObsEvents = New-Object System.Collections.Generic.List[object]
    $Script:ObsHosts = @{}
    $Script:ObsHours = @{}
    $Script:LastNormFields = $null
    $Script:LastEventTime = $null
    $Script:LastMatchedRule = $null
    $Script:AuditState = $null
    $Script:LastPollCapped = $false
    $Script:LastCheck = (Get-Date).AddMinutes(-2)
    $script:Raised = @()
  }

  # feed one event the way the poll loop does
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

  # Get-WinEvent-shaped object with real event XML, without paying for an [xml]
  # parse at construction time (the parser cost belongs to evaluation).
  function New-FakeEvent([int]$Id, [int]$RecordId, [datetime]$When, [hashtable]$Fields) {
    $fieldsXml = ''
    if ($Fields) {
      $fieldsXml = ($Fields.GetEnumerator() | ForEach-Object { "<Data Name='" + $_.Key + "'>" + $_.Value + "</Data>" }) -join ''
    }
    $xml = "<Event><System><Provider Name='Fake'/><EventID>$Id</EventID><TimeCreated SystemTime='" + $When.ToUniversalTime().ToString("o") + "'/><Computer>FAKE-DC</Computer></System><EventData>$fieldsXml</EventData></Event>"
    $e = New-Object PSObject
    $e | Add-Member -MemberType NoteProperty -Name Id -Value $Id -Force
    $e | Add-Member -MemberType NoteProperty -Name RecordId -Value $RecordId -Force
    $e | Add-Member -MemberType NoteProperty -Name TimeCreated -Value $When -Force
    $e | Add-Member -MemberType NoteProperty -Name Xml -Value $xml -Force
    $e | Add-Member -MemberType ScriptMethod -Name ToXml -Value { return $this.Xml } -Force
    return $e
  }

  # ---- fake event log ------------------------------------------------------
  # A function named Get-WinEvent shadows the real cmdlet inside this scope, so
  # Invoke-PollOnce runs unmodified against scripted events.
  $script:FakeEvents = @()
  $script:FakeFailChannels = @()
  $script:FakeFailXml = $false
  $script:FakeCalls = @()
  $script:FakeParams = @()

  function Get-WinEvent {
    [CmdletBinding()]
    param([hashtable]$FilterHashtable, [string]$FilterXml, [switch]$Oldest, [int]$MaxEvents = 0)
    $kind = if ($FilterXml) { 'FilterXml' } else { 'FilterHashtable' }
    $script:FakeCalls += $kind
    # the XPath path carries the channel and the time window inside the XML, so
    # the fake has to read them out of there as well as from the hashtable
    $channel = ''
    $sinceFromXml = $null
    if ($FilterHashtable) { $channel = "$($FilterHashtable['LogName'])" }
    if ($FilterXml) {
      if ($FilterXml -match 'Path="([^"]+)"') { $channel = "$($Matches[1])" }
      if ($FilterXml -match "SystemTime&gt;='([^']+)'") { $sinceFromXml = [datetime]$Matches[1] }
    }
    $script:FakeParams += [PSCustomObject]@{ Kind = $kind; Channel = $channel; Oldest = [bool]$Oldest; MaxEvents = $MaxEvents }
    if ($script:FakeFailXml -and $kind -eq 'FilterXml') { throw "fake provider rejected the XPath" }
    if ($channel -and ($script:FakeFailChannels -contains $channel)) { throw "fake log '$channel' unavailable" }

    $since = $sinceFromXml
    $ids = @()
    if ($FilterHashtable) {
      if ($FilterHashtable['StartTime']) { $since = [datetime]$FilterHashtable['StartTime'] }
      if ($FilterHashtable['Id']) { $ids = @($FilterHashtable['Id']) }
    }
    $matches = @()
    foreach ($e in $script:FakeEvents) {
      if ($since -and $e.TimeCreated -lt $since) { continue }
      if ($ids.Count -gt 0 -and ($ids -notcontains [int]$e.Id)) { continue }
      $matches += $e
    }
    # the real Get-WinEvent hands back newest-first unless -Oldest is given, and
    # -MaxEvents takes the first N of whichever order was asked for
    if ($Oldest) { $ordered = @($matches | Sort-Object TimeCreated) }
    else { $ordered = @($matches | Sort-Object TimeCreated -Descending) }
    if ($MaxEvents -gt 0) { $ordered = @($ordered | Select-Object -First $MaxEvents) }
    return $ordered
  }

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
  Write-Host "== v2.2 rule changes ==" -ForegroundColor Cyan
  # 4738 delegation flags, only when newly set
  Reset-Engine
  $d = Feed 4738 @{ TargetUserName = 'svc-web'; SubjectUserName = 'administrator'; OldUacValue = '0x200'; NewUacValue = '0x80200' }
  Assert-Fired 'account_control_changed' '4738 GAINING unconstrained delegation (0x80000) fires'
  Assert-True ($d -and $d.Description -match 'unconstrained Kerberos delegation') '  ...and says unconstrained delegation'
  Reset-Engine
  $null = Feed 4738 @{ TargetUserName = 'svc-web'; SubjectUserName = 'administrator'; OldUacValue = '0x80200'; NewUacValue = '0x80200' }
  Assert-Silent 'account_control_changed' '4738 on an account that ALREADY had delegation is silent'
  Reset-Engine
  $c = Feed 4738 @{ TargetUserName = 'svc-web'; SubjectUserName = 'administrator'; OldUacValue = '0x200'; NewUacValue = '0x1000200' }
  Assert-Fired 'account_control_changed' '4738 GAINING constrained delegation with protocol transition (0x1000000) fires'
  Assert-True ($c -and $c.Description -match 'protocol transition') '  ...and says protocol transition'
  Reset-Engine
  $null = Feed 4738 @{ TargetUserName = 'svc-web'; SubjectUserName = 'administrator'; OldUacValue = '0x1000200'; NewUacValue = '0x1000200' }
  Assert-Silent 'account_control_changed' '4738 with protocol transition already set is silent'

  # kerberoasting severity ladder
  Reset-Engine
  $k1 = Feed 4769 @{ TargetUserName = 'jsmith'; ServiceName = 'MSSQLSvc/sql01:1433'; TicketEncryptionType = '0x17'; Status = '0x0' }
  Assert-Fired 'kerberoasting' '4769 a single RC4 user SPN fires'
  Assert-True ($k1 -and $k1.Severity -eq 'Medium') '  ...at Medium for one ticket'
  Assert-True ("$(($RuleMeta['kerberoasting']).Severity)" -eq 'Medium') 'kerberoasting catalog severity is Medium'
  $null = Feed 4769 @{ TargetUserName = 'jsmith'; ServiceName = 'HTTP/intranet'; TicketEncryptionType = '0x17'; Status = '0x0' }
  $null = Feed 4769 @{ TargetUserName = 'jsmith'; ServiceName = 'CIFS/file01'; TicketEncryptionType = '0x17'; Status = '0x0' }
  Assert-Count 'kerberoasting' 1 'three distinct RC4 SPNs by one account -> one alert'
  Assert-True (@($script:Raised | Where-Object { $_.RuleKey -eq 'kerberoasting' })[0].Severity -eq 'High') '  ...escalated in place to High at 3 distinct SPNs'

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
  Write-Host "== audit-policy preflight ==" -ForegroundColor Cyan
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
  Assert-True ((Get-RuleAuditState 'ntlm_failed_auth').state -eq 'blind') 'Credential Validation=No Auditing -> ntlm_failed_auth is blind'
  Assert-True ((Get-RuleAuditState 'privilege_escalation').state -eq 'ok') 'Security Group Management=Success -> ok'
  Assert-True ((Get-RuleAuditState 'kerberos_preauth_spraying').state -eq 'ok') 'Kerberos Auth Service=Failure satisfies the Failure need'
  Assert-True ((Get-RuleAuditState 'asrep_roasting').state -eq 'blind') 'Kerberos Auth Service=Failure does NOT satisfy the Success need'
  Assert-True ((Get-RuleAuditState 'scheduled_task_created').state -eq 'blind') 'missing subcategory -> blind'
  $rep = Get-PreflightReport
  Assert-True ($rep.blindCount -gt 0) ('preflight report lists ' + $rep.blindCount + ' blind families')
  Assert-True (@($rep.fix | Where-Object { $_ -match 'auditpol /set /subcategory:' }).Count -eq @($rep.fix).Count) 'every remediation line is a runnable auditpol command'

  Write-Host ""
  Write-Host "== state + export ==" -ForegroundColor Cyan
  Reset-Engine
  foreach ($source in $LogSources) { $Script:ChannelMarks[$source.Log] = (Get-Date).AddMinutes(-7) }
  $Script:LastCheck = (Get-Date).AddMinutes(-7)
  Save-State
  Reset-Engine
  Assert-True (Restore-State) 'Save-State / Restore-State round-trips'
  Assert-True ($Script:ChannelMarks.Count -eq $LogSources.Count) 'one watermark per log channel is restored'
  Assert-True ([Math]::Abs(((Get-Date) - $Script:LastCheck).TotalMinutes - 7) -lt 0.5) 'the watermark keeps its value (no 2-minute re-alert on restart)'
  $stateJson = Get-Content -Raw $StateFile
  Assert-True ($stateJson -match 'channels') 'the state file stores per-channel watermarks'

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
  $csv = Join-Path $tmp 'export.csv'
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
  Write-Host "== authentication ==" -ForegroundColor Cyan

  # --- shared credential format, cross-checked against New-SentinelAdmin.ps1 ---
  $saltA = New-PasswordSalt
  Assert-True ($saltA.Length -eq 16) 'the salt is 16 random bytes'
  $saltB = New-PasswordSalt
  Assert-True (-not (Test-FixedTimeEquals $saltA $saltB)) 'two salts differ'
  $h1 = Get-PasswordHash 'correct horse battery staple' $saltA 100000
  $h2 = Get-PasswordHash 'correct horse battery staple' $saltA 100000
  $h3 = Get-PasswordHash 'correct horse battery stapl' $saltA 100000
  Assert-True ($h1.Length -eq 32) 'the PBKDF2 output is 32 bytes'
  Assert-True (Test-FixedTimeEquals $h1 $h2) 'hashing is deterministic for the same password and salt'
  Assert-True (-not (Test-FixedTimeEquals $h1 $h3)) 'a different password gives a different hash'
  Assert-True ($Script:Pbkdf2Iterations -ge 100000) ('iterations >= 100000 (actual ' + $Script:Pbkdf2Iterations + ')')
  Assert-True ((ConvertFrom-Hex (ConvertTo-Hex $saltA)).Length -eq 16) 'hex encoding round-trips'

  # a record written with the ADMIN TOOL's functions must verify with the
  # MONITOR's verifier - this is what stops the two files drifting apart
  $adminSalt = New-PasswordSalt
  $adminHash = Get-PasswordHash 'AdminToolPassword123!' $adminSalt 150000
  @{
    version = 1
    users   = @(
      [PSCustomObject]@{
        user = 'maty'; salt = (ConvertTo-Hex $adminSalt); hash = (ConvertTo-Hex $adminHash)
        iterations = 150000; created = '2026-03-04T09:00:00.0000000Z'; updated = '2026-03-04T09:00:00.0000000Z'
      },
      [PSCustomObject]@{
        user = 'admin'; salt = (ConvertTo-Hex $saltB); hash = (ConvertTo-Hex (Get-PasswordHash 'another secret phrase' $saltB 150000))
        iterations = 150000; created = '2026-03-04T09:05:00.0000000Z'; updated = '2026-03-04T09:05:00.0000000Z'
      }
    )
  } | ConvertTo-Json -Depth 5 | Set-Content -Path $UsersFile -Encoding UTF8

  Assert-True ((Get-UsersFileState).ok) 'a users file with accounts satisfies the startup gate'
  Assert-True (@(Get-UserStore | ForEach-Object { $_.users }).Count -eq 2) 'the user store reads both accounts'
  Assert-True (Test-UserPassword 'maty' 'AdminToolPassword123!') 'a hash written via the admin tool functions verifies in the monitor'
  Assert-True (-not (Test-UserPassword 'maty' 'AdministoolPassword123!')) 'a wrong password is rejected'
  Assert-True (-not (Test-UserPassword 'nosuchuser' 'AdminToolPassword123!')) 'an unknown user is rejected'
  Assert-True (-not (Test-UserPassword 'maty' '')) 'an empty password is rejected'
  Assert-True (@($RuleMeta.Keys).Count -eq 28) 'the rule catalog is untouched by the auth tests'

  # --- sessions ---
  $sid = New-Session 'maty'
  Assert-True ($sid.Length -eq 64 -and $sid -match '^[0-9a-f]{64}$') 'a session id is 32 random bytes, hex encoded (64 chars)'
  Assert-True ($null -ne (Get-Session $sid)) 'a fresh session resolves'
  Assert-True ((Get-Session $sid).User -eq 'maty') 'the session knows its user'
  Assert-True ($null -eq (Get-Session 'not-a-session')) 'an unknown session id resolves to nothing'
  Assert-True ($null -eq (Get-Session '')) 'an empty session id resolves to nothing'
  $s1 = New-Session 'a'; $s2 = New-Session 'b'
  Assert-True ($s1 -ne $s2) 'two sessions get different ids'

  $idle = New-Session 'maty'
  $Script:Sessions[$idle].LastSeen = (Get-Date).AddMinutes(-31)
  Assert-True ($null -eq (Get-Session $idle)) 'a session idle for 31 minutes is expired'
  Assert-True (-not $Script:Sessions.ContainsKey($idle)) 'the expired session is dropped'
  $fresh = New-Session 'maty'
  Assert-True ($null -ne (Get-Session $fresh)) 'a session is alive at 29 minutes idle'
  $Script:Sessions[$fresh].LastSeen = (Get-Date).AddMinutes(-29)
  Assert-True ($null -ne (Get-Session $fresh)) 'sliding idle timeout: still alive just under the limit'

  $old = New-Session 'maty'
  $Script:Sessions[$old].Created = (Get-Date).AddHours(-9)
  Assert-True ($null -eq (Get-Session $old)) 'a session past its 8h absolute lifetime is expired'
  $edge = New-Session 'maty'
  $Script:Sessions[$edge].Created = (Get-Date).AddHours(-7).AddMinutes(-59)
  Assert-True ($null -ne (Get-Session $edge)) 'a session just under 8h old is still alive'

  $bye = New-Session 'maty'
  Remove-Session $bye
  Assert-True ($null -eq (Get-Session $bye)) 'Remove-Session (logout) destroys it'
  Assert-True ($Script:SessionHours -eq 8 -and $Script:IdleMinutes -eq 30) 'session policy is 8h absolute / 30 min idle'

  # --- login rate limiting ---
  Reset-Engine
  $ip = '10.0.0.99'
  Assert-True (Test-LoginAllowed $ip) 'a fresh source IP may try'
  for ($i = 0; $i -lt 4; $i++) { $null = Register-LoginFailure $ip }
  Assert-True (Test-LoginAllowed $ip) '4 failures do not lock the IP out'
  $null = Register-LoginFailure $ip
  Assert-True (-not (Test-LoginAllowed $ip)) 'the 5th failure locks the IP out'
  Assert-True ((Get-LoginRetryAfter $ip) -gt 0) 'a Retry-After value is available while locked out'
  Assert-True ((Get-LoginRetryAfter $ip) -le (5 * 60) + 1) 'the lockout is ~5 minutes'
  $Script:LoginFailures[$ip].BlockedUntil = (Get-Date).AddSeconds(-1)
  Assert-True (Test-LoginAllowed $ip) 'the lockout expires'
  Reset-LoginFailures $ip
  Assert-True (Test-LoginAllowed $ip) 'a successful login clears the failure record'
  Reset-Engine
  for ($i = 0; $i -lt 6; $i++) { $null = Register-LoginFailure $ip }
  Assert-True (-not (Test-LoginAllowed $ip)) 'a sustained sweep stays locked out'
  Assert-True ($Script:LoginFailures[$ip].Count -eq 6) 'failures keep counting while blocked'

  # --- users-file gate ---
  $realUsers = $UsersFile
  $UsersFile = Join-Path $tmp 'missing-users.json'
  Remove-Item $UsersFile -Force -ErrorAction SilentlyContinue
  $state = Get-UsersFileState
  Assert-True (-not $state.ok) 'a missing users file blocks the web UI'
  Assert-True ($state.reason -eq 'missing') '  ...with reason "missing"'
  Assert-True ($state.message -match 'New-SentinelAdmin') '  ...and tells the admin how to create one'
  '{"version":1,"users":[]}' | Set-Content -Path $UsersFile -Encoding UTF8
  $state = Get-UsersFileState
  Assert-True (-not $state.ok -and $state.reason -eq 'empty') 'an empty users file also blocks the web UI'
  $UsersFile = $realUsers
  Assert-True ((Get-UsersFileState).ok) 'a populated users file allows it'
  Assert-True (-not (Get-Content -Raw $UsersFile).Contains('AdminToolPassword123!')) 'no plaintext password is in the users file'

  # --- Host header guard (DNS rebinding) ---
  function New-FakeContext([string]$HostHeader, [string]$RemoteAddress = '127.0.0.1') {
    $req = New-Object PSObject
    $req | Add-Member -MemberType NoteProperty -Name Headers -Value @{ 'Host' = $HostHeader } -Force
    $endpoint = New-Object PSObject
    $endpoint | Add-Member -MemberType NoteProperty -Name Address -Value $RemoteAddress -Force
    $req | Add-Member -MemberType NoteProperty -Name RemoteEndPoint -Value $endpoint -Force
    $ctx = New-Object PSObject
    $ctx | Add-Member -MemberType NoteProperty -Name Request -Value $req -Force
    return $ctx
  }
  $Bind = 'localhost'
  Assert-True (Test-HostAllowed (New-FakeContext 'localhost:8443')) 'loopback bind: localhost:8443 is allowed'
  Assert-True (Test-HostAllowed (New-FakeContext '127.0.0.1:8443')) 'loopback bind: 127.0.0.1:8443 is allowed'
  Assert-True (Test-HostAllowed (New-FakeContext '[::1]:8443')) 'loopback bind: [::1]:8443 is allowed'
  Assert-True (-not (Test-HostAllowed (New-FakeContext 'evil.example'))) 'loopback bind: a rebinding hostname is refused'
  Assert-True (-not (Test-HostAllowed (New-FakeContext 'dc01.corp.local:8443'))) 'loopback bind: another machine name is refused'
  Assert-True (-not (Test-HostAllowed (New-FakeContext ''))) 'loopback bind: a missing Host header is refused'
  $Bind = '0.0.0.0'
  Assert-True (Test-HostAllowed (New-FakeContext 'dc01.corp.local:8443')) 'LAN bind: other host names are allowed'
  $Bind = 'localhost'

  # --- auth audit trail ---
  Reset-Engine
  Remove-Item $AuthFile -Force -ErrorAction SilentlyContinue
  Write-AuthEvent '10.0.0.9' 'maty' 'failure' 'invalid credentials'
  Write-AuthEvent '10.0.0.9' 'maty' 'success' 'session created'
  $authText = Get-Content -Raw $AuthFile
  Assert-True ($authText -match '10.0.0.9') 'the auth audit records the source IP'
  Assert-True ($authText -match 'maty') 'the auth audit records the username'
  Assert-True (@(Import-Csv $AuthFile).Count -eq 2) 'both an attempt and a success are recorded'
  Assert-True ($authText -notmatch 'AdminToolPassword123!') 'no password reaches the auth audit'

  # --- generated passwords ---
  $p1 = New-RandomPassword 20
  $p2 = New-RandomPassword 20
  Assert-True ($p1.Length -eq 20) 'a generated password is 20 characters'
  Assert-True ($p1 -cmatch '[A-Z]' -and $p1 -cmatch '[a-z]' -and $p1 -match '[0-9]' -and $p1 -match '[^A-Za-z0-9]') 'it mixes upper, lower, digit and symbol'
  # -cnotmatch: the plain -notmatch is case-insensitive, which would treat the
  # pattern as also excluding o and i and hide a bad glyph slipping through
  Assert-True ($p1 -cnotmatch '[0Oo1Il]') 'it avoids the ambiguous glyphs 0/O/o/1/I/l'
  Assert-True ($p1 -ne $p2) 'two generated passwords differ'
  $same = $true
  foreach ($ch in $p1.ToCharArray()) { if ($ch -notmatch '[A-Za-z0-9!@#%^&*()\-_=+\[\]{}:,.?]') { $same = $false } }
  Assert-True $same 'it only uses the allowed character set'
  $idx = @()
  $rngForIndex = [System.Security.Cryptography.RandomNumberGenerator]::Create()
  for ($i = 0; $i -lt 200; $i++) { $idx += (Get-CryptoIndex $rngForIndex 4) }
  $rngForIndex.Dispose()
  Assert-True ((@($idx | Where-Object { $_ -lt 0 -or $_ -gt 3 }).Count) -eq 0) 'Get-CryptoIndex stays inside the requested range'

  Write-Host ""
  Write-Host "== lost-event fix: per-event isolation + per-channel watermarks ==" -ForegroundColor Cyan

  # a malformed event in the MIDDLE of a batch must not stop the rest
  Reset-Engine
  $poison = New-FakeEvent 4625 900000 (Get-Date).AddMinutes(-1) @{ TargetUserName = 'x'; IpAddress = '10.0.0.1' }
  $poison.Xml = '<Event><System><EventID>4625</EventID>'   # truncated XML
  $good1 = New-FakeEvent 4720 900001 (Get-Date).AddSeconds(-50) @{ TargetUserName = 'attackerA'; SubjectUserName = 'administrator' }
  $good2 = New-FakeEvent 4720 900002 (Get-Date).AddSeconds(-40) @{ TargetUserName = 'attackerB'; SubjectUserName = 'administrator' }
  $batchResult = Invoke-ChannelBatch 'Security' @($good1, $poison, $good2) 500
  Assert-True ($batchResult.Errors -eq 1) 'the malformed event is counted as an evaluation error'
  Assert-True ($batchResult.Evaluated -eq 3) 'all three events were attempted'
  Assert-True ($batchResult.Alerts -eq 2) 'the events AFTER the malformed one still alerted'
  Assert-True ($Script:EvalErrors -eq 1) 'evalErrors is exposed as a counter'
  Assert-True ("$($Script:LastEvalError)" -match 'record 900000') 'the last evaluation error names the record'
  Assert-True (@($Script:Alerts | Where-Object { $_.RuleKey -eq 'account_created' }).Count -eq 2) 'both later events produced real alerts'
  Assert-True ($batchResult.LastTime -ne $null) 'the batch reports the last event time so the watermark can advance past the deferral window'

  # a poison event must not be retried forever
  $before = $Script:EvalErrors
  $again = Invoke-ChannelBatch 'Security' @($poison) 500
  Assert-True ($again.Evaluated -eq 0) 'an already-seen record is not re-evaluated'
  Assert-True ($Script:EvalErrors -eq $before) 'and is not re-counted as an error'

  # a channel whose query fails must NOT move its watermark
  Reset-Engine
  foreach ($source in $LogSources) { $Script:ChannelMarks[$source.Log] = (Get-Date).AddMinutes(-5) }
  $script:FakeEvents = @()
  $script:FakeFailChannels = @('System')
  $script:FakeCalls = @()
  $before = @{}
  foreach ($source in $LogSources) { $before[$source.Log] = $Script:ChannelMarks[$source.Log] }
  $poll = Invoke-PollOnce
  Assert-True (-not $poll.Ok) 'a failed channel makes the poll report failure'
  Assert-True ($Script:PollErrors -ge 1) 'the poll error is counted'
  Assert-True ($Script:ChannelMarks['System'] -eq $before['System']) 'the failing channel keeps its watermark'
  Assert-True ($Script:ChannelMarks['Security'] -gt $before['Security']) 'the healthy channel still advances'
  Assert-True ($null -ne $Script:ChannelLastSuccess['Security']) 'the healthy channel records its last success'
  Assert-True ("$($Script:ChannelLastError['System'])" -match 'unavailable') 'the failing channel records its error'
  Assert-True ("$($Script:LastPollError)" -match 'System') 'lastPollError names the channel'

  # a complete poll advances the mark to the poll start and clears the error
  Reset-Engine
  foreach ($source in $LogSources) { $Script:ChannelMarks[$source.Log] = (Get-Date).AddMinutes(-5) }
  $script:FakeFailChannels = @()
  $script:FakeEvents = @(New-FakeEvent 4720 900100 (Get-Date).AddSeconds(-30) @{ TargetUserName = 'lateUser'; SubjectUserName = 'administrator' })
  $poll2 = Invoke-PollOnce
  Assert-True ($poll2.Ok) 'a complete poll reports success'
  Assert-True ($poll2.Alerts -eq 1) 'the event in the window was evaluated and alerted'
  Assert-True ($Script:ChannelMarks['Security'] -gt (Get-Date).AddMinutes(-1)) 'a non-capped channel moves its watermark up to the poll start (minus the 5s overlap)'
  Assert-True ($Script:LastPollCapped -eq $false) 'a complete poll leaves the capped flag clear'
  Assert-True ($poll2.Lag -le 6) 'lag is the deliberate 5s overlap after a successful poll, and nothing more'
  Assert-True ($script:FakeCalls -contains 'FilterXml') 'the XPath pre-filter is used first'

  Write-Host ""
  Write-Host "== backlog catch-up ==" -ForegroundColor Cyan
  Reset-Engine
  foreach ($source in $LogSources) { $Script:ChannelMarks[$source.Log] = (Get-Date).AddHours(-1) }
  $backlog = New-Object System.Collections.ArrayList
  $base = (Get-Date).AddMinutes(-50)
  for ($i = 0; $i -lt 5000; $i++) {
    [void]$backlog.Add((New-FakeEvent 4625 (910000 + $i) $base.AddMilliseconds($i * 10) @{ TargetUserName = "user$i"; IpAddress = '10.0.0.42'; Status = '0xC000006A' }))
  }
  $script:FakeEvents = @($backlog)
  $script:FakeFailChannels = @()
  $script:FakeFailXml = $false

  $pollCount = 0
  $evaluated = 0
  $cappedSeen = 0
  $lastMark = $Script:ChannelMarks['Security']
  $monotonic = $true
  while ($pollCount -lt 40) {
    $r = Invoke-PollOnce
    $pollCount++
    if ($r.Capped) { $cappedSeen++ }
    $evaluated += [int]$r.Evaluated
    if ($Script:ChannelMarks['Security'] -lt $lastMark) { $monotonic = $false }
    $lastMark = $Script:ChannelMarks['Security']
    if (-not $r.Capped) { break }
  }
  Assert-True ($pollCount -ge 10 -and $pollCount -le 12) ('a 5000-event backlog drains in ~11 polls at the 500 cap (actual ' + $pollCount + ')')
  Assert-True ($evaluated -eq 5000) ('every event was evaluated exactly once, with none lost or duplicated (evaluated ' + $evaluated + ')')
  Assert-True ($cappedSeen -ge 9 -and $cappedSeen -le 11) ('at least nine polls were capped and asked for catch-up (actual ' + $cappedSeen + ')')
  Assert-True $monotonic 'the watermark only ever moves forward'
  Assert-True ((Get-NextPollDelaySeconds $true) -eq 0.2) 'a capped poll asks for a 200 ms catch-up'
  Assert-True ((Get-NextPollDelaySeconds $false) -eq $PollSeconds) 'an idle poll waits the full interval'
  Assert-True ($Script:SeenRecords.Count -gt 0) 'seen records are remembered so a re-read boundary event is not double-counted'

  # deep backlog: the watermark must not skip the deferred events
  Reset-Engine
  foreach ($source in $LogSources) { $Script:ChannelMarks[$source.Log] = (Get-Date).AddHours(-1) }
  $script:FakeEvents = @($backlog)
  $r = Invoke-PollOnce
  Assert-True ($r.Capped) 'a poll over the cap reports it was capped'
  $deepMark = $Script:ChannelMarks['Security']
  Assert-True ($deepMark -lt (Get-Date).AddMinutes(-30)) 'a capped poll parks the watermark on the last event handled, not on "now"'
  Assert-True ($deepMark -gt (Get-Date).AddHours(-1)) 'and it still moved forward from where the poll started'

  Write-Host ""
  Write-Host "== XPath pre-filter ==" -ForegroundColor Cyan
  $ids = @(4624, 4625, 4648, 4657, 4662, 4672, 4697, 4698, 4719, 4720, 4722, 4724, 4725, 4726, 4728, 4729, 4732, 4733, 4738, 4740, 4756, 4768, 4769, 4771, 4776, 4946, 4947, 4948, 4949, 5141, 1100, 1102, 4616)
  # the synthetic events below are dated 2026-03-04, so the window has to start
  # before that or the time predicate filters everything out
  $since = [datetime]::Parse('2020-01-01T00:00:00Z')
  $filterXml = Get-ChannelFilterXml 'Security' $ids $since
  $parsed = $null
  $wellFormed = $true
  try { $parsed = [xml]$filterXml } catch { $wellFormed = $false }
  Assert-True $wellFormed 'the generated FilterXml is well-formed XML'
  Assert-True ($filterXml -match 'Path="Security"') 'it targets the requested channel'
  Assert-True ($parsed.QueryList.Query.Select.'#text' -ne $null) 'it carries a Select query'
  Assert-True ($filterXml -match 'LogonType') 'it pre-filters 4624 on LogonType'
  Assert-True ($filterXml -match 'TicketEncryptionType') 'it pre-filters 4769 on TicketEncryptionType'
  Assert-True ($filterXml -match "Status") 'it pre-filters 4776 on Status'
  Assert-True ($filterXml -match '&gt;=') 'the time comparison is XML-escaped inside the query document'
  $fullXPath = Get-ChannelFilterXPath $ids $since
  Assert-True ($fullXPath -match "TimeCreated\[@SystemTime>=") 'the window start is a SystemTime range predicate'
  $stamp = Format-EventLogTime ([datetime]$since)
  Assert-True ($stamp -match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$') ('the timestamp uses the event log format yyyy-MM-ddTHH:mm:ss.fffZ (actual ' + $stamp + ')')
  Assert-True ($fullXPath.Contains($stamp)) 'the formatted window start is in the query'
  Assert-True ($fullXPath -match 'System\[EventID=4624\]' -and $fullXPath -match 'LogonType') 'the full query carries both halves'
  $noisy = @($NoisyIdFilters.Keys | Sort-Object)
  Assert-True ($noisy.Count -eq 3 -and $noisy -contains '4624' -and $noisy -contains '4769' -and $noisy -contains '4776') 'exactly the three noisiest IDs are pre-filtered'

  # semantics: apply the Select path to a document shaped like the event log's
  # own XML view, and check exactly which events pass. The pre-filter must be a
  # SUPERSET of what the engine cares about - it may pass extras, never drop one.
  $evs = @()
  $mk = {
    param($rec, $id, $data)
    $d = ''
    foreach ($k in $data.Keys) { $d += "<Data Name='$k'>$($data[$k])</Data>" }
    "<Event><System><EventID>$id</EventID><TimeCreated SystemTime='2026-03-04T09:00:00.0000000Z'/><EventRecordID>$rec</EventRecordID><Computer>DC01</Computer></System><EventData>$d</EventData></Event>"
  }
  $evs += & $mk 1 4624 @{ LogonType = '3' }        # keep: network logon
  $evs += & $mk 2 4624 @{ LogonType = '2' }        # drop: interactive
  $evs += & $mk 3 4624 @{ LogonType = '10' }       # keep: RDP
  $evs += & $mk 4 4769 @{ TicketEncryptionType = '0x17' }   # keep: RC4
  $evs += & $mk 5 4769 @{ TicketEncryptionType = '0x12' }   # drop: AES
  $evs += & $mk 6 4776 @{ Status = '0xC000006A' }  # keep: failure
  $evs += & $mk 7 4776 @{ Status = '0x0' }         # drop: success
  $evs += & $mk 8 4720 @{ TargetUserName = 'x' }   # keep: not a noisy ID
  $evs += & $mk 9 4662 @{ ObjectType = 'domainDNS' }  # keep
  $evs += & $mk 10 4776 @{ PackageName = 'NTLM' }  # keep: no Status at all
  $evs += & $mk 11 4769 @{ TicketEncryptionType = '23' }    # keep: decimal RC4 form
  $doc = New-Object System.Xml.XmlDocument
  $doc.LoadXml('<Events>' + ($evs -join '') + '</Events>')
  # The ID/data disjunction is what can silently DROP an event the engine needed,
  # so it is evaluated here for real against a document shaped like the event
  # log's XML view. (The time predicate is validated by shape instead: it is a
  # string range comparison that only the event log's own engine performs - a
  # plain XPath 1.0 engine coerces '>=' to numbers and gets NaN.)
  # Context matters: the event log evaluates the Select path with the Events
  # collection as the context node, so '*' means "each Event".
  $xpath = "*[" + (Get-ChannelIdDisjuncts $ids) + "]"
  $selected = @($doc.DocumentElement.SelectNodes($xpath) | ForEach-Object { $_.SelectSingleNode('.//*[local-name()="EventRecordID"]').InnerText })
  $expected = @('1', '3', '4', '6', '8', '9', '10', '11')
  Assert-True ($selected.Count -eq $expected.Count) ('the pre-filter selects ' + $selected.Count + ' of 11 events (expected ' + $expected.Count + ')')
  $diff = @($expected | Where-Object { $selected -notcontains $_ })
  Assert-True ($diff.Count -eq 0) ('nothing the engine needs is dropped (missing: ' + ($diff -join ',') + ')')
  Assert-True ($selected -notcontains '2') 'a routine interactive logon is filtered out in the query'
  Assert-True ($selected -notcontains '5') 'an AES service ticket is filtered out'
  Assert-True ($selected -notcontains '7') 'a successful NTLM validation is filtered out'
  Assert-True ($selected -contains '10') 'an event with no Status field is kept (the engine decides)'
  Assert-True ($selected -contains '11') 'the decimal RC4 form is kept, matching the engine'

  # fallback when the provider rejects the XPath
  Reset-Engine
  foreach ($source in $LogSources) { $Script:ChannelMarks[$source.Log] = (Get-Date).AddMinutes(-2) }
  $script:FakeFailXml = $true
  $script:FakeCalls = @()
  $script:FakeEvents = @(New-FakeEvent 4720 900200 (Get-Date).AddSeconds(-20) @{ TargetUserName = 'fallbackUser'; SubjectUserName = 'administrator' })
  $rf = Invoke-PollOnce
  Assert-True ($script:FakeCalls -contains 'FilterHashtable') 'a rejected XPath falls back to the plain Id filter'
  Assert-True ($Script:XPathFallback['Security']) 'the fallback is remembered for that channel'
  Assert-True ($rf.Alerts -eq 1) 'the poll still processes events after falling back'
  $script:FakeCalls = @()
  $null = Invoke-PollOnce
  Assert-True (-not ($script:FakeCalls -contains 'FilterXml')) 'later polls skip the XPath that the provider already rejected'
  $script:FakeFailXml = $false

  Write-Host ""
  Write-Host "== v2.2 hardening: web DoS, catch-up, sessions, paging ==" -ForegroundColor Cyan

  # --- request bodies are refused BEFORE they are read ----------------------
  Assert-True ($Script:MaxLoginBodyBytes -eq 8192) 'the login route body budget is 8192 bytes'
  Assert-True ($Script:MaxJsonBodyBytes -eq 65536) 'the general route body budget is 65536 bytes'

  # a request context with a declared body length, like HttpListener hands us
  function New-BodyContext([int64]$Length, $TransferEncoding = $null, [string]$Body = '') {
    $stream = New-Object System.IO.MemoryStream
    if ($Body) {
      $bytes = [Text.Encoding]::UTF8.GetBytes($Body)
      $stream.Write($bytes, 0, $bytes.Length)
      $stream.Position = 0
    }
    $req = New-Object PSObject
    $req | Add-Member -MemberType NoteProperty -Name ContentLength64 -Value $Length -Force
    $req | Add-Member -MemberType NoteProperty -Name TransferEncoding -Value $TransferEncoding -Force
    $req | Add-Member -MemberType NoteProperty -Name InputStream -Value $stream -Force
    $req | Add-Member -MemberType NoteProperty -Name ContentEncoding -Value ([Text.Encoding]::UTF8) -Force
    $ctx = New-Object PSObject
    $ctx | Add-Member -MemberType NoteProperty -Name Request -Value $req -Force
    return $ctx
  }

  Assert-True ($null -eq (Test-BodyAllowed (New-BodyContext 8192) $Script:MaxLoginBodyBytes)) 'a login body at exactly 8192 bytes is allowed'
  Assert-True ((Test-BodyAllowed (New-BodyContext 8193) $Script:MaxLoginBodyBytes).Status -eq 413) 'a login body one byte over is refused with 413'
  Assert-True ($null -eq (Test-BodyAllowed (New-BodyContext 65536) $Script:MaxJsonBodyBytes)) 'a triage body at the general limit is allowed'
  Assert-True ((Test-BodyAllowed (New-BodyContext 65537) $Script:MaxJsonBodyBytes).Status -eq 413) 'a triage body over the general limit is refused with 413'
  Assert-True ((Test-BodyAllowed (New-BodyContext -1)).Status -eq 411) 'a body with no Content-Length is refused with 411'
  Assert-True ((Test-BodyAllowed (New-BodyContext 100 @('chunked'))).Status -eq 411) 'a chunked body is refused with 411 (its size is only knowable by reading it)'
  Assert-True ($null -eq (Read-JsonBody (New-BodyContext 70000 $null '{"u":"aaaa"}'))) 'Read-JsonBody reads nothing at all when the body is over the limit'
  Assert-True ($null -eq (Read-JsonBody (New-BodyContext 0))) 'an empty POST body is not an error (the drain path)'
  Assert-True ((Read-JsonBody (New-BodyContext 12 $null '{"a":"bbbb"}')).a -eq 'bbbb') 'Read-JsonBody still parses a normal JSON body'

  $web = Get-Section $raw $mWeb $mProbes
  Assert-True ($web.Contains('Test-BodyAllowed $ctx $bodyLimit')) 'the handler checks the body budget before the route switch'
  Assert-True ($web.Contains('$Script:BodyRejections++')) 'a refused body is counted'
  Assert-True ($web.Contains('TimeoutManager.EntityBody')) 'the listener bounds how long a client may take to send a body'
  Assert-True ($web.Contains('TimeoutManager.DrainEntityBody')) 'and how long we wait to drain one we did not read'
  Assert-True ($web.Contains('$bodyLimit = $Script:MaxLoginBodyBytes }')) 'the login route still reads with the smaller budget'
  Assert-True ($web.Contains('$bodyParsed = Read-JsonBody $ctx $bodyLimit')) 'and the budget is the one handed to the bounded reader'

  # --- the public health probe leaks nothing; the counters moved behind auth --
  $hStart = $web.IndexOf("'^/api/health" + [char]36)
  $sStart = $web.IndexOf("'^/api/status" + [char]36)
  Assert-True ($hStart -ge 0 -and $sStart -gt $hStart) 'the health and status routes both exist, health first'
  $healthBlock = $web.Substring($hStart, $sStart - $hStart)
  Assert-True ($healthBlock.Contains('{"ok":true}')) 'the health route answers exactly {"ok":true}'
  Assert-True (-not ($healthBlock -match 'lagSeconds|evalErrors|alerts|uptimeSeconds|usersConfigured')) 'the health route carries no counters, lag or alert data'
  Assert-True (-not ($healthBlock -match 'Get-|Where-Object')) 'and does no work beyond answering'
  Assert-True ($web.Contains('catchingUpThreshold = $catch.threshold')) 'the status payload publishes the catch-up verdict'
  Assert-True ($web.Contains('bodyRejections      = $Script:BodyRejections')) 'and the body-rejection counter'
  Assert-True ($web.Contains('sessions            = @($Script:Sessions.Keys).Count')) 'and how many sessions are open'
  Assert-True (-not $web.Contains('catchingUp       = ($lagMax -gt 2)')) 'the old lag > 2 catch-up test is gone from the server'

  # --- an idle system is not "catching up" (dashboard mirrors the rule) ------
  $savedPollSeconds = $PollSeconds
  $PollSeconds = 15
  $Script:LastPollCapped = $false
  $c = Get-CatchUpState 20
  Assert-True (-not $c.catchingUp) 'idle: one poll interval of lag (20s on a 15s poll) is NOT catching up'
  Assert-True ($c.threshold -eq 35) 'the threshold is two poll intervals plus the 5s overlap (35s)'
  Assert-True (-not (Get-CatchUpState 34).catchingUp) 'lag just under the threshold is still idle'
  Assert-True ((Get-CatchUpState 36).catchingUp) 'lag past the threshold IS catching up'
  $Script:LastPollCapped = $true
  Assert-True ((Get-CatchUpState 5).catchingUp) 'a poll that had to defer events is catching up whatever the lag'
  Assert-True ((Get-CatchUpState 5).capped) 'and the verdict reports the capped flag'
  $Script:LastPollCapped = $false

  Reset-Engine
  foreach ($source in $LogSources) { $Script:ChannelMarks[$source.Log] = (Get-Date).AddMinutes(-2) }
  $script:FakeEvents = @()
  $null = Invoke-PollOnce
  Assert-True (-not $Script:LastPollCapped) 'a poll that deferred nothing clears the capped flag'
  Assert-True (-not (Get-CatchUpState 20).catchingUp) 'so the tool reads as idle despite a poll interval of lag'

  $js = Get-Content -Raw (Join-Path (Split-Path -Parent $PSScriptRoot) 'dashboard.js')
  Assert-True ($js.Contains('function isCatchingUp')) 'dashboard.js has the shared catch-up rule'
  Assert-True ($js.Contains("api('/status')")) 'the dashboard reads the authenticated /api/status, not the bare probe'
  Assert-True (-not $js.Contains('lag > 2')) 'the old lag > 2 pill test is gone from the dashboard'
  Assert-True ($js.Contains('(poll * 2) + 5')) 'and the JS threshold is the same formula as the server'
  $PollSeconds = $savedPollSeconds

  # --- a session dies with its account --------------------------------------
  Reset-Engine
  $live = New-Session 'maty'
  Assert-True ($null -ne (Get-Session $live)) 'a session opened against the current users file is live'
  Assert-True ("$($Script:Sessions[$live].UserStamp)".Length -gt 0) 'the session records the account revision it was opened against'

  Start-Sleep -Milliseconds 30
  $same = Get-Content -Raw $UsersFile
  $same | Set-Content -Path $UsersFile -Encoding UTF8
  Assert-True ($null -ne (Get-Session $live)) 'rewriting the file with unchanged records does not end the session'

  Start-Sleep -Milliseconds 30
  $reset = $same -replace '2026-03-04T09:00:00\.0000000Z', '2026-03-05T11:22:33.0000000Z'
  $reset | Set-Content -Path $UsersFile -Encoding UTF8
  Assert-True ($null -eq (Get-Session $live)) 'a -Reset (record rewritten, new updated stamp) ends the existing session'
  Assert-True (-not $Script:Sessions.ContainsKey($live)) 'the session is dropped, not merely refused'
  Assert-True ($Script:UsersRevoked -ge 1) 'and the revocation is counted'

  $fresh = New-Session 'admin'
  Assert-True ($null -ne (Get-Session $fresh)) 'an account whose record was untouched survives the same file change'

  Start-Sleep -Milliseconds 30
  $fmaty = New-Session 'maty'
  Assert-True ($null -ne (Get-Session $fmaty)) 'a session opened after the reset is live'
  $null = Update-UsersFingerprint
  $adminStamp = "$($Script:UsersUpdated['admin'])"
  $onlyAdmin = @{ version = 1; users = @([PSCustomObject]@{
    user = 'admin'; salt = 'aabb'; hash = 'ccdd'; iterations = 150000
    created = '2026-03-04T09:05:00.0000000Z'; updated = $adminStamp }) } | ConvertTo-Json -Depth 5
  Start-Sleep -Milliseconds 30
  $onlyAdmin | Set-Content -Path $UsersFile -Encoding UTF8
  Assert-True ($null -eq (Get-Session $fmaty)) 'removing the account from the store (-Remove) ends its session'
  Assert-True (-not $Script:Sessions.ContainsKey($fmaty)) 'and that session is dropped too'
  $same | Set-Content -Path $UsersFile -Encoding UTF8
  Assert-True ((Get-Content -Raw $Script).Contains('$null = Revoke-StaleSessions')) 'Get-Session re-checks the account store on every call'

  # --- the watermark overlaps by 5s and the overlap is not double-counted ---
  Reset-Engine
  foreach ($source in $LogSources) { $Script:ChannelMarks[$source.Log] = (Get-Date).AddMinutes(-2) }
  $script:FakeEvents = @(New-FakeEvent 4720 910100 (Get-Date) @{ TargetUserName = 'overlapUser'; SubjectUserName = 'administrator' })
  $before = Get-Date
  $o1 = Invoke-PollOnce
  $mark = Get-ChannelMark 'Security'
  Assert-True ($o1.Alerts -eq 1) 'the event alerts on the first poll'
  Assert-True ($mark -lt $before.AddSeconds(-3)) 'an uncapped poll backdates the watermark by about 5s'
  Assert-True ($mark -gt $before.AddSeconds(-8)) 'and by no more than that'
  $o2 = Invoke-PollOnce
  Assert-True ($o2.Evaluated -eq 0) 'the overlap re-read is dropped by the seen-record ring'
  Assert-True ($o2.Alerts -eq 0) 'so the overlap raises no duplicate alert'

  # --- a capped poll reads only what it is going to process ----------------
  Reset-Engine
  foreach ($source in $LogSources) { $Script:ChannelMarks[$source.Log] = (Get-Date).AddMinutes(-30) }
  $page = New-Object System.Collections.ArrayList
  $pageBase = (Get-Date).AddMinutes(-25)
  for ($i = 0; $i -lt 1200; $i++) {
    [void]$page.Add((New-FakeEvent 4720 (930000 + $i) $pageBase.AddMilliseconds($i * 10) @{ TargetUserName = "page$i"; SubjectUserName = 'administrator' }))
  }
  $script:FakeEvents = @($page)
  $script:FakeParams = @()
  $p1 = Invoke-PollOnce
  $p1sec = @($script:FakeParams | Where-Object { $_.Channel -eq 'Security' })
  Assert-True ($p1sec.Count -ge 1) 'the Security channel queried the provider'
  Assert-True ($p1sec[0].MaxEvents -eq ($MaxEventsPerPoll + 1)) 'a capped poll asks the provider for exactly cap+1 events'
  Assert-True ($p1sec[0].Oldest) 'and asks for them oldest-first'
  Assert-True ($p1.Capped) 'the poll reports that it was capped'
  Assert-True ($p1.Evaluated -eq $MaxEventsPerPoll) 'and processed exactly one page, not the whole backlog'
  $markAfter1 = Get-ChannelMark 'Security'
  $p2 = Invoke-PollOnce
  Assert-True ($p2.Evaluated -ge ($MaxEventsPerPoll - 1)) 'the next poll reads the following page (the one event on the window boundary is deduped by the seen-record ring)'
  Assert-True ($p2.Capped) 'and it is still capped, because 1200 events do not fit in one page'
  Assert-True ((Get-ChannelMark 'Security') -gt $markAfter1) 'and the watermark advanced with it'
  Assert-True (@($script:FakeParams | Where-Object { $_.Channel -eq 'Security' -and $_.Oldest }).Count -ge 2) 'every windowed query asked for the oldest events, not the newest'

  # drain the rest: paging must not lose an event or alert twice across a boundary
  $guard = 0
  while ($guard -lt 10) {
    $pn = Invoke-PollOnce
    $guard++
    if (-not $pn.Capped) { break }
  }
  Assert-True ($guard -le 4) ('the whole 1200-event backlog drains in a few pages (actual ' + $guard + ' more poll(s))')
  Assert-True (@($Script:Alerts | Where-Object { $_.RuleKey -eq 'account_created' }).Count -eq 1200) 'all 1200 events alerted exactly once: nothing lost and nothing duplicated across page boundaries'

  # --- PBKDF2 is built with New-Object and is really PBKDF2-HMAC-SHA1 -------
  $salt6070 = [byte[]]@(0x73, 0x61, 0x6c, 0x74)
  $vectors = @(
    @{ Iterations = 1;    Expect = '0c60c80f961f0e71f3a9b524af6012062fe037a6' },
    @{ Iterations = 2;    Expect = 'ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957' },
    @{ Iterations = 4096; Expect = '4b007901b765489abead49d926f721d065a429c1' }
  )
  foreach ($v in $vectors) {
    $hex = ((Get-PasswordHash 'password' $salt6070 $v.Iterations) | ForEach-Object { $_.ToString('x2') }) -join ''
    Assert-True ($hex.Substring(0, 40) -eq $v.Expect) ("PBKDF2-HMAC-SHA1 matches RFC 6070 at " + $v.Iterations + " iteration(s)")
  }
  $monText = Get-Content -Raw $Script
  $admText = Get-Content -Raw (Join-Path (Split-Path -Parent $PSScriptRoot) 'New-SentinelAdmin.ps1')
  Assert-True (-not ($monText -match 'Rfc2898DeriveBytes\]::new')) 'AlphaSentinel.ps1 no longer uses [Type]::new() for the KDF'
  Assert-True (-not ($admText -match 'Rfc2898DeriveBytes\]::new')) 'New-SentinelAdmin.ps1 no longer uses [Type]::new() for the KDF'
  Assert-True ($monText.Contains('New-Object -TypeName System.Security.Cryptography.Rfc2898DeriveBytes')) 'it constructs the KDF with New-Object instead'

  Write-Host ""
  Write-Host "== v2.3 part 1: a stalled body cannot freeze the loop ==" -ForegroundColor Cyan

  Assert-True ([bool]('SentinelBody' -as [type])) 'the C# body reader is compiled and available'
  Assert-True ($Script:BodyReadMs -eq 2000) 'a client gets 2s to deliver the body it declared'

  # --- the helper: reads exactly what was promised, or gives up -------------
  $exact = [Text.Encoding]::UTF8.GetBytes('{"a":"bbbb"}')
  $ms = New-Object System.IO.MemoryStream
  $ms.Write($exact, 0, $exact.Length); $ms.Position = 0
  $got = [SentinelBody]::Read($ms, $exact.Length, 2000)
  Assert-True ($null -ne $got -and $got.Length -eq $exact.Length) 'Read returns exactly the promised bytes'
  $msEarly = New-Object System.IO.MemoryStream
  $msEarly.Write($exact, 0, 4); $msEarly.Position = 0
  Assert-True ($null -eq [SentinelBody]::Read($msEarly, $exact.Length, 500)) 'Read returns null when the stream ends early'
  $zero = [SentinelBody]::Read((New-Object System.IO.MemoryStream), 0, 500)
  Assert-True ($null -ne $zero -and $zero.Length -eq 0) 'an empty body reads as an empty array, not null'

  # a loopback socket pair is a real stall: the reader blocks until bytes arrive
  function New-StallPair {
    $l = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
    $l.Start()
    $cli = New-Object System.Net.Sockets.TcpClient
    $cli.Connect('127.0.0.1', [int]$l.LocalEndpoint.Port)
    $srv = $l.AcceptTcpClient()
    return [PSCustomObject]@{ Listener = $l; Client = $cli; Server = $srv; Stream = $srv.GetStream() }
  }
  function Close-StallPair($p) {
    try { $p.Client.Close() } catch { }
    try { $p.Server.Close() } catch { }
    try { $p.Listener.Stop() } catch { }
  }
  # a request context with a declared length, a stream and an abortable response
  function New-BodyContext2([int64]$Length, $Stream, $TransferEncoding = $null) {
    $req = New-Object PSObject
    $req | Add-Member -MemberType NoteProperty -Name ContentLength64 -Value $Length -Force
    $req | Add-Member -MemberType NoteProperty -Name TransferEncoding -Value $TransferEncoding -Force
    $req | Add-Member -MemberType NoteProperty -Name InputStream -Value $Stream -Force
    $req | Add-Member -MemberType NoteProperty -Name ContentEncoding -Value ([Text.Encoding]::UTF8) -Force
    $resp = New-Object PSObject
    $resp | Add-Member -MemberType NoteProperty -Name Aborted -Value $false -Force
    $resp | Add-Member -MemberType ScriptMethod -Name Abort -Value { $this.Aborted = $true } -Force
    $ctx = New-Object PSObject
    $ctx | Add-Member -MemberType NoteProperty -Name Request -Value $req -Force
    $ctx | Add-Member -MemberType NoteProperty -Name Response -Value $resp -Force
    return $ctx
  }

  $pair = New-StallPair
  $sw = [Diagnostics.Stopwatch]::StartNew()
  $abandoned = [SentinelBody]::Read($pair.Stream, 100, $Script:BodyReadMs)
  $sw.Stop()
  Assert-True ($null -eq $abandoned) 'a client that declares 100 bytes and sends none is abandoned'
  Assert-True ($sw.Elapsed.TotalSeconds -lt 3) ('and abandoned within ~3s (took ' + [Math]::Round($sw.Elapsed.TotalSeconds, 2) + 's)')
  Close-StallPair $pair

  # --- Read-JsonBody: abandons, flags, counts, aborts -----------------------
  Reset-Engine
  $pair2 = New-StallPair
  $ctx2 = New-BodyContext2 50 $pair2.Stream
  $sw2 = [Diagnostics.Stopwatch]::StartNew()
  $body2 = Read-JsonBody $ctx2
  $sw2.Stop()
  Assert-True ($null -eq $body2) 'Read-JsonBody returns null for a stalled body instead of blocking'
  Assert-True ($sw2.Elapsed.TotalSeconds -lt 3) 'and gives up inside ~3s rather than holding the loop'
  Assert-True ($Script:BodyTimedOut) 'it flags BodyTimedOut for the route that called it'
  Assert-True ($Script:BodyTimeouts -eq 1) 'and counts the timeout'
  Assert-True ($Script:BodyRejections -eq 0) 'a stall is a timeout, not a size/411 rejection'
  Assert-True ($ctx2.Response.Aborted) 'it aborts the connection so the socket is not left half-read'
  Close-StallPair $pair2

  # a body that actually arrives still parses
  $pair3 = New-StallPair
  $ctx3 = New-BodyContext2 12 $pair3.Stream
  $pay = [Text.Encoding]::UTF8.GetBytes('{"a":"bbbb"}')
  $pair3.Client.GetStream().Write($pay, 0, $pay.Length)
  $pair3.Client.GetStream().Flush()
  $parsed = Read-JsonBody $ctx3
  Assert-True ($null -ne $parsed -and $parsed.a -eq 'bbbb') 'a body that really arrives is still parsed'
  Assert-True (-not $Script:BodyTimedOut) 'and no timeout is flagged for it'
  Close-StallPair $pair3

  # --- three stalls from one address is an attack on the tool ---------------
  Reset-Engine
  $stallIp = '10.9.9.9'
  Assert-True ((Register-BodyStall $stallIp) -eq 1) 'a stalled body is counted against its source address'
  Assert-True (Test-LoginAllowed $stallIp) 'one stall does not block the address'
  Assert-True ((Register-BodyStall $stallIp) -eq 2) 'the second stall is counted'
  Assert-True (Test-LoginAllowed $stallIp) 'nor does the second'
  Assert-True ((Register-BodyStall $stallIp) -eq 3) 'the third stall is counted'
  Assert-True (-not (Test-LoginAllowed $stallIp)) 'the third stall from one address blocks it (the login route answers 429)'
  Assert-True ((Get-LoginRetryAfter $stallIp) -gt 0) 'and the Retry-After it reports is real'
  Assert-True (Test-LoginAllowed '10.9.9.10') 'an unrelated address is unaffected'
  Assert-True ($Script:LoginFailures[$stallIp].Count -ge $Script:MaxLoginFailures) 'the stall counts toward the login-failure budget too'

  # --- the handler is wired up (and reads the body once) --------------------
  $web2 = Get-Section $raw $mWeb $mProbes
  Assert-True ($web2.Contains('$Script:BodyTimedOut = $false')) 'every request starts with a clear stalled flag'
  Assert-True ($web2.Contains('Register-BodyStall $stallIp')) 'a stall registers against the source address in the handler'
  Assert-True ($web2.Contains('request body stalled - connection aborted')) 'and lands in the auth audit trail'
  Assert-True ($web2.Contains('bodyTimeouts        = $Script:BodyTimeouts')) 'the stall counter is exposed on /api/status'
  Assert-True ($web2.Contains('$bodyParsed = Read-JsonBody $ctx $bodyLimit')) 'the handler reads the body once, with the watchdog'
  Assert-True (-not $web2.Contains('# drain the body')) 'the routes no longer read (and re-drain) it themselves'
  Assert-True ((Get-Content -Raw $Script).Contains('[SentinelBody]::Read($ctx.Request.InputStream')) 'Read-JsonBody reads through the bounded C# reader'

  Write-Host ""
  Write-Host "== v2.3 part 2: dashboard backend ==" -ForegroundColor Cyan

  # --- the events ring buffer ----------------------------------------------
  Reset-Engine
  $when = (Get-Date).AddMinutes(-5)
  Add-ObservedEvent 'Security' @{ eventId = '4625'; hostname = 'DC01'; accountName = 'jsmith'; sourceIp = '10.0.0.7'; timestamp = $when.ToString('o') } 'brute_force_single_account' $when
  Add-ObservedEvent 'Security' @{ eventId = '9999'; hostname = 'DC01'; accountName = 'svc'; timestamp = $when.ToString('o') } $null $when
  Assert-True ($Script:ObsEvents.Count -eq 2) 'each evaluated event lands in the ring buffer'
  $keys = @($Script:ObsEvents[0].PSObject.Properties.Name)
  Assert-True ($keys.Count -eq 8) ('a ring entry carries exactly the documented fields (got ' + ($keys -join ',') + ')')
  foreach ($need in @('time', 'eventId', 'channel', 'host', 'user', 'sourceIp', 'summary', 'matchedRule')) {
    Assert-True ($keys -contains $need) ('   ring entry has ' + $need)
  }
  Assert-True ($Script:ObsEvents[1].matchedRule -eq $null) 'matchedRule is null when no rule fired'
  Assert-True ($Script:ObsEvents[0].matchedRule -eq 'brute_force_single_account') 'and carries the rule key when one did'
  Assert-True ("$($Script:ObsEvents[0].summary)".Length -le 120) 'the summary is bounded'
  Assert-True ("$($Script:ObsEvents[0].summary)" -match 'Failed logon - jsmith') 'and is generated text, not the event body'
  Assert-True ("$($Script:ObsEvents[1].summary)" -match 'Event 9999') 'an unknown event id still gets a usable label'

  # a secret must never reach the ring buffer, whatever the event carried
  Add-ObservedEvent 'Security' @{ eventId = '4698'; hostname = 'DC01'; commandLine = 'powershell -enc S3CR3T'; taskContent = 'S3CR3T'; password = 'S3CR3T' } $null $when
  $last = $Script:ObsEvents[$Script:ObsEvents.Count - 1]
  $serialised = ($last | ConvertTo-Json -Compress)
  Assert-True (-not $serialised.Contains('S3CR3T')) 'no field of the raw event (command line, task content, password) reaches the buffer'

  # the cap keeps the newest 300
  for ($i = 0; $i -lt 320; $i++) {
    Add-ObservedEvent 'Security' @{ eventId = '4624'; hostname = 'DC02'; accountName = "u$i"; timestamp = $when.AddSeconds($i).ToString('o') } $null ($when.AddSeconds($i))
  }
  Assert-True ($Script:ObsEvents.Count -eq $Script:MaxObsEvents) ('the ring buffer is capped at 300 (got ' + $Script:ObsEvents.Count + ')')
  Assert-True ("$($Script:ObsEvents[$Script:ObsEvents.Count - 1].user)" -eq 'u319') 'and holds the newest entries'
  Assert-True (@($Script:ObsEvents | Where-Object { "$($_.user)" -eq 'jsmith' }).Count -eq 0) 'the oldest entries are the ones evicted'

  # --- hosts seen ----------------------------------------------------------
  Reset-Engine
  Add-ObservedEvent 'Security' @{ eventId = '4625'; hostname = 'DC01'; accountName = 'jsmith'; sourceIp = '10.0.0.7' } $null $when
  Add-ObservedEvent 'Security' @{ eventId = '4625'; hostname = 'DC01'; accountName = 'jsmith'; sourceIp = '10.0.0.7' } $null $when
  Add-ObservedEvent 'Security' @{ eventId = '4720'; hostname = 'DC01'; accountName = 'svc'; sourceIp = '10.0.0.8' } $null $when
  $hosts = Get-HostsPayload
  Assert-True ($hosts.Count -eq 1) 'one host is tracked'
  Assert-True ($hosts[0].eventCount -eq 3) 'every event counts toward its host'
  Assert-True ($hosts[0].users.Count -eq 2) 'users are collected per host'
  Assert-True ($hosts[0].ips.Count -eq 2) 'and so are source addresses'
  Assert-True (@($hosts[0].users | Where-Object { $_ -eq 'jsmith' }).Count -eq 1) 'a repeated user is not duplicated'
  Assert-True ($hosts[0].alertCount -eq 0) 'no alerts counted yet'
  $al = New-Alert 'account_created' 'seeded' $null @{ hostname = 'DC01'; accountName = 'svc'; eventId = '4720' }
  $Script:Alerts.Add($al); Add-ObservedAlert $al
  $hosts = Get-HostsPayload
  Assert-True ($hosts[0].alertCount -eq 1) 'a raised alert counts toward its host'

  # hosts are capped: the oldest lastSeen is evicted
  Reset-Engine
  for ($i = 0; $i -lt 210; $i++) {
    Add-ObservedEvent 'Security' @{ eventId = '4624'; hostname = "HOST$i" } $null $when.AddSeconds($i)
  }
  Assert-True ($Script:ObsHosts.Count -eq $Script:MaxObsHosts) ('the host map is capped at 200 (got ' + $Script:ObsHosts.Count + ')')
  Assert-True (-not $Script:ObsHosts.ContainsKey('HOST0')) 'the least recently seen host is evicted'
  Assert-True ($Script:ObsHosts.ContainsKey('HOST209')) 'and the newest is kept'

  # --- hourly buckets ------------------------------------------------------
  Reset-Engine
  $base = (Get-Date).AddHours(-5)
  Add-ObservedEvent 'Security' @{ eventId = '4625'; hostname = 'DC01'; accountName = 'a' } $null $base
  Add-ObservedEvent 'Security' @{ eventId = '4625'; hostname = 'DC01'; accountName = 'b' } $null $base.AddMinutes(1)
  $hb = Get-HourBucket $base
  Assert-True ($hb.events -eq 2) 'events are counted into their hour'
  Assert-True ($Script:ObsHours.Count -eq 1) 'one bucket so far'
  $crit = New-Alert 'privilege_escalation' 'seeded crit' $null @{ hostname = 'DC01'; accountName = 'attacker'; eventId = '4728' }
  $Script:Alerts.Add($crit); Add-ObservedAlert $crit
  $hb2 = Get-HourBucket (Get-Date)
  Assert-True ($hb2.alertSev['Critical'] -eq 1) 'alerts are counted by severity into their hour'
  Assert-True ($hb2.tactics['Privilege Escalation'] -eq 1) 'and by MITRE tactic'
  Assert-True ($Script:ObsHours.Count -eq 2) 'a later event opens a new bucket'
  # 24 kept
  for ($i = 0; $i -lt 30; $i++) { $null = Get-HourBucket ((Get-Date).AddHours(-$i)) }
  Assert-True ($Script:ObsHours.Count -le 24) ('only the last 24 hourly buckets are kept (got ' + $Script:ObsHours.Count + ')')

  # --- mitre helpers -------------------------------------------------------
  $mp = Get-MitreParts 'T1098.003 - Account Manipulation'
  Assert-True ($mp.id -eq 'T1098.003' -and $mp.name -eq 'Account Manipulation') 'a technique id and name are split out'
  $mp = Get-MitreParts 'T1018 - Remote System Discovery / T1087 - Account Discovery'
  Assert-True ($mp.id -eq 'T1018' -and $mp.name -eq 'Remote System Discovery') 'a rule naming two techniques reports the first'
  Assert-True ((Get-MitreParts 'T1078').id -eq 'T1078') 'a bare id still parses'
  Assert-True ((Get-MitreTactic 'Identity Abuse') -eq 'Privilege Escalation') 'Identity Abuse maps onto a real tactic'
  Assert-True ((Get-MitreTactic 'Discovery') -eq 'Discovery') 'every other category is already a tactic'

  # --- the alert object a drawer and kill-chain need -----------------------
  Reset-Engine
  $a1 = Feed 4728 @{ MemberName = 'attacker'; TargetUserName = 'Domain Admins'; SubjectUserName = 'administrator'; hostname = 'DC01' }
  Assert-True ($null -ne $a1) 'an alert was raised'
  foreach ($need in @('Status', 'Acknowledged', 'MitreId', 'MitreName', 'Tactic', 'Entity', 'RuleKey', 'FirstSeen', 'LastSeen', 'Count', 'Events')) {
    Assert-True ($a1.PSObject.Properties.Name -contains $need) ('   alert exposes ' + $need)
  }
  Assert-True ($a1.Status -eq 'New') 'status starts at New (the four-value vocabulary)'
  Assert-True ($a1.Acknowledged -eq $false) 'acknowledged is a separate boolean'
  Assert-True ("$($a1.MitreId)" -match '^T\d{4}') 'the MITRE technique id is exposed'
  Assert-True ("$($a1.MitreName)".Length -gt 0) 'with its name'
  Assert-True ($a1.Tactic -eq 'Privilege Escalation') 'and the tactic'
  Assert-True ("$($a1.Entity)" -eq 'attacker') 'the entity it fired on is exposed'
  Assert-True ($a1.Count -eq 1) 'a new alert counts one contributing event'
  Assert-True ($a1.Events.Count -eq 1 -and "$($a1.Events[0].summary)".Length -gt 0) 'and carries that event as a summary'

  # a repeat inside the dedupe window contributes instead of duplicating
  $before = $Script:Alerts.Count
  $a2 = Feed 4728 @{ MemberName = 'attacker'; TargetUserName = 'Domain Admins'; SubjectUserName = 'administrator'; hostname = 'DC01' }
  Assert-True ($Script:Alerts.Count -eq $before) 'a deduped repeat does not create a second alert'
  Assert-True ($a1.Count -eq 2) 'but is counted on the open alert'
  Assert-True ($a1.Events.Count -eq 2) 'and joins its contributing events (the kill-chain timeline)'
  Assert-True ("$($a1.LastSeen)" -ge "$($a1.FirstSeen)") 'last-seen moves forward'

  # --- /api/overview ------------------------------------------------------
  Reset-Engine
  $ov = Get-OverviewPayload
  foreach ($need in @('tiles', 'deltas', 'coverage', 'severityCounts', 'tacticCounts', 'hourly', 'lastPoll', 'health', 'version')) {
    Assert-True ($ov.PSObject.Properties.Name -contains $need) ('   overview has ' + $need)
  }
  foreach ($need in @('openAlerts', 'critical', 'high', 'eventsLastHour', 'hostsSeen')) {
    Assert-True ($ov.tiles.PSObject.Properties.Name -contains $need) ('   tiles have ' + $need)
    Assert-True ($ov.deltas.PSObject.Properties.Name -contains $need) ('   deltas have ' + $need)
  }
  Assert-True ($ov.version -eq $Script:SentinelVersion) 'the overview reports the version'
  Assert-True ($ov.coverage.rulesTotal -eq $RuleMeta.Count) 'coverage counts every rule family'
  Assert-True ($ov.coverage.percent -eq 100) 'with the policy unreadable no rule is called blind, so coverage is 100%'
  Assert-True ($ov.health -eq 'ok') 'and health is ok'
  Assert-True ((Get-OverviewPayload).tiles.openAlerts -eq 0) 'an idle system has no open alerts'

  # a blind family drops coverage and flips health to blind
  $gated = @(Get-RuleCatalog | Where-Object { "$($_.auditSubcategory)" } | Select-Object -First 1)
  $sub = ("$($gated[0].auditSubcategory)" -split ' \+ ')[0].ToLower()
  $Script:AuditState = @{}
  $Script:AuditState[$sub] = 'No Auditing'
  $ovb = Get-OverviewPayload
  Assert-True ($ovb.coverage.rulesBlind -ge 1) 'a family whose audit subcategory is off is counted blind'
  Assert-True ($ovb.coverage.percent -lt 100) 'and coverage drops below 100%'
  Assert-True ($ovb.coverage.rulesWorking -eq ($ovb.coverage.rulesTotal - $ovb.coverage.rulesBlind)) 'working = total - blind'
  Assert-True ($ovb.coverage.blindRules.Count -ge 1) 'the blind rules are listed for the Rules page'
  Assert-True ("$($ovb.coverage.blindRules[0].reason)".Length -gt 0) 'each with the reason it cannot fire'
  Assert-True ($ovb.health -eq 'blind') 'health reports blind when a family cannot fire'
  $Script:AuditState = $null
  Assert-True ((Get-OverviewPayload).health -eq 'ok') 'and returns to ok when it can be read again'

  # --- /api/events --------------------------------------------------------
  Reset-Engine
  for ($i = 0; $i -lt 5; $i++) {
    Add-ObservedEvent 'Security' @{ eventId = '4625'; hostname = 'DC01'; accountName = 'jsmith'; sourceIp = '10.0.0.9' } 'brute_force_single_account' $when.AddSeconds($i)
  }
  Add-ObservedEvent 'System' @{ eventId = '7045'; hostname = 'DC02'; accountName = 'svc' } 'service_abuse' $when.AddSeconds(9)
  # NOTE: ",$q" - a bare "return $q" makes PowerShell enumerate the collection
  # into the pipeline, so the caller receives a string array (or nothing at all)
  # instead of a query string. That cost a debugging round; do not remove the comma.
  function New-Query($pairs) {
    $q = New-Object System.Collections.Specialized.NameValueCollection
    foreach ($k in $pairs.Keys) { $q.Add($k, "$($pairs[$k])") }
    return ,$q
  }
  $ev = Get-EventsPayload (New-Query @{})
  Assert-True ($ev.count -eq 6 -and $ev.total -eq 6) 'no filter returns everything'
  Assert-True ($ev.limit -eq 100) 'with a default limit of 100'
  Assert-True ("$($ev.events[0].eventId)" -eq '7045') 'newest first'
  $ev = Get-EventsPayload (New-Query @{ limit = '2' })
  Assert-True ($ev.count -eq 2 -and $ev.total -eq 6) 'limit slices the rows but still reports the total'
  $ev = Get-EventsPayload (New-Query @{ limit = '9999' })
  Assert-True ($ev.limit -eq $Script:MaxObsEvents) 'a limit above the cap is clamped to 300'
  $ev = Get-EventsPayload (New-Query @{ limit = 'nonsense' })
  Assert-True ($ev.limit -eq 100) 'a non-numeric limit falls back to the default'
  $ev = Get-EventsPayload (New-Query @{ limit = '-5' })
  Assert-True ($ev.limit -eq 100) 'a negative limit falls back to the default'
  $ev = Get-EventsPayload (New-Query @{ eventId = '4625' })
  Assert-True ($ev.count -eq 5) 'the eventId filter works'
  $ev = Get-EventsPayload (New-Query @{ eventId = 'abc' })
  Assert-True ($ev.status -eq 400 -and $ev.error) 'a non-numeric eventId is refused with 400'
  $ev = Get-EventsPayload (New-Query @{ host = 'DC02' })
  Assert-True ($ev.count -eq 1 -and "$($ev.events[0].host)" -eq 'DC02') 'the host filter is exact'
  $ev = Get-EventsPayload (New-Query @{ user = 'JS' })
  Assert-True ($ev.count -eq 0) 'the user filter is exact, not a prefix match'
  $ev = Get-EventsPayload (New-Query @{ user = 'jsmith' })
  Assert-True ($ev.count -eq 5) 'and matches the real user'
  $ev = Get-EventsPayload (New-Query @{ q = 'failed logon' })
  Assert-True ($ev.count -eq 5) 'q is a plain substring match over the summary'
  $ev = Get-EventsPayload (New-Query @{ q = '.*' })
  Assert-True ($ev.count -eq 0) 'q is never treated as a regular expression'

  # --- /api/settings must not leak a secret --------------------------------
  Reset-Engine
  $st = Get-SettingsPayload
  Assert-True ($st.version -eq $Script:SentinelVersion) 'settings reports the version'
  Assert-True ($st.pollSeconds -eq $PollSeconds) 'and the poll interval'
  Assert-True ($st.rateLimit.maxLoginFailures -eq $Script:MaxLoginFailures) 'the rate limits are exposed'
  Assert-True ($st.rateLimit.bodyReadMs -eq $Script:BodyReadMs) 'including the body watchdog'
  Assert-True ($st.users.Count -ge 1) 'the configured accounts are listed'
  $userFields = @($st.users[0].PSObject.Properties.Name)
  Assert-True (($userFields -contains 'user') -and ($userFields -contains 'created')) 'each with a name and a creation date'
  Assert-True ((($userFields -contains 'hash') -or ($userFields -contains 'salt')) -eq $false) 'and nothing else'
  Assert-True (-not ($st.users.PSObject.Properties.Name -contains 'hash') -and -not ($st.users.PSObject.Properties.Name -contains 'salt')) 'with no hash or salt'
  $stJson = ($st | ConvertTo-Json -Depth 6 -Compress)
  foreach ($needle in @($ForwardKey, 'iterations', 'sentinel_session', 'sentinel-users.json')) {
    if ($needle -and "$needle".Length -gt 3) {
      Assert-True (-not $stJson.Contains("$needle")) ('   settings output does not contain ' + $needle)
    }
  }
  Assert-True ($st.forwarding.PSObject.Properties.Name -contains 'host') 'forwarding reports a host'
  Assert-True (-not ($st.forwarding.PSObject.Properties.Name -contains 'url')) 'never the full URL'
  Assert-True (-not ($st.forwarding.PSObject.Properties.Name -contains 'key')) 'never the key'

  # --- the endpoints exist, are authenticated and are GET-only --------------
  $web3 = Get-Section $raw $mWeb $mProbes
  foreach ($ep in @('/api/overview', '/api/events', '/api/hosts', '/api/settings')) {
    $routePattern = "'^" + $ep + '$' + "' {"
    Assert-True ($web3.Contains($routePattern)) ("   the handler routes " + $ep)
  }
  Assert-True ($web3.Contains('this endpoint is read-only (GET)')) 'the new endpoints are GET-only'
  Assert-True ($web3.Contains('$ev = Get-EventsPayload $ctx.Request.QueryString')) 'and /api/events is driven by the query string'
  Assert-True (-not $web3.Contains("'/api/overview'")) 'the new routes are exact matches, not prefixes'

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
      if ($a) { $Script:Alerts.Add($a); $fired += $a }
    }
    $keys = @($fired | ForEach-Object { $_.RuleKey })
    $problems = @()
    foreach ($k in @($exp.expect)) { if ($keys -notcontains $k) { $problems += "expected $k to fire" } }
    foreach ($k in @($exp.forbid)) { if ($keys -contains $k) { $problems += "$k must NOT fire" } }
    if ($exp.PSObject.Properties['expectCount'] -and @($exp.expect).Count -gt 0) {
      $c = @($keys | Where-Object { $_ -eq $exp.expect[0] }).Count
      if ($c -ne [int]$exp.expectCount) { $problems += "expected $($exp.expectCount)x $($exp.expect[0]), got $c" }
    }
    if ($exp.PSObject.Properties['expectSeverity']) {
      foreach ($ruleKey in @($exp.expectSeverity.PSObject.Properties.Name)) {
        $want = "$($exp.expectSeverity.$ruleKey)"
        $hit = @($fired | Where-Object { $_.RuleKey -eq $ruleKey })
        if ($hit.Count -eq 0) { $problems += "no $ruleKey alert to check severity" }
        elseif ("$($hit[0].Severity)" -ne $want) { $problems += "$ruleKey severity $($hit[0].Severity), expected $want" }
      }
    }
    if ($problems.Count -eq 0) { Ok ($name + "  -> [" + (@($keys | Select-Object -Unique) -join ', ') + "]") }
    else { Bad ($name + "  -> " + ($problems -join '; ')) }
  }

  Write-Host ""
  $colour = if ($script:Fail -eq 0) { 'Green' } else { 'Red' }
  Write-Host ("RESULT: " + $script:Pass + " passed, " + $script:Fail + " failed") -ForegroundColor $colour
  if ($script:Fail -gt 0) { exit 1 }
} finally {
  Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
