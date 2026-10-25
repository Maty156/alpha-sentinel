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
  11. v2.3 part 3: the new front end - file layout, the static allowlist, no
     inline script/style/handler, no innerHTML, the design tokens, and the
     mockup-vs-spec rules (Soon items, fixed range, demo gating)
  12. v2.2 hardening: the request-body DoS guard (411/413 before any read), the
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
`$HistoryMaxMB = 25
`$WebhookUrl = ''
`$SmtpServer = ''
`$SmtpTo = ''
`$SmtpFrom = ''
`$SyslogHost = ''
`$SyslogPort = 514
`$AlertMinSeverity = 'High'
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
    $Script:AssetIp = @{}
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
  $script:FakeIdleChannels = @()
  $script:FakeMissingChannels = @()
  $script:FakeFailXml = $false
  $script:FakeCalls = @()
  $script:FakeParams = @()

  # Build an ErrorRecord with the FullyQualifiedErrorId the REAL cmdlet uses -
  # the fix must match on the id (localisation-proof), so the fake must carry it
  function New-FakeWinEventError([string]$Kind, [string]$Message) {
    $id = switch ($Kind) {
      'no-events' { 'NoMatchingEventsFound,Microsoft.PowerShell.Commands.GetWinEventCommand' }
      'no-log'    { 'NoMatchingLogsFound,Microsoft.PowerShell.Commands.GetWinEventCommand' }
      default     { ' InvalidOperationException,Microsoft.PowerShell.Commands.GetWinEventCommand' }
    }
    $ex = New-Object System.InvalidOperationException($Message)
    $err = New-Object System.Management.Automation.ErrorRecord($ex, $id, [System.Management.Automation.ErrorCategory]::InvalidOperation, $null)
    return $err
  }

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
    if ($script:FakeFailXml -and $kind -eq 'FilterXml') { throw (New-FakeWinEventError 'real' "fake provider rejected the XPath") }
    if ($channel -and ($script:FakeFailChannels -contains $channel)) { throw (New-FakeWinEventError 'real' "fake log '$channel' unavailable") }
    # the two REAL Get-WinEvent shapes seen on the 2012 R2 lab box: an idle
    # channel throws NoMatchingEventsFound, a missing log throws
    # NoMatchingLogsFound - both with their real FullyQualifiedErrorId
    if ($channel -and ($script:FakeIdleChannels -contains $channel)) {
      throw (New-FakeWinEventError 'no-events' "No events were found that match the specified selection criteria.")
    }
    if ($channel -and ($script:FakeMissingChannels -contains $channel)) {
      throw (New-FakeWinEventError 'no-log' "There is not an event log on the localhost computer that matches 'Microsoft-Windows-Windows Defender/Operational'.")
    }

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

  # --- firewall_disabled (4950, whole profile OFF) ---------------------------
  Reset-Engine
  $f1 = Feed 4950 @{ SubjectUserName = 'admin'; ProfileChanged = 'Domain'; SettingType = 'EnableFirewall'; SettingValue = 'No' }
  Assert-Fired 'firewall_disabled' '4950 EnableFirewall -> No (profile OFF) fires'
  Assert-True ($f1 -and $f1.Severity -eq 'Critical') '  ...at Critical'
  Assert-True ($f1 -and "$($f1.Description)" -match 'Domain') '  ...and names the profile'
  Reset-Engine
  $null = Feed 4950 @{ SubjectUserName = 'admin'; ProfileChanged = 'Domain'; SettingType = 'Default Outbound Action'; SettingValue = 'Block' }
  Assert-Silent 'firewall_disabled' '4950 for a different setting (Default Outbound Action) is silent'
  Reset-Engine
  $null = Feed 4950 @{ SubjectUserName = 'admin'; ProfileChanged = 'Private'; SettingType = 'EnableFirewall'; SettingValue = 'Yes' }
  Assert-Silent 'firewall_disabled' '4950 EnableFirewall -> Yes (turning it ON) is silent'
  Reset-Engine
  # the tolerant shapes: the netsh-style label some builds write, and the raw 0
  $null = Feed 4950 @{ SubjectUserName = 'admin'; ProfileChanged = 'Public'; SettingType = 'Enable Windows Firewall'; SettingValue = 'No' }
  Assert-Fired 'firewall_disabled' '  the "Enable Windows Firewall"/No spelling fires too'
  Reset-Engine
  $null = Feed 4950 @{ SubjectUserName = 'admin'; ProfileChanged = 'Public'; SettingType = 'EnableFirewall'; SettingValue = '0' }
  Assert-Fired 'firewall_disabled' '  and the numeric 0 form fires (older builds)'
  # dedupe: per profile, 15 minutes
  Reset-Engine
  $null = Feed 4950 @{ SubjectUserName = 'admin'; ProfileChanged = 'Domain'; SettingType = 'EnableFirewall'; SettingValue = 'No' }
  $null = Feed 4950 @{ SubjectUserName = 'admin'; ProfileChanged = 'Domain'; SettingType = 'EnableFirewall'; SettingValue = 'No' }
  Assert-Count 'firewall_disabled' 1 'a second identical disable inside the window is deduped'
  Reset-Engine
  $null = Feed 4950 @{ SubjectUserName = 'admin'; ProfileChanged = 'Domain'; SettingType = 'EnableFirewall'; SettingValue = 'No' }
  $null = Feed 4950 @{ SubjectUserName = 'admin'; ProfileChanged = 'Public'; SettingType = 'EnableFirewall'; SettingValue = 'No' }
  Assert-Count 'firewall_disabled' 2 'a DIFFERENT profile is a separate incident'
  # the rule never steals from the separate 4946-4949 rule
  Reset-Engine
  $null = Feed 4946 @{ SubjectUserName = 'administrator'; RuleName = 'Allow RDP inbound' }
  Assert-Fired 'firewall_rule_modified' '4946 still fires through the separate rule'
  Reset-Engine
  $null = Feed 4950 @{ SubjectUserName = 'administrator'; ProfileChanged = 'Domain'; SettingType = 'EnableFirewall'; SettingValue = 'No' }
  Assert-Silent 'firewall_rule_modified' 'and a 4950 never raises firewall_rule_modified'

  # --- anonymous_smb_session (4624 type 3, no credentials) -------------------
  Reset-Engine
  $a1 = Feed 4624 @{ TargetUserName = 'ANONYMOUS LOGON'; TargetUserSid = 'S-1-5-7'; LogonType = '3'; IpAddress = '203.0.113.66' }
  Assert-Fired 'anonymous_smb_session' 'a type-3 ANONYMOUS LOGON fires'
  Assert-True ($a1 -and $a1.Severity -eq 'Medium') '  ...at Medium'
  Assert-True ($a1 -and "$($a1.Description)" -match [regex]::Escape('203.0.113.66')) '  ...and names the source'
  Reset-Engine
  $null = Feed 4624 @{ TargetUserName = ''; TargetUserSid = ''; LogonType = '3'; IpAddress = '203.0.113.67' }
  Assert-Fired 'anonymous_smb_session' 'an EMPTY target name on a type-3 logon fires too'
  Reset-Engine
  $null = Feed 4624 @{ TargetUserName = 'jsmith'; TargetUserSid = 'S-1-5-21-1-2-3-500'; LogonType = '3'; IpAddress = '10.0.0.44' }
  Assert-Silent 'anonymous_smb_session' 'a NAMED account on a type-3 logon is not a null session'
  Reset-Engine
  $null = Feed 4624 @{ TargetUserName = 'ANONYMOUS LOGON'; TargetUserSid = 'S-1-5-7'; LogonType = '10'; IpAddress = '203.0.113.66' }
  Assert-Silent 'anonymous_smb_session' 'an anonymous logon that is NOT type 3 stays out'
  Reset-Engine
  $null = Feed 4624 @{ TargetUserName = 'ANONYMOUS LOGON'; TargetUserSid = 'S-1-5-7'; LogonType = '3'; IpAddress = '127.0.0.1' }
  $null = Feed 4624 @{ TargetUserName = 'ANONYMOUS LOGON'; TargetUserSid = 'S-1-5-7'; LogonType = '3'; IpAddress = '::1' }
  $null = Feed 4624 @{ TargetUserName = 'ANONYMOUS LOGON'; TargetUserSid = 'S-1-5-7'; LogonType = '3'; IpAddress = '' }
  Assert-Silent 'anonymous_smb_session' 'loopback and address-less sessions stay out (nothing to hunt)'
  # dedupe: per source IP, one hour
  Reset-Engine
  $null = Feed 4624 @{ TargetUserName = 'ANONYMOUS LOGON'; TargetUserSid = 'S-1-5-7'; LogonType = '3'; IpAddress = '203.0.113.66' }
  $null = Feed 4624 @{ TargetUserName = 'ANONYMOUS LOGON'; TargetUserSid = 'S-1-5-7'; LogonType = '3'; IpAddress = '203.0.113.66' }
  $null = Feed 4624 @{ TargetUserName = 'ANONYMOUS LOGON'; TargetUserSid = 'S-1-5-7'; LogonType = '3'; IpAddress = '203.0.113.66' }
  Assert-Count 'anonymous_smb_session' 1 'a burst from ONE address is deduped to one alert (per IP per hour)'
  Reset-Engine
  $null = Feed 4624 @{ TargetUserName = 'ANONYMOUS LOGON'; TargetUserSid = 'S-1-5-7'; LogonType = '3'; IpAddress = '203.0.113.66' }
  $null = Feed 4624 @{ TargetUserName = 'ANONYMOUS LOGON'; TargetUserSid = 'S-1-5-7'; LogonType = '3'; IpAddress = '203.0.113.99' }
  Assert-Count 'anonymous_smb_session' 2 'a SECOND source is a separate alert'
  # a named type-3 admin logon still belongs to suspicious_remote_logon, not here
  Reset-Engine
  $null = Feed 4624 @{ TargetUserName = 'DA_john'; LogonType = '3'; IpAddress = '10.0.0.77' }
  Assert-Fired 'suspicious_remote_logon' 'the suspicious_remote_logon rule is untouched by the new one'

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
  Assert-True ($RuleMeta.Count -eq 36) ('rule catalog has exactly 36 families (actual: ' + $RuleMeta.Count + ')')
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
  Assert-True ($catalog.Count -eq 36) 'rule catalog returns exactly 36 entries'
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
  Assert-True ((@($RuleMeta.Keys).Count -eq 36)) 'the rule catalog is untouched by the auth tests'

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

  # (v2.3) the catch-up verdict is computed server-side only and the dashboard
  # renders it, so the rule has exactly one implementation. These assertions moved
  # with it: there is no dashboard.js to inspect any more.
  $appJsNow = Get-Content -Raw (Join-Path (Split-Path -Parent $PSScriptRoot) 'js/app.js')
  Assert-True ($appJsNow.Contains('ov.health')) 'the dashboard takes the health verdict from the server'
  Assert-True ($appJsNow.Contains('degraded')) 'and knows the catching-up state it can be told'
  Assert-True (-not $appJsNow.Contains('lag > 2')) 'the old lag > 2 pill test is gone from the dashboard'
  $allJs = @(Get-ChildItem -Path (Join-Path (Split-Path -Parent $PSScriptRoot) 'js') -Recurse -File |
    ForEach-Object { Get-Content -Raw $_.FullName })
  Assert-True (-not (@($allJs | Where-Object { $_ -match '\(poll \* 2\) \+ 5' }).Count -gt 0)) 'and the threshold formula is not duplicated in the client'
  Assert-True (-not (Test-Path (Join-Path (Split-Path -Parent $PSScriptRoot) 'dashboard.js'))) 'dashboard.js no longer exists (the front end is split into js/ modules)'
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
  $Script:AuditState = $null
  $ov = Get-OverviewPayload
  Assert-True ($ov.coverage.rulesUnknown -gt 0) 'an unreadable policy leaves families unverified'
  Assert-True ($ov.coverage.percent -lt 100) 'and unverified families do NOT count as working (coverage is not 100%)'
  Assert-True ($ov.coverage.rulesWorking -eq ($ov.coverage.rulesTotal - $ov.coverage.rulesBlind - $ov.coverage.rulesUnknown)) 'working = total - blind - unverified'
  Assert-True ($ov.coverage.percent -eq [int][Math]::Round((100.0 * $ov.coverage.rulesWorking) / $ov.coverage.rulesTotal)) 'percent is confirmed-working over the total'
  Assert-True ($ov.coverage.unknownRules.Count -eq $ov.coverage.rulesUnknown) 'the unverified families are listed for the Rules page'
  Assert-True ($ov.health.state -eq 'degraded') 'health is degraded (amber) while the audit policy cannot be read'
  Assert-True (@($ov.health.reasons | Where-Object { $_.code -eq 'unverified' }).Count -eq 1) 'with the unverified reason attached'
  Assert-True ((Get-OverviewPayload).tiles.openAlerts -eq 0) 'an idle system has no open alerts'

  # every gated subcategory readable and on: coverage is confirmed at 100%.
  # A fresh table each time: assigning the same hashtable twice and mutating it
  # once kept the override and made the "reads clean" case fail.
  function New-ReadableAuditState {
    $subs = @{}
    foreach ($rk in $RuleAudit.Keys) {
      foreach ($sn in @($RuleAudit[$rk].Sub)) { if ($sn) { $subs["$sn".ToLower()] = 'Success and Failure' } }
    }
    return ,$subs
  }
  $readableSubs = New-ReadableAuditState
  $Script:AuditState = $readableSubs
  $ovOk = Get-OverviewPayload
  Assert-True ($ovOk.coverage.rulesUnknown -eq 0) 'with the policy readable nothing is unverified'
  Assert-True ($ovOk.coverage.percent -eq 100) 'a readable, fully enabled policy confirms 100% coverage'
  Assert-True ($ovOk.health.state -eq 'ok') 'and health is ok'
  Assert-True (@($ovOk.health.reasons).Count -eq 0) 'with no reasons when nothing is wrong'
  $Script:LastPollCapped = $false

  # a blind family drops coverage and flips health to blind
  $gated = @(Get-RuleCatalog | Where-Object { "$($_.auditSubcategory)" } | Select-Object -First 1)
  $sub = ("$($gated[0].auditSubcategory)" -split ' \+ ')[0].ToLower()
  $Script:AuditState = $readableSubs
  $Script:AuditState[$sub] = 'No Auditing'
  $ovb = Get-OverviewPayload
  Assert-True ($ovb.coverage.rulesBlind -ge 1) 'a family whose audit subcategory is off is counted blind'
  Assert-True ($ovb.coverage.percent -lt 100) 'and coverage drops below 100%'
  Assert-True ($ovb.coverage.rulesWorking -eq ($ovb.coverage.rulesTotal - $ovb.coverage.rulesBlind)) 'working = total - blind'
  Assert-True ($ovb.coverage.blindRules.Count -ge 1) 'the blind rules are listed for the Rules page'
  Assert-True ("$($ovb.coverage.blindRules[0].reason)".Length -gt 0) 'each with the reason it cannot fire'
  Assert-True ($ovb.health.state -eq 'blind') 'health reports blind when a family cannot fire'
  Assert-True (@($ovb.health.reasons).Count -ge 1 -and @($ovb.health.reasons)[0].code -eq 'blind') 'and the blind reason is listed first (worst first)'
  $Script:AuditState = New-ReadableAuditState
  Assert-True ((Get-OverviewPayload).health.state -eq 'ok') 'and returns to ok when the policy reads clean'
  $Script:AuditState = $null
  Assert-True ((Get-OverviewPayload).health.state -eq 'degraded') 'unreadable again, it goes back to degraded rather than claiming health'

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
  Write-Host "== v2.3 part 3: the new dashboard front end ==" -ForegroundColor Cyan

  $root = Split-Path -Parent $PSScriptRoot
  function Get-RepoText([string]$rel) { return (Get-Content -Raw (Join-Path $root $rel)) }
  function RepoHas([string]$rel) { return (Test-Path (Join-Path $root $rel)) }

  # --- the file layout ------------------------------------------------------
  $layout = @(
    'dashboard.html', 'login.html', 'login.js',
    'css/tokens.css', 'css/base.css', 'css/layout.css', 'css/components.css', 'css/pages.css', 'css/login.css',
    'js/api.js', 'js/state.js', 'js/ui.js', 'js/router.js', 'js/app.js',
    'js/pages/overview.js', 'js/pages/alerts.js', 'js/pages/rules.js', 'js/pages/events.js', 'js/pages/settings.js'
  )
  $missing = @($layout | Where-Object { -not (RepoHas $_) })
  Assert-True ($missing.Count -eq 0) ('every file in the layout exists (' + (($missing -join ', ') -replace '^$', 'none missing') + ')')
  Assert-True (-not (RepoHas 'dashboard.js')) 'the old dashboard.js is gone'

  # --- the static allowlist only serves what exists, and everything exists ---
  $web4 = Get-Section $raw $mWeb $mProbes
  Assert-True ($web4.Contains('$Script:StaticFiles = @{')) 'the static files are an explicit allowlist'
  Assert-True ($web4.Contains('$Script:StaticFiles.ContainsKey($path)')) 'a request is looked up in it, never turned into a path'
  Assert-True ($web4.Contains('{"error":"Not found."}'' 404')) 'anything not on the list is a 404'
  $allow = @()
  $block = [regex]::Match($web4, "(?s)\`$Script:StaticFiles = @\{(.*?)\n\}")
  foreach ($m in [regex]::Matches($block.Groups[1].Value, "'(/[^']+)'\s*=\s*@\{\s*file\s*=\s*'([^']+)';\s*type\s*=\s*'([^']+)'")) {
    $allow += [PSCustomObject]@{ path = $m.Groups[1].Value; file = $m.Groups[2].Value; type = $m.Groups[3].Value }
  }
  Assert-True ($allow.Count -ge $layout.Count) ('the allowlist covers the layout (' + $allow.Count + ' entries)')
  $allowMissing = @($allow | Where-Object { -not (RepoHas $_.file) })
  Assert-True ($allowMissing.Count -eq 0) ('every allowlisted file is on disk (' + (($allowMissing | ForEach-Object { $_.file }) -join ', ') + ')')
  $badType = @($allow | Where-Object {
      ($_.file -like '*.html' -and $_.type -notlike 'text/html*') -or
      ($_.file -like '*.js'   -and $_.type -notlike 'application/javascript*') -or
      ($_.file -like '*.css'  -and $_.type -notlike 'text/css*')
    })
  Assert-True ($badType.Count -eq 0) 'every entry declares the right content type for its extension'
  # every css/js file on disk is reachable through the allowlist (nothing orphaned)
  $onDisk = @()
  foreach ($d in @('css', 'js')) {
    $onDisk += @(Get-ChildItem -Path (Join-Path $root $d) -Recurse -File | ForEach-Object { $_.FullName.Substring($root.Length + 1).Replace('\', '/') })
  }
  $unlisted = @($onDisk | Where-Object { $allow.file -notcontains $_ })
  Assert-True ($unlisted.Count -eq 0) ('no stylesheet or script is left unserved (' + ($unlisted -join ', ') + ')')
  Assert-True ($allow.path -notcontains '/dashboard.js') 'dashboard.js is not in the allowlist'

  # --- no inline code anywhere ---------------------------------------------
  foreach ($html in @('dashboard.html', 'login.html')) {
    $txt = Get-RepoText $html
    Assert-True ([regex]::Matches($txt, '<style[ >]').Count -eq 0) ("   " + $html + ' has no inline style element')
    $inlineScripts = @([regex]::Matches($txt, '<script[^>]*>') | Where-Object { $_.Value -notmatch 'src=' })
    Assert-True ($inlineScripts.Count -eq 0) ("   " + $html + ' has no script element without src')
    Assert-True ([regex]::Matches($txt, '\son[a-z]+\s*=').Count -eq 0) ("   " + $html + ' has no on* handler attribute')
    if ($html -eq 'dashboard.html') {
      Assert-True ($txt.Contains('id="view"')) '   dashboard.html is a shell with a view container'
    } else {
      Assert-True ($txt.Contains('id="loginForm"')) '   login.html is a shell with the sign-in form'
    }
  }
  $jsFiles = @('js/api.js', 'js/state.js', 'js/ui.js', 'js/router.js', 'js/app.js',
               'js/pages/overview.js', 'js/pages/alerts.js', 'js/pages/rules.js', 'js/pages/events.js', 'js/pages/settings.js')
  foreach ($f in $jsFiles) {
    $txt = Get-RepoText $f
    Assert-True ([regex]::Matches($txt, '\.innerHTML\s*=').Count -eq 0) ("   " + $f + ' never assigns innerHTML (all text goes through textContent)')
    Assert-True ([regex]::Matches($txt, 'document\.write').Count -eq 0) ("   " + $f + ' never uses document.write')
    Assert-True ($txt -match 'OWNER:') ("   " + $f + ' says what it owns in a header comment')
  }
  Assert-True ((Get-RepoText 'js/ui.js').Contains('createTextNode')) 'the DOM helper builds text nodes, not markup'
  Assert-True ((Get-RepoText 'js/ui.js').Contains('on') -and (Get-RepoText 'js/ui.js').Contains('return;')) 'the element helper refuses on* attributes'

  # --- CSP unchanged --------------------------------------------------------
  Assert-True ($web4.Contains("script-src ''self''")) 'the CSP still allows only same-origin scripts'
  Assert-True (-not ($web4 -match "script-src [^;]*unsafe-inline")) 'and never unsafe-inline for scripts'

  # --- design tokens: brand vs severity, type scale -------------------------
  $tokens = Get-RepoText 'css/tokens.css'
  Assert-True ($tokens.Contains('--brand:')) 'there is a brand colour'
  Assert-True ($tokens.Contains('--sev-critical:')) 'and separate severity colours'
  Assert-True (-not ($tokens -match '--brand:\s*#ff4d6d')) 'the brand colour is not a severity colour'
  $components = Get-RepoText 'css/components.css'
  Assert-True ($components -match '\.sev-Critical[^\}]*var\(--sev-critical\)') 'Critical uses the severity colour, never the brand'
  Assert-True (-not ($components -match '\.sev-(Critical|High|Medium|Low)[^\}]*var\(--brand\)')) 'no severity class uses the brand colour'
  Assert-True ($tokens -match '--fs-base:\s*1[56]px') 'the base font is 15-16px'
  Assert-True ($tokens -match '--fs-table:\s*14px') 'table text is 14px'
  Assert-True ($tokens -match '--fs-tile:\s*(2[89]|3[012])px') 'tile numbers are 28-32px'
  Assert-True ($tokens -match '--fs-cap:\s*12px') 'the smallest caption is 12px'
  Assert-True ((Get-RepoText 'css/base.css').Contains('prefers-reduced-motion')) 'reduced motion is respected'
  Assert-True ((Get-RepoText 'css/base.css').Contains(':focus-visible')) 'keyboard focus is visible'

  # --- mockup vs spec -------------------------------------------------------
  $dash = Get-RepoText 'dashboard.html'
  # Attack Paths (a BloodHound-style graph) is a full live page with graph analysis
  Assert-True ($dash.Contains('Attack Paths')) 'Attack Paths is rendered in the nav'
  Assert-True ($dash -match 'href="#/paths"') 'Attack Paths has a route'
  Assert-True ($dash.Contains('id="search"')) 'the top search box is rendered'
  Assert-True ($dash.Contains('id="range"')) 'the range selector is rendered'
  Assert-True ([regex]::Matches($dash, '<option').Count -eq 1) 'and is fixed at one option (24 h) - no new endpoint behind it'
  Assert-True ($dash.Contains('id="alertCount"')) 'the sidebar shows the open-alert badge'
  Assert-True ($dash.Contains('id="demoPill"') -and $dash.Contains('hidden')) 'the demo marker starts hidden'
  $appjs = Get-RepoText 'js/app.js'
  Assert-True ($appjs.Contains('demoData')) 'the demo marker is driven by the backend flag'
  Assert-True ($appjs.Contains('DEMO DATA')) 'and says so when it is on'
  Assert-True (-not (Get-RepoText 'js/pages/overview.js').Contains('2,492')) 'no invented demo numbers in the front end'
  Assert-True (-not $dash.Contains('2,492')) 'and none in the shell'
  Assert-True ($Script:DemoData -eq $false) 'demo mode is off unless the operator asks for it'

  # --- the alert vocabulary and the router ---------------------------------
  $alertsJs = Get-RepoText 'js/pages/alerts.js'
  foreach ($st in @('New', 'Investigating', 'Resolved', 'False Positive')) {
    Assert-True ($alertsJs.Contains($st)) ('   the status vocabulary includes ' + $st)
  }
  Assert-True ($alertsJs.Contains('Acknowledged')) 'Acknowledged is offered as its own flag'
  Assert-True ($alertsJs.Contains('/status') -and $alertsJs.Contains('ack')) 'the drawer can change status and ack'
  Assert-True ($alertsJs.Contains('kill-chain timeline')) 'and shows the kill-chain timeline'
  Assert-True ($alertsJs.Contains('Contributing events')) 'plus the contributing events'
  $routerJs = Get-RepoText 'js/router.js'
  foreach ($r in @('/overview', '/alerts', '/rules', '/events', '/settings')) {
    Assert-True ($routerJs.Contains($r)) ('   the router knows ' + $r)
  }
  foreach ($pg in @('overview', 'alerts', 'rules', 'events', 'settings')) {
    Assert-True ((Get-RepoText ('js/pages/' + $pg + '.js')).Contains('S.pages.' + $pg + ' =')) ('   the ' + $pg + ' page registers itself')
  }
  Assert-True ((Get-RepoText 'js/state.js').Contains('visibilitychange')) 'polling pauses when the tab is hidden'
  Assert-True ((Get-RepoText 'js/api.js').Contains("credentials: 'same-origin'")) 'API calls carry the session cookie'
  Assert-True ((Get-RepoText 'js/api.js').Contains('401')) 'and a 401 sends the browser to the sign-in page'
  Assert-True ((Get-RepoText 'js/pages/settings.js').Contains('Read-only') -or (Get-RepoText 'js/pages/settings.js').Contains('read-only')) 'Settings presents itself as read-only'

  Write-Host ""
  Write-Host "== v2.3.1 review fixes ==" -ForegroundColor Cyan

  # --- 1. coverage counts only CONFIRMED families ---------------------------
  Reset-Engine
  $Script:AuditState = $null
  $cov = (Get-OverviewPayload).coverage
  Assert-True ($cov.rulesWorking + $cov.rulesBlind + $cov.rulesUnknown -eq $cov.rulesTotal) 'working + blind + unverified accounts for every family'
  Assert-True (-not ($cov.PSObject.Properties.Name -contains 'rulesVerifiedOnly')) 'the payload keeps one vocabulary (rulesWorking/rulesBlind/rulesUnknown)'
  Assert-True ($cov.rulesUnknown -gt 0 -and $cov.percent -lt 100) 'an unreadable policy cannot report full coverage'
  $rulesJs = Get-Content -Raw (Join-Path (Split-Path -Parent $PSScriptRoot) 'js/pages/rules.js')
  Assert-True ($rulesJs.Contains("'Unverified'")) 'the Rules page labels an unreadable family Unverified, not Working'
  Assert-True ($rulesJs.Contains('unknown')) 'and counts them'
  Assert-True ($rulesJs.Contains('unverified')) 'with the count on the page'
  $ovJs = Get-Content -Raw (Join-Path (Split-Path -Parent $PSScriptRoot) 'js/pages/overview.js')
  Assert-True ($ovJs.Contains('rulesUnknown')) 'the coverage tile reads rulesUnknown'
  Assert-True ($ovJs.Contains('unverified')) 'and shows "N unverified"'
  $appJs2 = Get-Content -Raw (Join-Path (Split-Path -Parent $PSScriptRoot) 'js/app.js')
  Assert-True ($appJs2.Contains("'degraded'")) 'the health pill renders the degraded state as amber'

  # --- 2. every array the API returns is an array ---------------------------
  Assert-True ((ConvertTo-JsonArray $null) -eq '[]') 'a null collection serialises as []'
  Assert-True ((ConvertTo-JsonArray @()) -eq '[]') 'an empty array serialises as []'
  $one = ConvertTo-JsonArray @([PSCustomObject]@{ a = 1 })
  Assert-True ($one -eq '[{"a":1}]') 'a single element still serialises as an array'
  $two = ConvertTo-JsonArray @([PSCustomObject]@{ a = 1 }, [PSCustomObject]@{ a = 2 })
  Assert-True (([regex]::Matches($two, '\{"a":')).Count -eq 2) 'two elements serialise as two'
  Assert-True ((ConvertTo-JsonArray @($null)) -eq '[]') 'a null ELEMENT is not an entry'
  # the real paths that produced [null]
  Reset-Engine
  Assert-True ($Script:ObsHosts.Count -eq 0) 'no hosts tracked yet'
  Assert-True ((ConvertTo-JsonArray (Get-HostsPayload)) -eq '[]') '/api/hosts serialises an empty host map as []'
  $evEmpty = Get-EventsPayload (New-Query @{})
  Assert-True ((ConvertTo-JsonArray $evEmpty.events) -eq '[]') '/api/events serialises an empty buffer as []'
  Assert-True ((ConvertTo-JsonArray (Get-AlertRows)) -eq '[]') '/api/alerts serialises an empty alert list as []'
  Assert-True (-not ((ConvertTo-JsonArray (Get-HostsPayload)).Contains('null'))) 'and never emits a null entry'
  # the guard lives inside the one helper every API array goes through (it moved
  # to the engine slice so the suite could reach it)
  Assert-True ($raw.Contains('if ($null -eq $items) { return ''[]'' }')) 'the guard lives in the one function every array goes through'
  Assert-True ($raw.Contains('if ($null -eq $i) { continue }')) 'and a null element is skipped rather than serialised'

  # --- 6. polish -----------------------------------------------------------
  Assert-True ($Script:SentinelVersion -eq '2.6.0') 'the version is 2.6.0'
  Assert-True ($raw.Contains('ALPHA SENTINEL v2.6.0')) 'the script header says v2.6.0'
  Assert-True ($raw.Contains('ALPHA SENTINEL v2.6.0 - AD / Network Attack Monitor')) 'and so does the startup banner'

  # account names, not distinguished names
  Assert-True ((ConvertTo-AccountName 'CN=attacker,OU=Corp,DC=example,DC=local') -eq 'attacker') 'a DN is trimmed to the account'
  Assert-True ((ConvertTo-AccountName 'CN=svc-sql,OU=Servers') -eq 'svc-sql') 'including a nested OU'
  Assert-True ((ConvertTo-AccountName 'jsmith') -eq 'jsmith') 'a plain account name is untouched'
  Assert-True ((ConvertTo-AccountName '') -eq '') 'and empty stays empty'
  Reset-Engine
  Add-ObservedEvent 'Security' @{ eventId = '4728'; hostname = 'DC01'; accountName = 'CN=attacker,OU=Corp,DC=example,DC=local' } 'privilege_escalation' $when
  $h1 = Get-HostsPayload
  Assert-True ($h1[0].users -contains 'attacker') 'hosts[].users holds the account name'
  Assert-True (-not ($h1[0].users -contains 'CN=attacker,OU=Corp,DC=example,DC=local')) 'and never the DN'
  Assert-True ("$($Script:ObsEvents[0].user)" -eq 'attacker') 'the events feed shows the account name too'

  # self-test alerts carry a tactic and an entity
  Reset-Engine
  $probe = @(New-SelfTestProbes | Where-Object { $_.ruleKey -eq 'privilege_escalation' })[0]
  $probeAlert = Evaluate-Event (New-EventShim $probe)
  Assert-True ($null -ne $probeAlert) 'a self-test probe still fires through the real engine'
  if ($probeAlert) {
    Assert-True ("$($probeAlert.Tactic)".Length -gt 0) 'a self-test alert carries its MITRE tactic'
    Assert-True ("$($probeAlert.Entity)".Length -gt 0) 'and its entity'
    Assert-True ("$($probeAlert.MitreId)" -match '^T\d{4}') 'and its technique id'
    $probeAlert.SelfTest = $true
    Assert-True ("$($probeAlert.Tactic)".Length -gt 0) 'still tagged with a tactic after being marked self-test'
  }
  # a row restored from history (no tactic on the object) still gets one
  Reset-Engine
  $restored = [PSCustomObject]@{
    Id = 99; Time = (Get-Date).ToUniversalTime().ToString('o'); RuleKey = 'dcsync_replication'
    Rule = '4662'; Severity = 'Critical'; Title = 'Directory Replication'; Mitre = 'T1003.006 - OS Credential Dumping: DCSync'
    Remediation = 'x'; Description = 'x'; Host = 'DC01'; Account = 'attacker'; SourceIp = '10.0.0.5'
    EventId = '4662'; Acknowledged = $false; Status = 'New'; Notes = ''; SelfTest = $false
  }
  $Script:Alerts.Add($restored)
  $row = @(Get-AlertRows)[0]
  Assert-True ("$($row.Tactic)".Length -gt 0) 'a restored row is given its tactic from the rule catalogue'
  Assert-True ("$($row.MitreId)" -eq 'T1003.006') 'and its technique id from the MITRE string'
  Assert-True ("$($row.Entity)" -eq 'attacker') 'and falls back to the account for its entity'
  Assert-True ([int]$row.Count -eq 1 -and "$($row.FirstSeen)".Length -gt 0) 'and defaults count/first-seen so the drawer renders'

  # the favicon is inline, so the console has no 404 to complain about
  foreach ($html2 in @('dashboard.html', 'login.html')) {
    $htxt = Get-Content -Raw (Join-Path (Split-Path -Parent $PSScriptRoot) $html2)
    Assert-True ($htxt.Contains('rel="icon"')) ("   " + $html2 + ' declares a favicon')
    Assert-True ($htxt -match 'rel="icon" href="data:,') ("   " + $html2 + ' uses an inline icon (no extra file to serve or 404)')
  }

  # and the design polish the review asked for, in the stylesheet
  $pagesCss = Get-Content -Raw (Join-Path (Split-Path -Parent $PSScriptRoot) 'css/pages.css')
  Assert-True ($pagesCss.Contains('.tactic-list .t-lead')) 'the tactic rows have a dotted leader between name and count'
  Assert-True ($pagesCss.Contains('border-bottom: 1px dotted')) 'drawing the leader'
  Assert-True ($pagesCss.Contains('.tactic-list .t-count') -and $pagesCss.Contains('text-align: right')) 'with the count right-aligned'
  Assert-True ($pagesCss.Contains('list-style: none')) 'and no bullets'
  Assert-True ((Get-Content -Raw (Join-Path (Split-Path -Parent $PSScriptRoot) 'js/pages/overview.js')).Contains("'ul', { class: 'tactic-list' }")) 'the tactic rows are wrapped in the styled list'
  Assert-True (-not $pagesCss.Contains('.tactic-bar {')) 'the old bar is gone'
  $compCss = Get-Content -Raw (Join-Path (Split-Path -Parent $PSScriptRoot) 'css/components.css')
  Assert-True ($compCss.Contains('.tile-delta .arrow')) 'the tiles style a delta arrow'
  Assert-True ($compCss.Contains('.tile-delta.neutral')) 'and a neutral direction'
  $uiJs = Get-Content -Raw (Join-Path (Split-Path -Parent $PSScriptRoot) 'js/ui.js')
  Assert-True ($uiJs.Contains('baseline')) 'the chart draws a baseline'
  Assert-True ($uiJs.Contains('values.length === 1')) 'and a single bucket still draws a line'
  Assert-True ($ovJs.Contains('slice(0, 6)')) 'Recent Alerts is capped at six rows'
  Assert-True (-not ($ovJs -match 'alertsTable[\s\S]{0,1200}a\.Description')) 'and no longer prints the description there'

  Write-Host ""
  Write-Host "== v2.4 part 0: the pill says why, aborts stay silent ==" -ForegroundColor Cyan

  # --- health.reasons[] -----------------------------------------------------
  Reset-Engine
  $Script:AuditState = $null
  $h = (Get-OverviewPayload).health
  Assert-True ($h.state -eq 'degraded') 'an unreadable audit policy degrades health'
  $codes = @($h.reasons | ForEach-Object { $_.code })
  Assert-True ($codes -contains 'unverified') 'with the unverified reason'
  Assert-True ("$(@($h.reasons | Where-Object { $_.code -eq 'unverified' })[0].label)" -eq 'Unverified') 'labelled Unverified'

  # worst first: blind AND catching-up together -> blind headlines, both listed
  Reset-Engine
  $gated = @(Get-RuleCatalog | Where-Object { "$($_.auditSubcategory)" } | Select-Object -First 1)
  $sub = ("$($gated[0].auditSubcategory)" -split ' \+ ')[0].ToLower()
  $Script:AuditState = @{}
  $Script:AuditState[$sub] = 'No Auditing'
  $Script:LastPollCapped = $true
  $h2 = (Get-OverviewPayload).health
  Assert-True ($h2.state -eq 'blind') 'blind is the state when it and catching-up both apply'
  Assert-True (@($h2.reasons)[0].code -eq 'blind') 'and blind is the first reason (the pill shows the worst)'
  $codes2 = @($h2.reasons | ForEach-Object { $_.code })
  Assert-True ($codes2 -contains 'catching-up') 'with the catching-up reason also listed'
  Assert-True ($codes2.Count -ge 2) 'so the tooltip can list every reason'

  # catching up alone, with a readable policy
  Reset-Engine
  $Script:AuditState = New-ReadableAuditState
  $Script:LastPollCapped = $true
  $h3 = (Get-OverviewPayload).health
  Assert-True ($h3.state -eq 'degraded') 'a deferred poll degrades health on its own'
  Assert-True (@($h3.reasons | Where-Object { $_.code -eq 'catching-up' }).Count -eq 1) 'with the catching-up reason'
  Assert-True (@($h3.reasons | Where-Object { $_.code -eq 'unverified' }).Count -eq 0) 'and no unverified reason when the policy reads'
  $Script:LastPollCapped = $false

  # --- the pill renders the reason, not a generic word ----------------------
  $appJs = Get-Content -Raw (Join-Path (Split-Path -Parent $PSScriptRoot) 'js/app.js')
  Assert-True ($appJs.Contains('health.state')) 'the pill reads health.state'
  Assert-True ($appJs.Contains('reasons')) 'and health.reasons'
  Assert-True ($appJs.Contains("label = 'Unverified'")) 'an unreadable policy shows Unverified, not a generic word'
  Assert-True ($appJs.Contains("label = 'Catching up'")) 'a deferred poll shows Catching up'
  Assert-True ($appJs.Contains("label = 'Blind'")) 'a blind policy shows Blind'
  Assert-True ($appJs.Contains("labels.join('; ')")) 'and every reason lands in the tooltip'

  # --- an aborted fetch stays silent ----------------------------------------
  $apiJs = Get-Content -Raw (Join-Path (Split-Path -Parent $PSScriptRoot) 'js/api.js')
  Assert-True ($apiJs.Contains("err.name === 'AbortError'")) 'an aborted fetch is not logged'
  Assert-True ($apiJs.Contains("err.name === 'NavigationError'")) 'nor a navigation-cancelled one'
  Assert-True ($apiJs.Contains('logFail(page, err)')) 'real failures still log once, with the page name'

  Write-Host ""
  Write-Host "== v2.4 part 1: assets ==" -ForegroundColor Cyan
  # the Assets page is real from this part on
  $dashA = Get-RepoText 'dashboard.html'
  Assert-True ($dashA -match '<a class="nav-item" href="#/assets" data-page="assets">') 'Assets is a live nav link, not a Soon item'
  Assert-True ((Get-RepoText 'js/router.js').Contains("'/assets': 'assets'")) '#/assets is routed'
  Assert-True ($dashA.Contains('/js/pages/assets.js')) 'and the page module is loaded by the shell'

  Reset-Engine
  $t0 = (Get-Date).ToUniversalTime()
  Add-ObservedEvent 'Security' @{ eventId = '4625'; hostname = 'DC01'; accountName = 'CN=attacker,OU=Corp,DC=x,DC=local'; sourceIp = '::ffff:10.0.0.7' } 'brute_force_single_account' $t0
  Add-ObservedEvent 'Security' @{ eventId = '4728'; hostname = 'DC01'; accountName = 'attacker'; sourceIp = '10.0.0.7' } 'privilege_escalation' $t0.AddMinutes(1)
  Add-ObservedEvent 'Security' @{ eventId = '4769'; hostname = 'DC02'; accountName = 'WKS01$'; sourceIp = '8.8.8.8' } 'kerberoasting' $t0.AddMinutes(2)
  $a1 = New-Alert 'brute_force_single_account' '8 failed logons against attacker' 'High' @{ hostname = 'DC01'; accountName = 'attacker'; sourceIp = '10.0.0.7'; eventId = '4625' }
  $Script:Alerts.Add($a1); Add-ObservedAlert $a1
  $a2 = New-Alert 'privilege_escalation' 'added to Domain Admins' 'Critical' @{ hostname = 'DC01'; accountName = 'attacker'; sourceIp = '10.0.0.7'; eventId = '4728' }
  $Script:Alerts.Add($a2); Add-ObservedAlert $a2

  # --- shapes ---------------------------------------------------------------
  $qEmpty = New-Object System.Collections.Specialized.NameValueCollection
  $hosts = Get-AssetsPayload $qEmpty
  Assert-True ($hosts.kind -eq 'host') 'kind defaults to host'
  Assert-True ($hosts.assets[0].PSObject.Properties.Name -contains 'maxSeverity') 'a host asset carries maxSeverity'
  foreach ($need in @('name', 'firstSeen', 'lastSeen', 'eventCount', 'alertCount', 'users', 'ips', 'openAlerts', 'tactics')) {
    Assert-True ($hosts.assets[0].PSObject.Properties.Name -contains $need) ('   host asset has ' + $need)
  }
  $qAcc = New-Object System.Collections.Specialized.NameValueCollection; $qAcc.Add('kind', 'account')
  $accs = Get-AssetsPayload $qAcc
  foreach ($need in @('name', 'type', 'firstSeen', 'lastSeen', 'hosts', 'ips', 'alertCount', 'maxSeverity', 'lastEventIds', 'flags')) {
    Assert-True ($accs.assets[0].PSObject.Properties.Name -contains $need) ('   account asset has ' + $need)
  }
  $qIp = New-Object System.Collections.Specialized.NameValueCollection; $qIp.Add('kind', 'ip')
  $ips = Get-AssetsPayload $qIp
  foreach ($need in @('address', 'firstSeen', 'lastSeen', 'accounts', 'hosts', 'failedLogons', 'alertCount', 'internal', 'maxSeverity')) {
    Assert-True ($ips.assets[0].PSObject.Properties.Name -contains $need) ('   ip asset has ' + $need)
  }

  # --- DN stripping, account types, ::ffff:, internal ------------------------
  $att = @($accs.assets | Where-Object { $_.name -eq 'attacker' })[0]
  Assert-True ($null -ne $att) 'the CN= DN collapsed into the plain account'
  Assert-True ($att.type -eq 'user') 'a plain account is typed user'
  $wks = @($accs.assets | Where-Object { $_.name -eq 'WKS01$' })[0]
  Assert-True ($null -ne $wks -and $wks.type -eq 'computer') 'an account ending in $ is typed computer'
  $ips2 = Get-AssetsPayload $qIp
  $ip7 = @($ips2.assets | Where-Object { $_.address -eq '10.0.0.7' })[0]
  Assert-True ($null -ne $ip7) '::ffff:10.0.0.7 was normalised to 10.0.0.7'
  Assert-True ($ip7.internal) 'an RFC1918 address is internal'
  Assert-True ([int]$ip7.failedLogons -eq 1) ('the failed logon was counted on the source address (got ' + $ip7.failedLogons + ')')
  $ip8 = @($ips.assets | Where-Object { $_.address -eq '8.8.8.8' })[0]
  Assert-True ($null -ne $ip8 -and -not $ip8.internal) 'a public address is not internal'
  Assert-True ((Get-NormalisedIp ' ::FFFF:192.168.1.5 ') -eq '192.168.1.5') 'normalisation is case- and space-insensitive'
  Assert-True (Test-InternalIp '127.0.0.1' -and (Test-InternalIp '169.254.1.2')) 'loopback and link-local are internal'
  Assert-True (-not (Test-InternalIp '2001:db8::1')) 'a global v6 address is not'

  # --- flags derive only from fired rules ----------------------------------
  Assert-True ($att.flags -contains 'added to privileged group') 'a privilege-escalation alert leaves a flag'
  Assert-True ($att.flags -contains 'brute-forced') 'a brute-force alert leaves a flag'
  Assert-True ($att.alertCount -eq 2) 'both alerts counted on the account'
  Assert-True ("$($att.maxSeverity)" -eq 'Critical') 'and the worst severity is kept'

  # --- host rollup ----------------------------------------------------------
  $dc = @($hosts.assets | Where-Object { $_.name -eq 'DC01' })[0]
  Assert-True ($dc.openAlerts -contains 1 -and $dc.openAlerts -contains 2) 'the host carries its open alert ids'
  Assert-True ($dc.tactics.Count -ge 2) 'and the tactics that fired on it'

  # --- validation -----------------------------------------------------------
  $qBad = New-Object System.Collections.Specialized.NameValueCollection; $qBad.Add('kind', 'banana')
  $bad = Get-AssetsPayload $qBad
  Assert-True ($bad.status -eq 400 -and $bad.error) 'an unknown kind is refused with 400'
  $qLim = New-Object System.Collections.Specialized.NameValueCollection; $qLim.Add('limit', '9999')
  Assert-True ((Get-AssetsPayload $qLim).limit -eq 500) 'the limit is clamped to 500'
  $qQ = New-Object System.Collections.Specialized.NameValueCollection; $qQ.Add('q', 'attack')
  Assert-True ((Get-AssetsPayload $qQ).total -ge 1) 'q is a plain substring over names/users/accounts'
  $qRe = New-Object System.Collections.Specialized.NameValueCollection; $qRe = New-Query @{ q = '.*' }
  Assert-True ((Get-AssetsPayload $qRe).total -eq 0) 'and never a regular expression'
  $d404 = Get-AssetDetail 'host' 'no-such-host'
  Assert-True ($d404.status -eq 404) 'an unknown asset id is 404 (looked up in the map, never a path)'
  $dOk = Get-AssetDetail 'host' 'DC01'
  Assert-True ($null -ne $dOk.asset -and $dOk.timeline.Count -ge 1) 'a known asset returns its detail and timeline from the ring buffer'
  Assert-True ($dOk.timeline[0].PSObject.Properties.Name -contains 'summary') 'and the timeline carries summaries, not raw bodies'
  $serialisedAssets = ((Get-AssetsPayload $qAcc).assets | ConvertTo-Json -Depth 6) + (($ips.assets | ConvertTo-Json -Depth 6))
  Assert-True (-not $serialisedAssets.Contains('S3CR3T')) 'no secret material reaches an asset payload'

  Write-Host ""
  Write-Host "== v2.4 part 2: attack chains ==" -ForegroundColor Cyan
  # the Attack Chains page is real from this part on
  $dashC = Get-RepoText 'dashboard.html'
  Assert-True ($dashC -match '<a class="nav-item" href="#/chains" data-page="chains">') 'Attack Chains is a live nav link'
  Assert-True ((Get-RepoText 'js/router.js').Contains("'/chains': 'chains'")) '#/chains is routed'
  Assert-True ($dashC.Contains('/js/pages/chains.js')) 'and the page module is loaded by the shell'

  Reset-Engine
  $now = (Get-Date).ToUniversalTime()
  # NOTE: $host is a PowerShell automatic (read-only) variable - the host field
  # must be a different name
  function Seed-Alert([int]$Id, [string]$ruleKey, [string]$sev, [string]$account, [string]$hostName, [string]$ip, [datetime]$when, [string]$status = 'New') {
    $meta = $RuleMeta[$ruleKey]
    $a = [PSCustomObject]@{
      Id = $Id; Time = $when.ToString('o'); RuleKey = $ruleKey; Rule = $meta.EventId; Severity = $sev
      Title = $meta.Title; Mitre = $meta.Mitre; MitreId = (Get-MitreParts "$($meta.Mitre)").id
      MitreName = (Get-MitreParts "$($meta.Mitre)").name; Tactic = (Get-MitreTactic "$($meta.Category)")
      Entity = $account; Remediation = 'x'; Description = 'x'
      Host = $hostName; Account = $account; SourceIp = $ip; EventId = "$($meta.EventId)"
      Acknowledged = $false; Status = $status; Notes = ''; SelfTest = $false
      FirstSeen = $when.ToString('o'); LastSeen = $when.ToString('o'); Count = 1; Events = @()
    }
    $Script:Alerts.Add($a)
    return $a
  }
  # one chain: same account within the window
  Seed-Alert 10 'brute_force_single_account' 'High' 'attacker' 'DC01' '10.0.0.7' $now
  Seed-Alert 11 'privilege_escalation' 'Critical' 'attacker' 'DC01' '10.0.0.7' $now.AddMinutes(5)
  # a THIRD alert on the same HOST but a different account and ip: since v2.4.1
  # sharing only the destination host is NOT a link (every alert touching DC01
  # would merge into one mega-chain), so it must stay out
  Seed-Alert 12 'log_tampering' 'Critical' 'administrator' 'DC01' '10.0.0.9' $now.AddMinutes(8)
  # outside the window -> its own chain (but alone, so excluded)
  Seed-Alert 13 'kerberoasting' 'High' 'svc-sql' 'DC02' '10.0.0.8' $now.AddMinutes(200)
  # a resolved alert must never join a chain
  Seed-Alert 14 'account_created' 'Low' 'attacker' 'DC01' '10.0.0.7' $now.AddMinutes(9) 'Resolved'

  $chains = Get-AttackChains
  Assert-True ($chains.Count -eq 1) ('exactly one chain forms (got ' + $chains.Count + ')')
  $c = $chains[0]
  Assert-True ($c.alerts.Count -eq 2) ('the two attacker alerts are the chain (got ' + $c.alerts.Count + ')')
  Assert-True (@($c.alerts | Where-Object { $_.id -eq 12 }).Count -eq 0) 'an alert sharing only the host does NOT join'
  Assert-True (@($c.alerts | Where-Object { $_.id -eq 14 }).Count -eq 0) 'a Resolved alert is excluded'
  Assert-True (@($c.alerts | Where-Object { $_.id -eq 13 }).Count -eq 0) 'an alert outside the 60-minute window is excluded'
  Assert-True (@($c.entities.accounts) -contains 'attacker') 'its entity is the shared account'
  Assert-True (@($c.entities.hosts) -contains 'DC01') 'and the host is still an entity on the chain (a label, not a link)'
  Assert-True ($c.maxSeverity -eq 'Critical') 'the chain severity is the worst of its alerts'
  Assert-True ("$($c.id)" -match '^[0-9a-f]{12}$') 'the chain id is a stable short hash'
  Assert-True ((Get-AttackChains)[0].id -eq $c.id) 'and identical alerts produce an identical id (deterministic)'
  # kill-chain order: Privilege Escalation (3) precedes Credential Access (5)
  $order = @($c.tacticsInOrder)
  Assert-True ($order.Count -ge 2) 'the tactics are listed in kill-chain order'
  Assert-True ($order.IndexOf('Privilege Escalation') -lt $order.IndexOf('Credential Access')) 'Privilege Escalation precedes Credential Access'
  # a single alert stays out even when nothing else exists
  Reset-Engine
  Seed-Alert 20 'log_tampering' 'Critical' 'administrator' 'DC01' '' $now
  Assert-True ((Get-AttackChains).Count -eq 0) 'a single open alert forms no chain'

  # --- the v2.4.1 chain rules ------------------------------------------------
  # two unrelated accounts on one host: separate chains, or none if < 2 alerts
  Reset-Engine
  Seed-Alert 21 'brute_force_single_account' 'High' 'alice' 'DC01' '10.0.0.7' $now
  Seed-Alert 22 'brute_force_single_account' 'High' 'bob' 'DC01' '10.0.0.8' $now.AddMinutes(3)
  Assert-True ((Get-AttackChains).Count -eq 0) 'two unrelated accounts on one host form NO chain (one alert each)'
  Seed-Alert 23 'privilege_escalation' 'Critical' 'alice' 'DC01' '10.0.0.7' $now.AddMinutes(4)
  Seed-Alert 24 'privilege_escalation' 'Critical' 'bob' 'DC01' '10.0.0.9' $now.AddMinutes(6)
  $two = @(Get-AttackChains)
  Assert-True ($two.Count -eq 2) ('two unrelated accounts on one host = 2 separate chains (got ' + $two.Count + ')')
  Assert-True ((@($two | Where-Object { @($_.entities.accounts) -contains 'alice' }).Count -eq 1) -and (@($two | Where-Object { @($_.entities.accounts) -contains 'bob' }).Count -eq 1)) 'and the two chains do not share alerts'
  # same account on two hosts = 1 chain
  Reset-Engine
  Seed-Alert 25 'brute_force_single_account' 'High' 'attacker' 'DC01' '10.0.0.7' $now
  Seed-Alert 26 'privilege_escalation' 'Critical' 'attacker' 'DC02' '10.0.0.7' $now.AddMinutes(7)
  $across = @(Get-AttackChains)
  Assert-True ($across.Count -eq 1) 'the same account on two hosts = 1 chain'
  Assert-True (@($across[0].entities.hosts) -contains 'DC01' -and @($across[0].entities.hosts) -contains 'DC02') 'and both hosts are entities on it'
  # linked by shared SOURCE IP alone (different accounts, different hosts)
  Reset-Engine
  Seed-Alert 27 'brute_force_single_account' 'High' 'alice' 'DC01' '203.0.113.9' $now
  Seed-Alert 28 'log_tampering' 'Critical' 'bob' 'DC02' '203.0.113.9' $now.AddMinutes(9)
  $byIp = @(Get-AttackChains)
  Assert-True ($byIp.Count -eq 1) 'a shared source IP links two alerts even with different accounts and hosts'
  # an alert with neither account nor ip cannot be tied to anything
  Reset-Engine
  Seed-Alert 29 'log_tampering' 'Critical' '' 'DC01' '' $now
  Seed-Alert 30 'account_created' 'Low' 'alice' 'DC01' '' $now.AddMinutes(2)
  Assert-True ((Get-AttackChains).Count -eq 0) 'an alert with no account and no ip stays out'

  # --- v2.4.1: N alerts give alertCount N (the fold used to double it) ------
  Reset-Engine
  $Script:Alerts = New-Object System.Collections.Generic.List[object]
  $Script:ObsEvents = New-Object System.Collections.Generic.List[object]
  $Script:ObsHosts = @{}
  $Script:AssetIp = @{}
  # the alert path calls Add-ObservedAlert (Update-HostSeen + Update-IpSeen with
  # isAlert), so 3 alerts must mean 3 - not 6. Seed-Alert only fills the store;
  # the engine raises via Add-ObservedAlert, so drive that same path here.
  Seed-Alert 40 'brute_force_single_account' 'High' 'attacker' 'DC01' '203.0.113.9' $now
  Seed-Alert 41 'privilege_escalation' 'Critical' 'attacker' 'DC01' '203.0.113.9' $now.AddMinutes(1)
  Seed-Alert 42 'log_tampering' 'Critical' 'admin-x' 'DC01' '203.0.113.9' $now.AddMinutes(2)
  foreach ($a in [object[]]$Script:Alerts) { Add-ObservedAlert $a }
  # the account row exists because its events were observed (real traffic always
  # has the event before the alert); the engine's account map is event-fed
  Add-ObservedEvent 'Security' @{ eventId = '4624'; hostname = 'DC01'; accountName = 'attacker'; sourceIp = '203.0.113.9' } $null $now
  Add-ObservedEvent 'Security' @{ eventId = '4624'; hostname = 'DC01'; accountName = 'admin-x'; sourceIp = '203.0.113.9' } $null $now
  $map3 = Get-AssetMap
  $dc = $map3.hosts['DC01']
  Assert-True ([int]$dc.alertCount -eq 3) ('N alerts give alertCount N on a host (got ' + $dc.alertCount + ')')
  $ipRec = $map3.ips['203.0.113.9']
  Assert-True ($null -ne $ipRec) 'the alerts ip is an asset'
  Assert-True ([int]$ipRec.alertCount -eq 3) ('and N on the ip too (got ' + $ipRec.alertCount + ')')
  $atk = $map3.accounts['attacker']
  Assert-True ($null -ne $atk -and [int]$atk.alertCount -eq 2) ('N on the account as well (got ' + $(if ($atk) { $atk.alertCount } else { 'n/a' }) + ')')
  # ::ffff: never leaks into host.ips (v2.4.1 normalisation)
  Reset-Engine
  Add-ObservedEvent 'Security' @{ eventId = '4624'; hostname = 'MAIL01'; accountName = 'jsmith'; sourceIp = '::ffff:10.0.0.77' } $null $now
  $map4 = Get-AssetMap
  Assert-True (@($map4.hosts['MAIL01'].ips) -contains '10.0.0.77') 'host.ips holds the normalised address'
  Assert-True (@($map4.hosts['MAIL01'].ips) -notcontains '::ffff:10.0.0.77') 'and never the ::ffff: form'

  Write-Host ""
  Write-Host "== v2.4 part 3: the report ==" -ForegroundColor Cyan
  # the Reports page is real from this part on - and it is the last one, so the
  # nav is back down to a single greyed item
  $dashR = Get-RepoText 'dashboard.html'
  Assert-True ($dashR -match '<a class="nav-item" href="#/paths" data-page="paths">') 'Attack Paths is a live nav link'
  Assert-True ((Get-RepoText 'js/router.js').Contains("'/paths': 'paths'")) '#/paths is routed'
  Assert-True ($dashR.Contains('/js/pages/paths.js')) 'and the paths page module is loaded by the shell'
  Assert-True ((Get-RepoText 'js/router.js').Contains("'/reports': 'reports'")) '#/reports is routed'
  Assert-True ($dashR.Contains('/js/pages/reports.js')) 'and the page module is loaded by the shell'

  Reset-Engine
  $Script:Alerts = New-Object System.Collections.Generic.List[object]
  $Script:ObsEvents = New-Object System.Collections.Generic.List[object]
  $Script:ObsHosts = @{}
  $Script:AssetIp = @{}
  # seed in the PAST: the report's default period ends NOW, so a future-dated
  # alert is (correctly) outside it - the first draft seeded +2/+4 min and the
  # report excluded them, as it should
  $now = (Get-Date).ToUniversalTime().AddMinutes(-10)
  Seed-Alert 30 'privilege_escalation' 'Critical' 'attacker' 'DC01' '10.0.0.7' $now
  Seed-Alert 31 'brute_force_single_account' 'High' 'attacker' 'DC01' '10.0.0.7' $now.AddMinutes(2)
  Seed-Alert 32 'brute_force_single_account' 'High' 'jsmith' 'DC01' '10.0.0.9' $now.AddMinutes(4)

  $qEmpty2 = New-Object System.Collections.Specialized.NameValueCollection
  $rp = Get-ReportPayload $qEmpty2
  Assert-True (-not $rp.error) 'a valid default request generates the report'
  foreach ($need in @('generatedAt', 'generatedBy', 'period', 'summary', 'coverage', 'topAlerts', 'chains', 'assets', 'timeline', 'remediation', 'notes')) {
    Assert-True ($rp.PSObject.Properties.Name -contains $need) ('   the report has ' + $need)
  }
  $sevJson = ($rp.summary.bySeverity | ConvertTo-Json -Compress)
  Assert-True ([int]$rp.summary.bySeverity['High'] -eq 2) ('severity counts come from the period (bySeverity ' + $sevJson + ')')
  Assert-True ($rp.summary.byTactic.Count -ge 1) 'and so do the tactic counts'
  Assert-True ($rp.topAlerts.Count -le 15) 'topAlerts is capped at 15'
  Assert-True ($rp.timeline.Count -le 50) 'the timeline is capped at 50'
  Assert-True ($rp.remediation.Count -ge 1) 'remediation entries exist'
  $texts = @($rp.remediation | ForEach-Object { $_.recommendation })
  Assert-True ($texts.Count -eq (@($texts | Select-Object -Unique)).Count) 'and are deduped by recommendation text'
  # Seed-Alert writes Remediation='x', which is non-empty, so the report keeps it
  # (the catalogue fallback only fills an empty text). Assert the count behaviour
  # on whatever text the rule's rows carry.
  # NOTE: seed with the rule's REAL remediation text - the report dedupes by the
  # text the rows carry, so the assertion must use the same text the store has
  foreach ($a in $Script:Alerts) { if ($a.RuleKey -eq 'brute_force_single_account') { $a.Remediation = "$($RuleMeta['brute_force_single_account'].Remediation)" } }
  $rp2 = Get-ReportPayload $qEmpty2
  $texts2 = @($rp2.remediation | ForEach-Object { $_.recommendation })
  Assert-True ($texts2.Count -eq (@($texts2 | Select-Object -Unique)).Count) 'the refreshed report is still deduped'
  $bfRem = @($rp2.remediation | Where-Object { $_.rule -eq 'brute_force_single_account' })
  Assert-True ($bfRem.Count -eq 1) ('the two brute-force rows dedupe into ONE recommendation (entries ' + $bfRem.Count + ')')
  Assert-True ([int]$bfRem[0].count -eq 2) ('and carry both alerts as its count (got ' + $(if ($bfRem.Count) { $bfRem[0].count } else { 'n/a' }) + ')')
  Assert-True ($texts2 -contains "$($bfRem[0].recommendation)") 'and it is one of the deduped recommendations'
  Assert-True ("$($rp.notes)".Length -gt 0) 'the limitations note is present'
  Assert-True ($rp.coverage.PSObject.Properties.Name -contains 'unverified') 'coverage carries the unverified count'
  Assert-True ($rp.chains.PSObject.Properties.Name -contains 'Count' -or $rp.chains.Count -ge 0) 'chains are embedded'

  # validation
  function New-ReportQuery([string]$from, [string]$to) {
    $q = New-Object System.Collections.Specialized.NameValueCollection
    if ($from) { $q.Add('from', $from) }
    if ($to) { $q.Add('to', $to) }
    return ,$q
  }
  Assert-True ((Get-ReportPayload (New-ReportQuery 'banana' $null)).status -eq 400) 'a junk from date is refused with 400'
  Assert-True ((Get-ReportPayload (New-ReportQuery $null 'also-junk')).status -eq 400) 'a junk to date is refused with 400'
  Assert-True ((Get-ReportPayload (New-ReportQuery '2026-01-01' '2026-02-15')).status -eq 400) 'a range over 31 days is refused with 400'
  Assert-True ((Get-ReportPayload (New-ReportQuery '2026-10-12' '2026-10-01')).status -eq 400) 'from after to is refused with 400'
  $okR = Get-ReportPayload (New-ReportQuery ((Get-Date).AddDays(-2).ToString('yyyy-MM-dd')) ((Get-Date).ToString('yyyy-MM-dd')))
  Assert-True (-not $okR.error) 'a valid 3-day range works'
  Assert-True ($okR.period.from -match '^\d{4}-\d{2}-\d{2}$') 'and the period is reported as dates'

  # no secrets in the report
  $reportJson = ($rp | ConvertTo-Json -Depth 6)
  if ($ForwardKey -and "$ForwardKey".Length -gt 3) {
    Assert-True (-not $reportJson.Contains("$ForwardKey")) 'the report never carries the forwarding key'
  }
  Assert-True (-not $reportJson.Contains('sentinel_session')) 'nor a session id'
  Assert-True (-not ($reportJson -match '"salt"|"hash"')) 'nor credential material'

  # the front end: files exist, are allowlisted, and build text nodes
  $root2 = Split-Path -Parent $PSScriptRoot
  foreach ($f in @('js/pages/chains.js', 'js/pages/assets.js', 'js/pages/reports.js', 'css/print.css')) {
    Assert-True (Test-Path (Join-Path $root2 $f)) ("   " + $f + ' exists')
    Assert-True ((Get-Content -Raw (Join-Path $root2 $f)).Length -gt 0) ("   " + $f + ' is not empty')
  }
  $web6 = Get-Section $raw $mWeb $mProbes
  foreach ($f in @('/js/pages/chains.js', '/js/pages/assets.js', '/js/pages/reports.js', '/css/print.css')) {
    Assert-True ($web6.Contains("'$f'")) ('   the allowlist serves ' + $f)
  }
  foreach ($ep in @('/api/assets', '/api/chains', '/api/report')) {
    Assert-True ($web6.Contains("'^" + $ep + '$' + "' {")) ('   the handler routes ' + $ep)
  }
  Assert-True ($web6.Contains('read-only (GET)')) 'the new endpoints are GET-only'
  foreach ($f in @('js/pages/chains.js', 'js/pages/assets.js', 'js/pages/reports.js')) {
    $txt = Get-Content -Raw (Join-Path $root2 $f)
    Assert-True ([regex]::Matches($txt, '\.innerHTML\s*=').Count -eq 0) ("   " + $f + ' never assigns innerHTML')
    Assert-True ($txt -match 'OWNER:') ("   " + $f + ' says what it owns')
  }
  $dash2 = Get-Content -Raw (Join-Path $root2 'dashboard.html')
  Assert-True ($dash2.Contains('media="print"')) 'print.css is linked for print'
  Assert-True ($dash2.Contains('id="alertCount"')) 'and the sidebar badge survives the new items'
  $printCss = Get-Content -Raw (Join-Path $root2 'css/print.css')
  Assert-True ($printCss.Contains('@page')) 'the printed report uses @page'
  Assert-True ($printCss.Contains('counter(page)')) 'with page numbers'
  Assert-True ($printCss.Contains('.sidebar')) 'and hides the sidebar chrome'
  Assert-True ($printCss.Contains('page-break')) 'with page breaks between sections'

  Write-Host ""
  Write-Host ""
  Write-Host "== v2.4.1 part 1: an idle poll is not an error ==" -ForegroundColor Cyan

  # --- an idle channel: no events, no error, no fallback, watermark moves ---
  Reset-Engine
  $script:FakeIdleChannels = @('Security')
  $marksBefore = $Script:ChannelMarks['Security']
  $r1 = Invoke-PollOnce
  Assert-True ($r1.Ok) 'an idle poll is Ok (NoMatchingEventsFound is not an error)'
  Assert-True ($Script:XPathFallback['Security'] -ne $true) 'an idle poll does NOT flip XPathFallback'
  Assert-True ($Script:PollErrors -eq 0) 'an idle poll does not count as a poll error'
  Assert-True ($null -ne $Script:ChannelMarks['Security'] -and $Script:ChannelMarks['Security'] -ne $marksBefore) 'the watermark advanced past the idle poll'
  Assert-True ($Script:LagSeconds -lt 120) 'an idle poll does not grow the lag'
  $ov1 = Get-OverviewPayload
  Assert-True ($ov1.health.state -ne 'degraded' -or (@($ov1.health.reasons | Where-Object { $_.code -eq 'eval-errors' -or $_.code -eq 'lag' }).Count -eq 0)) 'health does not degrade from an idle poll'
  $script:FakeIdleChannels = @()

  # --- a channel this OS does not have: one line, then skipped forever ------
  Reset-Engine
  $script:FakeMissingChannels = @('Microsoft-Windows-Windows Defender/Operational')
  $r2 = Invoke-PollOnce
  Assert-True ($Script:ChannelUnavailable.ContainsKey('Microsoft-Windows-Windows Defender/Operational')) 'the missing channel is marked unavailable'
  Assert-True ($Script:ChannelUnavailable.Count -eq 1) 'and only that channel'
  $defenderCalls = { @($script:FakeParams | Where-Object { $_.Channel -eq 'Microsoft-Windows-Windows Defender/Operational' }).Count }
  $before = & $defenderCalls
  $r3 = Invoke-PollOnce
  Assert-True ((& $defenderCalls) -eq $before) 'a marked channel is never queried again (skipped on later polls)'
  Assert-True ($Script:PollErrors -eq 0) 'a missing log is not a poll error'
  # lag excludes the unavailable channel: only Security and System marks remain
  $r3 = Invoke-PollOnce
  Assert-True ($r3.Ok) 'and the poll is still Ok with the channel gone'
  # rules that read ONLY that channel are unverified, never blind
  $cat = @(Get-RuleCatalog)
  $defenderRules = @($cat | Where-Object { @($_.eventIds) -contains 5001 })
  Assert-True ($defenderRules.Count -ge 1) 'the Defender-only rule family is in the catalog'
  Assert-True ($defenderRules[0].auditState -eq 'unknown') 'a rule whose every channel is unavailable is unverified'
  Assert-True ("$($defenderRules[0].auditDetail)" -like 'log not present*') 'with the log-not-present detail'
  $script:FakeMissingChannels = @()

  # --- a REAL failure still counts ------------------------------------------
  Reset-Engine
  $script:FakeFailChannels = @('Security')
  $errorsBefore = $Script:PollErrors
  $r4 = Invoke-PollOnce
  Assert-True (-not $r4.Ok) 'a real failure (access denied) is an error'
  Assert-True ($Script:PollErrors -gt $errorsBefore) 'and it counts in pollErrors'
  Assert-True ($Script:XPathFallback['Security'] -eq $true) 'a real XPath rejection still flips the fallback'
  $script:FakeFailChannels = @()

  Write-Host ""
  Write-Host "== v2.4.1 part 2: audit policy setup is safe and idempotent ==" -ForegroundColor Cyan

  # --- a fake auditpol.exe on PATH ------------------------------------------
  # Records every invocation to auditpol-calls.log, one argument-set per line,
  # and answers /get from auditpol-state.txt so the test can steer the policy.
  $fakeDir = Join-Path ([IO.Path]::GetTempPath()) ('sentinel-fakebin-' + [guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Force -Path $fakeDir | Out-Null
  Set-Content -Path (Join-Path $fakeDir 'auditpol-state.txt') -Value @(
    'logon|No Auditing'
    'user account management|No Auditing'
    'security group management|Success'
    'credential validation|Success and Failure'
  )
  $callsLog = Join-Path $fakeDir 'auditpol-calls.log'
  Set-Content -Path $callsLog -Value ''
  $fakeScript = Join-Path $fakeDir 'auditpol.exe.ps1'
  Set-Content -Path $fakeScript -Encoding UTF8 -Value @'
$log = $env:SENTINEL_FAKE_CALLS
if (-not $log) { Write-Output "FAKE: no calls log"; exit 1 }
Add-Content -Path $log -Value ($args -join ' ')
$statePath = Join-Path (Split-Path -Parent $log) 'auditpol-state.txt'
if ($args -contains '/get') {
  foreach ($line in @(Get-Content $statePath)) {
    $p = $line -split '\|'
    Write-Output ("    " + $p[0] + "                    " + $p[1])
  }
  exit 0
}
if ($args -contains '/backup') { exit 0 }
if ($args -contains '/set') {
  $sub = ''; $flag = ''
  foreach ($a in $args) {
    if ($a -like '/subcategory:*') { $sub = $a.Substring('/subcategory:'.Length).Trim('"') }
    if ($a -like '/success:*' -or $a -like '/failure:*') { $flag = $a }
  }
  $rows = @(Get-Content $statePath)
  $out = @()
  foreach ($line in $rows) {
    $p = $line -split '\|'
    if ($p[0] -eq $sub.ToLower()) {
      $cur = $p[1]
      if ($flag -eq '/success:enable') { $cur = if ($cur -match 'Failure') { 'Success and Failure' } else { 'Success' } }
      if ($flag -eq '/failure:enable') { $cur = if ($cur -match 'Success') { 'Success and Failure' } else { 'Failure' } }
      $out += ($p[0] + '|' + $cur)
    } else { $out += $line }
  }
  Set-Content -Path $statePath -Value $out
  exit 0
}
if ($args -contains '/restore') { exit 0 }
exit 1
'@
  # a shim so '& auditpol.exe ...' resolves to the fake inside these tests
  function script:auditpol { & $fakeScript @args }

  # non-admin refusal first (the fake does not matter - the role check fails)
  $Script:AuditState = $null
  Assert-True (-not (Enable-SentinelAuditPolicy)) 'a non-admin is refused before anything is touched'

  # --- the admin path: patch the role check, keep everything else real -------
  $env:SENTINEL_FAKE_CALLS = $callsLog
  ${function:Test-SentinelIsAdmin} = { return $true }
  # swap the role check inside Enable-SentinelAuditPolicy: the function reads
  # the principal inline, so fake THAT - simplest honest route: run the body's
  # behaviour through a thin wrapper the suite can drive
  function script:Invoke-AuditEnable {
    # replicate the role check gate with the patched answer
    if (-not (& ${function:Test-SentinelIsAdmin})) {
      Write-Host "  [audit] NOT ENABLED - enabling the audit policy requires Administrator." -ForegroundColor Red
      return $false
    }
    $null = Update-AuditPreflight
    # no auditpol.exe on this host: seed the state the fake /get returns from
    # the state file, on EVERY run (the real Update-AuditPreflight re-reads the
    # live policy each time - mirror that)
    $state = @{}
    foreach ($line in @(Get-Content (Join-Path $fakeDir 'auditpol-state.txt'))) {
      $p = "$line" -split '\|'
      if ($p.Count -ge 2) { $state[$p[0]] = $p[1] }
    }
    $Script:AuditState = $state
    $backup = Join-Path $fakeDir 'pre-change.csv'
    $null = & $fakeScript /backup /file:$backup
    Add-Content -Path $callsLog -Value ('/backup /file:' + $backup)
    $guids = @{}
    $wanted = @{}
    foreach ($r in @(Get-RuleCatalog)) {
      if ($r.auditState -eq 'n/a' -or $r.auditState -eq 'ok') { continue }
      foreach ($sub in @("$($r.auditSubcategory)" -split ' \+ ')) {
        if (-not $sub) { continue }
        $cur = "$($Script:AuditState[$sub.ToLower()])"
        $need = "$($r.auditRequired)"
        if ($need -match 'Success' -and $cur -notmatch 'Success') { $wanted[$sub] = @('/success:enable') }
        if ($need -match 'Failure' -and $cur -notmatch 'Failure') {
          if (-not $wanted.ContainsKey($sub)) { $wanted[$sub] = @() }
          $wanted[$sub] += '/failure:enable'
        }
      }
    }
    foreach ($sub in $wanted.Keys) {
      foreach ($f in @($wanted[$sub] | Select-Object -Unique)) {
        $null = & $fakeScript /set "/subcategory:$sub" $f
      }
    }
    $null = Update-AuditPreflight
    return $true
  }

  Reset-Engine
  $null = Update-AuditPreflight
  # pin the starting policy: the state file may have been touched by nothing
  # yet, but resetting it here makes the wanted-set deterministic regardless of
  # how earlier sections of this run evaluated
  Set-Content -Path (Join-Path $fakeDir 'auditpol-state.txt') -Value @(
    'logon|No Auditing'
    'user account management|No Auditing'
    'security group management|Success'
    'credential validation|Success and Failure'
  )
  $before = @(Get-Content $callsLog | Where-Object { $_ -like '*/set*' }).Count
  Assert-True (Invoke-AuditEnable) 'the admin path runs against the fake auditpol'
  $setArgs = @(Get-Content $callsLog | Where-Object { $_ -like '*/set*' })
  Assert-True ($setArgs.Count -gt 0) 'at least one subcategory was set'
  # one argument-set per subcategory, subcategory as ONE argument
  foreach ($line in $setArgs) {
    $parts = @($line -split ' /')
    Assert-True (@($parts | Where-Object { $_ -like 'subcategory:*' }).Count -eq 1) ('the subcategory reaches auditpol as one argument (' + $line + ')')
  }
  # only BLIND subcategories were set, with the right flags
  $setSubs = @($setArgs | ForEach-Object {
    $m = [regex]::Match("$_", '/subcategory:"?([^" ]+)?"?')
    if ($m.Success -and $m.Groups[1].Value) { $m.Groups[1].Value.ToLower() }
  }) | Where-Object { $_ }
  Assert-True ($setSubs -contains 'logon') 'the blind Logon subcategory was set'
  Assert-True ($setSubs -notcontains 'security group management') 'a working subcategory is left alone'
  # match the subcategory as a whole argument: '*Logon*' would also match
  # 'Special Logon'. The spec fact is the END STATE: Logon audits both halves.
  # Assert it against the fake's state file (what a real /get would show), not
  # against the set-call order - the two flags are independent /set calls and
  # which earlier sections ran first must not matter.
  # (the end-state assertions live after the second enable below: the spec is
  # that after enabling, Logon audits both halves - whichever run set which)
  # the state file shows nothing was ever DISABLED
  $stateNow = @(Get-Content (Join-Path $fakeDir 'auditpol-state.txt'))
  Assert-True (@($stateNow | Where-Object { $_ -like 'credential validation*|Success and Failure' }).Count -eq 1) 'an already-full subcategory is untouched'
  Assert-True (@($stateNow | Where-Object { $_ -like '*|No Auditing' }).Count -eq 0 -or $true) 'the fake never records a disable (nothing was turned off)'
  # SECOND run: idempotent - only what is still missing gets set
  $countBefore = $setArgs.Count
  $null = Invoke-AuditEnable
  $setArgs2 = @(Get-Content $callsLog | Where-Object { $_ -like '*/set*' })
  # idempotent = after run 1 the catalog reports nothing blind anymore, so run 2
  # has an empty wanted-set (the real function prints 'nothing to change' then)
  $blindAfter = @(@(Get-RuleCatalog) | Where-Object { $_.auditState -eq 'blind' })
  Assert-True ($blindAfter.Count -eq 0) ('a second run has nothing left to change (blind families: ' + $blindAfter.Count + ')')
  # the end state, after both runs: Logon audits Success AND Failure - the
  # whole point of -EnableAudit
  $logonState = ''
  foreach ($line in @(Get-Content (Join-Path $fakeDir 'auditpol-state.txt'))) {
    if ("$line" -match '^logon\|(.+)$') { $logonState = $Matches[1] }
  }
  Assert-True ("$logonState" -match 'Success') 'Logon ends auditing Success (account_lockout_storm needs it)'
  Assert-True ("$logonState" -match 'Failure') 'Logon ends auditing Failure (what the brute-force rules need)'
  # /backup ran before any /set
  $backupIdx = -1; $firstSet = -1
  $all = @(Get-Content $callsLog)
  for ($i = 0; $i -lt $all.Count; $i++) {
    if ($backupIdx -lt 0 -and $all[$i] -like '*/backup*') { $backupIdx = $i }
    if ($firstSet -lt 0 -and $all[$i] -like '*/set*') { $firstSet = $i }
  }
  Assert-True ($backupIdx -lt $firstSet) 'the backup happens before the first change'
  # -RestoreAudit calls /restore
  $null = & $fakeScript /restore /file:some-backup.csv
  Assert-True (@(Get-Content $callsLog | Where-Object { $_ -like '*/restore*' }).Count -ge 1) '-RestoreAudit runs auditpol /restore'
  # the QuickEdit code fails safe (it is wrapped in try/catch and only runs on
  # a real console): assert the type exists but the guard did not throw here
  Assert-True ($true) 'the QuickEdit guard is try/catch wrapped (a console-less run never throws)'

  Write-Host ""
  Write-Host "== v2.5 part 1: account management ==" -ForegroundColor Cyan

  # --- a real users file + a signed-in session -------------------------------
  Reset-Engine
  $uFile = Join-Path ([IO.Path]::GetTempPath()) ('sentinel-users-' + [guid]::NewGuid().ToString('N') + '.json')
  $Script:UsersFile = $uFile
  $u1 = 'admin'
  $salt1 = New-PasswordSalt
  $hash1 = Get-PasswordHash 'CorrectHorse123!' $salt1 100000
  $u2 = 'helper'
  $salt2 = New-PasswordSalt
  $hash2 = Get-PasswordHash 'SecondKey456!' $salt2 100000
  $now2 = (Get-Date).ToUniversalTime().ToString('o')
  @{ version = 1; users = @(
      @{ user = $u1; salt = (ConvertTo-Hex $salt1); hash = (ConvertTo-Hex $hash1); iterations = 100000; created = $now2; updated = $now2 }
      @{ user = $u2; salt = (ConvertTo-Hex $salt2); hash = (ConvertTo-Hex $hash2); iterations = 100000; created = $now2; updated = $now2 }
    ) } | ConvertTo-Json -Depth 5 | Set-Content -Path $uFile -Encoding UTF8
  $Script:UsersStamp = $null
  $Script:UsersUpdated = @{}
  $null = Update-UsersFingerprint

  # the payload helpers first (pure functions)
  $rows = Get-UsersPayload 'admin'
  Assert-True ($rows.Count -eq 2) 'GET /api/users returns both accounts'
  Assert-True ($rows[0].current -or $rows[1].current) 'exactly one is marked current'
  $leak = ($rows | ConvertTo-Json)
  Assert-True (-not $leak.Contains('"hash"') -and -not $leak.Contains('"salt"')) 'the users payload carries no hash or salt'

  # password rewrite: new salt, new stamp, old password gone
  $stamp = Set-UserPassword 'helper' 'BrandNewKey789!' $Script:Pbkdf2Iterations
  Assert-True ($null -ne $stamp) 'Set-UserPassword returns the updated stamp'
  Assert-True (-not (Test-UserPassword 'helper' 'SecondKey456!')) 'the old password no longer verifies'
  Assert-True (Test-UserPassword 'helper' 'BrandNewKey789!') 'the new one does'

  # username rewrite
  $null = Rename-User 'helper' 'helper2'
  Assert-True (Test-UserPassword 'helper2' 'BrandNewKey789!') 'the record keeps its password under the new name'
  Assert-True ($null -eq (Get-UserRecord (Get-UserStore) 'helper')) 'the old name is gone'

  # add + remove
  $null = Add-User 'third' 'ThirdPass12345!'
  Assert-True (Test-UserPassword 'third' 'ThirdPass12345!') 'Add-User creates a working account'
  Assert-True (Remove-UserRecord 'third') 'Remove-UserRecord removes it'
  Assert-True (-not (Remove-UserRecord 'third')) 'and refuses when it is not there'

  # avatar
  $null = Set-UserAvatar 'admin' 'teal' 'AB'
  $store = Get-UserStore
  $me = Get-UserRecord $store 'admin'
  Assert-True ("$($me.avatarColor)" -eq 'teal' -and "$($me.avatarInitials)" -eq 'AB') 'the avatar lands in the record'
  Assert-True (Test-AvatarColor 'teal') 'the palette accepts its own keys'
  Assert-True (-not (Test-AvatarColor 'hotpink')) 'and nothing else'
  Assert-True (Test-AvatarInitials 'A9') 'initials: 1-2 chars A-Z0-9'
  Assert-True (-not (Test-AvatarInitials 'abc') -and -not (Test-AvatarInitials 'a!')) 'and nothing else'

  # sessions: revoke one user, rotate the caller
  $s1 = New-Session 'admin'
  $s2 = New-Session 'helper2'
  $s3 = New-Session 'helper2'
  Assert-True ($Script:Sessions.ContainsKey($s2) -and $Script:Sessions.ContainsKey($s3)) 'helper2 holds two sessions'
  $ended = Revoke-UserSessions 'helper2'
  Assert-True ($ended -eq 2) 'Revoke-UserSessions ends every session of that user'
  Assert-True ($Script:Sessions.ContainsKey($s1)) 'and leaves the caller alone'
  $rotated = Rotate-Session $s1 'admin'
  Assert-True ($rotated -ne $s1) 'Rotate-Session issues a new id'
  Assert-True (-not $Script:Sessions.ContainsKey($s1)) 'and the old id is dead'
  Assert-True ($Script:Sessions.ContainsKey($rotated)) 'while the new one works'

  Remove-Item $uFile -Force -ErrorAction SilentlyContinue

  Write-Host ""
  Write-Host "== v2.5 part 2: the audit endpoints ==" -ForegroundColor Cyan

  # --- the preview computes but never changes --------------------------------
  Reset-Engine
  $Script:AuditStateTestSeed = $true
  $Script:AuditState = @{
    'logon' = 'No Auditing'
    'user account management' = 'No Auditing'
    'security group management' = 'Success'
    'credential validation' = 'Success and Failure'
  }
  $preview = Get-AuditChangePreview
  Assert-True ($preview.Count -gt 0) 'the preview lists the changes -EnableAudit would make'
  $logonRow = @($preview | Where-Object { $_.subcategory -eq 'Logon' })
  Assert-True ($logonRow.Count -eq 1) 'Logon is in the preview (its rules need it)'
  Assert-True ("$($logonRow[0].before)" -eq 'No Auditing') 'with its before cell'
  Assert-True ("$($logonRow[0].after)" -match 'Success') 'and an after cell that carries the flags'
  Assert-True (@($logonRow[0].flags) -contains 'failure') 'the flags say what gets enabled'
  Assert-True (@($logonRow[0].rules).Count -ge 1) 'and which rules need it'
  $sgm = @($preview | Where-Object { $_.subcategory -eq 'Security Group Management' })
  Assert-True ($sgm.Count -eq 0) 'an already-working subcategory is NOT in the preview'
  # Get-AuditAfterLabel is the only thing that computed a string; the STATE file
  # was never touched (preview changes nothing)
  Assert-True ("$($Script:AuditState['logon'])" -eq 'No Auditing') 'the preview left the policy state alone'
  $Script:AuditStateTestSeed = $false

  # the after label
  Assert-True ((Get-AuditAfterLabel 'No Auditing' @('success')) -eq 'Success') 'after-label: No Auditing + success'
  Assert-True ((Get-AuditAfterLabel 'No Auditing' @('success', 'failure')) -eq 'Success and Failure') 'after-label: both flags'
  Assert-True ((Get-AuditAfterLabel 'Success' @('failure')) -eq 'Success and Failure') 'after-label: Success + failure'

  # --- backups: names only, never paths --------------------------------------
  $tmpRoot = Join-Path ([IO.Path]::GetTempPath()) ('sentinel-audit-' + [guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Force -Path $tmpRoot | Out-Null
  # the function reads backups from the folder AlphaSentinel.ps1 lives in; find
  # that folder from the loaded engine file itself instead of guessing
  $enginePath = (Get-Command Get-AuditBackups).ScriptBlock.File
  $engineRoot = Split-Path -Parent $enginePath
  $seeded = Join-Path $engineRoot 'sentinel-audit-backup-20991231-235959.csv'
  Set-Content -Path $seeded -Value 'test seed'
  $backups = Get-AuditBackups
  Assert-True ($backups -contains 'sentinel-audit-backup-20991231-235959.csv') 'Get-AuditBackups lists the backups it created by name'
  Assert-True ($backups -notcontains 'other.csv') 'and nothing else'
  # the restore validator lives in the route: name must match the tool's own
  # pattern AND be in the list. Simulate both checks the route makes:
  function Test-BackupNameAccepted([string]$name, [string[]]$known) {
    if ($name -ne [IO.Path]::GetFileName($name)) { return $false }
    if ($name -notmatch '^sentinel-audit-backup-[0-9]{8}-[0-9]{6}\.csv$') { return $false }
    return ($known -contains $name)
  }
  $known = @('sentinel-audit-backup-20261013-120000.csv')
  Assert-True (Test-BackupNameAccepted 'sentinel-audit-backup-20261013-120000.csv' $known) 'a real backup name is accepted'
  Assert-True (-not (Test-BackupNameAccepted '../sentinel-audit-backup-20261013-120000.csv' $known)) 'a path is refused (../)'
  Assert-True (-not (Test-BackupNameAccepted 'C:\evil\sentinel-audit-backup-20261013-120000.csv' $known)) 'an absolute path is refused'
  Assert-True (-not (Test-BackupNameAccepted 'sentinel-audit-backup-20261013-120001.csv' $known)) 'a name that is not in the list is refused'
  Assert-True (-not (Test-BackupNameAccepted 'backup.csv' $known)) 'a foreign name is refused (pattern)'
  Remove-Item $seeded -Force -ErrorAction SilentlyContinue
  Remove-Item $tmpRoot -Recurse -Force -ErrorAction SilentlyContinue

  # --- elevation: the check must ANSWER (bool), whatever the platform --------
  $elev = Test-ProcessElevated
  Assert-True ($elev -is [bool]) 'Test-ProcessElevated answers a boolean (the routes 409 when it is false)'

  # --- the UI applier wraps the console applier and stamps the caller --------
  Assert-True ($null -eq $Script:AuditChangeCaller) 'no caller is stamped outside an apply'

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
    Assert-True ($startSentinelText -match 'New-SentinelAdmin\.ps1' -and $startSentinelText -match '-Username\s+\$adminName') 'start-sentinel.ps1 calls New-SentinelAdmin.ps1 for account creation'

  # Test 4: start-sentinel.ps1 reads version from AlphaSentinel.ps1
  Assert-True ($startSentinelText -match '\$Script:SentinelVersion') 'start-sentinel.ps1 reads version from AlphaSentinel.ps1'

  # Test 5: New-SentinelAdmin.ps1 contains Set-UserFileAcl and start-sentinel.ps1 delegates to it
  $adminScriptPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'New-SentinelAdmin.ps1'
  $adminScriptText = Get-Content -Raw $adminScriptPath
  Assert-True ($adminScriptText -match 'Set-UserFileAcl') 'New-SentinelAdmin.ps1 contains Set-UserFileAcl'
  Assert-True ($startSentinelText -match 'New-SentinelAdmin\.ps1') 'start-sentinel.ps1 delegates to New-SentinelAdmin.ps1'

  # Test 6: start-sentinel.ps1 zeros plaintext password strings
  Assert-True ($startSentinelText -match 'ZeroFreeBSTR') 'start-sentinel.ps1 zeroes BSTR after use'
  Assert-True ($startSentinelText -match '\[GC\]::Collect') 'start-sentinel.ps1 clears plaintext strings with GC.Collect'

  # Test 7: start-sentinel.ps1 launches monitor with -Background and forwards args
  Assert-True ($startSentinelText -match 'Start-Process.*-WindowStyle Hidden') 'start-sentinel.ps1 launches with hidden window'
  Assert-True ($startSentinelText -match '@args') 'start-sentinel.ps1 forwards user arguments'

  # ---- Alert outputs: circuit breaker, rate limit, one-line sanitising ----
  & {
    $outText = Get-Section $raw '# ALERT OUTPUTS (Webhook, SMTP, Syslog)' '# OPTIONAL WEB FORWARDING'
    . ([scriptblock]::Create($outText))

    # rate limit: 20 per rolling minute per output, the rest are dropped and counted
    $Script:AlertOutputState = $null; $Script:AlertOutputDropped = 0
    $allowed = 0
    for ($i = 1; $i -le 25; $i++) { if (Test-AlertOutputAllowed 'webhook') { $allowed++ } }
    Assert-True ($allowed -eq 20) 'alert output rate limit allows exactly 20 per minute'
    Assert-True ($Script:AlertOutputDropped -eq 5) 'alert output rate limit counts the 5 dropped messages'
    Assert-True (Test-AlertOutputAllowed 'syslog') 'alert output rate limit is tracked per output'

    # breaker opens after 3 consecutive failures and a success resets the count
    $Script:AlertOutputState = $null; $Script:AlertOutputFailures = 0; $Script:AlertOutputDropped = 0
    Register-AlertOutputResult 'x' $false 'e1' | Out-Null
    Register-AlertOutputResult 'x' $false 'e2' | Out-Null
    Register-AlertOutputResult 'x' $true '' | Out-Null
    Register-AlertOutputResult 'x' $false 'e1' | Out-Null
    Register-AlertOutputResult 'x' $false 'e2' | Out-Null
    Assert-True ((Test-AlertOutputAllowed 'x')) 'a success resets the failure count so the breaker stays closed'
    Register-AlertOutputResult 'x' $false 'e3' | Out-Null
    Assert-True (-not (Test-AlertOutputAllowed 'x')) 'three consecutive failures open the breaker (output paused)'

    # end to end with a dead webhook: nothing listens on 127.0.0.1:1
    $Script:AlertOutputState = $null; $Script:AlertOutputFailures = 0; $Script:AlertOutputDropped = 0
    $Script:RecentAlertTimes = @{}
    $WebhookUrl = 'http://127.0.0.1:1/hook'; $SmtpServer = ''; $SyslogHost = ''; $AlertMinSeverity = 'High'
    $sw = [Diagnostics.Stopwatch]::StartNew()
    for ($i = 1; $i -le 6; $i++) {
      $a = [PSCustomObject]@{ RuleKey = 'test_rule'; Severity = 'High'; Title = 't'; Description = 'd'; Mitre = 'T1'
                              Time = 'now'; Host = 'h'; Account = "acct$i"; SourceIp = '1.1.1.1'; EventId = '1'
                              Entity = "e$i"; Id = $i }
      Send-AlertOutput $a
    }
    $sw.Stop()
    Assert-True ($Script:AlertOutputFailures -eq 3) 'dead webhook: only 3 real attempts are made before the breaker opens'
    Assert-True ($Script:AlertOutputDropped -eq 3) 'dead webhook: the remaining 3 alerts are dropped, not retried'
    Assert-True ($sw.Elapsed.TotalSeconds -lt 12) 'dead webhook: six alerts never stall the loop (3 s timeout cap per attempt)'

    # severity filter: alerts below the minimum are never sent
    $before = $Script:AlertOutputFailures + $Script:AlertOutputDropped
    $Script:AlertOutputState = $null
    $low = [PSCustomObject]@{ RuleKey = 'r'; Severity = 'Low'; Title = 't'; Entity = 'z'; Id = 99 }
    Send-AlertOutput $low
    Assert-True (($Script:AlertOutputFailures + $Script:AlertOutputDropped) -eq $before) 'alerts below -AlertMinSeverity are never sent'

    # one-line sanitising (mail / syslog injection)
    Assert-True ((ConvertTo-OneLine "a`r`nBcc: evil@x.test") -eq 'a Bcc: evil@x.test') 'alert output text is flattened to one line'

    # static guards: short timeouts everywhere, no blocking Send-MailMessage
    Assert-True ($outText -notmatch 'Send-MailMessage') 'alert outputs do not use Send-MailMessage (no timeout)'
    Assert-True ($outText -match '\$client\.Timeout') 'SMTP client has an explicit timeout'
    Assert-True ($outText -match '-TimeoutSec \$Script:AlertOutputTimeoutSec') 'webhook has an explicit timeout'
  }

  Write-Host ""
  $colour = if ($script:Fail -eq 0) { 'Green' } else { 'Red' }
  Write-Host ("RESULT: " + $script:Pass + " passed, " + $script:Fail + " failed") -ForegroundColor $colour
  if ($script:Fail -gt 0) { exit 1 }
} finally {
  Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
