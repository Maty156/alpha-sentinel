# ============================================================================
# ALPHA SENTINEL v2 — AD / Network Attack Monitor (background service + web UI)
# ============================================================================
# A standalone Windows security monitor from the ALPHA Cybersecurity project.
# Like Wazuh's agent+dashboard model, but as ONE script with zero dependencies:
#
#   - Runs in the BACKGROUND (service-style, no window needed): polls the
#     Windows Security event log every -PollSeconds, runs 8 AD/network
#     detection rule families (Kerberoasting, AS-REP roasting, LDAP/SAMR
#     enumeration, password spraying, privilege escalation, suspicious remote
#     logons, service abuse, log tampering), and keeps alerts in memory +
#     a history CSV so acks survive restarts.
#   - Serves a MODERN WEB DASHBOARD on http://0.0.0.0:<Port> (default 8443):
#     open it from any browser on the network — Wazuh-style dark UI with
#     severity stat tiles, live search, severity/status filters, auto-refresh,
#     per-alert detail with MITRE ATT&CK mapping and remediation guidance,
#     acknowledge/unacknowledge, a /api/self-test endpoint, and CSV export.
#   - Optionally forwards every detection to the ALPHA web platform
#     (separate private repo: Maty156/alpha) so the same alert appears in
#     its admin Detections tab. Forwarding is optional; without it Sentinel
#     works fully standalone.
#
# QUICK START (as Administrator — reading the Security log requires elevation):
#   # enable audit categories once:
#   auditpol /set /subcategory:"Logon" /success:enable /failure:enable
#   auditpol /set /subcategory:"Security Group Management" /success:enable
#   auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable
#   auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable
#   auditpol /set /subcategory:"SAM" /success:enable
#   auditpol /set /subcategory:"Other Object Access Events" /success:enable
#
#   # run in the BACKGROUND (console closes, monitor + web UI keep running):
#   Start-Process powershell -ArgumentList '-ExecutionPolicy Bypass -File .\AlphaSentinel.ps1 -Background' -WindowStyle Hidden
#
#   # or run in the FOREGROUND with a small console window:
#   powershell -ExecutionPolicy Bypass -File .\AlphaSentinel.ps1
#
#   # then open:  http://localhost:8443   (or http://<DC-IP>:8443 from any machine)
#
# Optional flags:
#   -Port 8443                  web dashboard port
#   -PollSeconds 15             event-log poll interval
#   -Background                 run with no console window (service-style)
#   -ForwardUrl / -ForwardKey   forward detections to the ALPHA web platform
#   -HistoryFile                alert history CSV (default sentinel-history.csv)
#
# STOP the background monitor:
#   Stop-Sentinel   (helper function registered globally by this script)
# ============================================================================
#Requires -RunAsAdministrator

param(
  [int]$Port = 8443,
  [int]$PollSeconds = 15,
  [switch]$Background,
  [string]$ForwardUrl = "",
  [string]$ForwardKey = "",
  [string]$HistoryFile = ""
)

if (-not $HistoryFile -and $PSScriptRoot) {
  $HistoryFile = Join-Path $PSScriptRoot "sentinel-history.csv"
}

# ============================================================
# DETECTION RULES (8 families)
# ============================================================
$PrivilegedGroups = @('domain admins', 'enterprise admins', 'schema admins',
                      'administrators', 'account operators', 'backup operators')

$RuleMeta = @{
  password_spraying       = @{ Severity = 'High';     EventId = '4625';       Title = 'Suspicious Password Spraying Activity'
                               Mitre = 'T1110.003 - Brute Force: Password Spraying'
                               Remediation = 'Enforce account lockout policy, smart-card auth, and password spray detections on the DC. Block the source IP at the firewall.' }
  privilege_escalation    = @{ Severity = 'Critical'; EventId = '4728/4732';  Title = 'User Added to Privileged Group'
                               Mitre = 'T1078.002 - Valid Accounts: Domain Accounts'
                               Remediation = 'Immediately review group membership changes, reset the added account password, and check for lateral movement from that account.' }
  kerberoasting           = @{ Severity = 'High';     EventId = '4769';       Title = 'Kerberos Service Ticket Request (Kerberoasting)'
                               Mitre = 'T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting'
                               Remediation = 'Use gMSA with 128+ bit keys, disable RC4, and rotate the targeted service account password.' }
  asrep_roasting          = @{ Severity = 'High';     EventId = '4768';       Title = 'AS-REP Roasting (No-Preauth Ticket Request)'
                               Mitre = 'T1558.004 - Steal or Forge Kerberos Tickets: AS-REP Roasting'
                               Remediation = 'Ensure "Do not require Kerberos preauthentication"=OFF for all accounts and audit any account with preauth disabled.' }
  suspicious_remote_logon = @{ Severity = 'Medium';   EventId = '4624';       Title = 'Suspicious Remote Logon'
                               Mitre = 'T1021 - Remote Services'
                               Remediation = 'Verify the logon is expected, restrict RDP by firewall/GPO, and enable MFA for administrative remote access.' }
  ldap_recon              = @{ Severity = 'Medium';   EventId = '4662/5141';  Title = 'LDAP / SAMR Domain Enumeration'
                               Mitre = 'T1018 - Remote System Discovery / T1087 - Account Discovery'
                               Remediation = 'Harden SAMR enumeration via GPO (restrict anonymous access) and investigate the source host for recon tooling (BloodHound, SharpHound).' }
  service_abuse           = @{ Severity = 'Medium';   EventId = '4697/7045';  Title = 'Suspicious Service Creation/Modification'
                               Mitre = 'T1543.003 - Create or Modify System Process: Windows Service'
                               Remediation = 'Audit service binaries, restrict service creation to admins, and hunt for encoded PowerShell in the binary path.' }
  log_tampering           = @{ Severity = 'Critical'; EventId = '1102';       Title = 'Security Log Cleared (Anti-Forensics)'
                               Mitre = 'T1070.001 - Indicator Removal: Clear Windows Event Logs'
                               Remediation = 'Treat as an active intrusion. Isolate the host, preserve remaining logs, and review what was deleted.' }
}

$Script:RecentFailedLogons = @{}   # sourceIp -> list of (account, time)
$Script:RecentAsrep = @{}          # account -> list of time
$Script:RecentLdap = @{}           # sourceIp -> list of time
$Script:RecentAlertTimes = @{}     # ruleKey -> last-fired time (dedupe)
$Script:Alerts = New-Object System.Collections.Generic.List[object]
$Script:NextAlertId = 1

# restore history: alerts + ack state survive restarts
if (Test-Path $HistoryFile) {
  try {
    Import-Csv $HistoryFile | ForEach-Object {
      $ruleKey = $_.'RuleKey'
      if ($ruleKey -and $RuleMeta.ContainsKey($ruleKey)) {
        $meta = $RuleMeta[$ruleKey]
        $idInt = 0
        [void][int]::TryParse($_.'Id', [ref]$idInt)
        $Script:Alerts.Add([PSCustomObject]@{
          Id           = $idInt
          Time         = $_.'Time'
          RuleKey      = $ruleKey
          Rule         = $meta.EventId
          Severity     = $meta.Severity
          Title        = $meta.Title
          Mitre        = $meta.Mitre
          Remediation  = $meta.Remediation
          Description  = $_.'Description'
          Host         = $_.'Host'
          Account      = $_.'Account'
          SourceIp     = $_.'SourceIp'
          EventId      = $meta.EventId
          Acknowledged = ($_.'Acknowledged' -eq 'yes')
        })
        if ($idInt -ge $Script:NextAlertId) { $Script:NextAlertId = $idInt + 1 }
      }
    }
  } catch { }
}

function Should-Dedupe($ruleKey) {
  if ($Script:RecentAlertTimes.ContainsKey($ruleKey)) {
    if ((Get-Date) - $Script:RecentAlertTimes[$ruleKey] -lt (New-TimeSpan -Minutes 15)) { return $true }
  }
  $Script:RecentAlertTimes[$ruleKey] = Get-Date
  return $false
}

function Get-Field($xml, $name) {
  $node = $xml.Event.EventData.Data | Where-Object { $_.Name -eq $name }
  if ($node) { return $node.'#text' } else { return $null }
}

function New-Alert($ruleKey, $description, $severityOverride, $hostName, $account, $sourceIp, $realEventId) {
  $meta = $RuleMeta[$ruleKey]
  $sev = if ($severityOverride) { $severityOverride } else { $meta.Severity }
  $alert = [PSCustomObject]@{
    Id           = $Script:NextAlertId
    Time         = (Get-Date).ToUniversalTime().ToString("o")
    RuleKey      = $ruleKey
    Rule         = $meta.EventId
    Severity     = $sev
    Title        = $meta.Title
    Mitre        = $meta.Mitre
    Remediation  = $meta.Remediation
    Description  = $description
    Host         = $hostName
    Account      = $account
    SourceIp     = $sourceIp
    EventId      = "$realEventId"
    Acknowledged = $false
  }
  $Script:NextAlertId++
  return $alert
}

# Returns an alert object, or $null if this event didn't trigger anything.
function Evaluate-Event($e) {
  $xml = [xml]$e.ToXml()
  $id = $e.Id
  $hostName = $e.Machine

  switch ($id) {
    4625 {
      # Password spraying: many distinct accounts failing from one source / 10 min
      $account = Get-Field $xml "TargetUserName"
      $srcIp = Get-Field $xml "IpAddress"
      if (-not $srcIp -or $srcIp -eq '-') { return $null }
      if (-not $Script:RecentFailedLogons.ContainsKey($srcIp)) { $Script:RecentFailedLogons[$srcIp] = @() }
      $Script:RecentFailedLogons[$srcIp] = @($Script:RecentFailedLogons[$srcIp] | Where-Object { $_.Time -gt (Get-Date).AddMinutes(-10) })
      $Script:RecentFailedLogons[$srcIp] += [PSCustomObject]@{ Account = $account; Time = Get-Date }
      $distinct = ($Script:RecentFailedLogons[$srcIp] | Select-Object -ExpandProperty Account -Unique).Count
      if ($distinct -ge 5 -and -not (Should-Dedupe "password_spraying")) {
        return New-Alert "password_spraying" "$distinct distinct accounts failed to authenticate from $srcIp within 10 minutes." $null $hostName $account $srcIp $id
      }
    }
    { $_ -in 4728, 4732 } {
      # Privilege escalation: user added to a privileged group
      $account = Get-Field $xml "MemberName"
      $group = Get-Field $xml "TargetUserName"
      if ($group -and ($PrivilegedGroups | Where-Object { $group.ToLower().Contains($_) })) {
        if (-not (Should-Dedupe "privilege_escalation")) {
          return New-Alert "privilege_escalation" "Account `"$account`" was added to privileged group `"$group`"." $null $hostName $account $null $id
        }
      }
    }
    4769 {
      # Kerberoasting: RC4 (0x17) service ticket requests
      $encType = Get-Field $xml "TicketEncryptionType"
      if ($encType -eq "0x17" -and -not (Should-Dedupe "kerberoasting")) {
        $account = Get-Field $xml "TargetUserName"
        $service = Get-Field $xml "ServiceName"
        return New-Alert "kerberoasting" "Service ticket requested for `"$service`" using weak RC4 encryption (0x17) - account `"$account`"." $null $hostName $account $null $id
      }
    }
    4768 {
      # AS-REP roasting heuristic: repeated no-preauth TGT requests
      $account = Get-Field $xml "TargetUserName"
      if (-not $account) { return $null }
      if (-not $Script:RecentAsrep.ContainsKey($account)) { $Script:RecentAsrep[$account] = @() }
      $Script:RecentAsrep[$account] = @($Script:RecentAsrep[$account] | Where-Object { $_ -gt (Get-Date).AddMinutes(-10) })
      $Script:RecentAsrep[$account] += Get-Date
      $preAuthType = Get-Field $xml "PreAuthType"
      if ($preAuthType -eq "0" -and $Script:RecentAsrep[$account].Count -ge 3 -and -not (Should-Dedupe "asrep_roasting")) {
        return New-Alert "asrep_roasting" "Repeated no-preauth TGT requests for `"$account`" (AS-REP roasting pattern)." $null $hostName $account $null $id
      }
    }
    4624 {
      # Suspicious remote logon: RDP or admin network logon
      $logonType = Get-Field $xml "LogonType"
      $account = Get-Field $xml "TargetUserName"
      $srcIp = Get-Field $xml "IpAddress"
      $isRdp = $logonType -eq "10"
      $isNetworkAdmin = ($logonType -eq "3") -and ($account -match "admin")
      if (($isRdp -or $isNetworkAdmin) -and -not (Should-Dedupe "suspicious_remote_logon")) {
        $kind = if ($isRdp) { 'Remote desktop' } else { 'Network' }
        return New-Alert "suspicious_remote_logon" "$kind logon by `"$account`" from $srcIp." $null $hostName $account $srcIp $id
      }
    }
    { $_ -in 4662, 5141 } {
      # LDAP/SAMR recon: 25+ directory object reads from one source / 5 min
      $srcIp = Get-Field $xml "IpAddress"
      $objName = Get-Field $xml "ObjectName"
      $objType = Get-Field $xml "ObjectType"
      if (-not $srcIp -or $srcIp -eq '-') { return $null }
      if ($objType -and $objType -notmatch '(?i)user|group|computer|domain') { return $null }
      if (-not $Script:RecentLdap.ContainsKey($srcIp)) { $Script:RecentLdap[$srcIp] = @() }
      $Script:RecentLdap[$srcIp] = @($Script:RecentLdap[$srcIp] | Where-Object { $_ -gt (Get-Date).AddMinutes(-5) })
      $Script:RecentLdap[$srcIp] += Get-Date
      if ($Script:RecentLdap[$srcIp].Count -ge 25 -and -not (Should-Dedupe "ldap_recon")) {
        return New-Alert "ldap_recon" "25+ directory object reads (e.g. `"$objName`") from $srcIp within 5 minutes - domain enumeration pattern." $null $hostName $objName $srcIp $id
      }
    }
    { $_ -in 4697, 7045 } {
      # Service abuse: new service with suspicious binary path
      $service = Get-Field $xml "ServiceName"
      $path = Get-Field $xml "ServiceFileName"
      $suspicious = $path -match "(?i)powershell|cmd\.exe|-enc|\\temp\\|\\users\\public\\"
      if (-not (Should-Dedupe "service_abuse")) {
        $sev = if ($suspicious) { "High" } else { "Medium" }
        return New-Alert "service_abuse" "New service `"$service`" created$(if($path){" (binary: $path)"})." $sev $hostName $service $null $id
      }
    }
    1102 {
      # Anti-forensics: security log cleared
      if (-not (Should-Dedupe "log_tampering")) {
        return New-Alert "log_tampering" "The Security event log was cleared on $hostName." $null $hostName ($e.Machine) $null $id
      }
    }
  }
  return $null
}

# ============================================================
# ALERT STORE: history persistence, CSV export
# ============================================================
function Save-History {
  try {
    $Script:Alerts |
      Select-Object Id, Time, RuleKey, Severity, Description, Host, Account, SourceIp, @{ n = 'Acknowledged'; e = { if ($_.Acknowledged) { 'yes' } else { 'no' } } } |
      Export-Csv -Path $HistoryFile -NoTypeInformation -Force
  } catch { }
}

function Export-AlertsCsv($path) {
  $Script:Alerts |
    Select-Object Id, Time, RuleKey, Severity, Title, Mitre, Account, Host, SourceIp, Description, @{ n = 'Acknowledged'; e = { if ($_.Acknowledged) { 'yes' } else { 'no' } } } |
    Export-Csv -Path $path -NoTypeInformation -Force
  return $Script:Alerts.Count
}

# ============================================================
# EMBEDDED WEB SERVER (dashboard + JSON API) — HttpListener, no deps
# ============================================================
$Script:DashboardDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }

function Send-Bytes($res, $bytes, $contentType, $status = 200) {
  $res.StatusCode = $status
  $res.ContentType = $contentType
  $res.ContentLength64 = $bytes.Length
  $res.OutputStream.Write($bytes, 0, $bytes.Length)
}
function Send-Json($res, $json, $status = 200) {
  Send-Bytes $res ([Text.Encoding]::UTF8.GetBytes($json)) 'application/json; charset=utf-8' $status
}
function Send-File($res, $path, $contentType) {
  # fail LOUDLY (500 + clear message) instead of silently returning an empty
  # 200 when dashboard.html/dashboard.js is missing (e.g. iex-invoked run or
  # only the .ps1 was copied)
  if (-not (Test-Path $path)) {
    $name = [IO.Path]::GetFileName($path)
    Send-Json $res ('{"error":"' + $name + ' not found next to AlphaSentinel.ps1 - download the full release (dashboard.html + dashboard.js must sit beside the script)."}') 500
    return
  }
  Send-Bytes $res ([Text.Encoding]::UTF8.GetBytes((Get-Content -Raw $path))) $contentType
}

function Start-WebServer {
  $listener = New-Object System.Net.HttpListener
  $listener.Prefixes.Add("http://+:$Port/")
  $listener.Start()
  Write-Host "  [web] dashboard listening on http://+:$Port/"
  return $listener
}

# Handle a single HTTP request context. Called from the MAIN thread loop —
# single-threaded by design: PowerShell scriptblocks cannot run on .NET
# ThreadPool threads without a runspace, so the earlier Task.Run web thread
# died silently. One loop drains web requests AND polls the event log
# (works on PS 5.1 / Windows Server 2012).
function Invoke-Handler($ctx) {
  $path = $ctx.Request.Url.AbsolutePath
  $res = $ctx.Response
  try {
          switch -Regex ($path) {
            '^/$' {
              Send-File $res (Join-Path $Script:DashboardDir 'dashboard.html') 'text/html; charset=utf-8'
            }
            '^/dashboard\.js$' {
              Send-File $res (Join-Path $Script:DashboardDir 'dashboard.js') 'application/javascript; charset=utf-8'
            }
            '^/api/alerts$' {
              $json = if ($Script:Alerts.Count -eq 0) { '[]' } else { $Script:Alerts | ConvertTo-Json -Depth 4 -Compress }
              if ($Script:Alerts.Count -eq 1) { $json = "[$json]" }
              Send-Json $res $json
            }
            '^/api/alerts/(\d+)/ack$' {
              $alert = $Script:Alerts | Where-Object { $_.Id -eq [int]$Matches[1] } | Select-Object -First 1
              if ($alert) {
                $alert.Acknowledged = $true
                Save-History
                Send-Json $res '{"ok":true,"acknowledged":true}'
              } else { Send-Json $res '{"error":"Alert not found."}' 404 }
            }
            '^/api/alerts/(\d+)/unack$' {
              $alert = $Script:Alerts | Where-Object { $_.Id -eq [int]$Matches[1] } | Select-Object -First 1
              if ($alert) {
                $alert.Acknowledged = $false
                Save-History
                Send-Json $res '{"ok":true,"acknowledged":false}'
              } else { Send-Json $res '{"error":"Alert not found."}' 404 }
            }
            '^/api/export\.csv$' {
              $tmp = [IO.Path]::GetTempFileName()
              $null = Export-AlertsCsv $tmp
              $res.Headers.Add('Content-Disposition', 'attachment; filename="alpha-sentinel-alerts.csv"')
              Send-Bytes $res ([Text.Encoding]::UTF8.GetBytes((Get-Content -Raw $tmp))) 'text/csv; charset=utf-8'
              Remove-Item $tmp -Force -ErrorAction SilentlyContinue
            }
            '^/api/self-test$' {
              # fires 8 synthetic events through the REAL rule engine — same code path
              # as live event-log polling — and returns what fired.
              $fired = @()
              # snapshot trackers so repeated self-tests are deterministic and
              # probe events never pollute the live dedupe/brute-force state
              $savedTimes = $Script:RecentAlertTimes
              $savedFailed = $Script:RecentFailedLogons
              $savedAsrep = $Script:RecentAsrep
              $savedLdap = $Script:RecentLdap
              $Script:RecentAlertTimes = @{}
              $Script:RecentFailedLogons = @{}
              $Script:RecentAsrep = @{}
              $Script:RecentLdap = @{}
              $probe = @(
                @{ id = 4625; fields = @{ TargetUserName = 'sentinel-selftest'; IpAddress = '127.0.0.99' } }
                @{ id = 4728; fields = @{ MemberName = 'sentinel-selftest'; TargetUserName = 'Domain Admins' } }
                @{ id = 4769; fields = @{ TargetUserName = 'sentinel-selftest'; ServiceName = 'MSSQLSvc/selftest'; TicketEncryptionType = '0x17' } }
                @{ id = 4624; fields = @{ TargetUserName = 'administrator'; IpAddress = '127.0.0.99'; LogonType = '10' } }
                @{ id = 7045; fields = @{ ServiceName = 'SentinelSelfTest'; ServiceFileName = 'C:\Users\Public\selftest.exe -enc AA==' } }
                @{ id = 1102; fields = @{} }
              )
              $firedAlerts = @()
              foreach ($p in $probe) {
                $fieldsXml = ($p.fields.GetEnumerator() | ForEach-Object { "<Data Name='$($_.Key)'>$($_.Value)</Data>" }) -join ''
                $xmlString = "<Event><System><EventID>$($p.id)</EventID><Computer>SENTINEL-SELFTEST</Computer></System><EventData>$fieldsXml</EventData></Event>"
                $shim = New-Object PSObject
                $shimXml = [xml]$xmlString
                $shim | Add-Member -MemberType NoteProperty -Name Id -Value $p.id -Force
                $shim | Add-Member -MemberType NoteProperty -Name Machine -Value 'SENTINEL-SELFTEST' -Force
                $shim | Add-Member -MemberType ScriptProperty -Name XmlObj -Value ({ return $shimXml }.GetNewClosure()) -Force
                $shim | Add-Member -MemberType ScriptMethod -Name ToXml -Value { return $this.XmlObj.OuterXml } -Force
                $alert = Evaluate-Event $shim
                if ($alert) {
                  # land self-test alerts in the real store: they appear in the
                  # dashboard table (severity colors, MITRE, remediation) — the
                  # purple-team demo value — and export marked SENTINEL-SELFTEST
                  $alert.Description = "[SELF-TEST] $($alert.Description)"
                  $Script:Alerts.Add($alert)
                  Save-History
                  $firedAlerts += $alert
                  $fired += "$($alert.Severity): $($alert.Title)"
                }
              }
              $Script:RecentAlertTimes = $savedTimes
              $Script:RecentFailedLogons = $savedFailed
              $Script:RecentAsrep = $savedAsrep
              $Script:RecentLdap = $savedLdap
              Send-Json $res (@{ ok = $true; alertsFired = $firedAlerts.Count; fired = $fired } | ConvertTo-Json)
            }
            '^/api/health$' {
              Send-Json $res (@{ ok = $true; alerts = $Script:Alerts.Count; uptime = $true } | ConvertTo-Json)
            }
            default {
              Send-Json $res '{"error":"Not found."}' 404
            }
          }
  } catch {
    try { Send-Json $res ('{"error":"' + (($_.Exception.Message) -replace '"', "'") + '"}') 500 } catch { }
  } finally {
    try { $res.OutputStream.Close() } catch { }
  }
}

# ============================================================
# OPTIONAL WEB FORWARDING (real event IDs — matches platform rules)
# ============================================================
$Script:Forwarded = 0
function Forward-ToWeb($alert) {
  if (-not $ForwardUrl -or -not $ForwardKey) { return }
  try {
    $body = @{
      eventId     = "$($alert.EventId)"
      source      = "collector"
      hostname    = "$($alert.Host)"
      accountName = "$($alert.Account)"
      timestamp   = $alert.Time
    } | ConvertTo-Json
    Invoke-RestMethod -Uri $ForwardUrl -Method Post -Body $body -ContentType "application/json" `
      -Headers @{ "X-Alpha-Collector-Key" = $ForwardKey } -ErrorAction Stop | Out-Null
    $Script:Forwarded++
  } catch { }
}

# ============================================================
# EVENT-LOG POLLING LOOP
# ============================================================
$EventIds = @(4625, 4728, 4732, 4768, 4769, 4662, 5141, 4624, 4697, 7045, 1102)
$Script:LastCheck = (Get-Date).AddMinutes(-2)
$Script:ProcessedCount = 0

function Invoke-PollOnce {
  try {
    $events = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = $EventIds; StartTime = $Script:LastCheck } -ErrorAction SilentlyContinue
    if ($events) {
      foreach ($e in @($events)) {
        $alert = Evaluate-Event $e
        if ($alert) {
          $Script:Alerts.Add($alert)
          $Script:ProcessedCount++
          Forward-ToWeb $alert
        }
      }
      Save-History
    }
    $Script:LastCheck = Get-Date
    return $true
  } catch {
    Write-Host "  [poll] error: $_" -ForegroundColor Red
    return $false
  }
}

# ============================================================
# STOP HELPER — registered globally so any console can stop the monitor
# ============================================================
# callable from ANY console as `Stop-Sentinel` (a plain scriptblock variable
# would not be invocable by that name from another session)
function global:Stop-Sentinel {
  Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe' OR Name = 'pwsh.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -like '*AlphaSentinel.ps1*' -and $_.ProcessId -ne $PID } |
    ForEach-Object {
      Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
      Write-Host "stopped sentinel process $($_.ProcessId)"
    }
}

# ============================================================
# MAIN — start web server, single-threaded request/poll loop
# ============================================================
$listener = Start-WebServer

Write-Host ""
Write-Host "  ============================================================" -ForegroundColor Red
Write-Host "   ALPHA SENTINEL v2 - AD / Network Attack Monitor" -ForegroundColor Red
Write-Host "  ============================================================" -ForegroundColor Red
Write-Host "   Web dashboard : http://localhost:$Port   (LAN: http://<this-ip>:$Port)" -ForegroundColor Green
Write-Host "   Polling       : Security event log every $PollSeconds sec"
Write-Host "   Rules         : 8 families (spray, privesc, kerberoast, AS-REP,"
Write-Host "                   LDAP recon, remote logon, service abuse, log tamper)"
if ($ForwardUrl) { Write-Host "   Forwarding    : enabled -> $ForwardUrl" -ForegroundColor Yellow }
else { Write-Host "   Forwarding    : off (standalone mode)" -ForegroundColor DarkGray }
Write-Host "   History       : $HistoryFile"
Write-Host "   Stop          : run Stop-Sentinel from any PowerShell console"
Write-Host "   Self-test     : open http://localhost:$Port/api/self-test"
Write-Host ""
Write-Host "   Press Ctrl+C to stop. Dashboard serves while this runs." -ForegroundColor DarkGray
Write-Host ""

# MAIN LOOP — a single thread drains web requests AND polls the event log.
# PowerShell scriptblocks cannot run on .NET ThreadPool threads without a
# runspace, so both loops live on the main thread; the 250 ms sleep keeps the
# loop nearly idle. Works on PS 5.1 / Windows Server 2012.
$Script:NextPoll = (Get-Date).AddSeconds(1)
$Script:PendingTask = $null
try {
  while ($true) {
    if ($null -ne $Script:PendingTask -and $Script:PendingTask.IsCompleted) {
      $ctx = $Script:PendingTask.Result
      $Script:PendingTask = $null
      $null = Invoke-Handler $ctx
      continue   # drain any further queued requests immediately
    }
    if ($null -eq $Script:PendingTask) {
      $Script:PendingTask = $listener.GetContextAsync()
    }
    if ((Get-Date) -ge $Script:NextPoll) {
      $null = Invoke-PollOnce
      $Script:NextPoll = (Get-Date).AddSeconds($PollSeconds)
    }
    Start-Sleep -Milliseconds 250
  }
} finally {
  try { $listener.Stop() } catch { }
  Save-History
}
