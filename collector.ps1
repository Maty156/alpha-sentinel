# ============================================================================
# Alpha Cybersecurity - Windows Event Collector (headless)
# ============================================================================
# Run this on your lab DC (as Administrator). Polls the Security event log for
# every event ID the ALPHA detection engine understands, normalises the fields
# each rule needs, and forwards them to the web platform's
# POST /api/detections/ingest endpoint over HTTPS.
#
# For the full 28-family coverage table see ALPHA Sentinel's local
# GET /api/rules, or the web platform's admin panel ->
# Detections -> Detection Coverage (GET /api/admin/rules).
#
# SETUP (run once, as Administrator) - enable every audit category the rules
# read. Skipping one silently means that rule family can never fire. The
# mapping below is event ID -> Advanced Audit subcategory, and matches the
# live audit-policy preflight in AlphaSentinel.ps1
# (GET /api/preflight), which flags any family left blind:
#   auditpol /set /subcategory:"Logon" /success:enable /failure:enable                      ; 4624 4625 4648
#   auditpol /set /subcategory:"Special Logon" /success:enable                              ; 4672
#   auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable      ; 4776
#   auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable            ; 4740
#   auditpol /set /subcategory:"User Account Management" /success:enable                    ; 4720 4722 4724 4725 4726 4738
#   auditpol /set /subcategory:"Security Group Management" /success:enable                  ; 4728 4729 4732 4733 4756
#   auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable ; 4768 4771
#   auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable         ; 4769
#   auditpol /set /subcategory:"Directory Service Access" /success:enable                   ; 4662
#   auditpol /set /subcategory:"Directory Service Changes" /success:enable                  ; 5141
#   auditpol /set /subcategory:"Other Object Access Events" /success:enable                 ; 4698
#   auditpol /set /subcategory:"Security System Extension" /success:enable                  ; 4697
#   auditpol /set /subcategory:"Registry" /success:enable                                   ; 4657
#   auditpol /set /subcategory:"Audit Policy Change" /success:enable                        ; 4719
#   auditpol /set /subcategory:"Security State Change" /success:enable                      ; 4616
#   auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:enable            ; 4946 4947 4948 4949
#
# NOT gated by audit policy (no auditpol entry needed):
#   1100 1102  Eventlog service shutdown / log cleared - written by the Eventlog
#              service itself to the SECURITY log (1102 also needs no policy).
#   7045       Service Control Manager, SYSTEM log.
#   5001 5010 5012  Defender OPERATIONAL channel, not the Security log.
#
# USAGE:
#   $env:ALPHA_URL = "https://your-app.vercel.app/api/detections/ingest"
#   $env:ALPHA_KEY = "same value as COLLECTOR_API_KEY on the server"
#   .\collector.ps1
# ============================================================================
#Requires -RunAsAdministrator

param(
  [string]$AlphaUrl = $env:ALPHA_URL,
  [string]$AlphaKey = $env:ALPHA_KEY,
  [int]$PollSeconds = 30,
  [int]$MaxEventsPerBatch = 500,
  [int]$TimeoutSec = 20,
  [string]$StateFile = "",
  [switch]$Once
)

# Watermark file: lets a restart resume exactly where the previous run stopped
# instead of re-sending the last window or skipping the downtime.
if (-not $StateFile) {
  $StateFile = if ($PSScriptRoot) { Join-Path $PSScriptRoot "collector-state.json" } else { "collector-state.json" }
}

if (-not $AlphaUrl -or -not $AlphaKey) {
  Write-Error "Set ALPHA_URL and ALPHA_KEY (env vars or -AlphaUrl/-AlphaKey params) before running."
  exit 1
}

# Windows PowerShell 5.1 defaults to TLS 1.0/1.1 on older builds, which the
# hosted platform (and any modern endpoint) refuses - without this the very
# first Invoke-RestMethod fails on Server 2012 R2 / 2008 R2.
try {
  [Net.ServicePointManager]::SecurityProtocol =
    [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch { }

# Every event ID the ALPHA rule catalog watches (28 families / 36 event IDs) -
# grouped by the log channel each one is actually written to. A rule whose
# event lives in a channel this list omits can never fire, no matter how
# correct the rule is:
#   7045            -> System log (Service Control Manager)
#   5001/5010/5012  -> Microsoft-Windows-Windows Defender/Operational
#   1100/1102/4616  -> Security log. 1100 ("event logging service has shut
#                      down") is written by Microsoft-Windows-Eventlog to the
#                      SECURITY channel, not System - monitoring System for it
#                      silently never fires (verified against Microsoft's
#                      event-1100 reference XML: <Channel>Security</Channel>).
$LogSources = @(
  @{ Log = 'Security'; Ids = @(
      4624, 4625, 4648, 4657, 4662, 4672, 4697, 4698, 4719, 4720, 4722, 4724,
      4725, 4726, 4728, 4729, 4732, 4733, 4738, 4740, 4756, 4768, 4769, 4771,
      4776, 4946, 4947, 4948, 4949, 5141, 1100, 1102, 4616
    )
  }
  @{ Log = 'System'; Ids = @(7045) }
  @{ Log = 'Microsoft-Windows-Windows Defender/Operational'; Ids = @(5001, 5010, 5012) }
)

$MonitoredEventIdCount = (@($LogSources | ForEach-Object { $_.Ids }) | Select-Object -Unique).Count

# Event-loss fix: the old single $lastCheck was set to "now" AFTER processing,
# so every event written while a slow poll was running was skipped forever, and
# it advanced even when the POST had failed. Watermarks are now per channel,
# advanced only on a successful send, and persisted (see $marks / Save-Marks).

function Get-Field($xml, $name) {
  $node = $xml.Event.EventData.Data | Where-Object { $_.Name -eq $name }
  if ($node) { return $node.'#text' } else { return $null }
}

# Returns the first non-empty value among the given field names - event IDs
# disagree about what they call the same thing (e.g. 4776 uses "Workstation",
# 4625 uses "WorkstationName"; 7045 uses "ImagePath", 4697 "ServiceFileName").
function Get-FirstField($xml, [string[]]$names) {
  foreach ($n in $names) {
    $v = Get-Field $xml $n
    if ($v) { return $v }
  }
  return $null
}

function Normalize-Event($e) {
  $xml = [xml]$e.ToXml()
  $id = $e.Id

  $base = @{
    eventId   = "$id"
    timestamp = $e.TimeCreated.ToUniversalTime().ToString("o")
    hostname  = $env:COMPUTERNAME
  }

  switch ($id) {
    4625 {
      $base.accountName     = Get-Field $xml "TargetUserName"
      $base.sourceIp        = Get-Field $xml "IpAddress"
      $base.logonType       = Get-Field $xml "LogonType"
      $base.statusCode      = Get-Field $xml "Status"
      $base.subStatusCode   = Get-Field $xml "SubStatus"
      $base.workstationName = Get-Field $xml "WorkstationName"
    }
    4624 {
      $base.accountName     = Get-Field $xml "TargetUserName"
      $base.sourceIp        = Get-Field $xml "IpAddress"
      $base.logonType       = Get-Field $xml "LogonType"
      $base.workstationName = Get-Field $xml "WorkstationName"
    }
    { $_ -in 4728, 4729, 4732, 4733, 4756 } {
      # member + the group it was added to / removed from
      $base.accountName     = Get-Field $xml "MemberName"
      $base.memberName      = Get-Field $xml "MemberName"
      $base.targetGroup     = Get-Field $xml "TargetUserName"
      $base.subjectUserName = Get-Field $xml "SubjectUserName"
    }
    { $_ -in 4720, 4722, 4724, 4725, 4726 } {
      $base.accountName     = Get-Field $xml "TargetUserName"
      $base.targetUserName  = Get-Field $xml "TargetUserName"
      $base.subjectUserName = Get-Field $xml "SubjectUserName"
    }
    4738 {
      $base.accountName           = Get-Field $xml "TargetUserName"
      $base.targetUserName        = Get-Field $xml "TargetUserName"
      $base.subjectUserName       = Get-Field $xml "SubjectUserName"
      $base.oldUserAccountControl = Get-Field $xml "OldUacValue"
      $base.newUserAccountControl = Get-Field $xml "NewUacValue"
    }
    4740 {
      # TargetUserName is the LOCKED account; SubjectUserName is the caller
      $base.accountName     = Get-Field $xml "TargetUserName"
      $base.subjectUserName = Get-Field $xml "SubjectUserName"
      $base.workstationName = Get-FirstField $xml @("TargetDomainName")
    }
    { $_ -in 4768, 4769 } {
      $base.accountName    = Get-Field $xml "TargetUserName"
      $base.serviceName    = Get-Field $xml "ServiceName"
      $base.encryptionType = Get-Field $xml "TicketEncryptionType"
      $base.sourceIp       = Get-Field $xml "IpAddress"
      $base.statusCode     = Get-Field $xml "Status"
      $base.ticketOptions  = Get-Field $xml "TicketOptions"
      if ($id -eq 4768) { $base.preAuthType = Get-Field $xml "PreAuthType" }
    }
    4771 {
      $base.accountName   = Get-Field $xml "TargetUserName"
      $base.sourceIp      = Get-Field $xml "IpAddress"
      $base.statusCode    = Get-Field $xml "Status"
      $base.ticketOptions = Get-Field $xml "TicketOptions"
    }
    4776 {
      # Credential Validation - the workstation field is named "Workstation"
      $base.accountName     = Get-Field $xml "TargetUserName"
      $base.workstationName = Get-Field $xml "Workstation"
      $base.statusCode      = Get-Field $xml "Status"
    }
    { $_ -in 4662, 5141 } {
      # 4662: the extended rights that were exercised are listed in Properties.
      # The replication GUIDs that identify DCSync live THERE, not in
      # ObjectType - ObjectType carries the object CLASS (e.g. domainDNS or the
      # class GUID). Matching the replication GUIDs against ObjectType, as this
      # collector previously did, meant the DCSync rule could never fire on a
      # real event. Verified against Microsoft's 4662 reference XML and every
      # published DCSync detection (Splunk/Sigma: Properties|contains the GUID).
      $base.subjectUserName = Get-Field $xml "SubjectUserName"
      $base.objectType      = Get-Field $xml "ObjectType"
      $base.objectName      = Get-Field $xml "ObjectName"
      $base.properties      = Get-Field $xml "Properties"
      $base.accessMask      = Get-Field $xml "AccessMask"
      # legacy alias - platform builds older than this one read the DCSync
      # field under the name shareName
      $base.shareName       = $base.properties
    }
    { $_ -in 4697, 7045 } {
      $base.subjectUserName = Get-Field $xml "SubjectUserName"
      $base.accountName     = Get-FirstField $xml @("SubjectUserName", "AccountName")
      $base.serviceName     = Get-Field $xml "ServiceName"
      # 4697 logs ServiceFileName; 7045 logs ImagePath
      $base.serviceBinaryPath = Get-FirstField $xml @("ServiceFileName", "ImagePath")
      $base.imagePath         = Get-Field $xml "ImagePath"
    }
    4698 {
      $base.subjectUserName = Get-Field $xml "SubjectUserName"
      $base.taskName        = Get-Field $xml "TaskName"
      # Task content is XML inside one field - keep a bounded slice so the
      # 512-char server cap does not silently drop the command line.
      $content = Get-Field $xml "TaskContent"
      if ($content) { $base.commandLine = $content.Substring(0, [Math]::Min(400, $content.Length)) }
    }
    4657 {
      $base.subjectUserName     = Get-Field $xml "SubjectUserName"
      $base.objectName          = Get-Field $xml "ObjectName"
      $base.registryKey         = Get-Field $xml "ObjectName"
      $base.registryValueName   = Get-Field $xml "ObjectValueName"
    }
    { $_ -in 4946, 4947, 4948, 4949 } {
      $base.subjectUserName = Get-Field $xml "SubjectUserName"
      $base.ruleName        = Get-Field $xml "RuleName"
    }
    4672 {
      $base.accountName   = Get-Field $xml "SubjectUserName"
      $base.privilegeList = Get-Field $xml "PrivilegeList"
    }
    4648 {
      $base.accountName      = Get-Field $xml "SubjectUserName"
      $base.subjectUserName  = Get-Field $xml "SubjectUserName"
      $base.targetUserName   = Get-Field $xml "TargetUserName"
      $base.targetServerName = Get-Field $xml "TargetServerName"
      $base.processName      = Get-Field $xml "ProcessName"
    }
    4719 {
      $base.subjectUserName = Get-Field $xml "SubjectUserName"
      $base.subcategory     = Get-FirstField $xml @("SubcategoryId", "CategoryId")
    }
    4616 {
      $base.subjectUserName = Get-Field $xml "SubjectUserName"
      $base.newTime         = Get-Field $xml "NewTime"
    }
    { $_ -in 5001, 5010, 5012 } {
      $base.eventSource = "Microsoft-Windows-Windows Defender"
    }
  }

  # Drop empty keys - the server treats a present-but-empty field as a value.
  $clean = @{}
  foreach ($k in $base.Keys) {
    if ($base[$k] -ne $null -and "$($base[$k])" -ne '') { $clean[$k] = $base[$k] }
  }
  return $clean
}

# Windows PowerShell 5.1 has no ConvertTo-Json -AsArray, so build the array
# explicitly - always emits a JSON array, on every PS version.
function ConvertTo-JsonArray($items) {
  $parts = @()
  foreach ($i in @($items)) { $parts += ($i | ConvertTo-Json -Compress -Depth 5) }
  return "[" + ($parts -join ",") + "]"
}

# Post one batch, with bounded retry. Returns @{ ok = $true/$false; ... }.
# A 4xx is treated as permanent (a bad key or malformed payload will never
# succeed on retry), everything else is retried with exponential backoff so a
# brief platform outage does not silently drop the events.
function Send-EventBatch($items) {
  $body = ConvertTo-JsonArray $items
  $attempt = 0
  while ($true) {
    $attempt++
    try {
      $r = Invoke-RestMethod -Uri $AlphaUrl -Method Post -Body $body `
             -ContentType "application/json" `
             -Headers @{ "X-Alpha-Collector-Key" = $AlphaKey } `
             -TimeoutSec $TimeoutSec -ErrorAction Stop
      return @{ ok = $true; result = $r }
    } catch {
      $permanent = $false
      try {
        $resp = $_.Exception.Response
        if ($resp) {
          $code = [int]$resp.StatusCode
          if ($code -ge 400 -and $code -lt 500) { $permanent = $true }
        }
      } catch { }
      if ($permanent -or $attempt -ge 3) {
        return @{ ok = $false; error = "$_" }
      }
      $wait = [int][Math]::Min(30, [Math]::Pow(2, $attempt))
      Write-Warning "send failed (attempt $attempt/$3): $_ - retrying in $wait sec"
      Start-Sleep -Seconds $wait
    }
  }
}

# Per-channel watermark, persisted so a collector restart neither re-sends the
# last window (duplicate alerts) nor skips everything written while it was
# down. The old single shared $lastCheck advanced even when a send FAILED, so
# every event in a failed window was lost permanently.
$marks = @{}
foreach ($s in $LogSources) { $marks[$s.Log] = (Get-Date).AddMinutes(-2) }

if (Test-Path $StateFile) {
  try {
    $saved = Get-Content -Raw $StateFile | ConvertFrom-Json
    foreach ($s in $LogSources) {
      $v = $saved.($s.Log.Replace('.', '_').Replace('/', '_').Replace('-', '_'))
      if ($v) { $marks[$s.Log] = [datetime]$v }
    }
    Write-Host "Resumed watermarks from $StateFile."
  } catch {
    Write-Warning "Could not read $StateFile - starting with a 2 minute backfill: $_"
  }
}

function Save-Marks {
  try {
    $o = @{}
    foreach ($s in $LogSources) {
      $key = $s.Log.Replace('.', '_').Replace('/', '_').Replace('-', '_')
      $o[$key] = $marks[$s.Log].ToUniversalTime().ToString("o")
    }
    $o | ConvertTo-Json | Set-Content -Path $StateFile -Encoding UTF8 -Force
  } catch { }
}

Write-Host "ALPHA collector started. Polling $MonitoredEventIdCount event IDs across $($LogSources.Count) log channels every $PollSeconds seconds. Ctrl+C to stop."

while ($true) {
  foreach ($source in $LogSources) {
    try {
      # Watermark is read BEFORE the query and only advanced after a successful
      # send, so events written while we were normalising/posting are picked up
      # on the next pass instead of falling into the gap.
      $since = $marks[$source.Log]
      $events = Get-WinEvent -FilterHashtable @{
        LogName   = $source.Log
        Id        = $source.Ids
        StartTime = $since
      } -ErrorAction SilentlyContinue

      if ($events) {
        # Get-WinEvent returns newest-first; sort oldest-first so that when the
        # batch is capped we send the OLDEST events and keep the newest for the
        # next pass (the previous code sent the newest and threw the rest away).
        $batch = @($events) | Sort-Object TimeCreated
        $truncated = $false
        if ($batch.Count -gt $MaxEventsPerBatch) {
          $truncated = $true
          $pending = $batch.Count - $MaxEventsPerBatch
          $batch = $batch | Select-Object -First $MaxEventsPerBatch
        }

        $normalized = @($batch | ForEach-Object { Normalize-Event $_ })
        $send = Send-EventBatch $normalized

        if ($send.ok) {
          # Advance the watermark only to the last event actually accepted.
          $marks[$source.Log] = ($batch | Select-Object -Last 1).TimeCreated
          Save-Marks
          $procd = if ($null -ne $send.result.processed) { $send.result.processed } else { '?' }
          $fired = if ($null -ne $send.result.alertsFired) { $send.result.alertsFired } else { '?' }
          $note  = if ($truncated) { " ($pending more event(s) queued for the next pass)" } else { "" }
          Write-Host "$(Get-Date -Format o)  [$($source.Log)] sent $($normalized.Count) event(s) - server processed $procd, fired $fired alert(s).$note"
        } else {
          Write-Warning "$($source.Log): send failed, $($normalized.Count) event(s) will be retried next pass (watermark NOT advanced): $($send.error)"
        }
      }
    } catch {
      Write-Warning "Error polling $($source.Log): $_"
    }
  }

  if ($Once) { Write-Host "Single pass complete (-Once)."; break }
  Start-Sleep -Seconds $PollSeconds
}
