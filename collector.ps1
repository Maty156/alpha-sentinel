# Alpha Cybersecurity — Windows Event Collector
# Run this on your lab DC (as Administrator). Polls Security Event Log every
# 30 seconds for the 5 event types ALPHA's detection engine understands, and
# forwards new ones to ALPHA over HTTPS.
#
# SETUP (run once, as Administrator):
#   auditpol /set /subcategory:"Logon" /success:enable /failure:enable
#   auditpol /set /subcategory:"Security Group Management" /success:enable
#   auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable
#   auditpol /set /subcategory:"Other Object Access Events" /success:enable
#
# USAGE:
#   $env:ALPHA_URL = "https://your-app.vercel.app/api/detections/ingest"
#   $env:ALPHA_KEY = "same value as COLLECTOR_API_KEY on the server"
#   .\collector.ps1

param(
  [string]$AlphaUrl = $env:ALPHA_URL,
  [string]$AlphaKey = $env:ALPHA_KEY,
  [int]$PollSeconds = 30
)

if (-not $AlphaUrl -or -not $AlphaKey) {
  Write-Error "Set ALPHA_URL and ALPHA_KEY (env vars or -AlphaUrl/-AlphaKey params) before running."
  exit 1
}

$EventIds = @(4625, 4728, 4732, 4769, 4624, 4697, 7045)
$lastCheck = (Get-Date).AddMinutes(-2)  # small backfill on first run

function Get-Field($xml, $name) {
  $node = $xml.Event.EventData.Data | Where-Object { $_.Name -eq $name }
  if ($node) { return $node.'#text' } else { return $null }
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
      $base.accountName = Get-Field $xml "TargetUserName"
      $base.sourceIp    = Get-Field $xml "IpAddress"
    }
    { $_ -in 4728, 4732 } {
      $base.accountName = Get-Field $xml "MemberName"
      $base.targetGroup = Get-Field $xml "TargetUserName"
    }
    4769 {
      $base.accountName    = Get-Field $xml "TargetUserName"
      $base.serviceName    = Get-Field $xml "ServiceName"
      $base.encryptionType = Get-Field $xml "TicketEncryptionType"
    }
    4624 {
      $base.accountName = Get-Field $xml "TargetUserName"
      $base.sourceIp    = Get-Field $xml "IpAddress"
      $base.logonType   = Get-Field $xml "LogonType"
    }
    { $_ -in 4697, 7045 } {
      $base.accountName       = Get-Field $xml "SubjectUserName"
      $base.serviceName       = Get-Field $xml "ServiceName"
      $base.serviceBinaryPath = Get-Field $xml "ServiceFileName"
    }
  }

  return $base
}

Write-Host "ALPHA collector started. Polling every $PollSeconds seconds. Ctrl+C to stop."

while ($true) {
  try {
    $events = Get-WinEvent -FilterHashtable @{
      LogName = 'Security'
      Id      = $EventIds
      StartTime = $lastCheck
    } -ErrorAction SilentlyContinue

    if ($events) {
      $normalized = $events | ForEach-Object { Normalize-Event $_ }
      $body = $normalized | ConvertTo-Json -AsArray -Depth 4

      try {
        Invoke-RestMethod -Uri $AlphaUrl -Method Post -Body $body `
          -ContentType "application/json" `
          -Headers @{ "X-Alpha-Collector-Key" = $AlphaKey } | Out-Null
        Write-Host "$(Get-Date -Format o)  Sent $($normalized.Count) event(s)."
      } catch {
        Write-Warning "Failed to send events to ALPHA: $_"
      }
    }

    $lastCheck = Get-Date
  } catch {
    Write-Warning "Error polling event log: $_"
  }

  Start-Sleep -Seconds $PollSeconds
}
