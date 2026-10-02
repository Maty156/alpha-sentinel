# ALPHA Blue Team Console
# A standalone Windows desktop tool — NOT a website. Run this directly on the
# DC (or any domain-joined machine with access to the Security event log).
# It opens a real window, polls Windows Security Event Log locally, runs the
# same 5 detection rules ALPHA's web platform uses, shows live alerts in a
# table with color-coded severity, and pops a Windows notification when
# something Critical/High fires — so the AD admin doesn't have to be staring
# at a screen to notice.
#
# It can ALSO optionally forward what it finds to the ALPHA web platform
# (so the same alert shows up in the admin panel and can be promoted into a
# client report) — but that's optional. With forwarding off, this tool works
# fully standalone with zero dependency on the website at all.
#
# SETUP (run once, as Administrator, before first use):
#   auditpol /set /subcategory:"Logon" /success:enable /failure:enable
#   auditpol /set /subcategory:"Security Group Management" /success:enable
#   auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable
#   auditpol /set /subcategory:"Other Object Access Events" /success:enable
#
# RUN (as Administrator — reading the Security log requires elevation):
#   powershell -ExecutionPolicy Bypass -File BlueTeamConsole.ps1
#
# Optional forwarding to the ALPHA web platform:
#   powershell -ExecutionPolicy Bypass -File BlueTeamConsole.ps1 `
#     -ForwardUrl "https://your-app.vercel.app/api/detections/ingest" `
#     -ForwardKey "same value as COLLECTOR_API_KEY on the server"

param(
  [int]$PollSeconds = 15,
  [string]$ForwardUrl = "",
  [string]$ForwardKey = ""
)

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# ============================================================
# DETECTION RULES — same logic as ALPHA's web platform
# (utils/detectionRules.js), ported to PowerShell so this tool
# works fully offline with no dependency on the website.
# ============================================================
$PrivilegedGroups = @('domain admins', 'enterprise admins', 'schema admins', 'administrators', 'account operators', 'backup operators')
$Script:RecentFailedLogons = @{}   # sourceIp -> list of (account, time)
$Script:RecentAlertTimes = @{}     # ruleKey -> last-fired DateTime (dedupe, 15 min)

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

# Returns a hashtable alert object, or $null if this event didn't trigger anything.
function Evaluate-Event($e) {
  $xml = [xml]$e.ToXml()
  $id = $e.Id

  switch ($id) {
    4625 {
      $account = Get-Field $xml "TargetUserName"
      $srcIp = Get-Field $xml "IpAddress"
      if (-not $srcIp) { return $null }
      if (-not $Script:RecentFailedLogons.ContainsKey($srcIp)) { $Script:RecentFailedLogons[$srcIp] = @() }
      $Script:RecentFailedLogons[$srcIp] = @($Script:RecentFailedLogons[$srcIp] | Where-Object { $_.Time -gt (Get-Date).AddMinutes(-10) })
      $Script:RecentFailedLogons[$srcIp] += [PSCustomObject]@{ Account = $account; Time = Get-Date }
      $distinct = ($Script:RecentFailedLogons[$srcIp] | Select-Object -ExpandProperty Account -Unique).Count
      if ($distinct -ge 5 -and -not (Should-Dedupe "password_spraying")) {
        return @{ Severity = "High"; Title = "Suspicious Password Spraying Activity"
                   Mitre = "T1110.003 - Brute Force: Password Spraying"
                   Description = "$distinct distinct accounts failed to authenticate from $srcIp within 10 minutes." }
      }
    }
    { $_ -in 4728, 4732 } {
      $account = Get-Field $xml "MemberName"
      $group = Get-Field $xml "TargetUserName"
      if ($group -and ($PrivilegedGroups | Where-Object { $group.ToLower().Contains($_) })) {
        if (-not (Should-Dedupe "privilege_escalation")) {
          return @{ Severity = "Critical"; Title = "User Added to Privileged Group"
                     Mitre = "T1078.002 - Valid Accounts: Domain Accounts"
                     Description = "Account `"$account`" was added to privileged group `"$group`"." }
        }
      }
    }
    4769 {
      $encType = Get-Field $xml "TicketEncryptionType"
      if ($encType -eq "0x17" -and -not (Should-Dedupe "kerberoasting")) {
        $account = Get-Field $xml "TargetUserName"
        $service = Get-Field $xml "ServiceName"
        return @{ Severity = "High"; Title = "Suspicious Kerberos Service Ticket Request (Kerberoasting)"
                   Mitre = "T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting"
                   Description = "Service ticket requested for `"$service`" using weak RC4 encryption - account `"$account`"." }
      }
    }
    4624 {
      $logonType = Get-Field $xml "LogonType"
      $account = Get-Field $xml "TargetUserName"
      $srcIp = Get-Field $xml "IpAddress"
      $isRdp = $logonType -eq "10"
      $isNetworkAdmin = ($logonType -eq "3") -and ($account -match "admin")
      if (($isRdp -or $isNetworkAdmin) -and -not (Should-Dedupe "suspicious_remote_logon")) {
        return @{ Severity = "Medium"; Title = "Suspicious Remote Logon"
                   Mitre = "T1021 - Remote Services"
                   Description = "$(if($isRdp){'Remote desktop'}else{'Network'}) logon by `"$account`" from $srcIp." }
      }
    }
    { $_ -in 4697, 7045 } {
      $service = Get-Field $xml "ServiceName"
      $path = Get-Field $xml "ServiceFileName"
      $suspicious = $path -match "(?i)powershell|cmd\.exe|-enc|\\temp\\|\\users\\public\\"
      if (-not (Should-Dedupe "service_abuse")) {
        return @{ Severity = $(if ($suspicious) { "High" } else { "Medium" }); Title = "Suspicious Service Creation/Modification"
                   Mitre = "T1543.003 - Create or Modify System Process: Windows Service"
                   Description = "New service `"$service`" created$(if($path){" (binary: $path)"})." }
      }
    }
  }
  return $null
}

# ============================================================
# GUI
# ============================================================
$form = New-Object System.Windows.Forms.Form
$form.Text = "ALPHA Blue Team Console"
$form.Size = New-Object System.Drawing.Size(900, 600)
$form.StartPosition = "CenterScreen"
$form.BackColor = [System.Drawing.Color]::FromArgb(13, 12, 10)

# Summary panel (severity counts)
$summaryPanel = New-Object System.Windows.Forms.Panel
$summaryPanel.Size = New-Object System.Drawing.Size(880, 60)
$summaryPanel.Location = New-Object System.Drawing.Point(10, 10)
$form.Controls.Add($summaryPanel)

$counts = @{ Critical = 0; High = 0; Medium = 0; Low = 0 }
$colors = @{ Critical = "232,72,63"; High = "214,136,58"; Medium = "232,201,58"; Low = "74,222,128" }
$countLabels = @{}
$i = 0
foreach ($sev in @("Critical", "High", "Medium", "Low")) {
  $lbl = New-Object System.Windows.Forms.Label
  $rgb = $colors[$sev].Split(",")
  $lbl.ForeColor = [System.Drawing.Color]::FromArgb([int]$rgb[0], [int]$rgb[1], [int]$rgb[2])
  $lbl.Font = New-Object System.Drawing.Font("Segoe UI", 14, [System.Drawing.FontStyle]::Bold)
  $lbl.Text = "$sev`: 0"
  $lbl.Location = New-Object System.Drawing.Point((10 + $i * 220), 15)
  $lbl.Size = New-Object System.Drawing.Size(200, 30)
  $summaryPanel.Controls.Add($lbl)
  $countLabels[$sev] = $lbl
  $i++
}

# Alert list
$grid = New-Object System.Windows.Forms.DataGridView
$grid.Location = New-Object System.Drawing.Point(10, 80)
$grid.Size = New-Object System.Drawing.Size(880, 470)
$grid.Anchor = "Top,Bottom,Left,Right"
$grid.BackgroundColor = [System.Drawing.Color]::FromArgb(20, 19, 16)
$grid.ForeColor = [System.Drawing.Color]::White
$grid.ReadOnly = $true
$grid.AutoSizeColumnsMode = "Fill"
$grid.RowHeadersVisible = $false
$grid.AllowUserToAddRows = $false
$grid.Columns.Add("Time", "Time") | Out-Null
$grid.Columns.Add("Severity", "Severity") | Out-Null
$grid.Columns.Add("Title", "Title") | Out-Null
$grid.Columns.Add("Description", "Description") | Out-Null
$form.Controls.Add($grid)

$notifyIcon = New-Object System.Windows.Forms.NotifyIcon
$notifyIcon.Icon = [System.Drawing.SystemIcons]::Warning
$notifyIcon.Visible = $true
$notifyIcon.Text = "ALPHA Blue Team Console"

function Add-AlertRow($alert) {
  $sevColor = switch ($alert.Severity) {
    "Critical" { [System.Drawing.Color]::FromArgb(232, 72, 63) }
    "High"     { [System.Drawing.Color]::FromArgb(214, 136, 58) }
    "Medium"   { [System.Drawing.Color]::FromArgb(232, 201, 58) }
    default    { [System.Drawing.Color]::FromArgb(160, 157, 184) }
  }
  $rowIdx = $grid.Rows.Add((Get-Date -Format "HH:mm:ss"), $alert.Severity, $alert.Title, $alert.Description)
  $grid.Rows[$rowIdx].DefaultCellStyle.ForeColor = $sevColor
  $grid.FirstDisplayedScrollingRowIndex = $rowIdx

  if ($counts.ContainsKey($alert.Severity)) {
    $counts[$alert.Severity]++
    $countLabels[$alert.Severity].Text = "$($alert.Severity): $($counts[$alert.Severity])"
  }

  if ($alert.Severity -in @("Critical", "High")) {
    $notifyIcon.BalloonTipTitle = "$($alert.Severity): $($alert.Title)"
    $notifyIcon.BalloonTipText = $alert.Description
    $notifyIcon.ShowBalloonTip(8000)
  }

  if ($ForwardUrl -and $ForwardKey) {
    try {
      $payload = @{
        eventId = "0"; source = "collector"
        accountName = ""; timestamp = (Get-Date).ToUniversalTime().ToString("o")
      } | ConvertTo-Json
      Invoke-RestMethod -Uri $ForwardUrl -Method Post -Body $payload -ContentType "application/json" `
        -Headers @{ "X-Alpha-Collector-Key" = $ForwardKey } -ErrorAction SilentlyContinue | Out-Null
    } catch { }
  }
}

$statusLabel = New-Object System.Windows.Forms.Label
$statusLabel.Text = "Starting..."
$statusLabel.ForeColor = [System.Drawing.Color]::Gray
$statusLabel.Location = New-Object System.Drawing.Point(10, 555)
$statusLabel.Size = New-Object System.Drawing.Size(880, 20)
$statusLabel.Anchor = "Bottom,Left"
$form.Controls.Add($statusLabel)

$EventIds = @(4625, 4728, 4732, 4769, 4624, 4697, 7045)
$Script:LastCheck = (Get-Date).AddMinutes(-2)

$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = $PollSeconds * 1000
$timer.Add_Tick({
  try {
    $events = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = $EventIds; StartTime = $Script:LastCheck } -ErrorAction SilentlyContinue
    if ($events) {
      foreach ($e in $events) {
        $alert = Evaluate-Event $e
        if ($alert) { Add-AlertRow $alert }
      }
    }
    $Script:LastCheck = Get-Date
    $statusLabel.Text = "Last checked: $(Get-Date -Format 'HH:mm:ss')  |  Monitoring Security event log every $PollSeconds sec"
  } catch {
    $statusLabel.Text = "Error reading event log: $_  (run as Administrator?)"
  }
})
$timer.Start()

$form.Add_Shown({ $statusLabel.Text = "Monitoring started." })
$form.Add_FormClosing({ $notifyIcon.Visible = $false })
[System.Windows.Forms.Application]::Run($form)
