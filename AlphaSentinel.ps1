# ============================================================================
# ALPHA SENTINEL — AD / Network Attack Monitor
# ============================================================================
# A standalone Windows desktop monitoring tool (WinForms, .NET — no installs,
# no dependencies). Ships with ALPHA Cybersecurity's graduation project.
#
# WHAT IT DOES
#   Polls the Windows Security event log on a Domain Controller (or any
#   domain-joined machine), runs a rule engine covering the attack classes the
#   red-team chain demonstrates — Kerberos attacks (Kerberoasting, AS-REP),
#   LDAP recon (enumeration via SAMR), password spraying, privilege escalation,
#   suspicious remote logons, service abuse, and log tampering — and surfaces
#   everything in a live dark-theme console: severity dashboard, alert table,
#   full alert detail with MITRE mapping and remediation guidance, desktop
#   toast notifications for Critical/High alerts, alert acknowledgment, and a
#   CSV export for the engagement report.
#
#   It can ALSO optionally forward every detection to the ALPHA web platform
#   (so the same alert appears in the admin panel's Detections tab and can be
#   promoted into a client's findings) — but forwarding is optional; with it
#   off, Sentinel works fully standalone with zero website dependency.
#
# SETUP (run once, as Administrator, before first use — enables the audit
# categories the rules read):
#   auditpol /set /subcategory:"Logon" /success:enable /failure:enable
#   auditpol /set /subcategory:"Security Group Management" /success:enable
#   auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable
#   auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable
#   auditpol /set /subcategory:"SAM" /success:enable
#   auditpol /set /subcategory:"Other Object Access Events" /success:enable
#
# RUN (as Administrator — reading the Security log requires elevation):
#   powershell -ExecutionPolicy Bypass -File AlphaSentinel.ps1
#
# Optional forwarding to the ALPHA web platform:
#   powershell -ExecutionPolicy Bypass -File AlphaSentinel.ps1 `
#     -ForwardUrl "https://your-app.vercel.app/api/detections/ingest" `
#     -ForwardKey "same value as COLLECTOR_API_KEY on the server"
#
# Optional tuning: -PollSeconds 10 (default 15), -HistoryFile (default
# sentinel-history.csv next to the script, so acknowledged alerts survive
# restarts).
# ============================================================================

param(
  [int]$PollSeconds = 15,
  [string]$ForwardUrl = "",
  [string]$ForwardKey = "",
  [string]$HistoryFile = ""
)

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

if (-not $HistoryFile -and $PSScriptRoot) {
  $HistoryFile = Join-Path $PSScriptRoot "sentinel-history.csv"
}

# ============================================================
# THEME — matches the ALPHA site palette (dark, crimson accent)
# ============================================================
$C = @{
  Bg       = [System.Drawing.Color]::FromArgb(13, 12, 10)     # near-black warm
  Panel    = [System.Drawing.Color]::FromArgb(20, 19, 16)
  Panel2   = [System.Drawing.Color]::FromArgb(26, 24, 20)
  Border   = [System.Drawing.Color]::FromArgb(58, 55, 50)
  Text     = [System.Drawing.Color]::FromArgb(237, 233, 230)
  TextDim  = [System.Drawing.Color]::FromArgb(150, 145, 135)
  Crimson  = [System.Drawing.Color]::FromArgb(232, 72, 63)    # ALPHA red
  Orange   = [System.Drawing.Color]::FromArgb(214, 136, 58)
  Yellow   = [System.Drawing.Color]::FromArgb(232, 201, 58)
  Green    = [System.Drawing.Color]::FromArgb(74, 222, 128)
  Violet   = [System.Drawing.Color]::FromArgb(160, 157, 184)
}

function New-AlphaLabel($text, $size, $style, $color, $x, $y, $w, $h) {
  $lbl = New-Object System.Windows.Forms.Label
  $lbl.Text = $text
  $lbl.Font = New-Object System.Drawing.Font("Segoe UI", $size, $style)
  $lbl.ForeColor = $color
  $lbl.Location = New-Object System.Drawing.Point($x, $y)
  $lbl.Size = New-Object System.Drawing.Size($w, $h)
  return $lbl
}

# ============================================================
# DETECTION RULES — ported from ALPHA's web platform
# (utils/detectionRules.js) and extended with AD attack classes:
# AS-REP roasting, LDAP/SAMR enumeration, log clearing.
# ============================================================
$PrivilegedGroups = @('domain admins', 'enterprise admins', 'schema admins',
                      'administrators', 'account operators', 'backup operators')

# ruleKey -> @{ Title, Severity, Mitre, Remediation }
$RuleMeta = @{
  password_spraying       = @{ Severity = 'High';     Title = 'Suspicious Password Spraying Activity'
                               Mitre = 'T1110.003 - Brute Force: Password Spraying'
                               Remediation = 'Enforce account lockout policy, smart-card auth, and password spray detections on the DC. Block the source IP at the firewall.' }
  privilege_escalation    = @{ Severity = 'Critical'; Title = 'User Added to Privileged Group'
                               Mitre = 'T1078.002 - Valid Accounts: Domain Accounts'
                               Remediation = 'Immediately review group membership changes, reset the added account password, and check for lateral movement from that account.' }
  kerberoasting           = @{ Severity = 'High';     Title = 'Kerberos Service Ticket Request (Kerberoasting)'
                               Mitre = 'T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting'
                               Remediation = 'Use gMSA (group managed service accounts) with 128+ bit keys, disable RC4, and rotate the targeted service account password.' }
  asrep_roasting          = @{ Severity = 'High';     Title = 'AS-REP Roasting (No-Preauth Ticket Request)'
                               Mitre = 'T1558.004 - Steal or Forge Kerberos Tickets: AS-REP Roasting'
                               Remediation = 'Enable "Do not require Kerberos preauthentication"=OFF for all accounts and audit any account with preauth disabled.' }
  suspicious_remote_logon = @{ Severity = 'Medium';   Title = 'Suspicious Remote Logon'
                               Mitre = 'T1021 - Remote Services'
                               Remediation = 'Verify the logon is expected, restrict RDP by firewall/GPO, and enable MFA for administrative remote access.' }
  ldap_recon              = @{ Severity = 'Medium';   Title = 'LDAP / SAMR Domain Enumeration'
                               Mitre = 'T1018 - Remote System Discovery / T1087 - Account Discovery'
                               Remediation = 'Harden SAMR enumeration via GPO (restrict anonymous access) and investigate the source host for recon tooling (BloodHound, SharpHound).' }
  service_abuse           = @{ Severity = 'Medium';   Title = 'Suspicious Service Creation/Modification'
                               Mitre = 'T1543.003 - Create or Modify System Process: Windows Service'
                               Remediation = 'Audit service binaries, restrict service creation to admins, and hunt for encoded PowerShell in the binary path.' }
  log_tampering           = @{ Severity = 'Critical'; Title = 'Security Log Cleared (Anti-Forensics)'
                               Mitre = 'T1070.001 - Indicator Removal: Clear Windows Event Logs'
                               Remediation = 'Treat as an active intrusion. Isolate the host, preserve remaining logs, and review what was deleted.' }
}

# sourceIp -> list of (account, time) for password-spray windowing
$Script:RecentFailedLogons = @{}
# destAccount -> list of (time) for AS-REP windowing
$Script:RecentAsrep = @{}
# sourceIp -> list of time for LDAP recon windowing
$Script:RecentLdap = @{}
# ruleKey -> last-fired DateTime (dedupe window)
$Script:RecentAlertTimes = @{}
# acknowledged alert keys, persisted across restarts
$Script:Acknowledged = @{}

if (Test-Path $HistoryFile) {
  try {
    Import-Csv $HistoryFile | ForEach-Object {
      if ($_.'Acknowledged' -eq 'yes') { $Script:Acknowledged[$_.AlertKey] = $true }
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

# Builds the full alert record (all metadata, stable AlertKey for history).
function New-Alert($ruleKey, $description, $severityOverride, $hostName, $account) {
  $meta = $RuleMeta[$ruleKey]
  $sev = if ($severityOverride) { $severityOverride } else { $meta.Severity }
  return @{
    RuleKey     = $ruleKey
    AlertKey    = "$ruleKey|$account|$hostName|$((Get-Date).ToString('yyyyMMdd'))"
    Severity    = $sev
    Title       = $meta.Title
    Mitre       = $meta.Mitre
    Remediation = $meta.Remediation
    Description = $description
    Host        = $hostName
    Account     = $account
    Time        = Get-Date
    Acknowledged = $false
  }
}

# Returns an alert hashtable, or $null if this event didn't trigger anything.
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
        return New-Alert "password_spraying" "$distinct distinct accounts failed to authenticate from $srcIp within 10 minutes." $null $hostName $account
      }
    }
    { $_ -in 4728, 4732 } {
      # Privilege escalation: user added to a privileged group
      $account = Get-Field $xml "MemberName"
      $group = Get-Field $xml "TargetUserName"
      if ($group -and ($PrivilegedGroups | Where-Object { $group.ToLower().Contains($_) })) {
        if (-not (Should-Dedupe "privilege_escalation")) {
          return New-Alert "privilege_escalation" "Account `"$account`" was added to privileged group `"$group`"." $null $hostName $account
        }
      }
    }
    4769 {
      # Kerberoasting: RC4 (0x17) service ticket requests
      $encType = Get-Field $xml "TicketEncryptionType"
      if ($encType -eq "0x17" -and -not (Should-Dedupe "kerberoasting")) {
        $account = Get-Field $xml "TargetUserName"
        $service = Get-Field $xml "ServiceName"
        return New-Alert "kerberoasting" "Service ticket requested for `"$service`" using weak RC4 encryption (0x17) - account `"$account`"." $null $hostName $account
      }
    }
    4768 {
      # AS-REP roasting heuristic: repeated no-preauth TGT requests for distinct accounts
      $account = Get-Field $xml "TargetUserName"
      if (-not $account) { return $null }
      if (-not $Script:RecentAsrep.ContainsKey($account)) { $Script:RecentAsrep[$account] = @() }
      $Script:RecentAsrep[$account] = @($Script:RecentAsrep[$account] | Where-Object { $_ -gt (Get-Date).AddMinutes(-10) })
      $Script:RecentAsrep[$account] += Get-Date
      $preAuthType = Get-Field $xml "PreAuthType"
      if ($preAuthType -eq "0" -and $Script:RecentAsrep[$account].Count -ge 3 -and -not (Should-Dedupe "asrep_roasting")) {
        return New-Alert "asrep_roasting" "Repeated no-preauth TGT requests for `"$account`" (AS-REP roasting pattern)." $null $hostName $account
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
        return New-Alert "suspicious_remote_logon" "$kind logon by `"$account`" from $srcIp." $null $hostName $account
      }
    }
    { $_ -in 4662, 5141 } {
      # LDAP/SAMR recon: repeated directory reads of privileged objects from one source
      # (4662 = operation on directory object; keyed on "SAM" access or user objects)
      $srcIp = Get-Field $xml "IpAddress"
      $objName = Get-Field $xml "ObjectName"
      $objType = Get-Field $xml "ObjectType"
      if (-not $srcIp -or $srcIp -eq '-') { return $null }
      if ($objType -and $objType -notmatch '(?i)user|group|computer|domain') { return $null }
      if (-not $Script:RecentLdap.ContainsKey($srcIp)) { $Script:RecentLdap[$srcIp] = @() }
      $Script:RecentLdap[$srcIp] = @($Script:RecentLdap[$srcIp] | Where-Object { $_ -gt (Get-Date).AddMinutes(-5) })
      $Script:RecentLdap[$srcIp] += Get-Date
      if ($Script:RecentLdap[$srcIp].Count -ge 25 -and -not (Should-Dedupe "ldap_recon")) {
        return New-Alert "ldap_recon" "25+ directory object reads (e.g. `"$objName`") from $srcIp within 5 minutes - domain enumeration pattern." $null $hostName $objName
      }
    }
    { $_ -in 4697, 7045 } {
      # Service abuse: new service with suspicious binary path
      $service = Get-Field $xml "ServiceName"
      $path = Get-Field $xml "ServiceFileName"
      $suspicious = $path -match "(?i)powershell|cmd\.exe|-enc|\\temp\\|\\users\\public\\"
      if (-not (Should-Dedupe "service_abuse")) {
        $sev = if ($suspicious) { "High" } else { "Medium" }
        return New-Alert "service_abuse" "New service `"$service`" created$(if($path){" (binary: $path)"})." $sev $hostName $service
      }
    }
    1102 {
      # Anti-forensics: security log cleared
      if (-not (Should-Dedupe "log_tampering")) {
        return New-Alert "log_tampering" "The Security event log was cleared on $hostName." $null $hostName ($e.Machine)
      }
    }
  }
  return $null
}

# ============================================================
# FORM LAYOUT
# ============================================================
$form = New-Object System.Windows.Forms.Form
$form.Text = "ALPHA Sentinel — AD / Network Attack Monitor"
$form.Size = New-Object System.Drawing.Size(1180, 700)
$form.MinimumSize = New-Object System.Drawing.Size(980, 620)
$form.StartPosition = "CenterScreen"
$form.BackColor = $C.Bg
$form.Font = New-Object System.Drawing.Font("Segoe UI", 9)

# --- header ---
$header = New-Object System.Windows.Forms.Panel
$header.Size = New-Object System.Drawing.Size(1160, 44)
$header.Location = New-Object System.Drawing.Point(10, 8)
$header.Anchor = "Top,Left,Right"
$header.BackColor = $C.Panel
$form.Controls.Add($header)
$header.Controls.Add((New-AlphaLabel "ALPHA SENTINEL" 13 ([System.Drawing.FontStyle]::Bold) $C.Crimson 12 10 170 24))
$header.Controls.Add((New-AlphaLabel "AD / Network Attack Monitor — Kerberos · LDAP · Spraying · Privesc · Services" 9 ([System.Drawing.FontStyle]::Regular) $C.TextDim 190 12 600 24))

# --- severity dashboard ---
$dashPanel = New-Object System.Windows.Forms.Panel
$dashPanel.Size = New-Object System.Drawing.Size(1160, 64)
$dashPanel.Location = New-Object System.Drawing.Point(10, 56)
$dashPanel.Anchor = "Top,Left,Right"
$dashPanel.BackColor = $C.Panel
$form.Controls.Add($dashPanel)

$counts = @{ Critical = 0; High = 0; Medium = 0; Low = 0 }
$sevColors = @{ Critical = $C.Crimson; High = $C.Orange; Medium = $C.Yellow; Low = $C.Green }
$countLabels = @{}
$i = 0
foreach ($sev in @("Critical", "High", "Medium", "Low")) {
  $lbl = New-AlphaLabel "$sev`: 0" 15 ([System.Drawing.FontStyle]::Bold) $sevColors[$sev] (14 + $i * 285) 8 260 26
  $lbl.Tag = $sev
  $lbl.Cursor = [System.Windows.Forms.Cursors]::Hand
  # click a severity tile to filter the table to that severity (click again = all)
  $lbl.Add_Click({
    $script:SeverityFilter = if ($script:SeverityFilter -eq $this.Tag) { $null } else { $this.Tag }
    foreach ($k in $countLabels.Keys) {
      $countLabels[$k].Text = if ($script:SeverityFilter -and $k -ne $script:SeverityFilter) { "$k`: $($counts[$k])" } else { "$k`: $($counts[$k])" }
    }
  })
  $dashPanel.Controls.Add($lbl)
  $countLabels[$sev] = $lbl
  $i++
}
$ackLabel = New-AlphaLabel "Acknowledged: 0" 9 ([System.Drawing.FontStyle]::Regular) $C.TextDim 900 34 240 20
$dashPanel.Controls.Add($ackLabel)

# --- alert table ---
$grid = New-Object System.Windows.Forms.DataGridView
$grid.Location = New-Object System.Drawing.Point(10, 126)
$grid.Size = New-Object System.Drawing.Size(700, 470)
$grid.Anchor = "Top,Bottom,Left,Right"
$grid.BackgroundColor = $C.Panel
$grid.ForeColor = $C.Text
$grid.BorderStyle = [System.Windows.Forms.BorderStyle]::None
$grid.DefaultCellStyle.BackColor = $C.Panel
$grid.DefaultCellStyle.ForeColor = $C.Text
$grid.DefaultCellStyle.SelectionBackColor = $C.Panel2
$grid.DefaultCellStyle.SelectionForeColor = $C.Crimson
$grid.ColumnHeadersDefaultCellStyle.BackColor = $C.Panel2
$grid.ColumnHeadersDefaultCellStyle.ForeColor = $C.Text
$grid.EnableHeadersVisualStyles = $false
$grid.ReadOnly = $true
$grid.AutoSizeColumnsMode = "Fill"
$grid.RowHeadersVisible = $false
$grid.AllowUserToAddRows = $false
$grid.Columns.Add("Time", "Time") | Out-Null
$grid.Columns.Add("Severity", "Severity") | Out-Null
$grid.Columns.Add("Title", "Alert") | Out-Null
$grid.Columns.Add("Account", "Account") | Out-Null
$grid.Columns.Add("Host", "Host") | Out-Null
$grid.Columns["Time"].FillWeight = 10
$grid.Columns["Severity"].FillWeight = 12
$grid.Columns["Title"].FillWeight = 38
$grid.Columns["Account"].FillWeight = 18
$grid.Columns["Host"].FillWeight = 22
$form.Controls.Add($grid)

# --- detail pane ---
$detail = New-Object System.Windows.Forms.Panel
$detail.Size = New-Object System.Drawing.Size(450, 470)
$detail.Location = New-Object System.Drawing.Point(720, 126)
$detail.Anchor = "Top,Bottom,Right"
$detail.BackColor = $C.Panel
$form.Controls.Add($detail)

$dTitle   = New-AlphaLabel "" 12 ([System.Drawing.FontStyle]::Bold) $C.Crimson 12 12 424 44
$dSev     = New-AlphaLabel "" 10 ([System.Drawing.FontStyle]::Bold) $C.TextDim 12 58 424 22
$dMitre   = New-AlphaLabel "" 9 ([System.Drawing.FontStyle]::Regular) $C.Violet 12 82 424 22
$dHost    = New-AlphaLabel "" 9 ([System.Drawing.FontStyle]::Regular) $C.TextDim 12 106 424 22
$dDesc    = New-AlphaLabel "" 9.5 ([System.Drawing.FontStyle]::Regular) $C.Text 12 134 424 120
$dRemLbl  = New-AlphaLabel "REMEDIATION" 9 ([System.Drawing.FontStyle]::Bold) $C.TextDim 12 258 424 20
$dRem     = New-AlphaLabel "" 9 ([System.Drawing.FontStyle]::Regular) $C.Green 12 280 424 130
$detail.Controls.AddRange(@($dTitle, $dSev, $dMitre, $dHost, $dDesc, $dRemLbl, $dRem))

# --- action bar ---
$ackBtn = New-Object System.Windows.Forms.Button
$ackBtn.Text = "ACKNOWLEDGE"
$ackBtn.Size = New-Object System.Drawing.Size(130, 30)
$ackBtn.Location = New-Object System.Drawing.Point(12, 560)
$ackBtn.Anchor = "Bottom,Left"
$ackBtn.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$ackBtn.FlatAppearance.BorderColor = $C.Crimson
$ackBtn.FlatAppearance.MouseOverBackColor = $C.Panel2
$ackBtn.BackColor = $C.Panel
$ackBtn.ForeColor = $C.Crimson
$form.Controls.Add($ackBtn)

$exportBtn = New-Object System.Windows.Forms.Button
$exportBtn.Text = "EXPORT CSV"
$exportBtn.Size = New-Object System.Drawing.Size(110, 30)
$exportBtn.Location = New-Object System.Drawing.Point(150, 560)
$exportBtn.Anchor = "Bottom,Left"
$exportBtn.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$exportBtn.FlatAppearance.BorderColor = $C.Border
$exportBtn.FlatAppearance.MouseOverBackColor = $C.Panel2
$exportBtn.BackColor = $C.Panel
$exportBtn.ForeColor = $C.Text
$form.Controls.Add($exportBtn)

$statusLabel = New-AlphaLabel "Starting..." 9 ([System.Drawing.FontStyle]::Regular) $C.TextDim 280 566 700 20
$statusLabel.Anchor = "Bottom,Left,Right"
$form.Controls.Add($statusLabel)

$notifyIcon = New-Object System.Windows.Forms.NotifyIcon
$notifyIcon.Icon = [System.Drawing.SystemIcons]::Shield
$notifyIcon.Visible = $true
$notifyIcon.Text = "ALPHA Sentinel — AD Attack Monitor"

# ============================================================
# STATE + ACTIONS
# ============================================================
$Script:AllAlerts = New-Object System.Collections.Generic.List[object]
$Script:SelectedAlert = $null
$script:SeverityFilter = $null

function Update-Dashboard {
  foreach ($sev in $countLabels.Keys) {
    $countLabels[$sev].Text = "$sev`: $($counts[$sev])"
  }
  $ackCount = ($Script:AllAlerts | Where-Object { $_.Acknowledged }).Count
  $ackLabel.Text = "Acknowledged: $ackCount of $($Script:AllAlerts.Count)"
}

function Add-Alert($alert) {
  $Script:AllAlerts.Add([PSCustomObject]$alert)
  if ($counts.ContainsKey($alert.Severity)) { $counts[$alert.Severity]++ }
  Update-Dashboard

  if ($alert.Severity -in @("Critical", "High") -and -not $alert.Acknowledged) {
    $notifyIcon.BalloonTipTitle = "$($alert.Severity): $($alert.Title)"
    $notifyIcon.BalloonTipText = $alert.Description
    $notifyIcon.ShowBalloonTip(8000)
  }
}

function Refresh-Grid {
  $grid.Rows.Clear()
  $alerts = $Script:AllAlerts | Sort-Object Time
  if ($script:SeverityFilter) { $alerts = $alerts | Where-Object { $_.Severity -eq $script:SeverityFilter } }
  foreach ($a in $alerts) {
    $rowIdx = $grid.Rows.Add($a.Time.ToString("HH:mm:ss"), $a.Severity, $a.Title, $a.Account, $a.Host)
    $row = $grid.Rows[$rowIdx]
    $row.DefaultCellStyle.ForeColor = $sevColors[[string]$a.Severity]
    if ($a.Acknowledged) {
      $row.DefaultCellStyle.ForeColor = $C.TextDim
      $row.Cells[2].Value = "[ack] $($a.Title)"
    }
  }
  if ($grid.Rows.Count -gt 0) {
    $grid.FirstDisplayedScrollingRowIndex = $grid.Rows.Count - 1
  }
}

# row select -> detail pane
$grid.Add_SelectionChanged({
  try {
    $row = $grid.CurrentRow
    if (-not $row) { return }
    $timeStr = $row.Cells[0].Value
    $title = $row.Cells[2].Value -replace '^\[ack\] ', ''
    $match = $Script:AllAlerts | Where-Object { $_.Time.ToString("HH:mm:ss") -eq $timeStr -and $_.Title -eq $title } | Select-Object -Last 1
    if ($match) {
      $Script:SelectedAlert = $match
      $dTitle.Text = $match.Title
      $dSev.Text = "SEVERITY: $($match.Severity)$(if ($match.Acknowledged) { '   [ACKNOWLEDGED]' })"
      $dMitre.Text = "MITRE: $($match.Mitre)"
      $dHost.Text = "HOST: $($match.Host)   ACCOUNT: $($match.Account)"
      $dDesc.Text = $match.Description
      $dRem.Text = $match.Remediation
    }
  } catch { }
})

$ackBtn.Add_Click({
  if ($Script:SelectedAlert) {
    $Script:SelectedAlert.Acknowledged = $true
    $Script:Acknowledged[$Script:SelectedAlert.AlertKey] = $true
    Refresh-Grid
    Update-Dashboard
    $statusLabel.Text = "Acknowledged: $($Script:SelectedAlert.Title)"
  }
})

$exportBtn.Add_Click({
  try {
    $sfd = New-Object System.Windows.Forms.SaveFileDialog
    $sfd.Filter = "CSV files (*.csv)|*.csv"
    $sfd.FileName = "alpha-sentinel-alerts-$(Get-Date -Format 'yyyyMMdd-HHmm').csv"
    if ($sfd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
      $Script:AllAlerts | Select-Object Time, Severity, Title, Mitre, Account, Host, Description, Acknowledged |
        Export-Csv -Path $sfd.FileName -NoTypeInformation
      $statusLabel.Text = "Exported $($Script:AllAlerts.Count) alerts to $($sfd.FileName)"
    }
  } catch {
    $statusLabel.Text = "Export failed: $_"
  }
})

# persist acknowledged state on close
$form.Add_FormClosing({
  try {
    $Script:AllAlerts |
      Select-Object @{ n = 'AlertKey'; e = { $_.AlertKey } }, @{ n = 'Acknowledged'; e = { if ($_.Acknowledged) { 'yes' } else { 'no' } } } |
      Export-Csv -Path $HistoryFile -NoTypeInformation -Force
  } catch { }
  $notifyIcon.Visible = $false
})

# ============================================================
# OPTIONAL WEB FORWARDING — same payload shape the collector uses
# ============================================================
$forwarded = 0
function Forward-ToWeb($alert) {
  if (-not $ForwardUrl -or -not $ForwardKey) { return }
  try {
    # Map the alert onto the platform's ingest schema (utils/detectionRules.js
    # understands: eventId, accountName, sourceIp, targetGroup, encryptionType,
    # logonType, serviceName, serviceBinaryPath, hostname). We re-send the
    # ORIGINAL Windows event id so the server-side rules actually match.
    $body = @{
      eventId   = "$($alert.EventId)"
      source    = "collector"
      hostname  = "$($alert.Host)"
      accountName = "$($alert.Account)"
      timestamp = (Get-Date).ToUniversalTime().ToString("o")
    } | ConvertTo-Json
    Invoke-RestMethod -Uri $ForwardUrl -Method Post -Body $body -ContentType "application/json" `
      -Headers @{ "X-Alpha-Collector-Key" = $ForwardKey } -ErrorAction Stop | Out-Null
    $script:forwarded++
  } catch { }
}

# ============================================================
# EVENT-LOG POLLING
# ============================================================
$EventIds = @(4625, 4728, 4732, 4768, 4769, 4662, 5141, 4624, 4697, 7045, 1102)
$Script:LastCheck = (Get-Date).AddMinutes(-2)

$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = $PollSeconds * 1000
$timer.Add_Tick({
  try {
    $events = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = $EventIds; StartTime = $Script:LastCheck } -ErrorAction SilentlyContinue
    if ($events) {
      foreach ($e in @($events)) {
        $alert = Evaluate-Event $e
        if ($alert) {
          # -MemberType NoteProperty form works on Windows Server 2012's
          # PowerShell 3.0 too (-NotePropertyName does not)
          $alert | Add-Member -MemberType NoteProperty -Name EventId -Value $e.Id
          Add-Alert $alert
          Forward-ToWeb $alert
        }
      }
    }
    $Script:LastCheck = Get-Date
    $fwd = if ($script:forwarded -gt 0) { "  |  forwarded to web: $($script:forwarded)" } else { "" }
    $statusLabel.Text = "Last checked: $(Get-Date -Format 'HH:mm:ss')  |  monitoring Security log every $PollSeconds sec$fwd"
  } catch {
    $statusLabel.Text = "Error reading event log: $_  (run as Administrator?)"
  }
})
$timer.Start()

$form.Add_Shown({ $statusLabel.Text = "Monitoring started — Security event log, every $PollSeconds sec." })
[System.Windows.Forms.Application]::Run($form)
