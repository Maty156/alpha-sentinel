# ============================================================================
# ALPHA SENTINEL v2.4.0 - AD / Network Attack Monitor (background service + web UI)
# ============================================================================
# A standalone Windows security monitor from the ALPHA Cybersecurity project.
# Like Wazuh's agent+dashboard model, but as ONE script with zero dependencies:
#
#   - Runs in the BACKGROUND (service-style, no window needed): polls the
#     Windows event logs every -PollSeconds and runs 28 AD/network detection
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
#   auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:enable            ; 4946 4947 4948 4949
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
#Requires -RunAsAdministrator

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
  # The dashboard shows a "DEMO DATA" marker ONLY when the operator says this is
  # a lab demo. Production never invents numbers; an empty dashboard says it is
  # empty (see the v2.3 front end).
  [switch]$DemoData
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
        Stop-Process -Id $targetPid -Force -ErrorAction SilentlyContinue
        Write-Host "stopped sentinel process $targetPid"
        Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
        return
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
# DETECTION RULES (28 families)
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
  firewall_rule_modified      = @{ Sub = @('MPSSVC Rule-Level Policy Change'); Need = 'Success' }
  system_time_changed         = @{ Sub = @('Security State Change'); Need = 'Success' }
  special_privileges_assigned = @{ Sub = @('Special Logon'); Need = 'Success' }
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
}

# ============================================================
# STATE
# ============================================================
$Script:Windows = @{}             # trackerName -> @{ bucket -> @( @{ Value; Time } ) }
$Script:RecentAlertTimes = @{}    # dedupeKey -> last fired (dedupe window)
$Script:DedupeAlertId = @{}       # dedupeKey -> Id of the open alert it created
$Script:Alerts = New-Object System.Collections.Generic.List[object]
$Script:NextAlertId = 1
$Script:SeenRecords = @{}         # EventRecordID -> seen, so a re-polled event is evaluated once
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
  $ip = "$($fields.sourceIp)"
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
  Update-HostSeen @{ hostname = "$($alert.Host)"; accountName = "$($alert.Account)"; sourceIp = "$($alert.SourceIp)" } $true
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
    $reasons += [PSCustomObject]@{ code = 'unverified'; label = 'Unverified'
      detail = "the audit policy could not be read, so $unknownCount rule $noun unverified" }
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
      $hosts[$h].alertCount = [int]$hosts[$h].alertCount + 1
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
      $Script:AssetIp[$ip].alertCount = [int]$Script:AssetIp[$ip].alertCount + 1
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
$Script:SentinelVersion = '2.4.0'
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
      $f.accountName     = Get-Field $xml "TargetUserName"
      $f.sourceIp        = Get-Field $xml "IpAddress"
      $f.logonType       = Get-Field $xml "LogonType"
      $f.workstationName = Get-Field $xml "WorkstationName"
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
    { $_ -in 4946, 4947, 4948, 4949 } {
      $f.subjectUserName = Get-Field $xml "SubjectUserName"
      $f.ruleName        = Get-Field $xml "RuleName"
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

  $list = @()
  foreach ($k in $RuleMeta.Keys) {
    $m = $RuleMeta[$k]
    $hit = $fired[$k]
    $audit = Get-RuleAuditState $k
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

# ============================================================
# EMBEDDED WEB SERVER (dashboard + JSON API) - HttpListener, no deps
# ============================================================
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
  '/js/pages/assets.js'   = @{ file = 'js/pages/assets.js';   type = 'application/javascript; charset=utf-8' }
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
    if ($path -match '^/api/alerts/\d+/(ack|unack|status)$' -or $path -eq '/api/self-test' -or $path -eq '/api/preflight/refresh' -or $path -eq '/api/logout') {
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
        Send-Json $res (@{
          ok          = $true
          user        = "$($s.User)"
          sessionHours = $Script:SessionHours
          idleMinutes  = $Script:IdleMinutes
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

  $probes += @{ ruleKey = 'firewall_rule_modified'; id = 4946; fields = @{ SubjectUserName = 'administrator'; RuleName = 'Allow RDP inbound' } }
  $probes += @{ ruleKey = 'system_time_changed'; id = 4616; fields = @{ SubjectUserName = 'administrator'; NewTime = '2026-01-01T00:00:00.000Z' } }
  $probes += @{ ruleKey = 'special_privileges_assigned'; id = 4672; fields = @{ SubjectUserName = 'administrator'; PrivilegeList = 'SeSecurityPrivilege SeShutdownPrivilege SeChangeNotifyPrivilege' } }

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
      4624, 4625, 4648, 4657, 4662, 4672, 4697, 4698, 4719, 4720, 4722, 4724,
      4725, 4726, 4728, 4729, 4732, 4733, 4738, 4740, 4756, 4768, 4769, 4771,
      4776, 4946, 4947, 4948, 4949, 5141, 1100, 1102, 4616
    )
  }
  @{ Log = 'System'; Ids = @(7045) }
  @{ Log = 'Microsoft-Windows-Windows Defender/Operational'; Ids = @(5001, 5010, 5012) }
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
      $Script:XPathFallback[$channel] = $true
      $Script:ChannelLastError[$channel] = "XPath pre-filter rejected: $($_.Exception.Message)"
      Write-Host ("  [poll] " + $channel + ": XPath pre-filter not accepted - using the plain Id filter from now on.") -ForegroundColor DarkYellow
    }
  }
  if ($max -gt 0) {
    $events = @(Get-WinEvent -FilterHashtable @{ LogName = $channel; Id = $ids; StartTime = $since } -Oldest -MaxEvents $max -ErrorAction Stop)
  } else {
    $events = @(Get-WinEvent -FilterHashtable @{ LogName = $channel; Id = $ids; StartTime = $since } -ErrorAction Stop)
  }
  return @{ Events = $events; UsedXPath = $false }
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
      if ($Script:SeenRecords.ContainsKey($recId)) { continue }
      # marked seen BEFORE evaluation: a poison event must not be retried forever
      $Script:SeenRecords[$recId] = Get-Date
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
    $since = Get-ChannelMark $channel
    try {
      $query = Get-ChannelEvents $channel $source.Ids $since $MaxEventsPerPoll
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
if ($usersState.ok) {
  $listener = Start-WebServer
} else {
  Write-Host ""
  Write-Host "  [web] NOT STARTED - $($usersState.message)" -ForegroundColor Red
  Write-Host "  [web] Monitoring, alerting and forwarding keep running without it." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "  ============================================================" -ForegroundColor Red
Write-Host "   ALPHA SENTINEL v2.4.0 - AD / Network Attack Monitor" -ForegroundColor Red
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
  foreach ($f in $preflight.fix) { Write-Host ("                     " + $f) -ForegroundColor DarkYellow }
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
}
