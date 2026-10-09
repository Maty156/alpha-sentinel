# ============================================================================
# ALPHA SENTINEL v2 - AD / Network Attack Monitor (background service + web UI)
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
#   - Serves a MODERN WEB DASHBOARD on http://0.0.0.0:<Port> (default 8443):
#     open it from any browser on the network - Wazuh-style dark UI with
#     severity stat tiles, live search, severity/status filters, auto-refresh,
#     per-alert detail with MITRE ATT&CK mapping and remediation guidance,
#     a DETECTION COVERAGE table (every rule family + how often it fired),
#     acknowledge/unacknowledge, a /api/self-test endpoint, and CSV export.
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
#   # run in the BACKGROUND (no console window; -Background hides it and
#   # writes sentinel.pid so -Stop can find the process later):
#   powershell -ExecutionPolicy Bypass -File .\AlphaSentinel.ps1 -Background
#
#   # or run in the FOREGROUND with a small console window:
#   powershell -ExecutionPolicy Bypass -File .\AlphaSentinel.ps1
#
#   # then open:  http://localhost:8443
#   #             (the dashboard binds to LOCALHOST by default; add
#   #              -Bind 0.0.0.0 to serve the LAN, and read the -ApiToken note)
#
# Optional flags:
#   -Port 8443                  web dashboard port
#   -Bind localhost              interface to bind ('localhost', '0.0.0.0', or an IP)
#   -ApiToken <string>          require this token on /api/* (auto-generated if omitted)
#   -PollSeconds 15             event-log poll interval
#   -MaxEventsPerPoll 500       cap events parsed per poll (oldest first)
#   -Background                 run with no console window (service-style)
#   -Stop                       stop a running background monitor and exit
#   -ForwardUrl / -ForwardKey   forward detections to the ALPHA web platform
#   -HistoryFile                alert history CSV (default sentinel-history.csv)
#   -StateFile                  poll watermark / runtime state (sentinel-state.json)
#   -ReplayPath <file|dir>      replay exported event XML (wevtutil) through the
#                               real rule engine, print an alert report, exit
#
# STOP the background monitor (either works):
#   powershell -ExecutionPolicy Bypass -File .\AlphaSentinel.ps1 -Stop
#   Stop-Sentinel   (helper function, when running in the same session)
# ============================================================================
#Requires -RunAsAdministrator

param(
  [int]$Port = 8443,
  # Default bind is LOCALHOST. The previous build listened on http://+:8443
  # (every interface) with no authentication and GET-triggerable state changes,
  # so any host on the network - or any web page loaded in an admin's browser -
  # could read the alert feed and ack / close alerts. Serving the LAN now needs
  # an explicit -Bind, and every /api/* call carries the token below.
  [string]$Bind = "localhost",
  [string]$ApiToken = "",
  [int]$PollSeconds = 15,
  [int]$MaxEventsPerPoll = 500,
  [switch]$Background,
  [switch]$Stop,
  [string]$ForwardUrl = "",
  [string]$ForwardKey = "",
  [string]$HistoryFile = "",
  [string]$StateFile = "",
  [string]$ReplayPath = ""
)

if (-not $HistoryFile -and $PSScriptRoot) {
  $HistoryFile = Join-Path $PSScriptRoot "sentinel-history.csv"
}
if (-not $StateFile) {
  $StateFile = if ($PSScriptRoot) { Join-Path $PSScriptRoot "sentinel-state.json" } else { "sentinel-state.json" }
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
    Severity = 'High'; Title = 'Kerberos Service Ticket Request (Kerberoasting)'
    EventId = '4769'; EventIds = @('4769'); DedupeMinutes = 15
    Mitre = 'T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting'; Category = 'Credential Access'
    Description = 'A SUCCESSFUL service ticket request used weak RC4 (0x17) encryption for a user-owned service principal - that ticket is then cracked offline for the service account password. Machine accounts ($), krbtgt and failed requests are excluded, and the description reports how many distinct SPNs were roasted in the window.'
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
$Script:LastCheck = (Get-Date).AddMinutes(-2)
$Script:ProcessedCount = 0

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
function Add-WindowHit($name, $bucket, $value, $minutes, $when = $null) {
  $w = Get-Window $name
  $stamp = if ($when) { ([datetime]$when).ToUniversalTime() } else { (Get-Date).ToUniversalTime() }
  if (-not $w.ContainsKey($bucket)) { $w[$bucket] = @() }
  $cut = $stamp.AddMinutes(-$minutes)
  $kept = @($w[$bucket] | Where-Object { $_.Time -gt $cut })
  $kept += [PSCustomObject]@{ Value = $value; Time = $stamp }
  $w[$bucket] = $kept
  return $kept
}

function Get-DistinctCount($items) {
  $vals = @($items | ForEach-Object { $_.Value } | Where-Object { $_ })
  return @($vals | Select-Object -Unique).Count
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
  $alert = [PSCustomObject]@{
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

# Reads and parses a JSON request body (the dashboard's triage save posts one).
# Returns $null when the body is absent or not JSON, so callers can treat that
# as "leave the existing values alone". Endpoints that do not need one still
# call this to DRAIN the stream - a POST body left unread on a keep-alive
# connection can make HttpListener reject the next request on that socket.
function Read-JsonBody($ctx) {
  try {
    $reader = New-Object System.IO.StreamReader($ctx.Request.InputStream, $ctx.Request.ContentEncoding)
    $text = $reader.ReadToEnd()
    $reader.Close()
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

  # Every rolling window is stamped with the EVENT's own time, not the moment
  # this event happened to be parsed. The old code used Get-Date for both the
  # window stamps and the alerts, so a slow poll (or replaying an exported log)
  # dragged the whole window along with it.
  $evtTime = (Get-Date).ToUniversalTime()
  if ($f.timestamp) {
    try { $evtTime = ([datetime]::Parse("$($f.timestamp)")).ToUniversalTime() } catch { }
  }

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
        # one SPN is a targeted roast; several inside the window is a sweep
        $sev = if ($distinctSpn -ge 3) { 'Critical' } else { 'High' }
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
function Save-State {
  try {
    @{
      lastCheck = $Script:LastCheck.ToUniversalTime().ToString("o")
      savedAt   = (Get-Date).ToUniversalTime().ToString("o")
      forwarded = $Script:Forwarded
    } | ConvertTo-Json | Set-Content -Path $StateFile -Encoding UTF8 -Force
  } catch { }
}

function Restore-State {
  if (-not (Test-Path $StateFile)) { return $false }
  try {
    $saved = Get-Content -Raw $StateFile | ConvertFrom-Json
    if ($saved.lastCheck) {
      $Script:LastCheck = ([datetime]$saved.lastCheck).ToLocalTime()
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
# EMBEDDED WEB SERVER (dashboard + JSON API) - HttpListener, no deps
# ============================================================
$Script:DashboardDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }

# ------------------------------------------------------------
# API TOKEN
# ------------------------------------------------------------
# The old dashboard was an unauthenticated HTTP service on every interface, and
# its state-changing endpoints accepted GET with no origin check - so any page
# an administrator had open could silently ack or false-positive-close alerts.
# Every /api/* call now needs this token (auto-generated per run unless
# -ApiToken is supplied), and the dashboard gets it injected into the HTML it
# is served, so the browser never has to store it.
if (-not $ApiToken) {
  $bytes = New-Object byte[] 24
  [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
  $ApiToken = ($bytes | ForEach-Object { $_.ToString('x2') }) -join ''
}

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

function Test-Authorized($ctx) {
  $given = "$($ctx.Request.Headers['X-Sentinel-Token'])"
  if (-not $given) { $given = "$($ctx.Request.QueryString['token'])" }
  if (-not $given) { return $false }
  return ($given -eq $Script:ApiToken)
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
    # hand the page its API token, so every fetch() carries X-Sentinel-Token.
    # Injected at serve time - the file on disk stays token-free.
    $tokenScript = '<script>window.SENTINEL_TOKEN=' + ($Script:ApiToken | ConvertTo-Json) + ';</script>'
    $csp = 'default-src ''self''; img-src ''self'' data:; style-src ''self'' ''unsafe-inline''; script-src ''self'' ''unsafe-inline''; connect-src ''self''; form-action ''none''; frame-ancestors ''none'''
    try { $res.Headers['Content-Security-Policy'] = $csp } catch { }
    if ($body -match '</head>') { $body = $body -replace '</head>', ($tokenScript + '</head>') }
    else { $body = $tokenScript + $body }
  }
  Send-Bytes $res ([Text.Encoding]::UTF8.GetBytes($body)) $contentType
}

# PowerShell 5.1 has no ConvertTo-Json -AsArray, so always build the array
# explicitly - a single-element list must still serialise as [ ... ], not { ... }.
function ConvertTo-JsonArray($items) {
  $parts = @()
  foreach ($i in @($items)) { $parts += ($i | ConvertTo-Json -Compress -Depth 6) }
  return "[" + ($parts -join ",") + "]"
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
    Write-Host "  [web] WARNING: bound to every interface. Any host on the network can reach the dashboard;" -ForegroundColor Yellow
    Write-Host "  [web]          they still need the API token printed below." -ForegroundColor Yellow
  }
  return $listener
}

# The alert rows the JSON API returns. Fields (the full normalised event kept
# for web forwarding) is deliberately NOT serialised - the dashboard never reads
# it, and re-serialising it for every alert on every 10-second poll of every
# open tab was most of /api/alerts' cost.
function Get-AlertRows {
  return @($Script:Alerts | Select-Object Id, Time, RuleKey, Rule, Severity, Title, Mitre, Remediation, Description, Host, Account, SourceIp, EventId, Acknowledged, Status, Notes, SelfTest)
}

# Handle a single HTTP request context. Called from the MAIN thread loop -
# single-threaded by design: PowerShell scriptblocks cannot run on .NET
# ThreadPool threads without a runspace, so the earlier Task.Run web thread
# died silently. One loop drains web requests AND polls the event log
# (works on PS 5.1 / Windows Server 2012).
function Invoke-Handler($ctx) {
  $path = $ctx.Request.Url.AbsolutePath
  $method = "$($ctx.Request.HttpMethod)"
  $res = $ctx.Response
  try {
    # ---- auth: every /api/* call needs the token (health stays open for
    # ---- monitoring probes and carries no alert content)
    if ($path -like '/api/*' -and $path -ne '/api/health' -and -not (Test-Authorized $ctx)) {
      Send-Json $res '{"error":"Unauthorized. The dashboard must send the X-Sentinel-Token header; the token is printed at startup and injected into the page it serves (or set your own with -ApiToken)."}' 401
      return
    }
    # ---- state-changing endpoints are POST-only and same-origin
    if ($path -match '^/api/alerts/\d+/(ack|unack|status)$' -or $path -match '^/api/self-test$' -or $path -match '^/api/preflight/refresh$') {
      if ($method -ne 'POST') {
        Send-Json $res '{"error":"Method not allowed - this endpoint changes state, so it accepts POST only."}' 405
        return
      }
      if (-not (Test-SameOrigin $ctx)) {
        Send-Json $res '{"error":"Cross-origin request refused."}' 403
        return
      }
    }

    switch -Regex ($path) {
      '^/$' {
        Send-File $res (Join-Path $Script:DashboardDir 'dashboard.html') 'text/html; charset=utf-8'
      }
      '^/dashboard\.js$' {
        Send-File $res (Join-Path $Script:DashboardDir 'dashboard.js') 'application/javascript; charset=utf-8'
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
        $null = Read-JsonBody $ctx   # drain the body (see Read-JsonBody note)
        $alert = $Script:Alerts | Where-Object { $_.Id -eq [int]$Matches[1] } | Select-Object -First 1
        if ($alert) {
          $alert.Acknowledged = $true
          $Script:AlertsDirty = $true
          Save-History
          Send-Json $res '{"ok":true,"acknowledged":true}'
        } else { Send-Json $res '{"error":"Alert not found."}' 404 }
      }
      '^/api/alerts/(\d+)/unack$' {
        $null = Read-JsonBody $ctx   # drain the body (see Read-JsonBody note)
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
          $body = Read-JsonBody $ctx
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
        $null = Read-JsonBody $ctx   # drain the body (see Read-JsonBody note)
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
      '^/api/health$' {
        $nonSelfTest = @($Script:Alerts | Where-Object { -not $_.SelfTest }).Count
        Send-Json $res (@{
          ok               = $true
          alerts           = $nonSelfTest
          selfTestAlerts   = $Script:SelfTestAlerts
          rules            = $RuleMeta.Count
          lastCheck        = $Script:LastCheck.ToUniversalTime().ToString("o")
          forwarded        = $Script:Forwarded
          forwardingErrors = $Script:ForwardFailures
          auditBlind       = @(Get-RuleCatalog | Where-Object { $_.auditState -eq 'blind' }).Count
        } | ConvertTo-Json)
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

# The seen-record ring keeps a re-queried event (Get-WinEvent StartTime is
# inclusive, so the boundary event comes back) from being evaluated twice.
function Prune-SeenRecords {
  if ($Script:SeenRecords.Count -lt 5000) { return }
  $cut = (Get-Date).AddMinutes(-15)
  foreach ($k in @($Script:SeenRecords.Keys)) {
    if ($Script:SeenRecords[$k] -lt $cut) { $Script:SeenRecords.Remove($k) }
  }
}

function Invoke-PollOnce {
  $anyError = $false
  $newAlerts = 0
  # Read the watermark BEFORE querying and only advance it afterwards. Setting
  # it to "now" after processing - the old behaviour - meant every event written
  # while a slow poll was running landed in the gap and was never seen again.
  $pollStart = Get-Date
  $since = $Script:LastCheck
  $capped = $false
  $cappedBoundary = $null

  foreach ($source in $LogSources) {
    try {
      $events = @(Get-WinEvent -FilterHashtable @{ LogName = $source.Log; Id = $source.Ids; StartTime = $since } -ErrorAction SilentlyContinue)
      if ($events.Count -gt 0) {
        # oldest-first: a capped poll then defers the NEWEST events instead of
        # throwing them away, and the rolling windows see events in the order
        # they actually happened (Get-WinEvent returns newest-first)
        $batch = @($events | Sort-Object TimeCreated)
        $overCap = 0
        if ($MaxEventsPerPoll -gt 0 -and $batch.Count -gt $MaxEventsPerPoll) {
          $overCap = $batch.Count - $MaxEventsPerPoll
          $batch = @($batch | Select-Object -First $MaxEventsPerPoll)
        }

        foreach ($e in $batch) {
          $recId = [int64]0
          try { $recId = [int64]$e.RecordId } catch { $recId = 0 }
          if ($recId -gt 0) {
            if ($Script:SeenRecords.ContainsKey($recId)) { continue }
            $Script:SeenRecords[$recId] = Get-Date
          }
          $alert = Evaluate-Event $e
          if ($alert) {
            $Script:Alerts.Add($alert)
            $Script:ProcessedCount++
            $newAlerts++
            Forward-ToWeb $alert
          }
        }
        Prune-SeenRecords

        if ($overCap -gt 0) {
          # park the watermark on the last event actually handled, so the
          # deferred ones are still inside the next query window
          $capped = $true
          $last = $batch | Select-Object -Last 1
          if ($last -and $last.TimeCreated) {
            if (-not $cappedBoundary -or $last.TimeCreated -lt $cappedBoundary) { $cappedBoundary = $last.TimeCreated }
          }
          Write-Host ("  [poll] " + $source.Log + ": " + $overCap + " event(s) over the " + $MaxEventsPerPoll + "-per-poll cap - deferred to the next poll.") -ForegroundColor DarkYellow
        }
      }
    } catch {
      Write-Host "  [poll] $($source.Log) error: $_" -ForegroundColor Red
      $anyError = $true
    }
  }

  # advance the watermark: to the earliest capped boundary if we had to defer,
  # otherwise to the instant the poll started (no gap, no overlap)
  if ($capped -and $cappedBoundary) {
    if ($cappedBoundary -gt $since) { $Script:LastCheck = $cappedBoundary }
  } else {
    $Script:LastCheck = $pollStart
  }

  if ($newAlerts -gt 0) {
    $Script:AlertsDirty = $true
    Save-History
  }
  Save-State
  return (-not $anyError)
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

# resume the poll watermark from the previous run (no re-alerting the last two
# minutes, no blind spot for the downtime)
$null = Restore-State

$listener = Start-WebServer

Write-Host ""
Write-Host "  ============================================================" -ForegroundColor Red
Write-Host "   ALPHA SENTINEL v2 - AD / Network Attack Monitor" -ForegroundColor Red
Write-Host "  ============================================================" -ForegroundColor Red
if (-not $Bind -or $Bind -eq 'localhost' -or $Bind -eq '127.0.0.1') {
  Write-Host "   Web dashboard : http://localhost:$Port  (localhost only - add -Bind 0.0.0.0 to serve the LAN)" -ForegroundColor Green
} else {
  Write-Host "   Web dashboard : http://<this-ip>:$Port  (bound to $Bind)" -ForegroundColor Green
}
Write-Host "   API token     : $ApiToken" -ForegroundColor Green
Write-Host "                   the dashboard page is handed this automatically; any other" -ForegroundColor DarkGray
Write-Host "                   client must send it as the X-Sentinel-Token header" -ForegroundColor DarkGray
Write-Host "   Polling       : $MonitoredEventIdCount event IDs across $($LogSources.Count) log channels every $PollSeconds sec (cap $MaxEventsPerPoll/poll)"
Write-Host "   Rules         : $($RuleMeta.Count) families (spraying, brute force, Kerberos attacks,"
Write-Host "                   DCSync, enumeration, privesc, persistence, evasion)"
if ($ForwardUrl) { Write-Host "   Forwarding    : enabled -> $ForwardUrl" -ForegroundColor Yellow }
else { Write-Host "   Forwarding    : off (standalone mode)" -ForegroundColor DarkGray }
Write-Host "   History       : $HistoryFile"
Write-Host "   State         : $StateFile"
Write-Host "   Stop          : .\AlphaSentinel.ps1 -Stop    (or Stop-Sentinel)"
Write-Host "   Self-test     : the Self-test button, or POST http://localhost:$Port/api/self-test"
Write-Host "   Coverage      : http://localhost:$Port  -> Detection coverage panel"

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
  Save-State
  Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
}
