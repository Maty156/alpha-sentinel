# ALPHA Sentinel v2.1 - AD / Network Attack Monitor (background service + web dashboard)

A standalone Windows security-monitoring tool from the **Alpha Cybersecurity**
graduation project - **Wazuh's agent + dashboard model as ONE zero-dependency
script**: Sentinel runs silently in the BACKGROUND on a Domain Controller (or
any domain-joined machine), polls the Windows event logs, detects Active
Directory / network attack patterns - Kerberos attacks (Kerberoasting, AS-REP
roasting), LDAP/SAMR enumeration, password spraying, privilege escalation,
DCSync, suspicious remote logons, service abuse, persistence, and log
tampering - and serves a **modern web dashboard** you open in a browser.
Optionally forwards every detection to the **ALPHA web platform** (a separate
private repo: `Maty156/alpha`).

> The web platform (marketing site, client portal, admin panel, assessments,
> certificates) lives in its **own repo**. This repo is the Windows tooling
> only - Sentinel works fully standalone with zero dependency on the website.

## Tools in this repo

| File | What it is |
|---|---|
| `AlphaSentinel.ps1` | **The main tool (v2.1)** - background monitor + embedded web dashboard |
| `dashboard.html` / `dashboard.js` | The web UI, served by AlphaSentinel - must sit beside the script |
| `collector.ps1` | Minimal headless collector - polls the logs and forwards normalised events to the web platform, no UI |
| `tests/fixtures/` | Real-shaped event XML + expected detections, for `-ReplayPath` |

`BlueTeamConsole.ps1` (the v1 WinForms console) was removed in v2.1 - it is still
in git history if you want it for reference.

Files written at runtime, next to the script:

| File | Purpose |
|---|---|
| `sentinel-history.csv` | alert history + ack + triage state (survives restarts) |
| `sentinel-state.json` | poll watermark - a restart resumes instead of re-alerting or skipping |
| `sentinel.pid` | PID file, removed on clean exit (`-Stop` reads it) |
| `collector-state.json` | the same watermark for the headless collector |

## Architecture

- **Runs in the background** - `-Background` hides the console window;
  `-Stop` (or `Stop-Sentinel`) stops it from any console.
- **Embedded web server** (`System.Net.HttpListener`, zero dependencies),
  `http://localhost:8443` by default.
- **Single-threaded by design** - one loop drains web requests AND polls the
  event log (PowerShell scriptblocks can't run on .NET ThreadPool threads
  without a runspace; works on PS 5.1 / Server 2012).
- **Alerts persist** - `sentinel-history.csv` keeps every alert, its severity,
  ack and triage state, so state survives restarts and is shared across every
  browser (no browser-side storage).
- **Audit-policy preflight** - at startup (and on demand) Sentinel runs
  `auditpol /get` and marks every rule family whose audit subcategory is off. A
  rule whose events are not being written can never fire, and that used to be
  invisible. See `/api/preflight`.
- **`-ReplayPath`** - replay exported event XML (`wevtutil /f:xml`) through the
  real rule engine and print what would have fired. This is how field-shape bugs
  get caught; the synthetic self-test cannot see them.
- **`/api/self-test`** - fires one synthetic event sequence per rule family
  through the REAL rule engine, tags the results `[SELF-TEST]`, restores the
  live trackers afterward (in a `finally`, so a failed probe cannot wipe them),
  and keeps those rows out of the coverage counts and the CSV export.
- **`/api/rules` + `/api/coverage.csv`** - the detection coverage report: every
  rule family with severity, MITRE, event IDs, dedupe window, remediation,
  per-rule fired counts and its audit-policy state.
- **Fails loudly** - if `dashboard.html`/`dashboard.js` is missing, the server
  returns a clear 500 telling you to download the full release.

## The web dashboard

Wazuh-style dark UI matching the ALPHA platform's design language:

- **Severity stat tiles** - Total / Critical / High / Medium / Low / Open / Acknowledged
- **Live search** - by title, rule, MITRE, account, host, description
- **Filters** - severity buttons, status dropdown, and a Self-test visibility toggle
- **Auto-refresh** - every 10 s (toggleable) + manual refresh button
- **Alert table** - time, severity badge, alert, account, host, MITRE; click a
  row for the detail pane
- **Detail pane** - MITRE ATT&CK mapping (linked), rule, event ID, host,
  account, source IP, what happened, remediation guidance
- **Triage** - per-alert status (New / Investigating / Resolved / False
  Positive) + notes, same vocabulary as the web platform, saved server-side
- **Detection coverage panel** - every rule family, how often it fired, its
  audit-policy state, and a **preflight banner** listing the families this host
  is not logging plus the exact `auditpol` commands that fix them
- **Acknowledge / Unacknowledge** - per-row, persisted server-side
- **Export CSV** - the engagement report (MITRE + ack state, formula-injection
  safe, self-test rows excluded)

## Detection coverage (28 rule families)

The catalog mirrors `alpha/utils/detectionRules.js` key-for-key - same rule
keys, severities and event IDs, so an alert promoted in either product lands on
the same `rule_key`.

| Group | Rules | Event IDs |
|---|---|---|
| Brute force / spraying | password_spraying, brute_force_single_account, kerberos_preauth_spraying, ntlm_failed_auth, account_lockout_storm | 4625, 4771, 4776, 4740 |
| Privilege escalation / identity abuse | privilege_escalation, account_created, account_control_changed, account_enabled_disabled, password_reset_by_admin, group_membership_removed, account_deleted | 4728/4732/4756, 4720, 4738, 4722, 4724, 4729/4733, 4726 |
| Kerberos attacks / directory | kerberoasting, asrep_roasting, dcsync_replication, ldap_recon | 4769, 4768, 4662, 5141 |
| Logon / services | suspicious_remote_logon, explicit_credential_logon, service_abuse | 4624, 4648, 4697/7045 |
| Persistence | scheduled_task_created, registry_persistence | 4698, 4657 |
| Anti-forensics / defense evasion | log_tampering, audit_policy_changed, eventlog_service_stopped, defender_disabled, firewall_rule_modified, system_time_changed, special_privileges_assigned | 1102, 4719, 1100, 5001/5010/5012, 4946-4949, 4616, 4672 |

Open `http://localhost:8443/api/rules` for the full live catalog (severity,
MITRE, remediation, per-rule fired counts, audit state).

A few rules deliberately skip machine accounts (`DC01$`), system principals
(`SYSTEM`, `LOCAL SERVICE`, `NETWORK SERVICE`, ...) and service-account naming
patterns, because those log on and replicate continuously by design - see the
`description` of each rule.

## Run AlphaSentinel (as Administrator)

Enable the audit categories the rules read (once). Event ID -> Advanced Audit
subcategory; this is the same map the built-in preflight checks, and a
subcategory left off means that family is silently blind:

```powershell
auditpol /set /subcategory:"Logon" /success:enable /failure:enable                      # 4624 4625 4648
auditpol /set /subcategory:"Special Logon" /success:enable                              # 4672
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable      # 4776
auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable            # 4740
auditpol /set /subcategory:"User Account Management" /success:enable                    # 4720 4722 4724 4725 4726 4738
auditpol /set /subcategory:"Security Group Management" /success:enable                  # 4728 4729 4732 4733 4756
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable  # 4768 4771
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable         # 4769
auditpol /set /subcategory:"Directory Service Access" /success:enable                   # 4662
auditpol /set /subcategory:"Directory Service Changes" /success:enable                  # 5141
auditpol /set /subcategory:"Other Object Access Events" /success:enable                 # 4698
auditpol /set /subcategory:"Security System Extension" /success:enable                  # 4697
auditpol /set /subcategory:"Registry" /success:enable                                   # 4657
auditpol /set /subcategory:"Audit Policy Change" /success:enable                        # 4719
auditpol /set /subcategory:"Security State Change" /success:enable                      # 4616
auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:enable            # 4946 4947 4948 4949
```

No `auditpol` entry is needed for: **1100 / 1102** (the Eventlog service writes
those to the **Security** log itself), **7045** (Service Control Manager, System
log) or **5001 / 5010 / 5012** (the Defender **Operational** channel - not the
Security log).

Run it:

```powershell
# background (no console window); writes sentinel.pid
powershell -ExecutionPolicy Bypass -File .\AlphaSentinel.ps1 -Background

# or in the foreground with a small console window
powershell -ExecutionPolicy Bypass -File .\AlphaSentinel.ps1
```

Then open **http://localhost:8443**. The API token printed at startup is baked
into the page the server sends, so the browser needs no extra setup.

Stop it from any console:

```powershell
powershell -ExecutionPolicy Bypass -File .\AlphaSentinel.ps1 -Stop
# or, in the same session:  Stop-Sentinel
```

Optional flags:

| Flag | Default | Meaning |
|---|---|---|
| `-Port` | 8443 | dashboard port |
| `-Bind` | `localhost` | interface to bind: `localhost`, `0.0.0.0`, or an IP |
| `-ApiToken` | random per run | token required on `/api/*` |
| `-PollSeconds` | 15 | event-log poll interval |
| `-MaxEventsPerPoll` | 500 | cap events processed per poll (oldest first; the rest follow next poll) |
| `-Background` | off | hide the console window |
| `-Stop` | - | stop a running background monitor and exit |
| `-ForwardUrl` / `-ForwardKey` | - | forward detections to the ALPHA web platform |
| `-HistoryFile` | `sentinel-history.csv` | alert history |
| `-StateFile` | `sentinel-state.json` | poll watermark |
| `-ReplayPath` | - | replay exported event XML through the rule engine and exit |

Works on Windows Server 2012 R2+ and Windows 10/11, on Windows PowerShell 5.1
and PowerShell 7 (default .NET Framework 4.5+ covers everything the script uses;
no installs, no dependencies). Both scripts are saved as UTF-8 **with BOM** and
contain only ASCII, so a 5.1 run cannot mis-decode them.

## Security model of the dashboard

Sentinel serves live attack data, so the tool protects its own interface:

- **localhost by default.** Serving the LAN is opt-in (`-Bind 0.0.0.0`), and it
  warns when you do.
- **Token on every `/api/*` call** (`X-Sentinel-Token`, or `?token=` for API
  clients). The token is generated per run, printed at startup, injected into the
  served HTML, and never written to disk. `/api/health` stays open so a monitoring
  probe can read it - it carries no alert content.
- **State-changing endpoints are POST-only** (`ack`, `unack`, `status`,
  `self-test`, `preflight/refresh`) and same-origin only, so a web page an
  administrator happens to have open cannot ack or false-positive-close alerts.
- **CSV export is formula-injection safe** - attacker-chosen values starting with
  `=`, `+`, `-` or `@` are prefixed so Excel treats them as text.
- **No CDN, no outbound calls** from the dashboard; responses carry
  `Content-Security-Policy`, `X-Frame-Options: DENY`, `nosniff` and `no-store`.

## Testing

Two levels, both runnable on the DC:

**1. Self-test (plumbing + thresholds).** The **Self-test** button in the
dashboard, or `POST /api/self-test`. It fires one synthetic event sequence per
rule family through the real engine and reports how many of the 28 fired.

**2. Fixture replay (field shapes).** The self-test invents its field names, so
it cannot catch a rule reading the wrong field or the wrong channel. For that,
replay real events:

```powershell
wevtutil epl Security C:\evt\security.evtx
wevtutil qe C:\evt\security.evtx /f:xml /c:1000 > C:\evt\security.xml
.\AlphaSentinel.ps1 -ReplayPath C:\evt\security.xml     # or a directory of .xml
```

`tests/fixtures/` ships 16 small, real-shaped fixtures (the exact field layout a
real 4662 / 4776 / 4738 / 4769 / 4768 / 1100 has) with the expected outcome
recorded in `tests/fixtures/expected.json`, negative cases included. See
`tests/README.md`.

**3. The whole suite.** Both of the above are asserted automatically - no
elevation, no event log and no network needed - by a runner that drives the same
functions the live monitor uses:

```powershell
.\tests\run-tests.ps1          # 77 assertions: detection behaviour in both
                                 # directions, dedupe-per-entity, preflight
                                 # logic, state persistence, CSV safety, and
                                 # every fixture. Exit code 1 on failure.
```

## Forwarding to the web platform

```powershell
powershell -ExecutionPolicy Bypass -File .\AlphaSentinel.ps1 `
  -ForwardUrl "https://your-app.vercel.app/api/detections/ingest" `
  -ForwardKey "COLLECTOR_API_KEY value"
```

Sentinel POSTs the finished alert together with the full normalised event, so the
platform can ingest the alert directly instead of re-deriving it: the payload
carries `isAlert=true`, `ruleKey`, `severity`, `title`, `description`, `mitre` and
`alertedAt` alongside the event fields. Forwarding only the triggering event meant
the platform saw a single event that never met its own spray / brute-force
thresholds, so nothing appeared there.

Forwarding has an 8-second timeout - a single slow platform call used to freeze
the single-threaded poll loop, and the dashboard with it - and failures are
counted and exposed on `/api/health` as `forwardingErrors` instead of being
swallowed.

## Run the headless collector (no UI)

```powershell
powershell -ExecutionPolicy Bypass -File .\collector.ps1 `
  -ForwardUrl "https://your-app.vercel.app/api/detections/ingest" `
  -ForwardKey "COLLECTOR_API_KEY value"
```

Add `-Once` for a single pass (handy in a scheduled task). See the comments at the
top of `collector.ps1`.

## How it fits the purple-team workflow

1. Red team runs the attack chain in the lab (separate repo/environment).
2. **Alpha Sentinel** detects the patterns live on the DC; the admin monitors
   from the browser dashboard (or gets platform alerts with forwarding enabled).
3. The same alerts appear in the web platform's admin **Detections tab**, where
   they're investigated and can be promoted into a specific client's assessment
   findings.

---

Academic prototype - Alpha Cybersecurity is a student graduation project, not a
commercial security firm.
