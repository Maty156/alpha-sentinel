# ALPHA SENTINEL v2.6.0 - AD / Network Attack Monitor (background service + web dashboard)

## Project information

**Purpose.** Active Directory is the target of most enterprise intrusions, yet small
organisations rarely have a SIEM. ALPHA Sentinel is a zero-dependency monitor that
runs on a Domain Controller (or any domain-joined Windows machine), reads the
Windows event logs, detects the common AD attack techniques, and shows them in a
web dashboard - no agent install, no database, one PowerShell script.

**Main features**
- **36 detection rules** mapped to MITRE ATT&CK: Kerberoasting, AS-REP roasting,
  DCSync, password spraying and brute force, pass-the-hash, LDAP/SAMR recon,
  privilege escalation, GPO / AdminSDHolder tampering, computer-account abuse (RBCD),
  suspicious process creation and PowerShell script blocks, persistence (services,
  scheduled tasks, registry), log tampering, Defender / firewall tampering.
- **Web dashboard behind a login** (PBKDF2-hashed accounts, sessions, rate-limited
  sign-in): overview, alerts with triage, events, assets, attack paths and chains,
  rule coverage, reports, and settings.
- **Audit-policy preflight and one-step `-EnableAudit`** (backs the policy up first).
- **Optional alert outputs**: webhook, SMTP, syslog - with 3 s timeouts, a circuit
  breaker and rate limiting so a dead server can never freeze detection.
- **Replay mode** (`-ReplayPath`) and a **test suite** with real-shaped event fixtures.
- Alert history with rotation, survives restarts; optional forwarding to a web platform.

**Quick demo (lab):**
```powershell
.\New-SentinelAdmin.ps1                                              # create the login (password shown once)
powershell -ExecutionPolicy Bypass -File .\AlphaSentinel.ps1 -EnableAudit
powershell -ExecutionPolicy Bypass -File .\AlphaSentinel.ps1          # then open http://localhost:8443
.\tests\run-tests.ps1                                                # run the test suite
```

**Video presentation:** [add the link here]

**Team**

| # | Full name | CTC ID | Role |
|---|---|---|---|
| 1 | Matyas Abreham | CTC-207-26 | Project Lead & Lead Developer (architecture, detection engine, dashboard, testing, documentation) |
| 2 | Nathnail Wassie | CTC-7656-26 | Frontend Developer |
| 3 | Abu Geleta | CTC-4372-26 | Backend Developer |
| 4 | Omer Muzemil | CTC-7061-26 | Backend Developer |
| 5 | Surafel Ketema | CTC-307-26 | Frontend Developer |
| 6 | Eyorika Kassaye | CTC-6619-26 | Tester |

*A Python port (one codebase for Windows and Linux) is being developed in a separate
repository.*

---

A standalone Windows security-monitoring tool from the **Alpha Cybersecurity**
graduation project - **Wazuh's agent + dashboard model as ONE zero-dependency
script**: Sentinel runs silently in the BACKGROUND on a Domain Controller (or
any domain-joined machine), polls the Windows event logs, detects Active
Directory / network attack patterns - Kerberos attacks (Kerberoasting, AS-REP
roasting), LDAP/SAMR enumeration, password spraying, privilege escalation,
DCSync, suspicious remote logons, service abuse, persistence, and log
tampering - and serves a **modern web dashboard behind a login** you open in a
browser. Optionally forwards every detection to the **ALPHA web platform** (a
separate private repo: `Maty156/alpha`).

> The web platform (marketing site, client portal, admin panel, assessments,
> certificates) lives in its **own repo**. This repo is the Windows tooling
> only - Sentinel works fully standalone with zero dependency on the website.

## Tools in this repo

| File | What it is |
|---|---|
|| `AlphaSentinel.ps1` | **The main tool (v2.6.0)** - background monitor + embedded web dashboard ||
| `dashboard.html` | The dashboard, served by AlphaSentinel behind a login - must sit beside the script |
| `login.html` / `login.js` | The sign-in page (public) |
| `New-SentinelAdmin.ps1` | Creates and manages the dashboard accounts in `sentinel-users.json` |
| `collector.ps1` | Minimal headless collector - polls the logs and forwards normalised events to the web platform, no UI |
| `tests/` | Test suite + real-shaped event fixtures for `-ReplayPath` |

Files written at runtime, next to the script:

| File | Purpose |
|---|---|
| `sentinel-users.json` | dashboard accounts: PBKDF2 salt/hash/iterations only, never a password |
| `sentinel-history.csv` | alert history + ack + triage state (survives restarts) |
| `sentinel-state.json` | per-channel poll watermarks - a restart resumes instead of re-alerting or skipping |
| `sentinel-auth.csv` | login audit trail (time, source IP, username, outcome - never a password) |
| `sentinel.pid` | PID file, removed on clean exit (`-Stop` reads it) |
| `collector-state.json` | the headless collector's watermarks |

`sentinel-users.json`, `sentinel-history.csv`, `sentinel-state.json`,
`sentinel-auth.csv` and `sentinel.pid` are gitignored: they are local state, and
the users file is a credential store.

## First run

**1. Create the dashboard account.** The dashboard is not served until a users
file exists - it will not silently fall back to being an open port.

```powershell
.\New-SentinelAdmin.ps1                        # creates "admin", prints a random password ONCE
.\New-SentinelAdmin.ps1 -Username maty         # or your own username
.\New-SentinelAdmin.ps1 -List                  # usernames + created date (never hashes)
.\New-SentinelAdmin.ps1 -Username maty -Reset  # new random password
.\New-SentinelAdmin.ps1 -Username maty -PromptPassword   # type your own (min 12 chars)
.\New-SentinelAdmin.ps1 -Username maty -Remove
```

The password is printed once and never written to disk (only a PBKDF2 hash of
it is). Save it; `-Reset` is how you get a new one. The users file's ACL is
locked to Administrators + SYSTEM, which is why an elevated prompt is best.

**2. Enable the audit categories the rules read.** Event ID -> Advanced Audit
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
auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:enable            # 4946 4947 4948 4949 4950
```

No `auditpol` entry is needed for: **1100 / 1102** (the Eventlog service writes
those to the **Security** log itself), **7045** (Service Control Manager, System
log) or **5001 / 5010 / 5012** (the Defender **Operational** channel).

**3. Run it:**

```powershell
# one step instead of the manual auditpol list (backs up first, only enables):
powershell -ExecutionPolicy Bypass -File .\AlphaSentinel.ps1 -EnableAudit

# background (no console window); writes sentinel.pid
powershell -ExecutionPolicy Bypass -File .\AlphaSentinel.ps1 -Background

# or in the foreground with a small console window
powershell -ExecutionPolicy Bypass -File .\AlphaSentinel.ps1
```

Then open **http://localhost:8443** and sign in - plain **http://**: the
listener serves no TLS, so an **https://** URL will not connect. Encryption
comes from a TLS reverse proxy or a VPN. Stop it from any console:

```powershell
powershell -ExecutionPolicy Bypass -File .\AlphaSentinel.ps1 -Stop
# or, in the same session:  Stop-Sentinel
```

Optional flags:

| Flag | Default | Meaning |
|---|---|---|
| `-Port` | 8443 | dashboard port |
| `-Bind` | `localhost` | interface to bind: `localhost`, `0.0.0.0`, or an IP |
| `-PollSeconds` | 15 | event-log poll interval |
| `-MaxEventsPerPoll` | 500 | cap events processed per poll (oldest first; the rest follow next poll) |
| `-CatchUpMilliseconds` | 200 | when a poll was capped, retry this soon instead of a whole `-PollSeconds` |
| `-Background` | off | hide the console window |
| `-Stop` | - | stop a running background monitor and exit |
| `-EnableAudit` | off | set the audit subcategories the rules need: backs the policy up first (`sentinel-audit-backup-<timestamp>.csv`), only ever ENABLES what a rule needs, is idempotent, refuses without Administrator. Undo with `-RestoreAudit <that backup>` - or from the dashboard's Settings > Audit tab |
| `-RestoreAudit <file>` | - | restore an audit-policy backup (`auditpol /restore`) and exit |
| `-ForwardUrl` / `-ForwardKey` | - | forward detections to the ALPHA web platform |
| `-HistoryFile` | `sentinel-history.csv` | alert history |
| `-StateFile` | `sentinel-state.json` | per-channel poll watermarks |
| `-UsersFile` | `sentinel-users.json` | dashboard accounts |
| `-AuthFile` | `sentinel-auth.csv` | login audit trail |
| `-DemoData` | off | label the dashboard as a lab demo; the tool never invents numbers, so this only adds the marker |
| `-ReplayPath` | - | replay exported event XML through the rule engine and exit |

Works on Windows Server 2012 R2+ and Windows 10/11, on Windows PowerShell 5.1
and PowerShell 7 (default .NET Framework 4.5+ covers everything the script uses;
no installs, no dependencies). The scripts are saved as UTF-8 **with BOM** and
contain only ASCII, so a 5.1 run cannot mis-decode them.

## Dashboard login and sessions

The v2.1 build protected the dashboard with a per-run token that was injected
into the page it served, so anyone who could open the port received the token
with the page. That is replaced by a real login:

- **Accounts** live in `sentinel-users.json` as PBKDF2 (per-user 16-byte salt,
  150000 iterations, HMAC-SHA1 via the `Rfc2898DeriveBytes` overload that exists
  on .NET 4.x). Only salt, hash and iteration count are stored. Verification is a
  constant-time comparison, and an unknown username costs the same work as a real
  verification, so neither the response nor the timing says whether an account
  exists.
- **`POST /api/login`** returns a session id: 32 random bytes, hex, kept in
  server memory, **8 h absolute lifetime** and a **30 min sliding idle timeout**.
- **The browser only holds a cookie**: `sentinel_session=<id>; Path=/; HttpOnly;
  SameSite=Strict`. Nothing sensitive is ever put in the page.
- **`POST /api/logout`** destroys the session server-side and clears the cookie.
  The dashboard header shows *signed in as &lt;user&gt;* and a Logout button, and any
  401 sends the browser back to the sign-in page.
- **The read-only dashboard API** - `GET /api/overview` (tiles, deltas, coverage,
  severity/tactic counts, hourly series, lastPoll, health, version),
  `GET /api/events` (the last 300 events, newest first, filtered), `GET /api/hosts`
  and `GET /api/settings` (read-only, and it never carries a hash, salt, session id
  or forwarding key). They are session-required and GET-only; the older
  `/api/alerts`, `/api/rules`, `/api/preflight`, `/api/status` and the CSV exports
  are unchanged. All of this state is **in memory and resets with the process** - a
  dashboard window, not the alert history.
- **Every `/api/*` route except `/api/health` and `POST /api/login` answers 401
  JSON** without a live session. `/api/health` stays open for monitoring probes and
  now answers a bare `{"ok":true}` - nothing else at all - so an unauthenticated
  caller learns only that the port is open. Counters, lag, session count and error
  tallies live on the authenticated **`/api/status`**, which is what the dashboard
  reads.
- **Request bodies are bounded and refused before they are read.** The login route
  takes at most 8192 bytes and every other route 65536; a body with no
  `Content-Length`, or one sent chunked, is refused **411** - its size is only
  knowable by reading it, and reading it is the attack - while an oversized body is
  refused **413**. `EntityBody`, `DrainEntityBody` and `HeaderWait` are bounded too
  (the .NET defaults are two minutes, so one stalled client would hold the only web
  thread). Rejections are counted as `bodyRejections` in `/api/status`.
- **Brute-force protection**: 5 failed logins per source IP per 5 minutes, then
  429 with `Retry-After` for 5 minutes. Wrong username and wrong password return
  the same message.
- **Audit**: every attempt is appended to `sentinel-auth.csv` (time, source IP,
  username, outcome, reason - never a password), so a login sweep is visible even
  when the alert feed is quiet.
- **`/` serves the login page** when there is no session, and the dashboard when
  there is.
- **State-changing routes** (`ack`, `unack`, `status`, `self-test`,
  `preflight/refresh`, `logout`) are still POST-only and same-origin, and on a
  loopback bind only loopback Host headers are accepted (DNS-rebinding guard).
- **Cleartext warning**: `-Bind 0.0.0.0` is plain HTTP, so the password and the
  session cookie are unencrypted on the wire. Use a VPN or a trusted lab
  network, or put a TLS reverse proxy in front of it. Sentinel says so at startup
  when it is bound beyond localhost.
- **Bounded request bodies and timeouts** - the web server refuses a body it
  cannot size (411) or one over the route's budget (413) *before* reading a byte,
  and caps how long a client may take to send a body, to drain one, or to finish its
  headers. Because `TimeoutManager` is only enforced by HTTP.sys, the read itself
  runs on a dedicated thread with a 2 s limit (`SentinelBody`), so a client that
  declares a length and then stalls is **abandoned and its connection aborted**
  rather than parking the single web thread - a stalled body is a failed sign-in,
  and three of them from one address block it (`bodyTimeouts` on `/api/status`).
- Response hardening: `Content-Security-Policy` with **`script-src 'self'`** (no
  inline script anywhere; `dashboard.html` and `login.html` are served from the `js/` directory, and `dashboard.html`/`login.html` reference separate `js/` files for scripts,
  `X-Frame-Options: DENY`, `nosniff`, `no-store`. No CDN, no outbound calls.

## Architecture

- **Runs in the background** - `-Background` hides the console window;
  `-Stop` (or `Stop-Sentinel`) stops it from any console.
- **Embedded web server** (`System.Net.HttpListener`, zero dependencies),
  `http://localhost:8443` by default.
- **Single-threaded by design** - one loop drains web requests AND polls the
  event log (PowerShell scriptblocks can't run on .NET ThreadPool threads
  without a runspace; works on PS 5.1 / Server 2012).
- **One watermark per log channel**, persisted in `sentinel-state.json`. A
  channel's mark only moves when *that* channel's query **and** its processing
  both completed, so a slow or failing channel can neither hold back nor skip
  past the others.
- **Per-event error isolation** - a malformed event is counted
  (`/api/status` -> `evalErrors`) and skipped; it cannot abort the rest of the
  batch. A failed log read leaves that channel's watermark untouched and is
  retried next poll, so nothing is silently lost.
- **Backlog catch-up** - a capped poll re-polls in `-CatchUpMilliseconds`
  (200 ms) instead of a whole interval, so a backlog drains instead of trickling
  at ~33 events/second.
- **XPath pre-filter** - `4624` (LogonType 3/10), `4769` (RC4) and `4776` (not
  success) are filtered inside the query so their XML is never parsed in
  PowerShell. The filter is deliberately a *superset* of what the engine needs,
  every in-engine check is unchanged, and if the provider rejects the XPath the
  channel falls back to the plain Id filter and remembers it.
- **Poll lag is visible** - per-channel lag plus `evalErrors` / `pollErrors` are
  in `/api/status` and shown as a pill in the dashboard ("catching up: Ns behind"),
  with a warning past 2 minutes. "Catching up" means the truth: the last poll had to
  defer events, or the lag is past two poll intervals **plus** the 5 s watermark
  overlap - an idle monitor carries one interval of lag by design and is *not*
  behind.
- **A poll reads only what it processes** - `Get-WinEvent -Oldest -MaxEvents (cap +
  1)` - so a capped poll never materialises a whole backlog to throw most of it
  away, and the watermark is backdated 5 s on an uncapped poll so an event written
  between the query's snapshot and the poll start cannot fall outside every window
  (the seen-record ring drops the re-read).
- **Alerts persist** - `sentinel-history.csv` keeps every alert, its severity,
  ack and triage state, so state survives restarts and is shared across every
  browser (no browser-side storage).
- **Audit-policy preflight** - at startup (and on demand) Sentinel runs
  `auditpol /get` and marks every rule family whose audit subcategory is off.
- **`-ReplayPath`** - replay exported event XML (`wevtutil /f:xml`) through the
  real rule engine and print what would have fired.
- **`/api/self-test`** - fires one synthetic event sequence per rule family
  through the REAL rule engine, tags the results `[SELF-TEST]`, restores the live
  trackers afterward (in a `finally`), and keeps those rows out of the coverage
  counts and the CSV export.

## The web dashboard

A dark charcoal console with crimson used **only** for the brand (logo, active nav,
primary button). Severity has its own palette and never borrows crimson: Critical
is hot magenta-red `#ff4d6d`, High orange, Medium amber, Low blue-grey, and
healthy/coverage is teal. Base text 15px, tables 14px, tile numbers 30px, captions
never below 12px; keyboard focus is visible and `prefers-reduced-motion` is
respected.

Eight pages, one file each (see `js/pages/`):

- **Overview** - five stat tiles with delta arrows and sparklines (open alerts,
  critical, high, hosts seen, detection coverage), an alerts-by-severity bar, a
  coverage meter that counts only CONFIRMED families (with an "N unverified" note
  and a "N rules blind" banner linking to the Rules page), an hourly events/alerts
  chart drawn as inline SVG (no chart library; it draws a real chart even with one
  or two buckets), the top MITRE tactics, the latest six alerts (one line each -
  the description lives in the Alerts drawer) and the latest events.
- **Alerts** - severity / status / ack filter chips, a search box, a table, and a
  right-side drawer with the full detail: status dropdown (New / Investigating /
  Resolved / False Positive), a **separate** acknowledge toggle, the contributing
  events and a kill-chain timeline of the other alerts for the same host or account,
  in time order, tagged with their tactic.
- **Attack Chains** - open alerts grouped into kill chains by shared entity (same
  account OR host OR source IP) inside a 60-minute sliding window. The list is on
  the left (severity, title, alert count, time span); the selected chain is drawn
  as an 11-step MITRE kill-chain strip with the alerts listed under each tactic
  they touched, and every alert opens on the Alerts page. A chain needs at least
  two alerts - a lone alert is not a chain.
- **Assets** - three tabs (Hosts / Accounts / IPs) over what the window has seen:
  hosts with their users, source addresses, event and alert counts and top
  severity; accounts (DN prefixes stripped, user vs computer only - the type is
  never guessed) with the flags their fired rules justify; source addresses with
  the accounts and hosts behind them, a failed-logon count and an
  internal/external flag (`::ffff:` normalised, RFC1918 / loopback / link-local =
  internal). Search, sortable columns, and a drawer with the entity's open alerts
  and its timeline from the event ring buffer. Counts come from observed events
  and fired rules only - no risk scores are invented.
- **Reports** - pick a period (or a preset) and get a self-contained engagement
  report: executive summary, coverage and limitations (including how many
  families are unverified or blind), findings by severity / status / tactic,
  attack chains, affected assets, the top alerts, a remediation checklist and an
  alert-timeline appendix. It is a framed document with `css/print.css` for
  printing to PDF, and it says so plainly when the period is empty. Dates are
  validated (junk is refused, ranges over 31 days are refused).
- **Detection Rules** - all 36 families with their audit-policy state: Working,
  amber **Unverified** when the policy could not be read (that is not working, and
  it is counted separately in the header), or BLIND with the reason and the exact
  `auditpol` command that fixes it.
- **Events** - the last 300 normalised events, newest first, with the endpoint's
  filters (event id, host, user, substring).
- **Settings** - read-only: version, poll/bind/port, session and rate limits,
  forwarding on/off and destination host, the audit preflight and the account names
  with creation dates. No secret is ever rendered.

- **Attack Paths** - interactive Active Directory identity graph (`#/paths`). Maps the shortest lateral movement and privilege escalation attack vectors from low-privileged standard user accounts (Tier 2) through servers and service accounts (Tier 1) to Domain Admins and Domain Controllers (Tier 0). Correlates directly with live detections, highlighting compromised hops and calculating blast radius.

Settings has four tabs: **General** is the read-only configuration view; **Account**
changes your own password (>= 12 characters, the current one re-verified, every other
session of yours ends and the current one is rotated), your sign-in name (re-auth, 3-32
characters of `A-Za-z0-9._-`, unique) and a small avatar (initials + one of eight fixed
colours - no file upload); **Users** lists the accounts and creates, resets or removes
them - every change needs YOUR password again, the last account cannot be removed, you
cannot remove yourself, and the affected user's sessions all end; **Audit** shows each
rule family's audit state with a preview of what would change, and can apply it (the
same backup-first, enable-only, idempotent code as `-EnableAudit`) or restore one of
the backups the tool wrote - restore accepts only those file names, never a path.
Without elevation the audit tab is read-only. The top
search box filters the table on the current page only, and the range selector is fixed
at 24 hours - neither invents an endpoint. The header carries the health pill, which
says **why** rather than just that something is off: **Blind** (red) when a rule family
cannot fire, **Unverified** (amber) when the audit policy is unreadable, **Catching up**
(amber) only when the poller is actually behind, **Healthy** (green) otherwise - the
worst state is the headline and the tooltip lists every reason from
`/api/overview.health.reasons[]`. The sidebar badge carries the open-alert count, and
"DEMO DATA" appears **only** when the monitor was started with `-DemoData`.

The front end is split so a bug is easy to place: `css/tokens|base|layout|components|pages|login|print.css`,
`js/api.js` (the only caller of the API), `js/state.js` (store + polling that pauses
while the tab is hidden), `js/ui.js` (DOM helpers, formatting, badges, inline-SVG
sparkline, toasts), `js/router.js` (the `#/overview`-style hash router),
`js/pages/*.js` (one page per file) and `js/app.js` (boot). Each file starts with a
comment saying what it owns, and each has one `console.error` path tagged with the
page name. Nothing is inline: no style or script element, no `on*` attribute, and no
`innerHTML` assignment anywhere - every dynamic string goes through `textContent`.
Files are served from a **strict allowlist** (exact name, exact content type), so an
unknown path or a `../` traversal is a plain 404.

## Detection coverage (36 rule families)

The catalog mirrors `alpha/utils/detectionRules.js` key-for-key - same rule keys,
severities and event IDs, so an alert promoted in either product lands on the
same `rule_key`.

| Group | Rules | Event IDs |
|---|---|---|
| Brute force / spraying | password_spraying, brute_force_single_account, kerberos_preauth_spraying, ntlm_failed_auth, account_lockout_storm | 4625, 4771, 4776, 4740 |
| Privilege escalation / identity abuse | privilege_escalation, account_created, account_control_changed, account_enabled_disabled, password_reset_by_admin, group_membership_removed, account_deleted | 4728/4732/4756, 4720, 4738, 4722, 4724, 4729/4733, 4726 |
| Kerberos attacks / directory | kerberoasting, asrep_roasting, dcsync_replication, ldap_recon | 4769, 4768, 4662, 5141 |
| Logon / services | suspicious_remote_logon, explicit_credential_logon, service_abuse, pass_the_hash_logon | 4624, 4648, 4697/7045 |
| Persistence | scheduled_task_created, registry_persistence | 4698, 4657 |
| Anti-forensics / defense evasion | log_tampering, audit_policy_changed, eventlog_service_stopped, defender_disabled, firewall_disabled, firewall_rule_modified, system_time_changed, special_privileges_assigned | 1102, 4719, 1100, 5001/5010/5012, 4950, 4946-4949, 4616, 4672 |
| Discovery | anonymous_smb_session, ldap_recon | 4624 (type 3, no account), 4662, 5141 |
| GPO & admin object | gpo_or_admin_object_modified | 5136 |
| Computer account abuse | computer_account_abuse | 4741, 4742 |
| Suspicious process creation | suspicious_process_creation | 4688 |
| PowerShell script block | powershell_scriptblock | 4104 |
| DSRM password set | dsrm_password_set | 4794 |

Event **4950** (a whole firewall profile turned off) shares the **MPSSVC
Rule-Level Policy Change** audit subcategory with 4946-4949, so the same
`auditpol` entry covers both - no extra subcategory is needed. The rule reads
the real event fields (`ProfileChanged`, `SettingType`, `SettingValue`) and
fires only on `SettingType = EnableFirewall` with value `No` (also accepting
the `Enable Windows Firewall` spelling some builds write and the numeric `0`
form from the oldest ones); every other 4950 setting change is informational.

Two rules carry a severity ladder rather than a fixed level:

- **kerberoasting** is **Medium** for a single RC4 service ticket and escalates
  to **High** at 3+ distinct service principals requested by one account inside
  10 minutes (the open alert is upgraded in place).
- **account_control_changed** is **Critical** when Kerberos pre-authentication is
  switched off (AS-REP roastable) and **High** for a password-no-longer-required
  flag, a re-enable, or a newly granted **delegation** right - unconstrained
  (`0x80000`) or constrained with protocol transition (`0x1000000`).

A few rules deliberately skip machine accounts (`DC01$`), system principals
(`SYSTEM`, `LOCAL SERVICE`, `NETWORK SERVICE`, ...) and service-account naming
patterns, because those log on and replicate continuously by design - see the
`description` of each rule.

**New rules (v2.6.0) - key-for-key additions to alpha/utils/detectionRules.js:**
- `gpo_or_admin_object_modified` (5136, High/Critical) - GPO/GPO link/AdminSDHolder/sIDHistory changes
- `computer_account_abuse` (4741/4742, Medium/High) - non-admin computer creation, RBCD delegation changes
- `suspicious_process_creation` (4688, High) - ntdsutil, vssadmin, reg save, rundll32 MiniDump, certutil, encoded PS (needs Process Creation audit + command-line logging)
- `powershell_scriptblock` (4104, High) - Invoke-Mimikatz, FromBase64String+IEX, AmsiUtils, etc. (needs PowerShell Script Block Logging)
- `dsrm_password_set` (4794, Critical) - DSRM password change on DC (always Critical)
- `pass_the_hash_logon` (4624, Critical) - LogonType 9 or type 3 NTLM KeyLength=0 (needs Logon audit)

## Testing

**1. Self-test (plumbing + thresholds).** The **Self-test** button in the
dashboard, or `POST /api/self-test`. One synthetic event sequence per rule family
through the real engine; reports how many of the 36 fired.

**2. Fixture replay (field shapes).** The self-test invents its field names, so
it cannot catch a rule reading the wrong field or the wrong channel. For that,
replay real events:

```powershell
wevtutil epl Security C:\evt\security.evtx
wevtutil qe C:\evt\security.evtx /f:xml /c:1000 > C:\evt\security.xml
.\AlphaSentinel.ps1 -ReplayPath C:\evt\security.xml     # or a directory of .xml
```

**3. The whole suite.** Everything is asserted automatically - no elevation, no
event log, no HTTP and no network needed - by a runner that drives the same
functions the live monitor uses:

```powershell
.\tests\run-tests.ps1      # 925 assertions, exit code 1 on any failure (2 backlog catch-up checks are a known open issue)
```

It covers detection behaviour in both directions, dedupe-per-entity, the
severity ladders, self-test coverage, the audit-policy preflight logic, state
persistence, CSV-injection safety, the authentication model (PBKDF2 format
cross-checked against `New-SentinelAdmin.ps1`, sessions and both timeouts, login
rate limiting, the users-file gate, the Host guard), the lost-event fix
(per-event isolation, per-channel watermarks that only advance when a channel
completed), backlog catch-up (a 5000-event backlog draining without loss or
duplication) and the XPath pre-filter (well-formed, a superset of what the
engine needs, and the fallback), the hardening round (the request-body guard's
411/413 boundaries, the idle-vs-catching-up rule, sessions ending with their
account, the public-health / authenticated-status split, the 5 s watermark overlap
and that the overlap is not double-counted, paged oldest-first polls that lose
nothing across a page boundary, and PBKDF2 pinned to the RFC 6070 vectors) and the
v2.3 round (the stalled-body watchdog: the C# reader's exact/short/empty reads, a
real loopback stall abandoned inside 3s, the flag/counter/abort, the three-stall
block and its Retry-After; the dashboard backend: the ring buffer's exact field set
and its secret-free guarantee, host/user/ip collection and caps, hourly buckets and
their 24-hour window, the MITRE parsing, the alert object and the dedupe
contribution, and all four payloads with their limits, filters and validation; and
the new front end: the file layout, the allowlist, no inline code, no innerHTML, the
design tokens, and every mockup-vs-spec rule), the v2.3.1 review round (coverage
counting only confirmed families, empty arrays really empty, the tactic list and the
health pill) and the v2.4 round (the health reasons and the aborted-fetch silence; the
assets maps and their caps and eviction, DN stripping, `::ffff:` normalisation, the
internal flag, and every assets/sort/filter/paging boundary; the chain grouping, its
hash id and kill-chain ordering; and the report's period validation, its sections and
its secret-free guarantee), the v2.4.1 round (an idle poll is not an error and a
missing log is skipped, not degraded; the audit-policy setup's admin refusal, safe
one-argument invocation, backup-first ordering, idempotence and restore; the exact
alertCount arithmetic on hosts, IPs and accounts; and that a shared destination
host no longer merges chains), then replays all 23 fixtures in `tests/fixtures/`.
See `tests/README.md`.

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
counted and exposed on `/api/status` as `forwardingErrors` instead of being
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
