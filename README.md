# ALPHA Sentinel v2.2 - AD / Network Attack Monitor (background service + web dashboard)

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
| `AlphaSentinel.ps1` | **The main tool (v2.2)** - background monitor + embedded web dashboard |
| `dashboard.html` / `dashboard.js` | The dashboard, served by AlphaSentinel behind a login - must sit beside the script |
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
auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:enable            # 4946 4947 4948 4949
```

No `auditpol` entry is needed for: **1100 / 1102** (the Eventlog service writes
those to the **Security** log itself), **7045** (Service Control Manager, System
log) or **5001 / 5010 / 5012** (the Defender **Operational** channel).

**3. Run it:**

```powershell
# background (no console window); writes sentinel.pid
powershell -ExecutionPolicy Bypass -File .\AlphaSentinel.ps1 -Background

# or in the foreground with a small console window
powershell -ExecutionPolicy Bypass -File .\AlphaSentinel.ps1
```

Then open **http://localhost:8443** and sign in. Stop it from any console:

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
| `-ForwardUrl` / `-ForwardKey` | - | forward detections to the ALPHA web platform |
| `-HistoryFile` | `sentinel-history.csv` | alert history |
| `-StateFile` | `sentinel-state.json` | per-channel poll watermarks |
| `-UsersFile` | `sentinel-users.json` | dashboard accounts |
| `-AuthFile` | `sentinel-auth.csv` | login audit trail |
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
- **Every `/api/*` route except `/api/health` and `POST /api/login` answers 401
  JSON** without a live session. `/api/health` stays open for monitoring probes
  and deliberately carries counters only - no titles, accounts, rules or
  descriptions.
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
- Response hardening: `Content-Security-Policy` with **`script-src 'self'`** (no
  inline script anywhere; `dashboard.js` and `login.js` are separate files),
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
  (`/api/health` → `evalErrors`) and skipped; it cannot abort the rest of the
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
  in `/api/health` and shown as a pill in the dashboard ("catching up: Ns
  behind"), with a warning past 2 minutes.
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

Wazuh-style dark UI matching the ALPHA platform's design language:

- **Severity stat tiles** - Total / Critical / High / Medium / Low / Open / Acknowledged
- **Live search** - by title, rule, MITRE, account, host, description
- **Filters** - severity buttons, status dropdown, and a Self-test visibility toggle
- **Auto-refresh** - every 10 s (toggleable) + manual refresh button
- **Health pill** - poll lag, skipped events and failed log reads, or "up to date"
- **Alert table** - time, severity badge, alert, account, host, MITRE; click a row for the detail pane
- **Detail pane** - MITRE ATT&CK mapping (linked), rule, event ID, host, account, source IP, what happened, remediation guidance
- **Triage** - per-alert status (New / Investigating / Resolved / False Positive) + notes, saved server-side
- **Detection coverage panel** - every rule family, how often it fired, its audit-policy state, and a **preflight banner** listing the families this host is not logging plus the exact `auditpol` commands that fix them
- **Acknowledge / Unacknowledge** - per-row, persisted server-side
- **Export CSV** - the engagement report (MITRE + ack state, formula-injection safe, self-test rows excluded)
- **Signed in as &lt;user&gt; / Logout** in the header

## Detection coverage (28 rule families)

The catalog mirrors `alpha/utils/detectionRules.js` key-for-key - same rule keys,
severities and event IDs, so an alert promoted in either product lands on the
same `rule_key`.

| Group | Rules | Event IDs |
|---|---|---|
| Brute force / spraying | password_spraying, brute_force_single_account, kerberos_preauth_spraying, ntlm_failed_auth, account_lockout_storm | 4625, 4771, 4776, 4740 |
| Privilege escalation / identity abuse | privilege_escalation, account_created, account_control_changed, account_enabled_disabled, password_reset_by_admin, group_membership_removed, account_deleted | 4728/4732/4756, 4720, 4738, 4722, 4724, 4729/4733, 4726 |
| Kerberos attacks / directory | kerberoasting, asrep_roasting, dcsync_replication, ldap_recon | 4769, 4768, 4662, 5141 |
| Logon / services | suspicious_remote_logon, explicit_credential_logon, service_abuse | 4624, 4648, 4697/7045 |
| Persistence | scheduled_task_created, registry_persistence | 4698, 4657 |
| Anti-forensics / defense evasion | log_tampering, audit_policy_changed, eventlog_service_stopped, defender_disabled, firewall_rule_modified, system_time_changed, special_privileges_assigned | 1102, 4719, 1100, 5001/5010/5012, 4946-4949, 4616, 4672 |

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

## Testing

**1. Self-test (plumbing + thresholds).** The **Self-test** button in the
dashboard, or `POST /api/self-test`. One synthetic event sequence per rule family
through the real engine; reports how many of the 28 fired.

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
.\tests\run-tests.ps1      # 202 assertions, exit code 1 on any failure
```

It covers detection behaviour in both directions, dedupe-per-entity, the
severity ladders, self-test coverage, the audit-policy preflight logic, state
persistence, CSV-injection safety, the authentication model (PBKDF2 format
cross-checked against `New-SentinelAdmin.ps1`, sessions and both timeouts, login
rate limiting, the users-file gate, the Host guard), the lost-event fix
(per-event isolation, per-channel watermarks that only advance when a channel
completed), backlog catch-up (a 5000-event backlog draining without loss or
duplication) and the XPath pre-filter (well-formed, a superset of what the
engine needs, and the fallback), then replays all 19 fixtures in
`tests/fixtures/`. See `tests/README.md`.

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
