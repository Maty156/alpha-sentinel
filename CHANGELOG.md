# Changelog

## v2.2

Replaces the injected-token dashboard with a real login, and makes the polling
loop able to lose neither events nor time. Verified against the PowerShell parser
and a **272-assertion** suite (no elevation, no event log, no HTTP needed -
`tests/run-tests.ps1`), plus a live HTTP run of the auth flow.

### 1. Real login (replaces the injected API token)

- **The token scheme is gone** - no more `-ApiToken`, no `X-Sentinel-Token`, no
  `?token=`, and no token injected into the served HTML. The old design handed the
  token to anyone who could fetch the page, so "authentication" was really "can
  you reach the port". `script-src` no longer needs `'unsafe-inline'` either:
  scripts ship as `/dashboard.js` and `/login.js`.
- **`login.html` / `login.js`** - a sign-in page in the same dark/crimson style.
  `/` serves it unauthenticated and the dashboard when a session exists.
- **`POST /api/login`** verifies against `sentinel-users.json` with PBKDF2
  (per-user random 16-byte salt, 150000 iterations, the `Rfc2898DeriveBytes`
  overload that exists on .NET 4.x), compares in constant time, and mints a
  session: 32 random bytes as hex, kept in server memory, 8 h absolute lifetime
  with a 30 min sliding idle timeout. The cookie is
  `sentinel_session=<id>; Path=/; HttpOnly; SameSite=Strict`.
- **`POST /api/logout`** destroys the session and clears the cookie. The
  dashboard header shows "signed in as <user>" and a Logout button, and a 401
  sends the browser to the sign-in page.
- **Authorization**: every `/api/*` route except `/api/health` and
  `POST /api/login` answers 401 JSON without a live session. `/api/health` stays
  open for probes as a bare `{"ok":true}` - no counters and no alert content; the
  counters moved to the authenticated `/api/status` in section 6.
- **Brute-force protection**: 5 failed logins per source IP per 5 minutes, then
  429 with `Retry-After` for 5 minutes; one generic message for a bad username and
  a bad password; an unknown user costs the same hashing work as a known one.
- **Audited**: `sentinel-auth.csv` records every attempt (time, source IP,
  username, outcome, reason) and never a password.
- **Host-header allowlist** on loopback binds (localhost / 127.0.0.1 / ::1)
  against DNS rebinding, on top of HttpListener's own prefix matching.
- **Refuses to start the web UI without a users file** and prints exactly how to
  create one. Monitoring, alerting and forwarding keep running - a missing
  credential file must not blind the monitor.
- Startup warns, loudly, when bound beyond localhost over plain HTTP (the
  password and the cookie are unencrypted); the README documents VPN / TLS
  reverse proxy.
- State-changing endpoints remain POST-only + same-origin.

### 2. New-SentinelAdmin.ps1 (account manager)

- `.\New-SentinelAdmin.ps1` creates `admin` with a random 20-character password;
  `-Username`, `-Reset`, `-PromptPassword` (SecureString, min 12, confirmed),
  `-List` (usernames + created date, never hashes) and `-Remove`.
- Passwords come from `RandomNumberGenerator` (never `Get-Random`), guaranteed to
  mix upper/lower/digit/symbol and then shuffled with the CSPRNG; the ambiguous
  glyphs `0 O o 1 I l i` are excluded and the symbol set avoids characters that
  fight with the shell.
- Prints the password **once**, tells you to save it, and writes only salt+hash to
  disk. Refuses to overwrite an existing user without `-Reset`.
- Locks the users-file ACL to Administrators + SYSTEM by SID (localisation-proof)
  and warns if it cannot.
- The PBKDF2 record format is shared with AlphaSentinel.ps1; the test suite writes
  a record with the admin tool's functions and verifies it with the monitor's
  verifier, so the two cannot drift apart.

### 3. Lost-event bug

- `Evaluate-Event` is wrapped in a **try/catch per event**: a malformed event is
  counted (`evalErrors`, `lastEvalError`), skipped, and the rest of the batch
  continues. Previously one bad event aborted the remaining events while the
  watermark still advanced - they were lost permanently.
- **Per-channel watermarks** (Security / System / Defender) persisted in
  `sentinel-state.json`; a channel's mark moves only when that channel's query
  *and* processing completed. A failed query no longer hides behind
  `-ErrorAction SilentlyContinue`: it is caught, counted (`pollErrors`, per-channel
  `lastError`), and the watermark is left alone so those events are retried.
- A seen-record ring means the boundary event re-read on the next poll is not
  evaluated twice, and a poison event is never retried forever.
- `/api/status` (authenticated; `/api/health` until section 6) exposes
  `evalErrors`, `pollErrors` and per-channel `lastSuccess` / `lastError` /
  `lagSeconds`, and the dashboard shows them as a pill.

### 4. Backlog catch-up and lag

- A capped poll re-polls after `-CatchUpMilliseconds` (**200 ms**) instead of a
  whole `-PollSeconds`, lifting the ~33 events/second ceiling.
- **XPath pre-filter** (`Get-WinEvent -FilterXml`) for the three noisiest IDs:
  4624 (LogonType 3 or 10), 4769 (RC4 0x17 or 23) and 4776 (not 0x0). Their XML is
  no longer parsed in PowerShell. Every in-engine check is unchanged, the filter
  is a deliberate *superset* of what the engine needs (it may pass extras that the
  engine then rejects, never drop an event it would have alerted on), and if the
  provider rejects the query the channel falls back to the plain Id filter for good.
- Each channel queries only from its own watermark, so a deferred poll does not
  re-read what it already handled.
- **Poll lag** (now minus the oldest channel watermark) is in `/api/status` per
  channel and as a whole, shown as a "catching up: Ns behind" pill, with a
  warning past 2 minutes. Section 6 fixes what "catching up" meant: an idle
  monitor carries a poll interval of lag by design and is not behind.

### 5. Rule changes

- **4738 delegation**: newly granted unconstrained delegation (`0x80000`) and
  constrained delegation with protocol transition (`0x1000000`) now fire, at High,
  and only when the bit actually moved (`new AND NOT old`).
- **kerberoasting**: a single RC4 service ticket is **Medium**; 3 or more distinct
  service principals requested by one account inside 10 minutes escalates the open
  alert to **High** (the catalog severity is now Medium, matching the base case).

### 6. Web-DoS, liveness and session hardening

- **Request bodies are bounded, and refused before they are read.** The login route
  accepts at most **8192** bytes and every other route **65536**; a body with no
  `Content-Length`, or one that arrives chunked, is refused **411** (its size is
  only knowable by reading it, which is the attack) and an oversized one is refused
  **413**. The listener also bounds `EntityBody`, `DrainEntityBody` and `HeaderWait`
  - the defaults were two minutes, which on a single-threaded server means one
  stalled client holds the only thread. Rejections are counted and reported as
  `bodyRejections`.
- **An idle monitor no longer calls itself "catching up".** The test was
  `lag > 2 seconds`, but a healthy system carries lag by design: it polls every
  `-PollSeconds` and the watermark is deliberately backdated 5 s for overlap, so
  the pill read "catching up" forever. Catching up now means *the last poll had to
  defer events, or the lag is past two poll intervals plus the 5 s overlap*,
  computed once in `Get-CatchUpState` and mirrored by `dashboard.js`.
- **`/api/health` is a bare liveness probe** - `{"ok":true}` and nothing else, so an
  unauthenticated caller learns only that something is listening. Counters, lag,
  session count and error tallies moved to the authenticated **`/api/status`**, which
  is what the dashboard reads.
- **Sessions die with their account.** `Get-Session` re-checks
  `sentinel-users.json` (re-read only when its mtime moves) and ends any session
  whose user is gone or whose record was rewritten, so
  `New-SentinelAdmin.ps1 -Remove` / `-Reset` take effect on the very next request
  instead of at the next restart. A session that carries no recorded account
  revision is ended too: fail closed.
- **A capped poll reads only what it processes** -
  `Get-WinEvent -Oldest -MaxEvents (cap + 1)` instead of materialising a whole
  backlog and discarding most of it. The `+1` is how a full page is recognised.
- **The watermark overlaps by 5 s** on an uncapped poll (`pollStart - 5s`), so an
  event written between the query's snapshot and the poll start cannot fall outside
  every window. The seen-record ring drops the re-reads, so the overlap is free.
- **`[Type]::new()` is gone** in favour of `New-Object` in both scripts: `::new()` is
  PowerShell 5.0+ syntax and this has to run from 5.1 up. The construction is pinned
  by the published RFC 6070 PBKDF2-HMAC-SHA1 vectors, so it is verified rather than
  assumed.

### Performance (found while testing the backlog case)

- `Add-WindowHit` pruned its window with a `Where-Object` scan on every event, and
  `Get-DistinctCount` built three pipelines per call - both quadratic, so a
  sustained brute force would slow the tool down exactly when it matters. Expiry
  is now a prefix trim (events arrive oldest-first, and a non-monotonic window
  falls back to the exact filter) and distinctness is a hashtable.
- A 5000-event backlog now drains in ~11 polls, in a test suite that runs in
  about 80 seconds instead of not finishing within the harness timeout.

### Docs and packaging

- README and the script header document the login model, sessions, the account
  manager, the new flags, the resilience behaviour and the testing story.
- `.gitignore` also covers `sentinel-users.json` and `sentinel-auth.csv`.
- `tests/` grew to **202 assertions** and **19 fixtures** (delegation granted /
  unchanged, a Kerberoasting sweep), with per-fixture expected severities.

### Known follow-ups

- The platform side still needs to accept `isAlert` / `ruleKey` on
  `/api/detections/ingest` for forwarded alerts to surface as alerts there.
- `-Bind 0.0.0.0` remains plain HTTP; put it behind TLS or a VPN.
- The XPath pre-filter is exercised against synthetic event XML here; confirm it
  against a real Security log on the lab DC. A rejection falls back automatically,
  and a silent over-filter would show up as a channel whose lag climbs while
  alerts stop - which the health pill makes visible.

## v2.1

Answers the static review of the v2 tooling. Everything below was verified
against a PowerShell parser and a 79-assertion test suite (63 engine/dedupe/
preflight/export assertions + 16 event-fixture replays) before hand-off; the
items marked **verify on the DC** depend on your lab's real event data.

### Detection bugs

- **`ntlm_failed_auth` counted successes.** 4776 is written for both outcomes and
  `Status 0x0` means the credentials validated, but the rule never read `Status` -
  so healthy NTLM traffic raised a High alert. It now counts only non-zero status
  codes.
- **`dcsync_replication` could never fire on a real event.** It matched the
  replication GUIDs against `ObjectType`, but a real 4662 carries them in
  `Properties` (`ObjectType` holds the object class). It now matches across
  `Properties` + `ObjectType` + `ObjectName`, and skips machine accounts
  (`DC01$`) because a DC replicating is normal. **Verify on the DC** with one real
  4662.
- **Dedupe was per rule, not per entity.** One Domain Admins addition swallowed
  every other privileged-group addition for 15 minutes, and a second spraying
  source hid behind the first. The dedupe key is now `ruleKey + entity` (source
  IP, account, workstation, service principal, registry key, firewall rule), with
  per-entity lookup of the alert to upgrade in place.
- **`account_control_changed` tested the new flags, not the change.** Any edit to
  an account that already carried `PASSWD_NOTREQD`, or any edit to an
  already-disabled account, fired. It now compares `new AND NOT old` and flags
  only flags that actually moved (gained pre-auth-free / password-not-required,
  or cleared Account-Disabled).
- **`eventlog_service_stopped` polled the wrong channel.** 1100 is written to the
  **Security** log (Microsoft's reference XML: `<Channel>Security</Channel>`), not
  System - the rule could never fire.
- **Kerberoasting fired on ordinary traffic.** Now excludes failed requests,
  `krbtgt`, machine SPNs, and requests coming from machine accounts; keeps a
  distinct-SPN count per requesting account and escalates to Critical at three.
- **AS-REP roasting needed three hits.** One successful no-preauth TGT request is
  enough, so that is the threshold now.
- **Noisy rules.** `account_created` skips computer accounts (domain joins);
  `suspicious_remote_logon` skips machine and system principals and routine
  service-account type-3 logons, and dedupes per account + source IP;
  `special_privileges_assigned` skips `SYSTEM` / `LOCAL SERVICE` /
  `NETWORK SERVICE`.
- A 4662 replication event from a DC machine account is no longer also counted by
  the enumeration counter (found while testing the DCSync fix).

### Reliability

- **Event loss.** The watermark was set to "now" after processing, so every event
  written during a slow poll was skipped forever, and it advanced even when the
  send failed. It is now read before the query, advanced only afterwards (and
  only to the last event actually handled), persisted to `sentinel-state.json`,
  and a restart resumes instead of re-alerting the last two minutes or skipping
  the downtime.
- **Ordering and event time.** Events are processed oldest-first and the rolling
  windows are stamped with the *event's* time, not the poll's.
- **Busy-DC cost.** `-MaxEventsPerPoll` (default 500) caps parsing per poll and
  defers the newest events to the next pass instead of dropping them; a seen-
  record ring stops an overlapping window being evaluated twice.
- **Forwarding no longer freezes the tool** (8-second timeout), and failures are
  counted and exposed on `/api/health` instead of being swallowed.
- **Forwarding sends the finished alert**, not only the triggering event: the
  platform's own thresholds need a run of events and were never met, so nothing
  appeared there. The payload now carries `isAlert`, `ruleKey`, `severity`,
  `title`, `description`, `mitre`, `alertedAt`.
- **`/api/alerts` is cached** and no longer re-serialises every alert's full
  normalised event on every poll; `?limit=`, `?since=`, `?selfTest=` added.
- **Severity survives a restart.** History now stores severity/title/rule, so an
  alert upgraded in place no longer reverts to the rule's default.
- **Self-test cannot break the monitor.** Tracker restoration moved into a
  `finally`, probe values are XML-escaped (the `TaskContent` probe used to break
  its own shim), and self-test rows are tagged and excluded from coverage counts
  and the CSV export.
- **Collector.** Per-channel watermarks, advanced only on a successful send (a
  failed window used to be dropped silently), bounded retry with backoff, takes
  the *oldest* events when capping, `-TimeoutSec`, `-Once`, persisted state.

### Security

- **Dashboard binds to localhost by default** (`-Bind 0.0.0.0` opts into the LAN,
  with a warning) instead of serving every interface unauthenticated.
- **Token required on `/api/*`** (`X-Sentinel-Token`), generated per run, printed
  at startup, injected into the served page, never written to disk. `/api/health`
  stays open and carries no alert content.
- **State-changing endpoints are POST-only and same-origin**, so a page open in
  an administrator's browser can no longer ack or false-positive-close alerts.
- **CSV formula injection fixed** - exported cells beginning `=`, `+`, `-` or `@`
  are prefixed.
- Response hardening: CSP, `X-Frame-Options: DENY`, `nosniff`, `no-store`.

### New

- **Audit-policy preflight** (`/api/preflight`, `/api/preflight/refresh`, and a
  banner in the dashboard): maps every rule family to its Advanced Audit
  subcategory, reads the live policy with `auditpol /get`, marks families that
  cannot fire, and prints the exact `auditpol` commands that fix them. Unreadable
  policy reports *unknown*, never a false "blind".
- **`-ReplayPath`**: replay exported `wevtutil /f:xml` events through the real
  engine and print what would have fired. `tests/fixtures/` ships 16 real-shaped
  fixtures with negative cases (see `tests/README.md`).
- Self-test visibility toggle in the dashboard; per-rule audit state in the
  coverage table.

### Packaging and docs

- Both scripts normalised to pure ASCII and saved **UTF-8 with BOM** (the em
  dashes were cosmetic-only in comments, but a BOM-less UTF-8 script is decoded as
  ANSI by Windows PowerShell 5.1 - the failure mode is mojibake on non-CP1252
  systems, not a parse error).
- `-Background` now actually hides the window (the old switch did nothing; only
  the README's `Start-Process -WindowStyle Hidden` hid it).
- `-Stop` / `Stop-Sentinel` work from any console via `sentinel.pid` (the old
  function only existed inside the running monitor's own process).
- README, script header and collector header now carry the same audit-category
  list, corrected to the subcategories the events really live under (`MPSSVC
  Rule-Level Policy Change` for 4946-4949, `Security State Change` for 4616,
  `Directory Service Changes` for 5141; `SAM` was not a real subcategory).
- Rule-family counts corrected to 28 everywhere; `BlueTeamConsole.ps1` (deleted
  in the working tree) removed from the README.

### Known follow-ups

- The platform side needs to accept the `isAlert` / `ruleKey` fields on
  `/api/detections/ingest` to surface forwarded alerts as alerts.
- `-Bind 0.0.0.0` over plain HTTP still sends the token in cleartext; put it
  behind TLS or a reverse proxy if it leaves a trusted network.
- A baseline of legitimate replication accounts (AAD Connect, backup tooling) is
  still worth adding to `dcsync_replication` for real environments.
