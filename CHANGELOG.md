# Changelog

## v2.5.1

Two new detection families - the 28-rule set becomes **30**. **883 assertions**
(`tests/run-tests.ps1`), up from 857.

### firewall_disabled (NEW, Critical)

Event **4950** "A Windows Firewall setting has changed", alerting only when the
change turned a whole profile OFF: `SettingType = EnableFirewall` with
`SettingValue = No` (the `Enable Windows Firewall` spelling some builds write
and the numeric `0` form from the oldest ones are accepted too). Severity
Critical, `T1562.004 - Impair Defenses: Disable or Modify System Firewall`,
deduped per profile. **firewall_rule_modified (4946-4949) stays a separate
rule** - it covers individual rule add/modify/delete/restore and is never
raised by a 4950.

The event's field names were confirmed against Microsoft's own event-XML
sample (`ProfileChanged`, `SettingType`, `SettingValue`) before the parser was
written. 4950 shares the **MPSSVC Rule-Level Policy Change** audit subcategory
with 4946-4949, so no new `auditpol` entry is needed - documented in the rule,
the README rule table and the preflight list.

### anonymous_smb_session (NEW, Medium)

Event **4624** with `LogonType 3` and no credentials at all: `ANONYMOUS LOGON`,
an empty target name, or the anonymous SID `S-1-5-7` - the shape of pre-auth AD
enumeration (SID brute-forcing, RID cycling, null-session tooling). Deduped
**per source IP per hour** because printers and scanners can be constant
anonymous talkers. Remediation: "Disable null session access
(RestrictAnonymous) unless explicitly required". Mapped to `T1087 - Account
Discovery`, consistent with the other discovery rule (ldap_recon lists T1087
among its techniques).

### Tests and counts

- Four new fixture files (fire / no-fire for each rule) and `expected.json`
  entries; the fixture-replay count is 19 -> 23.
- The self-test suite gained probes for both rules, so the self-test fires all
  30 families.
- `rulesTotal` everywhere comes from `$RuleMeta.Count` (30); the Detection
  Rules page header, README rule table (with the 4950 subcategory note) and
  the auditpol preflight list are updated. 4950 is added to the XPath
  pre-filter and the Security-channel event list.

## v2.5.0

Settings that DO things - account management and the audit policy from the UI.
**857 assertions** (`tests/run-tests.ps1`), up from 816.

### Account management (Settings > Account / Users)

- `POST /api/account/password` re-verifies the current password (a wrong one
  counts as a login failure for the caller's IP), requires 12+ characters that
  differ from both the username and the current password, rewrites the record
  with a fresh salt and 150000 iterations, ends every OTHER session of the user
  and rotates the caller's session id.
- `POST /api/account/username` re-authenticates, then renames (3-32 chars of
  `A-Za-z0-9._-`, unique case-insensitively); the session continues under the
  new name.
- `GET /api/users` (names and dates only - never a hash or salt),
  `POST /api/users` (create), `/reset` and `/remove` - all re-authenticate with
  the caller's password. The last account cannot be removed, self-removal is
  refused, targets are looked up in the users list (never a path), and every
  change ends that user's sessions.
- `POST /api/account/avatar` stores initials (1-2 chars A-Z0-9) and one of
  eight fixed palette colours - no file upload - returned by `/api/session`
  and shown in the topbar user menu (Account, Logout).

### Audit policy from the UI (Settings > Audit)

- `GET /api/audit` (per-rule state, subcategory + flag needed, last change,
  backup names, elevation), `POST /api/audit/preview` (the exact diff,
  changing nothing), `POST /api/audit/apply` (re-auth, then the same
  backup-first, enable-only, idempotent code as `-EnableAudit`, preflight
  re-run at once, who/what auth-logged) and `POST /api/audit/restore`
  (re-auth; only backups this tool created, by name - path tricks are 400).
- Without elevation the change routes answer 409 and the tab is read-only.
- The confirm dialog lists every before -> after row before anything happens.

### Also

- Empty responses from `GET /api/users` and `POST /api/audit/preview`
  serialise as `[]` (an empty array through a pipeline was `$null`, and
  `UTF8.GetBytes($null)` was a 500).
- `tests/run-tests.ps1` builds its scratch dirs with
  `[IO.Path]::GetTempPath()` instead of `$env:TEMP`.

## v2.4.1

Review fixes and lab-box behaviour, no new detection features. **816 assertions**
(`tests/run-tests.ps1`), up from 757.

### Part 1 - an idle poll is not an error, and a missing log is skipped

Seen on the real Server 2012 R2 lab box: `Get-WinEvent -ErrorAction Stop` THROWS
when nothing matches (`NoMatchingEventsFound`), and a channel that does not
exist on the OS throws `NoMatchingLogsFound` (Defender's Operational log is
absent on Server 2012 R2). Both were treated as poll errors: every idle poll
flipped the XPath fallback, logged a red error, froze the watermark and grew
the lag until health degraded. Now the error is classified by its
FullyQualifiedErrorId (never the localised message): an idle channel returns an
empty result with the watermark still advancing; a missing log is announced
once, skipped from then on, and excluded from lag, pollErrors and health; only
real failures count as errors. A rule whose every channel is missing reads as
"unverified: log not present" - not blind, not ok.

### Part 2 - audit-policy setup (opt-in) + console safety

`-EnableAudit` sets the subcategories the rules need: it refuses without
Administrator, backs the policy up first, passes the whole
`/subcategory:"..."` (or the subcategory GUID) as ONE argument so it survives
PowerShell's quote-stripping, only ever enables, is idempotent, prints a
before/after table and logs each change. `-RestoreAudit <file>` runs
`auditpol /restore`. On interactive startup with blind rules it asks once
(default No, 15 s timeout). `/api/settings` shows the last audit change.
The QuickEdit console flag is cleared (and restored on exit) so a click in the
console can no longer freeze the monitor.

### Part 3 - the v2.4 review fixes

1. The Reports page's From/To/Generate/Print controls actually render above the
   report (the load callback used to wipe them), and print layout flows: only
   the top-alerts and appendix tables start a new page, so an 11-alert report
   prints in 4 pages instead of 8.
2. `alertCount` no longer doubles on hosts and IPs (N alerts = N, tested on
   host, IP and account).
3. Attack chains no longer merge alerts that merely share a destination host;
   the link is a shared account or a shared source IP inside the 60-minute
   window, and the host stays an entity/label on the chain.
4. Chains layout: 11 tactic columns at >= 150px in a horizontal scroller, no
   mid-word breaks, topbar title/subtitle wrap, one-line DEMO DATA pill.
5. `::ffff:` normalised in `host.ips`; asset drawer alert links read
   "#id - title (severity)"; the report's by-severity table sorts
   Critical, High, Medium, Low; spacing between report headings and bodies.

Every changed page was rendered in chromium from real endpoint payloads
(screen and print) and the screenshots reviewed before committing.

## v2.4.0

Assets, Attack Chains and Reports, plus two v2.3.1 leftovers. **757 assertions**
(`tests/run-tests.ps1`), up from 600.

### Part 0 - the health pill says why, and aborted fetches stay silent

1. **The pill names the reason.** `health` is no longer a bare string: it is
   `{ state, reasons[] }` on `/api/overview`. **Blind** (red) when a rule family
   cannot fire, **Unverified** (amber) when the audit policy is unreadable,
   **Catching up** (amber) only when the poller is behind, **Healthy** (green)
   otherwise. When several apply the worst is the headline and every reason is in
   the pill's tooltip, worst first, each with a sentence saying what it means.
2. **An aborted fetch is not an error.** `api.js` treats `AbortError` /
   `NavigationError` as silent - clicking away from a page with a poll in flight
   no longer logs a failure. Real failures still log once, tagged with the page.

### Part 1 - Assets

`GET /api/assets?kind=host|account|ip&q=&limit=` (limit clamped to 500, `kind`
validated with a 400 on junk, `q` a plain substring match) and
`GET /api/assets/<kind>/<id>` (the id is looked up in the map - never a path or a
regex - and an unknown id is a 404). All of it is built from what the window
actually observed: the hosts-seen map, a new capped ip map (oldest evicted) and
the alert state.

- **host** - name, first/last seen, event and alert counts, max severity, the
  users and source addresses seen on it, its open alert ids and its tactics.
- **account** - DN prefixes stripped to the account name, type user vs computer
  (a trailing `$`, and *only* that - nothing is guessed), first/last seen, hosts,
  addresses, alert count, max severity, recent event ids and flags derived
  **only** from fired rules ("added to a privileged group", "Security log
  cleared", ...). No invented risk scores.
- **ip** - `::ffff:` normalised, first/last seen, accounts and hosts, a failed
  logon count, alert count, max severity, and an `internal` flag (RFC1918,
  loopback and link-local are internal).

New `#/assets` page: Hosts / Accounts / IPs tabs, search, sortable columns (name,
last seen, alerts, max severity), a row opens a right-side drawer with the detail,
its open alerts linked to the Alerts page, and its activity timeline from the
event ring buffer. Empty and error states are explicit.

### Part 2 - Attack Chains

`GET /api/chains` groups the open alerts that share an entity - same account OR
same host OR same source IP - inside a 60-minute sliding window, ordered by time.
Each chain carries a stable hash id, a title ("attacker1 on DC01"), its entities,
first/last seen, its max severity, its alerts and its tactics in MITRE kill-chain
order. **A chain needs at least two alerts**; a lone alert is not a chain. The
grouping is deterministic: same alerts in, same chains out.

New `#/chains` page: the chain list on the left, and the selected chain drawn as
an 11-step kill-chain strip with the alerts under each tactic they touched. Every
alert opens that alert's drawer on the Alerts page.

### Part 3 - Engagement report

`GET /api/report?from=&to=` renders the period's report: executive summary,
coverage and limitations (including how many families are unverified or blind),
findings by severity / status / tactic, attack chains, affected assets, the top
alerts, a remediation checklist (deduped by recommendation, with the alert count)
and an alert-timeline appendix. Empty windows say so in plain words. The dates are
validated: junk is refused and a range over 31 days is refused, both with 400.

New `#/reports` page: the date form, range presets, and the report rendered as a
framed document with `css/print.css` so it prints to PDF cleanly.

### Housekeeping

- Every new file is in the strict static allowlist (`js/pages/assets.js`,
  `js/pages/chains.js`, `js/pages/reports.js`, `css/print.css`) - unknown paths
  are still a plain 404.
- Each new endpoint takes a session, is GET-only, and returns JSON; 401 / 400 /
  404 / 405 are all covered by tests.
- No raw event message bodies, no secrets and no credentials appear in any new
  payload, and `GET /api/settings` still exposes no secret.
- No detection rule logic was touched: the 28 families and their thresholds are
  unchanged.

## v2.3.1

Review fixes only - no new features. **599 assertions** (`tests/run-tests.ps1`).

1. **Coverage counts only CONFIRMED families.** A rule whose audit state could not
   be read is unverified, not working - counting `unknown` as `working` is how a
   blind deployment reports 100%. `coverage.percent = rulesWorking / rulesTotal`
   where working = total - blind - unknown, with new `rulesUnknown` and
   `unknownRules` fields, an "N unverified" note on the coverage tile, an amber
   **Unverified** badge (plus a count line and a banner) on the Detection Rules
   page, and `health = 'degraded'` (amber) while the policy is unreadable.
2. **Every array the API returns is an array.** An empty collection returned from a
   PowerShell function arrives as `$null`, and `@($null)` serialised as `[null]`.
   `ConvertTo-JsonArray` now returns `[]` for null and skips null elements, so
   `/api/hosts` (and every other list endpoint) is `[]` when empty.
3. **Top MITRE tactics** render as "Tactic ...... count" - no bullets, a dotted
   leader, the number right-aligned - and the rows are actually wrapped in the
   styled list (bare `<li>` nodes kept the browser's bullets).
4. **Overview > Recent Alerts** is capped at 6 rows, one line each (severity,
   title, host, account, time, status). The description moved to the Alerts drawer
   where the detail lives.
5. **Charts**: the hourly chart draws its area, line, baseline and hour labels even
   with one or two buckets (a single point is duplicated into a flat line, and each
   hour is labelled once); the tiles carry sparklines that fit their box plus delta
   arrows (up / down / neutral, coloured by what the metric means).
6. **Polish**: the banner says v2.3.1; `hosts[].users` holds account names (a
   `CN=...` DN prefix is stripped); self-test and history-restored alerts are given
   tactic / technique / entity from the rule catalogue so no row renders blanks;
   and both pages declare an inline favicon (`<link rel="icon" href="data:,">`) so
   the console has no 404. Two render defects found while re-checking visually were
   fixed: the tile sparklines overflowed their tiles (`.spark` hard-codes the big
   chart's height), and the tactic rows were missing their list wrapper.

## v2.3

Three parts: a security fix for a freeze one client could trigger, the backend the
new dashboard reads, and a rebuilt front end. Every part was verified against the
PowerShell parser and a **536-assertion** suite (`tests/run-tests.ps1`, exit code 1
on any failure - no elevation, no event log, no HTTP needed), plus live runs
against a real listener: the stall/abort/429 behaviour, every endpoint with and
without a session, and the static allowlist.

### 1. A stalled request body can no longer freeze the loop (do first)

- `TimeoutManager` is only enforced by HTTP.sys, and the managed listener does not
  enforce it: a client that declared a `Content-Length` and then sent nothing parked
  `ReadToEnd()` until the connection died. This server has ONE thread, so the
  dashboard and the event poll stopped with it - reproduced as a 25 s hold and five
  failed health probes.
- **`SentinelBody`** (C#, compiled once with `Add-Type` behind a type check) reads
  exactly the declared byte count on a dedicated `LongRunning` thread and gives up
  after `$Script:BodyReadMs` (2000). `ReadAsync` + `Wait` measured ~5 s per stall;
  this measures ~2.0 s, and a health probe during a stall now answers in ~1.8 s
  instead of timing out.
- `Read-JsonBody` reads through it, decodes with `ContentEncoding.GetString()`, and
  on a stall flags `BodyTimedOut`, counts `bodyTimeouts`, **aborts the connection**
  (so the socket is never left half-read) and returns null.
- The body is now read **once**, in `Invoke-Handler`, so the 411/413 decision and
  the watchdog live in one place; the routes consume the parsed body instead of
  reading and re-draining it themselves.
- The client address is captured at the top of the request. Aborting the connection
  makes `RemoteEndPoint` unavailable, which filed the attack under "unknown" and
  left the real source unlogged and unblocked.
- A stalled body is a failed sign-in (auth audit + the login-failure budget), and
  **three stalls from one address block it** for the login-block window: the next
  sign-in gets 429 with a `Retry-After` of 300 s. `bodyTimeouts` is on `/api/status`.

### 2. The backend for the new dashboard

Rolling, **in-memory, per-process** state - a dashboard window, not a second copy of
the history (`sentinel-history.csv` owns durability):

- **Events ring buffer**: the last 300 normalised events (time, eventId, channel,
  host, user, sourceIp, a generated summary, matchedRule). It stores only what the
  engine already parsed plus generated text - never a raw message body, a command
  line or a secret, and a test asserts the field set exactly.
- **Hosts seen**: host -> firstSeen/lastSeen/eventCount/alertCount/users[]/ips[],
  capped at 200 hosts (least recently seen evicted), 40 users and 20 addresses each.
- **Hourly buckets**: the last 24 hours of events, alerts by severity and alerts by
  MITRE tactic, plus the tile values at the start of each hour so the dashboard can
  show a delta against the previous hour.

Endpoints (session required, GET-only, JSON):

- `GET /api/overview` - tiles and deltas, coverage (percent / rulesWorking /
  rulesBlind / blindRules, from the existing audit preflight), severityCounts,
  tacticCounts, `hourly[]`, lastPoll, `health` (ok | degraded | blind) and version.
- `GET /api/events` - newest first; `limit` clamped to 300, `eventId` validated
  (400 on junk), `host`/`user` exact, `q` a plain substring and never a regex.
- `GET /api/hosts` - the host map, busiest first.
- `GET /api/settings` - read-only and deliberately narrow: version, poll/bind/port,
  session and rate limits, forwarding on/off + destination **host** only, the audit
  preflight, and account **names with creation dates**. No hash, salt, session id or
  forwarding key has any path into it.

Alerts now carry what a drawer and a kill-chain timeline need: `Status` (the
four-value vocabulary), a separate `Acknowledged` boolean, `MitreId` / `MitreName` /
`Tactic` (parsed from the rule's existing Mitre and Category - no rule logic
changed), `Entity`, `FirstSeen` / `LastSeen` / `Count`, and the contributing event
summaries. A hit suppressed by dedupe joins the open alert's list instead of
vanishing.

### 3. The new dashboard front end

- **Split into files** (`css/tokens|base|layout|components|pages|login.css`,
  `js/api|state|ui|router|app.js`, `js/pages/*.js`, `dashboard.html`, `login.html` +
  `login.js`). `dashboard.js` is gone. No inline style or script element and no
  `on*` attribute anywhere - the CSP keeps `script-src 'self'`.
- **A strict static allowlist**: every servable file is named with its content type,
  and a request is looked up in that table rather than turned into a filesystem
  path, so there is nothing to traverse - `../` and unknown paths are a plain 404.
- **Design**: dark charcoal, crimson reserved for the brand (logo, active nav,
  primary button). Severity has its own palette and never uses crimson - Critical
  `#ff4d6d`, High orange, Medium amber, Low blue-grey; healthy/coverage is teal.
  Base type 15px, tables 14px, tile numbers 30px, captions never below 12px, visible
  keyboard focus, `prefers-reduced-motion` respected.
- **Pages**: Overview (five tiles with deltas and sparklines, coverage meter with a
  blind-rules banner linking to Rules, severity bar, hourly chart as inline SVG,
  top tactics, latest alerts and events), Alerts (severity/status/ack chips, search,
  table, right-side drawer with status, a separate ack toggle, contributing events
  and a kill-chain timeline), Detection Rules (all 28 families, Working or BLIND
  with the reason and the `auditpol` fix), Events (live table with the endpoint's
  filters), Settings (read-only), each with empty and error states.
- **Mockup vs spec**: Assets / Attack Paths / Reports render as disabled "Soon"
  items with no route; the top search filters only the current page's table; the
  range is fixed at 24 h; the sidebar badge is `openAlerts`; Acknowledged is a flag
  and never a status; Critical never uses the brand crimson; charts show an honest
  empty state; and the **"DEMO DATA" marker appears only with the new `-DemoData`
  switch** - the tool never invents numbers to fill a panel.

### Docs

README: the new endpoints, the file layout and design rules, the `-DemoData` flag,
the stalled-body watchdog, and the assertion count (536).

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
