# Changelog

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
