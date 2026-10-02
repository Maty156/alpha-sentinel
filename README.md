# ALPHA Sentinel v2 — AD / Network Attack Monitor (background service + web dashboard)

A standalone Windows security-monitoring tool from the **Alpha Cybersecurity**
graduation project — **Wazuh's agent + dashboard model as ONE zero-dependency
script**: Sentinel runs silently in the BACKGROUND on a Domain Controller (or
any domain-joined machine), polls the Windows Security event log, detects
Active Directory / network attack patterns — Kerberos attacks (Kerberoasting,
AS-REP roasting), LDAP/SAMR enumeration, password spraying, privilege
escalation, suspicious remote logons, service abuse, and log tampering — and
serves a **modern web dashboard** you open in any browser on the network.
Optionally forwards every detection to the **ALPHA web platform** (a separate
private repo: `Maty156/alpha`).

> The web platform (marketing site, client portal, admin panel, assessments,
> certificates) lives in its **own repo**. This repo is the Windows tooling
> only — Sentinel works fully standalone with zero dependency on the website.

## Tools in this repo

| File | What it is |
|---|---|
| `AlphaSentinel.ps1` | **The main tool (v2)** — background monitor + embedded web dashboard (see below) |
| `dashboard.html` / `dashboard.js` | The web UI, served by AlphaSentinel on port 8443 — must sit beside the script |
| `collector.ps1` | Minimal headless collector — polls the Security log and forwards matches to the web platform, no UI |
| `BlueTeamConsole.ps1` | First-generation console (kept for reference; superseded by AlphaSentinel v2) |

## v2 architecture (what changed from v1)

v1 was a WinForms desktop console. v2 is **service-style + web UI** (like
Wazuh: agent on the host, dashboard in the browser):

- **Runs in the background** — no window needed; the monitor keeps running
  while you use any browser on the network.
- **Embedded web server** (`System.Net.HttpListener`, zero dependencies) —
  serves the dashboard and a JSON API on `http://0.0.0.0:8443`.
- **Single-threaded by design** — one loop drains web requests AND polls the
  event log (PowerShell scriptblocks can't run on .NET ThreadPool threads
  without a runspace; works on PS 5.1 / Server 2012).
- **Alerts persist** — every alert + acknowledgment is written to
  `sentinel-history.csv`, so state survives restarts and is shared across
  every browser (no browser-side storage).
- **`/api/self-test`** — fires 6 synthetic events through the REAL rule
  engine (same code path as live polling), lands the resulting alerts in the
  dashboard tagged `[SELF-TEST]`, and restores the live trackers afterward so
  it's repeatable.
- **Fails loudly** — if `dashboard.html`/`dashboard.js` is missing, the
  server returns a clear 500 telling you to download the full release.

## The web dashboard (modern UI)

Wazuh-style dark UI matching the ALPHA platform's design language:

- **Severity stat tiles** — Critical / High / Medium / Low / Open / Acknowledged
- **Live search** — by title, rule, MITRE, account, host, description
- **Filters** — severity buttons + status dropdown (Open / Acknowledged)
- **Auto-refresh** — every 10 s (toggleable) + manual refresh button
- **Alert table** — time, severity badge, alert, account, host, MITRE; click
  a row for the detail pane
- **Detail pane** — MITRE ATT&CK mapping, rule, event ID, host, account,
  source IP, what happened, and remediation guidance per alert
- **Acknowledge / Unacknowledge** — per-row, persisted server-side
- **Export CSV** — full alert list with MITRE + ack state for the engagement report

## Detection coverage (8 rule families)

| Rule | Event ID(s) | Severity | MITRE |
|---|---|---|---|
| Password spraying | 4625 | High | T1110.003 |
| Privilege escalation | 4728/4732 | Critical | T1078.002 |
| Kerberoasting (RC4) | 4769 | High | T1558.003 |
| AS-REP roasting | 4768 (no-preauth) | High | T1558.004 |
| LDAP/SAMR enumeration | 4662/5141 | Medium | T1018/T1087 |
| Suspicious remote logon | 4624 | Medium | T1021 |
| Service abuse | 4697/7045 | Medium/High | T1543.003 |
| Log tampering (cleared) | 1102 | Critical | T1070.001 |

## Run AlphaSentinel v2 (as Administrator)

Enable the audit categories the rules read (once):

```powershell
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable
auditpol /set /subcategory:"SAM" /success:enable
auditpol /set /subcategory:"Other Object Access Events" /success:enable
```

Run in the BACKGROUND (recommended — console closes, monitor + web UI keep
running):

```powershell
Start-Process powershell -ArgumentList '-ExecutionPolicy Bypass -File .\AlphaSentinel.ps1 -Background' -WindowStyle Hidden
```

Or run in the FOREGROUND (small console window with a startup banner):

```powershell
powershell -ExecutionPolicy Bypass -File .\AlphaSentinel.ps1
```

Then open the dashboard: **http://localhost:8443** (or
`http://<DC-IP>:8443` from any machine on the network).

**Try it instantly:** open `http://localhost:8443/api/self-test` — five
`[SELF-TEST]` alerts appear in the dashboard to demo every UI feature.

Optional forwarding to the web platform (same value as `COLLECTOR_API_KEY`
on the server):

```powershell
powershell -ExecutionPolicy Bypass -File .\AlphaSentinel.ps1 `
  -ForwardUrl "https://your-app.vercel.app/api/detections/ingest" `
  -ForwardKey "COLLECTOR_API_KEY value"
```

Optional tuning: `-Port 8443`, `-PollSeconds 15`, `-HistoryFile`
(default `sentinel-history.csv` next to the script).

Works on Windows Server 2012 R2+ and Windows 10/11 (default .NET Framework
4.5+ covers everything the script uses; no installs, no dependencies).

**Stop the background monitor:** from any PowerShell console, run
`Stop-Sentinel` (registered globally by the script).

## Run the headless collector (no UI)

```powershell
powershell -ExecutionPolicy Bypass -File .\collector.ps1 `
  -ForwardUrl "https://your-app.vercel.app/api/detections/ingest" `
  -ForwardKey "COLLECTOR_API_KEY value"
```

See the comments at the top of `collector.ps1` for details.

## How it fits the purple-team workflow

1. Red team runs the attack chain in the lab (separate repo/environment).
2. **Alpha Sentinel v2** detects the attack patterns live on the DC; the
   admin monitors from the browser dashboard (or gets platform alerts with
   forwarding enabled).
3. The same alerts appear in the web platform's admin **Detections tab**,
   where they're investigated and can be promoted into a specific client's
   assessment findings.

---

Academic prototype — Alpha Cybersecurity is a student graduation project,
not a commercial security firm.
