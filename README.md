# ALPHA Sentinel — AD / Network Attack Monitor

A standalone Windows security-monitoring tool from the **Alpha Cybersecurity**
graduation project: it watches the Windows Security event log on a Domain
Controller (or any domain-joined machine), detects Active Directory /
network attack patterns — Kerberos attacks (Kerberoasting, AS-REP roasting),
LDAP/SAMR enumeration, password spraying, privilege escalation, suspicious
remote logons, service abuse, and log tampering — and alerts the IT admin
with a desktop UI and (optionally) forwards every detection to the
**ALPHA web platform** (a separate private repo: `Maty156/alpha`).

> The web platform (marketing site, client portal, admin panel, assessments,
> certificates) lives in its **own repo**. This repo is the Windows tooling
> only — Sentinel works fully standalone with zero dependency on the website.

## Tools in this repo

| File | What it is |
|---|---|
| `AlphaSentinel.ps1` | **The main tool** — dark-theme WinForms console: severity dashboard, live alert table, detail pane with MITRE mapping + remediation guidance, toast notifications, alert acknowledgment (persisted), CSV export, optional web forwarding with real event IDs |
| `collector.ps1` | Minimal headless collector — polls the Security log and forwards matches to the web platform, no UI |
| `BlueTeamConsole.ps1` | First-generation console (kept for reference; superseded by AlphaSentinel) |

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

## Run AlphaSentinel (as Administrator)

Enable the audit categories the rules read (once):

```powershell
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable
auditpol /set /subcategory:"SAM" /success:enable
auditpol /set /subcategory:"Other Object Access Events" /success:enable
```

```powershell
powershell -ExecutionPolicy Bypass -File .\AlphaSentinel.ps1
```

Optional forwarding to the web platform (same value as `COLLECTOR_API_KEY`
on the server):

```powershell
powershell -ExecutionPolicy Bypass -File .\AlphaSentinel.ps1 `
  -ForwardUrl "https://your-app.vercel.app/api/detections/ingest" `
  -ForwardKey "COLLECTOR_API_KEY value"
```

Optional tuning: `-PollSeconds 10` (default 15), `-HistoryFile` (default
`sentinel-history.csv` next to the script — acknowledged state survives restarts).

Works on Windows Server 2012 R2+ and Windows 10/11 (default .NET Framework 4.5+
covers everything the script uses; no installs, no dependencies).

## Run the headless collector (no UI)

```powershell
powershell -ExecutionPolicy Bypass -File .\collector.ps1 `
  -ForwardUrl "https://your-app.vercel.app/api/detections/ingest" `
  -ForwardKey "COLLECTOR_API_KEY value"
```

See the comments at the top of `collector.ps1` for details.

## How it fits the purple-team workflow

1. Red team runs the attack chain in the lab (separate repo/environment).
2. **Alpha Sentinel** detects the attack patterns live on the DC and alerts the admin.
3. With forwarding enabled, the same alerts appear in the web platform's
   admin **Detections tab**, where they're investigated and can be promoted
   into a specific client's assessment findings.

---

Academic prototype — Alpha Cybersecurity is a student graduation project,
not a commercial security firm.
