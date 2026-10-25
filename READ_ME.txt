Alpha Sentinel - Windows AD Attack Monitor
==========================================

QUICK START:
-----------

1. FIRST TIME RUN (creates admin account):
   Double-click: start-sentinel.bat
   - Prompts for administrator username (3-32 chars)
   - Prompts for password (min 12 characters, confirm once)
   - Creates sentinel-users.json with PBKDF2 hash
   - Launches monitor in background

2. SUBSEQUENT RUNS:
   Double-click: AlphaSentinel.ps1
   - Or: double-click start-sentinel.bat (detects users file exists, skips prompt)
   - Launches monitor directly

3. ACCESS THE DASHBOARD:
   Open browser to: http://localhost:8443
   Sign in with the admin credentials you created
   - Wolf bot "🐺 Ask Wolf" button appears on dashboard

FILE STRUCTURE:
---------------
AlphaSentinel.ps1  - Main monitor script (v2.6.0, 36 rule families)
start-sentinel.bat - Wrapper (first run or subsequent runs)
start-sentinel.ps1 - Wrapper (first-run setup only, prompts for creds)
sentinel-users.json - Auto-created (do not edit manually)
README.txt - This file

USAGE:
--------
• The monitor polls Windows Event Logs (Security, System, Defender)
• Detects 36 AD attack rule families (Kerberoasting, DCSync, brute force, etc.)
• Dashboard shows alerts, coverage, attack paths, assets
• Optional forwarding to web platform via -ForwardUrl/-ForwardKey
• Wolf bot assistant answers questions about alerts, rules, coverage

NOTES:
- Requires PowerShell 5.1+ (Server 2012 R2+)
- Requires Administrator for full functionality
- Default bind: localhost only (plain HTTP beyond localhost)
- Dashboard CSP: no inline scripts, separate .js files only
