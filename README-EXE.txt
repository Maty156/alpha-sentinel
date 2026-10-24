Alpha Sentinel - Windows Executable Release
=============================================

This release contains AlphaSentinel.exe, a compiled version of AlphaSentinel.ps1
using PS2EXE (https://github.com/rgra/ps2exe).

IMPORTANT: The .exe MUST be run from inside the unzipped release folder.
It will NOT work if moved elsewhere, because it depends on sibling files:
  - dashboard.html
  - login.html
  - login.js
  - css/ (entire folder)
  - js/ (entire folder)

Files in this release:
  AlphaSentinel.exe         - The compiled monitor
  dashboard.html            - Dashboard shell (loaded by exe)
  login.html                - Login page
  login.js                  - Login page logic
  css/                      - Stylesheets (tokens, base, layout, components, pages, login, print)
  js/                       - JavaScript modules (api, state, ui, router, app, pages/*)
  start-sentinel.bat        - Wrapper for first-run setup (optional)
  start-sentinel.ps1        - PowerShell wrapper (alternative to .bat)
  New-SentinelAdmin.ps1     - Account management tool
  README.txt                - This file
  CHANGELOG.md              - Version history

REQUIREMENTS:
- Windows Server 2012 R2 / Windows 10 or later
- Windows PowerShell 5.1 or later (built-in on supported OS versions)
- Administrator privileges (required for reading Security event log and auditpol)

QUICK START:
1. Unzip this folder to a permanent location (e.g., C:\AlphaSentinel\)
2. Run as Administrator:
   .\AlphaSentinel.exe
3. First run will prompt for:
   - Administrator username (3-32 chars, A-Z a-z 0-9 . _ -)
   - Password (min 12 chars, not equal to username)
   - Domain-joined? (Y/n) - informational only, for UI labeling
4. Open browser to http://localhost:8443 and sign in

OPTIONS (passed to the .exe):
  -Port <n>                  Dashboard port (default 8443)
  -Bind <ip|localhost>       Bind address (default localhost)
  -PollSeconds <n>           Poll interval in seconds (default 15)
  -MaxEventsPerPoll <n>      Max events per poll (default 500)
  -Background                Run hidden (no console window)
  -Stop                      Stop a running background instance
  -Unattended                Skip all interactive prompts (for CI)
  -DemoData                  Label dashboard as demo (no fake data)
  -ReplayPath <path>         Replay exported event XML through engine

EXAMPLES:
  # First run (interactive setup):
  .\AlphaSentinel.exe

  # Subsequent runs (auto-detects existing account):
  .\AlphaSentinel.exe

  # Run in background (service-style):
  .\AlphaSentinel.exe -Background

  # With forwarding to Alpha web platform:
  .\AlphaSentinel.exe -ForwardUrl "https://your-app.vercel.app/api/detections/ingest" -ForwardKey "YOUR_COLLECTOR_API_KEY"

  # Non-interactive (CI/CD):
  .\AlphaSentinel.exe -Unattended -DemoData

STOPPING:
  .\AlphaSentinel.exe -Stop
  # or from any PowerShell:
  .\AlphaSentinel.ps1 -Stop

FILES CREATED AT RUNTIME (in same folder as exe):
  sentinel-users.json      - PBKDF2-hashed accounts (created on first run)
  sentinel-history.csv     - Alert history (persists across restarts)
  sentinel-state.json      - Per-channel poll watermarks
  sentinel-auth.csv        - Login audit trail
  sentinel.pid             - Process ID for -Stop
  sentinel-gemini.key      - Optional: Gemini API key (set in Settings > Account)

FORWARDING TO WEB PLATFORM:
Set -ForwardUrl to your Alpha platform's /api/detections/ingest endpoint
and -ForwardKey to the COLLECTOR_API_KEY from the platform settings.

TROUBLESHOOTING:
- "Access denied" or auditpol errors: Run as Administrator
- Port 8443 in use: Use -Port <n> or stop conflicting service
- Dashboard not loading: Check firewall, ensure port 8443 is open
- "Web dashboard NOT SERVED": Run first-run setup or create account with New-SentinelAdmin.ps1

VERIFICATION:
SHA256: (compute with: certutil -hashfile AlphaSentinel.exe SHA256)
Version: 2.6.0 (matches AlphaSentinel.ps1 version)