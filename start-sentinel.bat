@echo off
:: Alpha Sentinel - Entry point wrapper
:: Calls PowerShell to start the monitor with admin credential collection on first run

:: Check if the users file already exists
if exist "%~dp0sentinel-users.json" (
    :: Users file exists - just start the main monitor
    cd /d "%~dp0"
    powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0AlphaSentinel.ps1" %*
) else (
    :: First run - show setup and then launch
    cd /d "%~dp0"
    powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0start-sentinel.ps1" %*
)