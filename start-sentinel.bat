@echo off
:: Alpha Sentinel - Entry point wrapper
:: Calls PowerShell to start the monitor with admin credential collection on first run

:: Check if the users file already exists
if exist..\sentinel-users.json (
    :: Users file exists - just start the main monitor
    powershell -NoProfile -ExecutionPolicy Bypass -File .\AlphaSentinel.ps1 %*
) else (
    :: First run - show setup and then launch
    powershell -NoProfile -ExecutionPolicy Bypass -File .\start-sentinel.ps1 %*
)
