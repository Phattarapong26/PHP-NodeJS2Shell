@echo off
:: ==============================================================================
:: OPScaner - Windows Unblock & Desktop Launcher
:: ==============================================================================
cd /d "%~dp0"
title OPScaner - Security Audit Desktop Launcher

echo ============================================================
echo   OPScaner - Desktop Launcher for Windows
echo   ThaiCERT ^& NCSA Security Audit Framework
echo ============================================================
echo [*] Unblocking downloaded files from Windows SmartScreen...

powershell -Command "Get-ChildItem -Recurse '%~dp0' | Unblock-File" 2>nul

if exist "%~dp0OPScaner.exe" (
    echo [*] Starting OPScaner...
    start "" "%~dp0OPScaner.exe"
) else if exist "%~dp0dist\OPScaner\OPScaner.exe" (
    echo [*] Starting OPScaner...
    start "" "%~dp0dist\OPScaner\OPScaner.exe"
) else (
    echo [!] OPScaner.exe not found in this folder.
    pause
)
