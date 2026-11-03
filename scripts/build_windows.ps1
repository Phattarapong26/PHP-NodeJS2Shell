# ==============================================================================
# OPScaner - Local Windows Desktop Package Builder (PowerShell)
# ==============================================================================
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  OPScaner - Local Windows Release Packager                 " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# Install PyInstaller if needed
pip install pyinstaller -q

# Clean previous build directories
if (Test-Path "build") { Remove-Item -Recurse -Force "build" }
if (Test-Path "dist") { Remove-Item -Recurse -Force "dist" }
if (Test-Path "OPScaner-Windows.zip") { Remove-Item -Force "OPScaner-Windows.zip" }

Write-Host "[*] Compiling OPScaner executable for Windows..." -ForegroundColor Yellow
pyinstaller --noconfirm --onedir --name "OPScaner" `
  --add-data "GUI.html;." `
  --add-data "fonts;fonts" `
  app.py

Write-Host "[*] Adding unlock launcher..." -ForegroundColor Yellow
Copy-Item "scripts\unlock-windows.bat" "dist\OPScaner\"

Write-Host "[*] Creating OPScaner-Windows.zip..." -ForegroundColor Yellow
Compress-Archive -Path "dist\OPScaner\*" -DestinationPath "OPScaner-Windows.zip"

Write-Host "============================================================" -ForegroundColor Green
Write-Host " Packaging complete: OPScaner-Windows.zip" -ForegroundColor Green
Write-Host "  Users can unzip and double-click OPScaner.exe to run!" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
