#!/bin/bash
# ==============================================================================
# OPScaner - Local macOS Desktop Package Builder
# ==============================================================================
set -e
cd "$(dirname "$0")/.."

echo "============================================================"
echo "  OPScaner - Local macOS Release Packager                   "
echo "============================================================"

# Ensure PyInstaller is installed
./venv/bin/pip install pyinstaller -q

# Clean previous builds
rm -rf build dist OPScaner-macOS.zip

echo "[*] Compiling OPScaner executable..."
./venv/bin/pyinstaller --noconfirm --onedir --name "OPScaner" \
  --add-data "GUI.html:." \
  --add-data "diagram.html:." \
  --add-data "fonts:fonts" \
  app.py

echo "[*] Adding unlock launcher..."
cp scripts/unlock-macos.command dist/OPScaner/
chmod +x dist/OPScaner/unlock-macos.command

echo "[*] Creating OPScaner-macOS.zip..."
cd dist
zip -q -r ../OPScaner-macOS.zip OPScaner
cd ..

echo "============================================================"
echo "✓ Packaging complete: OPScaner-macOS.zip"
echo "  Users can unzip and double-click OPScaner to run!"
echo "============================================================"
