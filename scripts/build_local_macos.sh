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
rm -rf build dist OPScaner-macOS.zip OPScaner.dmg

echo "[*] Compiling OPScaner into standalone macOS App Bundle..."
./venv/bin/pyinstaller --noconfirm --windowed --name "OPScaner" \
  --add-data "GUI.html:." \
  --add-data "diagram.html:." \
  --add-data "fonts:fonts" \
  app.py

echo "[*] Creating OPScaner.dmg installer..."
hdiutil create -volname "OPScaner" -srcfolder dist/OPScaner.app -ov -format UDZO OPScaner.dmg 2>/dev/null

echo "[*] Adding unlock launcher..."
cp scripts/unlock-macos.command dist/OPScaner/
chmod +x dist/OPScaner/unlock-macos.command

echo "[*] Creating OPScaner-macOS.zip..."
cd dist
zip -q -r ../OPScaner-macOS.zip OPScaner.app OPScaner unlock-macos.command 2>/dev/null || zip -q -r ../OPScaner-macOS.zip *
cd ..

echo "============================================================"
echo "✓ Packaging complete!"
echo "  1. OPScaner.dmg        (Official macOS Installer disk image)"
echo "  2. OPScaner-macOS.zip  (Portable zip with .app)"
echo "  * Source code is fully compiled into binary (no .py files exposed)"
echo "============================================================"
