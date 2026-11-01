#!/bin/bash
# ==============================================================================
# OPScaner - macOS Quarantine Remover & Desktop Launcher
# ==============================================================================
cd "$(dirname "$0")" || exit 1

echo "============================================================"
echo "  OPScaner - Desktop Launcher for macOS                     "
echo "  ThaiCERT & NCSA Security Audit Framework                  "
echo "============================================================"
echo "[*] Removing macOS Gatekeeper quarantine flags..."

# Remove quarantine attribute from application files
xattr -cr . 2>/dev/null || true

if [ -f "./OPScaner" ]; then
    chmod +x "./OPScaner"
    echo "[*] Launching OPScaner..."
    ./OPScaner
elif [ -d "./OPScaner.app" ]; then
    open "./OPScaner.app"
else
    echo "[!] Executable OPScaner not found in current folder."
fi
