#!/bin/bash
# make-executable.sh
# Finds all .sh files from the repo root and sets them to executable.
# Place this script in the development/ sub-directory and run it from anywhere.
 
# Resolve the repo root (one level up from this script's directory)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
 
echo "[*] Scanning for .sh files under: $REPO_ROOT"
echo ""
 
COUNT=0
while IFS= read -r -d '' file; do
    chmod +x "$file"
    echo "[+] chmod +x: $file"
    ((COUNT++))
done < <(find "$REPO_ROOT" -type f -name "*.sh" -print0)
 
echo ""
echo "[✓] Done — $COUNT file(s) set to executable."
 