#!/usr/bin/env bash
# =============================================================
# recon.sh — nmap TCP + UDP scanning automation for CTF / HTB
# Usage: ./recon.sh <target_ip>
#
# Scan order (fastest → slowest):
#   1. TCP fast scan       (-F, top 100 ports)         ~30 sec
#   2. TCP default scan    (top 1000 ports)             ~2-5 min
#   3. UDP top 100 ports                                ~5-10 min
#   4. UDP top 1000 ports  [backgrounded]               ~20-40 min
#   5. TCP all ports       [backgrounded, parallel]     ~10-30 min
# =============================================================

set -euo pipefail

# ── Validation ────────────────────────────────────────────────
if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <target_ip>"
  exit 1
fi

TARGET="$1"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTDIR="./scans_${TARGET}_${TIMESTAMP}"

# Basic IP format sanity check
if ! [[ "$TARGET" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
  echo "[!] '$TARGET' doesn't look like a valid IPv4 address. Proceeding anyway..."
fi

# ── Setup ─────────────────────────────────────────────────────
mkdir -p "$OUTDIR"

echo ""
echo "============================================="
echo "  Target   : $TARGET"
echo "  Output   : $OUTDIR/"
echo "  Started  : $(date)"
echo "============================================="
echo ""
echo "  Scan plan:"
echo "    [foreground] 1 — TCP fast scan (top 100)"
echo "    [foreground] 2 — TCP default scan (top 1000)"
echo "    [foreground] 3 — UDP top 100"
echo "    [background] 4 — UDP top 1000        (parallel)"
echo "    [background] 5 — TCP all 65535 ports (parallel)"
echo "============================================="
echo ""

# ── Scan 1 — TCP Fast (foreground) ────────────────────────────
echo "[*] Scan 1/5 — TCP fast scan (top 100 ports)"
echo "    Flags: -Pn -sT -F -sC -sV -T5 -O"
echo ""

sudo nmap -Pn -sT -F -sC -sV -T5 -O -vv \
  --stats-every 30 \
  "$TARGET" \
  -oA "$OUTDIR/scan1_tcp_fast"

echo ""
echo "[+] Scan 1 complete — $(date)"
echo "--------------------------------------------"
echo ""

# ── Scan 2 — TCP Default (foreground) ─────────────────────────
echo "[*] Scan 2/5 — TCP default scan (top 1000 ports)"
echo "    Flags: -Pn -sT -sC -sV -T5 -O"
echo ""

sudo nmap -Pn -sT -sC -sV -T5 -O -vv \
  --stats-every 30 \
  "$TARGET" \
  -oA "$OUTDIR/scan2_tcp_default"

echo ""
echo "[+] Scan 2 complete — $(date)"
echo "--------------------------------------------"
echo ""

# ── Scan 3 — UDP Top 100 (foreground) ─────────────────────────
echo "[*] Scan 3/5 — UDP top 100 ports"
echo "    Flags: -Pn -sU --top-ports 100 -T4"
echo "    Note: T4 used for UDP — T5 causes unreliable results"
echo ""

sudo nmap -Pn -sU --top-ports 100 -T4 -vv \
  --stats-every 30 \
  "$TARGET" \
  -oA "$OUTDIR/scan3_udp_top100"

echo ""
echo "[+] Scan 3 complete — $(date)"
echo "--------------------------------------------"
echo ""

# ── Scans 4 & 5 — Background + Parallel ───────────────────────
echo "[*] Launching scans 4 and 5 in parallel background processes..."
echo ""

# Scan 4 — UDP Top 1000
echo "[*] Scan 4/5 — UDP top 1000 ports [backgrounded]"
echo "    Flags: -Pn -sU --top-ports 1000 -T4"
echo ""

sudo nmap -Pn -sU --top-ports 1000 -T4 -vv \
  --stats-every 30 \
  "$TARGET" \
  -oA "$OUTDIR/scan4_udp_top1000" \
  > "$OUTDIR/scan4_udp_top1000.log" 2>&1 &

SCAN4_PID=$!
echo "[+] Scan 4 running in background (PID: $SCAN4_PID)"
echo "    Live output: tail -f $OUTDIR/scan4_udp_top1000.log"
echo ""

# Scan 5 — TCP All Ports
echo "[*] Scan 5/5 — TCP all 65535 ports [backgrounded]"
echo "    Flags: -Pn -sT -p- -sV -T5"
echo ""

sudo nmap -Pn -sT -p- -sV -T5 -vv \
  --stats-every 30 \
  "$TARGET" \
  -oA "$OUTDIR/scan5_tcp_allports" \
  > "$OUTDIR/scan5_tcp_allports.log" 2>&1 &

SCAN5_PID=$!
echo "[+] Scan 5 running in background (PID: $SCAN5_PID)"
echo "    Live output: tail -f $OUTDIR/scan5_tcp_allports.log"
echo ""

# ── Tip ───────────────────────────────────────────────────────
echo "============================================="
echo "  Scans 1-3 complete. Start enumeration now."
echo ""
echo "  Monitor background scans:"
echo "    tail -f $OUTDIR/scan4_udp_top1000.log"
echo "    tail -f $OUTDIR/scan5_tcp_allports.log"
echo ""
echo "  Check if background scans are still running:"
echo "    ps aux | grep nmap"
echo "============================================="
echo ""

# ── Wait for background scans to finish ───────────────────────
echo "[*] Waiting for background scans to complete..."
echo ""

wait $SCAN4_PID
echo "[+] Scan 4 (UDP top 1000) complete — $(date)"

wait $SCAN5_PID
echo "[+] Scan 5 (TCP all ports) complete — $(date)"

# ── Final Summary ─────────────────────────────────────────────
echo ""
echo "============================================="
echo "  All scans finished — $(date)"
echo "  Results saved to: $OUTDIR/"
echo ""
echo "  Output files:"
ls "$OUTDIR/" | sed 's/^/    /'
echo "============================================="
