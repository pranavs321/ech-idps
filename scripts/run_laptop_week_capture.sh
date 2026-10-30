#!/usr/bin/env bash
# Week-Long Privacy-Preserving Benign Traffic Capture
# Captures only TCP handshakes (SYN, SYN-ACK) and TLS handshakes (port 443).
# Never captures unencrypted application data, URLs, or HTTP payloads.

set -euo pipefail

OUT_DIR="${1:-./laptop_capture}"
INTERFACE="${2:-en0}"
DURATION_HOURS="${3:-24}"

mkdir -p "$OUT_DIR"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
PCAP_OUT="$OUT_DIR/laptop_benign_${TIMESTAMP}.pcap"
CSV_OUT="$OUT_DIR/laptop_benign_${TIMESTAMP}_anonymized.csv"

echo "=== Starting Privacy-Preserving Laptop Capture ==="
echo "Interface : $INTERFACE"
echo "Output    : $PCAP_OUT"
echo "Duration  : $DURATION_HOURS hours"
echo "Filter    : TCP SYN/SYN-ACK + TLS Handshakes (port 443)"

# Capture only SYN packets or initial TLS packets on port 443
# Snaplen 160 bytes is enough for TCP + TLS Handshake headers without capturing payloads!
sudo tcpdump -i "$INTERFACE" -s 256 -nn -w "$PCAP_OUT" \
    'tcp[tcpflags] & (tcp-syn) != 0 or (tcp port 443 and tcp[((tcp[12:1] & 0xf0) >> 2):1] = 0x16)' \
    -G "$((DURATION_HOURS * 3600))" -W 1 &
TCPDUMP_PID=$!

echo "tcpdump running as PID $TCPDUMP_PID. Press Ctrl+C to stop capture at any time."
trap 'echo "Stopping capture..."; sudo kill -TERM "$TCPDUMP_PID" 2>/dev/null || true; wait "$TCPDUMP_PID" 2>/dev/null || true' INT TERM

wait "$TCPDUMP_PID" || true

echo "=== Processing & Anonymizing Capture ==="
python3 scripts/capture_laptop_tls.py --pcap "$PCAP_OUT" --out "$CSV_OUT"

echo "=== Capture Complete ==="
echo "Raw PCAP (keep local): $PCAP_OUT"
echo "Anonymized Table (shareable with team): $CSV_OUT"
