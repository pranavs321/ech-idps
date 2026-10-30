#!/usr/bin/env bash
# Clamped-Path Benign Experiment (M36 / Section 11.3 & 22.10)
# Demonstrates that a middlebox rewriting the SYN-ACK MSS to 1357 turns benign web traffic into "malware"
# Requires Linux with root/sudo capabilities (throwaway VM recommended).

set -euo pipefail

MODE="${1:-}"
OUT_DIR="${2:-./clamped_path_output}"
URL_LIST="${3:-top_sites.txt}"

if [ -z "$MODE" ] || { [ "$MODE" != "A" ] && [ "$MODE" != "B" ]; }; then
    echo "Usage: sudo $0 <A|B> [OUT_DIR] [URL_LIST]"
    echo "  Condition A: Normal baseline path (no clamping, standard MSS 1460)"
    echo "  Condition B: Clamped path (SYN-ACK MSS clamped to 1357)"
    exit 1
fi

mkdir -p "$OUT_DIR"

if [ ! -f "$URL_LIST" ]; then
    echo "Creating default URL list: $URL_LIST"
    cat << 'EOF' > "$URL_LIST"
https://www.google.com
https://www.wikipedia.org
https://www.github.com
https://www.cloudflare.com
https://www.mozilla.org
https://www.python.org
https://www.kernel.org
https://www.apache.org
https://www.w3.org
https://www.ietf.org
EOF
fi

echo "=== Cleaning up any existing network namespace ==="
ip netns del cl 2>/dev/null || true
ip link del veth0 2>/dev/null || true

echo "=== Setting up network namespace 'cl' ==="
ip netns add cl
ip link add veth0 type veth peer name veth1
ip link set veth1 netns cl

ip addr add 10.200.1.1/24 dev veth0
ip link set veth0 up

ip netns exec cl ip addr add 10.200.1.2/24 dev veth1
ip netns exec cl ip link set veth1 up
ip netns exec cl ip link set lo up
ip netns exec cl ip route add default via 10.200.1.1

mkdir -p /etc/netns/cl
echo "nameserver 1.1.1.1" > /etc/netns/cl/resolv.conf
sysctl -w net.ipv4.ip_forward=1 >/dev/null

iptables -t nat -D POSTROUTING -s 10.200.1.0/24 -j MASQUERADE 2>/dev/null || true
iptables -t nat -A POSTROUTING -s 10.200.1.0/24 -j MASQUERADE

iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1357 2>/dev/null || true

if [ "$MODE" = "B" ]; then
    echo "=== Condition B: Enabling TCP MSS clamping to 1357 ==="
    iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1357
else
    echo "=== Condition A: Standard unconstrained network path ==="
fi

PCAP_FILE="$OUT_DIR/condition_${MODE}.pcap"
echo "=== Starting packet capture to $PCAP_FILE ==="
ip netns exec cl tcpdump -i veth1 -nn -s 0 -w "$PCAP_FILE" 'tcp' >/dev/null 2>&1 &
TCPDUMP_PID=$!
sleep 2

echo "=== Generating benign traffic across URL list ==="
while read -r url; do
    [ -z "$url" ] && continue
    echo "  Fetching: $url"
    ip netns exec cl curl -s -k -m 10 --tlsv1.3 "$url" >/dev/null || true
done < "$URL_LIST"

sleep 3
echo "=== Stopping packet capture ==="
kill -TERM "$TCPDUMP_PID" 2>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true

echo "=== Teardown network namespace ==="
iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1357 2>/dev/null || true
iptables -t nat -D POSTROUTING -s 10.200.1.0/24 -j MASQUERADE 2>/dev/null || true
ip netns del cl 2>/dev/null || true
ip link del veth0 2>/dev/null || true

echo "=== Run Complete for Condition $MODE ==="
echo "Output capture saved to: $PCAP_FILE"
echo "Next step: Run extraction and score with score_clamped_path.py"
