"""
Attach / detach the XDP program and pin its maps.

Usage:
    sudo python3 -m idps.module1_dataplane.loader --iface eth0
    sudo python3 -m idps.module1_dataplane.loader --iface eth0 --detach
    python3 -m idps.module1_dataplane.loader --stats

Requirements: clang, llvm, bpftool, libbpf-dev, and a kernel >= 5.10.
On Debian/Ubuntu:
    sudo apt install clang llvm libbpf-dev linux-tools-common \
                     linux-tools-$(uname -r)

A note on attach modes, because this trips people up during demos
-----------------------------------------------------------------
Native XDP runs on the NIC driver and is where the nanosecond figures come
from, but it requires driver support. Many virtualised NICs (and most VM
setups students test on) do not have it, and the attach silently falls back to
generic/SKB mode, which runs after sk_buff allocation and is roughly an order
of magnitude slower. If you quote a latency number in the report, say which
mode produced it -- `ip link show <iface>` reports `xdpgeneric` versus `xdp`.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).parent
OBJ = HERE / "xdp_filter.o"
SRC = HERE / "xdp_filter.c"
PIN_DIR = "/sys/fs/bpf"


def _run(cmd: list, check: bool = True) -> subprocess.CompletedProcess:
    print("  $", " ".join(cmd))
    return subprocess.run(cmd, check=check, capture_output=True, text=True)


def build() -> None:
    if not SRC.exists():
        sys.exit(f"missing source: {SRC}")
    arch = "__x86_64__" if os.uname().machine == "x86_64" else "__aarch64__"
    _run(["clang", "-O2", "-g", "-target", "bpf", f"-D{arch}",
          "-I/usr/include", "-c", str(SRC), "-o", str(OBJ)])
    print(f"built {OBJ}")


def attach(iface: str, mode: str = "native") -> None:
    if not OBJ.exists():
        build()
    flag = {"native": "xdpdrv", "generic": "xdpgeneric",
            "offload": "xdpoffload"}[mode]
    _run(["bpftool", "prog", "load", str(OBJ), f"{PIN_DIR}/idps_filter",
          "type", "xdp"], check=False)
    _run(["ip", "link", "set", "dev", iface, flag, "obj", str(OBJ),
          "sec", "xdp"])
    print(f"attached to {iface} in {mode} mode; maps pinned under {PIN_DIR}")
    print("verify with: ip link show", iface)


def detach(iface: str) -> None:
    for flag in ("xdpdrv", "xdpgeneric", "xdpoffload", "xdp"):
        _run(["ip", "link", "set", "dev", iface, flag, "off"], check=False)
    for name in ("idps_filter", "blocked_ips", "blocked_tuples", "stats"):
        p = Path(PIN_DIR) / name
        if p.exists():
            p.unlink()
    print(f"detached from {iface}")


def stats() -> None:
    p = Path(PIN_DIR) / "stats"
    if not p.exists():
        sys.exit("stats map not pinned -- is the program attached?")
    r = _run(["bpftool", "map", "dump", "pinned", str(p), "-j"])
    data = json.loads(r.stdout or "[]")
    labels = ["seen", "dropped", "passed", "expired"]
    for i, entry in enumerate(data[:4]):
        total = sum(int(v, 16) if isinstance(v, str) else int(v)
                    for v in entry.get("values", [entry.get("value", 0)]))
        print(f"{labels[i]:>10}: {total}")


def main() -> None:
    ap = argparse.ArgumentParser(description="Module 1 XDP loader")
    ap.add_argument("--iface")
    ap.add_argument("--mode", default="native",
                    choices=["native", "generic", "offload"])
    ap.add_argument("--detach", action="store_true")
    ap.add_argument("--build-only", action="store_true")
    ap.add_argument("--stats", action="store_true")
    args = ap.parse_args()

    if args.stats:
        return stats()
    if args.build_only:
        return build()
    if not args.iface:
        ap.error("--iface is required unless --stats or --build-only")
    if os.geteuid() != 0:
        sys.exit("attaching XDP needs root")
    detach(args.iface) if args.detach else attach(args.iface, args.mode)


if __name__ == "__main__":
    main()
