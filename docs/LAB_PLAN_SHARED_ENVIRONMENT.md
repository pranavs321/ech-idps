# Experimental Protocol: Shared-Environment Evaluation of TLS Malware Detection

**Author:** S7 Research Team (Pranav, Nandakumar, Vighnesh)  
**Supervisor / Guide Review:** Arjun V (CISAI Cyber Lead)  
**Target Venues:** IEEE TNSM / ACM Transactions on Privacy and Security / CNSM 2027  
**Scope:** Controlled Cross-Environment & Counterfactual Intrusion Detection in Encrypted (TLS 1.3 + ECH) Traffic  

---

## 1. Executive Summary & Research Justification

Published machine learning intrusion detection systems (IDS) leveraging JA4 and flow statistics report up to 99% accuracy on public benchmarks (e.g., CNSM 2024, Beyond JA4+ 2026). However, recent audits reveal a critical structural flaw:
- Malicious samples originate from dynamic malware sandboxes (e.g., Recorded Future / Tria.ge), while benign samples originate from university research laboratories.
- Classifiers inadvertently learn the recording environment's TCP/IP stack (e.g., initial TTL, window size, middlebox SYN-ACK MSS clamping) rather than intrinsic malicious behaviors.
- In independent evaluations, models that see only TCP/IP handshake parameters match the full detector (Balanced Accuracy = 0.986), while failing completely (0% detection) on malware from earlier sandbox epochs and misclassifying 80–99% of foreign benign traffic as malicious.

To conclusively resolve this problem, this protocol establishes a **shared-environment dataset** where benign and command-and-control (C2) traffic are co-located on identical virtual machines and recorded across controlled network egress topologies.

---

## 2. Experimental Testbed Architecture

### 2.1 Virtual Machine Environments
Two clean-slate virtualized endpoints hosted on an isolated virtualization host (Proxmox VE / VMware ESXi):
1. **Windows Endpoint**: Windows 10 Enterprise (Build 19045 / 22H2), standard corporate software profile (browsers, PowerShell, Defender active in audit mode).
2. **Linux Endpoint**: Ubuntu 22.04 LTS Desktop, standard corporate developer profile.

### 2.2 Adversary Simulation (Zero Live Malware)
To guarantee 100% containment and institutional safety without handling dangerous weaponized binaries:
- **C2 Frameworks**: Open-source, widely utilized red-team frameworks:
  1. **Sliver** (BishopFox) over HTTPS / mTLS
  2. **Havoc C2** over HTTPS / WebSocket
  3. **Mythic** over HTTPS / REST
- **Beaconing Profiles**: Configurable sleep intervals (5s, 30s, 60s) with 20% to 50% randomized jitter.
- **Payload Execution**: Standard simulated post-exploitation activities (discovery commands, mock file exfiltration, heartbeat polling).

### 2.3 Concurrent Benign Baseline
Concurrent with C2 execution, the endpoint executes realistic automated benign tasks:
- Headless Chromium / Firefox visiting Tranco Top-1000 websites.
- API interactions, DNS lookups, background NTP and OS telemetry.

---

## 3. Four-Path Network Egress Matrix

Each session is routed through four distinct network path configurations to measure feature invariance:

| Path ID | Network Topology | Expected MTU / MSS | Impact on JA4 / JA4T / JA4TS |
|---|---|---|---|
| **Path 1** | Direct LAN Egress | MTU 1500, MSS 1460 | Baseline TCP handshake, native OS windowing. |
| **Path 2** | OpenVPN (`--dev tun`) | MTU ~1430, MSS Clamped (~1350–1360) | Rewrites SYN-ACK MSS in transit; JA4/JA4T invariant, JA4TS altered. |
| **Path 3** | WireGuard | MTU 1420, MSS Clamped (1380) | Fixed 80-byte encapsulation overhead; tests fixed-MTU response. |
| **Path 4** | Tor / SOCKS5 Proxy | Variable packet batching | Obscures inter-packet timing and connection boundaries. |

---

## 4. Sampling Matrix & Dataset Scale

- **Environments**: 2 (Windows, Linux)
- **Traffic Classes**: 2 (Benign Background Only vs. Benign + Active C2)
- **Egress Topologies**: 4 (Direct, OpenVPN, WireGuard, Tor)
- **C2 Frameworks**: 3 (Sliver, Havoc, Mythic) + 1 Pure Benign
- **Repetitions (Seeds)**: 10 independent captures per configuration
- **Total Recording Sessions**: $2 \times 4 \times 4 \times 10 = 320$ controlled sessions (30–60 minutes per session).
- **Target Connection Count**: $\ge 50,000$ TLS connections across identical network interfaces.

---

## 5. Pre-Registered Hypotheses (PREREG)

- **H1 (Environment Shortcut Elimination)**: When trained and evaluated on the shared-environment dataset under capture-disjoint splits, the `env_only` model will collapse to chance ($\text{Balanced Accuracy} \le 0.52$).
- **H2 (Zero-Shot Generalization via Pre-Hash Decomposition)**: On previously unseen JA4 fingerprints (Protocol P3), per-element ClientHello feature encoding will maintain $\ge 0.85$ balanced accuracy, whereas exact lookup matching drops to $0.0\%$.
- **H3 (Attacker Reshaping Cost)**: To evade physical timing and size attribution (ECH-IDPS Pillar 2), the adversary must introduce $\ge 25\%$ latency padding or packet size inflation.

---

## 6. Safety, Containment & Institutional Approvals

1. **Air-Gapped / Host-Only Listener Subnet**: C2 team servers reside on an isolated virtual network (`10.250.0.0/24`) inaccessible from the public campus LAN.
2. **No Live Exploits or Worms**: All communications are synthetic agent callbacks to local listeners.
3. **Data Availability**: The resulting dataset will be sanitized, hashed, and published under CC BY 4.0 as the first publicly available, environment-controlled TLS intrusion benchmark.
