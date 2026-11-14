# Threat model (paper section 3.x, draft)

The paper's venue checklist lists "explicit threat model" as a gap. This is a draft to paste and edit.

## Setting

A passive network sensor at an enterprise egress (or a SOC tap) sees every TCP/TLS connection that internal
Windows hosts open to the internet. It sees packet headers, the cleartext TLS handshake (ClientHello,
ServerHello and, for TLS 1.2 and below, the server certificate chain), packet sizes, directions and timing.
It does not decrypt traffic, has no endpoint agent, and does not see process names.

## Defender goal

For each internal host, rank its TLS connections so that connections opened by malware (C2, payload
download, check-ins caused by the implant) come first, with a false-alarm rate a SOC can afford
(at most 1% of benign connections; we also report 0.1%). The unit of decision is the connection; the unit of
triage is the host.

## Attacker capabilities (in scope)

1. **Chooses its TLS library.** The implant may use the operating system's library (Windows SChannel via
   WinHTTP/WinINet), a bundled one (OpenSSL, Go crypto/tls, .NET), or a mimicry library (uTLS) that copies a
   browser ClientHello exactly. *Consequence:* the ClientHello alone cannot be trusted; on real hosts 89.5% of
   malicious connections with a hostname already share an exact JA4 with benign software.
2. **Chooses destinations.** It can use bare IPs, newly registered domains, or reputable cloud and CDN
   services (domain fronting, cloud storage, ipify-style check-ins).
3. **Shapes traffic.** It can add jitter to beacons, pad records and change sleep intervals (Cobalt Strike
   malleable profiles, Sliver/Havoc jitter).
4. **Knows the feature families** but not the trained model or the site's benign baseline.

## Out of scope

* Malware that never uses TLS over TCP (QUIC/HTTP3 and DoH are future work; ECH hides the SNI and is
  discussed separately).
* An attacker who controls the sensor, the labels, or the training data (poisoning).
* Insider traffic that never leaves the network.
* Endpoint-level evasion (process injection into a browser so that the browser's own connections carry C2):
  then the connection *is* browser traffic and no network-only detector can separate it.

## What each feature family assumes

| Family | Assumption the attacker can break | Cost to break |
|---|---|---|
| TLS (ClientHello elements) | Malware uses a distinct TLS stack | Free: call the OS library, or uTLS |
| ENV (TCP/IP) | Malware traffic is recorded on a different path than benign | Not an attacker choice: it is a dataset artefact |
| BEH (connection behaviour) | C2 sessions look different from benign sessions | Moderate: traffic shaping, padding |
| SRV (certificate, JA4S) | C2 servers use cheap or self-signed certificates | Low: free CA certificates, CDN fronting |
| HR (host-relative, new) | The implant's connections stand out *against the same host's own traffic* (rare destination, periodic contact, deviating socket settings, unusual size pattern for its stack) | Must imitate the specific host's own benign mix: the attacker does not see it in advance and must keep doing it for every connection |

## Evaluation that follows from this model

* Natural mimicry (shared JA4 on the same host) is measured, not simulated.
* Feature-space forging of each family (copying benign values into malicious rows) bounds the adaptive attacker.
* Next step: real uTLS + jittered-beacon captures from open-source C2 frameworks in the isolated lab (crossed design).
