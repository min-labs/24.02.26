# M13 Round Observations

> **Overview.**
> This document records frame-level telemetry from each round's live deployment,
> side by side. Conclusions about system progress, regressions, and readiness
> are drawn from the data recorded here. Read in tandem Roadmap as per illustrated in `TODO.md`.
>
> **Contributing:**
> 1. Every round adds a row to Raw Data, Normalized Comparison, and Tests.
> 2. Provide frame counts, rates, and deltas — not prose.
> 3. New failure vectors go in the KFV table after resolution.

---

## Raw Data

| Round | Date | Elapsed | Hub RX | Hub TX | Node RX | Node TX | AEAD OK (H) | AEAD OK (N) | AEAD FAIL | HS | Slab |
|-------|------|---------|--------|--------|---------|---------|-------------|-------------|-----------|------|------|
| **1** | 2026-02-16 | 482s | 22,527 | 44,200 | 41,445 | 22,574 | 22,449 | 41,359 | **0** | 1/0 | 1538 |
| **2** | 2026-02-17 | 2386s | 158,172 | 752,105 | 689,417 | 158,172 | 158,157 | 689,407 | **2** | 2/0 | 1539 |

## Normalized Comparison (/s)

| Metric | Round 1 | Round 2 | Δ | Notes |
|--------|---------|---------|---|-------|
| **Hub RX/s** | 46.7 | 66.3 | ↑ 42% | Upstream ingress |
| **Hub TX/s** | 91.7 | 315.2 | ↑ 244% | Downstream egress |
| **Node RX/s** | 86.0 | 288.9 | ↑ 236% | Downstream ingress |
| **Node TX/s** | 46.8 | 66.3 | ↑ 42% | Upstream egress |
| **AEAD/s (Hub)** | 46.6 | 66.3 | ↑ 42% | Decrypt rate |
| **AEAD/s (Node)** | 85.8 | 288.9 | ↑ 237% | Decrypt rate |
| **AEAD FAIL/s** | 0 | 0.0008 | — | 2 failures in 2386s (HS window) |
| **TX:RX ratio** | 1.97:1 | 4.75:1 | ↑ | Higher downstream asymmetry |
| **Upstream loss %** | 0.21% | 0.009% | ↓ 23× | Near-zero |
| **Downstream loss %** | 6.23% | 8.34% | ↑ | WAN-dependent |
| **Internal loss** | 0 | 0 | — | — |
| **Slab** | 1538 | 1539 | — | No leak |
| **Reconnects** | 0 | 1 | ↑ | HS re-established once |

## Tests

| Round | Hub Unit | Hub Integration | Node Unit | Total | Pass Rate |
|-------|----------|-----------------|-----------|-------|-----------|
| **1** | 35 | 30 | 19 | 84 | 100% |
| **2** | 70 | 30 | 29 | 129 | 100% |

---

## Known Failure Vectors (KFV)

> Check here before investigating — the same class of problem may have been solved before.

| ID | Symptom | Root Cause | Fix | Round |
|----|---------|------------|-----|-------|
| KFV-01 | AF_XDP socket creation fails with `EINVAL` | NIC has multiple RX queues; AF_XDP bound to queue 0 but traffic steered elsewhere by RSS | `ethtool -L <iface> combined 1` — force single queue | Pre-Round 1 |
| KFV-02 | Hub TX counter = 0 despite established tunnel | `tun_write_vector` pushes to SPSC ring but `tun_housekeeping_thread` not performing actual VFS `write()` to TUN fd | TUN HK thread scaffolded — deferred to future round for UMEM base pointer sharing | Round 1 |
| KFV-03 | Node `recvmmsg` returns 0 intermittently | Legacy VFS event loop — `recvmmsg` has no backpressure, stalls on empty socket | Replaced with `io_uring` multishot recv (CQE-driven, never polls empty) | Round 1 |
| KFV-04 | Hub upstream packets silently dropped by switch | `gateway_mac` uninitialized → `00:00:00:00:00:00`. IEEE 802.3 switch discards frames addressed to null MAC as invalid unicast | Initialize `gateway_mac` from ARP/NDP or first-hop discovery before TX path | Pre-Round 1 |
| KFV-05 | Packets purged pre-transmission despite valid framing | IPv4/UDP checksum fields set to `0x0000`, relying on NIC hardware offload. AF_XDP raw mode disables offload — upstream validators interpret zero checksum as corruption | Compute IPv4 header checksum and UDP checksum in software before AF_XDP TX | Pre-Round 1 |
| KFV-06 | Return traffic impossible on WAN despite valid L2/L3 | Encapsulated payload retains source IP `10.13.13.2` (RFC 1918). Public internet has no route for `10.0.0.0/8` — return path physically impossible without NAT | Ensure outer UDP/IP header uses public source IP; TUN payload addressing is irrelevant to WAN routing | Pre-Round 1 |

---

## Metric Legend

| Metric | How Measured |
|--------|-------------|
| **TX / RX** | `TX:` / `RX:` counter at shutdown (per-side) |
| **TUN_R / TUN_W** | Frames read from / written to TUN or SPSC ring |
| **AEAD OK / FAIL** | `AEAD:OK/FAIL` or `AEAD_OK:` at shutdown |
| **Upstream Loss** | `Node.TX − Hub.RX` |
| **Downstream Loss** | `Hub.TX − Node.RX` |
| **Internal Loss** | `AEAD_FAIL + (TUN_R − TX)` |
| **HS OK / FAIL** | `HS:ok/fail` — handshake outcomes |
| **Slab** | `Slab:free/8192` at shutdown |
| **Reconnections** | `HS_OK − 1` |
| **Elapsed** | `Up:Xs` telemetry counter |
