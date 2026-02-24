# M13 HANDOFF BRIEFING — OPERATION PHOENIX

> **Date**: 2026-02-24  
> **From**: Previous thread (context saturated)  
> **To**: Next thread  
> **Classification**: Sprint 2.5 execution directive

---

## SITUATION

M13 is a BVLOS drone swarm encrypted tunnel (Hub + Node) built in Rust. The tunnel works — PQC handshake completes, AEAD encrypts, packets flow. But throughput is **2-10% of wire speed** (4 Mbps through a 200 Mbps link). The tunnel **collapses** under 4K video (25+ Mbps).

**Root cause**: 17.26 MB of unmanaged FIFO buffering across the stack (8 MB socket buffers, 2.83 MB SPSC ring, 1.38 MB TUN queue, 4 MB per TCP flow). This defeats kernel BQL/TSQ/fq_codel backpressure. Inner TCP sees ~0ms apparent TUN RTT, floods the tunnel, buffers fill, RTT explodes from 50ms to 5,550ms, cwnd collapses. Observed: 12× sawtooth oscillation (1.6-20 Mbps).

WireGuard (same architecture, in-kernel) retains **90%** throughput. The single variable explaining the gap: M13's 8 MB `SO_SNDBUFFORCE` socket buffer bypasses BQL.

---

## MISSION: EXECUTE OPERATION PHOENIX

**Objective**: Execute Sprint 2.5 from `TODO.md` — annihilate the tunnel collapse.

### The Plan

The complete battle plan is in **[Operation_Phoenix.md](file:///home/m13/Desktop/m13_test/Operation_Phoenix.md)** (432 lines). It contains:

- **89 active defects** organized by enemy class (Syscall Storms, Bufferbloat, Cache Thrashing, Context Switching, Security, Correctness)
- **6-wave execution order** (Wave 0: dead code → Wave 1: P0 correctness → Wave 2: kill tunnel collapse → Wave 3: hot-path syscalls → Wave 4: cache thrashing → Wave 5: cold-path + hardening)
- **Per-defect severity, file:line, and fix mapping**

### The Sprint Definition

Sprint 2.5 is defined in **[TODO.md](file:///home/m13/Desktop/m13_test/TODO.md)** starting at line 380. It contains:

- **Preamble**: Full 4K video connection lifecycle trace (DNS → QUIC → collapse timeline) — lines 68-377
- **9 culprits** with exact file:line (the bufferbloat chain)
- **40 fixes** organized as Fix 0-8 (root cause → AQM → kernel tuning → throughput → protocol → micro → CC engine → satellite-aware → symmetric CC)
- **Cross-reference table**: Culprit → Fix mapping

---

## NORTHSTAR REFERENCES (Runtime Traces)

These two files trace **exactly what happens** when you run the Hub and Node commands:

| File | What It Traces |
|------|----------------|
| [cmd3_hub_runtime_trace.md](file:///home/m13/Desktop/m13_test/cmd3_hub_runtime_trace.md) | `sudo ./m13-hub enp1s0f0 --tunnel --single-queue 0` — Phase 0 (process birth) → Phase 1 (executive: BPF, AF_XDP, TUN, SPSC, PQC) → Phase 2 (worker boot) → Phase 3 (VPP main loop: all pipeline stages) |
| [cmd4_node_runtime_trace.md](file:///home/m13/Desktop/m13_test/cmd4_node_runtime_trace.md) | `sudo ./m13-node --hub-ip 67.213.122.151:443 --tunnel` — Phase 0 → Phase 1 (io_uring PBR, UDP socket, TUN arming) → Phase 2 (3-pass VPP: CQE drain → batch AEAD → RxAction dispatch) |

Both include: dependency chains, handshake sequence, thread topology diagrams.

**Use these to locate exact code sites** when implementing fixes. Every defect in Operation_Phoenix.md references file:line, and these traces show you the execution context around those lines.

---

## EXECUTION ORDER (condensed from Operation_Phoenix.md)

### Wave 0: Dead Code (zero risk, do first)
| # | What | Lines Killed |
|---|------|-------------|
| #122 | Delete `run_udp_worker()` in `node/main.rs` | 408 lines |
| #68 | Wire or delete `typestate.rs` in Hub | 254 lines |
| #114 | Remove `debug_assertions` Vec in `rx_parse_raw` | ~3 lines |

### Wave 1: P0 Correctness (prevent datapath halts)
| # | What | Why First |
|---|------|-----------|
| #109 | Hub: `enqueue_critical_edt` return value ignored → slab leak | Hub halts after ~8,192 dropped enqueues |
| #126 | Node: CQE overflow drops BIDs → PBR exhaustion | Node halts after burst of >128 CQEs |
| #89 | Hub: `pending_return[4096]` no bounds check | Stack buffer overflow |

### Wave 2: Kill Tunnel Collapse (95% of throughput recovery)
| Order | Item | What |
|-------|------|------|
| 2a | #48 | Consolidate contradictory sysctls |
| 2b | #43-#45, #41-#42, #49-#50 | Fix sysctl values |
| 2c | Fix #1 | `SO_SNDBUF` 8MB → 256KB (**THE root cause fix**) |
| 2d | Fix #2 | `SO_RCVBUF` 8MB → 256KB |
| 2e | Fix #3 | `txqueuelen` 1000 → 20 |
| 2f | Fix #5 | Hub SPSC depth 2048 → 256 |
| 2g | #46/Fix #6 | TUN qdisc `fq` → CAKE |
| 2h | #52/Fix #8 | Add `tcp_notsent_lowat=131072` |
| 2i | #47/Fix #7 | MSS clamp fix |
| 2j | #56 | Remove `tcp_slow_start_after_idle=0` |
| 2k | Fix #4 | Remove Node EDT pacer (confirmed no-op) |

### Waves 3-6: See Operation_Phoenix.md for hot-path syscalls, cache thrashing, cold-path hardening, CC engine.

---

## KEY FILE LOCATIONS

```
/home/m13/Desktop/m13_test/
├── hub/src/
│   ├── main.rs          (1,515 lines — VPP main loop, worker_entry, TX graph)
│   ├── engine/
│   │   ├── protocol.rs  (1,099 lines — PeerTable, Scheduler, JitterBuffer)
│   │   ├── runtime.rs   (723 lines — FixedSlab, TSC, Telemetry)
│   │   ├── typestate.rs  (254 lines — DEAD CODE, zero call sites)
│   │   └── spsc.rs      (150 lines — SPSC ring)
│   ├── network/
│   │   ├── datapath.rs   (1,037 lines — VPP pipeline, TUN, NAT)
│   │   ├── xdp.rs        (358 lines — AF_XDP engine)
│   │   ├── uring_reactor.rs (254 lines — io_uring WiFi reactor)
│   │   ├── uso_pacer.rs  (261 lines — EDT pacer)
│   │   ├── bpf.rs        (118 lines — BPF steersman)
│   │   └── mod.rs        (243 lines — PacketVector, GraphCtx)
│   └── cryptography/
│       ├── async_pqc.rs  (451 lines — PQC offload)
│       ├── handshake.rs  (182 lines — PQC Hub responder)
│       └── aead.rs       (115 lines — AES-256-GCM)
├── node/src/
│   ├── main.rs          (1,348 lines — 3-pass VPP, EDT, handshake)
│   ├── engine/
│   │   ├── protocol.rs  (450 lines — wire format, assembler)
│   │   └── runtime.rs   (291 lines — NodeState FSM, TSC)
│   ├── network/
│   │   ├── datapath.rs   (255 lines — TUN, VPN routing)
│   │   ├── uring_reactor.rs (230 lines — io_uring PBR)
│   │   └── uso_pacer.rs  (262 lines — EDT pacer)
│   └── cryptography/
│       ├── aead.rs       (377 lines — batch AEAD)
│       └── handshake.rs  (212 lines — PQC Node initiator)
├── Operation_Phoenix.md  (432 lines — the battle plan)
├── TODO.md              (1,183 lines — full roadmap + Sprint 2.5 details)
├── README.md            (32 lines — M13 system description)
├── cmd3_hub_runtime_trace.md  (Hub execution flow)
└── cmd4_node_runtime_trace.md (Node execution flow)
```

---

## CRITICAL CONSTRAINTS

1. **NO task slicing**. Execute the full wave before moving to the next.
2. **`cargo check` both binaries after each wave.** Zero regressions.
3. **Wave 2 is where 95% of throughput recovery lives.** Don't skip to CC engine before fixing the buffer stack.
4. **The EDT pacer is a confirmed no-op** at all actual throughput rates (gap < inter-arrival). Don't waste time tuning it until CC drives `set_link_bps()` dynamically.
5. **Test after Wave 2**: expect 100+ Mbps throughput, stable (no oscillation). If not achieved, the buffer stack still has unmanaged FIFOs.
6. **Do NOT use `iperf3`** for throughput auditing. Use the M13 telemetry counters (RX/TX/AEAD_OK in the 1-second console output).

---

## BUILD & TEST

```bash
# Build
cd /home/m13/Desktop/m13_test && cargo build --release

# Run Hub (WAN NIC = enp1s0f0, single AF_XDP queue 0, TUN tunnel)
sudo RUST_LOG=debug ./target/release/m13-hub enp1s0f0 --tunnel --single-queue 0

# Run Node (connect to Hub at 67.213.122.151:443, TUN tunnel)
sudo RUST_LOG=debug ./target/release/m13-node --hub-ip 67.213.122.151:443 --tunnel

# Monitor Hub telemetry (separate terminal)
sudo ./target/release/m13-hub --monitor
```

---

## FIRST ACTION FOR NEXT THREAD

1. Read `Operation_Phoenix.md` — the complete battle plan
2. Read `TODO.md` lines 380-800 — Sprint 2.5 definition with all 40 fixes
3. Execute **Wave 0** (dead code deletion) — zero risk, establishes clean baseline
4. Execute **Wave 1** (P0 correctness) — prevent datapath halts
5. Execute **Wave 2** (kill tunnel collapse) — the main event
