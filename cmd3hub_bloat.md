# Cmd #3 Hub Bloat Audit

Phase-by-phase audit of unnecessary/bloated code in `hub/src/main.rs` and `hub/src/engine/runtime.rs`.

## Phase 1: `main()` L43-127 (85 lines)

| # | Lines | What | Wasted | Category |
|---|-------|------|--------|----------|
| 1 | L74 | `--monitor` duplicate check | 1 line | Dead code — already handled at L60 |
| 2 | L109-126 | `set_var("M13_HEXDUMP")` + `set_var("M13_LISTEN_PORT")` | 18 lines | Architectural bloat — 14 lines of convoluted 3-way logic to set 1 env var. Should be `let port = listen_port.unwrap_or(443);` passed as function arg. |

**Phase 1 bloat: ~19 lines / 85 total (22%)**

## Phase 2: `run_executive()` L132-287 (156 lines)

| # | Lines | What | Wasted | Category |
|---|-------|------|--------|----------|
| 3 | L135-138 | `libc::signal` re-registration | 4 lines | Dead code — already registered at L47-50 in `main()`. Signal dispositions are process-wide, inherited by all threads. These 4 lines are provably no-op. |
| 4 | L142-154 | `pgrep` subprocess for kill | ~7 lines | Over-engineering — `libc::kill()` via `/proc` scan = 5 lines, zero forks. |
| 5 | L159-173 | Verbose `ethtool` error handling | ~10 lines | Over-engineered 3-arm match — 5 lines suffice. |
| 6 | L256 | `wifi_iface.clone()` per worker | 1 line | Unnecessary heap alloc — only worker 0 uses WiFi. Should be `.take()` like SPSC handles. |

**Phase 2 bloat: ~22 lines / 156 total (14%)**

## Summary

```
Total Phase 1+2:  241 lines
Bloat:            ~38 lines (16%)
Dead code:          5 lines (L74 duplicate --monitor, L135-138 duplicate signal)
Architectural:     18 lines (env var abuse instead of function args)
Over-engineering:  ~15 lines (verbose error handling, subprocess spawning)
```

### Cross-Reference to TODO.md Fix 9

| Bloat # | TODO.md Defect # |
|---------|-----------------|
| 1 | #69 (duplicate `--monitor`) |
| 2 | #70 (env var abuse) |
| 3 | #74 (duplicate signal registration) |
| 4 | #71 (subprocess storm) |
| 5 | #71 (same subprocess storm) |
| 6 | #84 (wifi_iface.clone) |

### Notes

- None of these are features that should be removed entirely
- They are all necessary functions implemented with unnecessary verbosity or architectural mistakes
- The signal re-registration (L135-138) is the only code that is truly dead (provably no-op)
- No bloat affects the hot path — all cold-start only

## Phase 3: `run_executive()` — BPF + TUN + SPSC Setup (main.rs L200-220 + called functions)

### Source files in scope

| File | Lines | Function |
|------|-------|----------|
| `hub/network/bpf.rs` | L1-118 | `BpfSteersman::load_and_attach()` |
| `hub/network/datapath.rs` | L823-871 | `create_tun()` |
| `hub/network/datapath.rs` | L881-888 | `apply_sysctl()` |
| `hub/network/datapath.rs` | L890-932 | `setup_nat()` |
| `hub/engine/spsc.rs` | L1-150 | `make_spsc()` |
| `hub/main.rs` | L219-220 | `OnceLock` |

### Enemy Violations

| # | Enemy | File:Line | Defect | TODO# |
|---|-------|-----------|--------|-------|
| 7 | **Syscall Storm** | `datapath.rs:861-868` | `create_tun()` spawns 4× `ip` child processes = 12 syscalls. Replace with `ioctl()`. | #76 |
| 8 | **Syscall Storm** | `datapath.rs:890-932` | `setup_nat()` spawns **20 child processes** (14× sysctl, 1× tc, 5× iptables) = 60 fork syscalls + 42 VFS verification syscalls = **102 total syscalls**. WORST in codebase. | #77 |
| 9 | **Bufferbloat** | `datapath.rs:868` | `txqueuelen=1000` = 55ms kernel buffering at 200 Mbps. | #78 |
| 10 | **Bufferbloat** | `datapath.rs:899-908` | Hub-side `rmem_max=16MB`, `tcp_rmem max=16MB`, `netdev_max_backlog=10000` — same defects as Node #43-#48. | #80 |
| 11 | **(Security)** | `bpf.rs:45-48` | `RLIM_INFINITY` fallback removes all kernel memory lock limits. | #79 |

### Clean Components

| File | Lines | Why Clean |
|------|-------|-----------|
| `spsc.rs` | L1-150 | 128-byte `CachePadded` alignment prevents false sharing. DPDK-style local head/tail caching minimizes cross-core Acquire loads. Wait-free, zero-allocation. Architecture is textbook correct. |
| `bpf.rs` (except #79) | L1-118 | BPF load is kernel-mediated, unavoidable syscall cost. `include_bytes!()` avoids runtime file I/O. `Drop` impl cleanly detaches XDP. |
| `main.rs:219-220` | 2 lines | `OnceLock` is zero-cost after first set. No contention. |

### Bloat Analysis

| # | Lines | What | Wasted | Category |
|---|-------|------|--------|----------|
| 7 | `datapath.rs:861-868` | 4× `Command::new("ip")` in `create_tun()` | 4 lines | Subprocess abuse — `ioctl()` = 4 lines, zero forks |
| 8 | `datapath.rs:881-932` | `apply_sysctl()` + `setup_nat()` | ~42 lines | **52 lines** for 14 sysctl writes + verify + iptables. Direct `fs::write()` + netlink = ~20 lines. |
| 9 | `bpf.rs:36-49` | RLIMIT_MEMLOCK double-try | 13 lines | Over-engineered fallback. Fail hard on first rejection = 3 lines. |

**Phase 3 bloat: ~59 lines out of ~170 total (35%)**

## Phase 4: Thread Spawn (main.rs L222-287 — 66 lines)

### Enemy Violations

| # | Enemy | File:Line | Defect | TODO# |
|---|-------|-----------|--------|-------|
| 12 | **Cache Thrashing + Context Switching** | `main.rs:223,253` | TUN HK core (`isolated_cores.last()`) collides with last VPP worker in multi-queue mode. Two threads fighting on same L1d (32KB A53). **~11ms/sec stall.** | #81 |
| 13 | (Memory waste) | `main.rs:267` | 32MB stack per VPP worker. Actual usage ~64KB. 500× overprovisioned. 4 workers = 128MB virtual. | #82 |
| 14 | Syscall Storm | `main.rs:258` | `tun_ref.try_clone()` for every worker. Workers 1-3 waste `dup()+close()` syscall pairs. Silent failure via `.ok()`. | #83 |
| 15 | (Heap waste) | `main.rs:256` | `wifi_iface.clone()` allocates heap per worker. Only worker 0 uses it. | #84 |

### Bloat Analysis

| # | Lines | What | Wasted | Category |
|---|-------|------|--------|----------|
| 10 | `main.rs:258` | `try_clone()` in loop | 1 line | Should be outside loop, worker 0 only |
| 11 | `main.rs:256` | `wifi_iface.clone()` in loop | 1 line | Should use `.take()` pattern like SPSC |
| 12 | `main.rs:267` | `stack_size(32MB)` | 0 lines | Not bloat — one number change. But critical memory impact. |

**Phase 4 bloat: ~2 lines (trivial)** — but the core collision (#81) is a **critical hot-path enemy**.

## Thread 1: TUN Housekeeping (main.rs L714-867 — 154 lines, **HOT PATH**)

> **First hot-path thread traced. Every defect here hits the live datapath.**

### Enemy Violations

| # | Enemy | File:Line | Defect | TODO# |
|---|-------|-----------|--------|-------|
| 16 | Context Switching | `main.rs:727-736` | spin-wait `yield_now()` for UMEM base = ~1,000-5,000 `sched_yield()` syscalls at startup | #85 |
| 17 | **Syscall Storm (HOT)** | `main.rs:781` | per-packet `libc::write(tun_fd)` = **2,260 write() syscalls/sec** at 200 Mbps | #86 |
| 18 | **Syscall Storm** | `main.rs:795` | `poll(tun_fd, 1, 1ms)` = **1,000 poll() syscalls/sec minimum** even when idle | #87 |
| 19 | **Syscall Storm (HOT)** | `main.rs:808-810` | per-packet `libc::read(tun_fd)` = **2,260 read() syscalls/sec** at 200 Mbps | #88 |
| 20 | **(Correctness)** | `main.rs:813-818` | `pending_return[4096]` stack overflow — no bounds check. 22 failed drain iterations → UB | #89 |
| 21 | Context Switching | `main.rs:855` | `yield_now()` on idle = unnecessary `sched_yield()` when poll already backoffs | #90 |
| 22 | **Cache Thrashing** | `main.rs:848` | `push_batch(&[desc])` = degenerate batch of 1. **2,260 cross-core cache transfers/sec** instead of ~35 | #91 |
| 23 | **Cache Thrashing (HOT)** | `main.rs:765-776` | No `prefetch_read_l1()` before UMEM frame read. L1d miss → L2/DRAM stall per-packet | #92 |

### Syscall Budget (Thread 1 at 200 Mbps bidirectional)

```
write()  syscalls: 2,260/sec  (per-packet TUN write, downlink)
read()   syscalls: 2,260/sec  (per-packet TUN read, uplink)
poll()   syscalls: 1,000/sec  (1ms timeout, even when idle)
yield()  syscalls:   ~1,000/sec (idle path, redundant with poll)
─────────────────────────────────────────────────────────────
Total:              ~5,520 syscalls/sec  (Thread 1 alone)
```

**Compare: io_uring equivalent = ~35 submit()/sec** (batch 64, amortized).

### Bloat Analysis

Thread 1 has minimal code bloat — the 154 lines are dense and purposeful. The enemies are **architectural** (VFS syscalls instead of io_uring), not verbosity.

## Thread 2: VPP Worker (main.rs L870-1515 — 646 lines, **MAIN HOT PATH**)

> **This is the AF_XDP datapath core. The most performance-critical code in the system.**

### Enemy Violations

| # | Enemy | File:Line | Defect | TODO# |
|---|-------|-----------|--------|-------|
| 24 | ~~Context Switching + Cache Thrashing~~ | `main.rs:992-1003` | **RETRACTED**: PQC worker DOES call `pin_to_core(0)` at `async_pqc.rs:181`. Correctly pinned to core 0 (housekeeping). | #93 ~~retracted~~ |
| 25 | **Syscall Storm (isolated core)** | `datapath.rs:776` | `resolve_gateway_mac()` spawns `ping` subprocess **from the VPP worker thread on isolated core**. fork() on datapath core! | #94 |
| 26 | **Cache Pressure (HOT)** | `main.rs:1057-1087,1206-1236` | `GraphCtx` 30-field struct constructed **TWICE** per loop iteration = 480 bytes/iter × 18K iter/sec = 8.6MB/sec stack writes | #95 |
| 27 | **Atomic Contention** | `main.rs:1250-1262` | 13× `fetch_add(Relaxed)` per RX batch = **234K atomics/sec**. 1,664 bytes of SHM cache pollution per batch. | #96 |
| 28 | **Cache Thrashing (HOT)** | `main.rs:1296-1366` | Keepalive scan iterates ALL `MAX_PEERS` slots **every RX batch**. Touches cold PeerSlot memory for N-1 empty slots. | #97 |
| 29 | Context Switching | `main.rs:906,915` | `env::var()` global libc mutex on isolated core during init. | #98 |
| 30 | Cache Thrashing (cold) | `main.rs:941-955` | SLAB init loop touches 32MB UMEM sequentially. Evicts L1d/L2 ~125×. First real packet guaranteed L1d miss. | #99 |
| 31 | (Micro) | `main.rs:1063,1212` | `tun.as_raw_fd()` closure rebuilt twice per loop. Trivial cost but architecturally wasteful. | #100 |

### What Thread 2 Does RIGHT

- **Adaptive batch drain** (L1137-1171): Busy-waits within 50µs deadline to fill GRAPH_BATCH. Correct.
- **UMEM prefetch** (L1186-1202): `prefetch_read_l1()` on first `PREFETCH_DIST=4` frames before graph entry. Correct.
- **AF_XDP zero-copy**: `poll_rx_batch`/`stage_tx_addr`/`kick_tx` = kernel-bypassed I/O. Correct.
- **Single-producer SPSC**: TUN SPSC only on worker 0, `.take()` pattern for others. Correct.
- **GC throttle** (L1498-1502): `gc_counter % 10000` avoids per-batch peer/assembler GC. Correct.

## Thread 3: PQC Worker (async_pqc.rs L173-283 — 111 lines, **CONTROL PLANE**)

> **Cryptographic control plane. Infrequent but high-impact per invocation.**

### Enemy Violations

| # | Enemy | File:Line | Defect | TODO# |
|---|-------|-----------|--------|-------|
| 32 | **Syscall Storm** | `async_pqc.rs:189` | `yield_now()` tight spin with **no backoff**. >100K `sched_yield()/sec` when idle. Thread 1 has `poll(1ms)` gating; Thread 3 has **nothing.** | #101 |
| 33 | **Cache Thrashing** | `async_pqc.rs:278` | `PqcResp` = 9,280 bytes. Each `push_batch` copies 9.2KB = **145 cache lines** = 28% of L1d. | #102 |
| 34 | (Micro) | `async_pqc.rs:278` | Degenerate `push_batch(&[resp])` × 4 = 4× Release barriers where 1 suffices. | #103 |
| 35 | Cache Thrashing | `async_pqc.rs:228` | `FlatHubHandshakeState` = 2,720B struct copy = 42 cache lines per ClientHello. | #104 |
| 36 | (Heap alloc) | `async_pqc.rs:213` | `process_client_hello_hub()` returns `Vec<u8>` = ~13KB heap alloc per handshake. | #105 |

### What Thread 3 Does RIGHT

- **Arena-indexed PqcReq** (32 bytes): Slim SPSC envelope, payload in shared arena. Correct.
- **Pre-computed transcript2**: `SHA-512(CH || SH)` at ClientHello time avoids 13KB rehash at Finished. Correct.
- **Flat state arena**: `FlatHubHandshakeState` is `Copy` — no heap. Core 0-local, no cross-core contention.
- **Dedicated core**: `pin_to_core(0)` isolates PQC compute from datapath.

### Thread 3 Idle Syscall Budget

```
yield_now():  >100,000/sec  (UNBOUNDED — no backoff)

Compare Thread 1: ~1,000/sec (gated by poll 1ms)
Compare Thread 2: 0/sec (pure busy-poll, no syscalls)
```

## VPP Main Loop (~1,200 LOC across 5 files, **INNERMOST HOT PATH**)

> **The packet processing pipeline. Every nanosecond here is multiplied by millions of packets.**

### BUFFERBLOAT Chain (Critical — 4 interlocking defects)

```
   EdtPacer hardcoded 100 Mbps (#107)
        │  creates 10× over-pacing at 1 Gbps
        ▼
   release_ns = now + 120µs per 1500B packet
        │  scheduler holds packets longer than needed
        ▼
   TX_RING_SIZE = 256, no AQM (#106)
        │  standing queue fills in 30.7ms of continuous TX
        ▼
   enqueue returns false → return value IGNORED (#109)
        │  slab frame leaked permanently
        ▼
   SLAB exhaustion after ~8,192 drops → DATAPATH HALT
```

**Plus:** EdtPacer.last_tx_ns never reset (#108) → burst-compensating backlog after idle.
**Plus:** TUN txqueuelen=1000 + wmem_max=16MB (#117/79/78) → 689ms kernel standing queue.

### Enemy Violations

| # | Enemy | File:Line | Defect | TODO# |
|---|-------|-----------|--------|-------|
| 37 | **BUFFERBLOAT (CRITICAL)** | `protocol.rs:759` | `TX_RING_SIZE=256`, silent tail-drop, no telemetry, no AQM | #106 |
| 38 | **BUFFERBLOAT (CRITICAL)** | `main.rs:1008` | EdtPacer hardcoded 100Mbps, 10× over-pacing at 1Gbps | #107 |
| 39 | **BUFFERBLOAT** | `uso_pacer.rs:96` | `last_tx_ns` never reset → standing queue after idle pause | #108 |
| 40 | **BUFFERBLOAT + SLAB LEAK** | `datapath.rs:450` | `enqueue` return value ignored → permanent slab frame leak | #109 |
| 41 | **Cache Thrashing (HOT)** | `main.rs:378-420` | 12× `PacketVector::new()` = 37KB stack zeroing per subvector | #110 |
| 42 | **Cache Thrashing (HOT)** | `main.rs:619-624` | MAX_PEERS scan per TX iteration, up to 72K scans/sec | #111 |
| 43 | Cache Thrashing | `main.rs:676` | memmove 42B per TX packet = 3.2 MB/sec UMEM writes | #112 |
| 44 | (Micro) | `main.rs:1466` | scheduler.dequeue() per-element, no batch | #113 |
| 45 | (Debug only) | `datapath.rs:42` | Vec heap alloc in rx_parse_raw under debug_assertions | #114 |
| 46 | **BUFFERBLOAT signal** | `protocol.rs:619` | FEEDBACK_RTT=10ms hardcoded, never measured | #115 |
| 47 | (Micro) | `main.rs:345-366` | CycleStats no AddAssign, 15 manual field adds | #116 |
| 48 | **BUFFERBLOAT (systemic)** | `datapath.rs:890-932` | rmem/wmem_max=16MB + txqueuelen=1000 = 689ms queue | #117 |

### What the VPP Loop Does RIGHT

- **Adaptive batch drain** with 50µs deadline (L1137-1171) ✅
- **UMEM prefetch** before graph entry (L1186-1202) ✅
- **4-at-a-time vectorized processing** with prefetch lookahead in decrypt/encrypt/classify/scatter ✅
- **Zero-copy AF_XDP** + io_uring multiplexing ✅
- **EDT zero-spin**: pacer returns timestamp, scheduler gates — no spin-wait ✅
- **SPSC TUN decoupling**: tun_write_vector pushes to SPSC, not VFS ✅
- **PQC offload**: handshake data → arena → SPSC → Core 0. Zero crypto on datapath ✅

## Cumulative Summary

```
Phase 1:    ~19 lines / 85   (22%) —  2 enemies (#69-#70)
Phase 2:    ~22 lines / 156  (14%) —  5 enemies (#71-#75)
Phase 3:    ~59 lines / 170  (35%) —  5 enemies (#76-#80)
Phase 4:     ~2 lines / 66   ( 3%) —  4 enemies (#81-#84)
Thread 1:    ~0 lines / 154  ( 0%) —  8 enemies (#85-#92)
Thread 2:    ~0 lines / 646  ( 0%) —  7 enemies (#94-#100)  [#93 retracted]
Thread 3:    ~0 lines / 111  ( 0%) —  5 enemies (#101-#105)
VPP Loop:    ~0 lines / 1200 ( 0%) — 12 enemies (#106-#117)
──────────────────────────────────────────────────────────
Total:     ~102 lines / 2588 ( 4%) — 48 enemies (#69-#117, 1 retracted = 47 active)
```

### Enemy Category Breakdown

| Enemy | Count | Most Critical |
|-------|-------|--------------|
| **Bufferbloat** | **8** | #106 (TX_RING silent drop), #107 (100Mbps EdtPacer), #109 (slab leak) |
| **Syscall Storm** | 10 | #86/#88 (per-packet TUN read/write), #101 (>100K yield/sec) |
| **Cache Thrashing** | 14 | #110 (37KB stack zeroing/subvec), #111 (72K MAX_PEERS scans/sec) |
| **Context Switching** | 6 | #94 (fork on isolated core), #98 (env::var mutex) |
| **Other/Micro** | 9 | #109 (slab leak), #116 (code hygiene) |

## Dead Code / Underscore / Commented-Out Audit

### `#[allow(dead_code)]` — 4 instances

| # | File:Line | What | Verdict |
|---|-----------|------|---------|
| 1 | `xdp.rs:28` | `mod bindings` (bindgen FFI) | ✅ Standard practice for auto-generated bindings |
| 2 | `xdp.rs:88` | `_umem_handle: *mut xsk_umem` | ✅ Ownership anchor — holds UMEM lifetime. Correct `_` prefix. |
| 3 | `xdp.rs:89` | `sock_handle: *mut xsk_socket` | ⚠️ Same ownership pattern but **missing `_` prefix** (inconsistent with L88). Never read after construction. |
| 4 | `spsc.rs:20` | `pub struct SpscRing<T>` | ⚠️ Used indirectly via `Arc<SpscRing>` in `Producer`/`Consumer`. rustc flags it dead because the struct name is never referenced directly. Should use `pub(crate)` instead of `allow(dead_code)`. |

### Underscore-prefixed variables — 3 runtime instances

| # | File:Line | What | Verdict |
|---|-----------|------|---------|
| 1 | `main.rs:921` | `let (mut gateway_mac, _gw_ip) = resolve_gateway_mac(...)` | ⚠️ **Discarded data** — gateway IP resolved then thrown away. Potentially useful for direct-IP peer detection. |
| 2 | `main.rs:1403` | `\|frame_data, flen, _seq\|` (PQC ServerHello framing closure) | ✅ Correct — seq unused in closure |
| 3 | `main.rs:1422` | `\|frame_data, flen, _seq\|` (L2 variant) | ✅ Correct — same pattern |

### Commented-out code — **ZERO**

No commented-out executable statements found in any file along the Cmd #3 path.
