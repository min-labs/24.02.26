# M13 Sprint 2.5 — Enemy Annihilation Plan

> **Git Baseline**: https://github.com/min-labs/24.02.26 — pushed pre-Phoenix. Use this as the clean starting point.

> All defects from TODO.md Fix 9/10/11 (#41–#130), reorganized by enemy class.
> Includes Cmd #3 Hub Bloat Audit and Cmd #4 Node Bloat Audit findings.
> #93 retracted. **89 active defects.**

---

## 1. SYSCALL STORMS (21 defects)

> fork+exec+wait subprocess abuse, blocking send() bypassing io_uring, per-packet VFS read/write.

### Hub — Cold Path (6)

| # | Severity | File:Line | Defect |
|---|----------|-----------|--------|
| **69** | P1 | `hub/datapath.rs:934-949` | `nuke_cleanup_hub()` spawns 9 child processes in panic hook (27 syscalls) |
| **71** | P1 | `hub/main.rs:143-157` | `run_executive()` pre-flight spawns 4 child processes (pgrep, ip link, ethtool) |
| **72** | P2 | `hub/engine/runtime.rs:417-422` | `fence_interrupts()` spawns `pgrep irqbalance` + iterates ~200 IRQ files (~600 VFS syscalls) |
| **76** | P1 | `hub/datapath.rs:861-868` | `create_tun()` spawns 4× `ip` child processes |
| **77** | **P0** | `hub/datapath.rs:890-932` | `setup_nat()` spawns **20 child processes** — WORST IN HUB (60 syscalls, 102 VFS total) |
| **94** | P1 | `hub/datapath.rs:776-778` | `resolve_gateway_mac()` spawns `ping` subprocess **from isolated VPP core** |

### Hub — Hot Path (3)

| # | Severity | File:Line | Defect |
|---|----------|-----------|--------|
| **86** | **P0** | `hub/main.rs:781` | Per-packet `libc::write()` to TUN — 2,260 syscalls/sec |
| **87** | P1 | `hub/main.rs:795` | `poll(tun_fd, 1, 1ms)` — 1,000 syscalls/sec when idle |
| **88** | **P0** | `hub/main.rs:808-810` | Per-packet `libc::read()` from TUN — 2,260 syscalls/sec |

### Node — Cold Path (4)

| # | Severity | File:Line | Defect |
|---|----------|-----------|--------|
| **118** | P1 | `node/datapath.rs:63-72` | `create_tun()` spawns 4× `ip` child processes (=Hub #76) |
| **120** | P1 | `node/main.rs:278-332` | `tune_system_buffers()` spawns 14+ child processes (8.4ms overhead) |
| **121** | **P0** | `node/datapath.rs:92-187` | `setup_tunnel_routes()` spawns **27 child processes** — WORST IN NODE (16.2ms) |
| **128** | P2 | `node/main.rs:1169` | `reactor.submit()` called per TUN write instead of batched (128 SQ syncs) |

### Node — Hot Path (3)

| # | Severity | File:Line | Defect |
|---|----------|-----------|--------|
| **53** | P1 | `node/main.rs:1183` | Echo frames use blocking `sock.send()` bypassing io_uring |
| **54** | P1 | `node/main.rs:1273` | Keepalive frames use blocking `sock.send()` bypassing io_uring |
| **55** | P1 | `node/main.rs:1257` | Handshake retransmit calls `sock.send()` per fragment (3-7 blocking sends) |

### Shared

| # | Severity | File:Line | Defect |
|---|----------|-----------|--------|
| **101** | P1 | `hub/async_pqc.rs:189` | PQC worker `yield_now()` tight spin — >100,000 sched_yield()/sec when idle |
| **60** | P3 | `node/uring_reactor.rs:91` | SQPOLL idle timeout = 2000ms (kernel thread wakeup jitter) |
| **63** | P2 | `node/uring_reactor.rs:161-200` | SQ ring overflow spins in `while push.is_err() { submit(); }` — infinite busy-wait |
| **58** | P2 | `node/uring_reactor.rs:90-96` | No `IORING_SETUP_DEFER_TASKRUN` — task_work on every syscall |
| **62** | P2 | `node/main.rs:1076-1077` | `commit_pbr()` called per-BID recycle — 2,260 atomic stores/sec |

---

## 2. INTERRUPT STORMS (0 defects)

> No interrupt storm defects identified in the current codebase. io_uring SQPOLL and AF_XDP
> inherently avoid interrupt-driven I/O. NAPI coalescing configured via `netdev_budget`.

---

## 3. BUFFERBLOAT (23 defects)

> Socket buffer abuse, TUN queue oversizing, sysctl contradictions, absent AQM, pacing misconfiguration.

### Root Cause Chain (Sprint 2.5 Tunnel Collapse)

| # | Severity | File:Line | Defect |
|---|----------|-----------|--------|
| **123** | **P0** | `node/main.rs:891-897` | **SO_SNDBUFFORCE = 8MB** — THE root cause. 8MB unmanaged FIFO → 320ms fill → cwnd collapse → 98% loss |

### Socket Buffer Oversizing

| # | Severity | File:Line | Defect |
|---|----------|-----------|--------|
| **41** | P0 | `node/main.rs:317` | `rmem_default=4MB`, `wmem_default=4MB` — every TCP socket gets 4MB |
| **42** | P0 | `node/main.rs:326` | `netdev_max_backlog=10000` = 550ms kernel ingress buffering |
| **43** | P0 | `node/datapath.rs:154-156` | `rmem_max=16MB`, `wmem_max=16MB` — overwrites 8MB with WORSE 16MB |
| **44** | P0 | `node/datapath.rs:158-160` | `tcp_rmem max=16MB` — 640ms per TCP flow at 200 Mbps |
| **45** | P0 | `node/datapath.rs:159-160` | `tcp_wmem max=16MB` — same for write |
| **49** | P1 | `node/main.rs:316` | `rmem_max=8MB` ceiling enables Culprit #2 |
| **50** | P1 | `node/main.rs:316` | `wmem_max=8MB` ceiling enables Culprit #1 |
| **80** | P1 | `hub/datapath.rs:899-908` | Hub-side `setup_nat()` sets identical bufferbloat sysctls |
| **117** | P1 | `hub/datapath.rs:890-932` | Hub rmem/wmem=16MB + txqueuelen=1000 = 689ms standing queue |

### TUN Queue Oversizing

| # | Severity | File:Line | Defect |
|---|----------|-----------|--------|
| **78** | P0 | `hub/datapath.rs:868` | Hub `txqueuelen=1000` = 55ms kernel buffering |
| **119** | P0 | `node/datapath.rs:72` | Node `txqueuelen=1000` = 55ms kernel buffering (=Hub #78) |

### Missing AQM

| # | Severity | File:Line | Defect |
|---|----------|-----------|--------|
| **46** | **P0** | `node/datapath.rs:183` | TUN qdisc = `fq` — NO bandwidth shaping, NO AQM, NO sojourn drops |

### EDT Pacing Defects

| # | Severity | File:Line | Defect |
|---|----------|-----------|--------|
| **106** | **P0** | `hub/protocol.rs:759` | `TX_RING_SIZE=256` scheduler + silent tail-drop + no telemetry |
| **107** | **P0** | `hub/main.rs:1008` | EdtPacer hardcoded 100Mbps — 10× over-pacing at 1Gbps |
| **108** | P1 | `hub/uso_pacer.rs:96` | Hub `EdtPacer.last_tx_ns` never reset on idle → standing queue |
| **109** | **P0** | `hub/datapath.rs:450` | `enqueue_critical_edt` return value **ignored** → slab frame leak → datapath halt |
| **115** | P2 | `hub/protocol.rs:619` | `FEEDBACK_RTT_DEFAULT_NS=10ms` hardcoded, never measured |
| **130** | P1 | `node/main.rs:1060-1071` | DeferredTxRing overflow force-drains without EDT pacing |

### Config Contradictions

| # | Severity | File:Line | Defect |
|---|----------|-----------|--------|
| **48** | P1 | `node/main.rs:286-340` + `node/datapath.rs:152-168` | Two functions set same sysctls with different values — second overwrites first |
| **51** | P3 | `node/datapath.rs:166` | `netdev_budget=600` duplicated — dead code |
| **52** | P1 | `node/main.rs` + `node/datapath.rs` | Missing `tcp_notsent_lowat=131072` — apps dump unlimited data |
| **56** | P2 | `node/datapath.rs:162` | `tcp_slow_start_after_idle=0` causes WORSE bursts after idle |

---

## 4. CONTEXT SWITCHING (7 defects)

> Voluntary yields, core collisions, mutex contention on isolated cores.

| # | Severity | File:Line | Defect |
|---|----------|-----------|--------|
| **73** | P2 | `hub/runtime.rs:176-265` | `calibrate_tsc()` blocks 100ms + 1000 validation iterations (cold-start) |
| **81** | **P0** | `hub/main.rs:223,253` | TUN HK core collides with last VPP worker — two threads on one core |
| **85** | P1 | `hub/main.rs:727-736` | Spin-wait `yield_now()` for UMEM base (~1,000-5,000 context switches) |
| **90** | P3 | `hub/main.rs:855` | `yield_now()` on idle path — sched_yield when should sleep |
| **98** | P1 | `hub/main.rs:906,915` | `env::var()` global libc mutex on isolated VPP core |
| **70** | P2 | `hub/main.rs:110-124` | `set_var()` global libc mutex abuse (3× env writes) |
| **75** | P3 | `hub/runtime.rs:289` | `env::var()` called 3× across Phase 2 for same variable |

---

## 5. CACHE THRASHING (17 defects)

> Stack zeroing, sequential DRAM scans, missing prefetch, per-element SPSC pushes, atomic store storms.

### Hub — Hot Path (9)

| # | Severity | File:Line | Defect |
|---|----------|-----------|--------|
| **110** | **P0** | `hub/main.rs:378-420` | 12× `PacketVector::new()` = **37KB stack zeroing per subvector** (665 MB/sec) |
| **111** | **P0** | `hub/main.rs:619-624` | `MAX_PEERS` scan 4× per main loop = 72K scans/sec |
| **112** | P1 | `hub/main.rs:676` | `memmove` 42B per TX packet = 3.2 MB/sec UMEM writes |
| **91** | P1 | `hub/main.rs:848` | `push_batch(&[desc])` — degenerate batch of 1 (per-pkt Release barrier) |
| **92** | P1 | `hub/main.rs:765-776` | No `prefetch_read_l1` before UMEM write path |
| **95** | P1 | `hub/main.rs:1057-1087` | `GraphCtx` 30-field struct constructed twice per loop (480B stack/iter) |
| **96** | P1 | `hub/main.rs:1250-1262` | 13× `fetch_add(Relaxed)` per RX batch (234K atomics/sec) |
| **97** | P1 | `hub/main.rs:1296-1366` | Peer keepalive scan iterates ALL `MAX_PEERS` slots every batch |
| **100** | P3 | `hub/main.rs:1063-1066` | `tun_fd` recomputed via closure every loop iteration |

### Hub — Cold Path (3)

| # | Severity | File:Line | Defect |
|---|----------|-----------|--------|
| **82** | P2 | `hub/main.rs:267` | 32MB stack per VPP worker (500× overprovisioned) |
| **99** | P2 | `hub/main.rs:941-955` | SLAB init loop touches 32MB UMEM sequentially (cold-start cache flush) |
| **102** | P2 | `hub/async_pqc.rs:122-148` | `PqcResp` 9,280B copied through SPSC (28% of L1d) |

### Hub — Micro (2)

| # | Severity | File:Line | Defect |
|---|----------|-----------|--------|
| **103** | P3 | `hub/async_pqc.rs:278` | `push_batch(&[resp])` — degenerate batch of 1 for 9.2KB struct |
| **104** | P3 | `hub/async_pqc.rs:66-84` | `FlatHubHandshakeState` 2,720B full struct copy |

### Node — Hot Path (3)

| # | Severity | File:Line | Defect |
|---|----------|-----------|--------|
| **127** | P2 | `node/main.rs:1229-1231` | `commit_pbr()` per-frame — 128 atomic Release stores where 1 suffices |
| **113** | P3 | `hub/main.rs:1466` | `scheduler.dequeue()` single-element — per-packet loop overhead |
| **116** | P3 | `hub/main.rs:345-366` | `CycleStats` 15 manual field additions (no AddAssign) |

---

## 6. OTHERS

### Dead Code (3)

| # | Severity | File:Line | Defect |
|---|----------|-----------|--------|
| **68** | P1 | `hub/engine/typestate.rs:1-254` | `typestate.rs` 254 lines fully implemented but **zero call sites** |
| **122** | P1 | `node/main.rs:344-751` | `run_udp_worker()` **408 lines** dead code with `#[allow(dead_code)]`. SAFE TO DELETE. |
| **114** | P3 | `hub/datapath.rs:42-44` | `debug_assertions` Vec heap alloc in hot loop (debug only) |

### Security (4)

| # | Severity | File:Line | Defect |
|---|----------|-----------|--------|
| **64** | **P0** | `node/cryptography/aead.rs` | **No anti-replay window** — attacker can replay captured packets indefinitely |
| **65** | P2 | `node/main.rs:917,1052` | Nonce reuse across rekey if seq_tx not reset (safe today, fragile) |
| **79** | P2 | `hub/network/bpf.rs:45-48` | `RLIM_INFINITY` fallback removes all memory lock limits |
| **74** | P2 | `hub/runtime.rs:356-381` | `lock_pmu()` leaks file descriptor via `mem::forget` — no CLOEXEC |

### Correctness (7)

| # | Severity | File:Line | Defect |
|---|----------|-----------|--------|
| **126** | **P0** | `node/main.rs:984-988` | **CQE overflow silently drops CQEs → BID leak → PBR exhaustion → recv halts** |
| **89** | P1 | `hub/main.rs:813-818` | `pending_return[4096]` overflow — no bounds check (stack buffer overflow) |
| **47** | P1 | `node/datapath.rs:175` | MSS clamping uses `--clamp-mss-to-pmtu` — PMTUD fails over UDP tunnels |
| **59** | P2 | `node/uring_reactor.rs:156` | `MSG_TRUNC` on multishot recv — truncated frame → crypto failure |
| **61** | P3 | `node/uring_reactor.rs:100,124` | PBR only covers UDP BIDs, not TUN (design choice) |
| **66** | P2 | `node/main.rs:1241-1264` | No rate limiting on handshake retransmit — floods 28 pkts/sec if Hub unreachable |
| **67** | P2 | `node/datapath.rs:174-179` | iptables rules not idempotent — `-A` duplicates on re-setup |

### Bloat / Micro (8)

| # | Severity | File:Line | Defect |
|---|----------|-----------|--------|
| **83** | P3 | `hub/main.rs:258` | `tun_ref.try_clone()` for every worker — only worker 0 uses TUN |
| **84** | P3 | `hub/main.rs:256` | `wifi_iface.clone()` heap alloc per worker (only worker 0 needs it) |
| **105** | P3 | `hub/async_pqc.rs:213` | `process_client_hello_hub()` heap-allocates Vec (~13KB per ClientHello) |
| **124** | P3 | `node/main.rs:857` | `env::args().collect()` called twice — duplicate heap alloc |
| **125** | P3 | `node/main.rs:868-871` | EdtPacer double-init — `new()` then redundant `set_link_bps()` |
| **129** | P3 | `node/main.rs:1207-1209` | `Box::new(LessSafeKey)` heap alloc on handshake (avoidable) |
| **57** | P2 | `node/uring_reactor.rs:18` | `TUN_RX_ENTRIES=64` — starvation risk under burst |
| **93** | — | — | **RETRACTED** |

---

## Enemy Summary

| Enemy | Count | P0 | P1 | P2 | P3 | Most Critical |
|-------|-------|-----|-----|-----|------|--------------|
| **Syscall Storms** | 21 | 3 | 8 | 6 | 4 | #86/#88 (per-pkt TUN), #77 (20 subprocs), #121 (27 subprocs) |
| **Interrupt Storms** | 0 | — | — | — | — | N/A (io_uring/AF_XDP inherently avoids) |
| **Bufferbloat** | 23 | 8 | 7 | 4 | 4 | #123 (8MB SO_SNDBUF), #106 (silent drop), #109 (slab leak) |
| **Context Switching** | 7 | 1 | 2 | 2 | 2 | #81 (core collision) |
| **Cache Thrashing** | 17 | 2 | 6 | 4 | 5 | #110 (37KB/subvec), #111 (72K scans/sec) |
| **Dead Code** | 3 | — | 2 | — | 1 | #122 (408 lines), #68 (254 lines) |
| **Security** | 4 | 1 | — | 3 | — | #64 (no anti-replay window) |
| **Correctness** | 7 | 1 | 2 | 3 | 1 | #126 (BID leak → recv halt) |
| **Bloat/Micro** | 8 | — | — | 1 | 7 | #57 (TUN BID starvation) |
| **TOTAL** | **90** | **16** | **27** | **23** | **24** | — |
| *Active (excl. #93)* | **89** | | | | | |

---

## Cmd #3 Hub Bloat Audit Summary

> Full audit of `hub/src/main.rs` and `hub/src/engine/runtime.rs`. 
> Read ~2,588 LOC across main.rs, runtime.rs, datapath.rs, protocol.rs, uso_pacer.rs, mod.rs.

| Phase | LOC | Bloat% | Enemies | Range |
|-------|-----|--------|---------|-------|
| Phase 1 (main) | 85 | 22% | 2 | #69-#70 |
| Phase 2 (run_executive) | 156 | 14% | 5 | #71-#75 |
| Phase 3 (spawn_threads) | 170 | 35% | 5 | #76-#80 |
| Phase 4 (worker_entry) | 66 | 3% | 4 | #81-#84 |
| Thread 1 (TUN HK) | 160 | — | 8 | #85-#92 |
| Thread 2 (VPP Worker) | 800 | — | 7 | #94-#100 (#93 retracted) |
| Thread 3 (PQC) | 150 | — | 5 | #101-#105 |
| VPP Main Loop | 1200 | — | 12 | #106-#117 |
| **Total** | **~2,588** | — | **48** (47 active) | **#69-#117** |

### CRITICAL Bufferbloat Chain (Hub)

```
EdtPacer hardcoded 100Mbps (#107)  →  TX_RING_SIZE=256, silent drop (#106)
  →  enqueue return IGNORED (#109)  →  slab leak  →  DATAPATH HALT
```

---

## Cmd #4 Node Bloat Audit Summary

> Full audit of `node/src/main.rs`, `node/src/network/datapath.rs`, `node/src/network/uring_reactor.rs`.
> Read ~1,348 LOC (entire main.rs) + 255 LOC (datapath.rs) + 230 LOC (uring_reactor.rs).

| Phase | LOC | Bloat% | New | Existing | Range |
|-------|-----|--------|-----|----------|-------|
| Phase 1 (main) | 54 | 19% | 2 | — | #118-#119 |
| Phase 1.5 (cold funcs) | 153 | — | 3 | 10 | #120-#122, #41-#50 |
| Dead Code | 408 | 30% | 1 | — | #122 |
| Phase 2 (uring startup) | 112 | 29% | 3 | 1 | #123-#125, #59 |
| Phase 3 (CQE loop) | 546 | — | 5 | 3 | #126-#130, #53-#55 |
| **Total** | **~1,348** | 33% | **13** | **14** | **#118-#130** |

### What Node Does RIGHT (Hub Should Learn):

- **62-byte TUN read offset** → zero memmove (Hub #112 still memmoves) ✅
- **EDT pacer reset on 1s idle** (Hub #108 is missing this) ✅
- **Make-Before-Break** stale handshake discard ✅
- **3-pass VPP architecture** (CQE drain → batch AEAD → RxAction dispatch) ✅
- **HugeTLB arena** (MAP_HUGETLB | MAP_POPULATE | MAP_LOCKED) ✅

### P0 BUG: CQE overflow BID leak (#126)

```
>128 CQEs in burst  →  excess silently dropped  →  BIDs never returned to PBR
  →  PBR exhaustion after 3,968 leaks  →  multishot recv halts  →  DATAPATH DEAD
```

---

## Execution Order

> Fix #1-#40 are PRESCRIPTIONS (what to do). #41-#130 are DEFECTS (what's wrong).
> They are **many-to-many** — some defects must be fixed BEFORE their corresponding
> prescriptions, because the defects would sabotage the fix. Others are independent
> discoveries with no matching prescription.

### Wave 0: Dead Code Eradication (Zero Risk, Zero Side Effects)

> **Lowest hanging fruit.** Deleting unreachable code cannot break anything.
> Reduces cognitive load for every subsequent wave (662 fewer lines to scroll past).
> Establishes clean `cargo check` baseline for all future diffs.

| # | Binary | Defect | Lines Killed |
|---|--------|--------|--------------|
| **#122** | Node | Delete `run_udp_worker()` — fully superseded by `run_uring_worker()` | **408 lines** (30% of main.rs) |
| **#68** | Hub | Wire or delete `typestate.rs` — 254 lines, zero call sites | **254 lines** |
| **#114** | Hub | Remove `debug_assertions` Vec heap alloc in `rx_parse_raw` hot loop | ~3 lines (dead in release) |

> **── `cargo check` both binaries. Verify zero regressions. ──**

### Wave 1: P0 Correctness — Prevent Datapath Halts

> **Must fix first.** These are bugs that will crash the datapath regardless of CC improvements.

| # | Binary | Defect | Why First |
|---|--------|--------|-----------|
| **#109** | Hub | `enqueue_critical_edt` return ignored → slab leak → SLAB exhaustion → halt | Without this, Hub halts after ~8,192 dropped enqueues |
| **#126** | Node | CQE overflow → BID leak → PBR exhaustion → recv halts | Without this, Node halts after burst of >128 CQEs |
| **#89** | Hub | `pending_return[4096]` no bounds check → stack overflow | Memory safety violation |

### Wave 2: Fix 0 + Supporting Defects — Kill Tunnel Collapse

> **This is where 95% of throughput recovery lives.** Fix #1-#5 are the root cause knobs,
> but several defects must be resolved simultaneously or they will sabotage the fixes.

| Order | Item | What | Why this order |
|-------|------|------|----------------|
| 2a | **#48** | Consolidate contradictory sysctls into one function | If not fixed, `setup_tunnel_routes()` overwrites Fix #1/#2 values |
| 2b | **#43-#45, #41-#42, #49-#50** | Fix sysctl values (16MB→BDP, 4MB→256KB, backlog→300) | Clears the contradictions. Enables Fix #1/#2 to stick |
| 2c | **Fix #1** | `SO_SNDBUF = 256KB` (was 8MB) | **THE root cause fix.** #123 is the defect. |
| 2d | **Fix #2** | `SO_RCVBUF = 256KB` (was 8MB) | Symmetric to #1 |
| 2e | **Fix #3** | `txqueuelen = 20` (was 1000) | #78/#119 are the defects |
| 2f | **Fix #5** | Hub SPSC depth → 256 (was 2048) | Eliminates 2.83MB unmanaged FIFO |
| 2g | **#46 = Fix #6** | TUN qdisc `fq` → CAKE | AQM provides controlled backpressure (not raw drops) |
| 2h | **#52 = Fix #8** | Add `tcp_notsent_lowat=131072` | App-level backpressure valve |
| 2i | **#47 = Fix #7** | MSS clamp `--clamp-mss-to-pmtu` → `--set-mss 1318` | Prevents fragmentation |
| 2j | **#56** | Remove `tcp_slow_start_after_idle=0` | Prevents post-idle bursts |
| 2k | **Fix #4** | Remove Node EDT pacer (confirmed no-op) | Eliminates DeferredTxRing overhead |

> **── TEST: expect 100+ Mbps throughput, stable (no oscillation) ──**

### Wave 3: Hot-Path Syscall Elimination

> Eliminate per-packet kernel transitions. Measured impact: ~5ms/sec CPU on A53.

| # | Binary | Defect | Impact |
|---|--------|--------|--------|
| **#86** | Hub | Per-packet `libc::write()` to TUN → io_uring | 2,260 write() syscalls/sec eliminated |
| **#88** | Hub | Per-packet `libc::read()` from TUN → io_uring | 2,260 read() syscalls/sec eliminated |
| **#87** | Hub | `poll(tun_fd, 1, 1ms)` → io_uring multishot POLL_ADD | 1,000 poll() syscalls/sec eliminated |
| **#53** | Node | Echo `sock.send()` → `reactor.stage_udp_send()` | Blocking send in SQPOLL loop |
| **#54** | Node | Keepalive `sock.send()` → `reactor.stage_udp_send()` | Same |
| **#55** | Node | Handshake retransmit `sock.send()` → io_uring batch | 3-7 blocking sends per retransmit |
| **#101** | Hub | PQC worker `yield_now()` → `sleep(1ms)` | >100K sched_yield()/sec → 1K sleep/sec |

> **── TEST: measure CPU utilization drop, verify no latency regression ──**

### Wave 4: Cache Thrashing Hot-Path

> Eliminate the biggest cache polluters in the per-packet pipeline.

| # | Binary | Defect | Impact |
|---|--------|--------|--------|
| **#110** | Hub | Pre-allocate PacketVectors outside loop (37KB/subvec → 0) | 665 MB/sec stack zeroing eliminated |
| **#111** | Hub | Cache active peer indices (72K scans/sec → 0) | Eliminate cold MAX_PEERS scan |
| **#112** | Hub | In-place 42-byte header (learn from Node's 62-byte offset) | 3.2 MB/sec memmove eliminated |
| **#95** | Hub | Construct GraphCtx once, reuse for TX + RX | 480B stack writes/iteration eliminated |
| **#91** | Hub | Batch `push_batch` for TUN reads (32-64 at once vs per-pkt) | 2,260 Release barriers/sec → ~35/sec |
| **#92** | Hub | Add `prefetch_read_l1` before UMEM write | Hide DRAM latency |
| **#127** | Node | Batch `commit_pbr()` (128 atomics → 1) | 128 Release stores → 1 |
| **#128** | Node | Batch `reactor.submit()` per TUN write (128 syncs → 1) | 128 SQ syncs → 1 |
| **#96** | Hub | Batch telemetry atomics (13× per batch → 1× per 100) | 234K atomics/sec → 2.3K |
| **#97** | Hub | Active peer index cache for keepalive scan | Same as #111 pattern |

> **── TEST: measure per-packet latency, verify cache miss reduction via perf stat ──**

### Wave 5: Cold-Path Cleanup + Hardening

> Hygiene + hardening. No throughput impact, but reduces maintenance burden and attack surface.
> Dead code already killed in Wave 0.

| # | Binary | Defect | Impact |
|---|--------|--------|--------|
| **#77** | Hub | `setup_nat()` subprocesses → `fs::write()` + netlink | 20 forks → 0 |
| **#121** | Node | `setup_tunnel_routes()` subprocesses → ioctl/netlink | 27 forks → 0 |
| **#120** | Node | `tune_system_buffers()` subprocesses → `fs::write()` | 14 forks → 0 |
| **#76/#118** | Both | `create_tun()` subprocesses → ioctl | 4 forks → 0 (each) |
| **#69** | Hub | `nuke_cleanup_hub()` subprocesses → libc calls | 9 forks → 0 |
| **#64** | Node | Implement anti-replay window (security P0) | RFC 4303 §3.4.3 compliance |
| **#67** | Node | iptables rules idempotency (`-C` before `-A`) | Prevents double-processing |
| **#74** | Hub | `lock_pmu()` fd leak → add CLOEXEC + store for shutdown | Resource leak |

### Wave 6: Fix #24-#40 — CC Engine (New Feature Work)

> **Only after Waves 1-4 are tested and stable.** This is the congestion control engine —
> new code, not bug fixes. Requires a functioning, non-collapsing tunnel as baseline.

| Fix # | Component | Dependency |
|-------|-----------|------------|
| **#24** | `CcState` struct | None (new file) |
| **#25** | `on_feedback()` parse | Fix #10 (wire feedback) |
| **#26** | Swift AIMD CC | #24, #25 |
| **#27** | Inflight gate (TUN read suppression) | #24, #26 |
| **#28** | `on_send()` inflight tracking | #24 |
| **#29** | BtlBw windowed max filter | #25 |
| **#30** | EDT pacer ← dynamic btl_bw | #29, replaces Fix #9 |
| **#31** | CoDel sojourn on Hub SPSC | #5 (depth 256) |
| **#32** | Per-queue bytes-in-flight tracking | #28 |
| **#33** | Flow hash preservation for CAKE | #6 (CAKE deployed) |
| **#34-#37** | Satellite-aware CC (StarQUIC, LeoCC, Copa) | #26 stable first |
| **#38-#40** | Hub symmetric CC | #26 + #39 (Node→Hub feedback) |

> **── TEST: iperf3 sustained, YouTube 4K, MAVLink jitter, satellite handover simulation ──**

