# Cmd #4 Node Bloat Audit

Phase-by-phase audit of `node/src/main.rs`, `node/src/network/datapath.rs`, and called functions.

**Architecture:** Single-threaded + kernel SQPOLL. No AF_XDP. No BPF. io_uring for all I/O.

## Phase 1: `main()` L37-90 (54 lines)

### Enemy Violations

| # | Enemy | File:Line | Defect | TODO# |
|---|-------|-----------|--------|-------|
| 1 | **Syscall Storm** | `datapath.rs:63-72` | `create_tun()` spawns **4× child processes** (`ip link set up`, `ip addr add`, `ip link set mtu`, `ip link set txqueuelen`). 12 syscalls minimum (4× fork+exec+wait). Replace with `ioctl()`. | #118 (new) |
| 2 | **Bufferbloat** | `datapath.rs:72` | `txqueuelen=1000` on TUN interface. At 200 Mbps with 1380B frames: 1000 × 1380B = 1.38MB standing queue = **55ms of kernel buffering** before backpressure. | #119 (=Hub #78) |
| 3 | (Heap waste) | `main.rs:29` | `HUB_IP_GLOBAL: Mutex<String>` — global heap-allocated Mutex for panic hook. Accessed once at L79-81 (write) and once in panic hook (read). Cold path, minor. | — (not filed) |
| 4 | (Architectural) | `main.rs:41` | `env::args().collect::<Vec<String>>()` — heap allocation for CLI parse. Cold-start only, not an enemy. | — |

### Bloat Analysis

| # | Lines | What | Wasted | Category |
|---|-------|------|--------|----------|
| 1 | L63-72 | 4× `Command::new("ip")` in create_tun | ~10 lines | Subprocess abuse (same as Hub) |
| 2 | L55-57 | `args.iter().any()` × 3 for flags | 0 lines | Clean — simple pattern |

**Phase 1 bloat: ~10 lines / 54 total (19%)**

## Phase 1.5: Cold-Path Functions Called from Phase 1/2

### `tune_system_buffers()` — main.rs L286-342 (57 lines)

| # | Enemy | File:Line | Defect | TODO# |
|---|-------|-----------|--------|-------|
| 5 | **Syscall Storm** | `main.rs:278,301-302,315-332` | Spawns **14+ child processes**: 1× `iw` per WiFi interface + 10× `sysctl -w` (via `apply_sysctl`) + 10× `/proc/sys` readback verify + 1× `tc qdisc`. Each `Command::new("sysctl")` = fork+exec+wait = ~600µs. Total: **~8.4ms of startup subprocess overhead.** | #120 (new) |
| 6 | **Bufferbloat** | `main.rs:316-317` | `rmem_max=8MB`, `wmem_max=8MB`, `rmem_default=4MB`, `wmem_default=4MB`. | #49, #50 (existing) |
| 7 | **Bufferbloat** | `main.rs:326` | `netdev_max_backlog=10000` = 550ms of kernel ingress buffering. | #42 (existing) |
| 8 | **Bufferbloat** | `main.rs:317` | `rmem_default=4MB`, `wmem_default=4MB` — every inner TCP socket gets 4MB buffer. | #41 (existing) |

### `setup_tunnel_routes()` — datapath.rs L92-187 (96 lines)

| # | Enemy | File:Line | Defect | TODO# |
|---|-------|-----------|--------|-------|
| 9 | **Syscall Storm (WORST IN NODE)** | `datapath.rs:92-187` | Spawns **27 child processes**: 1× `discover_gateway` (`ip route show`), 3× `ip addr/link` (L106-116), 3× `ip route` (L120-140), 2× `sysctl` IPv6 (L144-149), 4× `sysctl` rmem/wmem/tcp_rmem/wmem (L153-160), 4× `sysctl` other (L161-168), 1× `sysctl ip_forward` (L171-172), 3× `iptables` (L174-179), 1× `tc qdisc` (L182-183). **Total: 27 fork+exec+wait = ~16.2ms.** Combined with `tune_system_buffers` = **24.6ms of pure subprocess overhead** at startup. | #121 (new) |
| 10 | **Bufferbloat** | `datapath.rs:153-160` | `rmem_max=16MB`, `wmem_max=16MB`, `tcp_rmem max=16MB`, `tcp_wmem max=16MB`. **Overwrites** tune_system_buffers' 8MB with **worse** 16MB. | #43, #44, #45 (existing) |
| 11 | **Contradictory Config** | `main.rs:286-342` + `datapath.rs:152-168` | `tune_system_buffers()` runs first with 8MB values. `setup_tunnel_routes()` runs later and overwrites with 16MB = **second function undoes the first.** | #48 (existing) |
| 12 | Bufferbloat | `datapath.rs:183` | TUN qdisc = `fq` (fair queueing only). No AQM, no bandwidth shaping, no sojourn drops. | #46 (existing) |
| 13 | (Correctness) | `datapath.rs:175` | MSS clamp uses `--clamp-mss-to-pmtu` — PMTUD fails over UDP tunnels. | #47 (existing) |

### `run_udp_worker()` — main.rs L344-751 (408 lines) — **DEAD CODE**

| # | Enemy | File:Line | Defect | TODO# |
|---|-------|-----------|--------|-------|
| 14 | **DEAD CODE (408 lines)** | `main.rs:344-751` | `#[allow(dead_code)]` on `run_udp_worker()`. This is the **legacy recvmmsg/sendmmsg fallback** path. Currently 408 lines of completely unreachable code. 30% of main.rs is dead. Comment says "retained for systems without Kernel 6.12+", but there is no runtime dispatch — `main()` always calls `run_uring_worker()`. | #122 (new) |

> [!CAUTION]
> **VERIFIED SAFE TO DELETE.** `run_udp_worker()` is fully superseded by `run_uring_worker()` (L846-1348). Same signature, same functionality, strictly superior I/O model (io_uring vs recvmmsg/sendmmsg). Zero call sites exist — grep confirms only the definition (L345) and a comment (L842: "Replaces run_udp_worker"). No `cfg`, no feature gate, no runtime dispatch. Recoverable from git history if ever needed.

## Phase 2: `run_uring_worker()` Startup — L846-957 (112 lines)

> **Worker initialization. UDP socket, io_uring reactor, EDT pacer, TUN arming.**

### Enemy Violations

| # | Enemy | File:Line | Defect | TODO# |
|---|-------|-----------|--------|-------|
| 15 | **BUFFERBLOAT (ROOT CAUSE — Sprint 2.5 Causal Chain)** | `main.rs:891-897` | `SO_RCVBUFFORCE = 8MB`, `SO_SNDBUFFORCE = 8MB`. **THIS IS THE SINGLE ROOT CAUSE of the Sprint 2.5 tunnel collapse.** The 8MB send buffer creates an unmanaged FIFO between TUN and wire. Inner TCP sees ~0ms TUN RTT, sends at max rate, fills 8MB in 320ms → RTT inflates → cwnd collapse → throughput oscillates 1.6-20 Mbps. See Sprint 2.5 causal chain. | #123 (new) |
| 16 | (Bloat) | `main.rs:857` | `env::args().collect::<Vec<String>>()` called **again** inside `run_uring_worker`. Already collected at `main()` L41. Heap allocation + parse of identical data. Should pass `link_bps` as function arg from `main()`. | #124 (new) |
| 17 | (Bloat) | `main.rs:868-871` | `EdtPacer::new(&cal, cli_link_bps)` at L868, then immediately `edt_pacer.set_link_bps(cli_link_bps)` at L871 if CLI override. `EdtPacer::new()` already uses the `link_bps` parameter — the `set_link_bps` call is **redundant** (re-computes identical `ns_per_byte`). | #125 (new) |
| 18 | (Tuning) | `uring_reactor.rs:91` | `setup_sqpoll(2000)` — SQPOLL kernel thread idle timeout = 2 seconds. After 2s of no submits, the kernel thread parks and must be woken via syscall. During active traffic this is irrelevant. During bursty traffic with >2s gaps, the first submit after idle incurs a kernel wakeup. **Consider reducing to 500ms** to match M13's 1s telemetry interval. | — (not filed, tuning) |
| 19 | (Correctness) | `uring_reactor.rs:156` | `MSG_TRUNC` on multishot recv — if UDP packet > FRAME_SIZE, data truncated but full length returned. Node processes truncated frame → crypto failure. | #59 (existing) |

### What Phase 2 Does RIGHT

- **62-byte TUN read offset** (`uring_reactor.rs:172`): `addr.add(62)` reserves headroom for M13 header. **Zero memmove at TX time** — header written at byte 0, payload already at byte 62. This is the CORRECT architecture that Hub #112 (memmove 42B per packet) lacks. ✅
- **HugeTLB arena** (`uring_reactor.rs:80-81`): `MAP_HUGETLB | MAP_POPULATE | MAP_LOCKED` for PBR + data arena. Eliminates TLB thrashing and page faults. ✅
- **PBR pre-population** (`uring_reactor.rs:124-126`): All 4096 UDP buffer ring entries initialized before first recv. ✅
- **Connected UDP socket** (`main.rs:884`): `sock.connect(hub_addr)` enables `send()` instead of `sendto()` — 1 less pointer dereference per TX syscall. ✅
- **SQPOLL + SINGLE_ISSUER** (`uring_reactor.rs:91-93`): Kernel thread handles submit, no syscall needed for SQE submission. `SINGLE_ISSUER` enables lock-free SQ access. ✅
- **Multishot recv** (`uring_reactor.rs:152-164`): Single SQE → kernel delivers all UDP packets via CQE with buffer IDs. Zero per-recv SQE submission. ✅

### Bloat Analysis

| # | Lines | What | Wasted | Category |
|---|-------|------|--------|----------|
| 1 | L856-867 | Re-parse CLI args for `--link-bps` | 12 lines | Should be parsed in `main()` and passed as arg |
| 2 | L869-877 | EdtPacer init + redundant `set_link_bps` + 2× eprintln | 9 lines | Double-init + verbose logging |
| 3 | L917-927 | 14 separate counter variables | 11 lines | Should be a `TelemetryCounters` struct |

**Phase 2 bloat: ~32 lines / 112 total (29%)**

## Phase 3: Main CQE Event Loop — L957-1348 + process_rx_frame L113-267 (546 lines, **HOT PATH**)

> **The single-threaded datapath. Every defect here multiplies by every packet.**

### Enemy Violations

| # | Enemy | File:Line | Defect | TODO# |
|---|-------|-----------|--------|-------|
| 20 | **Syscall Storm (HOT)** | `main.rs:1183` | Echo frames use blocking `sock.send()` bypassing io_uring. On isolated SQPOLL-driven loop, this injects a synchronous `sendto()` syscall. | #53 (existing) |
| 21 | **Syscall Storm (HOT)** | `main.rs:1273` | Keepalive frames use blocking `sock.send()` bypassing io_uring. 10×/sec pre-Established. | #54 (existing) |
| 22 | **Syscall Storm** | `main.rs:1257` | Handshake retransmit closure calls `sock.send()` per fragment. 3-7 blocking sends in CQE loop. | #55 (existing) |
| 23 | **CQE Overflow — silent drop** | `main.rs:984-988` | `MAX_CQE = 128`. CQE drain loop: `if cqe_count < MAX_CQE { ... }`. If >128 CQEs pending (burst arrival), **excess CQEs are iterated but never stored** — silently dropped. The BIDs for dropped UDP CQEs are **never returned to PBR** → permanent BID leak → PBR exhaustion after 4096 - 128 = 3,968 leaked BIDs → all multishot recv stops. | #126 (new) |
| 24 | **Cache Thrashing (micro)** | `main.rs:1229-1231` | `commit_pbr()` called **per-frame** in Pass 2. Each commit does an atomic `Release` store. At 128 CQEs/batch: 128 atomic stores. Should batch: single `commit_pbr()` after the Pass 2 loop. | #127 (new) |
| 25 | **Syscall Storm (micro)** | `main.rs:1169` | `reactor.submit()` called **per TUN write** inside Pass 2 loop. Each submit syncs SQ ring. At 128 TUN writes: 128 submit calls. Should batch: single `submit()` after the loop. | #128 (new) |
| 26 | (Heap alloc) | `main.rs:1207-1209` | `Box::new(aead::LessSafeKey::new(...))` on handshake completion. Heap allocation on the control path. Infrequent (once per session), but avoidable. | #129 (new) |
| 27 | **Bufferbloat (pacing bypass)** | `main.rs:1060-1071` | DeferredTxRing overflow: when ring is full (`DEFERRED_TX_CAPACITY=64`), oldest entry is force-drained **regardless of release_ns**. This **bypasses EDT pacing** — packets depart early under burst load. At 2,260 pkt/sec with 120µs pacing: ring fills in 64/2260 = 28ms. Every packet beyond 64 causes an un-paced forced TX. | #130 (new) |
| 28 | (Bloat) | `main.rs:991-993` | 3× stack arrays zeroed per iteration: `recv_bids[128]`, `recv_lens[128]`, `recv_flags[128]` = 128×(2+8+4) = 1,792 bytes. Minor vs Hub's 37KB, but could pre-allocate outside loop. | — (not filed) |

### What Phase 3 Does RIGHT (Hub should learn from these)

- **EDT pacer reset on 1s idle** (L1297-1304): Node calls `edt_pacer.reset(now)` when `last_tx_activity_ns` > 1s ago. **Hub #108 does NOT do this.** ✅
- **3-pass VPP architecture** (L968-976): CQE drain → batch AEAD → per-frame dispatch. Keeps crypto unit thermally hot. ✅
- **Vectorized AEAD batch** (L1091-1136): `decrypt_batch_ptrs()` with 4-at-a-time prefetch. Replaces per-frame scalar decrypt. ✅
- **PRE_DECRYPTED_MARKER** (L148-150): Batch decrypt stamps 0x02, process_rx_frame skips redundant decrypt. Zero double-decrypt. ✅
- **In-place M13 framing** (L1044-1048): TUN read at offset 62 → write header at byte 0 → zero memmove. Hub #112 still memmoves. ✅
- **DeferredTxRing EDT drain** (L1307-1323): monotonic `peek_release_ns() <= now` loop. Zero-spin. ✅
- **Multishot recv rearm** (L1235-1238): Only rearms when `CQE_F_MORE==0`. Minimal SQE churn. ✅
- **Shutdown flush** (L1329-1340): Drains all deferred TX entries on exit. No BID leaks at shutdown. ✅
- **Make-Before-Break** (L222-227): Stale handshake retransmits discarded after state transition. No session teardown on late fragment. ✅

### process_rx_frame (L113-267) — Clean

- Correct flag re-read after AEAD decrypt (L194)
- PRE_DECRYPTED_MARKER bypass for batch-decrypted frames (L148-150)
- Fragment reassembly via Assembler (L197-243) — same as Hub
- `_hexdump` parameter unused (L123) — minor underscore-prefix finding

## Cumulative Summary (Phase 1 + Phase 2 + Phase 3)

```
Phase 1 (main):       ~10 lines / 54   (19%) —  2 enemies (#118-#119)
Phase 1.5 (cold):      ~0 lines / 153  ( 0%) — 10 enemies (#120-#122 new, #41-#50 existing)
Dead code:            408 lines / 1348 (30%) —  1 enemy (#122)
Phase 2 (startup):    ~32 lines / 112  (29%) —  3 enemies (#123-#125)
Phase 3 (CQE loop):    ~0 lines / 546  ( 0%) —  9 enemies (#126-#130 new, #53-#55 existing)
──────────────────────────────────────────────────────────
Total Phases 1-3:    ~450 lines / 1348 (33%) — 13 new enemies (#118-#130)
                                                15 existing (#41-#55, #57-#59)
```

### Enemy Category Breakdown (Node)

| Enemy | Count | Most Critical |
|-------|-------|--------------|
| **Bufferbloat** | **6** | #123 (SO_SNDBUFFORCE=8MB), #119 (txqueuelen=1000), #130 (pacing bypass) |
| **Syscall Storm** | 9 | #53/#54/#55 (sock.send bypass io_uring), #121 (27 subprocesses) |
| **Cache Thrashing** | 1 | #127 (per-frame PBR commit) |
| **Dead Code** | 1 | #122 (408 lines run_udp_worker) |
| **Other/Micro** | 4 | #124 (double args), #125 (double EdtPacer init), #129 (heap alloc) |
| **BID Leak (P0)** | 1 | #126 (CQE overflow → PBR exhaustion → recv halts) |

### Cross-Reference to Existing TODO.md Defects

| New # | Existing TODO # | Relationship |
|-------|----------------|-------------|
| #118 | Hub #76 | Identical — both create_tun spawn 4× ip subprocesses |
| #119 | Hub #78 | Identical defect mirrored (both set txqueuelen=1000) |
| #120 | Hub #77 | Parallel — Hub's setup_nat spawns 20, Node's tune_system_buffers spawns 14+ |
| #121 | Hub #77 | Parallel — Hub's setup_nat spawns 20, Node's setup_tunnel_routes spawns 27 (WORSE) |
| **#123** | **Sprint 2.5** | **SO_SNDBUFFORCE=8MB is the documented root cause of tunnel collapse** |
| **#126** | Hub #106 | **Parallel — Hub has silent scheduler tail-drop, Node has CQE overflow BID leak** |
| #130 | Hub #108 | Inverted — Node has DeferredTxRing force-drain bypass; Hub has no pacer reset |


