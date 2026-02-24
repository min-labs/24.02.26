# ROADMAP

### ✅ Sprint 1: Foundation — COMPLETED

#### Debt

**[P0-01] VFS Syscall Avalanche (partial)** `← 1.2, 1.3`
**Defect:** Monolithic `loop {}` executing `recvmmsg`/`sendmmsg`/`File::read/write` via legacy POSIX FDs. 4 VFS syscalls per iteration = 8–40 µs static overhead on Cortex-A53, exceeding control-frame inter-arrival by 15×.
**Resolution:** Node datapath replaced with `io_uring` PBR multishot recv + CQE three-pass loop (S1.3). Hub TUN I/O decoupled to SPSC lock-free rings + housekeeping thread (S1.2). Remaining: stack buffer arena migration (→ S4.1), dead code eradication (→ S4.4).

| # | Sub-system | Deliverable |
| --- | --- | --- |
| **1** | Hardware Determinism | AF_XDP zero-copy enforcement, simulation eradication |
| **2** | Datapath VFS Decoupling | Hub SPSC TUN I/O, TUN housekeeping thread |
| **3** | Node io_uring | PBR multishot recv, CQE three-pass loop |
| **4** | FPU Eradication | Q60.4 fixed-point JitterEstimator |
| **5** | Spec Alignment | Closure TX, GraphCtx, dead code, test relocation |

#### Rationale

| # | Rationale |
| --- | --- |
| **1** | AF_XDP `XDP_ZEROCOPY` + `MAP_HUGETLB` strictly enforced. All simulation fallbacks (`M13_SIMULATION`, `XDP_COPY`, `SKB_MODE`) eradicated. Hardware or abort. |
| **2** | VFS `read`/`write` syscalls removed from AF_XDP hot-loops. SPSC lock-free rings decouple TUN I/O to a housekeeping thread. |
| **3** | `recvmmsg`/`sendmmsg` replaced with `io_uring` `SQPOLL` + PBR multishot recv. Zero context switches on the Node datapath. |
| **4** | IEEE 754 `f64` eradicated from `JitterEstimator`. Q60.4 fixed-point integer math per RFC 3550 §A.8. Zero FPU pollution. |
| **5** | Closure-based `send_fragmented_udp`, `GraphCtx` observability fields, dead `Assembler::new()` removed, `ETH_P_M13.to_be()` bug fixed. |

---

### ✅ Sprint 2: The 0-RTT Handshake — 2.1–2.4 COMPLETED

#### Debt

**[P0-03] Synchronous PQC Lattice Math → HoL Blocking** `← 2.3`
**Location:** Node `cryptography/handshake.rs` (`process_handshake_node`) & Hub (`process_client_hello_hub`)
**Defect:** ML-DSA-87 and ML-KEM-1024 evaluated synchronously on the datapath thread. 5–25 ms blackout queues ~300 KB at 100 Mbps, blowing NIC ring limits and crashing BBR `cwnd`.
**Resolution:** PQC offloaded to Core 0 via dual SPSC rings. Datapath continues routing Established flows (MBB) while key-exchange resolves in parallel.

**[P1-02] IP Fragmentation over RF** `← 2.4`
**Location:** Node `main.rs` (`tun_file.read(&mut frame[62..1562])`)
**Defect:** 1562-byte frames over 1500 MTU WiFi forces kernel IP fragmentation. Loss scales geometrically: P(loss) = 1-(1-p)^n.
**Resolution:** USO slices ciphertext into 1380-byte RF chunks in userspace. Zero kernel fragmentation.

**[P1-04] Sub-Par WiFi IO Substrate** `← 2.4, 2.5`
**Location:** Hub `main.rs` and `network/`
**Defect:** The Hub currently relies solely on `AF_XDP` `XDP_ZEROCOPY` wired interfaces. To act as a "flying telco" for WAN-deprived daughter drones, it must broadcast a WiFi 7 AP. `AF_XDP` cannot bind to `mac80211` WiFi interfaces.
**Resolution:** The Hub must ingest the Node's `io_uring` Reactor architecture to service the local WLAN, multiplexing packets between the `AF_XDP` wired backhaul and the `io_uring` local WiFi AP.

| # | Sub-system | Deliverable | Status |
| --- | --- | --- | --- |
| **1** | Stateful Security | MBB, Keepalives | ✅ |
| **2** | PQC Offload | Dual SPSC, Core 0 worker, FlatHubHandshakeState | ✅ |
| **3** | USO MTU Slicer | Userspace segmentation, zero kernel IP fragmentation | ✅ |
| **4** | Hub io_uring | `UringReactor` integration for `mac80211` interface, multi-interface multiplexing | ✅ |

#### Rationale

| # | Rationale |
| --- | --- |
| **1** | Make-Before-Break guarantees 0ms stream interruption during keygen. Active Keepalives defeat CGNAT deadlocks. |
| **2** | PQC lattice math (ML-KEM-1024, ML-DSA-87) blocks the datapath for 5-25ms. Offload to Core 0 via SPSC rings preserves Make-Before-Break continuity. |
| **3** | 1562-byte frames over 1500 MTU WiFi forces kernel IP fragmentation. Fragment loss scales geometrically. USO slices ciphertext into 1380-byte chunks in userspace. Zero kernel fragmentation. |
| **4** | `AF_XDP` strictly requires a wired NIC driver. To service the daughter drone swarm, the Hub must support `mac80211` WiFi interfaces via `io_uring` polling. |

---

### Sprint 2.5 Preamble: Full Connection Lifecycle Trace — youtube.com 4K Video

> [!CAUTION]
> **This is the bare-metal, nuts-and-bolts, packet-by-packet trace of what happens
> when a user types `youtube.com` through the M13 tunnel. Every packet accounted for.
> Every culprit function identified with exact `file:line`.**

#### Scenario Setup

```text
                 ┌──────────┐     WiFi 7 AP     ┌─────────┐     SATCOM      ┌──────────┐     ISP     ┌──────────┐
                 │  USER PC │◀───────────────────│   HUB   │◀───────────────▶│  Google  │◀───────────▶│ User CMD │
                 │ (Node)   │    m13tun0         │ (LALE)  │   UDP/443       │ CDN      │             │ Center   │
                 └──────────┘    10.13.0.2       └─────────┘   enp1s0f0      └──────────┘             └──────────┘
                                                  10.13.0.1
```

User PC runs apps over `m13tun0` (10.13.0.2). All traffic exits via Hub NAT (10.13.0.1 → MASQUERADE → satellite → internet).

#### Phase 1: DNS Resolution (works fine — tiny packets)

```text
USER TYPES youtube.com IN BROWSER

1. Browser → getaddrinfo("youtube.com") → stub resolver → UDP 53 DNS query (≈80B)
2. Kernel routes 8.8.8.8 via m13tun0 (default route installed by setup_tunnel_routes())

NODE UPLINK (DNS query, 80B):
3. Kernel writes DNS packet to m13tun0 TUN device
4. io_uring CQE fires: TAG_TUN_READ                          ← node/main.rs:1027
5. build M13 header in-place (62B header + 80B payload = 142B) ← node/main.rs:1044-1048
6. seal_frame() → AES-256-GCM encrypt                        ← node/main.rs:1050
7. edt_pacer.pace(now, 142) → release_ns                     ← node/main.rs:1058
   gap = 142 × 80ns/byte = 11.36µs (at 100Mbps)
   BUT: inter-arrival time for 1 DNS packet ≈ human-scale (seconds)
   ∴ pacer sees idle → release_ns = now. NO PACING EFFECT.
8. deferred_tx.push() → ring                                 ← node/main.rs:1060
9. Loop tail: peek_release_ns() ≤ now → pop() →              ← node/main.rs:1315-1322
   reactor.stage_udp_send(ptr, 142, bid, TAG_UDP_SEND_TUN)
10. io_uring SQE → kernel → UDP socket → 142B into SO_SNDBUF  ← node/main.rs:1326-1327
    SO_SNDBUF = 8 MB. 142B occupies 0.0017%. NO BACKPRESSURE.
11. Kernel sends UDP packet (142B) → WiFi → Hub

HUB UPLINK (DNS query):
12. AF_XDP poll_rx() → 142B frame in UMEM                     ← Hub VPP RX Graph
13. rx_parse_raw() → PacketVector                             ← hub/main.rs (execute_subvector)
14. aead_decrypt_vector() → plaintext                         ← Hub AEAD batch
15. classify_route() → Disposition::TunWrite                   ← hub/main.rs (classify/scatter)
16. tun_write_vector() → SPSC push to TUN HK thread           ← hub/main.rs (tun_write_vector)
17. TUN HK: pop PacketDesc → write(tun_fd, DNS_payload_80B)   ← hub/main.rs:~870 (Phase 1 TX)
18. Kernel: m13tun0 → ip_forward → NAT MASQUERADE → enp1s0f0 → satellite → Google DNS

DNS RESPONSE (same path, reverse, ≈200B): works perfectly. ✅
```

**Why DNS works**: Packets are tiny (80-200B), infrequent. No queue fills. No backpressure needed.

#### Phase 2: TCP/QUIC Connection to YouTube (works fine — handshake)

```text
BROWSER: HTTP/3 (QUIC over UDP/443) to YouTube CDN edge

1. Browser sends QUIC Initial (≈1200B) → kernel → m13tun0
2. Same path as DNS: TUN read → seal → 1262B frame → UDP socket → Hub → internet
3. YouTube responds: QUIC Handshake + 0-RTT data (≈1200B each)
4. Hub receives → AF_XDP → decrypt → TUN → m13tun0 → kernel → browser

QUIC handshake: 3-4 packets, each ≈1200B. Total ≈5KB.
Still fits trivially in 8 MB socket buffer. NO BACKPRESSURE TRIGGERED. ✅
```

#### Phase 3: Video Segment Fetch — WHERE IT BREAKS

> [!CAUTION]
> **This is the critical phase. The browser requests a video segment
> and the CDN pours data at maximum rate through the tunnel.**

##### Scenario A: 1×1080p (≈5 Mbps) — WORKS (barely)

```text
YouTube CDN sends 1080p segment at ~5 Mbps = 625 KB/s = ~450 packets/sec (1380B each)

HUB DOWNLINK PATH (CDN → Hub → Node):
1. Satellite delivers ≈450 pkt/s to Hub NIC (enp1s0f0)
2. Kernel → m13tun0 TUN → Hub reads from TUN

HUB TUN HK THREAD (Phase 2 RX):                              ← hub/main.rs:~880
3. poll(tun_fd, POLLIN, 1ms) → ready
4. alloc slab from free_slab_rx.pop()
5. read(tun_fd) → payload into UMEM slab
6. Build ETH+M13 header in UMEM (62B + payload)
7. Push PacketDesc to tx_to_dp SPSC ring                      ← SPSC depth = 2048

HUB VPP TX GRAPH (worker_entry):                              ← hub/main.rs:~1100
8. Pop PacketDesc from rx_tun_cons.pop_batch()
9. seal_frame() → AES-256-GCM encrypt
10. edt_pacer.pace() → release_ns                              ← Hub EdtPacer (100 Mbps default)
    At 5 Mbps actual: gap = 1380 × 80ns = 110µs needed
    Actual inter-arrival = 1,000,000 / 450 = 2,222 µs
    ∴ Pacer ALWAYS releases immediately. NO PACING EFFECT.     ← CULPRIT #1 (no-op)
11. Scheduler::schedule() → AF_XDP TX ring
12. AF_XDP sends → WAN NIC → satellite → Node

NODE DOWNLINK PATH (Hub → Node):
13. UDP packet arrives at Node socket
14. io_uring multishot recv CQE → recv_bids[]                  ← node/main.rs:1003-1023
15. Pass 1: decrypt_batch_ptrs() → PRE_DECRYPTED_MARKER       ← node/main.rs:1119-1124
16. Pass 2: process_rx_frame() → RxAction::TunWrite            ← node/main.rs:1153-1154
17. stage_tun_write(tun_fd, payload_ptr, len, bid)             ← node/main.rs:1168
18. Kernel writes payload to m13tun0 → IP stack → browser

AT 5 Mbps: Socket buffer accumulation rate:
  Incoming: 625 KB/s into 8 MB buffer
  Drain: Node processes CQEs in batches of 128
  Buffer fill time: 8 MB / 625 KB/s = 12.8 seconds to fill
  BUT: Node drains faster than 625 KB/s → buffer stays NEARLY EMPTY
  ∴ It works. Barely. RTT inflates slightly but doesn't collapse. ✅
```

##### Scenario B: 1×4K (≈25 Mbps) or 4×1080p (≈20 Mbps) — **COLLAPSES**

```text
YouTube CDN sends 4K segment at ~25 Mbps = 3.125 MB/s = ~2,260 packets/sec

══════════════════════════════════════════════════════════════════
THE UPSTREAM SAWTOOTH (Node → Hub → Internet → CDN ACKs)
══════════════════════════════════════════════════════════════════

INNER TCP/QUIC BEHAVIOR ON NODE:
1. Browser receives video data → QUIC stack sends ACKs upstream
2. Inner QUIC ACKs are tiny (≈60-100B each), ≈1,130 ACKs/sec at 25 Mbps
3. These ACKs go through the UPLINK path:
   m13tun0 → TAG_TUN_READ → seal_frame → DeferredTxRing → UDP socket

AT THIS RATE THE UPLINK IS FINE.
ACKs are tiny. 1,130 × 160B = 180 KB/s upload. Socket buffer handles it.

THE PROBLEM IS THE DOWNLINK:

══════════════════════════════════════════════════════════════════
THE DOWNLINK COLLAPSE — PACKET BY PACKET
══════════════════════════════════════════════════════════════════

SECOND 0.0 — 0.3: RAMP UP
─────────────────────────
1. YouTube CDN establishes QUIC connection. Inner QUIC cwnd = 10 segments.
2. CDN sends first flight: 10 × 1380B = 13.8 KB                  [via satellite → Hub → Node]
3. Node ACKs → travels uplink → CDN receives ACK
4. Inner QUIC doubles cwnd: 20 segments, then 40, 80...
5. By t=0.3s, inner QUIC has ramped to target rate (25 Mbps)
```

**HERE IS WHERE EVERY QUEUE STAGE FAILS:**

```text
SECOND 0.3 — 0.6: BUFFER FILLING
─────────────────────────────────
Rate: 25 Mbps = 3.125 MB/s from CDN

HUB SIDE (satellite → Hub → m13tun0 → SPSC → AF_XDP → satellite → Node):

CULPRIT #2: Hub TUN HK SPSC ring (depth 2048)                 ← hub/main.rs:218
  2048 × 1380B = 2.83 MB of unmanaged FIFO
  At 25 Mbps: fills in 2.83MB / 3.125MB/s = 0.9 seconds
  NO AQM. NO SOJOURN CHECK. NO DROP. PURE FIFO.
  Sojourn time when full: 2.83MB / 3.125MB/s = 905ms ← CATASTROPHIC

CULPRIT #3: Hub EDT Pacer at 100 Mbps                          ← hub/main.rs:~1050
  At 25 Mbps actual rate: gap needed = 1380B × 80ns = 110µs
  Actual inter-arrival from SPSC: ~440µs (= 1/2260 pkt/s)
  Pacer inter-packet gap = 110µs < 440µs actual arrival
  ∴ Pacer ALWAYS releases immediately. ZERO PACING EFFECT.
  Pacer only throttles if actual rate > 100 Mbps. We never reach that.

→ Hub pushes 2,260 pkt/s into AF_XDP → satellite → Node's NIC

NODE SIDE:

CULPRIT #4: Node UDP SO_RCVBUFFORCE = 8 MB                    ← node/main.rs:892-894
  Node receives 2,260 pkt/s × 1442B = 3.26 MB/s into socket
  Socket buffer ABSORBS everything without backpressure
  If Node's CQE processing lags (any jitter), packets queue in 8 MB buffer

CULPRIT #5: Node CQE batch = max 128 per loop iteration        ← node/main.rs:980
  At 2,260 pkt/s, Node must drain 128-CQE batches ≈18 times/sec
  Each batch: 128 × AEAD decrypt ≈ 1.2ms (AES-NI hot)
  Total decrypt time: 18 × 1.2ms = 21.6ms/sec — manageable
  BUT: Each batch also triggers 128 × stage_tun_write (io_uring SQEs)
  + 128 × TUN kernel writes + 128 × BID recycling
  Any operating system scheduling event (IRQ, timer, context switch)
  → Node misses a drain cycle → 128+ packets accumulate in socket buffer

NODE SENDS VIDEO DATA TO BROWSER VIA TUN:

CULPRIT #6: m13tun0 txqueuelen = 1000                          ← node/datapath.rs:72
  After decrypt, Node writes payload to m13tun0 via stage_tun_write()
  TUN can queue 1000 packets = 1.38 MB before dropping
  This is ANOTHER unmanaged FIFO between M13 and the browser
  NO AQM on m13tun0 (default qdisc = pfifo_fast, NOT fq_codel)

═══════════════ TIMELINE OF COLLAPSE ═══════════════

t=0.0s:   Inner QUIC slow-start. ≈10 pkt initial window.
t=0.3s:   QUIC ramped to 25 Mbps. All queues still draining.
t=0.5s:   8 MB socket buffer at 20% fill (1.6 MB queued).
          RTT has inflated: true RTT=50ms + buffer sojourn.
          Sojourn in 8 MB buffer: 1.6 MB / 25 Mbps × 8 = 512ms
          ∴ Inner QUIC sees RTT = 50ms + 512ms = 562ms ← ABNORMAL
t=0.8s:   Buffer at 50% (4 MB). Sojourn = 1,280ms. RTT = 1,330ms.
          Inner QUIC: "RTT is rising. Something is wrong."
          BBR: starts entering PROBE_RTT / drain phase
          Cubic: exponential backoff not yet triggered
t=1.0s:   Buffer at 75% (6 MB). Sojourn = 1,920ms. RTT = 1,970ms.

t=1.2s:   ████████████████████ COLLAPSE ████████████████████
          Buffer FULL (8 MB). Kernel starts dropping.
          OR: satellite link saturated → packet loss on WAN.
          Inner QUIC detects: loss + massive RTT spike
          QUIC cwnd HALVES (BBR) or COLLAPSES to 1 segment (Cubic loss)
          Throughput: 25 Mbps → 1.6 Mbps ← FLOOR

t=1.2-1.5s: Queue DRAINS. 8 MB / 25 Mbps = 2.56s drain time.
            But at 1.6 Mbps send rate, drain faster: 8 MB / 1.6 Mbps = 40s??
            NO: kernel drains socket at NIC rate (200 Mbps WAN)
            Socket drains in: 8 MB / 200 Mbps ≈ 320ms

t=1.5s:   Buffer empty. RTT normalizes to 50ms.
          Inner QUIC: "RTT is low again! Ramp up!"
          QUIC re-enters slow start → aggressive ramp

t=2.5s:   Back at 25 Mbps. Buffer filling again.

t=3.8s:   ████████████████████ COLLAPSE AGAIN ████████████████

OBSERVED: 12× throughput oscillation (1.6-20 Mbps), ~10-15 second period.
```

#### The 9 Culprits — Exact File:Line

| # | Culprit | File:Line | What It Does | Why It's Fatal |
|---|---------|-----------|-------------|----------------|
| **1** | `SO_SNDBUFFORCE = 8 MB` | `node/main.rs:891-897` | Node uplink UDP socket buffer | Absorbs all uplink without `EAGAIN` → defeats TSQ on m13tun0 → inner TCP floods |
| **2** | `SO_RCVBUFFORCE = 8 MB` | `node/main.rs:892-894` | Node downlink UDP socket buffer | Absorbs all downlink without backpressure → 8 MB unmanaged FIFO = 1,920ms sojourn at 25 Mbps |
| **3** | Hub SPSC `depth 2048` | `hub/main.rs:218` | TUN HK ↔ datapath SPSC ring | 2048 × 1380B = 2.83 MB unmanaged FIFO → 905ms sojourn at 25 Mbps. No AQM, no drop, pure FIFO |
| **4** | Hub `EdtPacer(100 Mbps)` | `hub/main.rs:~1050` | EDT pacing on TX graph | At 25 Mbps actual rate, gap needed < inter-arrival time → pacer always releases immediately = no-op |
| **5** | Node `EdtPacer(100 Mbps)` | `node/main.rs:868` | EDT pacing on uplink | Same: at actual throughput rates, pacer gap < arrival gap → permanent no-op |
| **6** | `txqueuelen 1000` (both) | `node/datapath.rs:72`, `hub/datapath.rs:868` | TUN device queue depth | 1000 × 1380B = 1.38 MB per side. Another unmanaged FIFO between M13 and kernel TCP |
| **7** | No AQM on m13tun0 | (absent) | Default qdisc = pfifo_fast | No CoDel, no fq_codel, no CAKE. Queue grows until drop. No early signaling |
| **8** | `tune_system_buffers()` | `node/main.rs:286-342` | Sets `rmem_default/wmem_default` to 4 MB | Each inner TCP flow gets 4 MB kernel buffer. Combined with #1: total buffering ≈ 16 MB before any signal |
| **9** | No feedback wiring | `node/main.rs` (absent) | Hub sends feedback frames (loss, RTT) | Node receives them but **never uses** them for rate control. `rx_timestamp_ns`, `delivered`, `loss_count` all ignored |

#### The Total Buffer Stack (worst case)

```text
                         DOWNLINK BUFFER STACK
                         (CDN → User Browser)
  ┌─────────────────────────────────────────────────┐
  │ Satellite modem TX buffer           ≈ ???   MB  │ ← out of our control
  ├─────────────────────────────────────────────────┤
  │ Hub NIC TX ring (256 default)       ≈ 0.35  MB  │ ← ethtool -G
  ├─────────────────────────────────────────────────┤
  │ Hub SPSC ring (depth 2048)          ≈ 2.83  MB  │ ← CULPRIT #3
  ├─────────────────────────────────────────────────┤
  │ Hub AF_XDP TX ring                  ≈ 0.35  MB  │ ← Engine::new_zerocopy
  ├─────────────────────────────────────────────────┤
  │ Node NIC RX ring (256 default)      ≈ 0.35  MB  │ ← ethtool -G
  ├─────────────────────────────────────────────────┤
  │ Node SO_RCVBUFFORCE                 ≈ 8.00  MB  │ ← CULPRIT #2
  ├─────────────────────────────────────────────────┤
  │ Node m13tun0 txqueuelen (1000)      ≈ 1.38  MB  │ ← CULPRIT #6
  ├─────────────────────────────────────────────────┤
  │ Inner TCP rmem_default per flow     ≈ 4.00  MB  │ ← CULPRIT #8
  ├─────────────────────────────────────────────────┤
  │ TOTAL UNMANAGED BUFFER              ≈ 17.26 MB  │
  ├─────────────────────────────────────────────────┤
  │ At 25 Mbps: total sojourn if full   ≈ 5.5 sec   │ ← RTT inflation
  │ At 5 Mbps: total sojourn if full    ≈ 27.6 sec  │ ← but 5 Mbps never fills
  └─────────────────────────────────────────────────┘

  WHY 1×1080p WORKS: 5 Mbps never fills any queue.
  WHY 1×4K DIES:     25 Mbps fills 17 MB in 5.5 seconds → RTT explodes → cwnd collapse.
  WHY 4×1080p DIES:  20 Mbps × 4 flows fills 17 MB in 6.9 seconds → same collapse.
```

#### Why We Are 98% Worse Than Linux

```text
LINUX WITHOUT M13 (200 Mbps):
  Browser → kernel TCP (BBR) → NIC
  BQL: limits NIC queue to ~2 ms of data (≈50 KB)
  TSQ: limits each TCP flow to 128 KB in qdisc
  fq_codel: drops packets with sojourn > 5ms
  TOTAL MANAGED BUFFER: ≈ 0.2 MB
  RTT: 50ms (true wire RTT)
  Throughput: 200 Mbps

LINUX WITH M13 (4-20 Mbps):
  Browser → kernel TCP → m13tun0 → M13 userspace → UDP socket → kernel → NIC
  BQL: bypassed (sendto() into socket buffer, not NIC driver)
  TSQ: defeated (M13 drains TUN instantly → TSQ sees queue empty)
  fq_codel: absent (no AQM on m13tun0)
  TOTAL UNMANAGED BUFFER: ≈ 17 MB (85× more than Linux)
  RTT: 50ms + 5,500ms buffer sojourn = 5,550ms
  Throughput: sawtooth 1.6-20 Mbps, average ≈ 4 Mbps

RATIO: 17 MB / 0.2 MB = 85× more buffering
       5,550ms / 50ms = 111× higher RTT
       4 Mbps / 200 Mbps = 2% throughput retention
```

---

### ❌ Sprint 2.5: Tunnel Collapse — Root Cause & Annihilation

> [!CAUTION]
> **Measured: 200 Mbps raw → 4 Mbps through M13 (98% loss). Tunnel throughput oscillates 12× (1.6–20 Mbps).**
> The EDT pacer is a confirmed no-op (`paced == TUN_R`, `defer=0` always). The tunnel has ZERO congestion control.
> WireGuard (same architecture, in-kernel) retains **90%** throughput. M13 retains **2-10%**. The delta is the 8 MB socket buffer.

#### Root Cause: M13 Defeats Kernel Backpressure

**Why M13 (userspace) loses 98% while WireGuard (kernel) loses only 10%:**

| Mechanism | Without VPN | WireGuard (kernel) | M13 (userspace) |
|-----------|------------|-------------------|-----------------|
| **BQL** (NIC byte limit) | ✅ Active | ✅ Output flows through kernel NIC driver | ❌ `sendto()` into 8 MB socket buffer |
| **TSQ** (~128 KB/flow) | ✅ Active | ✅ Inner TCP limited at TUN qdisc | ❌ M13 drains TUN instantly, TSQ never triggers |
| **fq_codel** (default qdisc) | ✅ On NIC | ✅ On wg0 interface | ❌ No AQM on m13tun0 |
| **RTT visibility** | ✅ True wire RTT | ⚠️ Slightly inflated | ❌ Inner TCP sees ~0ms TUN RTT |
| **Socket buffer** | N/A | N/A (kernel path) | ❌ **8 MB `SO_SNDBUFFORCE`** |
| **per-peer queue** | N/A | 1024 pkts (handshake only) | 2048 SPSC (always active, unmonitored) |
| **Throughput** | 200 Mbps | ~180 Mbps (90%) | **4-20 Mbps (2-10%)** |

**The single root cause: M13's userspace architecture inserts an 8 MB unmanaged FIFO
(the UDP socket buffer) between the TUN interface and the wire, defeating BQL + TSQ.**

```text
CAUSAL CHAIN OF TUNNEL COLLAPSE

Step 1: Inner TCP sends data → TUN qdisc (TSQ limits to ~128 KB per flow ← GOOD)
Step 2: M13 reads from TUN immediately (io_uring/read, never blocks)
Step 3: M13 encrypts → sends into UDP socket (SO_SNDBUFFORCE = 8 MB ← THE KILLER)
Step 4: UDP socket ALWAYS accepts (8 MB buffer never fills at inner TCP's rate)
Step 5: TSQ sees TUN drained → allows inner TCP to send MORE → goto Step 1

RESULT: M13 acts as an infinite drain. Inner TCP sees ~0ms apparent TUN RTT.
        TCP sends at maximum rate. 8 MB socket buffer fills over:
        8 MB / 200 Mbps = 320 ms

Step 6: Socket buffer full → kernel starts queuing at NIC (another 4K+ packets)
Step 7: WAN path saturated → real RTT inflates from 50ms → 370ms+
Step 8: Inner TCP finally detects loss/RTT spike → cwnd COLLAPSES
Step 9: Throughput drops to floor (1.6 Mbps). Queues drain over 320ms
Step 10: RTT normalizes → TCP ramps up → GOTO Step 1

PERIOD: ~10-15 seconds per sawtooth cycle. OBSERVED: 12× throughput variance.
```

> [!NOTE]
> WireGuard's official roadmap lists fq_codel+DQL integration as unfulfilled goals.
> Even with in-kernel advantages, WireGuard still has **higher loaded latency than OpenVPN**
> due to its efficient UDP sending filling downstream buffers faster.
> The OpenWrt community fix: `tc qdisc replace dev wg0 root cake bandwidth Xmbit overhead 80`.

#### Industry Research: How Every Major System Handles Transport

> 19 web searches · 20 systems analyzed · IEEE, ACM, IETF, SIGCOMM, SOSP, open-source repos

##### 1. Google BBR (IETF draft-cardwell-iccrg-bbr)

**What it is**: Model-based congestion control. Deployed on Google.com, YouTube, GCP.

**How it works**:
- **MEASURE**: `BtlBw = max(delivered_bytes / interval)` over 10 RTTs. `RTprop = min(rtt)` over 10-second window.
- **PACE**: EDT pacing at `BtlBw` rate. Pacing is MANDATORY — BBR cannot function without it.
- **BOUND**: `inflight ≤ BDP × gain`. During STARTUP gain=2.89, PROBE_BW gain=1.0/1.25, DRAIN gain=0.75.
- **SIGNAL**: Probes for more bandwidth periodically. Drains excess if overshoot detected. No loss-based signal.

**Lesson for M13**: M13 has `delivered_bytes` (feedback) and `rx_timestamp_ns` (RTT). Both unwired. Wire them → instant BBR-lite.

##### 2. Google Swift (SIGCOMM 2020)

**What it is**: Delay-based CC for datacenter. 50µs tail latency at 100 Gbps, loss rates 10× lower than DCTCP.

**How it works**:
- **MEASURE**: RTT decomposition — separates fabric delay (NIC-to-NIC) from host delay (endpoint). Uses NIC hardware timestamps.
- **PACE**: AIMD on `cwnd` with delay target. `if rtt < target: cwnd += α` / `if rtt > target: cwnd *= β`
- **BOUND**: `cwnd`-based inflight limit.
- **SIGNAL**: Pure delay (no loss, no ECN needed). Simpler than BBR state machine.

**Lesson for M13**: Swift's simplicity makes it the best fit for M13. No probe/drain state machine. Just: `if RTT rising → slow down, if RTT falling → speed up`. M13's keepalive RTT can drive this directly.

##### 3. Google Snap / Pony Express (SOSP'19)

**What it is**: Userspace networking microkernel. 3× Gbps/core vs kernel. Runs all of Google's VM networking.

**How it works**:
- Custom transport "Pony Express" with per-flow RTT, delivered bytes, delay-based CC (Swift/Timely).
- **Userspace** — bypasses kernel entirely BUT builds its own CC. Does NOT defer to kernel.
- Per-flow pacing, per-flow inflight tracking, per-flow AQM.

**Lesson for M13**: M13 is architecturally identical to Snap — it bypasses kernel (io_uring/AF_XDP) and needs its OWN CC. "Transparent glass" is wrong. Snap proves userspace transport MUST have its own CC.

##### 4. Amazon SRD (IEEE Micro 2020)

**What it is**: Custom transport on Nitro NIC hardware. 85% P99.9 latency reduction vs TCP. 25 Gbps single-flow.

**How it works**:
- **Hardware CC**: Rate limiting per-connection in NIC silicon. Sub-millisecond retransmission.
- **Per-path pacing**: Sprays packets across up to 64 paths. Each path has its own CC.
- **Out-of-order delivery**: App reorders. Eliminates head-of-line blocking.

**Lesson for M13**: Per-path pacing in hardware = Sprint 3+ FPGA target. Software BBR/Swift now, hardware SRD later.

##### 5. Meta mvfst (GitHub, open-source)

**What it is**: C++ QUIC implementation. 75% of Meta's internet traffic (Facebook, Instagram). Open-source.

**How it works**:
- **Pluggable CC**: Copa (delay-based, MIT), BBR, Cubic — switchable at runtime.
- **Copa**: Delay-based, targets `1/(δ × RTT_standing)` rate. Great for video where latency matters more than throughput.
- **QUIC Jump Start**: Caches CC state per-destination. New connections start at cached rate, not slow-start.

**Lesson for M13**: Copa is superior to BBR for video streaming (lower latency). M13 carries MAVLink/video — Copa's delay-targeting is ideal. Also: cache CC state across reconnects (M13's Make-Before-Break handshake could carry cached BtlBw/RTprop).

##### 6. ByteDance / TikTok (IEEE)

**What it is**: BBR-E2E — modified BBR with player↔edge collaboration. libtpa — DPDK userspace TCP.

**How it works**:
- **BBR-E2E**: Video player reports buffer status to edge server. Edge adjusts sending rate to match playback consumption. Result: 1.6% rebuffer reduction, 6.2% fewer rebuffer events globally.
- **libtpa**: DPDK-based userspace TCP stack. Kernel-bypass for selected accelerated connections. Significant p99 latency reduction.

**Lesson for M13**: Application-layer feedback (buffer status) integrated into transport CC = powerful. M13 could carry drone telemetry (battery, mission priority) as CC input. libtpa validates that kernel-bypass + custom CC is the correct architecture.

##### 7. Netflix Open Connect

**What it is**: 19,000+ OCAs in 1,500+ ISP locations. Custom adaptive concurrency.

**How it works**:
- **Adaptive concurrency limits**: Based on TCP CC algorithms — dynamically discovers max inflight requests before latency degrades.
- **Prioritized load shedding**: Drops lower-priority requests as utilization increases.
- **ABR**: Adaptive bitrate at application layer.

**Lesson for M13**: Adaptive concurrency limits = exactly what M13's inflight gate should do. Netflix uses CC algorithms for RPC load management — M13 should use CC for tunnel packet management.

##### 8. Google YouTube / QUICHE (open-source QUIC)

**What it is**: BBR deployed on all YouTube traffic via QUIC/HTTP3. QUICHE is open-source.

**How it works**:
- All YouTube video streaming uses BBR over QUIC on UDP port 443.
- Pacing is built into QUICHE's send path. Rate = BtlBw.
- BBRv2 adds loss signal integration + ECN awareness.

**Lesson for M13**: YouTube streams 4K video at 50+ Mbps over UDP with BBR pacing. M13 carries the same video but collapses to 4 Mbps. The difference: YouTube has BBR, M13 has nothing.

##### 9. Cloudflare BoringTun + quiche

**What it is**: BoringTun = Rust WireGuard (no CC). quiche = Rust QUIC (has CC). Cloudflare migrating WARP from BoringTun to MASQUE/QUIC.

**How it works**:
- **BoringTun**: Pure WireGuard. Encrypt→encapsulate→send. **Zero congestion control**. Relies on inner TCP.
- **quiche**: Pluggable CC (Reno, Cubic, BBRv2). Delivery rate estimation + windowed min-max filters.
- **MASQUE migration**: Cloudflare is moving WARP from WireGuard to QUIC-based MASQUE for better CC, multiplexing, and coalescing.

**Lesson for M13**: Cloudflare realized WireGuard (like M13) has no CC and is migrating to QUIC. M13 should add CC to its existing protocol rather than migrating to QUIC entirely. But the lesson is clear: **a tunnel without CC is not production-grade**.

##### 10. WireGuard Kernel Module — BUFFERBLOAT DEEP DIVE

**What it is**: Linux kernel VPN. Fastest consumer VPN. No built-in CC. **Retains ~90% throughput** (vs M13's 2-10%).

**Internal queues**:
- **`peer_queue`**: 1024 `MAX_QUEUED_PACKETS` per peer — handshake-only accumulation, oldest dropped when full.
- **MPMC decrypt queue**: Per-device for parallel crypto, feeds per-peer serial RX queue.
- **No AQM, no CoDel, no BQL internally** — processes & forwards as fast as possible.

**WireGuard's bufferbloat problem** (confirmed):
- WireGuard has **higher loaded latency than OpenVPN** despite higher throughput — classic bufferbloat.
- Efficient UDP sending fills downstream buffers faster than OpenVPN's less efficient TCP-based sending.
- RTT under load inflates significantly, but throughput stays high (90%) because kernel mechanisms (BQL, TSQ, fq_codel) are still active.

**Why WireGuard retains 90% while M13 retains 2-10%**:

| Mechanism | WireGuard (kernel) | M13 (userspace) |
|-----------|-------------------|-----------------|
| **BQL** | ✅ Active — output goes through kernel NIC driver | ❌ `sendto()` into 8 MB socket buffer bypasses BQL |
| **TSQ** | ✅ Inner TCP limited at TUN qdisc | ❌ M13 drains TUN instantly, TSQ never triggers |
| **fq_codel** | ✅ Default qdisc on wg0 | ❌ No AQM on m13tun0 |
| **Socket buffer** | N/A (kernel-to-kernel path) | ❌ **8 MB `SO_SNDBUFFORCE` — the killer** |

**Community fix** (OpenWrt SQM best practice):
```bash
tc qdisc replace dev wg0 root cake bandwidth 200mbit overhead 80
```
- Apply CAKE on wg0 interface (not physical NIC)
- 80 bytes WireGuard encap overhead for CAKE accounting
- Bandwidth at 80-95% of measured link speed
- `dual-srchost`/`dual-dsthost` for per-host fairness behind NAT

**Official roadmap** (wireguard.com/todo — all unfulfilled):
- ❌ fq_codel integration, ❌ DQL, ❌ GRO support, ❌ Lock-free queues, ❌ Core autoscaling

**`skb->hash` preservation patch**: Ensures qdisc (fq_codel/CAKE) on wg0 can identify inner flows correctly across encap/decap boundary.

**Lesson for M13**: (A) The 8 MB socket buffer is the single variable explaining the 90% vs 2-10% gap. (B) Even WireGuard (in-kernel, with BQL/TSQ/fq_codel) still has bufferbloat — it just doesn't collapse throughput because kernel mechanisms prevent queue explosion. (C) M13 must replicate BQL+TSQ+fq_codel in userspace since it bypasses all three. (D) CAKE with overhead accounting (62B for M13) on TUN interface matches the WireGuard community fix. (E) `skb->hash` preservation = M13 should preserve flow hash for qdisc integration.

##### 11. Tailscale

**What it is**: WireGuard-based mesh VPN. TUN GSO/GRO for 4× throughput. DERP relay for NAT traversal.

**How it works**:
- **TUN GSO/GRO**: Batch 64KB of TUN reads/writes per syscall. Kernel ≥6.2. 4× throughput.
- **DERP**: "Dumb pipe" encrypted relay. No CC. Optimized for availability, not throughput.
- **Peer relays**: For throughput-sensitive paths, uses on-network peer relays instead of shared DERP.

**Lesson for M13**: TUN GSO/GRO is mandatory (4× gain). M13's Hub DERP-like relay should also be "dumb" for data — CC belongs at endpoints (Node and Hub's TUN interfaces), not the relay.

##### 12. Nebula (Slack/Defined Networking)

**What it is**: Open-source mesh overlay. Noise Protocol framework. Lighthouse discovery.

**How it works**:
- `tx_queue` configurable queue depth per node.
- No built-in CC — relies on inner TCP.
- Research variant uses FEC + adaptive bitrate for cloud gaming.

**Lesson for M13**: Nebula is architecturally similar to M13 (mesh overlay, Noise-like auth). Its tx_queue = M13's SPSC. Neither has CC = both have the same bufferbloat problem.

##### 13. VpnCloud (Rust P2P mesh VPN, GitHub)

**What it is**: High-performance Rust VPN with peer-to-peer meshing over UDP.

**How it works**:
- TUN/TAP interface, ChaCha20-Poly1305 encryption, NAT traversal.
- No CC. Relies on inner TCP.

**Lesson for M13**: Another Rust VPN with identical architecture to M13 and identical CC gap.

##### 14. StarQUIC (ACM LEOnet 2023)

**What it is**: QUIC tuned for Starlink LEO satellite handovers (every 15 seconds).

**How it works**:
- Detects imminent handover → freezes cwnd → resumes at cached rate post-handover.
- 35% completion time improvement vs standard QUIC.

**Lesson for M13**: M13 operates over SATCOM. Must be handover-aware. Don't collapse cwnd on satellite switch. Cache CC state across Make-Before-Break handshakes.

##### 15. LeoCC (APNIC 2024)

**What it is**: LEO-specific CC. Reconfiguration-aware.

**How it works**:
- Detects LEO satellite reconfiguration intervals (15s for Starlink).
- Avoids misinterpreting handover latency spikes as congestion.
- Maintains stable sending rate across beam switches.

**Lesson for M13**: M13's Hub is a "flying telco" — beam switches and satellite handovers are its operating environment. LeoCC's reconfiguration awareness must be built into M13's CC.

##### 16. Linux BQL + TSQ

**What it is**: Layered backpressure in kernel networking stack.

**How it works**:
- **BQL**: NIC driver reports `netdev_tx_sent_queue()` / `netdev_tx_completed_queue()`. Dynamic byte limit. Shifts queue management from NIC FIFO to qdisc layer.
- **TSQ**: Per-TCP-socket limit (~128 KB) in qdisc. Prevents any single flow from monopolizing.

**Lesson for M13**: BQL principle = M13 must track bytes-in-flight at every queue stage. TSQ principle = M13 must limit inflight per-peer, not globally.

##### 17. CoDel (RFC 8289)

**What it is**: AQM algorithm. Sojourn time based. 5ms target.

**How it works**:
- Timestamp packet on enqueue. Check sojourn time on dequeue.
- If min(sojourn) over 100ms interval > 5ms target → drop packet.
- Self-tuning: drop frequency increases as congestion persists.

**Lesson for M13**: CoDel on `DeferredTxRing` = ~20 lines of code. Timestamp already exists (EDT release_ns). Add sojourn check on ring pop.

#### The Universal Architecture

Every single system above that achieves high throughput implements the same 4-phase loop:

```text
┌──────────────────────────────────────────────┐
│           MEASURE → PACE → BOUND → SIGNAL    │
│                                              │
│  MEASURE: RTT + delivered bytes + loss        │
│  PACE:    EDT departure at measured rate      │
│  BOUND:   inflight ≤ BDP = BtlBw × RTprop    │
│  SIGNAL:  Drop/mark when queue sojourn > 5ms  │
└──────────────────────────────────────────────┘
```

Systems **without** this loop (BoringTun, Nebula, VpnCloud, current M13) all have the same problem: **inner TCP floods the tunnel, buffers fill, throughput collapses.**

Systems **with** this loop (BBR, Swift, SRD, mvfst, QUICHE) achieve line-rate throughput with bounded latency.

#### M13 CC Architecture Design

##### Design: Swift-style Delay-Based CC + BBR-calibrated BtlBw + CoDel AQM

```text
NODE (sender):
  TUN read ──→ [INFLIGHT GATE] ──→ encrypt ──→ [EDT PACER] ──→ UDP send
                    ↑                                              │
                    │              ┌──────────┐                    │
                    └──────────────│ CC STATE  │←───────────────────┘
                                  └──────────┘  (feedback frame)

CC STATE per-peer:
  btl_bw    = max(delivered_bytes / interval) over 10 RTT window
  rt_prop   = min(rtt) over 10-second window
  bdp       = btl_bw × rt_prop
  inflight  = bytes_sent - bytes_acked
  cwnd      = bdp × gain

GATE:  if inflight >= cwnd → STOP reading from TUN (backpressure!)
PACE:  EdtPacer::set_link_bps(btl_bw)   ← dynamic, not 100 Mbps
SIGNAL: CoDel on DeferredTxRing (sojourn > 5ms → drop)
```

##### Why Swift over BBR

| Property | BBR | Swift | M13 Fit |
|----------|-----|-------|---------|
| State machine | Complex (STARTUP→DRAIN→PROBE_BW→PROBE_RTT) | Simple AIMD | M13 needs simplicity — drone firmware |
| Signal | Delivery rate model | RTT delta | M13 has RTT from keepalive |
| Pacing | Mandatory | Optional (cwnd-based) | M13 has EdtPacer ready |
| Loss handling | Ignores loss | Responds to loss | MANET has real loss (not just congestion) |
| Fairness | BBRv1 unfair to Cubic | Fair via AIMD | M13 has 1 peer — fairness irrelevant |

#### Fix 0 — Kill the Root Cause (MANDATORY, immediate)

| # | Fix | What It Does | Location |
| --- | --- | --- | --- |
| **1** | **Clamp `SO_SNDBUF` to BDP** | At 200 Mbps × 50ms RTT, BDP = 1.25 MB. Set `SO_SNDBUF` = 1.5 MB. `sendto()` returns `EAGAIN` when buffer is full → M13 stops draining TUN → TUN qdisc fills → TSQ kicks in → inner TCP gets natural backpressure. **This single fix restores the kernel's native congestion control.** | Node `main.rs:266` — change `SO_SNDBUFFORCE` from 8388608 → 1572864 |
| **2** | **Clamp `SO_RCVBUF` to BDP** | Same logic for receive path. 8 MB receive buffer absorbs bursts that should trigger backpressure. | Node `main.rs:266` — change `SO_RCVBUFFORCE` from 8388608 → 1572864 |
| **3** | **Clamp `txqueuelen` → 20** | Currently 1000 on both sides = 1.38 MB standing queue. With CAKE doing flow management, 20 packets suffices. | Node `datapath.rs:72`, Hub `datapath.rs:868` |
| **4** | **Remove EDT pacer from Node** | Confirmed no-op at all actual throughput rates. Adds overhead (DeferredTxRing push/pop per packet) with zero benefit. Self-throttling is wrong when tunnel can't reach link speed. Re-introduce ONLY when WiFi RF micro-burst control is needed (Sprint 3+). | Node `main.rs` — bypass DeferredTxRing, direct send |
| **5** | **Clamp Hub SPSC ring depth → 256** | Currently 2048 = 2.83 MB unmanaged FIFO (Culprit #3). At 25 Mbps fills in 0.9s with 905ms sojourn. Reduce to 256 = 354 KB ≈ BDP. When ring full, TUN HK thread blocks on `push()` → `read(tun_fd)` stalls → kernel TUN queue fills → AQM kicks in on Hub m13tun0. | Hub `main.rs:218` — change SPSC ring depth from 2048 → 256 |

#### Fix 1 — Active Queue Management

| # | Fix | What It Does | Location |
| --- | --- | --- | --- |
| **6** | **CAKE qdisc on TUN** | AQM + per-flow fairness + bandwidth shaping. `tc qdisc replace dev m13tun0 root cake bandwidth 200mbit overhead 62` (62B = M13 encap overhead, cf. WireGuard community uses 80B). Actively drops/marks when queue sojourn > target. | Node + Hub `datapath.rs` (`create_tun`) |
| **7** | **MSS clamping** | Inner TCP negotiates 1460B MSS → 1522B after M13 header → exceeds 1380B MTU → kernel fragments → double loss probability. Clamp MSS to 1318B → zero fragmentation. | Node + Hub `setup_tunnel_routes()` / `setup_nat()` |
| **8** | **`tcp_notsent_lowat` → 131072** | App-level backpressure valve. Limits unsent data in kernel TCP send buffer to 128 KB. Without it, apps dump unlimited data into kernel → M13 drains unlimited data into socket → buffer amplification. | Node `tune_system_buffers()` |
| **9** | **Hub EDT pacer → dynamic from feedback RTT** | Currently 100 Mbps hardcoded = permanent no-op (Culprit #4). Pacer only throttles if actual rate > link_bps. Fix: set `link_bps` to measured bottleneck rate from feedback frames (initially = satellite uplink speed, e.g. 25 Mbps). EDT then enforces real inter-packet gaps. | Hub `main.rs` EdtPacer + `uso_pacer.rs:set_link_bps()` |
| **10** | **Wire Hub feedback → Node rate control** | Hub already sends feedback every 32 pkts (Culprit #9): `rx_timestamp_ns`, `delivered`, `loss_count`, `nack_bitmap`. Node receives these but **discards them**. Wire into a minimal `CcState`: compute RTT, track `delivered_bytes`, gate TUN reads when `inflight > cwnd`. | Node `main.rs` feedback → new `cc.rs` or inline |

#### Fix 2 — Kernel Stack Tuning

| # | Fix | What It Does | Location |
| --- | --- | --- | --- |
| **11** | **`netdev_max_backlog` → 300** | Currently 10,000 = 550ms of kernel ingress buffering. Reduce to 300 (~16ms). | Node `tune_system_buffers()` |
| **12** | **`rmem_default`/`wmem_default` → 262144** | Currently 4 MB per socket. Each inner TCP flow gets 4 MB kernel buffer. 256 KB ≈ BDP. | Node `tune_system_buffers()` |
| **13** | **`nf_conntrack` NOTRACK** | Conntrack processes every forwarded packet twice. M13 traffic is AEAD-authenticated — conntrack is redundant overhead. | Hub `setup_nat()`, Node `setup_tunnel_routes()` |
| **14** | **NIC ring buffer depth → 128** | Default NIC rings (256–4096) = 6 MB hardware buffer invisible to AQM. Clamp to 128. | Hub pre-flight, Node `tune_system_buffers()` |

#### Fix 3 — Throughput Recovery

| # | Fix | What It Does | Location |
| --- | --- | --- | --- |
| **15** | **TUN UDP GSO/GRO** | Tailscale: **4× throughput** on kernel ≥6.2. Batch TUN reads/writes into 64KB aggregates. Amortize per-packet overhead. | Node + Hub `create_tun()` |
| **16** | **`rx-udp-gro-forwarding` ethtool** | Preserve GRO aggregation across TUN↔physical forwarding path. | Hub + Node `tune_system_buffers()` |

#### Fix 4 — Protocol-Level (deferred, re-evaluate after Fix 0–3)

| # | Fix | What It Does | Location |
| --- | --- | --- | --- |
| **17** | **ECN pass-through (RFC 6040)** | Copy inner IP ECN → outer IP header. WAN routers ECN-mark instead of drop. | Both `seal_frame` / `process_rx_frame` |

#### Fix 5 — Micro-Optimization (background)

| # | Fix | What It Does | Location |
| --- | --- | --- | --- |
| **18** | Remove redundant `submit_and_wait(0)` | SQPOLL only needs `submit()` | Node `main.rs` loop tail |
| **19** | Hub `rx_descs` → `#[repr(C)]` struct | Eliminate tuple padding waste | Hub `main.rs` STAGE 0 |
| **20** | `DeferredTxRing` → `align(64)` | Prevent false sharing (if retained after #4) | Node `engine/protocol.rs` |
| **21** | `DeferredTxRing` HWM telemetry | Max queue depth diagnostic (if retained after #4) | Node `main.rs` telemetry |
| **22** | Hub SPSC TUN ring HWM telemetry | Expose `tx_tun`/`rx_tun` queue depth (now 256, was 2.8 MB unmonitored) | Hub `main.rs` telemetry |
| **23** | Node `pin_to_core` | Eliminate scheduler migration jitter | Node `main.rs` startup |

#### Fix 6 — M13 CC Engine (MEASURE → PACE → BOUND → SIGNAL)

> Research source: BBR (#1), Swift (#2), Snap (#3), mvfst/Copa (#5), Netflix (#7), QUICHE (#8), BQL+TSQ (#16), CoDel (#17)

| # | Fix | What It Does | Location |
| --- | --- | --- | --- |
| **24** | **`CcState` struct** | Per-peer CC state: `btl_bw: u64` (max delivered bytes/interval, 10-RTT window), `rt_prop: u64` (min RTT, 10-sec window), `bdp: u64` (btl_bw × rt_prop), `inflight: u64` (bytes_sent − bytes_acked), `cwnd: u64` (bdp × gain), `delivered: u64`, `last_ack_seq: u64`. All Q16.16 fixed-point where needed. Cache-line aligned (`#[repr(C, align(64))]`). | Node `network/cc.rs` [NEW] |
| **25** | **`on_feedback()` — parse Hub feedback** | Hub already sends feedback every 32 pkts (#10). This function parses `rx_timestamp_ns` → compute RTT sample. `delivered` → compute delivery rate. `loss_count` → increment loss counter. Updates `btl_bw = max(delivery_rate)` over 10-RTT sliding window. Updates `rt_prop = min(rtt)` over 10-second window. Computes `bdp = btl_bw × rt_prop`. Sets `cwnd = bdp × gain`. | Node `network/cc.rs::on_feedback()` [NEW] |
| **26** | **Swift AIMD CC algorithm** | The CC core. On each feedback: `if rtt < target_delay: cwnd += α` (additive increase). `if rtt > target_delay: cwnd = cwnd × β` (multiplicative decrease). `target_delay = rt_prop + ε_proc` (fabric delay + processing floor). `α = 1 MSS per RTT`. `β = 0.8` (Swift default, less aggressive than Cubic's 0.7). No state machine (unlike BBR's STARTUP/DRAIN/PROBE_BW/PROBE_RTT). | Node `network/cc.rs::swift_update()` [NEW] |
| **27** | **Inflight gate — TUN read suppression** | **THE** backpressure mechanism. In CQE main loop: `if cc.inflight >= cc.cwnd → DO NOT arm TUN reads`. Node stops reading from m13tun0 → TUN qdisc fills → TSQ kicks in on inner TCP → inner TCP sees backpressure → natural cwnd reduction. This is the BQL/TSQ equivalent for userspace. When `inflight < cwnd`, re-arm TUN reads. | Node `main.rs` — gate `arm_tun_read()` behind `cc.should_send()` |
| **28** | **`on_send()` — inflight tracking** | Every packet sent: `cc.inflight += frame_bytes`. Every feedback received: `cc.inflight -= acked_bytes` (from `delivered` delta). Tracks bytes-in-flight at the M13 tunnel layer, not the inner TCP layer. This is the BQL principle: know exactly how many bytes are in the pipe. | Node `main.rs` — after `stage_udp_send()` |
| **29** | **BtlBw estimator — windowed max filter** | `btl_bw = max(delivered_bytes / interval)` over a sliding window of 10 RTTs (BBR's algorithm). Uses a circular buffer of 10 delivery rate samples. On each feedback, compute `rate = (delivered_now − delivered_prev) / (time_now − time_prev)`. Push to window. `btl_bw = max(window)`. This drives EDT pacer: `set_link_bps(btl_bw)`. | Node `network/cc.rs::update_btl_bw()` [NEW] |
| **30** | **EDT pacer ← dynamic `btl_bw`** | Replace hardcoded 100 Mbps with `edt_pacer.set_link_bps(cc.btl_bw)` on every feedback. Pacer now enforces real inter-packet gaps at measured bottleneck rate. At 25 Mbps: gap = 1380B × 320ns = 442µs (real pacing). Supersedes #9 (Hub static recalibration) with dynamic feedback-driven rate. | Node `main.rs` — after `on_feedback()` |
| **31** | **CoDel sojourn check on Hub SPSC ring** | Timestamp each `PacketDesc` on SPSC `push()`. On `pop()`, check `sojourn = now − enqueue_ts`. If `min(sojourn) > 5ms` over last 100ms interval → drop packet instead of transmitting. Self-tuning: drop interval decreases as congestion persists (`interval / sqrt(drops)`). ~20 lines. Prevents the 905ms sojourn at 25 Mbps (Culprit #3 defense-in-depth alongside #5 depth reduction). | Hub `main.rs` TUN HK thread Phase 1 TX |
| **32** | **Per-queue bytes-in-flight tracking** | BQL principle applied to every M13 queue stage. Track `bytes_enqueued` and `bytes_dequeued` on: (A) Hub SPSC ring, (B) Node DeferredTxRing (if retained), (C) Node UDP socket (estimate from `inflight`). Expose via telemetry. Alert if any stage exceeds BDP. | Hub `main.rs`, Node `main.rs` — telemetry counters |
| **33** | **Flow hash preservation for qdisc** | WireGuard's `skb->hash` patch ensures fq_codel/CAKE on wg0 can identify inner flows. M13 must do the same: when writing to TUN, set `skb->hash` from inner IP 5-tuple hash so CAKE on m13tun0 provides per-flow fairness (not per-packet FIFO). Requires `IFF_TUN` with `IFF_NAPI` or manual `SO_MARK` per-flow. | Node + Hub `datapath.rs` TUN write path |

#### Fix 7 — Satellite-Aware CC

> Research source: StarQUIC (#14), LeoCC (#15), mvfst Jump Start (#5), ByteDance BBR-E2E (#6)

| # | Fix | What It Does | Location |
| --- | --- | --- | --- |
| **34** | **Handover-aware cwnd freeze (StarQUIC)** | Detect imminent satellite handover or Make-Before-Break rekey: freeze `cwnd` at current value instead of collapsing to 1 MSS. On reconnect, resume at cached `cwnd` + `btl_bw` + `rt_prop`. 35% completion time improvement vs standard CC. Handover detection: RTT spike > 3× `rt_prop` AND loss burst within 1 RTT window = handover, not congestion. | Node `network/cc.rs::on_handover()` [NEW] |
| **35** | **LeoCC reconfiguration awareness** | Starlink beam switches cause 15-second reconfiguration intervals with latency spikes. Normal CC misinterprets as congestion → collapses rate → recovers slowly. Fix: maintain separate `rt_prop_stable` (excluding handover samples) and `rt_prop_raw`. If `rt_prop_raw > 2 × rt_prop_stable` AND `loss_rate < 1%` → reconfiguration event, NOT congestion → hold rate steady. | Node `network/cc.rs::classify_rtt_event()` [NEW] |
| **36** | **CC state cache across Make-Before-Break** | M13's PQC rekey performs Make-Before-Break: new session key negotiated while old tunnel still active. Current behavior: rekey → `NodeState::Registering` → all CC state lost → slow start from zero. Fix: carry `CcState {btl_bw, rt_prop, cwnd}` across rekey. New session starts at cached rate (mvfst's QUIC Jump Start pattern). | Node `main.rs` — `RxAction::RekeyNeeded` handler |
| **37** | **Copa delay-targeting for video priority** | M13 carries MAVLink (latency-critical) and video (throughput-critical). Copa targets `rate = 1/(δ × RTT_standing)`. For MAVLink flows: `δ = 0.5` (latency-biased). For video flows: `δ = 0.1` (throughput-biased). Flow classification from inner IP DSCP or port range. Deferred until #26 (Swift AIMD) is validated — Copa is Swift's evolution. | Node `network/cc.rs::copa_update()` [NEW, deferred] |

#### Fix 8 — Hub Symmetric CC

> Research source: Snap (#3) — both endpoints need CC. Netflix (#7) — adaptive concurrency at both sides.

| # | Fix | What It Does | Location |
| --- | --- | --- | --- |
| **38** | **Hub `CcState` per-peer (mirror of Node)** | Hub currently sends at AF_XDP wire speed for downlink (Hub→Node). No rate control. Mirror Node's `CcState` on Hub side: `btl_bw` from Node's ACK rate, `rt_prop` from Node feedback roundtrip. Hub EDT pacer at `btl_bw` per-peer. Inflight gate on Hub SPSC pop: if `inflight >= cwnd → stop popping from SPSC → TUN HK stalls → TUN AQM kicks in`. | Hub `network/cc.rs` [NEW], Hub `main.rs` TX graph |
| **39** | **Node → Hub feedback frames** | Currently only Hub→Node feedback exists (#10). For symmetric CC, Node must also send feedback to Hub: `highest_seq_received`, `rx_timestamp_ns`, `delivered`, `loss_count`. Piggyback on uplink keepalive or allocate every 32nd uplink packet as feedback. Hub's `on_feedback()` parses these to drive Hub-side CC. | Node `main.rs` — new `produce_node_feedback()`, Hub `main.rs` — parse in RX graph |
| **40** | **Hub per-peer EDT pacing from CC** | Hub's current EdtPacer is global (one rate for all peers). With CC, each peer has its own `btl_bw`. Hub must pace per-peer: after `seal_frame()`, call `peer.edt_pacer.pace(now, frame_len)` → per-peer `release_ns`. Scheduler already has per-peer Scheduler rings — wire EDT into the per-peer path. | Hub `main.rs` TX graph — per-peer `EdtPacer` instances |

#### Culprit → Fix Cross-Reference

| Culprit # | Description | Fix # | Fix Group |
|-----------|-------------|-------|-----------|
| **1** | `SO_SNDBUFFORCE = 8 MB` | #1 | Fix 0 |
| **2** | `SO_RCVBUFFORCE = 8 MB` | #2 | Fix 0 |
| **3** | Hub SPSC depth 2048 (2.83 MB FIFO) | #5, #31 | Fix 0, Fix 6 |
| **4** | Hub EdtPacer 100 Mbps (permanent no-op) | #9, #30 | Fix 1, Fix 6 |
| **5** | Node EdtPacer 100 Mbps (permanent no-op) | #4, #30 | Fix 0, Fix 6 |
| **6** | `txqueuelen 1000` both sides | #3 | Fix 0 |
| **7** | No AQM on m13tun0 | #6 | Fix 1 |
| **8** | `tune_system_buffers()` 4 MB defaults | #12 | Fix 2 |
| **9** | No feedback wiring (RTT/loss ignored) | #10, #25-#30 | Fix 1, Fix 6 |

#### Research → Fix Cross-Reference

| Research System | Key Lesson | Fix # |
|-----------------|-----------|-------|
| **BBR** (#1) | `BtlBw = max(delivered/interval)`, EDT pacing, BDP bound | #25, #29, #30 |
| **Swift** (#2) | AIMD on cwnd, delay target = `rt_prop + ε`, simplicity | #26 (core algorithm) |
| **Snap/Pony Express** (#3) | Userspace transport MUST have own CC | #24-#33 (entire Fix 6) |
| **Amazon SRD** (#4) | Per-path pacing in hardware | Sprint 3+ FPGA (out of scope) |
| **Meta mvfst/Copa** (#5) | Copa delay-targeting, CC state cache across reconnect | #36, #37 |
| **ByteDance BBR-E2E** (#6) | App-layer feedback into transport CC | #37 (DSCP-based flow priority) |
| **Netflix** (#7) | Adaptive concurrency limits = inflight gate | #27 |
| **YouTube/QUICHE** (#8) | BBR pacing over UDP for video | #29, #30 |
| **Cloudflare BoringTun→MASQUE** (#9) | Tunnel without CC is not production-grade | Entire Sprint 2.5 |
| **WireGuard** (#10) | `skb->hash` preservation, CAKE overhead, kernel vs userspace | #5, #6, #33 |
| **Tailscale** (#11) | TUN GSO/GRO = 4× throughput | #15 |
| **Nebula** (#12) | Same architecture, same problem | Validates Sprint 2.5 |
| **VpnCloud** (#13) | Same architecture, same problem | Validates Sprint 2.5 |
| **StarQUIC** (#14) | Handover-aware cwnd freeze | #34 |
| **LeoCC** (#15) | Reconfiguration-aware CC | #35 |
| **Linux BQL+TSQ** (#16) | Per-queue byte tracking, per-flow inflight limit | #27, #28, #32 |
| **CoDel** (#17) | Sojourn-based AQM on internal queues | #31 |

#### Fix 9 — Code-Level Defects (discovered in deep audit)

> These are **bugs and contradictions in the current source code** — not architectural issues.
> Each is a concrete line of code that actively harms performance or correctness.

| # | Defect | File:Line | What's Wrong | Fix |
| --- | --- | --- | --- | --- |
| **41** | **`tune_system_buffers()` sets `rmem_default=4MB`** | `node/main.rs:317` | Sets `net.core.rmem_default=4194304` and `wmem_default=4194304`. Every inner TCP socket gets 4 MB kernel buffer = amplifies bufferbloat. Fix #12 prescribes 262144. **This function creates the problem Fix #12 must undo.** | Change values to `262144` in-place |
| **42** | **`tune_system_buffers()` sets `netdev_max_backlog=10000`** | `node/main.rs:326` | Sets ingress backlog to 10,000 = 550ms of kernel buffering. Fix #11 prescribes 300. **Self-inflicted bloat.** | Change to `300` |
| **43** | **`setup_tunnel_routes()` sets `rmem_max=16MB`** | `node/datapath.rs:154-156` | Overwrites `tune_system_buffers()` with **worse** values: `rmem_max=16777216`, `wmem_max=16777216`. This 16 MB ceiling allows inner TCP to buffer 16 MB per flow. | Remove or reduce to `1572864` (BDP) |
| **44** | **`setup_tunnel_routes()` sets `tcp_rmem` max to 16 MB** | `node/datapath.rs:158-160` | `tcp_rmem=4096 1048576 16777216` — max 16 MB per TCP socket. At 200 Mbps this is 640ms of data per flow. Combined with #43: kernel can buffer 32 MB per flow (16 snd + 16 rcv). | `tcp_rmem=4096 131072 1572864` |
| **45** | **`setup_tunnel_routes()` sets `tcp_wmem` max to 16 MB** | `node/datapath.rs:159-160` | Same as #44 for write buffer. | `tcp_wmem=4096 131072 1572864` |
| **46** | **TUN qdisc = `fq` not CAKE** | `node/datapath.rs:183` | `tc qdisc replace dev m13tun0 root fq` — fair queueing only, NO bandwidth shaping, NO overhead accounting, NO sojourn-based drops. Fix #6 prescribes CAKE with `bandwidth 200mbit overhead 62`. **This is the active AQM gap** (Culprit #7). | Replace with `cake bandwidth 200mbit overhead 62` |
| **47** | **MSS clamping uses `--clamp-mss-to-pmtu`** | `node/datapath.rs:175` | Relies on PMTUD which fails over UDP tunnels (ICMP Fragmentation Needed never reaches inner TCP). Fix #7 prescribes explicit `--set-mss 1318`. | `iptables -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1318` |
| **48** | **Sysctl config duplicated and contradictory** | `node/main.rs:286-340` + `node/datapath.rs:152-168` | `tune_system_buffers()` and `setup_tunnel_routes()` both set the same sysctls with DIFFERENT values. `tune_system_buffers` runs first but `setup_tunnel_routes` overwrites later with worse values. | Consolidate into one function. Delete sysctl from `setup_tunnel_routes`. |
| **49** | **`tune_system_buffers()` sets `rmem_max=8MB`** | `node/main.rs:316` | `net.core.rmem_max=8388608` — allows `SO_RCVBUFFORCE` up to 8 MB. This is the ceiling that enables Culprit #2. Lower to BDP (1.5 MB). | Change to `1572864` |
| **50** | **`tune_system_buffers()` sets `wmem_max=8MB`** | `node/main.rs:316` | Same for write. Enables Culprit #1. | Change to `1572864` |
| **51** | **`setup_tunnel_routes()` netdev_budget=600** | `node/datapath.rs:166` | Duplicates `tune_system_buffers()` line 321. Second write wins. Not harmful but dead code / maintenance trap. | Remove from `setup_tunnel_routes` |
| **52** | **No `tcp_notsent_lowat` set anywhere** | `node/main.rs` + `node/datapath.rs` | Fix #8 prescribes `tcp_notsent_lowat=131072`. Neither `tune_system_buffers()` nor `setup_tunnel_routes()` sets it. Apps can dump unlimited data into inner TCP. | Add `sysctl net.ipv4.tcp_notsent_lowat=131072` to `tune_system_buffers()` |
| **53** | **Echo frames use blocking `sock.send()`** | `node/main.rs:1183` | In the io_uring worker, echo frames bypass io_uring and call `sock.send()` directly. This is a blocking syscall on a SQPOLL-driven loop. Can stall the entire CQE processing pipeline. | Route through `reactor.stage_udp_send()` instead |
| **54** | **Keepalive uses blocking `sock.send()`** | `node/main.rs:1273` | Same as #53: keepalive frames use `sock.send()` instead of io_uring path. Inconsistent with the "zero-syscall datapath" mandate. | Route through `reactor.stage_udp_send()` |
| **55** | **Handshake retransmit uses blocking `sock.send()`** | `node/main.rs:1257` | `send_fragmented_udp()` closure calls `sock.send()` for each fragment. During handshake retransmit, this fires 3-7 blocking sends in the hot loop. | Buffer fragments → batch via io_uring SQEs |
| **56** | **`tcp_slow_start_after_idle=0` set without justification** | `node/datapath.rs:162` | Disabling slow-start-after-idle means inner TCP keeps stale cwnd across idle periods. For a tunnel with bufferbloat, this causes WORSE bursts after idle: inner TCP resumes at full rate into an empty tunnel that immediately re-fills the socket buffer. Should be `=1` (default). | Remove or set to `1` |
| **68** | **`typestate.rs` fully implemented but unwired (254 lines dead)** | `hub/engine/typestate.rs:1-254` | `TypedPeer` state machine (Empty→Registered→Handshaking→Established) and 3 branchless ingress guards (`validate_frag_index`, `validate_m13_offset`, `validate_frag_data_bounds`) have **zero call sites** in the Hub codebase. `main.rs` mutates `PeerSlot.lifecycle` directly, bypassing typestate compile-time safety. Guards designed to prevent OOB reassembly writes are never invoked. **Not a speed issue** — typestate adds zero runtime cost (ZST erasure), guards cost ~2-5ns/pkt. This is a **correctness/security** gap: OOB fragment writes and illegal lifecycle transitions are unguarded. | Wire `validate_frag_index()` + `validate_frag_data_bounds()` into `process_fragment()`. Wire `TypedPeer` transitions into peer lifecycle management in `main.rs`. |
| **69** | **Phase 1 Cmd #3: `nuke_cleanup_hub()` spawns 9 child processes (syscall storm)** | `hub/datapath.rs:934-949` | Panic hook (registered at `hub/main.rs:54-58`) calls `nuke_cleanup_hub()` which fires 9× `Command::new().output()` = 9× `fork()+execve()+waitpid()` = **27 synchronous syscalls**. On Cortex-A53: ~200µs per `fork()` = **~1.8ms blocked** during crash teardown. Races with signal delivery if another thread panics simultaneously. | Replace `Command::new()` calls with direct `libc::` syscalls: `ioctl(SIOCSIFFLAGS)` + netlink for iptables. Eliminates all 9 `fork()`. Async-signal-safe. ~50µs total. |
| **70** | **Phase 1 Cmd #3: `std::env::set_var()` global libc mutex abuse** | `hub/main.rs:110-124` | 3× `set_var()` calls (`M13_HEXDUMP`, `M13_LISTEN_PORT`) invoke `setenv(3)` which acquires a global libc mutex. Single-threaded at this point so no deadlock, but architecturally wrong: downstream reads via `std::env::var()` also acquire the mutex. Pass config directly as function arguments to `run_executive()` instead of through global mutable environment. | Add `hexdump: bool` and `listen_port: u16` parameters to `run_executive()`. Remove all `set_var()` calls. |
| **71** | **Phase 2 Cmd #3: `run_executive()` pre-flight spawns 4 child processes (syscall storm)** | `hub/main.rs:143-157` | Pre-flight cleanup fires: `pgrep m13-hub` (L143, fork+execve+waitpid), `ip link set xdp off` (L156, fork+execve+waitpid), `ip link set xdpgeneric off` (L157, fork+execve+waitpid), `ethtool -L combined 1` (L159, fork+execve+waitpid) = **12 synchronous syscalls**. Cold-start only, but on Cortex-A53 these 4 forks cost ~800µs. | Replace with: `libc::kill()` via `/proc` scan for pgrep, `ioctl(SIOCETHTOOL)` for ethtool, netlink `RTM_SETLINK` for XDP detach. Zero forks. |
| **72** | **Phase 2 Cmd #3: `fence_interrupts()` spawns `pgrep irqbalance` (syscall storm)** | `hub/engine/runtime.rs:417-422` | `fence_interrupts()` calls `Command::new("pgrep").arg("irqbalance").output()` = another fork+execve+waitpid. Then iterates **every** `/proc/irq/N/smp_affinity` file via `readdir` + per-IRQ `fs::write()` (L424-438). At 200+ IRQs = 200+ `open()+write()+close()` syscalls = **~600 VFS syscalls**. Cold-start only but adds ~5ms on A53. | Replace pgrep with `/proc` walk. Batch IRQ affinity writes via single `for_each_entry` with pre-opened fd. |
| **73** | **Phase 2 Cmd #3: `calibrate_tsc()` blocks main thread 100ms + 1000 validation iterations** | `hub/engine/runtime.rs:176-265` | `calibrate_tsc()` calls `thread::sleep(100ms)` (L216) = voluntary context switch, main thread yields to scheduler for 100ms. Then runs 1000 validation iterations (L248-253) calling `rdtsc_ns()` + `clock_ns()` alternately = 2000 `clock_gettime` vDSO calls. Total: ~100ms wall-clock + ~0.5ms compute. Cold-start only. The 100ms sleep is necessary for calibration accuracy but causes a **context switch** to the kernel scheduler. | Accept as necessary cold-start cost. Document the 100ms block in startup timing budget. |
| **74** | **Phase 2 Cmd #3: `lock_pmu()` leaks file descriptor via `mem::forget`** | `hub/engine/runtime.rs:356-381` | `lock_pmu()` opens `/dev/cpu_dma_latency` (L359), writes `0i32` to lock C-states to C0 (L366), then calls `mem::forget(file)` (L380) to prevent the fd from closing on drop. This is correct behavior (the fd must stay open for the lock to persist), but: (1) the fd is **never closed** even on graceful shutdown (leak), (2) the fd is not `CloseOnExec`, so forked children (nuke_cleanup_hub, L938-947) inherit it and hold the PMU lock during teardown. | Set `CLOEXEC` flag on the fd via `fcntl(F_SETFD, FD_CLOEXEC)` before `mem::forget`. Store the raw fd in a static for explicit close on shutdown. |
| **75** | **Phase 2 Cmd #3: `discover_isolated_cores()` calls `std::env::var()` (global libc mutex, same as #70)** | `hub/engine/runtime.rs:289` | `discover_isolated_cores()` checks `M13_MOCK_CMDLINE` via `std::env::var()` which acquires the global libc `environ` mutex. Called again inside `fence_interrupts()` (L384, L386). **3 total mutex acquisitions** across Phase 2 for the same env var. | Cache the result in a `OnceLock<Option<String>>` at boot. Single mutex acquisition. |
| **76** | **Phase 3 Cmd #3: `create_tun()` spawns 4 child processes (syscall storm)** | `hub/datapath.rs:861-868` | 4× `Command::new("ip").output()`: `ip link set up` (L861), `ip addr add` (L862), `ip link set mtu` (L867), `ip link set txqueuelen` (L868) = 4× fork+execve+waitpid = **12 synchronous syscalls**. All 4 can be done via `ioctl(SIOCSIFFLAGS/SIOCSIFMTU/SIOCSIFTXQLEN)` + `ioctl(SIOCSIFADDR)` = 4 ioctl syscalls, zero forks. | Replace with direct `libc::ioctl()` calls. |
| **77** | **Phase 3 Cmd #3: `setup_nat()` spawns 20 child processes (WORST SYSCALL STORM IN CODEBASE)** | `hub/datapath.rs:890-932` | `apply_sysctl()` calls `Command::new("sysctl")` for each of 14 sysctls (L897-914) = 14× fork+execve+waitpid. Then `tc qdisc replace` (L918) = 1× fork. Then 5× `iptables` (L927-931) = 5× fork. **Total: 20× fork+execve+waitpid = 60 synchronous syscalls. On A53: ~4ms blocked.** Plus 14× `read_sysctl()` verification (L884) = 14× `open()+read()+close()` = 42 VFS syscalls. **Grand total: ~102 syscalls.** | Replace sysctl with direct `fs::write()` to `/proc/sys/`. Replace iptables with nftables netlink (`NFT_MSG_NEWRULE`). Replace tc with netlink (`RTM_NEWQDISC`). Zero forks. |
| **78** | **Phase 3 Cmd #3: `create_tun()` sets `txqueuelen=1000` (bufferbloat)** | `hub/datapath.rs:868` | `ip link set m13tun0 txqueuelen 1000` — 1000-packet kernel TX queue on TUN device. At 200 Mbps with 1380B packets, this is **1000 × 1380B / 200Mbps = 55ms of kernel buffering**. This is Culprit #4 from the bufferbloat analysis. Same defect exists on Node side. | Set `txqueuelen 10` (BDP-scaled). Or better: use `noqueue` qdisc since M13 manages its own pacing. |
| **79** | **Phase 3 Cmd #3: `BpfSteersman::load_and_attach()` RLIM_INFINITY fallback** | `hub/network/bpf.rs:45-48` | If initial `setrlimit(RLIMIT_MEMLOCK, UMEM+16MB)` fails, falls back to `RLIM_INFINITY` (L45-46). This removes **all** kernel memory lock limits for the process. Any subsequent `mmap(MAP_LOCKED)` or `mlock()` succeeds without bound. On a 4GB A53 SOM, a bug that accidentally locks memory could OOM-kill the system. | Remove RLIM_INFINITY fallback. Fail hard if the scoped limit is rejected — the operator must fix `/etc/security/limits.conf`. |
| **80** | **Phase 3 Cmd #3: `setup_nat()` sets Hub-side bufferbloat sysctls (cross-ref #43-#48)** | `hub/datapath.rs:899-908` | `rmem_max=16MB` (L899), `wmem_max=16MB` (L900), `rmem_default=4MB` (L901), `wmem_default=4MB` (L902), `tcp_rmem max=16MB` (L903), `tcp_wmem max=16MB` (L904), `tcp_slow_start_after_idle=0` (L905), `netdev_max_backlog=10000` (L906). **These are the SAME defects as #43-#56 but on the HUB side** (previously only filed for Node). Hub's `setup_nat()` applies identical bufferbloat-inducing values. The Hub is a **relay** — inner TCP flows traverse it. These settings affect ALL tunnel traffic. | Apply same BDP-scaled fixes as prescribed for Node: `rmem_max=1572864`, `tcp_rmem=4096 131072 1572864`, `netdev_max_backlog=300`, etc. |
| **81** | **Phase 4 Cmd #3: TUN HK core collides with last VPP worker (cache thrashing + context switching)** | `hub/main.rs:223,253` | `tun_hk_core = *isolated_cores.last()` (L223). In multi-queue mode (`worker_count = isolated_cores.len()`), the last worker also pins to `isolated_cores[worker_count-1]` = `isolated_cores.last()` (L253). **Two threads pinned to the same core.** TUN HK does blocking `poll()+read()+write()` = frequent voluntary context switches. Each switch flushes L1d (32KB on A53) — **VPP worker's prefetched UMEM data is evicted.** On A53 with 32KB L1d, a context switch costs ~5µs (TLB flush + cold pipeline). At 2,260 pkt/s TUN writes, this is ~11ms/sec of stall. **Provably causes both Cache Thrashing AND Context Switching.** | Reserve `isolated_cores.last()` exclusively for TUN HK. Set `worker_count = (isolated_cores.len() - 1).min(MAX_WORKERS)` when tunnel mode is active. |
| **82** | **Phase 4 Cmd #3: 32MB stack per VPP worker (unnecessary memory pressure)** | `hub/main.rs:267` | `stack_size(32 * 1024 * 1024)` = 32MB virtual per worker. With `MAX_WORKERS=4`: 128MB virtual committed. On a 4GB A53 SOM with 1GB UMEM + hugepages, this consumes **3.2% of total RAM** in page table entries alone. VPP workers use ~64KB of stack at most (256 × `PacketDesc` + local variables). The 32MB is 500× overprovisioned. | Reduce to `2 * 1024 * 1024` (2MB). Matches TUN HK stack (4MB) and is still 31× the actual usage. |
| **83** | **Phase 4 Cmd #3: `tun_ref.try_clone()` called for every worker, only worker 0 uses TUN** | `hub/main.rs:258` | `tun_ref.as_ref().and_then(\|f\| f.try_clone().ok())` runs inside the worker spawn loop for every `worker_idx`. `try_clone()` calls `libc::dup()` = 1 syscall per worker. Workers 1-3 receive an `Option<File>` they immediately drop. **3 wasted `dup()+close()` syscall pairs.** Also: if `try_clone()` fails silently (`.ok()`), worker 0 gets `None` for its TUN fd — silent tunnel failure, no error message. | Move `try_clone()` outside the loop. Only clone once for worker 0 explicitly. `unwrap_or_else()` instead of `.ok()` to catch clone failure. |
| **84** | **Phase 4 Cmd #3: `wifi_iface.clone()` heap allocation per worker (waste)** | `hub/main.rs:256` | `wifi_iface.clone()` allocates a new `Option<String>` on heap per worker. Only worker 0's WiFi UringReactor uses it. Workers 1-3 receive a `Some(String)` they never read → dropped on worker exit. **3 wasted heap allocations + deallocations.** | Use `.take()` pattern (same as SPSC handles at L260-263): `if worker_idx == 0 { wifi_iface.take() } else { None }`. |
| **85** | **Thread 1 Cmd #3: spin-wait `yield_now()` loop for UMEM base (context switching)** | `hub/main.rs:727-736` | `loop { if umem_info.get().is_some() { break; } yield_now(); }` — tight spin loop calling `sched_yield()` on every iteration. Each `yield_now()` = 1 syscall + 1 voluntary context switch. Worker 0 hasn't started yet, so this spins for ~1-5ms = **~1,000-5,000 context switches + syscalls** before UMEM is ready. On the isolated core, each switch evicts L1i. | Replace with `thread::sleep(Duration::from_micros(100))` or `OnceLock::wait()` (Rust 1.83+). Reduces to ~10-50 sleeps. |
| **86** | **Thread 1 Cmd #3: per-packet `libc::write()` syscall — no batching (syscall storm, HOT PATH)** | `hub/main.rs:781` | Each TUN write is a separate `libc::write(tun_fd, payload, plen)` inside the `for i in 0..write_count` loop (L765-786). At 2,260 pkt/s downlink, this is **2,260 `write()` syscalls/sec**. Each crosses the kernel boundary (~1µs on A53 with TUN overhead) = **~2.3ms/sec of syscall overhead.** The `write_buf` batch is already popped (up to 64 descs), but each is sent individually. `writev()` cannot batch TUN (each IP packet is separate), but `io_uring` linked SQEs could submit all 64 as a single `io_uring_enter()`. | Replace with `io_uring` WRITE SQEs for TUN: arm all `write_count` SQEs, single `submit()`. Amortizes syscall cost across batch. |
| **87** | **Thread 1 Cmd #3: `poll(tun_fd, 1, 1ms)` — 1000 syscalls/sec minimum (syscall storm)** | `hub/main.rs:795` | `poll(&mut pfd, 1, 1)` with 1ms timeout. When TUN has no data (idle tunnel), this fires **1,000 poll() syscalls/sec** returning 0. Each `poll()` is a kernel transition (~0.5µs) = **~0.5ms/sec wasted even when idle.** Combined with `write_count == 0` path at L854: if no writes AND no reads, calls `yield_now()` = **additional** syscall. Net: idle tunnel burns **2,000 syscalls/sec** (poll + yield). | Use `io_uring` multishot `POLL_ADD` for TUN fd — zero syscalls when idle. Or increase timeout to `10ms` for 100/sec minimum. |
| **88** | **Thread 1 Cmd #3: per-packet `libc::read()` syscall — no batching (syscall storm, HOT PATH)** | `hub/main.rs:808-810` | Each TUN read is a separate `libc::read(tun_fd, payload_ptr, max_payload)` for each allocated slab index (L802-853). Batch size up to `alloc_count` (max 64), but each read is individual. At 2,260 pkt/s uplink, this is **2,260 `read()` syscalls/sec** = ~2.3ms/sec. | Same fix as #86: `io_uring` READ SQEs batched with single `submit()`. |
| **89** | **Thread 1 Cmd #3: `pending_return[4096]` overflow — no bounds check** | `hub/main.rs:813-818` | When `read()` fails (L812, `n <= 0`), remaining slab indices are pushed into `pending_return[pending_count++]` (L815-817). **No bounds check on `pending_count`:** if `pending_return` is near full (4096 entries) and `alloc_count` adds more, `pending_count` exceeds 4096 → **stack buffer overflow.** `pending_return` is `[u32; 4096]` on stack. Same risk at L790-791 (write path) and L849-850 (push_batch failure path). Combined: write path (up to 64 per iteration) + read failure path (up to 64) + push failure path = max 192 entries per loop iteration into a 4096-element buffer. Overflow requires **22 consecutive failed drain iterations** — unlikely but mathematically possible under extreme SPSC backpressure. | Add `if pending_count + remaining < pending_return.len()` guard. Log + drop excess slabs if overflow imminent. |
| **90** | **Thread 1 Cmd #3: `yield_now()` on idle path — voluntary context switch (context switching)** | `hub/main.rs:855` | When `write_count == 0` AND `poll()` returns no data (L854), calls `std::thread::yield_now()` = `sched_yield()` syscall. **On an isolated core with no other runnable threads, `sched_yield()` returns immediately** (no other thread to yield to) but still costs ~110ns for the kernel transition. At idle, this fires ~1,000/sec (gated by poll 1ms timeout). Not a significant cost, but architecturally wrong: should sleep, not yield. | Replace with `thread::sleep(Duration::from_millis(1))` or remove entirely (poll already provides 1ms backoff). |
| **91** | **Thread 1 Cmd #3: `push_batch(&[desc])` — degenerate batch of 1 (cache thrashing)** | `hub/main.rs:848` | Each TUN-read frame is pushed to the datapath SPSC via `tx_to_dp.push_batch(&[desc])` with exactly 1 element. The SPSC `push_batch()` does an `Ordering::Release` atomic store on **every single push** (spsc.rs L118). At 2,260 pkt/s uplink, this is **2,260 Release barriers/sec.** Each Release barrier on A53 is a `DMB ISH` (~40 cycles = ~27ns). Total: ~61µs/sec — negligible cost, but the store-buffer drain forces cache-line writeback of the SPSC `head` line. The Consumer (VPP worker on different core) does `Acquire` load on the same `head` — **every single-element push forces a cross-core cache-line transfer.** DPDK batches 32-64 descs per push to amortize this interconnect cost. | Accumulate TUN-read frames in local buffer (up to 64), then single `push_batch(&local[..count])` at end of read loop. 1 Release + 1 cross-core transfer per batch instead of per-packet. |
| **92** | **Thread 1 Cmd #3: no `prefetch_read_l1` before UMEM write path (cache thrashing, HOT PATH)** | `hub/main.rs:765-776` | The write loop iterates `write_buf[0..write_count]`, reading M13 header + payload from UMEM (`umem_base.add(desc.addr)`) at L771-776. **No prefetch hint for the next descriptor's UMEM frame.** At A53 L1d miss → L2 (~10 cycles) or L3/DRAM (~100+ cycles), each 1380B payload read stalls the pipeline. The VPP worker uses `prefetch_read_l1()` in its hot loop. TUN HK does not. With 64 descs/batch, prefetching desc[i+1]'s UMEM frame while processing desc[i] would hide ~90% of DRAM latency. | Add `if i + 1 < write_count { prefetch_read_l1(umem_base.add(write_buf[i+1].addr as usize)); }` before the payload read at L770. |
| **93** | **~~Thread 2 Cmd #3: PQC worker thread spawned with NO `pin_to_core()`~~  RETRACTED** | `hub/main.rs:992, async_pqc.rs:181` | **CORRECTION**: PQC worker DOES call `pin_to_core(core_id=0)` at `async_pqc.rs:181`. It's correctly pinned to core 0 (housekeeping core). Original finding was wrong — `pin_to_core` is called inside the worker closure, not at spawn site. **Downgraded to informational.** Minor note: core 0 is shared with the blocked main thread (`join()`) and DRL worker — low contention since main is idle and DRL is infrequent. | No fix needed. |
| **94** | **Thread 2 Cmd #3: `resolve_gateway_mac()` spawns `ping` subprocess from VPP worker thread (syscall storm on isolated core)** | `hub/datapath.rs:776-778` | `Command::new("ping").args(["-c", "1", "-W", "1", &gw_ip_str])` — called during `worker_entry()` init (L921), which runs **on the isolated VPP core**. `fork()` on an isolated core: (1) COW page table copy (~200µs), (2) child inherits CPU affinity and runs on the isolated core briefly before migrating, (3) parent VPP thread stalls, L1d flushed. This only runs once at startup if ARP cache is cold, but it's a **fork on the datapath core**. | Move `resolve_gateway_mac()` call to `run_executive()` (main thread) before thread spawn. Pass result as function argument. |
| **95** | **Thread 2 Cmd #3: `GraphCtx` 30-field struct constructed TWICE per loop iteration (cache pressure)** | `hub/main.rs:1057-1087,1206-1236` | `GraphCtx` is a 30-field struct with pointers, integers, and mutable references. It's constructed at L1057-1087 (TX graph) and again at L1206-1236 (RX graph) — **60 field copies per loop iteration**. At ~18,000 iterations/sec, this is **~1,080,000 field copies/sec**. Each `GraphCtx` is ~240 bytes (30 fields × 8 bytes average) = **480 bytes written to stack per iteration**. The fields are identical between TX and RX construction except the stack `gctx` variable name. | Declare `GraphCtx` once before the TX path, reuse for RX path. Zero copies for the second use. Update only fields that change between TX and RX paths (if any). |
| **96** | **Thread 2 Cmd #3: telemetry 13× `fetch_add(Relaxed)` per RX batch (atomic contention)** | `hub/main.rs:1250-1262` | After `execute_graph()`, 13 separate `fetch_add(Relaxed)` calls update SHM telemetry: `decrypt_ok`, `auth_fail`, `drops`, `rx_count`, 5× per-stage TSC, `handshake_ok/fail`, `direction_fail`. Each `fetch_add` on A53 is a `LDXR/STXR` (load-exclusive/store-exclusive) pair with retry loop = ~8-15 cycles. At 18,000 batches/sec: **~234,000 atomics/sec**. Since `Telemetry` is SHM-mapped and the monitor reads it from another process, **each atomic write evicts the cache line** from the monitor's L1d. 13 atomics × 128B CachePadded = **13 × 128B = 1,664 bytes of cache pollution per batch.** | Accumulate counts in local `u64` variables. Write to SHM atomics only every Nth batch (e.g., N=100). Reduces atomics from 234K/sec to 2,340/sec. |
| **97** | **Thread 2 Cmd #3: peer keepalive scan iterates ALL `MAX_PEERS` slots every RX batch (cache thrashing)** | `hub/main.rs:1296-1366` | `for pidx in 0..MAX_PEERS { if peers.slots[pidx].is_empty() { continue; } ... }` — linear scan of the entire `PeerTable` on every RX batch. `MAX_PEERS` × `sizeof(PeerSlot)` = significant cache footprint. With 1 active peer out of `MAX_PEERS` slots, this touches cold memory for N-1 empty slots. At 18,000 batches/sec: **18,000 × MAX_PEERS unnecessary L1d loads/sec.** The scan is gated by `100ms` per-peer cooldown (L1300), so only 1 check per peer per 100ms is productive, but the **iteration** itself touches all slots unconditionally. | Maintain a `Vec<usize>` of active peer indices (updated on register/evict). Iterate only active peers. Or move keepalive scan to a separate timer-based check every 100ms instead of every batch. |
| **98** | **Thread 2 Cmd #3: `std::env::var("M13_HEXDUMP")` + `std::env::var("M13_LISTEN_PORT")` on VPP worker init (global mutex on isolated core)** | `hub/main.rs:906,915` | `std::env::var("M13_HEXDUMP").is_ok()` (L906) and `std::env::var("M13_LISTEN_PORT")` (L915) each acquire the global libc `environ` mutex. Called from `worker_entry()` which runs **on the isolated core**. The libc mutex acquisition may block if another thread (e.g., PQC worker L992, which is spawning ~simultaneously) is also calling `env::var`. On an isolated core, any mutex contention = voluntary context switch = L1d flush. | Pass `hexdump_enabled: bool` and `hub_port: u16` as function arguments from `run_executive()`. Zero mutex acquisitions on isolated core. |
| **99** | **Thread 2 Cmd #3: SLAB init loop touches 32MB UMEM sequentially (cache thrashing at startup)** | `hub/main.rs:941-955` | `for i in 0..SLAB_DEPTH { let fp = engine.get_frame_ptr(i); ... }` — iterates 8,192 UMEM frames × 4,096B = 32MB. For each frame, writes 62 bytes of M13 header at byte 0 (L944-953). This is a **sequential scan of 32MB of DRAM** on the isolated core. On A53 with 32KB L1d and 256KB L2, this evicts the entire L1d/L2 cache **~125 times**. After this loop, the cache is fully cold — the first real packet incurs guaranteed L1d miss. Cold-start only, but the immediately following `refill_rx_full` and first `poll_rx_batch` start with a thrashed cache. | Prefetch frame[i+4] while writing frame[i]. Or accept as cold-start cost but call `prefetch_read_l1()` on the first few UMEM frames immediately after the init loop to warm L1d. |
| **100** | **Thread 2 Cmd #3: `tun.as_ref().map(\|f\| f.as_raw_fd())` called twice per loop iteration** | `hub/main.rs:1063-1066,1212-1215` | `tun.as_ref().map(\|f\| { use std::os::unix::io::AsRawFd; f.as_raw_fd() }).unwrap_or(-1)` executed inside both `GraphCtx` constructions (L1063-1066 and L1212-1215). `as_raw_fd()` is trivial (returns an int), but the closure + `map` + `unwrap_or` pattern is rebuilt on every iteration. | Cache `let tun_fd = tun.as_ref().map(\|f\| f.as_raw_fd()).unwrap_or(-1);` once before the loop. Use the cached `tun_fd: i32` in both GraphCtx constructions. |
| **101** | **Thread 3 Cmd #3: `yield_now()` tight spin when idle (syscall storm)** | `hub/cryptography/async_pqc.rs:189` | `if n == 0 { std::thread::yield_now(); continue; }` — when no PQC requests pending, calls `sched_yield()` on every loop iteration. On core 0 (shared with main thread which is just `join()`), this fires **continuously** — potentially **>100,000 sched_yield() syscalls/sec** when no handshakes are active. Each is ~110ns kernel transition = **~11ms/sec wasted on empty spins.** Unlike Thread 1's `yield_now()` which is gated by `poll(1ms)`, Thread 3 has **no backoff at all.** | Replace with `thread::sleep(Duration::from_millis(1))` for 1,000/sec max, or add adaptive backoff: sleep 1ms after N consecutive empty pops. |
| **102** | **Thread 3 Cmd #3: `PqcResp` is 9,280 bytes — copied through SPSC per handshake (cache thrashing)** | `hub/cryptography/async_pqc.rs:122-148,278` | `PqcResp` struct contains `response_payload: [u8; 9216]` + 64 bytes of headers/key = **9,280 bytes total**. `push_batch(&[resp])` at L278 copies the entire 9,280B into the SPSC ring buffer via `ptr::write()` (spsc.rs L113). This spans **145 cache lines** (64B each). The write pollutes L1d (32KB on A53) — 9.2KB is **28% of the entire L1d.** For a handshake occurring every ~30s, this is infrequent (~0.03/sec), but each copy flushes 28% of working set. | Use an arena + index pattern: write ServerHello payload to `response_arena[pidx]`, return only a slim `PqcRespSlim { pidx, msg_type, success, response_len, session_key }` (~40 bytes) through SPSC. Same pattern as PqcReq. |
| **103** | **Thread 3 Cmd #3: `push_batch(&[resp])` — degenerate batch of 1 for 9.2KB struct** | `hub/cryptography/async_pqc.rs:278` | Even though `pqc_worker_thread` processes up to 4 requests per `pop_batch` (L184, `req_buf = [PqcReq::EMPTY; 4]`), each response is pushed **individually** at L278. The `push_batch` does a `Release` store after each 9.2KB copy. With 4 requests processed, this is 4× Release barriers + 4× 9.2KB copies = **37KB of SPSC writes + 4 memory barriers** where a single batched push would suffice. | Accumulate responses in `resp_buf: [PqcResp; 4]`, push all at once: `resp_prod.push_batch(&resp_buf[..resp_count])`. 1 Release barrier instead of up to 4. |
| **104** | **Thread 3 Cmd #3: `FlatHubHandshakeState` is 2,720 bytes — full struct copy on write** | `hub/cryptography/async_pqc.rs:66-84,228` | `FlatHubHandshakeState` contains `node_pk_bytes: [u8; 2592]` + `shared_secret: [u8; 32]` + `session_nonce: [u8; 32]` + `transcript2: [u8; 64]` + `valid: bool` = ~2,720 bytes. At L228: `*hs_state_arena.add(pidx) = flat;` copies the full 2,720B struct. This spans **42 cache lines.** Combined with PqcResp write (145 lines), a single ClientHello processing copies **~12KB to two different memory regions** — 37% of L1d. | Acceptable for now (handshakes are infrequent). Long-term: write fields individually to arena slot to minimize cache-line touches. |
| **105** | **Thread 3 Cmd #3: `process_client_hello_hub()` likely heap-allocates (Vec for server_hello)** | `hub/cryptography/async_pqc.rs:213` | `process_client_hello_hub(payload, &mut dummy_seq, req.rx_ns)` returns `Option<(HubHandshakeState, Vec<u8>)>`. The `server_hello: Vec<u8>` is a **heap allocation** (~8.8KB for ServerHello). On core 0, `malloc()` acquires the global allocator lock (jemalloc/glibc). During a handshake burst (multiple simultaneous peers), this serializes on the allocator mutex. Additionally, `HubHandshakeState` contains `client_hello_bytes: Vec<u8>` (~4.2KB) — another heap alloc. **Total: ~13KB heap allocated per ClientHello.** | Convert `process_client_hello_hub` to write into pre-allocated `response_arena` buffer. Zero heap allocations. Requires refactoring handshake.rs return type. |
| **106** | **VPP Loop Cmd #3: `TX_RING_SIZE=256` scheduler with silent tail-drop (BUFFERBLOAT)** | `hub/engine/protocol.rs:759,783-788` | `TX_RING_SIZE = 256`. The critical ring (`Scheduler.critical`) and bulk ring (`Scheduler.bulk`) are each 256 entries. At 2,260 pkt/sec downlink + 2,260 pkt/sec uplink + control/feedback, the scheduler receives ~5,000 enqueues/sec. With `enqueue_critical_edt` returning `false` silently when full (L785), **packets are silently dropped with zero telemetry.** The EDT pacer delays packets in the scheduler, which compounds: at 100Mbps with 1500B frames, `delay_ns = 1500 × 80 = 120µs` per packet. A burst of 256 packets fills the ring, and the 257th is tail-dropped. This is **classic standing-queue bufferbloat** — CoDel-style queue management is needed. The caller at `tx_enqueue_vector` (datapath.rs:450) doesn't check the return value! Neither does `execute_tx_graph` (main.rs:705)! **Blind enqueue with blind drop = uncontrolled bufferbloat.** | (1) Add telemetry counter for `enqueue_fail`. (2) Check return value at all 4 enqueue call sites. (3) Increase TX_RING_SIZE to 2048 or add CoDel/FQ-CoDel AQM. (4) On enqueue failure, `slab.free()` the frame — currently leaked. |
| **107** | **VPP Loop Cmd #3: `EdtPacer` hardcoded to 100 Mbps — creates bufferbloat at higher link rates (BUFFERBLOAT)** | `hub/main.rs:1008` | `EdtPacer::new(&cal, 100_000_000)` — hardcoded to 100 Mbps. `ns_per_byte = 8e9 / 100e6 = 80 ns/byte`. For a 1500B frame: `delay_ns = 1500 × 80 = 120µs`. If actual link rate is 1 Gbps: optimal `delay_ns = 12µs`. **Pacer inserts 10× too much delay.** This means the scheduler holds packets 10× longer than necessary, filling the TX_RING_SIZE=256 buffer 10× faster. Combined with #106 (silent tail-drop when full), this is **pacing-induced bufferbloat** — the pacer is the root cause of standing queues. | Make EdtPacer configurable: `--link-rate` CLI arg or auto-detect via `ethtool`. At minimum, detect if link is 1G and set accordingly. |
| **108** | **VPP Loop Cmd #3: `EdtPacer.last_tx_ns` never reset on idle — burst-compensating backlog (BUFFERBLOAT)** | `hub/network/uso_pacer.rs:96-101` | `release_ns = self.last_tx_ns.max(now_ns) + delay_ns`. If the pacer is idle for 1 second (no traffic), `last_tx_ns` is 1s in the past. When a burst arrives, `last_tx_ns.max(now_ns) = now_ns` — no backlog. BUT: if traffic is continuous and then briefly pauses for 50ms, `last_tx_ns` is 50ms ahead of `now_ns` (from the EDT schedule). When traffic resumes, `self.last_tx_ns.max(now_ns) = last_tx_ns` (still 50ms in the future). **All new packets get release_ns far in the future, creating a standing queue in the scheduler.** The `reset()` method exists but is never called. | Call `pacer.reset(now)` when `rdtsc_ns(&cal) - last_tx_ns > threshold` (e.g., 10ms). Or reset at the start of each main loop iteration if `scheduler.pending() == 0`. |
| **109** | **VPP Loop Cmd #3: `enqueue_critical_edt` return value ignored — slab leak (BUFFERBLOAT + MEMORY LEAK)** | `hub/network/datapath.rs:450, hub/main.rs:705` | `ctx.scheduler.enqueue_critical_edt(desc.addr, desc.len, release_ns, tx_iface)` at datapath.rs:450 — return value (`bool`) is **ignored.** If the scheduler ring is full, the frame index is never freed back to the slab. This is a **slab leak** — each failed enqueue permanently loses a UMEM frame. With SLAB_DEPTH=8192, after 8192 leaked enqueues, the slab is exhausted and the datapath halts. Similarly at main.rs:705 in execute_tx_graph. | Check return value. On `false`: `ctx.slab.free((desc.addr / frame_size) as u32)` and increment a `tx_drop` telemetry counter. |
| **110** | **VPP Loop Cmd #3: 9× `PacketVector::new()` per subvector = 29KB stack zeroing (cache thrashing, HOT PATH)** | `hub/main.rs:378-420` | `execute_subvector` creates: `decrypt_vec`, `cleartext_vec`, `all_packets`, `recycle_decrypt`, `recycle_classify`, `tun_vec`, `recycle_encrypt`, `tx_vec`, `handshake_vec`, `feedback_vec`, `drop_vec`, `cleartext_echo_vec` = **12 PacketVectors**. Plus 3 `Disposition::new()`. `PacketVector` = `[PacketDesc; 64]` = `64 × 48B = 3,072B` + 8B len = ~3,080B. 12 × 3,080B = **36,960B stack zeroing per subvector.** At 18,000 iterations/sec with 1 subvector each: **665 MB/sec of stack writes.** On A53 with 32KB L1d, this evicts L1d **1,155×/sec** from stack zeroing alone. | Pre-allocate all PacketVectors outside the main loop (in worker_entry). Pass as `&mut` references to `execute_subvector`. Clear `.len = 0` between iterations instead of re-zeroing the entire array. |
| **111** | **VPP Loop Cmd #3: `execute_tx_graph` scans `MAX_PEERS` on every TX iteration (cache thrashing, HOT PATH)** | `hub/main.rs:619-624` | `for pi in 0..MAX_PEERS { if peers.slots[pi].lifecycle == PeerLifecycle::Established { ... } }` — linear scan of entire PeerTable to find fallback peer and count established peers. This runs **up to 4× per main loop iteration** (L612: `for _ in 0..4`). At 18,000 main loops/sec: up to **72,000 × MAX_PEERS cache-line loads/sec** just for peer counting. With 1 active peer, MAX_PEERS-1 slots are cold reads. | Cache `established_count` and `fallback_idx` in PeerTable. Update on `lookup_or_insert`/`evict`. Zero scans needed. |
| **112** | **VPP Loop Cmd #3: `std::ptr::copy` (memmove) 42 bytes per TX packet for UDP encapsulation** | `hub/main.rs:676` | `std::ptr::copy(frame_ptr, frame_ptr.add(RAW_HDR_LEN), m13_flen)` — shifts entire M13 frame right by 42 bytes (ETH+IP+UDP) in UMEM. `m13_flen` is typically 1380+48=1428 bytes. **1,428-byte memmove per TX packet** at 2,260 pkt/sec = **3.2 MB/sec of UMEM writes.** The memmove also forces a UMEM cache-line write-back for the entire frame. On A53 with no write-combining: ~23 cache-line writeback dirties per packet. | Pre-reserve 42-byte headroom in TUN read path: write M13 payload at offset 42 initially. Zero memmove needed at TX time — just fill in ETH+IP+UDP headers at byte 0. |
| **113** | **VPP Loop Cmd #3: `scheduler.dequeue()` is single-element — per-packet loop overhead (micro)** | `hub/main.rs:1466` | `while let Some(submit) = scheduler.dequeue(now) { ... }` — dequeues one `TxSubmit` at a time. Each call does 2 branch comparisons (crit_head/tail, then release_ns check). At 256 packets, this is 256 function calls + 512 branches. | Add `dequeue_batch(now, &mut buf[..N]) -> usize` to Scheduler. Batches reduce function call overhead and improve branch prediction. |
| **114** | **VPP Loop Cmd #3: `debug_assertions` `Vec` heap allocation in `rx_parse_raw` (debug builds only)** | `hub/network/datapath.rs:42-44` | `let hex_bytes: Vec<String> = (0..dump_len).map(\|i\| format!("{:02x}", ...)).collect();` — allocates a `Vec<String>` on the **heap** inside the hottest RX parsing loop. Only fires in debug builds (`cfg!(debug_assertions)`), but when it fires, it is catastrophic: `malloc()` + `format!()` × 120 = 120 heap allocations **per packet.** | Move debug hexdump behind a runtime flag (`hexdump_enabled`) instead of `cfg!(debug_assertions)`. Or use a stack-allocated buffer. |
| **115** | **VPP Loop Cmd #3: `FEEDBACK_RTT_DEFAULT_NS = 10ms` hardcoded — never updated from actual RTT (BUFFERBLOAT signal)** | `hub/engine/protocol.rs:619` | `FEEDBACK_RTT_DEFAULT_NS = 10_000_000` (10ms). Used in `stage_feedback_gen` at main.rs:303: `rx_state.needs_feedback(rx_batch_ns, rtt_est=10ms)`. This controls how often the Hub sends feedback (bitmap + ACK) to the Node. At 10ms intervals with 2,260 pkt/sec: ~23 packets arrive between feedback frames. **The Node's congestion controller only learns about loss 10ms later.** With actual satellite RTT of ~30-100ms, 10ms is too aggressive; with LAN RTT of <1ms, 10ms is too conservative. **The RTT estimate is never updated from actual measurements** despite the system having `rx_state.last_rx_batch_ns` and per-peer timestamps. | Wire actual RTT measurement from peer echo round-trip. Use measured RTT as `rtt_est` in `needs_feedback()`. |
| **116** | **VPP Loop Cmd #3: `CycleStats` accumulated with 15 manual field additions per subvector (micro, no AddAssign)** | `hub/main.rs:345-366` | `execute_graph` accumulates CycleStats from subvectors with 15 lines of `stats.field += sub_stats.field`. No `impl AddAssign for CycleStats`. This is repeated for every chunk of 64 packets. Functionally correct but verbose and fragile (adding a new stat field requires editing 2 locations). | Implement `impl std::ops::AddAssign for CycleStats` and replace with `stats += sub_stats;`. |
| **117** | **VPP Loop Cmd #3: `setup_nat()` sets `rmem_max=16MB`, `wmem_max=16MB`, `tcp_rmem max=16MB`, `tcp_wmem max=16MB` (BUFFERBLOAT, system-wide)** | `hub/network/datapath.rs:890-932` | Already filed as #79, but now visible in full VPP context: every socket on the system (including new connections) inherits 16MB kernel buffers. The AF_XDP socket itself uses UMEM-backed zero-copy (no kernel socket buffer), so these sysctl values only affect the TUN device and any auxiliary TCP connections. The TUN device with `txqueuelen=1000` (from #78) plus 16MB `wmem_max` = up to **10,666 packets** standing in the TUN write queue before kernel backpressure. This is **689ms of standing queue** at 200Mbps. | See #79 fix: reduce to 256KB/512KB. Reduce `txqueuelen` to 64 (per #78 fix). Combined: max standing queue drops from 689ms to ~4ms. |
| **118** | **Phase 1 Cmd #4: `create_tun()` spawns 4× child processes (syscall storm)** | `node/network/datapath.rs:63-72` | Node's `create_tun()` spawns 4× `ip` child processes: `ip link set up`, `ip addr add`, `ip link set mtu 1380`, `ip link set txqueuelen 1000`. Each = fork+exec+wait = ~600µs. **Identical defect to Hub #76.** Replace with `ioctl()` calls. | Replace all 4 with `ioctl(SIOCSIFFLAGS)`, `ioctl(SIOCSIFADDR)`, `ioctl(SIOCSIFMTU)`, `ioctl(SIOCSIFDSTADDR)`. |
| **119** | **Phase 1 Cmd #4: `txqueuelen=1000` on TUN device (BUFFERBLOAT)** | `node/network/datapath.rs:72` | `ip link set dev m13tun0 txqueuelen 1000`. At 200 Mbps with 1380B frames: 1000 × 1380B = 1.38MB standing queue = **55ms of kernel buffering.** Identical defect to Hub #78. | Reduce to `txqueuelen=64` (per Hub #78 fix). |
| **120** | **Phase 1.5 Cmd #4: `tune_system_buffers()` spawns 14+ child processes (syscall storm)** | `node/main.rs:278,301-302,315-332` | Spawns: 1× `iw dev <iface> set power_save off` per WiFi interface, 10× `sysctl -w` via `apply_sysctl()`, 10× `/proc/sys` readback verify, 1× `tc qdisc`. Each `Command::new("sysctl")` = fork+exec+wait = ~600µs. **Total: ~8.4ms of startup subprocess overhead.** Parallel to Hub #77. | Replace `sysctl -w` with direct `fs::write("/proc/sys/...")`. Zero forks. |
| **121** | **Phase 1.5 Cmd #4: `setup_tunnel_routes()` spawns 27 child processes (syscall storm — WORST IN NODE)** | `node/network/datapath.rs:92-187` | Spawns: 1× `ip route show` (discover_gateway), 3× `ip addr/link`, 3× `ip route`, 2× `sysctl` IPv6, 4× `sysctl` rmem/wmem, 4× `sysctl` other, 1× `sysctl` ip_forward, 3× `iptables`, 1× `tc qdisc` = **27 fork+exec+wait = ~16.2ms.** Combined with #120 = 24.6ms pure subprocess overhead at startup. **Worse than Hub's setup_nat (20 subprocesses).** | Replace sysctls with `fs::write()`, iptables with netlink, ip commands with `ioctl()`. |
| **122** | **Phase 1.5 Cmd #4: `run_udp_worker()` = 408 lines of dead code with `#[allow(dead_code)]`** | `node/main.rs:344-751` | Legacy recvmmsg/sendmmsg fallback path. **408 lines (30% of main.rs) are completely unreachable.** `main()` always calls `run_uring_worker()` — there is no runtime dispatch, no cfg flag, no feature gate. The `#[allow(dead_code)]` silences the compiler warning. Comment says "retained for systems without Kernel 6.12+" but there is no mechanism to invoke it. | Delete entirely. If needed in the future, recover from git history. |
| **123** | **Phase 2 Cmd #4: `SO_RCVBUFFORCE=8MB`, `SO_SNDBUFFORCE=8MB` — ROOT CAUSE of Sprint 2.5 tunnel collapse (BUFFERBLOAT)** | `node/main.rs:891-897` | `setsockopt(SOL_SOCKET, SO_SNDBUFFORCE, 8MB)`. **This is THE root cause documented in Sprint 2.5.** The 8MB send buffer creates an unmanaged FIFO between TUN and NIC. Inner TCP sees ~0ms TUN RTT → sends at max rate → 8MB fills in 320ms → real RTT inflates from 50ms to 370ms+ → cwnd collapses → throughput oscillates 1.6-20 Mbps (98% loss vs raw). WireGuard retains 90% because it bypasses userspace socket buffers entirely. | Reduce to `SO_SNDBUF=262144` (256KB). With EDT pacing active, 256KB provides 10ms of burst tolerance. Combined with fq-CoDel on m13tun0, this eliminates the standing queue. |
| **124** | **Phase 2 Cmd #4: `env::args().collect()` called twice — duplicate heap allocation** | `node/main.rs:857` | `std::env::args().collect::<Vec<String>>()` called inside `run_uring_worker()` to parse `--link-bps`. Already collected at `main()` L41. Two separate heap allocations for identical CLI data. | Parse `--link-bps` in `main()` alongside other args. Pass as function parameter. |
| **125** | **Phase 2 Cmd #4: EdtPacer double-init — `new()` then immediate `set_link_bps()`** | `node/main.rs:868-871` | `EdtPacer::new(&cal, cli_link_bps)` at L868 initializes with `cli_link_bps`. If CLI override, `edt_pacer.set_link_bps(cli_link_bps)` at L871 re-computes identical `ns_per_byte`. The `new()` constructor already uses the parameter — the `set_link_bps` call is redundant. | Remove L871 `set_link_bps` call. `new()` already handles it. |
| **126** | **Phase 3 Cmd #4: CQE overflow silently drops CQEs — BID leak → PBR exhaustion (P0 CORRECTNESS)** | `node/main.rs:984-988` | `MAX_CQE = 128`. CQE drain: `if cqe_count < MAX_CQE { cqe_batch[cqe_count] = ...; cqe_count += 1; }`. If >128 CQEs pending in a burst, excess CQEs are iterated by `for cqe in completion()` but **never stored**. The BIDs for overflow UDP CQEs are never returned to PBR → permanent BID leak. After 3,968 leaked BIDs, PBR is exhausted → all multishot recv stops → **datapath halts.** | Increase `MAX_CQE` to match `CQ_SIZE` (8320). Or: handle overflow CQEs inline (recycle BIDs immediately if batch full). |
| **127** | **Phase 3 Cmd #4: `commit_pbr()` called per-frame in Pass 2 — excessive atomic stores** | `node/main.rs:1229-1231` | In Pass 2 RxAction dispatch, `reactor.add_buffer_to_pbr(bid); reactor.commit_pbr();` is called for every non-deferred frame. Each `commit_pbr()` does an `AtomicU16::store(Release)`. At 128 CQEs/batch: 128 atomic Release stores where 1 suffices. | Move `commit_pbr()` outside the Pass 2 loop. Single atomic store after all BIDs returned. |
| **128** | **Phase 3 Cmd #4: `reactor.submit()` called per TUN write — excessive SQ syncs** | `node/main.rs:1169` | Inside Pass 2's `TunWrite` handler: `reactor.stage_tun_write(...); reactor.submit();`. Each `submit()` syncs the submission ring. With 128 TUN writes per batch: 128 SQ syncs where 1 suffices. | Move `submit()` outside the Pass 2 loop. Single sync after all SQEs staged. |
| **129** | **Phase 3 Cmd #4: `Box::new(LessSafeKey)` heap allocation on handshake completion** | `node/main.rs:1207-1209` | `cipher: Box::new(aead::LessSafeKey::new(...))` allocates on heap during session establishment. Infrequent (once per session), but `LessSafeKey` is only 32+16 bytes — could be stack-allocated in `NodeState::Established`. | Change `Established { cipher: Box<LessSafeKey>, ... }` to `Established { cipher: LessSafeKey, ... }`. |
| **130** | **Phase 3 Cmd #4: DeferredTxRing overflow force-drains without EDT pacing (BUFFERBLOAT)** | `node/main.rs:1060-1071` | `DEFERRED_TX_CAPACITY=64`. When ring is full, oldest entry is force-popped and sent via `stage_udp_send()` **regardless of release_ns**. This bypasses EDT pacing under burst load. At 2,260 pkt/sec with 120µs pacing, ring fills in 28ms. Every TX beyond 64 is un-paced. | Increase `DEFERRED_TX_CAPACITY` to 256+. Or: drop the packet (backpressure) instead of bypassing pacing. |

#### Fix 10 — io_uring & Protocol Defects





| # | Defect | File:Line | What's Wrong | Fix |
| --- | --- | --- | --- | --- |
| **57** | **TUN_RX_ENTRIES = 64 (starvation risk)** | `node/uring_reactor.rs:18` | Only 64 BIDs for TUN reads. At 2,260 pkt/s downlink, each TUN write takes ~1 CQE cycle. If write latency spikes (kernel scheduling), 64 BIDs exhaust in 28ms. No more TUN reads until BIDs recycle. | Increase to 256 or 512 |
| **58** | **No `IORING_SETUP_DEFER_TASKRUN`** | `node/uring_reactor.rs:90-96` | io_uring without `DEFER_TASKRUN` processes task_work on every syscall/timer. On kernel ≥6.1, `DEFER_TASKRUN` + `SINGLE_ISSUER` batches task_work to `submit()` calls only. Reduces interrupt overhead. | Add `.setup_defer_taskrun()` to IoUring builder |
| **59** | **`MSG_TRUNC` on multishot recv** | `node/uring_reactor.rs:156` | `RecvMulti` uses `MSG_TRUNC \| MSG_DONTWAIT`. If a UDP packet exceeds FRAME_SIZE (2048B), `MSG_TRUNC` returns the full length but the data is truncated. Node processes truncated frame → crypto failure → AEAD reject → wasted CPU. Should drop silently. | Check `result > FRAME_SIZE` in CQE processing → drop + recycle BID |
| **60** | **SQPOLL idle timeout = 2000ms** | `node/uring_reactor.rs:91` | SQPOLL thread idles after 2 seconds of no submissions. On wake, first SQE incurs kernel thread wakeup latency (~50-200µs). For a real-time transport, this adds jitter after idle gaps longer than 2s. | Reduce to 500ms or disable idle timeout with `setup_sqpoll(0)` |
| **61** | **PBR only covers UDP BIDs, not TUN** | `node/uring_reactor.rs:100,124` | PBR ring has `ring_entries = UDP_RING_ENTRIES (4096)`. TUN BIDs (4096-4159) are NOT in the PBR. TUN reads use manual `arm_tun_read()` with direct pointer math. This works but means TUN reads are NOT provided-buffer and cannot share the zero-copy recovery path. | Accept as design choice or unify under PBR with separate BGID |
| **62** | **`commit_pbr()` called per-BID recycle** | `node/main.rs:1076-1077` | Every `TAG_TUN_WRITE` CQE calls `add_buffer_to_pbr()` + `commit_pbr()`. `commit_pbr()` does an atomic store (Release). At 2,260 pkt/s, that's 2,260 atomic stores/sec. Should batch: accumulate BIDs, commit once per loop iteration. | Batch `add_buffer_to_pbr()` calls, single `commit_pbr()` at loop tail |
| **63** | **No SQ ring overflow detection** | `node/uring_reactor.rs:161,182,191,200` | All `push()` calls spin in `while push.is_err() { submit(); }`. If the SQ ring is persistently full (backpressure), this becomes an infinite busy-wait. No telemetry, no backoff, no drop policy. | Add overflow counter + bounded retry + telemetry |

#### Fix 11 — Security & Correctness

| # | Defect | File:Line | What's Wrong | Fix |
| --- | --- | --- | --- | --- |
| **64** | **No anti-replay window** | `node/cryptography/aead.rs` | AEAD decrypt accepts any valid `seq_id`. An attacker who captures a valid encrypted packet can replay it indefinitely — the reflection guard only prevents same-direction replay, not sequence replay. Missing: sliding window bitmap (RFC 4303 §3.4.3). | Implement 131072-bit sliding window. Reject seq < `highest_seen - window`. Mark seen seqs in bitmap. |
| **65** | **Nonce reuse across rekey if seq_tx not reset** | `node/main.rs:917,1052` | `seq_tx` is initialized once and monotonically incremented. On rekey (`RxAction::RekeyNeeded` → `NodeState::Registering`), seq_tx is NOT reset. New session key + old seq_tx = safe. BUT: if Node crashes and restarts with `seq_tx=0` and same session key is somehow cached → nonce reuse → catastrophic. Current code derives fresh key on each handshake, so this is safe TODAY, but fragile. | Document as design assumption. Add assertion: new session_key != old session_key |
| **66** | **No rate limiting on handshake retransmit** | `node/main.rs:1241-1264` | Handshake retransmit fires every 250ms (`HANDSHAKE_RETX_INTERVAL_NS`). Each retransmit sends 3-7 fragments via blocking `sock.send()`. If Hub is unreachable, Node floods 3-7 × 4 = 28 packets/sec of PQC fragments into a black hole. No exponential backoff. | Add exponential backoff: 250ms → 500ms → 1s → 2s → 5s cap |
| **67** | **iptables rules not idempotent** | `node/datapath.rs:174-179` | `setup_tunnel_routes()` uses `-A` (append). If called twice (e.g., rekey → re-setup), rules duplicate. Multiple identical iptables rules cause double-processing of every forwarded packet. | Use `-C` (check) before `-A`, or use `-I` (insert) with dedup |

---

### ❌ Sprint 3: AXI DMA Memory Architecture (CANNOT PROCEED: PENDING HARDWARE)

#### Debt

**[P0-01] Software Memory Moves (UmemSlice)** `← 3.1`
**Location:** `datapath.rs` and `rx_parse_raw`
**Defect:** `UmemSlice` and `io_uring` force the A53 CPU to fetch packets into L1d cache, causing massive TLB thrashing and memory bus overhead on the K26.
**Mandate:** The CPU datapath logic must be gutted. Replaced by a zero-copy DMA ring orchestrator.

**[P2-03] Branch Predictor Collapse** `← 3.2`
**Defect:** Typestate routing branching consumes PS cycles. 
**Mandate:** Routing classification shifts to PL gates. The PS Rust Application merely pushes descriptors.

| # | Sub-system | Deliverable |
| --- | --- | --- |
| **1** | AXI-Stream Ring Descriptors | 16-byte aligned hardware DMA descriptors (`paddr`, `len`, `status`). |
| **2** | UIO/VFIO Datapath | Rust userspace orchestrator managing continuous physical memory mapping to DMA rings. |
| **3** | Zero-Payload PS | The A53 CPU must never dereference payload pointers outside of TUN edge injection. |

#### Rationale

| # | Rationale |
| --- | --- |
| **1** | 16-byte descriptors perfectly align with AXI cache lines, ensuring optimal bus transfer efficiency without fetching payload memory to the CPU. |
| **2** | `vfio-pci` or UIO exposes the physical registers to the Rust application, providing full userspace polling without kernel context switching. |
| **3** | Removing packet data from the A53 L1d cache solves 90% of the latency variation. |

---

### ❌ Sprint 4: System I/O & PL Extensibility (CANNOT PROCEED: PENDING HARDWARE)

#### Debt

**[P2-01] L1i Annihilation via Subprocess Spawning** `← 4.2`
**Defect:** Software routing updates are slow.
**Mandate:** The PL controls the primary switching matrix. PTP timestamps must be assigned at the MAC, not the CPU.

| # | Sub-system | Deliverable |
| --- | --- | --- |
| **1** | PL MAC PTP Timestamping | Hardware IEEE 1588 timestamps assigned at the physical PHY boundary. |
| **2** | PL RSS Toeplitz Hashing | Symmetric flow scattering processed instantly in logic gates. |
| **3** | PL Multipath Demux | Demultiplexes heterogeneous incoming satellite streams directly to AXI queues. |

#### Rationale

| # | Rationale |
| --- | --- |
| **1** | Bypasses Linux kernel timing inaccuracies. Timestamps become 100% deterministic, resolving the 50µs transport jitter. |
| **2** | Software RSS costs valuable PS cycles. Hashing at the PL steering logic is free. |

---

### ❌ Sprint 5: PL Cryptographic Ascension (CANNOT PROCEED: PENDING HARDWARE)

#### Debt

**[P1-01] Cryptographic ALU Saturation** `← 5.1, 5.2`
**Defect:** Software NEON/AES-NI interleaving can only achieve so much throughput before the A53 inevitably overheats or stalls. 
**Mandate:** All Rust `ring` / inline assembly AES-GCM logic is entirely deleted. The PL performs all inline encryption/decryption as a bump-in-the-wire.

| # | Sub-system | Deliverable |
| --- | --- | --- |
| **1** | PL AES-256-GCM Encrypt IP | Line-rate hardware AEAD encapsulation block. |
| **2** | PL AES-256-GCM Decrypt IP | Line-rate hardware AEAD decapsulation block. |
| **3** | IP Checksum Offload | Checksum computation folded into PL transmission pipeline. |

#### Rationale

| # | Rationale |
| --- | --- |
| **1 & 2** | An AES-GCM PL IP core achieves 1 cycle/block throughput natively, guaranteeing 0 ALU bubbles on the A53 and completely annihilating the performance ceiling imposed by software crypto. |
| **3** | IP Checksum calculation in hardware costs 0 PS cycles. |

---

### ❌ Sprint 6: Hardware Sovereign Hardening (CANNOT PROCEED: PENDING HARDWARE)

#### Debt

**[P1-03] Asymmetric CPU DoS via Unfiltered Replays** `← 6.4`
**Defect:** Processing hardware anti-replay bitmasks in software still consumes DMA bandwidth and interrupts the Cortex-A53.
**Mandate:** Spoofed or replayed frames must die on the wire before they ever cross the AXI bus into the Processing System.

| # | Sub-system | Deliverable |
| --- | --- | --- |
| **1** | PL Wire-Speed Anti-Replay | RFC 6479 64-bit sliding bitmask handled in BRAM registers. |
| **2** | PL Rate-Limiting | Token bucket filters implemented in PL logic, replacing eBPF XDP. |
| **3** | Signal Handlers | Atomic wait-free teardown of AXI DMA streams in PS. |

#### Rationale

| # | Rationale |
| --- | --- |
| **1 & 2** | Drops unauthorized or spoofed traffic at the MAC boundary. The A53 never perceives the attack, maintaining 100% availability for legitimate C2 traffic and PQC handshakes. |

---

### ❌ Sprint 7: Hardware RL-AFEC & DRL (CANNOT PROCEED: PENDING HARDWARE)

#### Debt

**[P0-04] CPU Stall on Galois Field Math → 100% Drops** `← 7.1, 7.2`
**Defect:** Software RLNC encoding/decoding on Cortex-A53 consumes ~4,500 CPU cycles per parity packet. At 1 Gbps, this instantly saturates the ALU pipeline, causing catastrophic bufferbloat and dropped traffic. 
**Mandate:** SW RLNC is completely eradicated for the K26 target. GF(2^8) SIMD matrix multiplication must be offloaded to the Programmable Logic (PL) using continuous DSP slices and BRAM sliding windows.

**[P0-05] High-Latency AXI Telemetry Reads** `← 7.3`
**Defect:** Polling AXI-Lite registers for continuously changing telemetry (loss/burst arrays) saturates the AXI-Lite interface and stalls the A53 Core.
**Mandate:** DRL worker remains in software (Core 0), but ingests Continuous Implicit Feedback (CIF) telemetry natively from DMA-mapped AXI-Stream TUSER metadata, not via stalling register reads.

| # | Sub-system | Deliverable |
| --- | --- | --- |
| **1** | PL RLNC Encoder | GF(2^8) parity generation IP block in PL with AXI-Stream interfaces. |
| **2** | PL RLNC Decoder | Forward Elimination / Back-Substitution IP block in PL. |
| **3** | DRL Action-Space Control | Q16.16 NEON PPO remains on PS Core 0. Target pacing dispatched to PL via AXI-Lite registers. |
| **4** | CIF Telemetry DMA | Loss/Burst heuristics appended to AXI-Stream TUSER side-channel. |

#### Rationale

| # | Rationale |
| --- | --- |
| **1** | PL logic computes Galois Field math sequentially in O(1) clock cycles without utilizing the A53 CPU execution pipeline, making line-rate throughput deterministic. |
| **2** | Matrix inversion (Gaussian Elimination) executes deterministically within the FPGA fabric. |
| **3** | DRL Neural Network PPO updates occur at 1 Hz — too complex to synthesize into PL gates easily, but perfectly suited for background A53 NEON execution. The AI outputs a pacing integer written into an AXI-Lite register read by the PL. |
| **4** | Telemetry travels alongside packet data via stream metadata (TUSER), eliminating the need for slow, blocking register reads. |

---

### ❌ Sprint 8: FPGA V&V (CANNOT PROCEED: PENDING HARDWARE)

| # | Sub-system | Deliverable |
| --- | --- | --- |
| **1** | V&V | Tiers 2–5 + Hardware Co-Simulation |

#### V&V Matrix

"Happy Path" testing is prohibited.

**Tier 1: Core Mathematical Integration** (`tests/integration.rs`)
Validates PS control-plane mathematical logic (PQC handshakes, EWMA math).

**Tier 2: Co-Simulation** (Verilator / Cocotb)
Instead of pure Rust NetNS E2E, we must co-simulate the Rust PS binary interacting with the AXI-Stream PL testbenches via virtual UIO drivers.

**Tier 3: Cryptographic Fuzzing** (`libfuzzer` & AXI BFM)
Fuzzing the DMA transaction boundaries and the PQC payloads.

**Tier 4: Cycle Perfection** 
Guaranteeing the PL IP blocks achieve closure at the target clock frequency (e.g., 250MHz for 10Gbps path, 100MHz for 1Gbps). 

**Tier 5: Kinetic Survival / Chaos** (`tc netem` + Hardware JTAG Injection)
* Introduce artificial AXI backpressure to ensure the hardware pacing correctly throttles the PS DMA loops without freezing the A53.

---

### Sprint 9: Proof of Concept — Solo Hub Flight (within VLOS) (CANNOT PROCEED: PENDING HARDWARE)

> [!NOTE]
> No daughter drones. No WiFi AP. Single drone, single SATCOM link, within visual line of sight (VLOS). Commodity flight frame (LALE integration is Sprint X). Proves the Hub flies and is controllable over M13. Third-party software: control & telemetry (ArduPilot + MAVLink), vision (GStreamer + V4L2), D&A (uAvionix / Iris Automation). 

#### Phase 1: Bench Validation

| # | Sub-system | Deliverable |
| --- | --- | --- |
| **1** | KV260 Bench Rig | KV260 + MIPI camera (TBD) + SATCOM modem on bench harness, M13 tunnel over live satellite link |

#### Phase 2: First Flight

| # | Sub-system | Deliverable |
| --- | --- | --- |
| **1** | Hardware-Software System Integration | KV260 + MIPI camera (TBD) + SATCOM mounted on commodity flight frame, powered flight with live SATCOM backhaul |

---

### Sprint 10: Block 0 Prototype — Full Architecture (CANNOT PROCEED: PENDING HARDWARE)

> [!NOTE]
> Hub + WAN-deprived daughter drones (target: 2), WiFi 7 AP/STA, multi-SATCOM bonded backhaul, commodity airframe (LALE and custom PCB are Sprint X). Hardware: KV260 (K26 SOM), multiple SATCOM modems (target: 2), WiFi 7 radio, MIPI camera (TBD), R5F/FreeRTOS flight controller. Software: M13 (encrypted tunnel + multipath scheduler), ArduPilot + MAVLink (control & telemetry), GStreamer + V4L2 (vision), mavlink-router (multiplexing), D&A (uAvionix / Iris Automation), Yocto Linux. 

#### Phase 1: Dev Test Bench

| # | Sub-system | Deliverable |
| --- | --- | --- |
| **1** | Hub + Node Bench Rig | KV260 (Hub) + commodity ARM SBC (Node), WiFi 7 AP/STA pairing, full tunnel E2E on bench |
| **2** | Vision Integration | V4L2/GStreamer ingest interface, M13 tunnel priority class for video streams |
| **3** | Real-Time Telemetry | MAVLink bridge to M13 tunnel, priority scheduling (C2 > safety > telemetry > video) |
| **4** | NetNS Chaos Suite | Full Tier 2–5 V&V under `tc netem` loss/delay/duplication on bench |

#### Phase 2: FPGA Offload

| # | Sub-system | Deliverable |
| --- | --- | --- |
| **1** | Silicon Ascension | FPGA PL offload (AES-256-GCM pipeline via AXI4-Stream DMA) |
| **2** | Regression Validation | Re-run Phase 1 + Sprint 8 V&V tests with FPGA AES backend, verify identical output |

#### Phase 3: VLOS Flight

| # | Sub-system | Deliverable |
| --- | --- | --- |
| **1** | Hub Flight Rig | KV260 + SATCOM + WiFi 7 AP mounted on commodity airframe |
| **2** | Node Flight Rig | Daughter drone(s) with m13-node, WiFi 7 STA, tethered to Hub AP |
| **3** | Swarm C2 (VLOS) | Ground station controls Hub and Nodes over M13 tunnel, within visual line of sight |
| **4** | D&A (VLOS) | Detect-and-avoid system validation within visual line of sight |

#### Phase 4: Stress & Endurance

| # | Sub-system | Deliverable |
| --- | --- | --- |
| **1** | RF Stress Test | Controlled jamming / interference injection, validate RL-AFEC recovery |
| **2** | Endurance Soak | Continuous flight with full architecture active, measure uptime, rekey cycles, thermal |

#### Phase 5: BVLOS

| # | Sub-system | Deliverable |
| --- | --- | --- |
| **1** | BVLOS C2 | Ground station controls Hub and Nodes over M13 tunnel at >1km range, beyond visual line of sight |
| **2** | D&A (BVLOS) | Detect-and-avoid system active during BVLOS flight, verify regulatory compliance |
| **3** | Redundant C2 (software kill) | Software-kill primary SATCOM interface via M13 tunnel, verify multipath scheduler fails over to remaining links — measure switchover latency, tunnel continuity, session recovery |

---

### Sprint X: End-State Hardware Design (Future Sprint)

> [!NOTE]
> K26 SOM on both low-altitude long endurance airborne network gateway (LALE-ANG) and WAN-deprived attritable daughter drone swarm (ADDS) are end-state hardware targets. LALE and ADDS are made feasible via custom PCBs. 

| # | Sub-system | Deliverable |
| --- | --- | --- |
| **1** | LALE-ANG | Airframe integration, SATCOM modem mounting, power budget, long-endurance, target altitude (TBD) |
| **2** | ADDS | Stable swarm flight and connection to LALE-ANG, form factor, price point |
| **3** | Custom PCB | KiCad schematic, layout, BOM — weight reduction, connector elimination |

#### Rationale

| # | Rationale |
| --- | --- |
| **1** | Hub airframe must carry SATCOM modem(s), Kria K26 SOM, WiFi 7 AP, and power supply within LALE flight envelope. Physical integration defines weight/power constraints. |
| **2** | Daughter drones must be cheap enough to attrit. WAN-deprived by design — WiFi 7 STA only, no SATCOM. Form factor drives PCB requirements. |
| **3** | COTS dev boards add ~200g of unnecessary connectors, peripherals, and packaging. Custom PCB strips to essentials: SOM + radio + power regulation. Enables attritability economics at scale. |


