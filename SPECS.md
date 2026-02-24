## §1. System Specification

M13's design targets bounded-latency transport over contested RF through kernel-bypass I/O, post-quantum encryption, adaptive FEC, and COTS hardware designed for attrition-tolerant swarm deployment. The Hub runs dual kernel-bypass paths: `AF_XDP` zero-copy on the WAN-facing satellite interfaces and `io_uring` on the WiFi 7 AP interface (since `mac80211` does not support `AF_XDP`). Nodes run `io_uring` exclusively. Both run on isolated CPU cores with PQC payload encapsulation.

Implementation status by layer:

| Layer | Implemented | Remaining |
|-------|-------------|-----------|
| **Cryptography** | PQC ✅ + AES-256-GCM ✅ + Async offload ✅ | Anti-replay ❌ (S7.4) |
| **Engine** | VPP ✅ + SPSC ✅ + HugePage ✅ + EDT ✅ | RL-AFEC ❌ (S3) + BBRv3 ❌ (S5.3) |
| **Network** | AF_XDP ✅ + io_uring ✅ + eBPF ✅ + USO ✅ | RSS ❌ (S5.5) + Multipath SATCOM ❌ (S5.6) |
| **Firmware** | | FPGA PL offload ❌ (S9) |
| **Hardware** | | LALE-ANG ❌ (S11) / ADDS ❌ (S11) / Custom PCB ❌ (S11) |

> [!NOTE]
> See `TODO.md` for detailed sprint status, implementation priorities, and the full roadmap.

### Data Flow Physics

**Commands (Downstream - Low Latency, Strict Priority):**
```text
User PC ──Fiber──→ ISP ──Fiber──→ Satellite Constellation ──→ Hub [AF_XDP WAN │ WiFi AP io_uring] ──WiFi 7──→ Node (io_uring)
```

**Telemetry/Video (Upstream - High Throughput, Isochronous):**

```text
Node (io_uring) ──WiFi 7──→ Hub [io_uring WiFi AP │ AF_XDP WAN] ──Multi-Path LEO/MEO──→ Satellite Constellation ──Fiber──→ ISP ──→ User PC
```

---

## §2. Source Tree Architecture

```text
m13/
├── Cargo.toml                      ← Workspace root: hub, node, tests
├── README.md                       ← Architecture & system documentation
├── TODO.md                         ← Roadmap & technical debt ledger
├── OTHERS.md                       ← Silicon provisioning, dependencies, V&V, telemetry
├── OBSERVATIONS.md                 ← Quantified round metrics & comparisons
├── PROTOCOL.md                     ← Engineering workflow & execution protocol
│
├── tests/                          ← Integration test suite (m13-tests)
│   ├── Cargo.toml
│   ├── integration.rs              ← VPP graph, AEAD, PQC handshake, wire parity tests
│   └── src/
│       └── lib.rs
│
├── hub/                            ← Hub: AF_XDP satellite aggregator
│   ├── Cargo.toml
│   ├── build.rs                    ← eBPF compilation & kernel bindgen
│   ├── m13-hub.bb                  ← Yocto BitBake recipe
│   ├── m13-hub.p4                  ← P4 behavioral model
│   └── src/
│       ├── lib.rs                  ← Public re-exports for tests
│       ├── main.rs                 ← Orchestrator & VPP loop
│       ├── engine/
│       │   ├── mod.rs
│       │   ├── protocol.rs         ← Wire format, peer management, scheduling
│       │   ├── runtime.rs          ← Telemetry, slab allocator, core pinning
│       │   ├── spsc.rs             ← Lock-free SPSC ring
│       │   └── typestate.rs        ← Compile-time FSM typestates
│       ├── network/
│       │   ├── mod.rs
│       │   ├── xdp.rs              ← AF_XDP zero-copy engine
│       │   ├── bpf.rs              ← eBPF steering
│       │   ├── datapath.rs         ← VPP graph nodes & TUN I/O
│       │   └── uso_pacer.rs        ← Userspace Segmentation Offload
│       └── cryptography/
│           ├── mod.rs
│           ├── aead.rs             ← AES-256-GCM batch encrypt/decrypt
│           ├── handshake.rs        ← PQC handshake (server side)
│           └── async_pqc.rs        ← Async PQC offload to Core 0
│
└── node/                           ← Node: io_uring edge endpoint
    ├── Cargo.toml
    ├── build.rs                    ← Kernel bindgen
    ├── m13-node.bb                 ← Yocto BitBake recipe
    ├── m13-node.p4                 ← P4 behavioral model
    └── src/
        ├── main.rs                 ← Orchestrator & CQE three-pass loop
        ├── engine/
        │   ├── mod.rs
        │   ├── protocol.rs         ← Wire format, fragment assembly
        │   └── runtime.rs          ← Node FSM & diagnostics
        ├── network/
        │   ├── mod.rs
        │   ├── datapath.rs         ← TUN creation & route management
        │   └── uring_reactor.rs    ← io_uring SQPOLL + PBR reactor
        └── cryptography/
            ├── mod.rs
            ├── aead.rs             ← AES-256-GCM batch encrypt/decrypt
            └── handshake.rs        ← PQC handshake (client side)
```

---

## §3. Phase 1: Build & Execution Chains

### 1. Hub Build

```bash
RUSTFLAGS="-C target-cpu=native" cargo build --release --manifest-path hub/Cargo.toml
```

**What happens:**

1.  **`hub/build.rs`** executes first:
    -   Writes inline eBPF C source to `OUT_DIR/m13_xdp.c`
    -   Compiles it via `clang -O2 -g -target bpf` → `OUT_DIR/m13_xdp.o`
    -   Sets `BPF_OBJECT_PATH` env var (consumed at runtime by `BpfSteersman`)
    -   Runs `bindgen` against `linux/ethtool.h`, `linux/sockios.h`, `linux/if.h`
    -   Emits `OUT_DIR/bindings.rs` (`ethtool_ringparam`, `ifreq`, `SIOCETHTOOL`)

2.  **`rustc`** compiles with workspace release profile:
    -   `panic = "abort"`, `lto = true`, `codegen-units = 1`, `opt-level = 3`, `strip = "symbols"`
    -   `-C target-cpu=native` → AVX2/AES-NI on x86_64, NEON/CE on aarch64

3.  **Output:** `target/release/m13-hub`

### 2. Hub Execution

```bash
sudo RUST_LOG=debug ./target/release/m13-hub enp1s0f0 --tunnel --single-queue 0
```

**Exact execution sequence** (`hub/src/main.rs`):

```text
main()
├── Signal handlers: SIGTERM/SIGINT → AtomicBool SHUTDOWN
├── Panic hook: nuke_cleanup_hub() on unwind
├── CLI parse: if_name="enp1s0f0", tunnel=true, single_queue=Some(0)
│   ├── Also supports: --monitor, --hexdump, --port, -i/--iface
│   └── --monitor → run_monitor() → read /dev/shm telemetry (exits early)
├── Set M13_LISTEN_PORT=443 (default, CLI --port overrides, then env var)
└── run_executive(&if_name, single_queue, tunnel)

run_executive()
├── Re-register signal handlers (SIGTERM/SIGINT)
├── Pre-flight cleanup:
│   ├── Kill stale m13-hub processes via pgrep/SIGKILL (excludes own PID)
│   ├── Detach stale XDP: ip link set <if> xdp off
│   ├── Detach stale XDP: ip link set <if> xdpgeneric off
│   ├── ethtool -L <if> combined 1 — collapse NIC to single queue
│   └── Auto-allocate hugepages: write (workers × UMEM_SIZE / 2MB) to /proc/sys/vm/nr_hugepages (Hub UMEM fallback)
├── TSC calibration: calibrate_tsc() (rdtsc loop)
├── lock_pmu() + fence_interrupts() + discover_isolated_cores()
├── Worker count = 1 (single-queue mode) or min(isolated_cores, MAX_WORKERS)
├── BpfSteersman::load_and_attach(if_name)
│   └── Steers EtherType 0x88B5 (raw L2) and IPv4 UDP/443 to AF_XDP via XSKMAP
├── Create TUN m13tun0 + setup_nat() (if --tunnel)
│
├── SPSC Ring Creation (4 TUN rings × depth 2048):
│   ├── tx_tun:       Producer<PacketDesc> → Consumer<PacketDesc>    (datapath → TUN HK)
│   ├── rx_tun:       Producer<PacketDesc> → Consumer<PacketDesc>    (TUN HK → datapath)
│   ├── free_to_tun:  Producer<u32> → Consumer<u32>                  (datapath → TUN HK slab IDs)
│   └── free_to_dp:   Producer<u32> → Consumer<u32>                  (TUN HK → datapath slab IDs)
├── OnceLock<(usize, u32)> for UMEM base sharing between Worker 0 and TUN HK
│
├── TUN Housekeeping Thread spawn (pinned to last isolated core):
│   ├── Blocks until OnceLock published by Worker 0
│   ├── DPDK-style local cache: [u32; 4096] pending_return
│   └── Main loop:
│       ├── Phase 0: Drain pending_return → free_slab_tx
│       ├── Phase 1 (TX): Pop PacketDesc from rx_from_dp → write(tun_fd) → return slab
│       └── Phase 2 (RX): poll(POLLIN,1ms) → alloc from free_slab_rx → read(tun_fd) →
│           build Eth+M13 header in UMEM → push PacketDesc to tx_to_dp
│
├── Worker 0 handle distribution via .take():
│   └── Only worker 0 gets SPSC Producer/Consumer handles
│
└── worker_entry() (per worker thread):
    ├── pin_to_core(core_id) + verify_affinity()
    ├── Telemetry::map_worker() → /dev/shm mmap
    ├── Engine::new_zerocopy(if_name, queue_id, bpf_map_fd) → AF_XDP bind
    ├── Worker 0: umem_info.set() → unblock TUN HK thread
    ├── FixedSlab::new(8192), Scheduler, PeerTable, ReceiverState, RxBitmap
    ├── Detect hub IP from interface, resolve gateway MAC from ARP
    ├── Pre-stamp all 8192 slab frames with Eth+M13 headers
    ├── Measure ε_proc (processing jitter floor), create JitterBuffer
    │
    ├── PQC Arena Allocation:
    │   ├── payload_arena: [[0u8; 9216]; MAX_PEERS] → leaked *mut (datapath writes, Core 0 reads)
    │   └── hs_state_arena: [FlatHubHandshakeState; MAX_PEERS] → leaked *mut (Core 0 local)
    ├── PQC SPSC Rings (2 × depth 128):
    │   ├── pqc_req: Producer<PqcReq> → Consumer<PqcReq>   (datapath → Core 0)
    │   └── pqc_resp: Producer<PqcResp> → Consumer<PqcResp> (Core 0 → datapath)
    ├── PQC Control Plane Thread spawn (Core 0):
    │   └── pqc_worker_thread(): Pop PqcReq → process ClientHello/Finished → push PqcResp
    ├── EdtPacer::new(cal, 100_000_000) — zero-spin EDT, 100 Mbps default MANET link
    │
    └── VPP Main Loop:
        ├── SHUTDOWN check → graceful close: 3× FIN burst, drain until FIN-ACK or deadline
        ├── engine.recycle_tx() + engine.refill_rx()
        │
        ├── TX Graph (worker 0 only):
        │   ├── Reclaim returned slabs: free_to_dp_cons.pop_batch() → slab.free()
        │   ├── Demand-driven provision: free_to_tun_prod.available() → bounded alloc
        │   └── Pop pre-built TUN frames: rx_tun_cons.pop_batch() → encrypt → enqueue
        │
        ├── RX Graph:
        │   ├── engine.poll_rx() → rx_batch[]
        │   ├── execute_graph() → execute_subvector() per 64-packet chunk:
        │   │   ├── rx_parse_raw() → PacketVector
        │   │   ├── aead_decrypt_vector() → batch AEAD
        │   │   ├── classify/scatter → per-packet Disposition
        │   │   ├── Handshake fragments → Assembler → PQC SPSC dispatch to Core 0
        │   │   └── tun_write_vector() → SPSC push to TUN HK
        │   └── CycleStats accumulation → Telemetry SHM via fetch_add(Relaxed)
        │
        ├── PQC Response Drain:
        │   ├── Pop PqcResp batch from pqc_resp_cons
        │   ├── ServerHello: frame with datapath-local hub_ip/gateway_mac
        │   │   → build_fragmented_raw_udp() → enqueue_critical via AF_XDP
        │   └── SessionEstablished: install AES-256-GCM cipher
        │       → PeerLifecycle::Established, clear hs_sidecar
        │
        ├── Feedback generation: stage_feedback_gen() if receiver state indicates
        │
        └── Telemetry: 1/sec report:
            RX:{} TX:{} TUN_R:{} TUN_W:{} AEAD:{}/{} HS:{}/{} Slab:{}/{} Peers:{}/{} Up:{}s
```

### 3. Node Build

```bash
RUSTFLAGS="-C target-cpu=native" cargo build --release --manifest-path node/Cargo.toml
```

**What happens:**

1.  **`node/build.rs`** executes first:
    -   Runs `bindgen` against `linux/ethtool.h`, `linux/sockios.h`, `linux/if.h`
    -   Emits `OUT_DIR/bindings.rs` (`ethtool_ringparam`, `ifreq`)
    -   No eBPF compilation (Node uses `io_uring`, not `AF_XDP`)

2.  **`rustc`** compiles with identical release profile (LTO, panic=abort, codegen-units=1, target-cpu=native)

3.  **Output:** `target/release/m13-node`

### 4. Node Execution

```bash
sudo RUST_LOG=debug ./target/release/m13-node --hub-ip 206.223.224.25:443 --tunnel
```

**Exact execution sequence** (`node/src/main.rs`):

```text
main()
├── Signal handlers: SIGTERM/SIGINT → AtomicBool SHUTDOWN
├── Panic hook: nuke_cleanup_node()
├── CLI parse: echo=false, hexdump=false, tunnel=true
├── create_tun("m13tun0") → TUN fd (if --tunnel)
├── Parse --hub-ip "206.223.224.25:443" (required)
├── Store Hub IP in HUB_IP_GLOBAL Mutex (for panic hook route teardown)
└── run_uring_worker(&ip, echo, hexdump, tun_file)

run_uring_worker()
├── TSC calibration: calibrate_tsc()
├── System tuning: tune_system_buffers()
│   └── sysctl: net.core.rmem_max, wmem_max, netdev_max_backlog, rmem_default, wmem_default
├── UdpSocket::bind("0.0.0.0:0") → connect(hub_addr)
├── Socket: O_NONBLOCK, SO_RCVBUFFORCE=8MB, SO_SNDBUFFORCE=8MB
│
├── UringReactor::new(raw_fd, cpu=0):
│   ├── HugeTLB mmap: 2MB-aligned arena (PBR metadata + data frames)
│   ├── IoUring::builder().setup_sqpoll(2000ms).setup_single_issuer()
│   ├── SYS_io_uring_register IORING_REGISTER_PBUF_RING
│   ├── Pre-register all BIDs in PBR
│   └── arm_multishot_recv() → single SQE for lifetime of socket
│
├── Arm TUN reads: BIDs in [UDP_RING_ENTRIES .. TOTAL_BIDS)
├── Assembler::init(alloc_asm_arena()) — fragment reassembly state
├── Counter init: seq_tx, rx/tx/aead/tun counters
├── Build M13 header template (src_mac, hub_mac, magic, version)
├── Send initial registration frame via sock.send()
├── State machine init: NodeState::Registering
│
└── CQE Three-Pass Main Loop:
    ├── SHUTDOWN check
    ├── Connection timeout: 30s pre-Established → exit
    │
    ├── ═══ Pass 0: CQE Drain + Classify ═══
    │   ├── reactor.ring.completion().sync()
    │   ├── Drain up to 128 CQEs into cqe_batch[]
    │   ├── For each CQE, classify by tag:
    │   │   ├── TAG_UDP_RECV_MULTISHOT → collect into recv_bids[]/recv_lens[]
    │   │   │   └── Track multishot termination (IORING_CQE_F_MORE == 0 → rearm)
    │   │   ├── TAG_TUN_READ → build M13 header in-place → seal_frame → stage_udp_send
    │   │   ├── TAG_TUN_WRITE → recycle BID to PBR (add_buffer_to_pbr + commit_pbr)
    │   │   └── TAG_UDP_SEND_ECHO/TUN → arm_tun_read(bid) to recycle BID
    │   └── recv_count = number of UDP recv CQEs in this batch
    │
    ├── ═══ Pass 1: Vectorized AEAD Batch Decrypt ═══
    │   ├── If Established AND recv_count > 0:
    │   │   ├── Scan recv frames for crypto_flag == 0x01 → collect enc_ptrs[]
    │   │   ├── decrypt_batch_ptrs(enc_ptrs, enc_lens, enc_count, cipher)
    │   │   │   └── Stamps PRE_DECRYPTED_MARKER (0x02) on success
    │   │   └── Rekey check: frame_count >= limit || time > limit
    │
    ├── ═══ Pass 2: Per-Frame RxAction Dispatch ═══
    │   ├── For each recv frame:
    │   │   ├── process_rx_frame() → RxAction (PRE_DECRYPTED_MARKER skips scalar decrypt)
    │   │   ├── RxAction::NeedHandshakeInit → initiate_handshake() (PQC ClientHello)
    │   │   ├── RxAction::TunWrite → stage_tun_write(tun_fd, ptr, len, bid) — BID deferred
    │   │   ├── RxAction::Echo → build_echo_frame → seal_frame → sock.send
    │   │   ├── RxAction::HandshakeComplete → derive AEAD key → NodeState::Established
    │   │   │   └── Finished sent via send_fragmented_udp() → setup_tunnel_routes()
    │   │   ├── RxAction::HandshakeFailed → NodeState::Disconnected
    │   │   └── RxAction::RekeyNeeded → NodeState::Registering
    │   └── Recycle BID to PBR (unless deferred by TunWrite)
    │
    ├── Re-arm multishot recv if terminated
    ├── Handshake micro-timeout: 250ms retransmit via send_fragmented_udp()
    ├── Keepalive: 100ms interval, pre-Established only
    ├── Assembler GC: every 5 telemetry ticks
    ├── Telemetry: 1/sec:
    │   RX:{} TX:{} TUN_R:{} TUN_W:{} AEAD_OK:{} FAIL:{} State:{} Up:{}s
    └── reactor.submit() + submit_and_wait(0)
```

---

## §4. Connection Lifecycle: Registration → PQC Handshake → Established Tunnel

These two commands constitute the **entire** connection lifecycle. The Hub must be started first — it listens passively. The Node initiates the connection.

### Wire Protocol Constants

| Constant | Value | Source | Purpose |
|---|---|---|---|
| `ETH_P_M13` | `0x88B5` | `hub/engine/protocol.rs`, `node/engine/protocol.rs` | IEEE 802.1 Local Experimental EtherType |
| `M13_WIRE_MAGIC` | `0xD1` | both `protocol.rs` | Wire magic byte at `signature[0]` |
| `M13_WIRE_VERSION` | `0x01` | both `protocol.rs` | Protocol version at `signature[1]` |
| `FLAG_CONTROL` | `0x80` | both `protocol.rs` | Control frame (echo, keepalive) |
| `FLAG_FEEDBACK` | `0x40` | `hub/engine/protocol.rs` | Receiver feedback (loss/RTT) |
| `FLAG_TUNNEL` | `0x20` | both `protocol.rs` | Encapsulated user IP traffic |
| `FLAG_FIN` | `0x08` | `hub/engine/protocol.rs`, `node/engine/protocol.rs` | Graceful close signal |
| `FLAG_FEC` | `0x04` | `hub/engine/protocol.rs` | Reserved (formerly RLNC FEC, now unused) |
| `FLAG_HANDSHAKE` | `0x02` | both `protocol.rs` | PQC handshake control |
| `FLAG_FRAGMENT` | `0x01` | both `protocol.rs` | Fragmented message |
| `HS_CLIENT_HELLO` | `0x01` | both `protocol.rs` | Handshake sub-type: ClientHello |
| `HS_SERVER_HELLO` | `0x02` | both `protocol.rs` | Handshake sub-type: ServerHello |
| `HS_FINISHED` | `0x03` | both `protocol.rs` | Handshake sub-type: Finished |
| `DIR_HUB_TO_NODE` | `0x00` | `hub/engine/protocol.rs` | AEAD nonce direction byte (Hub→Node) |
| `DIR_NODE_TO_HUB` | `0x01` | both `protocol.rs` | AEAD nonce direction byte (Node→Hub) |
| `USO_MTU` | `1380` | `hub/network/uso_pacer.rs:22` | USO slicer MTU for EDT pacing |
| `PRE_DECRYPTED_MARKER` | `0x02` | `node/cryptography/aead.rs:56` | Stamp at `signature[2]` after batch decrypt success |
| `MAX_PEERS` | `256` | `hub/engine/protocol.rs` | PeerTable flat array capacity |
| `TUNNEL_SUBNET` | `10.13.0.0` | `hub/engine/protocol.rs` | Tunnel IP allocation range (/24) |
| `VECTOR_SIZE` | `64` | `hub/network/mod.rs` | VPP packet vector width |
| `JBUF_CAPACITY` | `128` | `hub/engine/protocol.rs` | Jitter buffer circular capacity |
| `TX_RING_SIZE` | `256` | `hub/engine/protocol.rs` | Scheduler ring depth (critical + bulk) |
| `FEEDBACK_INTERVAL_PKTS` | `32` | `hub/engine/protocol.rs` | Packets between feedback frame generation |

### Protocol Timing Constants

| Constant | Value | Source | Purpose |
|---|---|---|---|
| `REKEY_FRAME_LIMIT` | `2³² (4,294,967,296)` | both `protocol.rs` | Rekey after this many frames under one session key |
| `REKEY_TIME_LIMIT_NS` | `3,600,000,000,000 (1h)` | both `protocol.rs` | Rekey after 1 hour under one session key |
| `HANDSHAKE_RETX_INTERVAL_NS` | `5,000,000,000 (5s)` | `node/engine/protocol.rs:41` | ClientHello/Finished retransmission micro-ARQ |
| `FEEDBACK_RTT_DEFAULT_NS` | `10,000,000 (10ms)` | `hub/engine/protocol.rs` | Default RTT estimate for feedback gating |

### Message Sizes

| Message | Size | Breakdown | Source |
|---|---|---|---|
| **EthernetHeader** | 14 B | `dst(6) + src(6) + ethertype(2)` | both `protocol.rs` |
| **M13Header** | 48 B | `signature(32) + seq_id(8) + flags(1) + payload_len(4) + padding(3)` | both `protocol.rs` |
| **FragHeader** | 8 B | `msg_id(2) + index(1) + total(1) + offset(2) + len(2)` | both `protocol.rs` |
| **FeedbackFrame** | 40 B | `highest_seq(8) + rx_timestamp_ns(8) + delivered(4) + delivered_time_ns(8) + loss_count(4) + nack_bitmap(8)` | `hub/engine/protocol.rs` |
| **Feedback on wire** | 102 B | `ETH(14) + M13(48) + FeedbackFrame(40)` | `hub/engine/protocol.rs` (`FEEDBACK_FRAME_LEN`) |
| **AssemblySlot** | 9,280 B | `buf(9216) + metadata(64) = 145 cache lines, align(64)` | both `protocol.rs` |
| **ClientHello** | 4,194 B | `type(1) + version(1) + nonce(32) + ek(1568) + pk_node(2592)` | `hub/cryptography/handshake.rs:6` |
| **ServerHello** | 8,788 B | `type(1) + ct(1568) + pk_hub(2592) + sig_hub(4627)` | `hub/cryptography/handshake.rs:9` |
| **Finished** | 4,628 B | `type(1) + sig_node(4627)` | `hub/cryptography/handshake.rs:7` |
| **Registration frame** | 62 B | `ETH(14) + M13(48), flags=0x00` | `node/main.rs` (`sock.send()`) |
| **Echo frame** | 62 B | `ETH(14) + M13(48), flags=FLAG_CONTROL` | `hub/main.rs` (registration echo) |
| **Max fragment payload** | 1,402 B | Inline `max_chunk` in `build_fragmented_*` functions | both `protocol.rs` |

### AEAD Wire Geometry (M13 Header Byte Map)

```text
Byte   Field                    Encrypted?   Notes
─────  ───────────────────────  ──────────   ─────────────────────────────────────
 0- 5  dst MAC                  No           Ethernet: broadcast or peer MAC
 6-11  src MAC                  No           Ethernet: interface MAC
12-13  EtherType                No           0x88B5 (big-endian on wire)
   14  signature[0] = magic     No           0xD1 (M13_WIRE_MAGIC)
   15  signature[1] = version   No           0x01 (M13_WIRE_VERSION)
   16  signature[2] = crypto_v  No           0x00=cleartext, 0x01=encrypted, 0x02=pre-decrypted
   17  signature[3] = reserved  No           0x00 (set explicitly by seal_frame)
18-33  signature[4..20] = tag   No           16-byte AES-256-GCM authentication tag
34-45  signature[20..32] = nonce No          12-byte AEAD nonce: seq_id(8) || direction(1) || zeros(3)
46-53  seq_id                   YES          8 bytes, little-endian, monotonic
   54  flags                    YES          Single-byte bitfield (see FLAG_* table)
55-58  payload_len              YES          4 bytes, little-endian
59-61  padding                  YES          3 bytes, zero
  62+  payload                  YES          Variable: tunnel IP data or handshake fragment
```

**Encrypted region:** `signature[2]` is set to `0x01` by `seal_frame`. Bytes `[m13_off+32..frame_end]` are encrypted in-place via AES-256-GCM. The 16-byte authentication tag is stored in `signature[4..20]`.

**Nonce construction** (`hub/cryptography/aead.rs`, `node/cryptography/aead.rs`):
```text
nonce[0..8] = seq_id as little-endian u64 (8 bytes, monotonic counter)
nonce[8]    = direction byte (DIR_HUB_TO_NODE=0x00 or DIR_NODE_TO_HUB=0x01)
nonce[9..12]= zeros (3 bytes)
               Total: 12 bytes (AES-256-GCM standard nonce)
```
The full 12-byte nonce is stored on-wire at `signature[20..32]`. On decrypt, `open_frame()` reads it back from the frame.

**AAD:** `signature[0..4]` (magic + version + crypto_ver + reserved) = 4 bytes of Associated Authenticated Data.

**Reflection guard:** `open_frame()` rejects frames where `nonce_bytes[8] == our_dir`. A Hub (`DIR_HUB_TO_NODE=0x00`) only accepts frames with `nonce[8]=0x01` (Node→Hub). This prevents replaying a party's own frames back at it.

**Offset parameter:** Hub AEAD functions take an `offset` parameter to handle different wire encodings:
- L2 mode: `offset = ETH_HDR_SIZE (14)` — M13 header immediately after Ethernet
- UDP mode: `offset = 42` (ETH + IP + UDP headers, `RAW_HDR_LEN` from `hub/network/datapath.rs`)

### Sequence Diagram

```text
     Node                                          Hub
       │                                            │
       │  1. Registration: ETH+M13(62B, flags=0x00) │
       │───────────────────────────────────────────→│ lookup_or_insert() → PeerLifecycle::Registered
       │                                            │ Reconnection guard: evict same-IP stale peers
       │                                            │
       │  2. Echo: ETH+M13(62B, flags=FLAG_CONTROL) │
       │←───────────────────────────────────────────│ 100ms throttled echo (slab-safe)
       │                                            │
       │  3. ClientHello (4194B, fragmented)         │
       │  k=3 systematic frags × 1402B              │
       │───────────────────────────────────────────→│ Assembler.feed() → reassemble
       │                                            │ Dispatch to Core 0 via PQC SPSC ring
       │                                            │
       │                              ┌─────────────┤ Core 0: process_client_hello_hub()
       │                              │  ML-KEM-1024 encaps + ML-DSA-87 sign
       │                              │  ~10ms (cold-path, off datapath)
       │                              └─────────────┤ PqcResp{msg_type=0x02, ServerHello payload}
       │                                            │
       │  4. ServerHello (8788B, fragmented)         │
       │  k=7 systematic frags × 1402B              │
       │  via build_fragmented_raw_udp()            │
       │←───────────────────────────────────────────│ PQC drain → frame with local hub_ip/gw_mac
       │                                            │
       │  Node: process_rx_frame() →                │
       │    Assembler.feed() → reassemble           │
       │    ML-KEM-1024 decaps + HKDF-SHA-512       │
       │    ML-DSA-87 verify hub signature          │
       │    Derive session_key → install cipher     │
       │    NodeState::Established                  │
       │    setup_tunnel_routes()                   │
       │                                            │
       │  5. Finished (4628B, fragmented)            │
       │  k=4 systematic frags × 1402B              │
       │  via send_fragmented_udp()                 │
       │───────────────────────────────────────────→│ Assembler.feed() → reassemble
       │                                            │ Dispatch to Core 0 via PQC SPSC ring
       │                              ┌─────────────┤ Core 0: process_finished_hub()
       │                              │  ML-DSA-87 verify node signature
       │                              │  ~5ms (cold-path, off datapath)
       │                              └─────────────┤ PqcResp{msg_type=0x03, session_key}
       │                                            │
       │                                            │ PQC drain: install AES-256-GCM cipher
       │                                            │ PeerLifecycle::Established
       │                                            │ alloc_tunnel_ip() → 10.13.0.X
       │                                            │
       │══════════ AEAD Tunnel Established ═════════│
       │                                            │
       │  6a. Upstream: TUN read → seal_frame()     │
       │  Batch encrypt_batch_ptrs (4-at-a-time)    │
       │  → sock.send() via build_m13_frame()      │
       │───────────────────────────────────────────→│ rx_parse_raw() → aead_decrypt_vector()
       │                                            │ classify_route() → TunWrite
       │                                            │ tun_write_vector() → SPSC → TUN HK thread
       │                                            │
       │  6b. Downstream: TUN HK read → SPSC →     │
       │  execute_tx_graph() → seal_frame()         │
       │  build_raw_udp_frame()                     │
       │  EDT pacer → Scheduler → AF_XDP TX        │
       │←───────────────────────────────────────────│
       │  decrypt_batch_ptrs() → PRE_DECRYPTED_MARKER
       │  process_rx_frame() → TunWrite             │
       │  stage_tun_write() → kernel TUN            │
       │                                            │
       │  7. Feedback (every 32 pkts)                │
       │←───────────────────────────────────────────│ produce_feedback_frame() (102B)
       │                                            │
       │  8. Rekey (2³² frames or 1 hour)            │
       │  Node: RxAction::RekeyNeeded →             │
       │  NodeState::Registering → restart from 1   │
       │                                            │
```

### Phase 1: Hub Startup

**Command:** `sudo RUST_LOG=debug ./target/release/m13-hub enp1s0f0 --tunnel --single-queue 0`

```text
main()                                                        [hub/src/main.rs:44]
├── Signal handlers: SIGTERM/SIGINT → AtomicBool SHUTDOWN     [main.rs:48-51]
├── Panic hook: nuke_cleanup_hub() on unwind                  [main.rs:55-59]
├── CLI parse:                                                [main.rs:65-103]
│   if_name = "enp1s0f0"
│   tunnel_mode = true
│   single_queue = Some(0)
│   listen_port = Some(443)  ← default, blends with QUIC
│   hexdump_mode = false
├── Set M13_LISTEN_PORT = "443" (env var)                     [main.rs:109-123]
└── run_executive("enp1s0f0", Some(0), true)                  [main.rs:124]

run_executive()                                               [hub/src/main.rs:128]
├── Re-register SIGTERM/SIGINT signal handlers                [main.rs:133-136]
│
├── === PRE-FLIGHT CLEANUP ===
│   ├── Kill stale m13-hub: pgrep + SIGKILL (exclude self)    [main.rs:141-154]
│   ├── Detach stale XDP:                                     [main.rs:156-157]
│   │   ip link set enp1s0f0 xdp off
│   │   ip link set enp1s0f0 xdpgeneric off
│   ├── ethtool -L enp1s0f0 combined 1                        [main.rs:162-176]
│   │   Collapse NIC to single queue so ALL traffic hits queue 0
│   │   (AF_XDP binds to queue 0; RSS would distribute packets away)
│   └── Hugepage allocation:                                  [main.rs:178-185]
│       Write ceil(UMEM_SIZE/2MB) to /proc/sys/vm/nr_hugepages (Hub UMEM fallback)
│
├── TSC calibration: calibrate_tsc()                          [hub/engine/runtime.rs]
│   rdtsc loop against CLOCK_MONOTONIC → TscCal{tsc_hz, ns_per_tsc}
│
├── lock_pmu() + fence_interrupts()                           [hub/engine/runtime.rs]
│   perf_event_open PMU on every core (prevent frequency scaling)
│   IRQ affinity: move all IRQs off isolated cores
│
├── discover_isolated_cores()                                 [hub/engine/runtime.rs]
│   Parse /sys/devices/system/cpu/isolated or M13_MOCK_CMDLINE
│
├── worker_count = 1 (single-queue mode)
│
├── BpfSteersman::load_and_attach("enp1s0f0")                [hub/network/bpf.rs]
│   ├── Read BPF_OBJECT_PATH (set by build.rs)
│   ├── bpf_object__open_file() → bpf_object__load()
│   ├── m13_steersman XDP program:                            [hub/build.rs:44-77]
│   │   Path 1: EtherType 0x88B5 → bpf_redirect_map(xsks_map) [raw L2 M13]
│   │   Path 2: IPv4 UDP dst port 443 → bpf_redirect_map     [UDP-encaps M13]
│   │   Default: XDP_PASS (SSH, ARP, etc. to kernel stack)
│   ├── bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_DRV_MODE)
│   │   Fallback: XDP_FLAGS_SKB_MODE if driver mode fails
│   └── xsks_map fd returned for AF_XDP socket registration
│
├── create_tun("m13tun0")                                     [hub/network/datapath.rs]
│   ioctl(TUNSETIFF, IFF_TUN | IFF_NO_PI) → TUN fd
│
├── setup_nat()                                               [hub/network/datapath.rs]
│   ├── ip link set m13tun0 up
│   ├── ip addr add 10.13.0.1/24 dev m13tun0
│   ├── sysctl net.ipv4.ip_forward = 1
│   ├── iptables -t nat -A POSTROUTING -s 10.13.0.0/24 -j MASQUERADE
│   ├── iptables -A FORWARD -i m13tun0 -j ACCEPT
│   ├── iptables -A FORWARD -o m13tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT
│   └── System buffer tuning: sysctl rmem_max/wmem_max/netdev_max_backlog/rmem_default/wmem_default
│
├── SPSC Ring Creation (4 rings × depth 2048):                [main.rs:218-227]
│   tx_tun:      Producer<PacketDesc> → Consumer<PacketDesc>  (datapath → TUN HK)
│   rx_tun:      Producer<PacketDesc> → Consumer<PacketDesc>  (TUN HK → datapath)
│   free_to_tun: Producer<u32> → Consumer<u32>                (datapath → TUN HK: slab IDs)
│   free_to_dp:  Producer<u32> → Consumer<u32>                (TUN HK → datapath: slab IDs)
│   All rings from hub/engine/spsc.rs: lock-free, cache-aligned, power-of-two
│
├── OnceLock<(usize, u32)> for UMEM base sharing              [main.rs:232-233]
│   Worker 0 publishes (umem_base_ptr, frame_size) after Engine::new()
│   TUN HK thread blocks on .get() until published
│
├── TUN Housekeeping Thread spawn                              [main.rs:236-254]
│   Pinned to last isolated core
│   tun_housekeeping_thread():                                [main.rs:757-940]
│   ├── Blocks until umem_info.get() returns (Worker 0 must start first)
│   ├── DPDK-style local cache: [u32; 4096] pending_return
│   └── Main loop:
│       ├── Phase 0: Drain pending_return → free_slab_tx.push_batch()
│       ├── Phase 1 (TX to kernel): Pop PacketDesc from rx_from_dp →
│       │   write(tun_fd, payload) → return slab ID to free_slab_tx
│       └── Phase 2 (RX from kernel): poll(POLLIN, 1ms) →
│           alloc from free_slab_rx → read(tun_fd) →
│           build ETH+M13 header in UMEM → push PacketDesc to tx_to_dp
│
├── Worker 0 handle distribution via .take()                   [main.rs:262-278]
│   Only worker 0 gets SPSC Producer/Consumer handles
│
└── worker_entry() spawned on isolated core                    [main.rs:942-1542]
    ├── pin_to_core(core_id) + verify_affinity()              [hub/engine/runtime.rs]
    ├── Telemetry::map_worker() → /dev/shm mmap               [hub/engine/runtime.rs]
    │
    ├── Engine::new_zerocopy(if_name, queue_id, bpf_map_fd)    [hub/network/xdp.rs]
    │   ├── HugeTLB mmap for UMEM (2MB hugepages)
    │   ├── xsk_socket__create_shared() → AF_XDP socket
    │   ├── bpf_map_update_elem(xsks_map, queue_id, xsk_fd)
    │   └── Fill Ring, Completion Ring, RX Ring, TX Ring initialized
    │
    ├── Worker 0: umem_info.set() → unblock TUN HK thread     [main.rs:962-966]
    │
    ├── FixedSlab::new(8192)                                   [hub/engine/runtime.rs]
    │   Bitmap-based O(1) allocator for UMEM frame indices
    │
    ├── Scheduler::new() — dual-queue (critical/bulk) + EDT    [hub/engine/protocol.rs]
    ├── PeerTable::new(epoch_ns) — 256 slots + assemblers      [hub/engine/protocol.rs]
    │   Each slot: PeerSlot(64B align), Scheduler, ReceiverState, JitterBuffer,
    │   Assembler(8 HugeTLB AssemblySlots), cipher, hs_sidecar
    ├── ReceiverState::new() + RxBitmap::new()                 [hub/engine/protocol.rs]
    │
    ├── Detect hub_ip from interface, resolve gateway_mac       [hub/network/datapath.rs]
    │   get_interface_ip() + resolve_gateway_mac() (ARP table parse)
    │
    ├── Pre-stamp ALL 8192 slab frames with ETH+M13 headers    [main.rs:1007-1022]
    │   dst=[0xFF;6], src=iface_mac, ethertype=0x88B5(BE),
    │   magic=0xD1, version=0x01, seq=0, flags=0
    │
    ├── measure_epsilon_proc() → processing jitter floor        [hub/engine/protocol.rs]
    ├── JitterBuffer::new()                                    [hub/engine/protocol.rs]
    │   RFC 3550 EWMA Q60.4 fixed-point jitter estimator
    │   Circular release buffer, JBUF_CAPACITY=128
    │
    ├── PQC Arena Allocation:                                  [main.rs:1052-1064]
    │   payload_arena: [[0u8; 9216]; MAX_PEERS] → leaked *mut
    │     (datapath writes reassembled handshake, Core 0 reads)
    │   hs_state_arena: [FlatHubHandshakeState; MAX_PEERS] → leaked *mut
    │     (Core 0 local: stores inter-message handshake state)
    │
    ├── PQC SPSC Rings (2 × depth 128):                        [hub/cryptography/async_pqc.rs]
    │   pqc_req: Producer<PqcReq> → Consumer<PqcReq>           (datapath → Core 0)
    │   pqc_resp: Producer<PqcResp> → Consumer<PqcResp>        (Core 0 → datapath)
    │
    ├── PQC Control Plane Thread spawn on Core 0:               [main.rs:1070-1081]
    │   pqc_worker_thread(): Pop PqcReq → process ClientHello/Finished → push PqcResp
    │   Runs ML-KEM-1024 + ML-DSA-87 (~10ms+5ms) OFF the datapath
    │
    ├── EdtPacer::new(cal, 100_000_000)                         [hub/network/uso_pacer.rs]
    │   Zero-spin EDT pacer, 100 Mbps default MANET link rate
    │   per-byte pacing: delay_ns = frame_bytes × ns_per_byte
    │
    └── ═══ VPP Main Loop ═══                                 [main.rs:1094-1530]
        │
        ├── SHUTDOWN check → graceful close:                   [main.rs:1097-1131]
        │   3× FIN burst to all Established peers via
        │   send_fin_burst_udp() or send_fin_burst_l2()
        │   Then RX-only until FIN-ACK or deadline
        │
        ├── engine.recycle_tx() + engine.refill_rx()           [hub/network/xdp.rs]
        │   Reclaim completed TX descriptors, refill RX ring
        │
        ├── TX Graph (worker 0 only):                          [main.rs:1140-1178]
        │   execute_tx_graph() → [hub/main.rs:651-755]
        │   ├── Reclaim returned slabs: free_to_dp_cons.pop_batch() → slab.free()
        │   ├── Demand-driven slab provision: free_to_tun_prod.push_batch()
        │   └── Pop TUN frames: rx_tun_cons.pop_batch() →
        │       lookup_by_tunnel_ip() → seal_frame() → build_fragmented_raw_udp()
        │       EDT pacer.pace() → enqueue_bulk_edt() with release_ns timestamp
        │
        ├── Telemetry: 1/sec report                            [main.rs:1180-1196]
        │
        ├── STAGE 0: Adaptive batch drain                      [main.rs:1198-1207]
        │   engine.poll_rx_batch() → xdp_desc[] (up to GRAPH_BATCH=256)
        │   Coalesce loop: gather until 256 or DEADLINE_NS (50µs)
        │
        ├── STAGE 0.5: Jitter buffer drain                     [main.rs:1209-1222]
        │   jbuf.drain(now_ns, scheduler) → release buffered frames
        │
        ├── VPP Graph Executor:                                [main.rs:1224-1418]
        │   execute_graph(rx_descs, GraphCtx)                  [main.rs:340-379]
        │   └── execute_subvector() per 64-packet chunk:       [main.rs:381-552]
        │       ├── rx_parse_raw() → PacketVector              [hub/network/datapath.rs]
        │       │   Validates magic, version, crypto_ver routing:
        │       │   crypto_ver=0x00 → cleartext_out (handshake/control)
        │       │   crypto_ver=0x01 → decrypt_out  (AEAD encrypted)
        │       │   Learns hub_ip/gateway_mac from first inbound
        │       │
        │       ├── aead_decrypt_vector()                      [hub/network/datapath.rs]
        │       │   Per-packet: peer lookup → open_frame() with peer cipher
        │       │   Reflection guard: nonce[0] ≠ DIR_HUB_TO_NODE
        │       │
        │       ├── classify_route() → Disposition             [hub/network/datapath.rs]
        │       │   Priority routing (first match wins):
        │       │   FLAG_FIN       → Consumed (FIN deferred to post-executor)
        │       │   FLAG_FEEDBACK  → Feedback
        │       │   FLAG_FRAGMENT  → Handshake
        │       │   FLAG_HANDSHAKE → Handshake
        │       │   FLAG_CONTROL   → Consumed (echo, keepalive)
        │       │   FLAG_TUNNEL    → TunWrite
        │       │   default        → TxEnqueue (data forward)
        │       │
        │       ├── scatter()                                  [hub/network/mod.rs]
        │       │   4-wide prefetch scatter into per-NextNode output vectors
        │       │
        │       ├── Handshake fragments:                       [main.rs:554-649]
        │       │   process_fragment() →
        │       │     typestate validate_frag_index() + validate_frag_data_bounds()
        │       │     Assembler.feed() →
        │       │     process_handshake_message() →
        │       │       Copy payload into payload_arena[pidx]
        │       │       Push PqcReq to Core 0 via pqc_req SPSC
        │       │
        │       ├── tun_write_vector()                         [hub/network/datapath.rs]
        │       │   Push PacketDesc to SPSC tx_tun ring → TUN HK thread
        │       │   (worker 0 only; other workers: direct write(tun_fd))
        │       │
        │       └── CycleStats accumulation → Telemetry SHM
        │
        ├── FIN processing (deferred from executor):           [main.rs:1309-1338]
        │   FIN received → send_fin_burst_*() FIN-ACK → evict peer
        │   FIN-ACK received → clear deadline, close complete
        │
        ├── Registration echo processing:                      [main.rs:1340-1417]
        │   For each non-Established peer:
        │   100ms throttle → build Echo (FLAG_CONTROL) →
        │   build_raw_udp_frame() or raw L2 → enqueue_critical()
        │   Slab leak prevention: free on enqueue failure
        │
        ├── STAGE 3: Feedback generation                       [main.rs:1422, main.rs:310-336]
        │   stage_feedback_gen() if needs_feedback(pkt_since_feedback ≥ 32)
        │   produce_feedback_frame() → 102B → enqueue_critical()
        │
        ├── V4: PQC Response Drain                             [main.rs:1424-1516]
        │   Pop PqcResp batch from pqc_resp_cons:
        │   ├── msg_type=0x02 (ServerHello):
        │   │   Frame payload with local hub_ip/gateway_mac
        │   │   build_fragmented_raw_udp() or build_fragmented_l2()
        │   │   → enqueue_critical() (handshake frames are priority)
        │   └── msg_type=0x03 (SessionEstablished):
        │       Install AES-256-GCM LessSafeKey in peers.ciphers[pidx]
        │       PeerLifecycle::Established, alloc_tunnel_ip()
        │       Clear hs_sidecar
        │
        ├── STAGE 6: Schedule TX                               [main.rs:1518-1523]
        │   scheduler.schedule(tx_path, now_ns):
        │   EDT-gated dequeue: critical-first, then bulk
        │   Won't release frames before release_ns timestamp
        │   tx_path.stage_tx_addr() → tx_path.commit_tx() → kick_tx()
        │
        └── Periodic GC (every 10,000 cycles):                 [main.rs:1524-1529]
            peers.gc() + assembler.gc() per peer

═══ HUB IS NOW IDLE, VPP LOOP POLLING, WAITING FOR INBOUND NODE PACKETS ═══
```

### Phase 2: Node Connection

**Command:** `sudo RUST_LOG=debug ./target/release/m13-node --hub-ip 206.223.224.25:443 --tunnel`

```text
main()                                                        [node/src/main.rs:37]
├── Signal handlers: SIGTERM/SIGINT → AtomicBool SHUTDOWN     [main.rs:42-44]
├── Panic hook: nuke_cleanup_node()                            [main.rs:48-52]
│   Calls: nuke_cleanup("m13tun0", hub_ip)                    [node/network/datapath.rs]
│   Idempotent: ip route del, ip link del, iptables flush
│
├── CLI parse:                                                 [main.rs:54-74]
│   echo = false, hexdump = false, tunnel = true
│   hub_ip = Some("206.223.224.25:443")
│
├── create_tun("m13tun0")                                      [node/network/datapath.rs]
│   ioctl(TUNSETIFF, IFF_TUN | IFF_NO_PI) → File
│
├── Store hub IP in HUB_IP_GLOBAL Mutex                        [main.rs:78-79]
│   (for panic hook route teardown)
│
└── run_uring_worker("206.223.224.25:443", false, false, Some(tun))  [main.rs:81]

run_uring_worker()                                             [node/src/main.rs:723]
├── TSC calibration: calibrate_tsc()                           [node/engine/runtime.rs]
│
├── tune_system_buffers()                                      [main.rs:274-330]
│   sysctl: net.core.rmem_max, wmem_max, netdev_max_backlog,
│   rmem_default, wmem_default (all to 4MB+)
│
├── UdpSocket::bind("0.0.0.0:0") → connect(hub_addr)          [main.rs]
│   O_NONBLOCK, SO_RCVBUFFORCE=8MB, SO_SNDBUFFORCE=8MB
│
├── UringReactor::new(raw_fd, cpu=0)                           [node/network/uring_reactor.rs]
│   ├── HugeTLB mmap: 2MB-aligned arena (PBR metadata + data frames)
│   ├── IoUring::builder()
│   │   .setup_sqpoll(2000ms)        SQPOLL kernel thread, 2s idle timeout
│   │   .setup_single_issuer()       Single-thread SQ ownership
│   ├── SYS_io_uring_register IORING_REGISTER_PBUF_RING
│   │   Register Provided Buffer Ring with kernel
│   ├── Pre-register all BIDs in PBR
│   └── arm_multishot_recv()
│       Single SQE IORING_OP_RECV with IOSQE_BUFFER_SELECT + MULTISHOT
│       Survives for lifetime of socket (no per-packet SQE submission)
│
├── Arm TUN reads: BIDs in [UDP_RING_ENTRIES .. TOTAL_BIDS)
│
├── Assembler::init(alloc_asm_arena())                         [node/engine/protocol.rs]
│   8 AssemblySlots × 9280B per slot (HugeTLB arena)
│
├── Build M13 header template                                  [node/engine/protocol.rs]
│   detect_mac(None) → LAA random MAC
│   src_mac, hub_mac=[0xFF;6], magic=0xD1, version=0x01
│
├── ══════════════════════════════════════════════════════════
│   STEP 1: REGISTRATION
│   ══════════════════════════════════════════════════════════
│   build_m13_frame(src_mac, hub_mac, seq=0, flags=0x00)       [node/engine/protocol.rs:61]
│   → 62-byte frame: ETH(14) + M13(48), all zeroes payload
│   sock.send(&frame)                                          [main.rs]
│   NodeState::Registering                                     [node/engine/runtime.rs]
│
│   Hub receives:
│   rx_parse_raw() → cleartext_out (crypto_ver=0x00)
│   classify_route() → Consumed (flags=0x00, no flag match → TxEnqueue but no session)
│   lookup_or_insert(PeerAddr::Udp{ip, port}, src_mac) → PeerSlot allocated
│   PeerLifecycle::Registered
│   Reconnection guard: if same source IP exists with different port, evict stale
│
│   Hub responds with Echo:
│   100ms throttled, build_raw_udp_frame(FLAG_CONTROL) → enqueue_critical()
│
└── ═══ CQE Three-Pass Main Loop ═══                          [main.rs]
    │
    ├── SHUTDOWN check + 30s connection timeout                [main.rs]
    │
    ├── ══════════════════════════════════════════════════════
    │   STEP 2: NODE RECEIVES ECHO → INITIATES HANDSHAKE
    │   ══════════════════════════════════════════════════════
    │   CQE Pass 0: TAG_UDP_RECV_MULTISHOT → recv frame
    │   Pass 2: process_rx_frame() scans flags:
    │     flags=FLAG_CONTROL, state=Registering
    │     → RxAction::NeedHandshakeInit
    │
    │   initiate_handshake():                                  [node/cryptography/handshake.rs]
    │   ├── OsRng → client_nonce (32 bytes)
    │   ├── ML-KEM-1024 KeyGen → (dk_node, ek_node)            [ml-kem crate]
    │   │   ek_node = 1568 bytes (encapsulation key)
    │   │   dk_node = decapsulation key (stored in NodeHandshakeState)
    │   ├── ML-DSA-87 KeyGen → (sk_node, pk_node)              [ml-dsa crate]
    │   │   pk_node = 2592 bytes (verification key)
    │   │   sk_node = signing key (stored in NodeHandshakeState)
    │   └── Build ClientHello payload (4194B):
    │       [0] = HS_CLIENT_HELLO (0x01)
    │       [1] = version (0x01)
    │       [2..34] = client_nonce
    │       [34..1602] = ek_node (ML-KEM-1024 encapsulation key)
    │       [1602..4194] = pk_node (ML-DSA-87 verification key)
    │
    │   send_fragmented_udp(payload, flags=FLAG_CONTROL|FLAG_HANDSHAKE)
    │     k = ceil(4194/1402) = 3 systematic fragments
    │     Each fragment: ETH(14) + M13(48) + FragHdr(8) + chunk(≤1402)
    │   NodeState::Handshaking
    │
    ├── ══════════════════════════════════════════════════════
    │   STEP 3: HUB PROCESSES CLIENT HELLO
    │   ══════════════════════════════════════════════════════
    │   Hub VPP loop receives 3 fragments:
    │   rx_parse_raw() → cleartext_out (crypto_ver=0x00, handshake)
    │   classify_route(): FLAG_FRAGMENT → NextNode::Handshake
    │   scatter() → handshake_out vector
    │
    │   process_fragment():                                    [hub/main.rs:554-596]
    │   ├── typestate::validate_frag_index(index, total)       [hub/engine/typestate.rs]
    │   │   Branchless: (index >= total) as usize → panic-free clamp
    │   ├── typestate::validate_frag_data_bounds(offset, len)  [hub/engine/typestate.rs]
    │   │   Branchless OOB check preventing adversarial slice
    │   └── peers.assemblers[pidx].feed(msg_id, index, total, offset, data)
    │       On completion (all 3 fragments received):
    │       → process_handshake_message(reassembled_4194B)
    │
    │   process_handshake_message():                            [hub/main.rs:598-649]
    │   ├── reassembled[0] = HS_CLIENT_HELLO (0x01)
    │   ├── Copy 4194B into payload_arena[pidx]
    │   │   (shared memory: datapath writes, Core 0 reads)
    │   ├── Push PqcReq{pidx, msg_type=0x01, payload_len=4194}
    │   │   to pqc_req SPSC ring
    │   └── PeerLifecycle::Handshaking
    │
    │   Core 0 PQC Worker Thread:                              [hub/cryptography/async_pqc.rs]
    │   pqc_worker_thread() pops PqcReq:
    │   ├── Reads payload from payload_arena[pidx]
    │   ├── process_client_hello_hub(payload):                 [hub/cryptography/handshake.rs]
    │   │   ├── Validate: len ≥ 4194, type=0x01, version=0x01
    │   │   ├── Parse: nonce(32B), ek_node(1568B), pk_node(2592B)
    │   │   ├── ML-KEM-1024 Encapsulate(ek_node) → (ct, shared_secret)
    │   │   │   ct = 1568 bytes (ciphertext)
    │   │   │   shared_secret = 32 bytes
    │   │   ├── ML-DSA-87 KeyGen → (sk_hub, pk_hub)
    │   │   │   pk_hub = 2592 bytes
    │   │   ├── Transcript hash: SHA-512(client_nonce || ct || pk_hub)
    │   │   ├── ML-DSA-87 sign_deterministic(sk_hub, transcript)
    │   │   │   → sig_hub = 4627 bytes
    │   │   ├── Build ServerHello (8788B):
    │   │   │   [0] = HS_SERVER_HELLO (0x02)
    │   │   │   [1..1569] = ct
    │   │   │   [1569..4161] = pk_hub
    │   │   │   [4161..8788] = sig_hub
    │   │   └── Store HubHandshakeState{shared_secret, pk_node, transcript, pk_hub}
    │   │
    │   └── Push PqcResp{pidx, msg_type=0x02, response=ServerHello(8788B), success=1}
    │
    │   Back on datapath (PQC Response Drain):                 [hub/main.rs:1424-1496]
    │   ├── Pop PqcResp, msg_type=0x02
    │   ├── Frame ServerHello with local hub_ip/gateway_mac
    │   ├── build_fragmented_raw_udp():                        [hub/engine/protocol.rs]
    │   │   k = ceil(8788/1402) = 7 systematic fragments
    │   │   Each: ETH(14) + IP(20) + UDP(8) + M13_FRAG
    │   └── enqueue_critical() for each fragment (priority TX)
    │
    ├── ══════════════════════════════════════════════════════
    │   STEP 4: NODE PROCESSES SERVER HELLO
    │   ══════════════════════════════════════════════════════
    │   Node CQE loop receives 7 fragments:
    │   Pass 2: process_rx_frame():                            [node/main.rs:112-255]
    │   ├── flags & FLAG_FRAGMENT → Assembler.feed()
    │   │   7 fragments → reassemble 8788B ServerHello
    │   ├── reassembled[0] = HS_SERVER_HELLO (0x02)
    │   ├── process_server_hello_node():                       [node/cryptography/handshake.rs]
    │   │   ├── Parse: ct(1568B), pk_hub(2592B), sig_hub(4627B)
    │   │   ├── Transcript hash: SHA-512(client_nonce || ct || pk_hub)
    │   │   ├── ML-DSA-87 verify_with_context(pk_hub, transcript, sig_hub)
    │   │   │   → Verify hub identity (prevents MITM)
    │   │   ├── ML-KEM-1024 Decapsulate(dk_node, ct) → shared_secret
    │   │   ├── HKDF-SHA-512(salt=client_nonce, IKM=shared_secret,
    │   │   │     info="M13-PQC-SESSION-KEY-v1", L=32)
    │   │   └── Return NodeHandshakeResult{session_key, pk_hub, transcript}
    │   │
    │   ├── Install AES-256-GCM cipher: LessSafeKey::new(session_key)
    │   ├── Build Finished message (4628B):
    │   │   [0] = HS_FINISHED (0x03)
    │   │   [1..4628] = ML-DSA-87 sign_deterministic(sk_node, transcript)
    │   │               = sig_node (4627 bytes)
    │   │
    │   ├── send_fragmented_udp(Finished, FLAG_CONTROL|FLAG_HANDSHAKE)
    │   │   k = ceil(4628/1402) = 4 systematic fragments
    │   │
    │   ├── NodeState::Established                             [node/engine/runtime.rs]
    │   │
    │   └── setup_tunnel_routes(hub_ip):                       [node/network/datapath.rs]
    │       ├── ip addr add 10.13.0.2/24 dev m13tun0
    │       ├── ip link set m13tun0 up
    │       ├── Detect default gateway via ip route show default
    │       ├── ip route add <hub_ip>/32 via <gateway>         [preserve Hub reachability]
    │       ├── ip route add 0.0.0.0/1 dev m13tun0             [split-default routing]
    │       ├── ip route add 128.0.0.0/1 dev m13tun0           [covers all IPs, overrides default]
    │       ├── Disable IPv6: net.ipv6.conf.all.disable_ipv6=1
    │       ├── iptables -t nat -A POSTROUTING -o m13tun0 -j MASQUERADE
    │       ├── MSS clamping: iptables -A FORWARD -p tcp --tcp-flags SYN,RST SYN
    │       │   -j TCPMSS --clamp-mss-to-pmtu
    │       ├── TCP BDP tuning: sysctl net.ipv4.tcp_wmem/rmem max=16MB
    │       └── tc qdisc replace dev m13tun0 root fq
    │
    ├── ══════════════════════════════════════════════════════
    │   STEP 5: HUB PROCESSES FINISHED
    │   ══════════════════════════════════════════════════════
    │   Hub receives 4 fragments → Assembler → reassemble 4628B
    │   process_handshake_message():
    │   ├── reassembled[0] = HS_FINISHED (0x03)
    │   ├── Copy into payload_arena[pidx]
    │   └── Push PqcReq{pidx, msg_type=0x03} to Core 0
    │
    │   Core 0: process_finished_hub():                        [hub/cryptography/handshake.rs]
    │   ├── Parse: sig_node (4627B)
    │   ├── ML-DSA-87 verify_with_context(pk_node, transcript, sig_node)
    │   │   → Verify node identity (mutual authentication)
    │   ├── HKDF-SHA-512(salt=session_nonce, IKM=shared_secret,
    │   │     info="M13-PQC-SESSION-KEY-v1", L=32)
    │   └── Push PqcResp{pidx, msg_type=0x03, session_key, success=1}
    │
    │   Datapath PQC drain:                                    [hub/main.rs:1497-1512]
    │   ├── Install AES-256-GCM: LessSafeKey::new(session_key)
    │   │   into peers.ciphers[pidx]
    │   ├── peers.slots[pidx].lifecycle = PeerLifecycle::Established
    │   ├── alloc_tunnel_ip() → 10.13.0.X (bitmap allocator)
    │   └── Clear hs_sidecar[pidx]
    │
    ├── ══════════════════════════════════════════════════════
    │   STEP 6: AEAD TUNNEL — STEADY STATE
    │   ══════════════════════════════════════════════════════
    │
    │   === UPSTREAM (Node → Hub) ===
    │   Node CQE loop:
    │   ├── TUN read (CQE TAG_TUN_READ):
    │   │   Build M13 header in-place over HugeTLB buffer
    │   │   seal_frame(buf, cipher, seq, DIR_NODE_TO_HUB)      [node/cryptography/aead.rs]
    │   │   stage_udp_send() → io_uring SQE
    │   │
    │   ├── Batch path (encrypt_batch_ptrs):                   [node/cryptography/aead.rs]
    │   │   4-at-a-time prefetch → saturate AES-NI/ARMv8-CE pipeline
    │   │   Each frame sealed individually with monotonic seq
    │   │
    │   Hub VPP graph:
    │   ├── rx_parse_raw(): crypto_ver=0x01 → decrypt_out
    │   ├── aead_decrypt_vector(): open_frame(peer cipher, DIR_HUB_TO_NODE)
    │   │   Reflection guard: nonce[0]=0x01 ≠ 0x00 → passes
    │   ├── classify_route(): FLAG_TUNNEL → TunWrite
    │   ├── tun_write_vector() → SPSC push to TUN HK thread
    │   └── TUN HK: write(tun_fd, decrypted IP payload) → kernel routing
    │
    │   === DOWNSTREAM (Hub → Node) ===
    │   Hub TUN HK thread:
    │   ├── poll(POLLIN) → read(tun_fd) → IP packet from internet
    │   ├── Build ETH+M13 header in UMEM slab
    │   └── Push PacketDesc to rx_tun SPSC ring
    │
    │   Hub datapath (execute_tx_graph):                        [hub/main.rs:651-755]
    │   ├── Pop from rx_tun_cons → encrypted packets
    │   ├── lookup_by_tunnel_ip(dst_ip) → peer index
    │   ├── seal_frame(buf, cipher, seq, DIR_HUB_TO_NODE, offset)
    │   │   offset=42 for UDP peers (ETH+IP+UDP header space)
    │   │   offset=14 for L2 peers (ETH header only)
    │   ├── build_fragmented_raw_udp() if payload > 1402B
    │   │   k systematic fragments (no parity — FEC removed)
    │   ├── EDT pacer.pace(frame_bytes) → release_ns           [hub/network/uso_pacer.rs]
    │   └── scheduler.enqueue_bulk_edt(addr, len, release_ns)
    │
    │   Hub scheduler.schedule():                              [hub/engine/protocol.rs:1180]
    │   EDT-gated dequeue: won't release before release_ns
    │   Critical queue drained first (handshakes, feedback, FIN)
    │   tx_path.stage_tx_addr() → tx_path.commit_tx() → kick_tx()
    │
    │   Node receives:
    │   ├── CQE Pass 1: decrypt_batch_ptrs()                   [node/cryptography/aead.rs]
    │   │   Scan recv frames for crypto_flag=0x01 → collect enc_ptrs[]
    │   │   4-at-a-time prefetch → batch AES-256-GCM open
    │   │   Stamp PRE_DECRYPTED_MARKER (0x02) at signature[2] on success
    │   │
    │   ├── CQE Pass 2: process_rx_frame()                     [node/main.rs:112-255]
    │   │   PRE_DECRYPTED_MARKER check → skip scalar re-decrypt
    │   │   FLAG_TUNNEL → RxAction::TunWrite
    │   │   stage_tun_write(tun_fd, payload_ptr, payload_len, bid)
    │   │   BID recycled to PBR after kernel consumes TUN write CQE
    │   │
    │   └── Rekey check: frame_count ≥ REKEY_FRAME_LIMIT (2³²)
    │       OR elapsed ≥ REKEY_TIME_LIMIT_NS (1 hour)
    │       → RxAction::RekeyNeeded → NodeState::Registering → restart from Step 1
    │
    ├── ══════════════════════════════════════════════════════
    │   STEP 7: FAILURE & RECOVERY
    │   ══════════════════════════════════════════════════════
    │
    │   Handshake timeout:
    │   ├── Node: 250ms micro-ARQ retransmit ClientHello/Finished
    │   │   via send_fragmented_udp() (HANDSHAKE_RETX_INTERVAL_NS)
    │   ├── Node: 30s total connection timeout → exit
    │   ├── Hub: Assembler GC every 5 telemetry ticks
    │   │   5-second stale fragment expiry
    │   │
    │   Graceful close (SIGTERM/SIGINT):
    │   ├── Hub: 3× FIN burst to all Established peers
    │   │   send_fin_burst_udp() / send_fin_burst_l2()
    │   │   RX-only loop until FIN-ACK or 5× RTT deadline
    │   ├── Node: receives FIN → RxAction::Drop (peer evicted)
    │   │   nuke_cleanup_node() on exit
    │   └── Hub: nuke_cleanup_hub() on exit
    │
    │   AEAD failure:
    │   ├── Hub: open_frame() returns false → CycleStats.aead_fail++
    │   │   Packet silently dropped (no response to attacker)
    │   └── Node: decrypt fails → aead_fail_count++
    │       After threshold: RxAction::RekeyNeeded
    │
    ├── Re-arm multishot recv if terminated (CQE_F_MORE==0)
    ├── Keepalive: 100ms interval, pre-Established only
    ├── Assembler GC: every 5 telemetry ticks (5-second stale expiry)
    └── Telemetry: 1/sec:
        RX:{} TX:{} TUN_R:{} TUN_W:{} AEAD_OK:{} FAIL:{} State:{} Up:{}s
```


## §5. Dependencies & Security Posture

M13 relies on an absolute minimum of external crates to reduce the supply chain attack surface.

### Workspace Release Profile (`Cargo.toml`)

```toml
[profile.release]
panic = "abort"      # No unwind tables — binary size reduction, panic = instant exit
lto = true           # Whole-program link-time optimization across all crates
codegen-units = 1    # Maximum optimization (no parallel codegen splitting)
opt-level = 3        # Aggressive optimization
strip = "symbols"    # Strip debug symbols from release binary
```

### Hub & Node Shared Dependencies

| Crate | Version | Subsystem | Hot Path? | Justification |
| --- | --- | --- | --- | --- |
| `libc` | 0.2 | Core I/O | ✅ | `mmap`, `sched_setaffinity`, `poll`, `read`/`write` |
| `ring` | 0.17 | Crypto | ✅ | AES-256-GCM `LessSafeKey` for AEAD seal/open |
| `bytemuck` | 1.14 | Parsing | ✅ | Zero-copy header casting (`derive` feature) |
| `ml-kem` | 0.2 | PQC | ❌ | FIPS 203 ML-KEM-1024 key encapsulation (handshake only) |
| `ml-dsa` | 0.0.4 | PQC | ❌ | FIPS 204 ML-DSA-87 digital signatures (handshake only) |
| `sha2` | 0.10 | PQC | ❌ | SHA-512 for HKDF + transcript hashing (handshake only) |
| `hkdf` | 0.12 | PQC | ❌ | HKDF-SHA-512 session key derivation (handshake only) |
| `rand` | 0.8 | PQC | ❌ | OsRng CSPRNG via `getrandom(2)` (handshake only) |
| `bindgen` | 0.69 | Build | ❌ | Build-time kernel header bindings |

### Hub-Specific Dependencies

| Crate | Version | Subsystem | Hot Path? | Justification |
| --- | --- | --- | --- | --- |
| `libbpf-sys` | 0.6 | Network | ❌ (Init) | Loads XDP/eBPF redirect program at `run_executive()` init |

### Node-Specific Dependencies

| Crate | Version | Subsystem | Hot Path? | Justification |
| --- | --- | --- | --- | --- |
| `io-uring` | 0.7 | Network | ✅ | Kernel 6.12+ `IORING_SETUP_SQPOLL`, `IORING_RECV_MULTISHOT`, PBR |

---


## §6. Dynamic Environment Directives vs. Compile-Time Invariants

Hardcoded network values prohibit horizontal scaling and invalidate Namespace (NetNS) integration testing. However, memory layout constants must remain statically compiled to allow the LLVM optimizer to perform aggressive loop unrolling.

**A. Dynamic Configuration Targets:**
These variables must be stripped from the `.text` segment and loaded into a statically initialized `OnceLock<M13Config>` from CLI arguments or Environment Variables at boot.

* **Tunnel Subnets:** `--tunnel-ip` (Replaces hardcoded `10.13.0.1/24`). Essential for overlapping swarm deployments.
* **TUN Properties:** `--tun-name` and `--mtu` (Replaces `m13tun0` and `1400`).
* **VPN Split Routes:** `--split-tunnel` (Boolean flag to disable the hardcoded `0.0.0.0/1` lockdown paradigm).
* **Socket Buffer Geometry:** `--sock-buf` (Replaces hardcoded `4MB`/`8MB`).
* **Hardware Fallbacks:** `--iface` and `--fallback-mac`.
* **Sysctl Blocks:** Tuning must be dynamically applied based on OS capability check.
* **Worker Thread Stack:** `--stack-size` (Replaces hardcoded `2MB`).

**B. Compile-Time Engine Constants (Strictly Immutable):**
These constants dictate physical cache alignment, mathematical boundaries, and prevent modulo division (`%`) latency. They must never be made dynamic.

* `MAX_WORKERS` (4), `MAX_PEERS` (256), `UMEM_SIZE` (1 GB), `FRAME_SIZE` (4096), `SLAB_DEPTH` (8192), `GRAPH_BATCH` (256), `VECTOR_SIZE` (64), `TX_RING_SIZE` (256), `JBUF_CAPACITY` (128).
* `REKEY_FRAME_LIMIT` (), `DEADLINE_NS` (50 µs), `REKEY_TIME_LIMIT_NS`, `HANDSHAKE_RETX_INTERVAL_NS`, `FEEDBACK_RTT_DEFAULT_NS`, `HEXDUMP_INTERVAL_NS`.

## §7. Telemetry & Observability Matrix

#### Hub Observability

The Hub employs a dual-layer telemetry architecture: a `/dev/shm` shared-memory export for cross-process monitoring, and `eprintln!` diagnostic lines for operator visibility.

**Layer 1 — Shared Memory Export (`/dev/shm`)**

The `Telemetry` struct (`hub/src/engine/runtime.rs:453-481`) is `mmap()`'d to `/dev/shm`. Each field is `CachePadded<AtomicU64>` (128-byte aligned) to eliminate false sharing. The Monitor process (`--monitor` mode) reads these atomics with zero datapath contention.

Data flow: VPP graph nodes → `CycleStats` (per-batch, `hub/src/network/mod.rs:210-232`, 17 fields) → accumulated per subvector (`execute_subvector`, `main.rs:380-640`) → bridged to SHM via `fetch_add(Relaxed)` (`main.rs:1222-1232`).

| Field | Status | Location | Description |
| --- | --- | --- | --- |
| `pid` | **WIRED** | `main.rs:951` | Worker TID via `SYS_gettid` |
| `rx_count` | **WIRED** | `xdp.rs:321`, `main.rs:1225` | AF_XDP RX + VPP `parsed` accumulation |
| `tx_count` | **WIRED** | `xdp.rs:321` | AF_XDP TX completion ring |
| `drops` | **WIRED** | `main.rs:1224` | Parse failures + AEAD failures + classify drops |
| `cycles` | **WIRED** | `main.rs:1079` | Main loop iteration counter |
| `decrypt_ok` | **WIRED** | `main.rs:1222` | `aead_decrypt_vector()` success count |
| `auth_fail` | **WIRED** | `main.rs:1223` | AEAD MAC verification failures |
| `handshake_ok` | **WIRED** | `main.rs:632` | `process_finished_hub()` success |
| `handshake_fail` | **WIRED** | `main.rs:618,636` | PQC verification failure / malformed |
| `direction_fail` | **WIRED** | `datapath.rs:230` | Direction binding rejection (reflection defense) |
| `jbuf_depth_us` | **WIRED** | `main.rs:1154` | JitterBuffer instantaneous depth (µs) |
| `jbuf_jitter_us` | **WIRED** | `main.rs:1155` | RFC 3550 EWMA jitter estimate (µs) |
| `jbuf_releases` | **WIRED** | `main.rs:1156` | JitterBuffer cumulative releases |
| `jbuf_drops` | **WIRED** | `main.rs:1157` | JitterBuffer late/overflow drops |
| `parse_tsc_total` | **WIRED** | `main.rs:1228` | `rdtsc` delta: `rx_parse_raw()` |
| `decrypt_tsc_total` | **WIRED** | `main.rs:1229` | `rdtsc` delta: `aead_decrypt_vector()` |
| `classify_tsc_total` | **WIRED** | `main.rs:1230` | `rdtsc` delta: `classify()` |
| `scatter_tsc_total` | **WIRED** | `main.rs:1231` | `rdtsc` delta: `scatter()` |
| `tun_write_tsc_total` | **WIRED** | `main.rs:1232` | `rdtsc` delta: `tun_write_vector()` |
| `replay_drops` | **UNWIRED** | — | Increment on RFC 6479 bitmask rejection, before AEAD. |
| `bbr_phase` | **UNWIRED** | — | BbrPhase as `u32` (0=Startup, 1=Drain, 2=ProbeBW, 3=ProbeRTT). |
| `bbr_calibrated` | **UNWIRED** | — | Flip to `1` on BBRv3 `STARTUP` exit. |
| `bbr_btlbw_kbps` | **UNWIRED** | — | 10-RTT max-filtered bottleneck bandwidth. |
| `bbr_rtprop_us` | **UNWIRED** | — | 10-second min-filtered RTT. |

**Layer 2 — Operator Diagnostics (`eprintln!`)**

| Diagnostic | Location | Trigger | Output |
| --- | --- | --- | --- |
| 1/sec telemetry line | `main.rs:1150` | Timer | `[M13-W0] RX:{} TX:{} TUN_R:{} TUN_W:{} AEAD:{}/{} HS:{}/{} Slab:{}/{} Peers:{}/{} Up:{}s` |
| Slab exhaustion (UDP frag) | `main.rs:587` | `slab.alloc()` returns `None` during ServerHello UDP fragmentation | `[M13-DIAG] SLAB EXHAUSTION: ...Slab: {}/{} free. Enqueued {}/{} fragments.` |
| Slab exhaustion (L2 frag) | `main.rs:608` | `slab.alloc()` returns `None` during ServerHello L2 fragmentation | Same format, L2 AF_XDP path |
| Shutdown summary | `main.rs:1389` | Process exit | `Slab: {}/{} free. UDP TX:{} RX:{} TUN_R:{} TUN_W:{} AEAD_OK:{} FAIL:{} Peers:{} Up:{}s` |
| Hexdump RX | `process_rx_frame()` | `M13_HEXDUMP=1` | Per-packet hex dump of inbound frames |
| Hexdump TX | — | — | **UNWIRED.** Wire after `scheduler.enqueue_bulk()` for bidirectional inspection. |

**Blind Spots:**

| Gap | Mandate |
| --- | --- |
| SPSC ring occupancy | Ring fill-level invisible to Monitor. Wire `available()` to `Telemetry` SHM. |
| TUN HK thread | `tun_housekeeping_thread()` (`main.rs:759-933`) has zero counters. VFS I/O latency, `pending_return` queue depth, and DPDK cache hit rates are all invisible. |
| `tun_writes` semantic shift | Post-R-02A, counts SPSC push operations, not VFS `write()`. Actual VFS I/O in TUN HK thread is unmetered. |

#### Node Observability

The Node uses 7 local `u64` counters printed to stderr every 1 second. No `/dev/shm` export, no cross-process monitoring.

| Counter | Location | Description |
| --- | --- | --- |
| `rx_count` | Pass 0: CQE drain | UDP recv CQEs processed |
| `tx_count` | TUN read / echo / keepalive / registration | Successful `sock.send()` calls |
| `aead_ok_count` | Pass 1: batch decrypt | `decrypt_batch_ptrs()` successes |
| `aead_fail_count` | `process_rx_frame()` | AEAD open failures |
| `tun_read_count` | Pass 0: `TAG_TUN_READ` | TUN read CQEs processed |
| `tun_write_count` | Pass 2: `RxAction::TunWrite` | TUN writes staged |
| `State` | 1/sec report | `Reg` / `HS` / `Est` / `Disc` from `NodeState` enum |

**Output format:**
```
[M13-N0] RX:983 TX:986 TUN_R:982 TUN_W:965 AEAD_OK:965 FAIL:0 State:Est
```

**Blind Spots:**

| Gap | Mandate |
| --- | --- |
| No SHM export | Node must gain a `Telemetry` struct to `/dev/shm`, matching Hub's architecture. `eprintln!` fails the operational requirement of external monitoring without log scraping. |
| io_uring ring pressure | `UringReactor` does not expose SQ depth or CQ overflow. Wire to detect SQPOLL stalls. |
| Hexdump TX | Same as Hub — `dump_tx()` unwired. |
| Elapsed time at shutdown | Shutdown line does not emit `elapsed_ns` or `duration_s`. Must be captured externally. |
| No reconnection counter | `HS_OK` is only on Hub side. Node has no visible counter for re-handshakes. Must infer from state transitions in log. |

> **Cross-reference:** Round-over-round quantified metrics tracked in [`OBSERVATIONS.md`](OBSERVATIONS.md).

---

