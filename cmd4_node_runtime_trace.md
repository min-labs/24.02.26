# Cmd 4: `sudo RUST_LOG=debug ./target/release/m13-node --hub-ip 67.213.122.151:443 --tunnel`

> **This trace follows exactly what happens, in order, from the moment the kernel loads the ELF binary into memory until the 3-pass VPP event loop reaches steady state.**

---

## PHASE 0: PROCESS BIRTH (main.rs L38-90)

### Step 0.1 — Signal Handlers + Panic Hook
```
main:L43-53   libc::signal(SIGTERM, signal_handler)  → sets SHUTDOWN AtomicBool
              libc::signal(SIGINT,  signal_handler)
              set_hook(|info| { nuke_cleanup_node(); exit(1) })
              → nuke_cleanup removes TUN routes + iptables even on panic
```

### Step 0.2 — TUN Interface (BEFORE arg parse)
```
main:L61-65   create_tun("m13tun0")  → datapath.rs L18-76
              ├─ open("/dev/net/tun")
              ├─ ioctl(fd, TUNSETIFF, IFF_TUN | IFF_NO_PI) → m13tun0
              ├─ fcntl(F_SETFL, O_NONBLOCK)
              ├─ ip addr add 10.13.0.2/24 dev m13tun0
              ├─ ip link set dev m13tun0 up
              ├─ ip link set dev m13tun0 mtu 1380
              └─ ip link set dev m13tun0 txqueuelen 1000
```

### Step 0.3 — Arg Parse + Hub IP Storage
```
main:L68-86   hub_ip = "67.213.122.151:443"
              HUB_IP_GLOBAL.lock() = "67.213.122.151"
              → Stored globally so panic hook can teardown pinned route
```

### Step 0.4 — Dispatch
```
main:L82      run_uring_worker("67.213.122.151:443", echo=false, hexdump=false, tun_file)
              ──────────────────────────────────────────────
              Everything below happens inside run_uring_worker()
```

---

## PHASE 1: WORKER BOOT (run_uring_worker, main.rs L846-955)

### Step 1.1 — TSC Clock Calibration
```
L849          calibrate_tsc()  →  engine/runtime.rs
              ├─ CPUID leaf 0x80000007 bit 8: verify invariant TSC
              ├─ 100× warmup loop
              ├─ Two-point calibration over 100ms
              ├─ mult = (mono_delta << 32) / tsc_delta
              └─ 1000-sample validation (reject if max_error > 1µs)
              
              Output: "[M13-TSC] Calibrated: freq=3700.0MHz mult=1157 shift=32 max_err=23ns"
```

### Step 1.2 — System Tuning
```
L850          tune_system_buffers()  → main.rs L288-342
              ├─ WiFi power_save OFF on all wireless interfaces
              ├─ sysctl: rmem_max/wmem_max = 8MB, rmem_default/wmem_default = 4MB
              ├─ sysctl: netdev_budget=600, netdev_budget_usecs=8000
              ├─ sysctl: netdev_max_backlog=10000
              ├─ sysctl: tcp_congestion_control=bbr
              ├─ sysctl: tcp_no_metrics_save=1
              └─ sysctl: tcp_mtu_probing=1
```

### Step 1.3 — EDT Pacer Initialization
```
L855-878      EdtPacer::new(&cal, 100_000_000)  →  uso_pacer.rs
              ├─ link_bps = 100 Mbps (default WiFi MANET)
              ├─ ns_per_byte = 8e9 / 100e6 = 80 ns/byte
              └─ Zero-spin: returns release timestamp, never blocks
              
              DeferredTxRing::new()  → 64-entry circular buffer for EDT gating
```

### Step 1.4 — UDP Socket (Connected Mode)
```
L882-898      sock = UdpSocket::bind("0.0.0.0:0")
              sock.connect("67.213.122.151:443")
              ├─ Connected mode: kernel caches route lookup → sendto-free
              ├─ fcntl(F_SETFL, O_NONBLOCK)
              ├─ SO_RCVBUFFORCE = 8MB  → absorbs Hub's wire-speed bursts
              └─ SO_SNDBUFFORCE = 8MB
```

### Step 1.5 — io_uring PBR Reactor (uring_reactor.rs L73-128)
```
L903          UringReactor::new(raw_fd, sq_thread_cpu=0)
              ├─ PBR metadata: mmap(2MB-aligned) for 4096 × 16-byte entries
              ├─ Data region: mmap(MAP_HUGETLB | MAP_POPULATE | MAP_LOCKED)
              │   Total: (4096 + 64) × 2048 = ~8.5MB (PBR metadata + all frame buffers)
              ├─ io_uring builder:
              │   ├─ SQPOLL(2000µs idle before sleep)
              │   ├─ setup_sqpoll_cpu(0)  → kernel SQ thread on CPU 0
              │   ├─ setup_single_issuer
              │   └─ CQ size = 8320, SQ size = 4160
              ├─ SYS_io_uring_register(IORING_REGISTER_PBUF_RING)
              │   → FATAL if kernel < 6.12
              ├─ Pre-populate PBR: all 4096 UDP buffers registered
              │   ├─ write_unaligned for addr/len/bid (avoids tail corruption at offset 14)
              │   └─ Atomic Release store of local_tail
              └─ arm_multishot_recv() → RecvMulti SQE with BUFFER_SELECT
```

### Step 1.6 — TUN Read Arming
```
L910-914      For bid in 4096..4159 (TUN_RX_ENTRIES = 64):
              ├─ reactor.arm_tun_read(tun_fd, bid)
              │   Read at offset +62 → leaves room for M13 header prepend
              │   Max payload: min(2048 - 62, 1380) = 1380 bytes
              └─ reactor.submit()
              
              → 64 TUN read SQEs armed, waiting for kernel TUN packets
```

### Step 1.7 — State + Assembler Init
```
L917-937      seq_tx = 0
              HexdumpState::new(false)
              alloc_asm_arena(8 slots) → mmap(MAP_HUGETLB | MAP_POPULATE)
              Assembler::init(arena_ptr)
              src_mac = detect_mac(None)  → random LAA MAC
              hub_mac = [0xFF; 6]         → broadcast, Hub identifies by addr
```

### Step 1.8 — Registration Frame
```
L940-944      reg = build_m13_frame(&src_mac, &hub_mac, seq=0, FLAG_CONTROL)
              ├─ 62 bytes: ETH(14) + M13(48), magic=0xD1, version=0x01
              sock.send(&reg) → UDP to 67.213.122.151:443
              seq_tx = 1
              state = NodeState::Registering
              
              → This is the FIRST packet Hub sees from this Node.
              → Hub creates PeerSlot, learns Node's IP:port for return path.
```

### Step 1.9 — M13 Header Template
```
L947-953      hdr_template[0..62]:
              ├─ dst = hub_mac (broadcast)
              ├─ src = src_mac
              ├─ ethertype = 0x88B5
              ├─ magic = 0xD1, version = 0x01
              └─ All other fields zeroed
              
              → Stamped onto every TUN TX frame. Avoids per-packet header fill.
```

> **At this point**: Socket connected, io_uring reactor armed, TUN reads armed, registration sent.
> **Waiting for**: Hub to respond with any frame → triggers handshake.

---

## PHASE 2: 3-PASS VPP MAIN LOOP — STEADY STATE (main.rs L957-1348)

```
This is an infinite loop. Each iteration processes a batch of events.
The loop has THREE PASSES followed by post-processing.
```

### Cycle Pre-Check: Timeout
```
L962-966      If NOT Established && 30s elapsed:
              → Log timeout, break loop
```

### ═══ PASS 0: CQE Drain + Classify (L978-1089) ═══

```
L979          reactor.ring.completion().sync()  → memory barrier, refresh CQ
L981-988      Batch drain: for cqe in ring.completion():
              ├─ Store (result, flags, user_data) into cqe_batch[128]
              └─ If overflow: SILENTLY DROPPED (⚠️ Defect D2)
```

**For each CQE, classify by tag:**

```
TAG_UDP_RECV_MULTISHOT (tag=1):
├─ Extract BID from flags >> 16
├─ Store in recv_bids/recv_lens/recv_flags arrays
├─ If F_MORE == 0: needs rearm
└─ Accumulated for batch AEAD in Pass 1

TAG_TUN_READ (tag=2):
├─ Result = payload bytes read from TUN (at offset +62)
├─ Clamp to 1380 bytes (USO MTU)
├─ Build M13 frame IN-PLACE on the HugeTLB arena:
│   ├─ frame_base = arena_ptr + bid * 2048
│   ├─ Copy hdr_template[0..46] → frame[0..46]  (ETH + M13 minus seq/flags)
│   ├─ Stamp seq_tx → frame[46..54]
│   ├─ frame[54] = FLAG_TUNNEL
│   ├─ Stamp payload_len → frame[55..59]
│   └─ If Established: seal_frame(frame, cipher, seq, DIR_NODE_TO_HUB)
├─ EDT pacing: release_ns = edt_pacer.pace(now, frame_len)
├─ deferred_tx.push(frame_ptr, len, bid, release_ns)
│   If ring full: force-pop oldest → stage_udp_send (bypass pacing)
└─ seq_tx++, last_tx_activity_ns = now

TAG_TUN_WRITE (tag=3):
└─ Return BID to PBR: add_buffer_to_pbr(bid), commit_pbr()

TAG_UDP_SEND_ECHO|TAG_UDP_SEND_TUN (tag=4|5):
├─ If tag=5 && tun_fd >= 0: re-arm TUN read with the freed BID
└─ reactor.submit()
```

### ═══ PASS 1: Vectorized AEAD Batch Decrypt (L1091-1135) ═══

```
Only if recv_count > 0 AND state == Established:

L1098-1134    Collect encrypted frame pointers:
              for each recv BID:
              ├─ frame_ptr = arena_base + bid * FRAME_SIZE
              ├─ If frame[ETH_HDR_SIZE + 2] == 0x01 (encrypted marker):
              │   enc_ptrs[enc_count] = frame_ptr
              │   enc_lens[enc_count] = recv_len
              │   enc_count++
              └─ 
              
              decrypt_batch_ptrs(enc_ptrs, enc_lens, enc_count, cipher, DIR_NODE_TO_HUB)
              ├─ 4-at-a-time prefetch loop (AES-NI/ARMv8-CE saturating)
              ├─ decrypt_one(frame, cipher, dir):
              │   ├─ Verify encrypted marker (0x01)
              │   ├─ Reflection guard: reject if nonce[8] == our_dir
              │   ├─ Extract tag (16B) + nonce (12B) from frame
              │   ├─ LessSafeKey::open_in_place_separate_tag()
              │   ├─ On success: stamp PRE_DECRYPTED_MARKER (0x02)
              │   └─ Return ok/fail
              ├─ frame_count += ok_count
              └─ Rekey check: if frame_count >= 2^32 || elapsed > 1hr → Registering
```

### ═══ PASS 2: Per-Frame RxAction Dispatch (L1135-1300) ═══

```
For each recv BID:
L1137-1150    frame = get_frame(bid, len)  → UmemSlice
              hexdump.dump_rx(frame, now)
              
              action = process_rx_frame(frame, &mut state, &mut assembler, ...)
              ├─ Length check: < 62 → Drop
              ├─ Magic/version: ≠ 0xD1/0x01 → Drop
              ├─ If Registering: return NeedHandshakeInit
              ├─ PRE_DECRYPTED_MARKER check: if 0x02 → skip decrypt
              ├─ If not pre-decrypted:
              │   ├─ Established + cleartext non-HS → Drop (downgrade attack)
              │   └─ encrypted: open_frame() scalar fallback
              ├─ Re-read flags from DECRYPTED buffer
              └─ Dispatch:
                 ├─ FLAG_FRAGMENT + FLAG_HANDSHAKE → assembler.feed()
                 │   On complete reassembly:
                 │   ├─ Make-Before-Break: if !Handshaking → discard stale retransmit
                 │   ├─ process_handshake_node(reassembled, state)
                 │   │   ├─ Parse ServerHello (8788B)
                 │   │   ├─ dk.decapsulate(ct) → shared secret
                 │   │   ├─ Verify Hub signature: pk_hub.verify_with_context(transcript, "M13-HS-v1")
                 │   │   ├─ HKDF-SHA-512 → session_key
                 │   │   ├─ Sign transcript2 → Finished (4628B)
                 │   │   └─ Return (session_key, finished_payload)
                 │   └─ Return HandshakeComplete or HandshakeFailed
                 ├─ FLAG_TUNNEL → TunWrite { start=62, plen }
                 └─ FLAG_CONTROL → Drop (consumed)
```

**RxAction dispatch:**

```
NeedHandshakeInit:
├─ initiate_handshake(sock, src_mac, hub_mac, &mut seq, ...)
│   ├─ MlKem1024::generate(&mut OsRng) → (dk, ek)
│   ├─ MlDsa87::key_gen(&mut OsRng) → (sk, pk)
│   ├─ Random 32-byte session_nonce
│   ├─ Build ClientHello: type(1) + version(1) + nonce(32) + ek(1568) + pk(2592) = 4194B
│   ├─ send_fragmented_udp(payload, 1380 MTU):
│   │   ├─ slice_uso_counted(4194, 1380) → 4 fragments
│   │   ├─ For each: build ETH+M13+FragHdr+data, sock.send()
│   │   └─ seq_tx += 4
│   └─ Return NodeState::Handshaking { dk_bytes, session_nonce, client_hello_bytes, our_pk, our_sk }
└─ state = Handshaking

HandshakeComplete { session_key, finished_payload }:
├─ send_fragmented_udp(finished_payload, ...)
│   ├─ Finished = 4628B → ⌈4628/1380⌉ = 4 fragments → sock.send() each
│   └─ seq_tx += 4
├─ state = Established { session_key, cipher: LessSafeKey(AES_256_GCM, key), frame_count=0 }
└─ If --tunnel && !routes_installed:
   setup_tunnel_routes("67.213.122.151")  → datapath.rs L93-187
   ├─ ip route add 67.213.122.151 via <gateway> dev <wan_iface>  (pin Hub route)
   ├─ ip route add 0.0.0.0/1 dev m13tun0    (override default route)
   ├─ ip route add 128.0.0.0/1 dev m13tun0
   ├─ sysctl: disable IPv6 (leak prevention)
   ├─ sysctl: TCP BDP tuning (rmem/wmem 16MB, BBR, etc.)
   ├─ iptables: FORWARD + MSS clamp-to-PMTU
   └─ tc qdisc replace dev m13tun0 root fq

TunWrite { start, plen }:
└─ reactor.stage_tun_write(tun_fd, frame_ptr + start, plen, bid)
   → io_uring SQE queued for kernel write to m13tun0
```

### Post-Processing (L1245-1348)

**Multishot Rearm:**
```
L1245         If multishot_needs_rearm: reactor.arm_multishot_recv()
```

**Return PBR Buffers:**
```
L1250-1260    For each processed recv BID:
              reactor.add_buffer_to_pbr(bid), commit_pbr()
```

**Handshake Retransmit:**
```
L1265-1295    If Handshaking && elapsed > HANDSHAKE_RETX_INTERVAL_NS (5s):
              ├─ Re-send ClientHello fragments via sock.send()
              └─ Reset started_ns = now
```

**Keepalive:**
```
L1300-1315    If NOT Established && 100ms elapsed:
              ├─ build_m13_frame(FLAG_CONTROL) → sock.send()
              └─ Maintains NAT hole during handshake
```

**Telemetry:**
```
L1315-1330    Every 1s:
              eprintln!("[M13-N0] RX:{} TX:{} TUN_R:{} TUN_W:{} AEAD_OK:{} FAIL:{} State:{} DL:{}kbps UL:{}kbps")
              Every 5s: assembler.gc(now)
```

**EDT Drain — Zero-Spin Pacing:**
```
L1330-1345    while deferred_tx.peek_release_ns() <= now:
              ├─ entry = deferred_tx.pop()
              ├─ reactor.stage_udp_send(entry.frame_ptr, entry.frame_len, entry.bid, TAG_UDP_SEND_TUN)
              └─ tx_count++
              
              reactor.submit()  → push all pending SQEs to kernel
```

**EDT Idle Reset:**
```
L1345-1348    If no TX for > 1s:
              edt_pacer.reset(now)  → prevents burst-compensation after idle
```

### GOTO loop start

---

## HANDSHAKE SEQUENCE (what happens across both Hub + Node)

```
Node                                    Hub
────                                    ───
1. Registration frame (FLAG_CONTROL) ──────► PeerTable.lookup_or_insert() → pidx
                                              Hub stores Node IP:port, tx_iface
                                              (Hub doesn't respond to bare control)

2. Node receives... nothing (Hub silent)
   → 100ms keepalive timer fires
   → Node sends another FLAG_CONTROL ──────► Hub recognizes peer exists
   
3. Hub's keepalive or any response ◄────── Hub sends keepalive (pre-Established only)
   → NodeState = Registering
   → process_rx_frame returns NeedHandshakeInit

4. initiate_handshake():
   ML-KEM-1024 keygen
   ML-DSA-87 keygen                    
   ClientHello (4194B, 4 frags) ───────────► rx_parse_raw → classify → Handshake
                                              process_fragment → assembler.feed()
                                              On complete: push PqcReq(type=1) to SPSC

                                              Core 0 PQC Worker:
                                              ├─ pop PqcReq
                                              ├─ process_client_hello_hub()
                                              │   ML-KEM encapsulate → (ct, ss)
                                              │   ML-DSA-87 sign(transcript)
                                              │   Build ServerHello (8788B)
                                              │   Pre-compute transcript2
                                              │   Write FlatHubHandshakeState
                                              └─ push PqcResp(type=1, payload=ServerHello)

                                              Main loop: drain PqcResp
                                              ├─ Fragment ServerHello → 7 fragments
                                    ◄──────── Enqueue all 7 to Scheduler.critical
                                              Dequeue → AF_XDP TX → wire

5. Node receives 7 ServerHello fragments
   → assembler.feed() reassembles 8788B
   → process_handshake_node():
     ML-KEM decapsulate → shared secret
     Verify Hub ML-DSA-87 signature ✓
     HKDF-SHA-512 → session_key
     ML-DSA-87 sign(transcript2) → Finished

6. Finished (4628B, 4 frags) ──────────────► rx_parse_raw → classify → Handshake
                                              process_fragment → assembler.feed()
                                              push PqcReq(type=2) to SPSC

                                              Core 0 PQC Worker:
                                              ├─ process_finished_flat()
                                              │   Verify Node ML-DSA-87 signature ✓
                                              │   HKDF-SHA-512 → session_key
                                              └─ push PqcResp(type=2, session_key)

                                              Main loop: drain PqcResp
                                              ├─ Install cipher: LessSafeKey(AES_256_GCM, key)
                                              ├─ peers.ciphers[pidx] = Some(cipher)
                                              └─ peers.slots[pidx].lifecycle = Established

7. Node: state = Established
   If --tunnel: setup_tunnel_routes()
   ────── ENCRYPTED BIDIRECTIONAL TUNNEL ACTIVE ──────
```

---

## DEPENDENCY CHAIN (what must succeed before VPP runs)

```
1. TUN created (m13tun0, 10.13.0.2/24)          → VPN routing depends on this
2. TSC calibrated                                → All timestamps depend on this
3. System buffers tuned (sysctls)                → Burst absorption depends on this
4. EDT Pacer initialized (100 Mbps)              → TX pacing depends on this
5. UDP socket connected to Hub                   → All network I/O depends on this
6. Socket buffers set to 8MB                     → Burst absorption depends on this
7. io_uring PBR reactor created                  → Zero-syscall RX/TX depends on this
   ├─ HugeTLB arena mmap'd                      → Frame storage depends on this
   ├─ PBR registered with kernel                 → Buffer selection depends on this
   └─ Multishot recv armed                       → RX depends on this
8. TUN read BIDs armed (64 slots)                → TUN → tunnel forwarding depends on this
9. Assembly arena allocated (HugeTLB)            → Fragment reassembly depends on this
10. Registration frame sent                      → Hub peer creation depends on this
11. → VPP MAIN LOOP BEGINS
12. Hub responds → triggers ClientHello          → PQC handshake depends on this
13. ServerHello received + verified              → Session key depends on this
14. Finished sent + Hub verifies                 → Bidirectional AEAD depends on this
15. setup_tunnel_routes() applied                → Internet forwarding depends on this
16. → ENCRYPTED TUNNEL ACTIVE
```
