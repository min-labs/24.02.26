# Cmd 3: `sudo RUST_LOG=debug ./target/release/m13-hub enp1s0f0 --tunnel --single-queue 0`

> **This trace follows exactly what happens, in order, from the moment the kernel loads the ELF binary into memory until the VPP main loop reaches steady state.**

---

## PHASE 0: PROCESS BIRTH (main.rs L43-128)

```
Kernel calls main()
```

### Step 0.1 — Signal Handlers
```
main:L47-50   libc::signal(SIGTERM, signal_handler)
              libc::signal(SIGINT,  signal_handler)
              → signal_handler sets SHUTDOWN AtomicBool(Relaxed) on Ctrl+C
```

### Step 0.2 — Panic Hook
```
main:L53-58   set_hook(|info| { nuke_cleanup_hub("enp1s0f0"); exit(1) })
              → If any thread panics, TUN/XDP/iptables are cleaned up before death
```

### Step 0.3 — Arg Parse
```
main:L64-127  if_name     = "enp1s0f0"    (first positional arg)
              tunnel_mode = true           (--tunnel flag)
              single_queue = Some(0)       (--single-queue 0)
              listen_port = 443            (default, blends with QUIC)
              hexdump     = false
              wifi_iface  = None
              → sets M13_LISTEN_PORT env var to "443"
```

### Step 0.4 — Dispatch
```
main:L127     run_executive("enp1s0f0", Some(0), true, None)
              ──────────────────────────────────────────────
              Everything below happens inside run_executive()
```

---

## PHASE 1: THE EXECUTIVE — Hardware Bootstrap (main.rs L132-287)

### Step 1.1 — Auto-Cleanup (stale processes + XDP)
```
L141-157      pgrep m13-hub → kill -9 any stale PID ≠ ours
              ip link set enp1s0f0 xdp off
              ip link set enp1s0f0 xdpgeneric off
```

### Step 1.2 — NIC Queue Collapse
```
L159-173      ethtool -L enp1s0f0 combined 1
              → Forces single queue for AF_XDP steering. If fails, warns but continues.
```

### Step 1.3 — HugePage Allocation
```
L175-180      hugepages_needed = 1 × (1GB + 16MB) / 2MB = 520 pages
              write "520\n" → /proc/sys/vm/nr_hugepages
              → Reading it back verifies allocation
```

### Step 1.4 — TSC Clock Calibration
```
L183          calibrate_tsc()  →  runtime.rs L182-265
              ├─ CPUID leaf 0x80000007 bit 8: verify invariant TSC
              ├─ 100× warmup: read_tsc() + clock_ns()
              ├─ tsc0, mono0 = snapshot
              ├─ sleep(100ms)
              ├─ tsc1, mono1 = snapshot
              ├─ mult = (mono_delta << 32) / tsc_delta
              ├─ 1000-sample validation (reject if max_error > 1µs)
              └─ Returns TscCal { tsc_base, mono_base, mult, shift=32, valid=true }
              
              Output: "[M13-TSC] Calibrated: freq=3700.0MHz mult=1157 shift=32 max_err=23ns"
```

### Step 1.5 — CPU Isolation & Power Management
```
L185          lock_pmu()  →  runtime.rs L380-398
              ├─ open("/dev/cpu_dma_latency")
              ├─ write(0u32) → forces CPU C0 (no sleep states)
              └─ mem::forget(file) → fd stays open forever

L186          fence_interrupts()  →  runtime.rs L400-440
              ├─ For each /proc/irq/*/smp_affinity:
              │   Write mask excluding isolated cores
              └─ Warns if irqbalance is running

L187-190      discover_isolated_cores()  →  runtime.rs L300-360
              ├─ Read /sys/devices/system/cpu/isolated
              │   (or M13_MOCK_CMDLINE env)
              ├─ parse_cpu_list("2,3") → vec![2, 3]
              └─ FATAL if empty

              worker_count = 1  (because --single-queue)
```

> **At this point**: TSC calibrated, CPU C0 locked, IRQs fenced, isolated cores known.

### Step 1.6 — BPF XDP Steersman (bpf.rs L31-103)
```
L200-202      BpfSteersman::load_and_attach("enp1s0f0")
              ├─ setrlimit(RLIMIT_MEMLOCK, UMEM_SIZE + 16MB)
              │   → fallback to RLIM_INFINITY if rejected
              ├─ if_nametoindex("enp1s0f0") → FATAL if 0
              ├─ bpf_object__open_mem(BPF_OBJ_BYTES)
              │   → BPF_OBJ_BYTES = include_bytes! at compile time
              ├─ bpf_object__load() → FATAL if verifier rejects
              ├─ Find program "m13_steersman" → FATAL if missing
              ├─ Find map "xsks_map" → FATAL if missing
              ├─ bpf_set_link_xdp_fd(ifindex, prog_fd, DRV_MODE | UPDATE_IF_NOEXIST)
              │   → FATAL if NIC lacks native XDP support
              └─ Returns BpfSteersman { obj, map_fd, if_index }
              
              Output: "[M13-EXEC] BPF Steersman attached to enp1s0f0 [Native (Driver) Mode]. map_fd=5"
```

### Step 1.7 — TUN Interface (datapath.rs L811-870)
```
L204-208      create_tun("m13tun0")
              ├─ open("/dev/net/tun") → File
              ├─ ioctl(fd, TUNSETIFF, IFF_TUN | IFF_NO_PI) → m13tun0
              ├─ fcntl(F_SETFL, O_NONBLOCK)
              ├─ ip addr add 10.13.0.1/24 dev m13tun0
              ├─ ip link set dev m13tun0 up
              ├─ ip link set dev m13tun0 mtu 1380
              └─ ip link set dev m13tun0 txqueuelen 1000

              setup_nat()  → datapath.rs L870-949
              ├─ sysctl: ip_forward=1, bbr, rmem/wmem 16MB, tcp_slow_start_after_idle=0
              ├─ iptables -t nat -A POSTROUTING -s 10.13.0.0/24 -j MASQUERADE
              ├─ iptables FORWARD rules for m13tun0
              └─ tc qdisc replace dev m13tun0 root fq
```

### Step 1.8 — SPSC Ring Creation (spsc.rs)
```
L210-217      4 SPSC rings, each depth=2048:
              ├─ tx_tun:       Datapath→TUN_HK  (PacketDesc)  TUN write requests
              ├─ rx_tun:       TUN_HK→Datapath  (PacketDesc)  TUN-read frames
              ├─ free_to_tun:  Datapath→TUN_HK  (u32)         Free slab indices
              └─ free_to_dp:   TUN_HK→Datapath  (u32)         Returned slab indices

              Each ring: Vec::with_capacity(2048), leak pointer, wrap in Arc<SpscRing>
              Head/tail: 128-byte CachePadded<AtomicUsize>
```

### Step 1.9 — TUN Housekeeping Thread Spawn
```
L222-240      Thread "m13-tun-hk" (4MB stack)
              ├─ pin_to_core(last isolated core)
              ├─ Owns: TUN fd, SPSC consumers (tx_tun, free_to_tun), producers (rx_tun, free_to_dp)
              ├─ Blocks on OnceLock waiting for UMEM base from worker 0
              └─ Once UMEM arrives: enters poll() loop
              
              TUN HK poll() loop:
              ├─ Drain rx_from_dp → libc::write(tun_fd, payload) per packet
              ├─ poll(tun_fd, POLLIN, 1ms timeout)
              ├─ If readable: pop free slabs → libc::read(tun_fd) → build M13 frame → push to tx_to_dp
              └─ yield_now() if idle
```

### Step 1.10 — Worker Thread Spawn
```
L252-277      Thread "m13-w0" (32MB stack)
              worker_idx=0, core_id=isolated_cores[0], queue_id=0
              Gets: SPSC producers/consumers, TUN file clone, umem_info Arc
              → Calls worker_entry()
              ──────────────────────────────────────────────────
              Executive thread joins here. Everything below is on the WORKER thread.
```

---

## PHASE 2: WORKER BOOT (worker_entry, main.rs L870-1008)

### Step 2.1 — CPU Pinning & Telemetry
```
L880-883      pin_to_core(core_id) → sched_setaffinity
              verify_affinity(core_id) → read /proc/self/task/{tid}/status
              Telemetry::map_worker(0, true)
              ├─ shm_open("/m13_telem_0") → mmap(MAP_SHARED)
              └─ Zero-initialize entire Telemetry struct
              Store our TID into telemetry.pid
```

### Step 2.2 — AF_XDP Engine (xdp.rs L86-238)
```
L885          Engine::new_zerocopy("enp1s0f0", queue_id=0, bpf_map_fd)
              ├─ check_nic_limits("enp1s0f0")
              │   SIOCETHTOOL → verify rx_max_pending >= 2048, tx_max_pending >= 2048
              │   → FATAL if NIC can't hold 2048 entries
              ├─ mmap(1GB, MAP_HUGETLB | MAP_POPULATE | MAP_LOCKED) → umem_area
              │   → FATAL if fails
              ├─ xsk_umem__create(umem_area, 1GB, fq_ring, cq_ring, config)
              │   → FATAL if fails
              ├─ xsk_socket__create(XDP_ZEROCOPY | XDP_USE_NEED_WAKEUP, queue=0)
              │   → FATAL if fails
              ├─ bpf_map_update_elem(xsks_map, &queue, &xsk_fd) → wire XSK into BPF
              ├─ setsockopt(SO_BUSY_POLL, 50µs) → non-fatal if fails
              └─ getsockopt(XDP_MMAP_OFFSETS) → FATAL if ABI mismatch
              
              Returns Engine with: umem_area (1GB), XSK fd, RX/TX/FQ/CQ rings
```

### Step 2.3 — Publish UMEM to TUN HK
```
L896-898      umem_info.set((umem_base as usize, 4096))
              → TUN HK thread unblocks from OnceLock spin
```

### Step 2.4 — Slab + State Init
```
L901-925      FixedSlab::new(8192)  →  Stack of 8192 indices [0..8191]
              Scheduler::new()      →  Dual-ring: critical[512] + bulk[512]
              TxCounter::new()      →  AtomicU64 inflight/total
              ReceiverState::new()  →  highest_seq=0, delivered=0
              RxBitmap::new()       →  256-bit ACK bitmap
              PeerTable::new(now)   →  256 PeerSlots, 256 Assemblers, 256 cipher slots

              detect_mac("enp1s0f0") → read /sys/class/net/enp1s0f0/address
              get_interface_ip("enp1s0f0") → ioctl SIOCGIFADDR → hub_ip
              resolve_gateway_mac("enp1s0f0") → parse /proc/net/route + /proc/net/arp → gateway_mac
```

### Step 2.5 — Pre-stamp All Slab Frames
```
L941-955      For each of 8192 slab frames:
              ├─ engine.get_frame_ptr(i)
              ├─ Write EthernetHeader: dst=FF:FF:FF:FF:FF:FF, src=iface_mac, ethertype=0x88B5
              └─ Write M13Header: magic=0xD1, version=0x01, all else zeroed
              
              Then: refill_rx_full(&mut slab) → fill AF_XDP FQ ring completely
```

### Step 2.6 — JitterBuffer + Epsilon
```
L962-963      epsilon_ns = measure_epsilon_proc(&cal)
              ├─ Measures scheduling uncertainty via 100 clock_gettime pairs
              └─ Used for jitter buffer calibration
              JitterBuffer::new() → capacity 128 entries
```

### Step 2.7 — PQC SPSC + Arenas + Worker Thread
```
L975-1003     make_pqc_spsc() → 4 SPSC channels for PQC offload
              
              payload_arena = Box::new([[0u8; 9216]; 256]) → leaked to raw ptr
              hs_state_arena = Box::new([FlatHubHandshakeState::EMPTY; 256]) → leaked to raw ptr
              
              Thread "m13-pqc-cp" spawned:
              ├─ pin_to_core(0)
              └─ pqc_worker_thread(core=0, req_cons, resp_prod, payload_arena, hs_state_arena, 256)
                 → Infinite loop: pop PqcReq → ML-KEM/ML-DSA math on Core 0 → push PqcResp
```

### Step 2.8 — EDT Pacer
```
L1008         EdtPacer::new(&cal, 100_000_000)
              ├─ link_bps = 100 Mbps
              ├─ ns_per_byte = 8e9 / 100e6 = 80 ns/byte
              └─ Zero-spin: returns release_ns timestamp, never blocks
```

> **At this point**: All hardware wired. 4 threads running:
> - Core 0: PQC worker (ML-KEM + ML-DSA)
> - Core N-1: TUN housekeeping (poll-based VFS I/O)
> - Core N: VPP datapath worker (AF_XDP + io_uring)
> - Main thread: joined, waiting for worker exit

---

## PHASE 3: VPP MAIN LOOP — STEADY STATE (main.rs L1010-1515)

```
This is an infinite loop that runs until SHUTDOWN is set.
Each iteration is ONE VPP CYCLE. The cycle has this structure:
```

### Cycle Step 1: Shutdown Check
```
L1010-1045    If SHUTDOWN && !closing:
              ├─ Send FIN bursts to all Established peers
              ├─ Set fin_deadline_ns = now + 5×RTprop
              └─ If deadline expired: break
```

### Cycle Step 2: Timestamp + Telemetry Tick
```
L1046-1047    now = rdtsc_ns(&cal)     (~5 cycles)
              stats.cycles += 1
```

### Cycle Step 3: AF_XDP Ring Housekeeping
```
L1049-1054    engine.recycle_tx(&slab)  →  Consume CQ ring, free slab indices
              engine.refill_rx(&slab)   →  Alloc from slab, push to FQ ring
              If WiFi: uring.replenish_pbr(&slab, umem, 4096)
```

### Cycle Step 4: TUN TX Graph (worker 0 only)
```
L1056-1091    execute_tx_graph(&mut tx_gctx)
              ├─ tun_read_batch() → pop SPSC rx_tun_cons for pre-built frames from TUN HK
              │   (or direct libc::read(tun_fd) fallback if no SPSC)
              ├─ For each TUN packet:
              │   ├─ Lookup peer by dst IP in PeerTable
              │   ├─ Get next_seq(), stamp into M13 header
              │   └─ Push to routed_vec
              ├─ aead_encrypt_vector(routed_vec)
              │   ├─ 4-at-a-time prefetch on UMEM payload
              │   └─ seal_frame() per packet
              ├─ For each encrypted packet:
              │   ├─ Copy M13 payload → +RAW_HDR_LEN offset (make room for ETH+IP+UDP)
              │   ├─ Build ETH+IPv4+UDP headers in front
              │   ├─ EDT pace: pacer.pace(now, total_len) → release_ns
              │   └─ scheduler.enqueue_bulk_edt(addr, len, release_ns, tx_iface)
              └─ Return count
```

### Cycle Step 5: Telemetry Report (every 1s)
```
L1093-1132    If 1s elapsed since last_hub_report:
              ├─ Count Established peers
              ├─ Log: "RX:N TX:N AEAD_OK:N FAIL:N HS:ok/fail peers:N"
              ├─ Write counters to SHM Telemetry struct
              └─ GC: every 5s, assembler.gc(now) for each peer
```

### Cycle Step 6: PQC Response Drain
```
L1134-1210    If pqc_resp_rx available:
              pop_batch(&mut resp_buf) → drain up to 4 PqcResp
              For each response:
              ├─ If msg_type=1 (ServerHello response):
              │   ├─ Read raw ServerHello from resp.response_payload
              │   ├─ Build fragmented response (either L2 or UDP-encap based on peer tx_iface)
              │   ├─ Enqueue all fragments to scheduler.critical ring
              │   └─ Stats: handshake_ok++
              ├─ If msg_type=2 (SessionEstablished response):
              │   ├─ Install session key: LessSafeKey::new(AES_256_GCM, key)
              │   ├─ peers.ciphers[pidx] = Some(cipher)
              │   ├─ peers.slots[pidx].lifecycle = Established
              │   ├─ Clear assembler for this peer
              │   └─ Stats: handshake_ok++
              └─ If failed: handshake_fail++, lifecycle→Empty
```

### Cycle Step 7: RX Batch — Hardware Ingress
```
L1212-1260    rx_count = engine.poll_rx_batch(&mut rx_batch, GRAPH_BATCH=256)
              → Consume AF_XDP RX ring: up to 256 xdp_desc {addr, len, options}

              If WiFi reactor:
              ├─ uring.drain_cqes(&slab, &mut wifi_rx, frame_size)
              │   → Drain io_uring CQEs into (addr, len) pairs
              └─ Merge both into unified rx_descs: [(addr, len, rx_iface=0|1)]
```

### Cycle Step 8: Execute VPP Graph — THE PIPELINE
```
L1262-1280    execute_graph(rx_descs, &mut ctx) → CycleStats

              Inside execute_graph (L332-370):
              └─ Split into VECTOR_SIZE(64)-packet sub-batches:
                 execute_subvector(chunk, ctx) for each sub-batch
```

**VPP Sub-vector Pipeline** (execute_subvector, L372-489):

```
              STAGE 1: rx_parse_raw()                    [datapath.rs L25-171]
              ├─ For each (addr, len, rx_iface):
              │   ├─ Bounds check: len >= ETH_HDR_SIZE + M13_HDR_SIZE
              │   ├─ EtherType dispatch:
              │   │   ├─ 0x88B5 (L2 M13): extract peer MAC
              │   │   └─ 0x0800 (IPv4 UDP): extract src_ip/port
              │   ├─ lookup_or_insert(addr) → pidx, binds rx_iface → tx_iface
              │   ├─ Validate magic=0xD1, version=0x01
              │   └─ Split: crypto_ver==0x01 → decrypt_vec, else → cleartext_vec
              └─ TSC: stats.parse_tsc = read_tsc() - t_parse
              
              STAGE 1b: handle_reconnection()            [datapath.rs L274-295]
              └─ Cleartext control frame + peer has active session → force reset_session()

              STAGE 2: aead_decrypt_vector()             [datapath.rs L178-271]
              ├─ 4-at-a-time prefetch_read_l1 on UMEM payload
              ├─ For each packet: decrypt_one()
              │   ├─ Lookup cipher from peers.ciphers[pidx]
              │   ├─ Reflection guard: reject if nonce_dir == DIR_HUB_TO_NODE
              │   ├─ aead::open_frame() → decrypt in-place
              │   ├─ Rekey check: frame_count >= 2^32 || elapsed > 1hr
              │   └─ If fail: disposition → Drop
              └─ TSC: stats.decrypt_tsc

              STAGE 3: classify_route()                  [datapath.rs L356-411]
              ├─ 4-at-a-time prefetch on PacketDesc (flags field)
              └─ Flag dispatch:
                 ├─ FLAG_FRAGMENT              → Handshake
                 ├─ FLAG_FEEDBACK              → Feedback
                 ├─ FLAG_TUNNEL                → TunWrite
                 ├─ FLAG_FIN                   → log + Consumed
                 ├─ FLAG_HANDSHAKE             → Handshake
                 ├─ FLAG_CONTROL               → Consumed
                 └─ default                    → TxEnqueue
              TSC: stats.classify_tsc

              STAGE 4: scatter()                         [network/mod.rs L131-187]
              ├─ 4-at-a-time prefetch on PacketDesc structs
              └─ Demux: decrypt→ classify→ tun→ encrypt→ tx→ handshake→ feedback→ drop→ echo

              STAGE 5a: tun_write_vector()               [datapath.rs L463-540]
              └─ SPSC path: tx_tun_prod.push_batch(descs) → TUN HK thread writes to TUN fd

              STAGE 5b: tx_enqueue_vector()              [datapath.rs L421-458]
              ├─ For each data packet:
              │   ├─ rx_state: update highest_seq, delivered
              │   ├─ rx_bitmap.mark(seq)
              │   ├─ Resolve tx_iface from peer slot → EDT: pacer.pace(now, len) → release_ns
              │   └─ scheduler.enqueue_critical_edt(addr, len, release_ns, tx_iface)
              └─ (These are forwarded data packets — Hub-as-relay between nodes)

              STAGE 5c: process_fragment() → PQC offload
              ├─ Parse FragHeader (read_unaligned on packed struct)
              ├─ assembler.feed() → on complete reassembly:
              │   ├─ ClientHello: copy to payload_arena, push PqcReq(type=1) to SPSC
              │   └─ Finished: copy to payload_arena, push PqcReq(type=2) to SPSC
              └─ Free slab frame

              STAGE 5d: stage_feedback_gen()
              ├─ If rx_state needs feedback (threshold reached):
              │   ├─ Alloc slab, build feedback frame (FeedbackFrame struct)
              │   ├─ scheduler.enqueue_critical(addr, len, tx_iface=0)
              │   └─ If WiFi: duplicate to tx_iface=1
              └─ (Feedback frames carry ACK/loss/RTT/jitter back to nodes)

              STAGE 6: Free all consumed/dropped slab frames
```

### Cycle Step 9: TX Dequeue — Hardware Egress
```
L1280-1400    while scheduler.dequeue(now_ns) yields TxSubmit:
              ├─ If release_ns > now: break (EDT gating — packet not ready yet)
              ├─ Route by tx_iface:
              │   ├─ 0 (AF_XDP WAN): engine.tx_path.stage_tx(frame_idx, len)
              │   └─ 1 (io_uring WLAN): uring.stage_send_xdp_slab(ptr, len, slab_idx)
              ├─ udp_tx_count++
              └─ tx_counter.on_send()

              engine.tx_path.commit_tx()  → fence(Release) + store producer
              engine.tx_path.kick_tx()    → sendto(xsk_fd, null, 0, MSG_DONTWAIT)
              
              If WiFi: uring.submit()
```

### Cycle Step 10: EDT Idle Reset
```
L1470-1480    If no TX activity for >1s:
              ├─ pacer.reset(now)
              └─ Prevents burst-compensation after quiescent period
```

### GOTO Cycle Step 1

---

## THREAD TOPOLOGY SUMMARY

```
┌─────────────────────────────────────────────────────────────────┐
│                        PROCESS m13-hub                          │
│                                                                 │
│  ┌──────────────┐  ┌──────────────────┐  ┌───────────────────┐  │
│  │   Core 0     │  │  Isolated Core   │  │  Last Iso. Core   │  │
│  │  PQC Worker  │  │  VPP Datapath    │  │  TUN Housekeep    │  │
│  │              │  │                  │  │                   │  │
│  │ ML-KEM-1024  │  │ AF_XDP Engine    │  │ poll(tun_fd)      │  │
│  │ ML-DSA-87    │  │ BPF Steersman    │  │ read/write TUN    │  │
│  │ HKDF-SHA512  │  │ VPP Graph Exec   │  │                   │  │
│  │              │  │ AEAD AES-256-GCM │  │                   │  │
│  │ ◄──SPSC───── │  │ ─────SPSC──────► │  │ ◄──SPSC────       │  │
│  │  req   resp  │  │ tx_tun  rx_tun   │  │ free_to_tun       │  │
│  └──────────────┘  └──────────────────┘  └───────────────────┘  │
│                                                                 │
│  Main Thread: joined, waiting for worker(s) to exit             │
└─────────────────────────────────────────────────────────────────┘
```

---

## DEPENDENCY CHAIN (what must succeed before VPP runs)

```
1. HugePages allocated            → UMEM mmap depends on this
2. TSC calibrated                 → All timestamps depend on this  
3. PMU locked + IRQs fenced       → Latency guarantee
4. Isolated cores discovered      → Thread pinning depends on this
5. BPF steersman attached (DRV)   → AF_XDP ingress depends on this
6. AF_XDP UMEM mmap'd (1GB)       → All packet storage depends on this
7. XSK socket created + wired     → RX/TX ring depends on this
8. NIC HW ring verified ≥ 2048    → AF_XDP flow depends on this
9. TUN created (if --tunnel)      → IP forwarding depends on this
10. NAT + iptables applied        → Internet transit depends on this
11. SPSC rings created            → TUN HK ↔ Datapath IPC depends on this
12. TUN HK thread spawned         → VFS I/O offload depends on this
13. Worker thread spawned         → Everything below depends on this
14. FixedSlab initialized         → Frame allocation depends on this
15. PeerTable + Scheduler init    → Peer tracking + TX depends on this
16. All slab frames pre-stamped   → Avoids per-packet header init
17. FQ ring fully filled          → RX reception depends on this
18. PQC arenas allocated          → PQC offload depends on this
19. PQC worker spawned on Core 0  → Handshake processing depends on this
20. EDT Pacer initialized         → Pacing depends on this
21. → VPP MAIN LOOP BEGINS
```
