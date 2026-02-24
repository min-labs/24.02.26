// M13 HUB — NETWORK: DATAPATH
// Everything about moving packets — one file, one truth.
//
// RX pipeline: rx_parse_raw → aead_decrypt_vector → classify_route → scatter
// TX pipeline: tun_read_batch → aead_encrypt_vector → tx_enqueue_vector
// TUN I/O:     tun_write_vector, tun_read_batch
// Transport:   build_raw_udp_frame, ip_checksum, create_tun, setup_nat
// FIN bursts:  send_fin_burst_udp, send_fin_burst_l2
// Cold paths:  handle_reconnection

use crate::network::{PacketVector, PacketDesc, Disposition, NextNode, GraphCtx, CycleStats, VECTOR_SIZE};
use crate::engine::protocol::*;
use crate::engine::protocol::{PeerAddr, MAX_PEERS};

use crate::engine::runtime::prefetch_read_l1;

// ============================================================================
// RX PARSE — First node in the RX pipeline
// ============================================================================

/// Parse raw hardware descriptors into PacketDesc vectors.
/// Splits into decrypt (needs AEAD) and cleartext (handshake/control) vectors.
/// [P1-04] Multiplexing: Consumes rx_iface (0=AF_XDP, 1=io_uring) from the execution batch.
#[inline]
pub fn rx_parse_raw(
    descs: &[(u64, u32, u8)], // (addr, len, rx_iface)
    decrypt_out: &mut PacketVector,
    cleartext_out: &mut PacketVector,
    ctx: &mut GraphCtx<'_>,
    stats: &mut CycleStats,
) {
    let now = ctx.now_ns;

    for &(addr, len, rx_iface) in descs {
        // SAFETY: Pointer arithmetic within UMEM bounds; offset validated by kernel ring descriptor.
        let frame_ptr = unsafe { ctx.umem_base.add(addr as usize) };
        let frame_len = len as usize;

        // === DEBUG HEXDUMP: first packet in batch ===
        if cfg!(debug_assertions) && stats.parsed == 0 {
            let dump_len = frame_len.min(120);
            let hex_bytes: Vec<String> = (0..dump_len).map(|i| {
                format!("{:02x}", unsafe { *frame_ptr.add(i) })
            }).collect();
            eprintln!("[DBG-RX] addr=0x{:x} len={} iface={} hex: {}", addr, frame_len, rx_iface, hex_bytes.join(" "));
        }

        if frame_len < ETH_HDR_SIZE + M13_HDR_SIZE {
            ctx.slab.free((addr / ctx.frame_size as u64) as u32);
            stats.drops += 1;
            continue;
        }

        // Determine encapsulation and M13 offset
        // SAFETY: Pointer arithmetic within UMEM bounds; offset validated by kernel ring descriptor.
        let ethertype = unsafe { u16::from_be(*(frame_ptr.add(12) as *const u16)) };

        let (m13_offset, peer_idx) = if ethertype == ETH_P_M13 {
            // L2 raw M13 (air-gapped WiFi 7 or Direct Ethernet)
            // SAFETY: Pointer arithmetic within UMEM bounds; offset validated by kernel ring descriptor.
            let peer_mac = unsafe { *(frame_ptr.add(6) as *const [u8; 6]) };
            let peer_addr = PeerAddr::new_l2(peer_mac);
            // [P1-04] Bind the inbound rx_iface to the peer's tx_iface for symmetric routing
            match ctx.peers.lookup_or_insert(peer_addr, peer_mac, rx_iface) {
                Some(idx) => (ETH_HDR_SIZE as u16, idx as u8),
                None => {
                    ctx.slab.free((addr / ctx.frame_size as u64) as u32);
                    stats.drops += 1;
                    continue;
                }
            }
        } else if ethertype == 0x0800 && frame_len >= 56 + M13_HDR_SIZE {
            // IPv4 UDP encapsulated
            // SAFETY: Pointer arithmetic within UMEM bounds; offset validated by kernel ring descriptor.
            let src_ip = unsafe { *(frame_ptr.add(26) as *const [u8; 4]) };
            let src_port = unsafe { u16::from_be(*(frame_ptr.add(34) as *const u16)) };
            if cfg!(debug_assertions) {
                eprintln!("[DBG-RX] UDP from {}.{}.{}.{}:{} ethertype=0x{:04x} iface={}",
                    src_ip[0], src_ip[1], src_ip[2], src_ip[3], src_port, ethertype, rx_iface);
            }

            // Learn hub IP from wire if needed
            if ctx.hub_ip == [0, 0, 0, 0] {
                // SAFETY: Pointer arithmetic within UMEM bounds; offset validated by kernel ring descriptor.
                ctx.hub_ip = unsafe { *(frame_ptr.add(30) as *const [u8; 4]) };
                if cfg!(debug_assertions) { eprintln!("[DBG-RX] Learned hub_ip={:?}", ctx.hub_ip); }
            }
            if ctx.gateway_mac == [0xFF; 6] {
                // SAFETY: Pointer arithmetic within UMEM bounds; offset validated by kernel ring descriptor.
                ctx.gateway_mac = unsafe { *(frame_ptr.add(6) as *const [u8; 6]) };
                if cfg!(debug_assertions) { eprintln!("[DBG-RX] Learned gateway_mac={:02x?}", ctx.gateway_mac); }
            }

            // SAFETY: Pointer arithmetic within UMEM bounds; offset validated by kernel ring descriptor.
            let peer_mac = unsafe { *(frame_ptr.add(56 + 6) as *const [u8; 6]) };
            let peer_addr = PeerAddr::new_udp(src_ip, src_port);
            if cfg!(debug_assertions) { eprintln!("[DBG-RX] Before lookup_or_insert"); }
            // [P1-04] Plumb rx_iface down to peer table to symmetrically bind outbound route
            match ctx.peers.lookup_or_insert(peer_addr, peer_mac, rx_iface) {
                Some(idx) => {
                    if cfg!(debug_assertions) { eprintln!("[DBG-RX] After lookup_or_insert → slot {}", idx); }
                    (56u16, idx as u8) // ETH(14) + IP(20) + UDP(8) + FakeETH(14) = 56
                },
                None => {
                    ctx.slab.free((addr / ctx.frame_size as u64) as u32);
                    stats.drops += 1;
                    continue;
                }
            }
        } else {
            ctx.slab.free((addr / ctx.frame_size as u64) as u32);
            stats.drops += 1;
            continue;
        };

        // Validate M13 magic/version
        // SAFETY: Pointer arithmetic within UMEM bounds; offset validated by kernel ring descriptor.
        let m13_ptr = unsafe { frame_ptr.add(m13_offset as usize) };
        let magic = unsafe { *m13_ptr };
        // SAFETY: Pointer arithmetic within UMEM bounds; offset validated by kernel ring descriptor.
        let version = unsafe { *m13_ptr.add(1) };
        if magic != M13_WIRE_MAGIC || version != M13_WIRE_VERSION {
            ctx.slab.free((addr / ctx.frame_size as u64) as u32);
            stats.drops += 1;
            continue;
        }

        // Extract M13 header fields
        // SAFETY: Pointer and length are valid; pointer comes from UMEM or kernel ring within bounds.
        let flags_raw = unsafe { *m13_ptr.add(40) };
        let seq_id = unsafe {
            u64::from_le_bytes(std::slice::from_raw_parts(m13_ptr.add(32), 8).try_into().unwrap())
        };
        // SAFETY: Pointer and length are valid; pointer comes from UMEM or kernel ring within bounds.
        let payload_len = unsafe {
            u32::from_le_bytes(std::slice::from_raw_parts(m13_ptr.add(41), 4).try_into().unwrap_or([0;4]))
        };
        // SAFETY: Pointer arithmetic within UMEM bounds; offset validated by kernel ring descriptor.
        let crypto_ver = unsafe { *m13_ptr.add(2) };
        if cfg!(debug_assertions) {
            eprintln!("[DBG-RX] m13_off={} magic=0x{:02x} ver=0x{:02x} flags=0x{:02x} seq={} plen={} cver=0x{:02x}",
                m13_offset, magic, version, flags_raw, seq_id, payload_len, crypto_ver);
        }

        let mut desc = PacketDesc::EMPTY;
        desc.addr = addr;
        desc.len = len;
        desc.m13_offset = m13_offset;
        desc.peer_idx = peer_idx;
        desc.flags = flags_raw;
        desc.seq_id = seq_id;
        desc.payload_len = payload_len;
        desc.rx_ns = now;
        desc.rx_iface = rx_iface; // [P1-04] Embed interface ID for symmetric routing

        // Store source IP/port for UDP peers
        if m13_offset == 56 {
            // SAFETY: Pointer arithmetic within UMEM bounds; offset validated by kernel ring descriptor.
            desc.src_ip = unsafe { *(frame_ptr.add(26) as *const [u8; 4]) };
            desc.src_port = unsafe { u16::from_be(*(frame_ptr.add(34) as *const u16)) };
        }

        // Split by crypto version: encrypted → decrypt_out, cleartext → cleartext_out
        if crypto_ver == 0x01 {
            decrypt_out.push(desc);
        } else {
            cleartext_out.push(desc);
        }
        stats.parsed += 1;
    }
}

// ============================================================================
// AEAD — Vectorized AES-256-GCM encrypt/decrypt
// ============================================================================

/// Vectorized AEAD decrypt. Processes the entire batch.
#[inline]
pub fn aead_decrypt_vector(
    input: &mut PacketVector,
    disp: &mut Disposition,
    ctx: &mut GraphCtx<'_>,
    stats: &mut CycleStats,
) {
    let now = ctx.now_ns;
    let n = input.len;
    let mut i = 0;

    while i + 4 <= n {
        if i + 8 <= n {
            for k in 4..8 {
                let idx = i + k;
                if input.descs[idx].addr != 0 {
                    // SAFETY: Prefetch is advisory; no memory safety impact if address is invalid.
                    unsafe { prefetch_read_l1(ctx.umem_base.add(input.descs[idx].addr as usize) as *const u8); }
                }
            }
        }
        for j in 0..4 {
            disp.next[i + j] = decrypt_one(&mut input.descs[i + j], ctx, stats, now);
        }
        i += 4;
    }
    while i < n {
        disp.next[i] = decrypt_one(&mut input.descs[i], ctx, stats, now);
        i += 1;
    }
}

#[inline(always)]
fn decrypt_one(
    desc: &mut PacketDesc,
    ctx: &mut GraphCtx<'_>,
    stats: &mut CycleStats,
    now: u64,
) -> NextNode {
    let pidx = desc.peer_idx as usize;
    if pidx >= MAX_PEERS { return NextNode::Drop; }

    let cipher = match ctx.peers.ciphers[pidx].as_ref() {
        Some(c) => c,
        None => { stats.aead_fail += 1; return NextNode::Drop; }
    };

    // SAFETY: desc.addr is a UMEM offset; add to umem_base for actual mapped address.
    let frame = unsafe {
        std::slice::from_raw_parts_mut(ctx.umem_base.add(desc.addr as usize), desc.len as usize)
    };
    let m13_off = desc.m13_offset as usize;

    // Direction reflection pre-check: if nonce direction byte matches our_dir,
    // this is a reflected packet. Count it separately from MAC failures.
    if frame.len() >= m13_off + 32 && frame[m13_off + 28] == DIR_HUB_TO_NODE {
        stats.direction_fail += 1;
        stats.aead_fail += 1;
        return NextNode::Drop;
    }

    if crate::cryptography::aead::open_frame(frame, cipher, DIR_HUB_TO_NODE, m13_off) {
        // Re-read flags from decrypted buffer
        // SAFETY: desc.addr is UMEM offset; umem_base + offset gives actual pointer.
        let decrypted_flags = unsafe { *(ctx.umem_base.add(desc.addr as usize + m13_off + 40)) };
        desc.flags = decrypted_flags;

        // Re-read seq_id from decrypted buffer
        // SAFETY: desc.addr is UMEM offset; umem_base + offset gives actual pointer.
        desc.seq_id = unsafe {
            u64::from_le_bytes(
                std::slice::from_raw_parts(ctx.umem_base.add(desc.addr as usize + m13_off + 32), 8)
                    .try_into().unwrap()
            )
        };

        ctx.peers.slots[pidx].frame_count += 1;
        stats.aead_ok += 1;

        // Rekey check
        let established_ns = (ctx.peers.slots[pidx].established_rel_s as u64) * 1_000_000_000 + ctx.peers.epoch_ns;
        if ctx.peers.slots[pidx].frame_count as u64 >= REKEY_FRAME_LIMIT
           || now.saturating_sub(established_ns) > REKEY_TIME_LIMIT_NS {
            ctx.peers.slots[pidx].reset_session();
            ctx.peers.ciphers[pidx] = None;
            ctx.peers.hs_sidecar[pidx] = None;
        }

        NextNode::ClassifyRoute
    } else {
        stats.aead_fail += 1;
        NextNode::Drop
    }
}

/// Handle reconnection detection for cleartext control packets.
#[inline]
pub fn handle_reconnection(
    input: &PacketVector,
    ctx: &mut GraphCtx<'_>,
) {
    for i in 0..input.len {
        let desc = &input.descs[i];
        let pidx = desc.peer_idx as usize;

        if pidx < MAX_PEERS
            && ctx.peers.slots[pidx].has_session()
            && (desc.flags & FLAG_HANDSHAKE == 0)
            && (desc.flags & FLAG_FRAGMENT == 0)
            && (desc.flags & FLAG_CONTROL != 0)
        {
            ctx.peers.slots[pidx].reset_session();
            ctx.peers.ciphers[pidx] = None;
            ctx.peers.hs_sidecar[pidx] = None;
            ctx.peers.assemblers[pidx].clear_all();
        }
    }
}

/// Vectorized AEAD encrypt. Called on the TUN→wire TX path.
#[inline]
pub fn aead_encrypt_vector(
    input: &mut PacketVector,
    disp: &mut Disposition,
    ctx: &mut GraphCtx<'_>,
) {
    let n = input.len;
    let mut i = 0;

    while i + 4 <= n {
        if i + 8 <= n {
            for k in 4..8 {
                let idx = i + k;
                if input.descs[idx].addr != 0 {
                    // SAFETY: Prefetch is advisory; no memory safety impact if address is invalid.
                    unsafe { prefetch_read_l1(ctx.umem_base.add(input.descs[idx].addr as usize) as *const u8); }
                }
            }
        }
        for j in 0..4 {
            disp.next[i + j] = encrypt_one(&mut input.descs[i + j], ctx);
        }
        i += 4;
    }
    while i < n {
        disp.next[i] = encrypt_one(&mut input.descs[i], ctx);
        i += 1;
    }
}

#[inline(always)]
fn encrypt_one(desc: &mut PacketDesc, ctx: &mut GraphCtx<'_>) -> NextNode {
    let peer_idx = desc.peer_idx as usize;
    if peer_idx >= MAX_PEERS { return NextNode::Drop; }

    let cipher = match &ctx.peers.ciphers[peer_idx] {
        Some(c) => c,
        None => return NextNode::Drop,
    };

    let seq = ctx.peers.slots[peer_idx].next_seq();
    // SAFETY: desc.addr is a UMEM offset; add to umem_base for actual mapped address.
    let frame = unsafe {
        std::slice::from_raw_parts_mut(ctx.umem_base.add(desc.addr as usize), desc.len as usize)
    };
    let m13_off = desc.m13_offset as usize;

    crate::cryptography::aead::seal_frame(frame, cipher, seq, DIR_HUB_TO_NODE, m13_off);
    desc.seq_id = seq;
    ctx.peers.slots[peer_idx].frame_count += 1;

    NextNode::TxEnqueue
}

// ============================================================================
// CLASSIFY — Post-decrypt routing
// ============================================================================

/// Classify a vector of packets and route to next node.
#[inline]
pub fn classify_route(
    input: &PacketVector,
    disp: &mut Disposition,
    stats: &mut CycleStats,
    closing: bool,
) {
    let n = input.len;
    let mut i = 0;

    while i + 4 <= n {
        if i + 8 <= n {
            for k in 4..8 {
                let idx = i + k;
                if input.descs[idx].addr != 0 {
                    // SAFETY: Prefetch is advisory; no memory safety impact if address is invalid.
                    // Prefetch the PacketDesc struct itself (flags field) — NOT UMEM payload.
                    // classify_one reads desc.flags only; prefetching UMEM here would pollute L1d
                    // with payload data not accessed until tun_write_vector runs later.
                    unsafe { prefetch_read_l1(&input.descs[idx] as *const PacketDesc as *const u8); }
                }
            }
        }
        for j in 0..4 {
            disp.next[i + j] = classify_one(&input.descs[i + j], stats, closing);
        }
        i += 4;
    }
    while i < n {
        disp.next[i] = classify_one(&input.descs[i], stats, closing);
        i += 1;
    }
}

#[inline(always)]
fn classify_one(desc: &PacketDesc, stats: &mut CycleStats, closing: bool) -> NextNode {
    let flags = desc.flags;

    if flags & FLAG_FRAGMENT != 0 { return NextNode::Handshake; }
    if flags & FLAG_FEEDBACK != 0 { return NextNode::Feedback; }
    if flags & FLAG_TUNNEL != 0 { return NextNode::TunWrite; }

    if flags & FLAG_FIN != 0 {
        if stats.fin_count < stats.fin_events.len() {
            stats.fin_events[stats.fin_count] = (desc.peer_idx, closing);
            stats.fin_count += 1;
        }
        return NextNode::Consumed;
    }

    if flags & FLAG_HANDSHAKE != 0 { return NextNode::Handshake; }
    if flags & FLAG_CONTROL != 0 { return NextNode::Consumed; }

    NextNode::TxEnqueue
}

// ============================================================================
// TX ENQUEUE — Submit packets to scheduler
// ============================================================================

/// Enqueue a vector of packets to the TX scheduler.
/// V4: EDT pacing gates timing before scheduler enqueue.
/// [P1-04] Multiplexing: Extract the egress `tx_iface` from the peer slot to properly route to AF_XDP or io_uring.
#[inline]
pub fn tx_enqueue_vector(
    input: &PacketVector,
    disp: &mut Disposition,
    ctx: &mut GraphCtx<'_>,
    stats: &mut CycleStats,
) {
    let n = input.len;
    for i in 0..n {
        let desc = &input.descs[i];

        if !ctx.closing {
            ctx.rx_state.highest_seq = desc.seq_id;
            ctx.rx_state.delivered += 1;
            ctx.rx_state.last_rx_batch_ns = ctx.now_ns;
            ctx.rx_bitmap.mark(desc.seq_id);

            let pidx = desc.peer_idx as usize;
            let tx_iface = if pidx < MAX_PEERS {
                ctx.peers.slots[pidx].tx_iface
            } else {
                desc.rx_iface // default: reflect back to where it came from
            };

            // V4: EDT pacing — compute release time per-packet (zero-spin)
            let release_ns = if let Some(ref mut pacer) = ctx.pacer {
                pacer.pace(ctx.now_ns, desc.len)
            } else {
                0
            };
            ctx.scheduler.enqueue_critical_edt(desc.addr, desc.len, release_ns, tx_iface);
            stats.data_fwd += 1;
        } else {
            ctx.slab.free((desc.addr / ctx.frame_size as u64) as u32);
        }

        disp.next[i] = NextNode::Consumed;
    }
}

// ============================================================================
// TUN I/O — Read/write packets from/to the TUN interface
// ============================================================================

/// Write decrypted tunnel packets to the TUN interface.
/// R-02: If SPSC ring is available, push PacketDesc to TX ring (ownership transfers to TUN thread).
///       If no SPSC ring, fall back to direct VFS write.
#[inline]
pub fn tun_write_vector(
    input: &PacketVector,
    disp: &mut Disposition,
    ctx: &mut super::GraphCtx<'_>,
    stats: &mut CycleStats,
) {
    let n = input.len;
    if n == 0 { return; }

    // R-02 SPSC PATH: Push packets to TUN thread. Slab ownership transfers.
    if let Some(ref mut prod) = ctx.tx_tun_prod {
        let pushed = prod.push_batch(&input.descs[..n]);
        for i in 0..pushed {
            disp.next[i] = NextNode::Consumed;
            stats.tun_writes += 1;
        }
        // Backpressure: if ring was full, drop the remaining packets and free their slabs.
        for i in pushed..n {
            disp.next[i] = NextNode::Consumed;
            ctx.slab.free((input.descs[i].addr / ctx.frame_size as u64) as u32);
        }
        return;
    }

    // FALLBACK: Direct VFS write (no SPSC ring, e.g. --no-tunnel or single-threaded mode)
    let tun_fd = ctx.tun_fd;
    let umem_base = ctx.umem_base as *const u8;
    let mut i = 0;
    while i + 4 <= n {
        if i + 8 <= n {
            for k in 4..8 {
                let idx = i + k;
                if input.descs[idx].addr != 0 {
                    // SAFETY: Prefetch is advisory; umem_base + offset is valid UMEM address.
                    unsafe { prefetch_read_l1(umem_base.add(input.descs[idx].addr as usize)); }
                }
            }
        }
        for j in 0..4 {
            disp.next[i + j] = write_one_tun(&input.descs[i + j], tun_fd, umem_base, stats);
        }
        i += 4;
    }
    while i < n {
        disp.next[i] = write_one_tun(&input.descs[i], tun_fd, umem_base, stats);
        i += 1;
    }
}

#[inline(always)]
fn write_one_tun(desc: &PacketDesc, tun_fd: i32, umem_base: *const u8, stats: &mut CycleStats) -> NextNode {
    let m13_off = desc.m13_offset as usize;
    let payload_start = m13_off + M13_HDR_SIZE;

    // SAFETY: desc.addr is UMEM offset; umem_base + offset gives actual pointer.
    let plen = unsafe {
        let m13_ptr = umem_base.add(desc.addr as usize + m13_off);
        u32::from_le_bytes(std::slice::from_raw_parts(m13_ptr.add(41), 4).try_into().unwrap_or([0;4]))
    } as usize;

    if plen == 0 || payload_start + plen > desc.len as usize || tun_fd < 0 {
        return NextNode::Consumed;
    }

    // SAFETY: desc.addr is UMEM offset.
    let payload_ptr = unsafe { umem_base.add(desc.addr as usize + payload_start) };
    unsafe {
        libc::write(tun_fd, payload_ptr as *const libc::c_void, plen);
    }
    stats.tun_writes += 1;

    NextNode::Consumed
}

/// Read IP packets from TUN and build M13 frames for wire TX.
/// R-02: If SPSC ring is available, pop pre-built frames from TUN thread.
///       Also drain free-index returns and provision empty slabs.
///       If no SPSC ring, fall back to direct VFS read.
#[inline]
pub fn tun_read_batch(
    output: &mut PacketVector,
    ctx: &mut super::GraphCtx<'_>,
) -> usize {
    // R-02: Drain free slab indices returned by TUN thread
    if let Some(ref mut free_cons) = ctx.free_to_dp_cons {
        let mut free_buf = [0u32; 64];
        let freed = free_cons.pop_batch(&mut free_buf);
        for i in 0..freed {
            ctx.slab.free(free_buf[i]);
        }
    }

    // R-02: Demand-Driven Provisioning (AF_XDP Fill Ring pattern)
    // Only provision what the ring can accept to prevent slab pool drain
    if let Some(ref mut free_prod) = ctx.free_to_tun_prod {
        let ring_space = free_prod.available();
        let provision_cap = ring_space.min(64); // Max batch size, bounded by ring space

        if provision_cap > 0 {
            let mut slab_buf = [0u32; 64];
            let mut slab_count = 0;
            while slab_count < provision_cap {
                if let Some(idx) = ctx.slab.alloc() {
                    slab_buf[slab_count] = idx;
                    slab_count += 1;
                } else {
                    break;
                }
            }
            if slab_count > 0 {
                let pushed = free_prod.push_batch(&slab_buf[..slab_count]);
                // Reclaim any unpushed (mathematically guaranteed to fit via available(), belt-and-suspenders)
                for i in pushed..slab_count {
                    ctx.slab.free(slab_buf[i]);
                }
            }
        }
    }

    // R-02 SPSC PATH: Pop pre-built TUN frames from the housekeeping thread
    if let Some(ref mut cons) = ctx.rx_tun_cons {
        let available = output.capacity() - output.len;
        if available == 0 { return 0; }
        let mut desc_buf = [PacketDesc::EMPTY; VECTOR_SIZE];
        let popped = cons.pop_batch(&mut desc_buf[..available]);
        for i in 0..popped {
            output.push(desc_buf[i]);
        }
        return popped;
    }

    // FALLBACK: Direct VFS read (no SPSC ring)
    let mut count = 0;

    // [P1-02] STRICT USO MTU CLAMPING (1380 bytes)
    // Ensures L2 length never exceeds 1442, preventing kernel-level WiFi fragmentation.
    let max_payload = (ctx.frame_size as usize - ETH_HDR_SIZE - M13_HDR_SIZE).min(1380);

    while !output.is_full() {
        let idx = match ctx.slab.alloc() {
            Some(i) => i,
            None => break,
        };
        let addr = (idx as u64) * (ctx.frame_size as u64);
        // SAFETY: Pointer arithmetic within UMEM bounds.
        let frame_ptr = unsafe { ctx.umem_base.add(addr as usize) };

        // SAFETY: Pointer arithmetic within UMEM bounds.
        let payload_ptr = unsafe { frame_ptr.add(ETH_HDR_SIZE + M13_HDR_SIZE) };

        // SAFETY: FFI call with valid fd and buffer.
        let n = unsafe {
            libc::read(ctx.tun_fd, payload_ptr as *mut libc::c_void, max_payload)
        };

        if n <= 0 {
            ctx.slab.free(idx);
            break;
        }

        let payload_len = n as usize;
        let frame_len = ETH_HDR_SIZE + M13_HDR_SIZE + payload_len;

        // SAFETY: Pointer and length are valid within UMEM bounds.
        let frame = unsafe { std::slice::from_raw_parts_mut(frame_ptr, frame_len) };
        frame[0..6].copy_from_slice(&[0xFF; 6]);
        frame[6..12].copy_from_slice(&ctx.src_mac);
        frame[12] = (ETH_P_M13 >> 8) as u8;
        frame[13] = (ETH_P_M13 & 0xFF) as u8;

        frame[14] = M13_WIRE_MAGIC;
        frame[15] = M13_WIRE_VERSION;
        frame[54] = FLAG_TUNNEL;
        frame[55..59].copy_from_slice(&(payload_len as u32).to_le_bytes());

        let mut desc = PacketDesc::EMPTY;
        desc.addr = addr;
        desc.len = frame_len as u32;
        desc.m13_offset = ETH_HDR_SIZE as u16;
        desc.flags = FLAG_TUNNEL;
        desc.payload_len = payload_len as u32;
        desc.rx_iface = 0; // Default AF_XDP for fallback

        if payload_len >= 20 {
            // SAFETY: Pointer and length are valid within UMEM bounds.
            let ip_hdr = unsafe { std::slice::from_raw_parts(payload_ptr, 20) };
            desc.src_ip.copy_from_slice(&ip_hdr[16..20]);
        }

        output.push(desc);
        count += 1;
    }

    count
}

// ============================================================================
// TRANSPORT — Raw UDP framing, IP checksum, MAC/gateway resolution, TUN, NAT
// ============================================================================

pub const IP_HDR_LEN: usize = 20;
pub const UDP_HDR_LEN: usize = 8;
pub const RAW_HDR_LEN: usize = ETH_HDR_SIZE + IP_HDR_LEN + UDP_HDR_LEN; // 42

/// RFC 1071: Internet checksum.
#[inline]
pub fn ip_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() { sum += (data[i] as u32) << 8; }
    while sum >> 16 != 0 { sum = (sum & 0xFFFF) + (sum >> 16); }
    !(sum as u16)
}

/// Construct a raw Ethernet + IPv4 + UDP frame in a buffer.
#[allow(clippy::too_many_arguments)]
pub fn build_raw_udp_frame(
    buf: &mut [u8], src_mac: &[u8; 6], dst_mac: &[u8; 6],
    src_ip: [u8; 4], dst_ip: [u8; 4],
    src_port: u16, dst_port: u16, ip_id: u16, payload: &[u8],
) -> usize {
    let payload_len = payload.len();
    let udp_len = UDP_HDR_LEN + payload_len;
    let ip_total_len = IP_HDR_LEN + udp_len;
    let frame_len = ETH_HDR_SIZE + ip_total_len;
    debug_assert!(frame_len <= buf.len(), "frame too large for buffer");

    buf[0..6].copy_from_slice(dst_mac);
    buf[6..12].copy_from_slice(src_mac);
    buf[12..14].copy_from_slice(&0x0800u16.to_be_bytes());

    let ip = &mut buf[14..34];
    ip[0] = 0x45; ip[1] = 0x00;
    ip[2..4].copy_from_slice(&(ip_total_len as u16).to_be_bytes());
    ip[4..6].copy_from_slice(&ip_id.to_be_bytes());
    ip[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    ip[8] = 64; ip[9] = 17;
    ip[10..12].copy_from_slice(&[0, 0]);
    ip[12..16].copy_from_slice(&src_ip);
    ip[16..20].copy_from_slice(&dst_ip);
    let cksum = ip_checksum(ip);
    ip[10..12].copy_from_slice(&cksum.to_be_bytes());

    let udp = &mut buf[34..42];
    udp[0..2].copy_from_slice(&src_port.to_be_bytes());
    udp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    udp[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    udp[6..8].copy_from_slice(&[0, 0]);

    buf[42..42 + payload_len].copy_from_slice(payload);
    frame_len
}

/// Read hardware MAC from sysfs.
pub fn detect_mac(if_name: &str) -> [u8; 6] {
    let path = format!("/sys/class/net/{}/address", if_name);
    if let Ok(contents) = std::fs::read_to_string(&path) {
        let parts: Vec<u8> = contents.trim().split(':')
            .filter_map(|h| u8::from_str_radix(h, 16).ok()).collect();
        if parts.len() == 6 {
            eprintln!("[M13-EXEC] Detected MAC for {}: {}", if_name, contents.trim());
            return [parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]];
        }
    }
    eprintln!("[M13-EXEC] WARNING: Could not read MAC from sysfs ({}), using LAA fallback", path);
    [0x02, 0x00, 0x00, 0x00, 0x00, 0x01]
}

/// Resolve default gateway MAC from /proc/net/route + /proc/net/arp.
pub fn resolve_gateway_mac(if_name: &str) -> Option<([u8; 6], [u8; 4])> {
    let route_data = std::fs::read_to_string("/proc/net/route").ok()?;
    let mut gw_ip_hex: Option<u32> = None;
    for line in route_data.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 3 && fields[0] == if_name && fields[1] == "00000000" {
            gw_ip_hex = u32::from_str_radix(fields[2], 16).ok();
            break;
        }
    }
    let gw_hex = gw_ip_hex?;
    let gw_ip = gw_hex.to_le_bytes();

    let arp_data = std::fs::read_to_string("/proc/net/arp").ok()?;
    let gw_ip_str = format!("{}.{}.{}.{}", gw_ip[0], gw_ip[1], gw_ip[2], gw_ip[3]);
    let try_resolve = |data: &str| -> Option<[u8; 6]> {
        for line in data.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() >= 6 && fields[0] == gw_ip_str && fields[5] == if_name {
                let mac_parts: Vec<u8> = fields[3].split(':')
                    .filter_map(|h| u8::from_str_radix(h, 16).ok()).collect();
                if mac_parts.len() == 6 {
                    return Some([mac_parts[0], mac_parts[1], mac_parts[2],
                                 mac_parts[3], mac_parts[4], mac_parts[5]]);
                }
            }
        }
        None
    };
    if let Some(mac) = try_resolve(&arp_data) {
        eprintln!("[M13-NET] Gateway: {} MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} dev: {}",
            gw_ip_str, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], if_name);
        return Some((mac, gw_ip));
    }
    eprintln!("[M13-NET] WARNING: Gateway {} not in ARP cache. Pinging...", gw_ip_str);
    let _ = std::process::Command::new("ping")
        .args(["-c", "1", "-W", "1", &gw_ip_str])
        .stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status();
    if let Ok(arp2) = std::fs::read_to_string("/proc/net/arp") {
        if let Some(mac) = try_resolve(&arp2) {
            eprintln!("[M13-NET] Gateway: {} MAC resolved (after ARP)", gw_ip_str);
            return Some((mac, gw_ip));
        }
    }
    None
}

/// Read IPv4 address of a network interface via ioctl.
pub fn get_interface_ip(if_name: &str) -> Option<[u8; 4]> {
    // SAFETY: Caller ensures invariants documented at module level.
    unsafe {
        let sock = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if sock < 0 { return None; }
        let mut ifr: libc::ifreq = std::mem::zeroed();
        let name_bytes = if_name.as_bytes();
        let copy_len = name_bytes.len().min(libc::IFNAMSIZ - 1);
        std::ptr::copy_nonoverlapping(name_bytes.as_ptr(), ifr.ifr_name.as_mut_ptr() as *mut u8, copy_len);
        if libc::ioctl(sock, libc::SIOCGIFADDR as libc::c_ulong, &mut ifr) < 0 {
            libc::close(sock); return None;
        }
        libc::close(sock);
        let sa = &*(&ifr.ifr_ifru as *const _ as *const libc::sockaddr_in);
        let ip_u32 = sa.sin_addr.s_addr;
        let ip_ne = ip_u32.to_ne_bytes();
        eprintln!("[M13-NET] Interface {} IP: {}.{}.{}.{}", if_name,
            ip_ne[0], ip_ne[1], ip_ne[2], ip_ne[3]);
        Some(ip_ne)
    }
}

// ── TUN & NAT ───────────────────────────────────────────────────────────

const IFF_TUN: i16 = 0x0001;
const IFF_NO_PI: i16 = 0x1000;
const TUNSETIFF: u64 = 0x400454ca;

#[repr(C)]
struct ifreq_tun {
    ifr_name: [u8; 16],
    ifr_flags: i16,
}

pub fn create_tun(name: &str) -> Option<std::fs::File> {
    use std::os::unix::io::AsRawFd;
    let tun_path = "/dev/net/tun";
    let file = match std::fs::OpenOptions::new().read(true).write(true).open(tun_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("[M13-TUN] Failed to open {}: {}", tun_path, e);
            return None;
        }
    };

    let mut req = ifreq_tun {
        ifr_name: [0; 16],
        ifr_flags: IFF_TUN | IFF_NO_PI,
    };

    let name_bytes = name.as_bytes();
    if name_bytes.len() > 15 {
        eprintln!("[M13-TUN] Interface name too long");
        return None;
    }
    for (i, b) in name_bytes.iter().enumerate() {
        req.ifr_name[i] = *b;
    }

    // SAFETY: FFI call with valid socket fd and ioctl struct pointer.
    unsafe {
        if libc::ioctl(file.as_raw_fd(), TUNSETIFF, &req) < 0 {
            eprintln!("[M13-TUN] ioctl(TUNSETIFF) failed");
            return None;
        }
        let fd = file.as_raw_fd();
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags >= 0 {
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
    }

    let _ = std::process::Command::new("ip").args(["link", "set", "dev", name, "up"]).output();
    let _ = std::process::Command::new("ip").args(["addr", "add", "10.13.0.1/24", "dev", name]).output();
    
    // [P1-02] MATHEMATICAL MTU CLAMP: Set TUN MTU to strictly 1380 bytes.
    // Forces kernel to segment oversized IP packets down to 1380 bytes before writing to TUN.
    // 1380 + 14 + 48 + 8 (fragment metadata safety) = 1450 <= 1500 limit.
    let _ = std::process::Command::new("ip").args(["link", "set", "dev", name, "mtu", "1380"]).output();
    let _ = std::process::Command::new("ip").args(["link", "set", "dev", name, "txqueuelen", "1000"]).output();

    eprintln!("[M13-TUN] Created tunnel interface {} (10.13.0.1/24, MTU 1380)", name);
    Some(file)
}

/// Read a sysctl value from /proc/sys.
fn read_sysctl(key: &str) -> Option<String> {
    let path = format!("/proc/sys/{}", key.replace('.', "/"));
    std::fs::read_to_string(&path).ok().map(|s| s.trim().to_string())
}

/// Apply a sysctl and verify it took effect. Returns true if verified.
fn apply_sysctl(key: &str, value: &str) -> bool {
    let arg = format!("{}={}", key, value);
    let _ = std::process::Command::new("sysctl").args(["-w", &arg]).output();
    match read_sysctl(key) {
        Some(actual) => actual == value,
        None => false,
    }
}

pub fn setup_nat() {
    use std::process::Command;
    eprintln!("[M13-NAT] Enabling NAT + TCP BDP tuning...");
    let mut ok = 0u32;
    let mut fail = 0u32;

    // Core sysctls — apply and verify each one
    for (k, v) in [
        ("net.ipv4.ip_forward", "1"),
        ("net.core.rmem_max", "16777216"),
        ("net.core.wmem_max", "16777216"),
        ("net.core.rmem_default", "4194304"),
        ("net.core.wmem_default", "4194304"),
        ("net.ipv4.tcp_rmem", "4096\t1048576\t16777216"),
        ("net.ipv4.tcp_wmem", "4096\t1048576\t16777216"),
        ("net.ipv4.tcp_slow_start_after_idle", "0"),
        ("net.core.netdev_max_backlog", "10000"),
        ("net.core.netdev_budget", "600"),
        ("net.core.netdev_budget_usecs", "8000"),
        ("net.ipv4.tcp_window_scaling", "1"),
        ("net.ipv4.tcp_congestion_control", "bbr"),
        ("net.ipv4.tcp_no_metrics_save", "1"),
        ("net.ipv4.tcp_mtu_probing", "1"),
    ] {
        if apply_sysctl(k, v) { ok += 1; } else { fail += 1; eprintln!("[M13-NAT] WARN: {} failed", k); }
    }

    // fq qdisc — required by BBR for pacing
    let _ = Command::new("tc").args(["qdisc", "replace", "dev", "m13tun0", "root", "fq"]).output();

    if fail == 0 {
        eprintln!("[M13-NAT] ✓ Optimisation Applied ({} sysctls verified)", ok);
    } else {
        eprintln!("[M13-NAT] ⚠ Optimisation Partial ({}/{} applied, {} failed)", ok, ok + fail, fail);
    }

    // MASQUERADE only tunnel subnet — NOT all outbound traffic.
    let _ = Command::new("iptables").args(["-t", "nat", "-A", "POSTROUTING", "-s", "10.13.0.0/24", "!", "-o", "m13tun0", "-j", "MASQUERADE"]).output();
    let _ = Command::new("iptables").args(["-A", "FORWARD", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"]).output();
    let _ = Command::new("iptables").args(["-A", "FORWARD", "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"]).output();
    let _ = Command::new("iptables").args(["-A", "FORWARD", "-i", "m13tun0", "-j", "ACCEPT"]).output();
    let _ = Command::new("iptables").args(["-A", "FORWARD", "-o", "m13tun0", "-j", "ACCEPT"]).output();
}

pub fn nuke_cleanup_hub(if_name: &str) {
    use std::process::Command;
    eprintln!("[M13-NUKE] Tearing down all Hub state...");
    // Remove scoped MASQUERADE (current rule)
    let _ = Command::new("iptables").args(["-t", "nat", "-D", "POSTROUTING", "-s", "10.13.0.0/24", "!", "-o", "m13tun0", "-j", "MASQUERADE"]).output();
    // Also remove legacy unscoped MASQUERADE (cleanup from older builds)
    let _ = Command::new("iptables").args(["-t", "nat", "-D", "POSTROUTING", "!", "-o", "m13tun0", "-j", "MASQUERADE"]).output();
    let _ = Command::new("iptables").args(["-D", "FORWARD", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"]).output();
    let _ = Command::new("iptables").args(["-D", "FORWARD", "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"]).output();
    let _ = Command::new("iptables").args(["-D", "FORWARD", "-o", "m13tun0", "-j", "ACCEPT"]).output();
    let _ = Command::new("iptables").args(["-D", "FORWARD", "-i", "m13tun0", "-j", "ACCEPT"]).output();
    let _ = Command::new("ip").args(["link", "del", "m13tun0"]).output();
    let _ = Command::new("ip").args(["link", "set", if_name, "xdp", "off"]).output();
    let _ = Command::new("ip").args(["link", "set", if_name, "xdpgeneric", "off"]).output();
    eprintln!("[M13-NUKE] ✓ All Hub state destroyed.");
}

// ── FIN + L2 TX Helpers ─────────────────────────────────────────────────

use crate::engine::runtime::FixedSlab;
use crate::network::xdp::{Engine, ZeroCopyTx, FRAME_SIZE};
use crate::engine::protocol::Scheduler;

/// Send `count` redundant FIN or FIN-ACK frames wrapped in raw UDP.
#[inline(never)]
#[allow(clippy::too_many_arguments)]
pub fn send_fin_burst_udp(
    slab: &mut FixedSlab, engine: &Engine<ZeroCopyTx>,
    scheduler: &mut Scheduler,
    src_mac: &[u8; 6], gateway_mac: &[u8; 6],
    hub_ip: [u8; 4], peer_ip: [u8; 4],
    hub_port: u16, peer_port: u16,
    ip_id: &mut u16,
    final_seq: u64, fin_ack: bool, count: usize,
    tx_iface: u8, // [P1-04] Added tx_iface for routing multiplexed FIN bursts
) -> usize {
    let mut sent = 0;
    let mut fin_m13 = [0u8; 62];
    fin_m13[0..6].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
    fin_m13[6..12].copy_from_slice(src_mac);
    fin_m13[12] = (ETH_P_M13 >> 8) as u8;
    fin_m13[13] = (ETH_P_M13 & 0xFF) as u8;
    fin_m13[14] = M13_WIRE_MAGIC;
    fin_m13[15] = M13_WIRE_VERSION;
    fin_m13[46..54].copy_from_slice(&final_seq.to_le_bytes());
    fin_m13[54] = FLAG_CONTROL | FLAG_FIN | if fin_ack { FLAG_FEEDBACK } else { 0 };

    for _ in 0..count {
        if let Some(idx) = slab.alloc() {
            // SAFETY: Pointer arithmetic within UMEM bounds.
            let frame_ptr = unsafe { engine.umem_base().add((idx as usize) * FRAME_SIZE as usize) };
            let total_len;
            // SAFETY: Pointer and length are valid within UMEM bounds.
            unsafe {
                let buf = std::slice::from_raw_parts_mut(frame_ptr, FRAME_SIZE as usize);
                total_len = build_raw_udp_frame(
                    buf, src_mac, gateway_mac,
                    hub_ip, peer_ip, hub_port, peer_port,
                    *ip_id, &fin_m13,
                );
                *ip_id = ip_id.wrapping_add(1);
            }
            scheduler.enqueue_critical((idx as u64) * FRAME_SIZE as u64, total_len as u32, tx_iface);
            sent += 1;
        }
    }
    sent
}

/// Send `count` redundant FIN or FIN-ACK frames via raw L2.
#[inline(never)]
#[allow(clippy::too_many_arguments)]
pub fn send_fin_burst_l2(
    slab: &mut FixedSlab, engine: &Engine<ZeroCopyTx>,
    scheduler: &mut Scheduler,
    src_mac: &[u8; 6], peer_mac: &[u8; 6],
    final_seq: u64, fin_ack: bool, count: usize,
    tx_iface: u8, // [P1-04] Added tx_iface
) -> usize {
    let mut sent = 0;
    let mut fin_m13 = [0u8; 62];
    fin_m13[0..6].copy_from_slice(peer_mac);
    fin_m13[6..12].copy_from_slice(src_mac);
    fin_m13[12] = (ETH_P_M13 >> 8) as u8;
    fin_m13[13] = (ETH_P_M13 & 0xFF) as u8;
    fin_m13[14] = M13_WIRE_MAGIC;
    fin_m13[15] = M13_WIRE_VERSION;
    fin_m13[46..54].copy_from_slice(&final_seq.to_le_bytes());
    fin_m13[54] = FLAG_CONTROL | FLAG_FIN | if fin_ack { FLAG_FEEDBACK } else { 0 };

    for _ in 0..count {
        if let Some(idx) = slab.alloc() {
            // SAFETY: Pointer and length are valid within UMEM bounds.
            let frame_ptr = unsafe { engine.umem_base().add((idx as usize) * FRAME_SIZE as usize) };
            unsafe {
                let buf = std::slice::from_raw_parts_mut(frame_ptr, FRAME_SIZE as usize);
                buf[..62].copy_from_slice(&fin_m13);
            }
            scheduler.enqueue_critical((idx as u64) * FRAME_SIZE as u64, 62, tx_iface);
            sent += 1;
        }
    }
    sent
}