// M13 HUB — INTEGRATION TESTS
// Tests the full VPP graph pipeline: parse → decrypt → classify → scatter.
// Uses a heap-allocated Vec<u8> as mock UMEM to avoid kernel dependencies.

use m13_hub::engine::protocol::*;
use m13_hub::engine::runtime::FixedSlab;
use m13_hub::network::*;
use m13_hub::network::datapath;

const MOCK_FRAME_SIZE: u32 = 4096;
const MOCK_FRAMES: usize = 64;

/// Run a test body on a thread with 32 MB stack.
/// PeerTable::new() alone exceeds the default 8 MB test-thread stack in debug mode
/// (256 × Scheduler + JitterBuffer + Assembler + ... > 8 MB).
fn run_with_large_stack<F: FnOnce() + Send + 'static>(f: F) {
    const STACK_SIZE: usize = 32 * 1024 * 1024;
    let handle = std::thread::Builder::new()
        .stack_size(STACK_SIZE)
        .spawn(f)
        .expect("Failed to spawn test thread with large stack");
    handle.join().expect("Test thread panicked");
}

/// Allocate a mock UMEM region on the heap (no hugepages needed for tests).
fn mock_umem() -> Vec<u8> {
    vec![0u8; MOCK_FRAME_SIZE as usize * MOCK_FRAMES]
}

/// Build a minimal valid L2 M13 frame at the given UMEM offset.
/// Returns (addr, len) descriptor pair.
fn build_l2_m13_packet(umem: &mut [u8], frame_idx: usize, flags: u8) -> (u64, u32) {
    let addr = frame_idx as u64 * MOCK_FRAME_SIZE as u64;
    let buf = &mut umem[addr as usize..addr as usize + MOCK_FRAME_SIZE as usize];

    // Ethernet header (14 bytes)
    buf[0..6].copy_from_slice(&[0xFF; 6]);                // dst MAC (broadcast)
    buf[6..12].copy_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]); // src MAC
    let ethertype = ETH_P_M13.to_be();
    buf[12..14].copy_from_slice(&ethertype.to_ne_bytes());

    // M13 header (48 bytes) starts at offset 14
    let m13_off = ETH_HDR_SIZE;
    buf[m13_off]     = M13_WIRE_MAGIC;     // signature[0]
    buf[m13_off + 1] = M13_WIRE_VERSION;   // signature[1]
    // seq_id at offset 32..40
    buf[m13_off + 32..m13_off + 40].copy_from_slice(&1u64.to_le_bytes());
    // flags at offset 40
    buf[m13_off + 40] = flags;
    // direction at offset 41
    buf[m13_off + 41] = DIR_HUB_TO_NODE;

    let frame_len = ETH_HDR_SIZE + M13_HDR_SIZE + 64; // 14 + 48 + 64 payload
    (addr, frame_len as u32)
}

/// Build a truncated frame (too short to contain M13 header).
fn build_runt_packet(umem: &mut [u8], frame_idx: usize) -> (u64, u32) {
    let addr = frame_idx as u64 * MOCK_FRAME_SIZE as u64;
    let buf = &mut umem[addr as usize..addr as usize + 20];
    buf.fill(0xDE);
    (addr, 20)
}

/// Build a frame with wrong magic byte.
fn build_bad_magic_packet(umem: &mut [u8], frame_idx: usize) -> (u64, u32) {
    let addr = frame_idx as u64 * MOCK_FRAME_SIZE as u64;
    let buf = &mut umem[addr as usize..addr as usize + MOCK_FRAME_SIZE as usize];
    // Valid Ethernet header
    buf[0..6].copy_from_slice(&[0xFF; 6]);
    buf[6..12].copy_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    let ethertype = ETH_P_M13.to_be();
    buf[12..14].copy_from_slice(&ethertype.to_ne_bytes());
    // Wrong magic
    buf[ETH_HDR_SIZE]     = 0x00; // BAD: should be M13_WIRE_MAGIC
    buf[ETH_HDR_SIZE + 1] = M13_WIRE_VERSION;
    let frame_len = ETH_HDR_SIZE + M13_HDR_SIZE + 32;
    (addr, frame_len as u32)
}

/// The peer MAC used by all encrypted frame tests.
const PEER_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];

/// Build an AEAD-encrypted L2 M13 frame at the given UMEM offset.
/// Mirrors the node's build_m13_frame + seal_frame sequence exactly:
///   1. Ethernet header: dst(broadcast) + src(PEER_MAC) + EtherType(0x88B5 BE)
///   2. M13 header: magic(0xD1) + version(0x01) + seq_id(LE) + flags + direction
///   3. Payload: known pattern (0..payload_len) XOR 0xAA
///   4. seal_frame: encrypts [m13_off+32..], sets crypto_ver=0x01, writes nonce+tag
///
/// Returns (addr, total_frame_len, original_payload) for verification after decrypt.
fn build_encrypted_l2_frame(
    umem: &mut [u8],
    frame_idx: usize,
    seq: u64,
    flags: u8,
    key: &ring::aead::LessSafeKey,
    payload_len: usize,
) -> (u64, u32, Vec<u8>) {
    let addr = frame_idx as u64 * MOCK_FRAME_SIZE as u64;
    let m13_off = ETH_HDR_SIZE;
    // Total: ETH(14) + M13(48) + payload
    // Note: AEAD tag is stored INSIDE the M13 header (signature[4..20]),
    // not appended after the payload. seal_in_place_separate_tag encrypts
    // the region [m13_off+32..] in-place and returns the tag separately.
    let total_len = m13_off + M13_HDR_SIZE + payload_len;
    assert!(total_len <= MOCK_FRAME_SIZE as usize, "frame exceeds UMEM slot");
    let buf = &mut umem[addr as usize..addr as usize + total_len];
    buf.fill(0);

    // Ethernet header — identical to node's build_m13_frame
    buf[0..6].copy_from_slice(&[0xFF; 6]);       // dst MAC (broadcast)
    buf[6..12].copy_from_slice(&PEER_MAC);        // src MAC
    buf[12] = (ETH_P_M13 >> 8) as u8;            // EtherType big-endian
    buf[13] = (ETH_P_M13 & 0xFF) as u8;

    // M13 header — identical to node's build_m13_frame
    buf[m13_off]     = M13_WIRE_MAGIC;
    buf[m13_off + 1] = M13_WIRE_VERSION;
    // signature[2] will be set to 0x01 by seal_frame (crypto_ver marker)
    buf[m13_off + 32..m13_off + 40].copy_from_slice(&seq.to_le_bytes());
    buf[m13_off + 40] = flags;

    // Payload — known pattern for post-decrypt verification
    let payload_start = m13_off + M13_HDR_SIZE;
    for i in 0..payload_len {
        buf[payload_start + i] = (i as u8) ^ 0xAA;
    }
    let original_payload: Vec<u8> = buf[payload_start..payload_start + payload_len].to_vec();

    // Seal — encrypts in-place, sets crypto_ver=0x01, writes nonce+tag
    m13_hub::cryptography::aead::seal_frame(buf, key, seq, DIR_NODE_TO_HUB, m13_off);

    // Verify seal set crypto_ver (sanity)
    assert_eq!(buf[m13_off + 2], 0x01, "seal_frame must set crypto_ver = 0x01");

    (addr, total_len as u32, original_payload)
}

/// Create a minimal GraphCtx for testing (no TUN, no real engine).
fn make_test_ctx<'a>(
    peers: &'a mut PeerTable,
    slab: &'a mut FixedSlab,
    scheduler: &'a mut Scheduler,
    rx_state: &'a mut ReceiverState,
    rx_bitmap: &'a mut RxBitmap,
    ip_id: &'a mut u16,
    umem: &'a mut Vec<u8>,
    hexdump: &'a mut m13_hub::engine::runtime::HexdumpState,
    cal: m13_hub::engine::runtime::TscCal,
) -> GraphCtx<'a> {
    GraphCtx {
        peers,
        slab,
        scheduler,
        rx_state,
        rx_bitmap,
        tun_fd: -1,
        src_mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
        gateway_mac: [0xFF; 6],
        hub_ip: [10, 13, 0, 1],
        hub_port: 443,
        ip_id_counter: ip_id,
        worker_idx: 0,
        closing: false,
        now_ns: 1_000_000_000,
        umem_base: umem.as_mut_ptr(),
        frame_size: MOCK_FRAME_SIZE,
        tx_tun_prod: None,
        rx_tun_cons: None,
        free_to_tun_prod: None,
        free_to_dp_cons: None,
        hexdump,
        cal,
        // V4: PQC offload + EDT pacer (not used in unit tests)
        pqc_req_tx: None,
        pqc_resp_rx: None,
        payload_arena: std::ptr::null_mut(),
        pacer: None,
    }
}

/// Helper: create a PacketDesc with specific flags (uses EMPTY + field overrides).
fn desc_with_flags(flags: u8) -> PacketDesc {
    let mut d = PacketDesc::EMPTY;
    d.addr = 0;
    d.len = 100;
    d.m13_offset = 14;
    d.flags = flags;
    d.peer_idx = 0;
    d.seq_id = 0;
    d.payload_len = 52;
    d
}

// ============================================================================
// TEST 1: Valid L2 M13 packet → parse → classify → scatter → TunWrite bin
// ============================================================================

#[test]
fn pipeline_valid_tunnel_packet_reaches_tun_write() { run_with_large_stack(|| {
    let mut umem = mock_umem();
    let (addr, len) = build_l2_m13_packet(&mut umem, 0, FLAG_TUNNEL);
    let descs = [(addr, len)];

    let mut peers = PeerTable::new(1_000_000_000);
    let mut slab = FixedSlab::new(MOCK_FRAMES);
    let mut scheduler = Scheduler::new();
    let mut rx_state = ReceiverState::new();
    let mut rx_bitmap = RxBitmap::new();
    let mut ip_id: u16 = 0;
    let mut hexdump = m13_hub::engine::runtime::HexdumpState::new(false);
    let cal = m13_hub::engine::runtime::TscCal::fallback();
    let mut ctx = make_test_ctx(
        &mut peers, &mut slab, &mut scheduler,
        &mut rx_state, &mut rx_bitmap, &mut ip_id, &mut umem,
        &mut hexdump, cal,
    );

    // Parse
    let mut decrypt_vec = PacketVector::new();
    let mut cleartext_vec = PacketVector::new();
    let mut stats = CycleStats::default();
    datapath::rx_parse_raw(&descs, &mut decrypt_vec, &mut cleartext_vec, &mut ctx, &mut stats);

    let total_parsed = decrypt_vec.len + cleartext_vec.len;
    assert!(total_parsed > 0, "rx_parse_raw should parse at least one packet, got 0");
    assert_eq!(stats.parsed, 1, "Should have parsed exactly 1 packet");

    // Build combined vector for classify, simulating post-decrypt flag recovery
    let mut all_packets = PacketVector::new();
    for i in 0..cleartext_vec.len {
        all_packets.push(cleartext_vec.descs[i]);
    }
    for i in 0..decrypt_vec.len {
        let mut desc = decrypt_vec.descs[i];
        desc.flags = FLAG_TUNNEL; // Simulate post-decrypt flag recovery
        all_packets.push(desc);
    }

    let mut disp = Disposition::new();
    datapath::classify_route(&all_packets, &mut disp, &mut stats, false);

    // Scatter
    let mut dec_out = PacketVector::new();
    let mut cls_out = PacketVector::new();
    let mut tun_out = PacketVector::new();
    let mut enc_out = PacketVector::new();
    let mut tx_out = PacketVector::new();
    let mut hs_out = PacketVector::new();
    let mut fb_out = PacketVector::new();
    let mut drop_out = PacketVector::new();
    let mut echo_out = PacketVector::new();
    scatter(
        &all_packets, &disp,
        &mut dec_out, &mut cls_out,
        &mut tun_out, &mut enc_out,
        &mut tx_out, &mut hs_out,
        &mut fb_out, &mut drop_out,
        &mut echo_out,
    );

    assert_eq!(tun_out.len, 1, "FLAG_TUNNEL packet should end up in TunWrite bin");
    assert_eq!(drop_out.len, 0, "Valid packet should not be dropped");
})}

// ============================================================================
// TEST 2: Malformed packets → parse → Drop
// ============================================================================

#[test]
fn pipeline_runt_packet_dropped() { run_with_large_stack(|| {
    let mut umem = mock_umem();
    let (addr, len) = build_runt_packet(&mut umem, 0);
    let descs = [(addr, len)];

    let mut peers = PeerTable::new(1_000_000_000);
    let mut slab = FixedSlab::new(MOCK_FRAMES);
    let mut scheduler = Scheduler::new();
    let mut rx_state = ReceiverState::new();
    let mut rx_bitmap = RxBitmap::new();
    let mut ip_id: u16 = 0;
    let mut hexdump = m13_hub::engine::runtime::HexdumpState::new(false);
    let cal = m13_hub::engine::runtime::TscCal::fallback();
    let mut ctx = make_test_ctx(
        &mut peers, &mut slab, &mut scheduler,
        &mut rx_state, &mut rx_bitmap, &mut ip_id, &mut umem,
        &mut hexdump, cal,
    );

    let mut decrypt_vec = PacketVector::new();
    let mut cleartext_vec = PacketVector::new();
    let mut stats = CycleStats::default();
    datapath::rx_parse_raw(&descs, &mut decrypt_vec, &mut cleartext_vec, &mut ctx, &mut stats);

    assert_eq!(decrypt_vec.len, 0, "Runt packet should not parse into decrypt vector");
    assert_eq!(cleartext_vec.len, 0, "Runt packet should not parse into cleartext vector");
    assert_eq!(stats.drops, 1, "Runt packet should count as dropped");
})}

#[test]
fn pipeline_bad_magic_dropped() { run_with_large_stack(|| {
    let mut umem = mock_umem();
    let (addr, len) = build_bad_magic_packet(&mut umem, 0);
    let descs = [(addr, len)];

    let mut peers = PeerTable::new(1_000_000_000);
    let mut slab = FixedSlab::new(MOCK_FRAMES);
    let mut scheduler = Scheduler::new();
    let mut rx_state = ReceiverState::new();
    let mut rx_bitmap = RxBitmap::new();
    let mut ip_id: u16 = 0;
    let mut hexdump = m13_hub::engine::runtime::HexdumpState::new(false);
    let cal = m13_hub::engine::runtime::TscCal::fallback();
    let mut ctx = make_test_ctx(
        &mut peers, &mut slab, &mut scheduler,
        &mut rx_state, &mut rx_bitmap, &mut ip_id, &mut umem,
        &mut hexdump, cal,
    );

    let mut decrypt_vec = PacketVector::new();
    let mut cleartext_vec = PacketVector::new();
    let mut stats = CycleStats::default();
    datapath::rx_parse_raw(&descs, &mut decrypt_vec, &mut cleartext_vec, &mut ctx, &mut stats);

    assert_eq!(decrypt_vec.len, 0, "Bad magic packet should not parse");
    assert_eq!(cleartext_vec.len, 0, "Bad magic packet should not parse");
    assert_eq!(stats.drops, 1, "Bad magic should count as dropped");
})}

// ============================================================================
// TEST 3: classify_route flag routing
// ============================================================================

#[test]
fn classify_routes_all_flag_types_correctly() {
    let test_cases: &[(u8, NextNode, &str)] = &[
        (FLAG_TUNNEL,    NextNode::TunWrite,   "FLAG_TUNNEL → TunWrite"),
        (FLAG_FEEDBACK,  NextNode::Feedback,   "FLAG_FEEDBACK → Feedback"),
        (FLAG_FRAGMENT,  NextNode::Handshake,  "FLAG_FRAGMENT → Handshake"),
        (FLAG_HANDSHAKE, NextNode::Handshake,  "FLAG_HANDSHAKE → Handshake"),
        (FLAG_CONTROL,   NextNode::Consumed,   "FLAG_CONTROL → Consumed"),
        (FLAG_FIN,       NextNode::Consumed,   "FLAG_FIN → Consumed"),
        (0x00,           NextNode::TxEnqueue,  "no flags → TxEnqueue (data forward)"),
    ];

    for &(flags, expected_next, label) in test_cases {
        let mut pv = PacketVector::new();
        pv.push(desc_with_flags(flags));

        let mut disp = Disposition::new();
        let mut stats = CycleStats::default();
        datapath::classify_route(&pv, &mut disp, &mut stats, false);

        assert_eq!(disp.next[0], expected_next, "FAIL: {}", label);
    }
}

// ============================================================================
// TEST 4: scatter distributes to correct output bins
// ============================================================================

#[test]
fn scatter_distributes_to_correct_bins() {
    let mut pv = PacketVector::new();
    let routes = [
        NextNode::TunWrite,
        NextNode::Feedback,
        NextNode::Handshake,
        NextNode::TxEnqueue,
    ];

    let mut disp = Disposition::new();
    for (i, next) in routes.iter().enumerate() {
        let mut d = PacketDesc::EMPTY;
        d.addr = (i as u64) * MOCK_FRAME_SIZE as u64;
        d.len = 100;
        pv.push(d);
        disp.next[i] = *next;
    }

    let mut dec = PacketVector::new();
    let mut cls = PacketVector::new();
    let mut tun = PacketVector::new();
    let mut enc = PacketVector::new();
    let mut tx  = PacketVector::new();
    let mut hs  = PacketVector::new();
    let mut fb  = PacketVector::new();
    let mut drp = PacketVector::new();
    let mut echo = PacketVector::new();
    scatter(
        &pv, &disp,
        &mut dec, &mut cls, &mut tun, &mut enc,
        &mut tx, &mut hs, &mut fb, &mut drp,
        &mut echo,
    );

    assert_eq!(tun.len, 1, "TunWrite packet should be in tun bin");
    assert_eq!(fb.len,  1, "Feedback packet should be in fb bin");
    assert_eq!(hs.len,  1, "Handshake packet should be in hs bin");
    assert_eq!(tx.len,  1, "TxEnqueue packet should be in tx bin");
    assert_eq!(drp.len, 0, "No packets should be dropped");
}

// ============================================================================
// TEST 5: AEAD seal → open round-trip
// ============================================================================

#[test]
fn aead_seal_open_roundtrip() {
    use ring::aead::{UnboundKey, LessSafeKey, AES_256_GCM};

    let key_bytes = [0x42u8; 32];
    let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &key_bytes).unwrap());

    // Build frame: ETH(14) + M13(48) + payload(64) → need tag space too
    let m13_off = 14usize;
    let payload_len = 64;
    let mut frame = vec![0u8; m13_off + M13_HDR_SIZE + payload_len + 16];

    // Set M13 header
    frame[m13_off]     = M13_WIRE_MAGIC;
    frame[m13_off + 1] = M13_WIRE_VERSION;
    frame[m13_off + 32..m13_off + 40].copy_from_slice(&42u64.to_le_bytes());
    frame[m13_off + 40] = FLAG_TUNNEL;
    frame[m13_off + 41] = DIR_HUB_TO_NODE;

    // Fill payload with known pattern
    let payload_start = m13_off + M13_HDR_SIZE;
    for i in 0..payload_len {
        frame[payload_start + i] = (i & 0xFF) as u8;
    }
    let original_payload: Vec<u8> = frame[payload_start..payload_start + payload_len].to_vec();

    // Seal (encrypt in place) — returns (), panics on failure
    m13_hub::cryptography::aead::seal_frame(&mut frame, &key, 42, DIR_HUB_TO_NODE, m13_off);

    // Payload should now be ciphertext
    assert_ne!(&frame[payload_start..payload_start + payload_len], &original_payload[..],
        "After seal, payload should be encrypted (different from plaintext)");

    // Open (decrypt in place) — direction guard: open expects opposite direction
    // seal used DIR_HUB_TO_NODE, so open must use the opposite direction to pass reflection guard
    let opened = m13_hub::cryptography::aead::open_frame(&mut frame, &key, DIR_NODE_TO_HUB, m13_off);
    assert!(opened, "open_frame should succeed with correct key and opposite direction");

    // Payload should match original
    assert_eq!(&frame[payload_start..payload_start + payload_len], &original_payload[..],
        "After open, payload should match original plaintext");
}

// ============================================================================
// TEST 6: AEAD wrong key rejected
// ============================================================================

#[test]
fn aead_wrong_key_rejected() {
    use ring::aead::{UnboundKey, LessSafeKey, AES_256_GCM};

    let key1 = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &[0x42u8; 32]).unwrap());
    let key2 = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &[0x99u8; 32]).unwrap());

    let m13_off = 14usize;
    let mut frame = vec![0u8; m13_off + M13_HDR_SIZE + 64 + 16];
    frame[m13_off] = M13_WIRE_MAGIC;
    frame[m13_off + 1] = M13_WIRE_VERSION;
    frame[m13_off + 41] = DIR_HUB_TO_NODE;

    // Seal with key1
    m13_hub::cryptography::aead::seal_frame(&mut frame, &key1, 1, DIR_HUB_TO_NODE, m13_off);

    // Try to open with key2 — must fail
    let opened = m13_hub::cryptography::aead::open_frame(&mut frame, &key2, DIR_NODE_TO_HUB, m13_off);
    assert!(!opened, "open_frame with wrong key should fail");
}

// ============================================================================
// TEST 7: Batch parse — multiple packets in one rx batch
// ============================================================================

#[test]
fn pipeline_batch_parse_multiple_packets() { run_with_large_stack(|| {
    let mut umem = mock_umem();

    let d0 = build_l2_m13_packet(&mut umem, 0, FLAG_TUNNEL);
    let d1 = build_l2_m13_packet(&mut umem, 1, FLAG_HANDSHAKE);
    let d2 = build_runt_packet(&mut umem, 2); // should drop
    let descs = [d0, d1, d2];

    let mut peers = PeerTable::new(1_000_000_000);
    let mut slab = FixedSlab::new(MOCK_FRAMES);
    let mut scheduler = Scheduler::new();
    let mut rx_state = ReceiverState::new();
    let mut rx_bitmap = RxBitmap::new();
    let mut ip_id: u16 = 0;
    let mut hexdump = m13_hub::engine::runtime::HexdumpState::new(false);
    let cal = m13_hub::engine::runtime::TscCal::fallback();
    let mut ctx = make_test_ctx(
        &mut peers, &mut slab, &mut scheduler,
        &mut rx_state, &mut rx_bitmap, &mut ip_id, &mut umem,
        &mut hexdump, cal,
    );

    let mut decrypt_vec = PacketVector::new();
    let mut cleartext_vec = PacketVector::new();
    let mut stats = CycleStats::default();
    datapath::rx_parse_raw(&descs, &mut decrypt_vec, &mut cleartext_vec, &mut ctx, &mut stats);

    let total_parsed = decrypt_vec.len + cleartext_vec.len;
    assert_eq!(total_parsed, 2, "Should parse 2 valid packets out of 3");
    assert_eq!(stats.drops, 1, "Runt packet should be dropped");
    assert_eq!(stats.parsed, 2, "2 packets should register as parsed");
})}

// ============================================================================
// TEST 8: AEAD reflection attack blocked
// ============================================================================

#[test]
fn aead_reflection_attack_blocked() {
    use ring::aead::{UnboundKey, LessSafeKey, AES_256_GCM};

    let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &[0x42u8; 32]).unwrap());
    let m13_off = 14usize;
    let mut frame = vec![0u8; m13_off + M13_HDR_SIZE + 64 + 16];
    frame[m13_off] = M13_WIRE_MAGIC;
    frame[m13_off + 1] = M13_WIRE_VERSION;
    frame[m13_off + 41] = DIR_HUB_TO_NODE;

    // Seal with DIR_HUB_TO_NODE
    m13_hub::cryptography::aead::seal_frame(&mut frame, &key, 1, DIR_HUB_TO_NODE, m13_off);

    // Try to open with SAME direction (reflection) — must be blocked
    let opened = m13_hub::cryptography::aead::open_frame(&mut frame, &key, DIR_HUB_TO_NODE, m13_off);
    assert!(!opened, "Reflection attack (same direction) should be rejected");
}

// ############################################################################
// CROSS-PATH CORRECTNESS: NODE → HUB and HUB → NODE
// ############################################################################

// ============================================================================
// TEST 9: Wire format — both sides agree on header sizes
// ============================================================================

#[test]
fn cross_path_header_sizes_match() {
    // Hub side
    assert_eq!(ETH_HDR_SIZE, 14, "EthernetHeader must be 14 bytes");
    assert_eq!(M13_HDR_SIZE, 48, "M13Header must be 48 bytes");

    // Verify M13Header field offsets by building from raw bytes and reading via struct.
    // The node writes: frame[14]=magic, frame[15]=version, frame[46..54]=seq_id(LE), frame[54]=flags
    // This means: within M13Header, seq_id is at byte 32 (signature[32] fills 0..32)
    // and flags is at byte 40 (seq_id is 8 bytes → 32+8=40).
    let mut raw = [0u8; 48]; // Exactly one M13Header
    raw[0] = M13_WIRE_MAGIC;
    raw[1] = M13_WIRE_VERSION;
    raw[32..40].copy_from_slice(&0xDEADBEEFCAFEu64.to_le_bytes());
    raw[40] = FLAG_TUNNEL;

    // Interpret via bytemuck (same as Hub datapath does)
    // Copy the struct to avoid unaligned field access on repr(C, packed)
    let hdr: M13Header = *bytemuck::from_bytes(&raw);
    assert_eq!(hdr.signature[0], M13_WIRE_MAGIC, "magic via struct must match raw[0]");
    assert_eq!(hdr.signature[1], M13_WIRE_VERSION, "version via struct must match raw[1]");
    // Extract multi-byte fields to avoid unaligned references in assert_eq! macro
    let seq = hdr.seq_id;
    let flags = hdr.flags;
    assert_eq!(seq, 0xDEADBEEFCAFE, "seq_id via struct must match LE bytes at [32..40]");
    assert_eq!(flags, FLAG_TUNNEL, "flags via struct must match raw[40]");
}

// ============================================================================
// TEST 10: EtherType endianness — node writes big-endian 0x88B5
// ============================================================================

#[test]
fn cross_path_ethertype_endianness() {
    // The node writes EtherType as:
    //   frame[12] = (ETH_P_M13 >> 8) as u8;  // 0x88
    //   frame[13] = (ETH_P_M13 & 0xFF) as u8; // 0xB5
    // This is big-endian (network byte order).
    let hi = (ETH_P_M13 >> 8) as u8;
    let lo = (ETH_P_M13 & 0xFF) as u8;
    assert_eq!(hi, 0x88, "EtherType high byte");
    assert_eq!(lo, 0xB5, "EtherType low byte");

    // Hub reads with: u16::from_be(*(frame_ptr.add(12) as *const u16))
    // Simulate that:
    let wire = [hi, lo];
    let read_back = u16::from_be(u16::from_ne_bytes(wire));
    assert_eq!(read_back, ETH_P_M13, "Hub must read 0x88B5 from big-endian wire format");
}

// ============================================================================
// TEST 11: Node → Hub: build_m13_frame matches Hub's parser offsets + routing
// ============================================================================

/// Simulates what the node does (build_m13_frame) and verifies the hub can
/// read all fields at the expected offsets. Then verifies crypto_ver routing:
/// cleartext (crypto_ver=0x00) → cleartext_out, encrypted (crypto_ver=0x01) → decrypt_out.
#[test]
fn cross_path_node_frame_matches_hub_parser() { run_with_large_stack(|| {
    let src_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    let dst_mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
    let seq: u64 = 12345;
    let flags = FLAG_TUNNEL;

    // This is exactly what the node does:
    let mut frame = [0u8; 62];
    frame[0..6].copy_from_slice(&dst_mac);
    frame[6..12].copy_from_slice(&src_mac);
    frame[12] = (ETH_P_M13 >> 8) as u8;
    frame[13] = (ETH_P_M13 & 0xFF) as u8;
    frame[14] = M13_WIRE_MAGIC;
    frame[15] = M13_WIRE_VERSION;
    frame[46..54].copy_from_slice(&seq.to_le_bytes());
    frame[54] = flags;

    // Verify hub reads the same offsets:
    let hub_ethertype = u16::from_be(u16::from_ne_bytes([frame[12], frame[13]]));
    assert_eq!(hub_ethertype, ETH_P_M13, "Hub must read correct EtherType");
    assert_eq!(frame[ETH_HDR_SIZE], M13_WIRE_MAGIC, "Hub reads magic at offset 14");
    assert_eq!(frame[ETH_HDR_SIZE + 1], M13_WIRE_VERSION, "Hub reads version at offset 15");
    let hub_seq = u64::from_le_bytes(frame[46..54].try_into().unwrap());
    assert_eq!(hub_seq, seq, "Hub reads seq_id from [46..54] LE");
    assert_eq!(frame[54], flags, "Hub reads flags from abs offset 54");
    assert_eq!(&frame[6..12], &src_mac, "Hub reads peer src MAC at [6..12]");

    // --- Behavioral: crypto_ver routing split through rx_parse_raw ---
    // Build two frames in UMEM: one cleartext (crypto_ver=0), one encrypted marker (crypto_ver=1).
    // Feed both through rx_parse_raw and verify they land in different output vectors.
    let mut umem = mock_umem();

    // Frame 0: cleartext (crypto_ver = 0x00, the default)
    let (addr0, len0) = build_l2_m13_packet(&mut umem, 0, FLAG_TUNNEL);
    // Verify crypto_ver is 0x00 (cleartext)
    let cv0 = umem[addr0 as usize + ETH_HDR_SIZE + 2];
    assert_eq!(cv0, 0x00, "Default frame must have crypto_ver = 0x00");

    // Frame 1: set crypto_ver = 0x01 to simulate encrypted frame
    let (addr1, len1) = build_l2_m13_packet(&mut umem, 1, FLAG_TUNNEL);
    umem[addr1 as usize + ETH_HDR_SIZE + 2] = 0x01; // mark as encrypted

    let descs = [(addr0, len0), (addr1, len1)];
    let mut peers = PeerTable::new(1_000_000_000);
    let mut slab = FixedSlab::new(MOCK_FRAMES);
    let mut scheduler = Scheduler::new();
    let mut rx_state = ReceiverState::new();
    let mut rx_bitmap = RxBitmap::new();
    let mut ip_id: u16 = 0;
    let mut hexdump = m13_hub::engine::runtime::HexdumpState::new(false);
    let cal = m13_hub::engine::runtime::TscCal::fallback();
    let mut ctx = make_test_ctx(
        &mut peers, &mut slab, &mut scheduler,
        &mut rx_state, &mut rx_bitmap, &mut ip_id, &mut umem,
        &mut hexdump, cal,
    );

    let mut decrypt_vec = PacketVector::new();
    let mut cleartext_vec = PacketVector::new();
    let mut stats = CycleStats::default();
    datapath::rx_parse_raw(&descs, &mut decrypt_vec, &mut cleartext_vec, &mut ctx, &mut stats);

    assert_eq!(stats.parsed, 2, "Both frames must parse");
    assert_eq!(cleartext_vec.len, 1, "crypto_ver=0x00 frame must route to cleartext_out");
    assert_eq!(decrypt_vec.len, 1, "crypto_ver=0x01 frame must route to decrypt_out");
})}

// ============================================================================
// TEST 16: ClientHello validation — hub rejects bad messages
// ============================================================================

#[test]
fn cross_path_client_hello_rejects_short() {
    // The hub expects ClientHello = type(1) + version(1) + nonce(32) + ek(1568) + pk(2592) = 4194
    let short_hello = vec![HS_CLIENT_HELLO, 0x01, 0x00]; // way too short
    let mut seq = 0u64;
    let result = m13_hub::cryptography::handshake::process_client_hello_hub(&short_hello, &mut seq, 1000);
    assert!(result.is_none(), "Hub must reject a too-short ClientHello");
}

#[test]
fn cross_path_client_hello_rejects_wrong_type() {
    // Send the right length but wrong type byte
    let mut bad_type = vec![0u8; 4194]; // correct length
    bad_type[0] = 0xFF; // not HS_CLIENT_HELLO (0x01)
    bad_type[1] = 0x01; // correct version
    let mut seq = 0u64;
    let result = m13_hub::cryptography::handshake::process_client_hello_hub(&bad_type, &mut seq, 1000);
    assert!(result.is_none(), "Hub must reject ClientHello with wrong type byte");
}

#[test]
fn cross_path_client_hello_rejects_wrong_version() {
    let mut bad_ver = vec![0u8; 4194];
    bad_ver[0] = HS_CLIENT_HELLO;
    bad_ver[1] = 0x99; // wrong version
    let mut seq = 0u64;
    let result = m13_hub::cryptography::handshake::process_client_hello_hub(&bad_ver, &mut seq, 1000);
    assert!(result.is_none(), "Hub must reject ClientHello with unsupported version");
}

// ============================================================================
// TEST 17: AEAD direction bytes — hub and node use complementary values
// ============================================================================

#[test]
fn cross_path_aead_direction_symmetry() {
    // Hub seals with DIR_HUB_TO_NODE (0x00), node opens expecting != DIR_NODE_TO_HUB (0x01)
    // Node seals with DIR_NODE_TO_HUB (0x01), hub opens expecting != DIR_HUB_TO_NODE (0x00)
    assert_eq!(DIR_HUB_TO_NODE, 0x00, "Hub direction byte must be 0x00");
    assert_eq!(DIR_NODE_TO_HUB, 0x01, "Node direction byte must be 0x01");
    assert_ne!(DIR_HUB_TO_NODE, DIR_NODE_TO_HUB, "Direction bytes must differ");

    // Full round-trip: node seals (dir=0x01) → hub opens (our_dir=0x00) → passes reflection guard
    use ring::aead::{UnboundKey, LessSafeKey, AES_256_GCM};
    let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &[0x42u8; 32]).unwrap());
    let m13_off = 14;
    let mut frame = vec![0u8; m13_off + M13_HDR_SIZE + 64 + 16];
    frame[m13_off] = M13_WIRE_MAGIC;
    frame[m13_off + 1] = M13_WIRE_VERSION;

    // Node seals
    m13_hub::cryptography::aead::seal_frame(&mut frame, &key, 1, DIR_NODE_TO_HUB, m13_off);

    // Hub opens (our_dir = DIR_HUB_TO_NODE → nonce dir ≠ our_dir → passes)
    let ok = m13_hub::cryptography::aead::open_frame(&mut frame, &key, DIR_HUB_TO_NODE, m13_off);
    assert!(ok, "Hub must accept frame sealed by node with correct direction byte");
}

// ============================================================================
// TEST 18: FragHeader layout — hub and node agree on field positions
// ============================================================================

#[test]
fn cross_path_frag_header_layout() {
    assert_eq!(FRAG_HDR_SIZE, 8, "FragHeader must be 8 bytes");

    // Node builds frag header at (ETH_HDR_SIZE + M13_HDR_SIZE) = 62:
    //   [0..2] = msg_id (LE u16)
    //   [2]    = frag_index (u8)
    //   [3]    = frag_total (u8)
    //   [4..6] = frag_offset (LE u16)
    //   [6..8] = frag_len (LE u16)
    let mut raw = [0u8; 8];
    let msg_id: u16 = 0x1234;
    let index: u8 = 2;
    let total: u8 = 5;
    let offset: u16 = 2888; // 2 * 1444
    let chunk_len: u16 = 512;

    raw[0..2].copy_from_slice(&msg_id.to_le_bytes());
    raw[2] = index;
    raw[3] = total;
    raw[4..6].copy_from_slice(&offset.to_le_bytes());
    raw[6..8].copy_from_slice(&chunk_len.to_le_bytes());

    // Hub reads via FragHeader struct (repr(C, packed))
    // Use read_unaligned to avoid unaligned reference errors on packed struct
    let hdr: FragHeader = unsafe { std::ptr::read_unaligned(raw.as_ptr() as *const FragHeader) };
    // Extract multi-byte fields to local vars — assert_eq! borrows, creating unaligned refs
    let mid = hdr.frag_msg_id;
    let idx = hdr.frag_index;
    let tot = hdr.frag_total;
    let off = hdr.frag_offset;
    let clen = hdr.frag_len;
    assert_eq!(mid, msg_id, "Hub reads msg_id at [0..2] LE");
    assert_eq!(idx, index, "Hub reads index at [2]");
    assert_eq!(tot, total, "Hub reads total at [3]");
    assert_eq!(off, offset, "Hub reads offset at [4..6] LE");
    assert_eq!(clen, chunk_len, "Hub reads len at [6..8] LE");
}

// ============================================================================
// TEST 19: Feedback frame wire size — behavioral (construct and measure)
// ============================================================================

#[test]
fn cross_path_feedback_frame_size() {
    // Verify by construction: the formula ETH + M13 + sizeof(FeedbackFrame) is consistent.
    // This catches any silent struct padding changes that would break wire compatibility.
    let eth = std::mem::size_of::<EthernetHeader>();
    let m13 = std::mem::size_of::<M13Header>();
    let fb  = std::mem::size_of::<FeedbackFrame>();
    let computed = (eth + m13 + fb) as u32;
    assert_eq!(computed, FEEDBACK_FRAME_LEN,
        "FEEDBACK_FRAME_LEN must equal sizeof(EthernetHeader)+sizeof(M13Header)+sizeof(FeedbackFrame)");
    // Cross-check absolute value to catch if ALL three structs change in a coordinated way
    assert_eq!(computed, 102, "Feedback frame total wire size must be 102 bytes");
}

// ############################################################################
// TEST 20: FULL PQC HANDSHAKE ROUND-TRIP: ClientHello → ServerHello → Finished
// ############################################################################

/// Full 3-message PQC handshake round-trip.
/// This test inlines the node-side logic (zero-share architecture: node crate is
/// not a dependency of hub). Proves both sides derive the same 32-byte session key.
///
/// Flow:
///   1. "Node" generates ML-KEM-1024 keypair + ML-DSA-87 keypair → builds ClientHello
///   2. Hub's process_client_hello_hub() → encapsulates ss, signs transcript → ServerHello
///   3. "Node" decapsulates ss, verifies hub sig, derives key, signs → Finished
///   4. Hub's process_finished_hub() → verifies node sig, derives key
///   5. Assert: node_key == hub_key
#[test]
fn handshake_full_round_trip() {
    use sha2::{Sha512, Digest};
    use hkdf::Hkdf;
    use rand::rngs::OsRng;
    use ml_kem::{MlKem1024, KemCore, EncodedSizeUser};
    use ml_kem::kem::Decapsulate;
    use ml_dsa::{MlDsa87, KeyGen};

    // Must match hub's private constants exactly
    const PQC_CONTEXT: &[u8] = b"M13-HS-v1";
    const PQC_INFO: &[u8] = b"M13-PQC-SESSION-KEY-v1";

    // ── Step 1: Node builds ClientHello ──────────────────────────────────
    let (dk, ek) = MlKem1024::generate(&mut OsRng);
    let ek_bytes = ek.as_bytes();

    let dsa_kp = MlDsa87::key_gen(&mut OsRng);
    let pk_dsa = dsa_kp.verifying_key().encode();
    let sk_dsa = dsa_kp.signing_key().encode();

    let mut session_nonce = [0u8; 32];
    use rand::RngCore;
    OsRng.fill_bytes(&mut session_nonce);

    let mut client_hello = Vec::with_capacity(1 + 1 + 32 + ek_bytes.len() + pk_dsa.len());
    client_hello.push(HS_CLIENT_HELLO);
    client_hello.push(0x01); // version
    client_hello.extend_from_slice(&session_nonce);
    client_hello.extend_from_slice(&ek_bytes);
    client_hello.extend_from_slice(&pk_dsa);

    assert_eq!(client_hello.len(), 4194,
        "ClientHello must be type(1)+ver(1)+nonce(32)+ek(1568)+pk(2592) = 4194 bytes");

    // ── Step 2: Hub processes ClientHello → returns ServerHello ──────────
    let mut hub_seq = 0u64;
    let now = 1_000_000_000u64;
    let (hs_state, server_hello) = m13_hub::cryptography::handshake::process_client_hello_hub(
        &client_hello, &mut hub_seq, now,
    ).expect("Hub must accept a valid ClientHello");

    assert_eq!(server_hello[0], HS_SERVER_HELLO, "ServerHello type byte must be 0x02");
    assert_eq!(server_hello.len(), 8788,
        "ServerHello must be type(1)+ct(1568)+pk(2592)+sig(4627) = 8788 bytes");

    // ── Step 3: Node processes ServerHello → derives key + builds Finished ─
    // (Inlined node logic — cannot import node crate)

    let ct_bytes = &server_hello[1..1569];
    let pk_hub_bytes = &server_hello[1569..4161];
    let sig_hub_bytes = &server_hello[4161..8788];

    // Decapsulate shared secret
    let dk_bytes = dk.as_bytes().to_vec();
    let dk_encoded = ml_kem::Encoded::<ml_kem::kem::DecapsulationKey<ml_kem::MlKem1024Params>>::try_from(
        dk_bytes.as_slice()
    ).expect("DecapsulationKey parse must succeed");
    let dk_restored = ml_kem::kem::DecapsulationKey::<ml_kem::MlKem1024Params>::from_bytes(&dk_encoded);

    let ct = ml_kem::Ciphertext::<MlKem1024>::try_from(ct_bytes)
        .expect("ML-KEM ciphertext parse must succeed");
    let ss = dk_restored.decapsulate(&ct)
        .expect("ML-KEM decapsulation must succeed");

    // Verify hub's signature: transcript = SHA-512(ClientHello || ct)
    let mut hasher = Sha512::new();
    hasher.update(&client_hello);
    hasher.update(ct_bytes);
    let transcript: [u8; 64] = hasher.finalize().into();

    let pk_hub_enc = ml_dsa::EncodedVerifyingKey::<MlDsa87>::try_from(pk_hub_bytes)
        .expect("Hub verifying key parse must succeed");
    let pk_hub = ml_dsa::VerifyingKey::<MlDsa87>::decode(&pk_hub_enc);

    let sig_hub = ml_dsa::Signature::<MlDsa87>::try_from(sig_hub_bytes)
        .expect("Hub signature parse must succeed");
    assert!(pk_hub.verify_with_context(&transcript, PQC_CONTEXT, &sig_hub),
        "Hub ML-DSA-87 signature must verify");

    // Node derives session key
    let hk_node = Hkdf::<Sha512>::new(Some(&session_nonce), &ss);
    let mut node_session_key = [0u8; 32];
    hk_node.expand(PQC_INFO, &mut node_session_key)
        .expect("HKDF expand must succeed");

    // Node signs Finished: transcript2 = SHA-512(ClientHello || ServerHello)
    let mut hasher2 = Sha512::new();
    hasher2.update(&client_hello);
    hasher2.update(&server_hello);
    let transcript2: [u8; 64] = hasher2.finalize().into();

    let sk_enc = ml_dsa::EncodedSigningKey::<MlDsa87>::try_from(sk_dsa.as_slice())
        .expect("Node signing key reconstruct must succeed");
    let sk = ml_dsa::SigningKey::<MlDsa87>::decode(&sk_enc);
    let sig_node = sk.sign_deterministic(&transcript2, PQC_CONTEXT)
        .expect("Node ML-DSA signing must succeed");
    let sig_node_bytes = sig_node.encode();

    let mut finished = Vec::with_capacity(1 + sig_node_bytes.len());
    finished.push(HS_FINISHED);
    finished.extend_from_slice(&sig_node_bytes);

    assert_eq!(finished.len(), 4628,
        "Finished must be type(1)+sig(4627) = 4628 bytes");

    // ── Step 4: Hub processes Finished → derives key ────────────────────
    let hub_session_key = m13_hub::cryptography::handshake::process_finished_hub(
        &finished, &hs_state,
    ).expect("Hub must accept a valid Finished message");

    // ── Step 5: Both sides must derive the same session key ─────────────
    assert_eq!(node_session_key, hub_session_key,
        "CRITICAL: Node and Hub must derive the same 32-byte session key");

    // Bonus: verify the key is not all zeros (sanity)
    assert_ne!(hub_session_key, [0u8; 32], "Session key must not be all zeros");

    // Bonus: verify the key can be used for AEAD — seal on one side, open on other
    use ring::aead::{UnboundKey, LessSafeKey, AES_256_GCM};
    let hub_aead_key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &hub_session_key).unwrap());
    let node_aead_key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &node_session_key).unwrap());

    let m13_off = 14;
    let mut frame = vec![0u8; m13_off + M13_HDR_SIZE + 64 + 16];
    frame[m13_off] = M13_WIRE_MAGIC;
    frame[m13_off + 1] = M13_WIRE_VERSION;
    let payload_start = m13_off + M13_HDR_SIZE;
    for i in 0..64 { frame[payload_start + i] = (i as u8) ^ 0xAA; }
    let original: Vec<u8> = frame[payload_start..payload_start+64].to_vec();

    // Node encrypts with derived key
    m13_hub::cryptography::aead::seal_frame(&mut frame, &node_aead_key, 1, DIR_NODE_TO_HUB, m13_off);

    // Hub decrypts with its independently-derived key — must succeed
    let ok = m13_hub::cryptography::aead::open_frame(&mut frame, &hub_aead_key, DIR_HUB_TO_NODE, m13_off);
    assert!(ok, "Hub must decrypt frame sealed by node using independently-derived session key");
    assert_eq!(&frame[payload_start..payload_start+64], &original[..],
        "Decrypted payload must match original");
}

// ############################################################################
// ENCRYPTED PIPELINE: FULL DATAPATH TESTS
// parse → AEAD decrypt → classify → scatter (the real production path)
// ############################################################################

// ============================================================================
// TEST 21: Encrypted pipeline — correct key, full datapath
// ============================================================================

/// Build an encrypted frame exactly as the node would, then feed it through
/// the hub's full RX pipeline: rx_parse_raw → aead_decrypt_vector → classify_route → scatter.
/// Verifies: peer auto-registration, AEAD decrypt success, flag recovery, scatter routing,
/// and payload integrity after decryption.
#[test]
fn encrypted_pipeline_correct_key() { run_with_large_stack(|| {
    use ring::aead::{UnboundKey, LessSafeKey, AES_256_GCM};

    let key_bytes = [0x42u8; 32];
    let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &key_bytes).unwrap());
    let payload_len = 64;

    let mut umem = mock_umem();
    let (addr, len, original_payload) =
        build_encrypted_l2_frame(&mut umem, 0, 1, FLAG_TUNNEL, &key, payload_len);
    let descs = [(addr, len)];

    let mut peers = PeerTable::new(1_000_000_000);
    let mut slab = FixedSlab::new(MOCK_FRAMES);
    let mut scheduler = Scheduler::new();
    let mut rx_state = ReceiverState::new();
    let mut rx_bitmap = RxBitmap::new();
    let mut ip_id: u16 = 0;
    let mut hexdump = m13_hub::engine::runtime::HexdumpState::new(false);
    let cal = m13_hub::engine::runtime::TscCal::fallback();
    let mut ctx = make_test_ctx(
        &mut peers, &mut slab, &mut scheduler,
        &mut rx_state, &mut rx_bitmap, &mut ip_id, &mut umem,
        &mut hexdump, cal,
    );

    // Step 1: Parse — frame must land in decrypt_out (crypto_ver=0x01 set by seal_frame)
    let mut decrypt_vec = PacketVector::new();
    let mut cleartext_vec = PacketVector::new();
    let mut stats = CycleStats::default();
    datapath::rx_parse_raw(&descs, &mut decrypt_vec, &mut cleartext_vec, &mut ctx, &mut stats);

    assert_eq!(stats.parsed, 1, "Frame must parse");
    assert_eq!(decrypt_vec.len, 1, "Encrypted frame must route to decrypt_out");
    assert_eq!(cleartext_vec.len, 0, "Should not appear in cleartext_out");

    // rx_parse_raw auto-registered the peer via lookup_or_insert.
    // Install the AEAD cipher key for decryption.
    let peer_idx = decrypt_vec.descs[0].peer_idx as usize;
    ctx.peers.ciphers[peer_idx] =
        Some(LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &key_bytes).unwrap()));
    ctx.peers.slots[peer_idx].lifecycle = PeerLifecycle::Established;

    // Step 2: Decrypt — must succeed and recover the plaintext flags
    let mut disp = Disposition::new();
    datapath::aead_decrypt_vector(&mut decrypt_vec, &mut disp, &mut ctx, &mut stats);

    assert_eq!(stats.aead_ok, 1, "AEAD decrypt must succeed with correct key");
    assert_eq!(stats.aead_fail, 0, "No AEAD failures expected");
    // decrypt_one sets disp.next to ClassifyRoute on success
    assert_eq!(disp.next[0], NextNode::ClassifyRoute,
        "Successful decrypt must route to ClassifyRoute");
    // Verify flags were recovered from decrypted buffer
    assert_eq!(decrypt_vec.descs[0].flags, FLAG_TUNNEL,
        "Decrypted flags must match original FLAG_TUNNEL");

    // Step 3: Classify — FLAG_TUNNEL should route to TunWrite
    let mut classify_disp = Disposition::new();
    datapath::classify_route(&decrypt_vec, &mut classify_disp, &mut stats, false);
    assert_eq!(classify_disp.next[0], NextNode::TunWrite,
        "FLAG_TUNNEL packet must route to TunWrite after decrypt");

    // Step 4: Scatter — verify correct output bin
    let mut dec = PacketVector::new();
    let mut cls = PacketVector::new();
    let mut tun = PacketVector::new();
    let mut enc = PacketVector::new();
    let mut tx  = PacketVector::new();
    let mut hs  = PacketVector::new();
    let mut fb  = PacketVector::new();
    let mut drp = PacketVector::new();
    let mut echo = PacketVector::new();
    scatter(&decrypt_vec, &classify_disp,
        &mut dec, &mut cls, &mut tun, &mut enc,
        &mut tx, &mut hs, &mut fb, &mut drp,
        &mut echo);
    assert_eq!(tun.len, 1, "Decrypted tunnel packet must land in TunWrite bin");
    assert_eq!(drp.len, 0, "No packets should be dropped");

    // Step 5: Verify payload integrity — the actual bytes must match pre-encryption
    let m13_off = decrypt_vec.descs[0].m13_offset as usize;
    let payload_start = decrypt_vec.descs[0].addr as usize + m13_off + M13_HDR_SIZE;
    let decrypted_payload = &umem[payload_start..payload_start + payload_len];
    assert_eq!(decrypted_payload, &original_payload[..],
        "Decrypted payload must match original plaintext byte-for-byte");
})}

// ============================================================================
// TEST 22: Encrypted pipeline — wrong key rejection
// ============================================================================

/// Same encrypted frame as test 18, but hub has a DIFFERENT key installed.
/// Must fail AEAD authentication and route to Drop.
#[test]
fn encrypted_pipeline_wrong_key_rejected() { run_with_large_stack(|| {
    use ring::aead::{UnboundKey, LessSafeKey, AES_256_GCM};

    let node_key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &[0x42u8; 32]).unwrap());

    let mut umem = mock_umem();
    let (addr, len, _) =
        build_encrypted_l2_frame(&mut umem, 0, 1, FLAG_TUNNEL, &node_key, 64);
    let descs = [(addr, len)];

    let mut peers = PeerTable::new(1_000_000_000);
    let mut slab = FixedSlab::new(MOCK_FRAMES);
    let mut scheduler = Scheduler::new();
    let mut rx_state = ReceiverState::new();
    let mut rx_bitmap = RxBitmap::new();
    let mut ip_id: u16 = 0;
    let mut hexdump = m13_hub::engine::runtime::HexdumpState::new(false);
    let cal = m13_hub::engine::runtime::TscCal::fallback();
    let mut ctx = make_test_ctx(
        &mut peers, &mut slab, &mut scheduler,
        &mut rx_state, &mut rx_bitmap, &mut ip_id, &mut umem,
        &mut hexdump, cal,
    );

    let mut decrypt_vec = PacketVector::new();
    let mut cleartext_vec = PacketVector::new();
    let mut stats = CycleStats::default();
    datapath::rx_parse_raw(&descs, &mut decrypt_vec, &mut cleartext_vec, &mut ctx, &mut stats);
    assert_eq!(decrypt_vec.len, 1, "Frame must parse into decrypt_out");

    // Install WRONG key — different from what sealed the frame
    let peer_idx = decrypt_vec.descs[0].peer_idx as usize;
    let wrong_key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &[0x99u8; 32]).unwrap());
    ctx.peers.ciphers[peer_idx] = Some(wrong_key);
    ctx.peers.slots[peer_idx].lifecycle = PeerLifecycle::Established;

    let mut disp = Disposition::new();
    datapath::aead_decrypt_vector(&mut decrypt_vec, &mut disp, &mut ctx, &mut stats);

    assert_eq!(stats.aead_fail, 1, "AEAD must fail with wrong key");
    assert_eq!(stats.aead_ok, 0, "No successful decrypts expected");
    assert_eq!(disp.next[0], NextNode::Drop, "Wrong key must route to Drop");
})}

// ============================================================================
// TEST 23: Encrypted pipeline — no cipher installed (peer has no session key)
// ============================================================================

/// Peer is registered (lookup_or_insert succeeds) but no cipher key is set.
/// AEAD must fail and packet must be dropped.
#[test]
fn encrypted_pipeline_no_cipher_drops() { run_with_large_stack(|| {
    use ring::aead::{UnboundKey, LessSafeKey, AES_256_GCM};

    let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &[0x42u8; 32]).unwrap());

    let mut umem = mock_umem();
    let (addr, len, _) =
        build_encrypted_l2_frame(&mut umem, 0, 1, FLAG_TUNNEL, &key, 64);
    let descs = [(addr, len)];

    let mut peers = PeerTable::new(1_000_000_000);
    let mut slab = FixedSlab::new(MOCK_FRAMES);
    let mut scheduler = Scheduler::new();
    let mut rx_state = ReceiverState::new();
    let mut rx_bitmap = RxBitmap::new();
    let mut ip_id: u16 = 0;
    let mut hexdump = m13_hub::engine::runtime::HexdumpState::new(false);
    let cal = m13_hub::engine::runtime::TscCal::fallback();
    let mut ctx = make_test_ctx(
        &mut peers, &mut slab, &mut scheduler,
        &mut rx_state, &mut rx_bitmap, &mut ip_id, &mut umem,
        &mut hexdump, cal,
    );

    let mut decrypt_vec = PacketVector::new();
    let mut cleartext_vec = PacketVector::new();
    let mut stats = CycleStats::default();
    datapath::rx_parse_raw(&descs, &mut decrypt_vec, &mut cleartext_vec, &mut ctx, &mut stats);
    assert_eq!(decrypt_vec.len, 1);

    // Do NOT install any cipher — ciphers[peer_idx] remains None
    let mut disp = Disposition::new();
    datapath::aead_decrypt_vector(&mut decrypt_vec, &mut disp, &mut ctx, &mut stats);

    assert_eq!(stats.aead_fail, 1, "Missing cipher must count as AEAD failure");
    assert_eq!(disp.next[0], NextNode::Drop, "No cipher must route to Drop");
})}

// ============================================================================
// TEST 24: Rekey threshold — frame_count triggers session reset
// ============================================================================

/// Decrypt succeeds, but frame_count reaches REKEY_FRAME_LIMIT.
/// After decrypt, the cipher must be cleared (rekey triggered).
#[test]
fn encrypted_pipeline_rekey_threshold() { run_with_large_stack(|| {
    use ring::aead::{UnboundKey, LessSafeKey, AES_256_GCM};

    let key_bytes = [0x42u8; 32];
    let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &key_bytes).unwrap());

    let mut umem = mock_umem();
    let (addr, len, _) =
        build_encrypted_l2_frame(&mut umem, 0, 1, FLAG_TUNNEL, &key, 64);
    let descs = [(addr, len)];

    let mut peers = PeerTable::new(1_000_000_000);
    let mut slab = FixedSlab::new(MOCK_FRAMES);
    let mut scheduler = Scheduler::new();
    let mut rx_state = ReceiverState::new();
    let mut rx_bitmap = RxBitmap::new();
    let mut ip_id: u16 = 0;
    let mut hexdump = m13_hub::engine::runtime::HexdumpState::new(false);
    let cal = m13_hub::engine::runtime::TscCal::fallback();
    let mut ctx = make_test_ctx(
        &mut peers, &mut slab, &mut scheduler,
        &mut rx_state, &mut rx_bitmap, &mut ip_id, &mut umem,
        &mut hexdump, cal,
    );

    let mut decrypt_vec = PacketVector::new();
    let mut cleartext_vec = PacketVector::new();
    let mut stats = CycleStats::default();
    datapath::rx_parse_raw(&descs, &mut decrypt_vec, &mut cleartext_vec, &mut ctx, &mut stats);
    assert_eq!(decrypt_vec.len, 1);

    let peer_idx = decrypt_vec.descs[0].peer_idx as usize;
    ctx.peers.ciphers[peer_idx] =
        Some(LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &key_bytes).unwrap()));
    ctx.peers.slots[peer_idx].lifecycle = PeerLifecycle::Established;
    // Set frame_count to just below the rekey threshold.
    // decrypt_one increments frame_count by 1, then checks >= REKEY_FRAME_LIMIT.
    ctx.peers.slots[peer_idx].frame_count = REKEY_FRAME_LIMIT - 1;

    let mut disp = Disposition::new();
    datapath::aead_decrypt_vector(&mut decrypt_vec, &mut disp, &mut ctx, &mut stats);

    assert_eq!(stats.aead_ok, 1, "Decrypt must succeed");
    assert_eq!(disp.next[0], NextNode::ClassifyRoute, "Should still route to classify");

    // After decrypt, rekey must have been triggered:
    // - cipher cleared
    // - session_key zeroed
    // - frame_count reset
    assert!(ctx.peers.ciphers[peer_idx].is_none(),
        "Cipher must be cleared after rekey threshold");
    assert_eq!(ctx.peers.slots[peer_idx].session_key, [0u8; 32],
        "Session key must be zeroed after rekey");
    assert_eq!(ctx.peers.slots[peer_idx].frame_count, 0,
        "Frame count must be reset after rekey");
})}

// ############################################################################
// GAP CLOSURE: UDP ENCAPSULATED PATH
// ############################################################################

// ============================================================================
// TEST 25: UDP-encapsulated encrypted pipeline — the real internet path
// ============================================================================

/// Build an IPv4+UDP-encapsulated L2 M13 frame (EtherType 0x0800), encrypt it,
/// and feed it through the full RX pipeline. This is the actual production path
/// for internet-connected nodes — NOT the L2 raw WiFi7 path.
///
/// Frame layout: ETH(14) + IPv4(20) + UDP(8) + FakeETH(14) + M13(48) + payload
/// m13_offset = 56
#[test]
fn encrypted_pipeline_udp_encapsulated() { run_with_large_stack(|| {
    use ring::aead::{UnboundKey, LessSafeKey, AES_256_GCM};

    let key_bytes = [0x77u8; 32];
    let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &key_bytes).unwrap());
    let payload_len = 48;

    let mut umem = mock_umem();
    let addr: u64 = 0;
    let m13_off: usize = 56; // ETH(14) + IP(20) + UDP(8) + FakeETH(14)
    let total_len = m13_off + M13_HDR_SIZE + payload_len;
    let buf = &mut umem[0..total_len];
    buf.fill(0);

    // Outer Ethernet header: EtherType = IPv4 (0x0800)
    let gateway_mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01];
    buf[0..6].copy_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]); // dst (hub)
    buf[6..12].copy_from_slice(&gateway_mac);                          // src (gateway)
    buf[12..14].copy_from_slice(&0x0800u16.to_be_bytes());             // EtherType IPv4

    // IPv4 header (20 bytes at offset 14)
    let node_ip: [u8; 4] = [192, 168, 1, 100];
    let hub_ip: [u8; 4]  = [10, 13, 0, 1];
    let node_port: u16 = 12345;
    let hub_port: u16 = 443;
    buf[14] = 0x45; // version + IHL
    let ip_total_len = (20 + 8 + 14 + M13_HDR_SIZE + payload_len) as u16;
    buf[16..18].copy_from_slice(&ip_total_len.to_be_bytes());
    buf[23] = 17; // protocol = UDP
    buf[26..30].copy_from_slice(&node_ip);  // src IP
    buf[30..34].copy_from_slice(&hub_ip);   // dst IP

    // UDP header (8 bytes at offset 34)
    buf[34..36].copy_from_slice(&node_port.to_be_bytes()); // src port
    buf[36..38].copy_from_slice(&hub_port.to_be_bytes());  // dst port
    let udp_len = (8 + 14 + M13_HDR_SIZE + payload_len) as u16;
    buf[38..40].copy_from_slice(&udp_len.to_be_bytes());

    // Inner/Fake Ethernet header (14 bytes at offset 42)
    buf[42..48].copy_from_slice(&[0xFF; 6]);                            // inner dst
    buf[48..54].copy_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0xBB]); // inner src (peer MAC)
    buf[54..56].copy_from_slice(&ETH_P_M13.to_be_bytes());

    // M13 header at m13_off=56
    buf[m13_off]     = M13_WIRE_MAGIC;
    buf[m13_off + 1] = M13_WIRE_VERSION;
    let seq: u64 = 42;
    buf[m13_off + 32..m13_off + 40].copy_from_slice(&seq.to_le_bytes());
    buf[m13_off + 40] = FLAG_TUNNEL;

    // Payload
    let payload_start = m13_off + M13_HDR_SIZE;
    for i in 0..payload_len {
        buf[payload_start + i] = (i as u8) ^ 0x55;
    }
    let original_payload: Vec<u8> = buf[payload_start..payload_start + payload_len].to_vec();

    // Seal with node's direction
    m13_hub::cryptography::aead::seal_frame(buf, &key, seq, DIR_NODE_TO_HUB, m13_off);

    let descs = [(addr, total_len as u32)];

    let mut peers = PeerTable::new(1_000_000_000);
    let mut slab = FixedSlab::new(MOCK_FRAMES);
    let mut scheduler = Scheduler::new();
    let mut rx_state = ReceiverState::new();
    let mut rx_bitmap = RxBitmap::new();
    let mut ip_id: u16 = 0;
    let mut hexdump = m13_hub::engine::runtime::HexdumpState::new(false);
    let cal = m13_hub::engine::runtime::TscCal::fallback();
    let mut ctx = make_test_ctx(
        &mut peers, &mut slab, &mut scheduler,
        &mut rx_state, &mut rx_bitmap, &mut ip_id, &mut umem,
        &mut hexdump, cal,
    );

    // Parse — must detect IPv4/UDP encapsulation and use m13_offset=56
    let mut decrypt_vec = PacketVector::new();
    let mut cleartext_vec = PacketVector::new();
    let mut stats = CycleStats::default();
    datapath::rx_parse_raw(&descs, &mut decrypt_vec, &mut cleartext_vec, &mut ctx, &mut stats);

    assert_eq!(stats.parsed, 1, "UDP-encapsulated frame must parse");
    assert_eq!(decrypt_vec.len, 1, "Encrypted UDP frame must route to decrypt_out");
    assert_eq!(decrypt_vec.descs[0].m13_offset, 56,
        "m13_offset must be 56 for UDP-encapsulated frames");

    // Verify peer registered as UDP (not L2)
    let peer_idx = decrypt_vec.descs[0].peer_idx as usize;
    assert!(ctx.peers.slots[peer_idx].addr.is_udp(),
        "Peer must be registered with UDP address, not L2");

    // Install cipher and decrypt
    ctx.peers.ciphers[peer_idx] =
        Some(LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &key_bytes).unwrap()));
    ctx.peers.slots[peer_idx].lifecycle = PeerLifecycle::Established;

    let mut disp = Disposition::new();
    datapath::aead_decrypt_vector(&mut decrypt_vec, &mut disp, &mut ctx, &mut stats);

    assert_eq!(stats.aead_ok, 1, "AEAD must succeed on UDP-encapsulated frame");
    assert_eq!(disp.next[0], NextNode::ClassifyRoute);
    assert_eq!(decrypt_vec.descs[0].flags, FLAG_TUNNEL,
        "Flags must be recovered after decrypt");

    // Verify payload integrity
    let dec_payload = &umem[payload_start..payload_start + payload_len];
    assert_eq!(dec_payload, &original_payload[..],
        "Decrypted payload must match original byte-for-byte");
})}

// ============================================================================
// TEST 26: Multi-peer concurrent decrypt — 4 peers in one batch
// ============================================================================

/// Simulates 4 different nodes sending encrypted frames simultaneously.
/// Each peer has its own key. Verifies no cross-peer cipher confusion,
/// correct per-peer frame_count increment, and all 4 decrypt successfully.
#[test]
fn encrypted_pipeline_multi_peer_concurrent() { run_with_large_stack(|| {
    use ring::aead::{UnboundKey, LessSafeKey, AES_256_GCM};

    const NUM_PEERS: usize = 4;
    let key_material: [[u8; 32]; NUM_PEERS] = [
        [0x11u8; 32], [0x22u8; 32], [0x33u8; 32], [0x44u8; 32],
    ];
    let peer_macs: [[u8; 6]; NUM_PEERS] = [
        [0x02, 0x00, 0x00, 0x00, 0x01, 0x01],
        [0x02, 0x00, 0x00, 0x00, 0x01, 0x02],
        [0x02, 0x00, 0x00, 0x00, 0x01, 0x03],
        [0x02, 0x00, 0x00, 0x00, 0x01, 0x04],
    ];

    let mut umem = mock_umem();
    let mut descs_arr: Vec<(u64, u32)> = Vec::new();
    let mut original_payloads: Vec<Vec<u8>> = Vec::new();

    for i in 0..NUM_PEERS {
        let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &key_material[i]).unwrap());
        let payload_len = 32 + i * 8; // different payload sizes per peer
        let seq = (i as u64) + 1;

        let addr = i as u64 * MOCK_FRAME_SIZE as u64;
        let m13_off = ETH_HDR_SIZE;
        let total_len = m13_off + M13_HDR_SIZE + payload_len;
        let buf = &mut umem[addr as usize..addr as usize + total_len];
        buf.fill(0);

        // Ethernet
        buf[0..6].copy_from_slice(&[0xFF; 6]);
        buf[6..12].copy_from_slice(&peer_macs[i]);
        buf[12] = (ETH_P_M13 >> 8) as u8;
        buf[13] = (ETH_P_M13 & 0xFF) as u8;

        // M13
        buf[m13_off]     = M13_WIRE_MAGIC;
        buf[m13_off + 1] = M13_WIRE_VERSION;
        buf[m13_off + 32..m13_off + 40].copy_from_slice(&seq.to_le_bytes());
        buf[m13_off + 40] = FLAG_TUNNEL;

        // Payload — unique per peer
        let payload_start = m13_off + M13_HDR_SIZE;
        for j in 0..payload_len {
            buf[payload_start + j] = (j as u8) ^ (i as u8 + 0xAA);
        }
        original_payloads.push(buf[payload_start..payload_start + payload_len].to_vec());

        m13_hub::cryptography::aead::seal_frame(buf, &key, seq, DIR_NODE_TO_HUB, m13_off);
        descs_arr.push((addr, total_len as u32));
    }

    let mut peers = PeerTable::new(1_000_000_000);
    let mut slab = FixedSlab::new(MOCK_FRAMES);
    let mut scheduler = Scheduler::new();
    let mut rx_state = ReceiverState::new();
    let mut rx_bitmap = RxBitmap::new();
    let mut ip_id: u16 = 0;
    let mut hexdump = m13_hub::engine::runtime::HexdumpState::new(false);
    let cal = m13_hub::engine::runtime::TscCal::fallback();
    let mut ctx = make_test_ctx(
        &mut peers, &mut slab, &mut scheduler,
        &mut rx_state, &mut rx_bitmap, &mut ip_id, &mut umem,
        &mut hexdump, cal,
    );

    // Parse all 4 frames
    let mut decrypt_vec = PacketVector::new();
    let mut cleartext_vec = PacketVector::new();
    let mut stats = CycleStats::default();
    datapath::rx_parse_raw(&descs_arr, &mut decrypt_vec, &mut cleartext_vec, &mut ctx, &mut stats);

    assert_eq!(stats.parsed, NUM_PEERS as u64, "All 4 frames must parse");
    assert_eq!(decrypt_vec.len, NUM_PEERS, "All 4 must route to decrypt_out");

    // Install per-peer cipher keys
    for i in 0..NUM_PEERS {
        let pidx = decrypt_vec.descs[i].peer_idx as usize;
        ctx.peers.ciphers[pidx] =
            Some(LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &key_material[i]).unwrap()));
        ctx.peers.slots[pidx].lifecycle = PeerLifecycle::Established;
    }

    // Decrypt all 4
    let mut disp = Disposition::new();
    datapath::aead_decrypt_vector(&mut decrypt_vec, &mut disp, &mut ctx, &mut stats);

    assert_eq!(stats.aead_ok, NUM_PEERS as u64, "All 4 peers must decrypt successfully");
    assert_eq!(stats.aead_fail, 0, "No AEAD failures expected");

    for i in 0..NUM_PEERS {
        assert_eq!(disp.next[i], NextNode::ClassifyRoute,
            "Peer {} must route to ClassifyRoute", i);
        assert_eq!(decrypt_vec.descs[i].flags, FLAG_TUNNEL,
            "Peer {} must have FLAG_TUNNEL after decrypt", i);

        // Verify each peer's frame_count incremented independently
        let pidx = decrypt_vec.descs[i].peer_idx as usize;
        assert_eq!(ctx.peers.slots[pidx].frame_count, 1,
            "Peer {} frame_count must be 1 after one frame", i);
    }

    // Verify all 4 got distinct peer indices (no cross-peer confusion)
    let mut indices: Vec<u8> = (0..NUM_PEERS).map(|i| decrypt_vec.descs[i].peer_idx).collect();
    indices.sort();
    indices.dedup();
    assert_eq!(indices.len(), NUM_PEERS, "All 4 peers must have distinct indices");

    // Drop ctx (which borrows umem mutably) before reading umem for payload verification
    drop(ctx);

    // Verify payload integrity per peer
    for i in 0..NUM_PEERS {
        let m13_off = decrypt_vec.descs[i].m13_offset as usize;
        let payload_start = decrypt_vec.descs[i].addr as usize + m13_off + M13_HDR_SIZE;
        let payload_len = original_payloads[i].len();
        let dec = &umem[payload_start..payload_start + payload_len];
        assert_eq!(dec, &original_payloads[i][..],
            "Peer {} payload must match original after decrypt", i);
    }
})}

// ============================================================================
// TEST 27: TX encrypt pipeline — hub→node direction
// ============================================================================

/// Build a cleartext frame in UMEM (as tun_read_batch would), encrypt it via
/// aead_encrypt_vector, then verify the encrypted frame can be decrypted with
/// the node's direction byte — exercising the full TX path except libc::read().
#[test]
fn tx_encrypt_pipeline_hub_to_node() { run_with_large_stack(|| {
    use ring::aead::{UnboundKey, LessSafeKey, AES_256_GCM};

    let key_bytes = [0x55u8; 32];
    let payload_len = 80;

    let mut umem = mock_umem();
    let addr: u64 = 0;
    let m13_off = ETH_HDR_SIZE;
    let frame_len = m13_off + M13_HDR_SIZE + payload_len;
    let buf = &mut umem[0..frame_len];
    buf.fill(0);

    // Build exactly as tun_read_batch does:
    buf[0..6].copy_from_slice(&[0xFF; 6]);
    buf[6..12].copy_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    buf[12] = (ETH_P_M13 >> 8) as u8;
    buf[13] = (ETH_P_M13 & 0xFF) as u8;
    buf[14] = M13_WIRE_MAGIC;
    buf[15] = M13_WIRE_VERSION;
    buf[54] = FLAG_TUNNEL;
    buf[55..59].copy_from_slice(&(payload_len as u32).to_le_bytes());

    // Payload
    let ps = m13_off + M13_HDR_SIZE;
    for i in 0..payload_len { buf[ps + i] = (i as u8) ^ 0xCC; }
    let original_payload: Vec<u8> = buf[ps..ps + payload_len].to_vec();

    let peer_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0xBB];
    let peer_addr = PeerAddr::new_l2(peer_mac);

    let mut peers = PeerTable::new(1_000_000_000);
    let mut slab = FixedSlab::new(MOCK_FRAMES);
    let mut scheduler = Scheduler::new();
    let mut rx_state = ReceiverState::new();
    let mut rx_bitmap = RxBitmap::new();
    let mut ip_id: u16 = 0;
    let mut hexdump = m13_hub::engine::runtime::HexdumpState::new(false);
    let cal = m13_hub::engine::runtime::TscCal::fallback();

    // Pre-register peer with cipher — must do before building PacketDesc
    let real_peer_idx = peers.lookup_or_insert(peer_addr, peer_mac).unwrap();
    peers.ciphers[real_peer_idx] =
        Some(LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &key_bytes).unwrap()));
    peers.slots[real_peer_idx].lifecycle = PeerLifecycle::Established;

    // Build PacketDesc as tun_read_batch does
    let mut desc = PacketDesc::EMPTY;
    desc.addr = addr;
    desc.len = frame_len as u32;
    desc.m13_offset = m13_off as u16;
    desc.peer_idx = real_peer_idx as u8;
    desc.flags = FLAG_TUNNEL;
    desc.payload_len = payload_len as u32;

    let mut encrypt_vec = PacketVector::new();
    encrypt_vec.push(desc);

    let mut ctx = make_test_ctx(
        &mut peers, &mut slab, &mut scheduler,
        &mut rx_state, &mut rx_bitmap, &mut ip_id, &mut umem,
        &mut hexdump, cal,
    );

    // Encrypt
    let mut disp = Disposition::new();
    datapath::aead_encrypt_vector(&mut encrypt_vec, &mut disp, &mut ctx);

    assert_eq!(disp.next[0], NextNode::TxEnqueue, "Encrypted frame must route to TxEnqueue");
    assert_eq!(ctx.peers.slots[real_peer_idx].frame_count, 1, "frame_count must increment");
    assert_eq!(ctx.peers.slots[real_peer_idx].seq_tx, 1, "seq_tx must advance to 1");

    // Verify crypto_ver was set
    assert_eq!(umem[m13_off + 2], 0x01, "seal_frame must set crypto_ver = 0x01");

    // Verify the node can decrypt what the hub encrypted.
    // Node uses DIR_NODE_TO_HUB as its own direction byte → open_frame checks
    // nonce direction != our_dir. Hub sealed with DIR_HUB_TO_NODE, so
    // node calls open_frame with our_dir=DIR_NODE_TO_HUB → nonce_dir=0x00 != 0x01 → pass.
    let node_key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &key_bytes).unwrap());
    let frame = &mut umem[0..frame_len];
    let ok = m13_hub::cryptography::aead::open_frame(frame, &node_key, DIR_NODE_TO_HUB, m13_off);
    assert!(ok, "Node must be able to decrypt hub-encrypted frame");

    // Verify payload recovered correctly
    assert_eq!(&umem[ps..ps + payload_len], &original_payload[..],
        "Decrypted payload must match original");
})}

// ============================================================================
// TEST 28: TX enqueue — RxBitmap + Scheduler integration
// ============================================================================

/// Feed packets through tx_enqueue_vector and verify that RxBitmap gets marked,
/// Scheduler gets enqueued, and stats are updated.
#[test]
fn tx_enqueue_marks_bitmap_and_scheduler() { run_with_large_stack(|| {
    let mut umem = mock_umem();
    let mut peers = PeerTable::new(1_000_000_000);
    let mut slab = FixedSlab::new(MOCK_FRAMES);
    let mut scheduler = Scheduler::new();
    let mut rx_state = ReceiverState::new();
    let mut rx_bitmap = RxBitmap::new();
    let mut ip_id: u16 = 0;
    let mut hexdump = m13_hub::engine::runtime::HexdumpState::new(false);
    let cal = m13_hub::engine::runtime::TscCal::fallback();
    let mut ctx = make_test_ctx(
        &mut peers, &mut slab, &mut scheduler,
        &mut rx_state, &mut rx_bitmap, &mut ip_id, &mut umem,
        &mut hexdump, cal,
    );

    // Build 3 PacketDescs with known seq_ids
    let mut vec = PacketVector::new();
    for i in 0..3u64 {
        let mut d = PacketDesc::EMPTY;
        d.addr = i * MOCK_FRAME_SIZE as u64;
        d.len = 100;
        d.seq_id = i + 1; // seq 1, 2, 3
        d.peer_idx = 0;
        vec.push(d);
    }

    let mut disp = Disposition::new();
    let mut stats = CycleStats::default();
    datapath::tx_enqueue_vector(&vec, &mut disp, &mut ctx, &mut stats);

    assert_eq!(stats.data_fwd, 3, "3 packets must be forwarded");
    assert_eq!(ctx.rx_state.highest_seq, 3, "highest_seq must track last seq_id");
    assert_eq!(ctx.rx_state.delivered, 3, "delivered count must be 3");

    for i in 0..3 {
        assert_eq!(disp.next[i], NextNode::Consumed, "All must be Consumed");
    }

    // Verify Scheduler received the enqueues
    assert!(ctx.scheduler.pending() >= 3,
        "Scheduler must have at least 3 pending entries");
})}

// ============================================================================
// TEST 29: Fragment reassembly — Assembler with real FragHeaders
// ============================================================================

/// Build 3 fragments of a message, feed them through the Assembler, and verify
/// the reassembled payload matches the original. Tests the cold path used for
/// PQC handshake (ClientHello is ~4KB, fragmented into 3-4 pieces).
#[test]
fn fragment_reassembly_three_fragments() {
    let original_data = vec![0xABu8; 300]; // 300-byte message

    let arena = alloc_asm_arena(ASM_SLOTS_PER_PEER);
    let mut assembler = Assembler::init(arena);
    let mut reassembled = Vec::new();

    // Fragment 0: bytes [0..100]
    assembler.feed(1, 0, 3, 0, &original_data[0..100], 1_000_000_000,
        |data| reassembled.extend_from_slice(data));
    assert!(reassembled.is_empty(), "Incomplete message must not reassemble");

    // Fragment 2 (out of order): bytes [200..300]
    assembler.feed(1, 2, 3, 200, &original_data[200..300], 1_000_000_001,
        |data| reassembled.extend_from_slice(data));
    assert!(reassembled.is_empty(), "Still incomplete after 2/3 fragments");

    // Fragment 1 (final, out of order): bytes [100..200]
    assembler.feed(1, 1, 3, 100, &original_data[100..200], 1_000_000_002,
        |data| reassembled.extend_from_slice(data));
    assert_eq!(reassembled.len(), 300, "Reassembled length must be 300");
    assert_eq!(&reassembled[..], &original_data[..],
        "Reassembled payload must match original byte-for-byte");

    free_asm_arena(arena, ASM_SLOTS_PER_PEER);
}

// ============================================================================
// TEST 30: RxBitmap — sliding window gap detection
// ============================================================================

/// Mark packets with gaps in the sequence, then drain losses.
/// Verifies the 1024-bit sliding window correctly identifies missing packets.
#[test]
fn rxbitmap_gap_detection() {
    let mut bm = RxBitmap::new();

    // Mark packets 0, 1, 2, then skip 3, 4, and mark 5
    bm.mark(0);
    bm.mark(1);
    bm.mark(2);
    // Skip 3, 4
    bm.mark(5);

    // Advance far enough that the bitmap's drain window covers 0..5
    bm.mark(600);

    let (loss_count, nack_bitmap) = bm.drain_losses();
    // Packets 3 and 4 were never marked — they should be counted as losses
    assert!(loss_count >= 2,
        "At least 2 gaps (seq 3, 4) must be detected, got {}", loss_count);
    assert!(nack_bitmap != 0,
        "NACK bitmap must be non-zero (gap positions encoded)");
}

// ============================================================================
// TEST 31: FIN flag — graceful close through full pipeline
// ============================================================================

/// Build a FIN-flagged frame, run through classify, and verify it's recorded
/// in stats.fin_events and consumed (not forwarded to TUN).
#[test]
fn fin_flag_graceful_close() {
    let desc = desc_with_flags(FLAG_FIN);
    let mut vec = PacketVector::new();
    vec.push(desc);

    let mut disp = Disposition::new();
    let mut stats = CycleStats::default();
    datapath::classify_route(&vec, &mut disp, &mut stats, false);

    assert_eq!(disp.next[0], NextNode::Consumed, "FIN must be Consumed, not forwarded");
    assert_eq!(stats.fin_count, 1, "FIN must be recorded in fin_events");

    // Test with closing=true (hub is shutting down)
    let mut stats2 = CycleStats::default();
    let mut disp2 = Disposition::new();
    datapath::classify_route(&vec, &mut disp2, &mut stats2, true);
    assert_eq!(stats2.fin_events[0].1, true,
        "FIN with closing=true must record closing flag");
}
