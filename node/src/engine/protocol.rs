// M13 NODE — ENGINE: PROTOCOL MODULE
// Wire format, fragmentation, and frame builders.
// Zero-share: independent copy from Hub.

use std::mem;

use bytemuck::{Pod, Zeroable};

// ============================================================================
// WIRE CONSTANTS
// ============================================================================

/// IEEE 802.1 Local Experimental EtherType for M13 raw Ethernet frames.
pub const ETH_P_M13: u16 = 0x88B5;
/// Wire protocol magic byte. Stored in M13Header.signature[0].
pub const M13_WIRE_MAGIC: u8 = 0xD1;
/// Wire protocol version. Phase 1 = 0x01.
pub const M13_WIRE_VERSION: u8 = 0x01;

/// IEEE 802.3 Ethernet header. 14 bytes on wire: dst(6) + src(6) + ethertype(2).
#[repr(C, packed)] #[derive(Copy, Clone, Pod, Zeroable)]
pub struct EthernetHeader { pub dst: [u8; 6], pub src: [u8; 6], pub ethertype: u16 }

/// M13 wire protocol header. 48 bytes. Carried after EthernetHeader.
/// signature[0]=magic(0xD1), signature[1]=version(0x01), [2..32]=reserved(Phase 2 crypto).
#[repr(C, packed)] #[derive(Copy, Clone, Pod, Zeroable)]
pub struct M13Header {
    pub signature: [u8; 32], pub seq_id: u64, pub flags: u8,
    pub payload_len: u32, pub padding: [u8; 3],
}
const _: () = assert!(mem::size_of::<M13Header>() == 48);

pub const ETH_HDR_SIZE: usize = mem::size_of::<EthernetHeader>();
pub const M13_HDR_SIZE: usize = mem::size_of::<M13Header>();

pub const FLAG_CONTROL: u8   = 0x80;
pub const FLAG_TUNNEL: u8    = 0x20;
pub const FLAG_HANDSHAKE: u8 = 0x02;
pub const FLAG_FRAGMENT: u8  = 0x01;

/// PQC Handshake retransmit interval (nanoseconds).
/// Must exceed the worst-case PQC handshake round-trip:
///   WAN RTT (~300ms) + ML-KEM-1024 encaps (~50ms) + ML-DSA-87 sign (~100ms)
///   + fragment reassembly (~5ms) + scheduling jitter (~100ms) = ~555ms
/// At 10,000 nodes, premature retransmits flood the Hub's PQC worker queue.
/// 5s = ~9× worst-case, provides ample headroom for congested links.
pub const HANDSHAKE_RETX_INTERVAL_NS: u64 = 5_000_000_000;
/// Rekey after 2^32 frames under one session key
pub const REKEY_FRAME_LIMIT: u64 = 1u64 << 32;
/// Rekey after 1 hour under one session key
pub const REKEY_TIME_LIMIT_NS: u64 = 3_600_000_000_000;

// PQC handshake sub-types (first byte of handshake payload)
pub const HS_CLIENT_HELLO: u8 = 0x01;
pub const HS_SERVER_HELLO: u8 = 0x02;
pub const HS_FINISHED: u8     = 0x03;

// Direction bytes for AEAD nonce (prevents reflection attacks)
pub const DIR_NODE_TO_HUB: u8 = 0x01;

// ============================================================================
// FRAME BUILDER
// ============================================================================
pub fn build_m13_frame(src_mac: &[u8; 6], dst_mac: &[u8; 6], seq: u64, flags: u8) -> [u8; 62] {
    let mut frame = [0u8; 62];
    frame[0..6].copy_from_slice(dst_mac);
    frame[6..12].copy_from_slice(src_mac);
    frame[12] = (ETH_P_M13 >> 8) as u8;
    frame[13] = (ETH_P_M13 & 0xFF) as u8;
    frame[14] = M13_WIRE_MAGIC;
    frame[15] = M13_WIRE_VERSION;
    frame[46..54].copy_from_slice(&seq.to_le_bytes());
    frame[54] = flags;
    frame
}

pub fn build_echo_frame(rx_frame: &[u8], new_seq: u64) -> Option<Vec<u8>> {
    if rx_frame.len() < ETH_HDR_SIZE + M13_HDR_SIZE { return None; }
    let mut echo = rx_frame.to_vec();
    // Swap dst/src MAC
    let (dst, src) = echo.split_at_mut(6);
    let mut tmp = [0u8; 6];
    tmp.copy_from_slice(&dst[..6]);
    dst[..6].copy_from_slice(&src[..6]);
    src[..6].copy_from_slice(&tmp);
    // Stamp our seq
    echo[46..54].copy_from_slice(&new_seq.to_le_bytes());
    Some(echo)
}

/// Read the hardware MAC address of a network interface from sysfs.
/// Returns the 6-byte MAC or a locally-administered random fallback.
pub fn detect_mac(if_name: Option<&str>) -> [u8; 6] {
    if let Some(iface) = if_name {
        let path = format!("/sys/class/net/{}/address", iface);
        if let Ok(contents) = std::fs::read_to_string(&path) {
            let parts: Vec<u8> = contents.trim().split(':')
                .filter_map(|h| u8::from_str_radix(h, 16).ok())
                .collect();
            if parts.len() == 6 {
                eprintln!("[M13-NODE] Detected MAC for {}: {}", iface, contents.trim());
                return [parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]];
            }
        }
    }
    // Generate a random locally-administered MAC (LAA)
    let seed = crate::engine::runtime::clock_ns() & 0xFFFFFFFFFFFF;
    let mac = [
        0x02,
        ((seed >> 8) & 0xFF) as u8,
        ((seed >> 16) & 0xFF) as u8,
        ((seed >> 24) & 0xFF) as u8,
        ((seed >> 32) & 0xFF) as u8,
        ((seed >> 40) & 0xFF) as u8,
    ];
    eprintln!("[M13-NODE] Using generated LAA MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    mac
}

// ============================================================================
// R-04: O(1) ZERO-ALLOCATION FRAGMENT MATRIX (HugeTLB)
// ============================================================================

pub const FRAG_HDR_SIZE: usize = 8;
pub const MAX_FRAGMENTS: u8 = 16;
pub const MAX_REASSEMBLY_SIZE: usize = 9216;
pub const ASM_SLOTS_PER_PEER: usize = 8;

#[repr(C, packed)]
pub struct FragHeader {
    pub frag_msg_id: u16,
    pub frag_index: u8,
    pub frag_total: u8,
    pub frag_offset: u16,
    pub frag_len: u16,
}
const _: () = assert!(mem::size_of::<FragHeader>() == FRAG_HDR_SIZE);

/// Hardware-aligned reassembly slot.
#[repr(C, align(64))]
pub struct AssemblySlot {
    pub buf: [u8; MAX_REASSEMBLY_SIZE],
    pub first_rx_ns: u64,
    pub msg_id: u16,
    pub received_mask: u16,
    pub max_len: u16,
    pub total: u8,
    pub active: bool,
}
const _: () = assert!(mem::size_of::<AssemblySlot>() == 9280);

impl AssemblySlot {
    #[inline(always)]
    pub fn reset(&mut self, msg_id: u16, total: u8, now_ns: u64) {
        self.msg_id = msg_id;
        self.total = total;
        self.received_mask = 0;
        self.max_len = 0;
        self.first_rx_ns = now_ns;
        self.active = true;
    }
}

/// Zero-allocation O(1) fragment assembler (Node side — single peer).
#[derive(Copy, Clone)]
pub struct Assembler {
    pub slots: *mut AssemblySlot,
    pub mask: u16,
}

unsafe impl Send for Assembler {}

impl Default for Assembler {
    fn default() -> Self {
        Assembler { slots: std::ptr::null_mut(), mask: (ASM_SLOTS_PER_PEER - 1) as u16 }
    }
}

impl Assembler {

    pub fn init(ptr: *mut AssemblySlot) -> Self {
        Assembler { slots: ptr, mask: (ASM_SLOTS_PER_PEER - 1) as u16 }
    }

    #[inline(always)]
    pub fn feed<F>(
        &mut self, msg_id: u16, index: u8, total: u8, offset: u16,
        data: &[u8], now_ns: u64, mut on_complete: F,
    ) where F: FnMut(&[u8]) {
        if total == 0 || total > MAX_FRAGMENTS || index >= total { return; }
        if self.slots.is_null() { return; }
        let off = offset as usize;
        let dlen = data.len();
        if off + dlen > MAX_REASSEMBLY_SIZE { return; }

        let slot_idx = ((msg_id ^ (msg_id >> 3)) & self.mask) as usize;
        let slot = unsafe { &mut *self.slots.add(slot_idx) };

        // SURGICAL PATCH: If the slot is inactive, it unconditionally belongs to the incoming msg_id.
        // This prevents the zero-initialized memory (msg_id=0) from rejecting the first ServerHello.
        if slot.msg_id != msg_id || !slot.active {
            if !slot.active || now_ns.saturating_sub(slot.first_rx_ns) > 5_000_000_000 {
                slot.reset(msg_id, total, now_ns);
            } else { return; }
        }

        let bit = 1u16 << index;
        if (slot.received_mask & bit) != 0 { return; }

        unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), slot.buf.as_mut_ptr().add(off), dlen); }
        slot.received_mask |= bit;
        let end_bound = (off + dlen) as u16;
        if end_bound > slot.max_len { slot.max_len = end_bound; }

        let expected_mask = ((1u32 << total) - 1) as u16;
        if slot.received_mask == expected_mask {
            let final_len = slot.max_len as usize;
            let complete_slice = unsafe { std::slice::from_raw_parts(slot.buf.as_ptr(), final_len) };
            on_complete(complete_slice);
            slot.active = false;
        }
    }

    #[inline(always)]
    pub fn gc(&mut self, now_ns: u64) {
        if self.slots.is_null() { return; }
        for i in 0..ASM_SLOTS_PER_PEER {
            let slot = unsafe { &mut *self.slots.add(i) };
            if slot.active && now_ns.saturating_sub(slot.first_rx_ns) > 5_000_000_000 {
                slot.active = false;
            }
        }
    }
}

/// Allocate HugeTLB arena for assembler slots.
pub fn alloc_asm_arena(n_slots: usize) -> *mut AssemblySlot {
    let size = n_slots * mem::size_of::<AssemblySlot>();
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(), size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_HUGETLB | libc::MAP_POPULATE,
            -1, 0,
        )
    };
    if ptr == libc::MAP_FAILED {
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(), size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_POPULATE,
                -1, 0,
            )
        };
        if ptr == libc::MAP_FAILED {
            panic!("[M13-R04] Node ASM arena mmap failed");
        }
        eprintln!("[M13-R04] Node ASM arena: {}B via regular mmap", size);
        unsafe { std::ptr::write_bytes(ptr as *mut u8, 0, size); }
        return ptr as *mut AssemblySlot;
    }
    eprintln!("[M13-R04] Node ASM arena: {}B via MAP_HUGETLB", size);
    unsafe { std::ptr::write_bytes(ptr as *mut u8, 0, size); }
    ptr as *mut AssemblySlot
}

/// Free HugeTLB arena.
#[cfg(test)]
pub fn free_asm_arena(ptr: *mut AssemblySlot, n_slots: usize) {
    if ptr.is_null() { return; }
    let size = n_slots * mem::size_of::<AssemblySlot>();
    unsafe { libc::munmap(ptr as *mut libc::c_void, size); }
}

// ── Zero-Allocation Closure-Based Fragment Sender ───────────────────────

/// [P1-02] RESOLUTION: Incorporates USO MTU Slicer mathematically bounded to 1380 bytes.
/// Caller provides an `emit` closure that receives each built frame.
#[inline(always)]
pub fn send_fragmented_udp<F>(
    src_mac: &[u8; 6], dst_mac: &[u8; 6],
    payload: &[u8], flags: u8, seq: &mut u64,
    mut emit: F,
) -> u64 where F: FnMut(&[u8]) {
    use crate::network::uso_pacer::slice_uso_counted;

    // [P1-02] STRICT USO MTU CLAMPING (1380 bytes max chunk)
    // Ensures L2 length never exceeds 1442 bytes (under 1500 MTU limit).
    // Annihilates Kernel IP fragmentation.
    let max_chunk = 1380;
    let (uso_iter, total_slices) = slice_uso_counted(payload, max_chunk);
    let total = total_slices as u8;
    let msg_id = (*seq & 0xFFFF) as u16;
    let mut sent = 0u64;
    let mut frame = [0u8; 1500];

    if cfg!(debug_assertions) && total > 1 {
        eprintln!("[M13-FRAG] Fragmenting {}B payload → {} slices (USO MTU={})", payload.len(), total_slices, max_chunk);
    }

    for (i, chunk) in uso_iter.enumerate() {
        let offset = i * max_chunk;
        let chunk_len = chunk.len();
        let flen = ETH_HDR_SIZE + M13_HDR_SIZE + FRAG_HDR_SIZE + chunk_len;
        
        frame[0..6].copy_from_slice(dst_mac);
        frame[6..12].copy_from_slice(src_mac);
        frame[12] = (ETH_P_M13 >> 8) as u8;
        frame[13] = (ETH_P_M13 & 0xFF) as u8;
        frame[14] = M13_WIRE_MAGIC; frame[15] = M13_WIRE_VERSION;
        for b in &mut frame[16..46] { *b = 0; }
        frame[46..54].copy_from_slice(&seq.to_le_bytes());
        frame[54] = flags | FLAG_FRAGMENT;
        for b in &mut frame[55..59] { *b = 0; }
        
        let fh = ETH_HDR_SIZE + M13_HDR_SIZE;
        frame[fh..fh+2].copy_from_slice(&msg_id.to_le_bytes());
        frame[fh+2] = i as u8; frame[fh+3] = total as u8;
        frame[fh+4..fh+6].copy_from_slice(&(offset as u16).to_le_bytes());
        frame[fh+6..fh+8].copy_from_slice(&(chunk_len as u16).to_le_bytes());
        
        let dp = fh + FRAG_HDR_SIZE;
        frame[dp..dp+chunk_len].copy_from_slice(chunk);

        emit(&frame[..flen]);

        sent += 1;
        *seq += 1;
    }
    sent
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_assembler() -> (Assembler, *mut AssemblySlot) {
        let arena = alloc_asm_arena(ASM_SLOTS_PER_PEER);
        let asm = Assembler::init(arena);
        (asm, arena)
    }

    #[test]
    fn header_sizes() {
        assert_eq!(mem::size_of::<EthernetHeader>(), 14);
        assert_eq!(mem::size_of::<M13Header>(), 48);
        assert_eq!(ETH_HDR_SIZE, 14);
        assert_eq!(M13_HDR_SIZE, 48);
    }

    #[test]
    fn build_frame_magic_and_flags() {
        let src = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let dst = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let frame = build_m13_frame(&src, &dst, 42, FLAG_CONTROL);
        assert_eq!(&frame[0..6], &dst);
        assert_eq!(&frame[6..12], &src);
        assert_eq!(frame[14], M13_WIRE_MAGIC);
        assert_eq!(frame[15], M13_WIRE_VERSION);
        assert_eq!(u64::from_le_bytes(frame[46..54].try_into().unwrap()), 42);
        assert_eq!(frame[54], FLAG_CONTROL);
    }

    #[test]
    fn echo_frame_swaps_macs() {
        let src = [0x02; 6];
        let dst = [0xAA; 6];
        let orig = build_m13_frame(&src, &dst, 1, FLAG_CONTROL);
        let echo = build_echo_frame(&orig, 99).unwrap();
        assert_eq!(&echo[0..6], &src);
        assert_eq!(&echo[6..12], &dst);
        assert_eq!(u64::from_le_bytes(echo[46..54].try_into().unwrap()), 99);
    }

    #[test]
    fn echo_frame_rejects_short() {
        let short = [0u8; 10];
        assert!(build_echo_frame(&short, 1).is_none());
    }

    #[test]
    fn single_fragment_completes() {
        let (mut asm, arena) = test_assembler();
        let mut result = Vec::new();
        asm.feed(1, 0, 1, 0, b"hello", 100, |data| result.extend_from_slice(data));
        assert_eq!(&result, b"hello");
        free_asm_arena(arena, ASM_SLOTS_PER_PEER);
    }

    #[test]
    fn multi_fragment_reassembly() {
        let (mut asm, arena) = test_assembler();
        let mut result = Vec::new();
        asm.feed(42, 0, 3, 0, b"AAAA", 100, |data| result.extend_from_slice(data));
        assert!(result.is_empty());
        asm.feed(42, 1, 3, 4, b"BBBB", 100, |data| result.extend_from_slice(data));
        assert!(result.is_empty());
        asm.feed(42, 2, 3, 8, b"CC", 100, |data| result.extend_from_slice(data));
        assert_eq!(&result[0..4], b"AAAA");
        assert_eq!(&result[4..8], b"BBBB");
        assert_eq!(&result[8..10], b"CC");
        free_asm_arena(arena, ASM_SLOTS_PER_PEER);
    }

    #[test]
    fn duplicate_fragment_ignored() {
        let (mut asm, arena) = test_assembler();
        let mut count = 0usize;
        asm.feed(1, 0, 2, 0, b"A", 100, |_| count += 1);
        assert_eq!(count, 0);
        asm.feed(1, 0, 2, 0, b"A", 100, |_| count += 1); // dup
        assert_eq!(count, 0);
        asm.feed(1, 1, 2, 1, b"B", 100, |_| count += 1);
        assert_eq!(count, 1);
        free_asm_arena(arena, ASM_SLOTS_PER_PEER);
    }

    #[test]
    fn gc_removes_stale() {
        let (mut asm, arena) = test_assembler();
        let mut count = 0usize;
        asm.feed(1, 0, 2, 0, b"X", 100, |_| count += 1);
        asm.gc(6_000_000_100); 
        asm.feed(1, 1, 2, 1, b"Y", 6_000_000_200, |_| count += 1);
        assert_eq!(count, 0); 
        free_asm_arena(arena, ASM_SLOTS_PER_PEER);
    }

    #[test]
    fn out_of_range_rejected() {
        let (mut asm, arena) = test_assembler();
        let mut count = 0usize;
        asm.feed(1, 16, 2, 0, b"bad", 100, |_| count += 1);
        asm.feed(1, 2, 2, 0, b"bad", 100, |_| count += 1);
        assert_eq!(count, 0);
        free_asm_arena(arena, ASM_SLOTS_PER_PEER);
    }

    #[test]
    fn assembly_slot_size() {
        assert_eq!(mem::size_of::<AssemblySlot>(), 9280);
        assert_eq!(9280 % 64, 0);
    }
}