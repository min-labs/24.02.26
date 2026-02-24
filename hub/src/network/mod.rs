// M13 HUB — NETWORK MODULE
// Clean 4-module structure:
//   xdp.rs           — AF_XDP zero-copy engine (UMEM, rings, TX/RX)
//   uring_reactor.rs — io_uring SQPOLL + PBR zero-syscall reactor (for wlan0)
//   bpf.rs           — BPF steersman (eBPF XDP filter)
//   datapath.rs      — Everything about moving packets (parse, classify, AEAD)

pub mod xdp;
pub mod uring_reactor;
pub mod bpf;
pub mod datapath;
pub mod uso_pacer;

use std::fmt;

use crate::engine::protocol::PeerTable;
use crate::engine::runtime::FixedSlab;
use crate::engine::protocol::{Scheduler, ReceiverState, RxBitmap};
use crate::engine::spsc::{Producer, Consumer};

// ============================================================================
// PACKET VECTOR — The fundamental VPP data structure
// ============================================================================

pub const VECTOR_SIZE: usize = 64;

#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub struct PacketDesc {
    pub addr: u64,
    pub len: u32,
    pub m13_offset: u16,
    pub flags: u8,
    pub peer_idx: u8,
    pub seq_id: u64,
    pub payload_len: u32,
    pub rx_ns: u64,
    pub src_ip: [u8; 4],
    pub src_port: u16,
    pub rx_iface: u8, // [P1-04] Interface router: 0 = AF_XDP (WAN), 1 = io_uring (WLAN)
    _pad: [u8; 5],
}

impl PacketDesc {
    pub const EMPTY: Self = PacketDesc {
        addr: 0, len: 0, m13_offset: 0, flags: 0, peer_idx: 0xFF,
        seq_id: 0, payload_len: 0, rx_ns: 0,
        src_ip: [0; 4], src_port: 0, rx_iface: 0, _pad: [0; 5],
    };
}

pub struct PacketVector {
    pub descs: [PacketDesc; VECTOR_SIZE],
    pub len: usize,
}

impl Default for PacketVector {
    fn default() -> Self { Self::new() }
}

impl PacketVector {
    #[inline(always)]
    pub fn new() -> Self {
        PacketVector { descs: [PacketDesc::EMPTY; VECTOR_SIZE], len: 0 }
    }

    #[inline(always)]
    pub fn push(&mut self, desc: PacketDesc) -> bool {
        if self.len < VECTOR_SIZE { self.descs[self.len] = desc; self.len += 1; true } else { false }
    }

    #[inline(always)]
    pub fn clear(&mut self) { self.len = 0; }

    #[inline(always)]
    pub fn is_empty(&self) -> bool { self.len == 0 }

    #[inline(always)]
    pub fn is_full(&self) -> bool { self.len >= VECTOR_SIZE }

    #[inline(always)]
    pub fn capacity(&self) -> usize { VECTOR_SIZE }
}

// ============================================================================
// GRAPH NODE ROUTING
// ============================================================================

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum NextNode {
    Drop = 0, AeadDecrypt = 1, ClassifyRoute = 2, TunWrite = 3,
    AeadEncrypt = 4, TxEnqueue = 5, Handshake = 6, Feedback = 7, Consumed = 8,
    Echo = 9,
}

impl fmt::Display for NextNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NextNode::Drop => write!(f, "drop"),
            NextNode::AeadDecrypt => write!(f, "aead-decrypt"),
            NextNode::ClassifyRoute => write!(f, "classify-route"),
            NextNode::TunWrite => write!(f, "tun-write"),
            NextNode::AeadEncrypt => write!(f, "aead-encrypt"),
            NextNode::TxEnqueue => write!(f, "tx-enqueue"),
            NextNode::Handshake => write!(f, "handshake"),
            NextNode::Feedback => write!(f, "feedback"),
            NextNode::Consumed => write!(f, "consumed"),
            NextNode::Echo => write!(f, "echo"),
        }
    }
}

pub struct Disposition {
    pub next: [NextNode; VECTOR_SIZE],
}

impl Default for Disposition {
    fn default() -> Self { Self::new() }
}

impl Disposition {
    #[inline(always)]
    pub fn new() -> Self { Disposition { next: [NextNode::Drop; VECTOR_SIZE] } }
}

// ============================================================================
// SCATTER
// ============================================================================

#[allow(clippy::too_many_arguments)]
#[inline]
pub fn scatter(
    src: &PacketVector, disp: &Disposition,
    decrypt_out: &mut PacketVector, classify_out: &mut PacketVector,
    tun_out: &mut PacketVector, encrypt_out: &mut PacketVector,
    tx_out: &mut PacketVector, handshake_out: &mut PacketVector,
    feedback_out: &mut PacketVector, drop_out: &mut PacketVector,
    cleartext_out: &mut PacketVector,
) {
    let n = src.len;
    let mut i = 0;
    while i + 4 <= n {
        if i + 8 <= n {
            unsafe {
                let base = src.descs.as_ptr().add(i + 4);
                crate::engine::runtime::prefetch_read_l1(base as *const u8);
                crate::engine::runtime::prefetch_read_l1(base.add(1) as *const u8);
                crate::engine::runtime::prefetch_read_l1(base.add(2) as *const u8);
                crate::engine::runtime::prefetch_read_l1(base.add(3) as *const u8);
            }
        }
        for j in 0..4 {
            let idx = i + j;
            let desc = &src.descs[idx];
            match disp.next[idx] {
                NextNode::AeadDecrypt => { decrypt_out.push(*desc); }
                NextNode::ClassifyRoute => { classify_out.push(*desc); }
                NextNode::TunWrite => { tun_out.push(*desc); }
                NextNode::AeadEncrypt => { encrypt_out.push(*desc); }
                NextNode::TxEnqueue => { tx_out.push(*desc); }
                NextNode::Handshake => { handshake_out.push(*desc); }
                NextNode::Feedback => { feedback_out.push(*desc); }
                NextNode::Drop => { drop_out.push(*desc); }
                NextNode::Echo => { cleartext_out.push(*desc); }
                NextNode::Consumed => {}
            }
        }
        i += 4;
    }
    while i < n {
        let desc = &src.descs[i];
        match disp.next[i] {
            NextNode::AeadDecrypt => { decrypt_out.push(*desc); }
            NextNode::ClassifyRoute => { classify_out.push(*desc); }
            NextNode::TunWrite => { tun_out.push(*desc); }
            NextNode::AeadEncrypt => { encrypt_out.push(*desc); }
            NextNode::TxEnqueue => { tx_out.push(*desc); }
            NextNode::Handshake => { handshake_out.push(*desc); }
            NextNode::Feedback => { feedback_out.push(*desc); }
            NextNode::Drop => { drop_out.push(*desc); }
            NextNode::Echo => { cleartext_out.push(*desc); }
            NextNode::Consumed => {}
        }
        i += 1;
    }
}

// ============================================================================
// GRAPH CONTEXT
// ============================================================================

pub struct GraphCtx<'a> {
    pub peers: &'a mut PeerTable,
    pub slab: &'a mut FixedSlab,
    pub scheduler: &'a mut Scheduler,
    pub rx_state: &'a mut ReceiverState,
    pub rx_bitmap: &'a mut RxBitmap,
    pub tun_fd: i32,
    pub src_mac: [u8; 6],
    pub gateway_mac: [u8; 6],
    pub hub_ip: [u8; 4],
    pub hub_port: u16,
    pub ip_id_counter: &'a mut u16,
    pub worker_idx: usize,
    pub closing: bool,
    pub now_ns: u64,
    pub umem_base: *mut u8,
    pub frame_size: u32,
    pub tx_tun_prod: Option<&'a mut Producer<PacketDesc>>,
    pub rx_tun_cons: Option<&'a mut Consumer<PacketDesc>>,
    pub free_to_tun_prod: Option<&'a mut Producer<u32>>,
    pub free_to_dp_cons: Option<&'a mut Consumer<u32>>,
    pub hexdump: &'a mut crate::engine::runtime::HexdumpState,
    pub cal: crate::engine::runtime::TscCal,
    pub pqc_req_tx: Option<&'a mut Producer<crate::cryptography::async_pqc::PqcReq>>,
    pub pqc_resp_rx: Option<&'a mut Consumer<crate::cryptography::async_pqc::PqcResp>>,
    pub payload_arena: *mut [u8; crate::cryptography::async_pqc::MAX_HS_PAYLOAD_SIZE],
    pub pacer: Option<&'a mut crate::network::uso_pacer::EdtPacer>,
}

#[derive(Default, Clone)]
pub struct CycleStats {
    pub parsed: u64,
    pub aead_ok: u64,
    pub aead_fail: u64,
    pub tun_writes: u64,
    pub handshakes: u64,
    pub feedback: u64,
    pub drops: u64,
    pub data_fwd: u64,
    pub fin_events: [(u8, bool); 16],
    pub fin_count: usize,
    pub parse_tsc: u64,
    pub decrypt_tsc: u64,
    pub classify_tsc: u64,
    pub scatter_tsc: u64,
    pub tun_write_tsc: u64,
    pub handshake_ok: u64,
    pub handshake_fail: u64,
    pub direction_fail: u64,
    pub pqc_drain: u64,
}