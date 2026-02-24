// M13 NODE — Orchestrator

mod engine;
mod cryptography;
mod network;

use crate::engine::protocol::*;
use crate::engine::protocol::{Assembler, FragHeader, FRAG_HDR_SIZE, send_fragmented_udp,
    alloc_asm_arena, ASM_SLOTS_PER_PEER};
use crate::engine::runtime::{
    rdtsc_ns, calibrate_tsc,
    fatal, NodeState, HexdumpState};
use crate::cryptography::aead::{seal_frame, open_frame};
use crate::network::datapath::{create_tun, setup_tunnel_routes, teardown_tunnel_routes, nuke_cleanup};
use crate::cryptography::handshake::{initiate_handshake, process_handshake_node};
use crate::network::uso_pacer::USO_MTU;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::net::UdpSocket;
use std::os::unix::io::AsRawFd;

use ring::aead;

static SHUTDOWN: AtomicBool = AtomicBool::new(false);
extern "C" fn signal_handler(_sig: i32) { SHUTDOWN.store(true, Ordering::Relaxed); }

/// Global Hub IP for panic hook cleanup. Set once before worker starts.
static HUB_IP_GLOBAL: Mutex<String> = Mutex::new(String::new());

/// Nuclear cleanup: tear down EVERYTHING — routes, TUN, IPv6, iptables.
/// Safe to call multiple times (idempotent). Safe to call from panic hook.
fn nuke_cleanup_node() {
    nuke_cleanup(&HUB_IP_GLOBAL);
}

// ── MAIN ───────────────────────────────────────────────────────────────────
fn main() {
    // Logs go to terminal (stderr)

    let args: Vec<String> = std::env::args().collect();
    // SAFETY: Caller ensures invariants documented at module level.
    unsafe {
        libc::signal(libc::SIGTERM, signal_handler as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, signal_handler as *const () as libc::sighandler_t);
    }

    // Panic hook: guarantee cleanup even on unwinding crash
    std::panic::set_hook(Box::new(|info| {
        eprintln!("[M13-NODE] PANIC: {}", info);
        nuke_cleanup_node();
        std::process::exit(1);
    }));

    let echo = args.iter().any(|a| a == "--echo");
    let hexdump = args.iter().any(|a| a == "--hexdump");
    let tunnel = args.iter().any(|a| a == "--tunnel");

    // Create TUN interface if requested
    // Note: MUST be done before dropping privileges (if any)
    let tun_file = if tunnel {
        Some(create_tun("m13tun0").expect("Failed to create TUN interface"))
    } else {
        None
    };

    // Parse --hub-ip <ip:port> (required)
    let mut hub_ip = None;
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--hub-ip" && i + 1 < args.len() {
            hub_ip = Some(args[i+1].clone());
        }
        i += 1;
    }

    if let Some(ip) = hub_ip {
        // Store Hub IP globally so panic hook can tear down routes
        if let Ok(mut g) = HUB_IP_GLOBAL.lock() {
            *g = ip.split(':').next().unwrap_or(&ip).to_string();
        }
        run_uring_worker(&ip, echo, hexdump, tun_file);
    } else {
         eprintln!("Usage: m13-node --hub-ip <ip:port> [--echo] [--hexdump] [--tunnel]");
         std::process::exit(1);
    }

    // Post-worker cleanup: nuke everything
    nuke_cleanup_node();
}



/// What the transport-specific caller should do after shared RX processing.
enum RxAction {
    /// Drop the frame (invalid, failed AEAD, or consumed internally).
    Drop,
    /// Tunnel data: write payload at (start, len) to TUN device.
    TunWrite { start: usize, plen: usize },
    /// Echo: caller should build echo response using the frame.
    Echo,
    /// Handshake complete: send Finished payload, transition to Established.
    HandshakeComplete { session_key: [u8; 32], finished_payload: Vec<u8> },
    /// Handshake failed: transition to Disconnected.
    HandshakeFailed,
    /// Rekey needed: transition to Registering.
    RekeyNeeded,
    /// Registration trigger: caller should initiate handshake.
    NeedHandshakeInit,
}

/// Shared RX frame processing for both UDP and AF_XDP workers.
/// Handles: M13 validation, AEAD decrypt, rekey, flag re-read,
/// fragment reassembly, handshake processing, classify.
///
/// The frame must include the ETH header at offset 0 and M13 at ETH_HDR_SIZE.
/// For UDP, the outer UDP/IP headers are stripped before calling this.
fn process_rx_frame(
    buf: &mut [u8],
    state: &mut NodeState,
    assembler: &mut Assembler,
    _hexdump: &mut HexdumpState,
    now: u64,
    echo: bool,
    aead_fail_count: &mut u64,
) -> RxAction {
    let len = buf.len();

    if len < ETH_HDR_SIZE + M13_HDR_SIZE {
        return RxAction::Drop;
    }

    // SAFETY: Pointer arithmetic within UMEM bounds; offset validated by kernel ring descriptor.
    let m13 = unsafe { &*(buf.as_ptr().add(ETH_HDR_SIZE) as *const M13Header) };
    if m13.signature[0] != M13_WIRE_MAGIC || m13.signature[1] != M13_WIRE_VERSION {
        return RxAction::Drop;
    }

    // Registration trigger: initiate handshake on first valid Hub frame
    if matches!(state, NodeState::Registering) {
        return RxAction::NeedHandshakeInit;
    }

    // Initial flags (may be ciphertext — will re-read after decrypt)
    let flags_pre = m13.flags;

    // Pre-decrypted by batch AEAD — skip both decrypt and cleartext-reject.
    // PRE_DECRYPTED_MARKER (0x02) is stamped by decrypt_batch_ptrs on success.
    let pre_decrypted = buf[ETH_HDR_SIZE + 2] == crate::cryptography::aead::PRE_DECRYPTED_MARKER;

    if !pre_decrypted {
        // Mandatory encryption — reject cleartext data after session
        // Exempt: handshakes, fragments, and control frames (FIN/keepalive)
        if matches!(state, NodeState::Established { .. })
           && buf[ETH_HDR_SIZE + 2] != 0x01
           && flags_pre & FLAG_HANDSHAKE == 0 && flags_pre & FLAG_FRAGMENT == 0
           && flags_pre & FLAG_CONTROL == 0 {
            return RxAction::Drop; // drop cleartext data frame
        }

        // AEAD verification on encrypted frames (scalar fallback for non-batched frames)
        if buf[ETH_HDR_SIZE + 2] == 0x01 {
            if let NodeState::Established { ref cipher, ref mut frame_count, ref established_ns, .. } = state {
                if !open_frame(buf, cipher, DIR_NODE_TO_HUB) {
                    *aead_fail_count += 1;
                    if cfg!(debug_assertions) && *aead_fail_count <= 3 {
                        eprintln!("[M13-NODE-AEAD] FAIL #{} len={} nonce={:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}:{:02x}{:02x}{:02x}{:02x}",
                            aead_fail_count, len,
                            buf[ETH_HDR_SIZE+20], buf[ETH_HDR_SIZE+21], buf[ETH_HDR_SIZE+22], buf[ETH_HDR_SIZE+23],
                            buf[ETH_HDR_SIZE+24], buf[ETH_HDR_SIZE+25], buf[ETH_HDR_SIZE+26], buf[ETH_HDR_SIZE+27],
                            buf[ETH_HDR_SIZE+28], buf[ETH_HDR_SIZE+29], buf[ETH_HDR_SIZE+30], buf[ETH_HDR_SIZE+31]);
                    }
                    return RxAction::Drop;
                }
                *frame_count += 1;

                // Rekey check — frame count or time limit
                if *frame_count >= REKEY_FRAME_LIMIT
                   || now.saturating_sub(*established_ns) > REKEY_TIME_LIMIT_NS {
                    eprintln!("[M13-NODE-PQC] Rekey threshold reached. Re-initiating handshake.");
                    return RxAction::RekeyNeeded;
                }
            } else {
                return RxAction::Drop; // encrypted frame but no session
            }
        }
    }
    // pre_decrypted frames: batch decrypt already verified AEAD, incremented
    // frame_count, and checked rekey. Proceed directly to flag re-read + classify.

    // CRITICAL: Re-read flags from decrypted buffer.
    // Original flags were read BEFORE decrypt — they hold ciphertext.
    let flags = buf[ETH_HDR_SIZE + 40];

    // Fragment handling
    if flags & FLAG_FRAGMENT != 0 && len >= ETH_HDR_SIZE + M13_HDR_SIZE + FRAG_HDR_SIZE {
        // SAFETY: Pointer arithmetic within valid bounds.
        let frag_hdr = unsafe { &*(buf.as_ptr().add(ETH_HDR_SIZE + M13_HDR_SIZE) as *const FragHeader) };
        // SAFETY: Using read_unaligned because FragHeader is repr(C, packed).
        let frag_msg_id = unsafe { std::ptr::addr_of!(frag_hdr.frag_msg_id).read_unaligned() };
        let frag_index = unsafe { std::ptr::addr_of!(frag_hdr.frag_index).read_unaligned() };
        let frag_total = unsafe { std::ptr::addr_of!(frag_hdr.frag_total).read_unaligned() };
        let frag_offset = unsafe { std::ptr::addr_of!(frag_hdr.frag_offset).read_unaligned() };
        let frag_data_len = unsafe { std::ptr::addr_of!(frag_hdr.frag_len).read_unaligned() } as usize;
        let frag_start = ETH_HDR_SIZE + M13_HDR_SIZE + FRAG_HDR_SIZE;
        if frag_start + frag_data_len <= len {
            // Closure IoC: capture action as Option, set inside closure on completion
            let mut action: Option<RxAction> = None;
            let has_handshake = flags & FLAG_HANDSHAKE != 0;
            assembler.feed(
                frag_msg_id, frag_index, frag_total, frag_offset,
                &buf[frag_start..frag_start + frag_data_len], now,
                |reassembled| {
                    if has_handshake {
                        eprintln!("[M13-NODE] Reassembled handshake msg_id={} len={}",
                            frag_msg_id, reassembled.len());
                        // Make-Before-Break: If we've already transitioned past Handshaking
                        // (Established, Disconnected, Registering), a reassembled handshake
                        // message is a stale retransmit from a previous epoch. Silently
                        // discard it — do NOT tear down the active session.
                        if !matches!(state, NodeState::Handshaking { .. }) {
                            if cfg!(debug_assertions) {
                                eprintln!("[M13-NODE-PQC] Discarding stale handshake retransmit (state={:?})",
                                    std::mem::discriminant(state));
                            }
                            // No action — falls through to Drop
                        } else if let Some((session_key, finished_payload)) = process_handshake_node(reassembled, state) {
                            action = Some(RxAction::HandshakeComplete { session_key, finished_payload });
                        } else {
                            // Genuine crypto failure while in Handshaking state
                            action = Some(RxAction::HandshakeFailed);
                        }
                    } else if cfg!(debug_assertions) {
                        eprintln!("[M13-NODE] Reassembled data msg_id={} len={}",
                            frag_msg_id, reassembled.len());
                    }
                },
            );
            if let Some(a) = action { return a; }
        }
        return RxAction::Drop; // Fragment consumed (or partial)
    }

    // Control frame — consume
    if flags & FLAG_CONTROL != 0 {
        return RxAction::Drop;
    }

    // Tunnel data → TUN write
    if flags & FLAG_TUNNEL != 0 {
        let start = ETH_HDR_SIZE + M13_HDR_SIZE;
        let plen_bytes = &buf[55..59];
        let plen = u32::from_le_bytes(plen_bytes.try_into().unwrap()) as usize;
        if start + plen <= len {
            return RxAction::TunWrite { start, plen };
        }
        return RxAction::Drop;
    }

    // Echo
    if echo && matches!(state, NodeState::Established { .. }) {
        return RxAction::Echo;
    }

    RxAction::Drop
}

/// Read a sysctl value from /proc/sys (e.g. "net.core.rmem_max" → "/proc/sys/net/core/rmem_max").
fn read_sysctl(key: &str) -> Option<String> {
    let path = format!("/proc/sys/{}", key.replace('.', "/"));
    std::fs::read_to_string(&path).ok().map(|s| s.trim().to_string())
}

/// Apply a sysctl and verify it took effect. Returns true if verified.
fn apply_sysctl(key: &str, value: &str) -> bool {
    let arg = format!("{}={}", key, value);
    let _ = std::process::Command::new("sysctl").args(["-w", &arg]).output();
    // Read back to verify
    match read_sysctl(key) {
        Some(actual) => actual == value,
        None => false,
    }
}

/// Pre-flight system tuning — applied once per startup (requires root).
/// Symmetric counterpart: Hub does the same in `setup_nat()`.
fn tune_system_buffers() {
    eprintln!("[M13-TUNE] Applying kernel + NIC tuning...");
    let mut ok = 0u32;
    let mut fail = 0u32;

    // 1. WiFi power save off — eliminates 20-100ms wake latency on RX.
    //    Auto-detect wireless interface from /sys/class/net/*/wireless.
    if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let iface = name.to_string_lossy().to_string();
            let wireless_path = format!("/sys/class/net/{}/wireless", iface);
            if std::path::Path::new(&wireless_path).exists() {
                let r = std::process::Command::new("iw")
                    .args(["dev", &iface, "set", "power_save", "off"]).output();
                if r.map(|o| o.status.success()).unwrap_or(false) {
                    eprintln!("[M13-TUNE] WiFi power_save OFF on {}", iface);
                    ok += 1;
                } else {
                    eprintln!("[M13-TUNE] WARN: WiFi power_save off failed on {}", iface);
                    fail += 1;
                }
            }
        }
    }

    // 2. Socket buffer ceiling
    for (k, v) in [
        ("net.core.rmem_max", "8388608"), ("net.core.wmem_max", "8388608"),
        ("net.core.rmem_default", "4194304"), ("net.core.wmem_default", "4194304"),
    ] { if apply_sysctl(k, v) { ok += 1; } else { fail += 1; eprintln!("[M13-TUNE] WARN: {} failed", k); } }

    // 3. NAPI budget
    for (k, v) in [("net.core.netdev_budget", "600"), ("net.core.netdev_budget_usecs", "8000")] {
        if apply_sysctl(k, v) { ok += 1; } else { fail += 1; eprintln!("[M13-TUNE] WARN: {} failed", k); }
    }

    // 4. Backlog queue
    if apply_sysctl("net.core.netdev_max_backlog", "10000") { ok += 1; } else { fail += 1; }

    // 5. BBR congestion control
    if apply_sysctl("net.ipv4.tcp_congestion_control", "bbr") { ok += 1; } else { fail += 1; eprintln!("[M13-TUNE] WARN: BBR not available"); }

    // 6. Don't cache stale TCP metrics
    if apply_sysctl("net.ipv4.tcp_no_metrics_save", "1") { ok += 1; } else { fail += 1; }

    // 7. MTU probing (mode 1 = probe on black hole detection)
    if apply_sysctl("net.ipv4.tcp_mtu_probing", "1") { ok += 1; } else { fail += 1; }

    if fail == 0 {
        eprintln!("[M13-TUNE] ✓ Optimisation Applied ({} sysctls verified)", ok);
    } else {
        eprintln!("[M13-TUNE] ⚠ Optimisation Partial ({}/{} applied, {} failed)", ok, ok + fail, fail);
    }
}



// ── EDT-Gated Deferred TX Ring ─────────────────────────────────────────
// Same-thread SPSC ring (single-producer/single-consumer, no atomics needed).
// Holds frames for EDT-gated submission: frames are pushed with release_ns,
// drained at loop tail when release_ns <= now.
// Prevents WiFi micro-burst DMA flooding — the Node-side equivalent of
// the Hub's Scheduler::schedule() EDT gating.

/// A single deferred TX entry: frame pointer, length, Buffer ID, and
/// the EDT release timestamp from EdtPacer::pace().
#[derive(Clone, Copy)]
struct DeferredTxEntry {
    frame_ptr: *mut u8,
    frame_len: u32,
    bid: u16,
    release_ns: u64,
}

impl DeferredTxEntry {
    const EMPTY: Self = DeferredTxEntry {
        frame_ptr: std::ptr::null_mut(),
        frame_len: 0,
        bid: 0,
        release_ns: 0,
    };
}

/// Fixed-capacity circular buffer for EDT-gated TX deferral.
/// Capacity MUST be power-of-two for branchless masking.
const DEFERRED_TX_CAPACITY: usize = 64;

struct DeferredTxRing {
    entries: [DeferredTxEntry; DEFERRED_TX_CAPACITY],
    head: usize,  // consumer index (drain)
    tail: usize,  // producer index (push)
}

impl DeferredTxRing {
    fn new() -> Self {
        DeferredTxRing {
            entries: [DeferredTxEntry::EMPTY; DEFERRED_TX_CAPACITY],
            head: 0,
            tail: 0,
        }
    }

    /// Number of entries currently in the ring.
    #[inline(always)]
    fn len(&self) -> usize {
        self.tail.wrapping_sub(self.head)
    }

    /// Returns true if the ring is full.
    #[inline(always)]
    fn is_full(&self) -> bool {
        self.len() >= DEFERRED_TX_CAPACITY
    }

    /// Push a deferred TX entry. Returns false if ring is full.
    #[inline(always)]
    fn push(&mut self, frame_ptr: *mut u8, frame_len: u32, bid: u16, release_ns: u64) -> bool {
        if self.is_full() {
            return false;
        }
        let slot = self.tail & (DEFERRED_TX_CAPACITY - 1);
        self.entries[slot] = DeferredTxEntry { frame_ptr, frame_len, bid, release_ns };
        self.tail = self.tail.wrapping_add(1);
        true
    }

    /// Peek at the head entry's release_ns without consuming.
    /// Returns u64::MAX if the ring is empty.
    #[inline(always)]
    fn peek_release_ns(&self) -> u64 {
        if self.head == self.tail { return u64::MAX; }
        let slot = self.head & (DEFERRED_TX_CAPACITY - 1);
        self.entries[slot].release_ns
    }

    /// Pop the head entry. Caller must check len() > 0 first.
    #[inline(always)]
    fn pop(&mut self) -> DeferredTxEntry {
        let slot = self.head & (DEFERRED_TX_CAPACITY - 1);
        let entry = self.entries[slot];
        self.head = self.head.wrapping_add(1);
        entry
    }
}

// ── io_uring SQPOLL Worker (R-02B: Zero-Syscall Datapath) ──────────────
// Replaces run_udp_worker. Uses UringReactor for ALL network I/O.
// CQE-driven event loop: multishot recv for UDP RX, staged SQEs for TX.
// EDT pacing via DeferredTxRing: frames are paced then deferred,
// drained at loop tail when release_ns <= now.
fn run_uring_worker(hub_addr: &str, echo: bool, hexdump_mode: bool, tun: Option<std::fs::File>) {
    use crate::network::uring_reactor::*;

    let cal = calibrate_tsc();
    tune_system_buffers();

    // ── EDT Pacer Initialization ──────────────────────────────
    // Default: 100 Mbps WiFi MANET link rate (matches Hub's default).
    // Override via --link-bps <bps> CLI parameter for set_link_bps wiring.
    let link_bps_default: u64 = 100_000_000; // 100 Mbps
    let cli_link_bps: u64 = {
        let args: Vec<String> = std::env::args().collect();
        let mut bps = link_bps_default;
        let mut i = 1;
        while i < args.len() {
            if args[i] == "--link-bps" && i + 1 < args.len() {
                bps = args[i + 1].parse::<u64>().unwrap_or(link_bps_default);
            }
            i += 1;
        }
        bps
    };
    let mut edt_pacer = crate::network::uso_pacer::EdtPacer::new(&cal, cli_link_bps);
    if cli_link_bps != link_bps_default {
        // Wire set_link_bps: CLI override applied.
        edt_pacer.set_link_bps(cli_link_bps);
        eprintln!("[M13-NODE-EDT] Link rate override: {} bps ({}ns/byte)",
            cli_link_bps, edt_pacer.ns_per_byte());
    } else {
        eprintln!("[M13-NODE-EDT] EdtPacer initialized: {} bps ({}ns/byte). Override with --link-bps.",
            cli_link_bps, edt_pacer.ns_per_byte());
    }
    let mut deferred_tx = DeferredTxRing::new();
    let mut last_tx_activity_ns: u64 = 0; // For idle detection → pacer reset

    // UDP socket — connected mode for sendto-free operation
    let sock = UdpSocket::bind("0.0.0.0:0")
        .unwrap_or_else(|_| fatal(0x30, "UDP bind failed"));
    sock.connect(hub_addr)
        .unwrap_or_else(|_| fatal(0x31, "UDP connect failed"));

    let raw_fd = sock.as_raw_fd();
    unsafe {
        let flags = libc::fcntl(raw_fd, libc::F_GETFL);
        libc::fcntl(raw_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        let buf_sz: libc::c_int = 8 * 1024 * 1024;
        libc::setsockopt(raw_fd, libc::SOL_SOCKET, libc::SO_RCVBUFFORCE,
            &buf_sz as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t);
        libc::setsockopt(raw_fd, libc::SOL_SOCKET, libc::SO_SNDBUFFORCE,
            &buf_sz as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t);
    }

    let hub_ip = hub_addr.split(':').next().unwrap_or(hub_addr).to_string();

    // Initialize io_uring reactor (SQPOLL on CPU 0)
    let mut reactor = UringReactor::new(raw_fd, 0);
    eprintln!("[M13-NODE-URING] io_uring PBR reactor initialized. SQPOLL active.");

    // TUN fd for io_uring ops
    let tun_fd: i32 = tun.as_ref().map(|f| f.as_raw_fd()).unwrap_or(-1);

    // Arm initial TUN reads using BIDs in [UDP_RING_ENTRIES .. TOTAL_BIDS)
    if tun_fd >= 0 {
        for bid in UDP_RING_ENTRIES as u16..(UDP_RING_ENTRIES + TUN_RX_ENTRIES) as u16 {
            reactor.arm_tun_read(tun_fd, bid);
        }
        reactor.submit();
    }

    let mut seq_tx: u64 = 0;
    let mut rx_count: u64 = 0;
    let mut tx_count: u64 = 0;
    let mut aead_fail_count: u64 = 0;
    let mut aead_ok_count: u64 = 0;
    let mut tun_read_count: u64 = 0;
    let mut tun_write_count: u64 = 0;
    let mut rx_bytes: u64 = 0;
    let mut tx_bytes: u64 = 0;
    let mut prev_rx_bytes: u64 = 0;
    let mut prev_tx_bytes: u64 = 0;
    let mut hexdump = HexdumpState::new(hexdump_mode);
    let asm_arena = alloc_asm_arena(ASM_SLOTS_PER_PEER);
    let mut assembler = Assembler::init(asm_arena);
    let mut last_report_ns: u64 = rdtsc_ns(&cal);
    let mut last_keepalive_ns: u64 = 0;
    let mut gc_counter: u64 = 0;
    let mut routes_installed = false;
    let start_ns = rdtsc_ns(&cal);
    let src_mac: [u8; 6] = detect_mac(None);
    let hub_mac: [u8; 6] = [0xFF; 6];

    // Registration frame via legacy send (before main CQE loop)
    let reg = build_m13_frame(&src_mac, &hub_mac, seq_tx, FLAG_CONTROL);
    seq_tx += 1;
    if sock.send(&reg).is_ok() { tx_count += 1; }
    hexdump.dump_tx(&reg, rdtsc_ns(&cal));
    let mut state = NodeState::Registering;

    // Pre-built M13 header template for TUN TX path
    let mut hdr_template = [0u8; 62];
    hdr_template[0..6].copy_from_slice(&hub_mac);
    hdr_template[6..12].copy_from_slice(&src_mac);
    hdr_template[12] = (ETH_P_M13 >> 8) as u8;
    hdr_template[13] = (ETH_P_M13 & 0xFF) as u8;
    hdr_template[14] = M13_WIRE_MAGIC;
    hdr_template[15] = M13_WIRE_VERSION;

    eprintln!("[M13-NODE-URING] Connected to {}. Echo={} Hexdump={}", hub_addr, echo, hexdump_mode);

    loop {
        if SHUTDOWN.load(Ordering::Relaxed) { break; }
        let now = rdtsc_ns(&cal);

        // Connection timeout
        if !matches!(state, NodeState::Established { .. })
            && now.saturating_sub(start_ns) > 30_000_000_000 {
            eprintln!("[M13-NODE-URING] Connection timed out (30s). Exiting.");
            break;
        }

        // ══════════════════════════════════════════════════════════
        // VPP (Vector Packet Processing) — Three-Pass CQE Pipeline
        // Industry pattern (DPDK, FD.io/VPP, Cloudflare flowtrackd):
        //   Pass 0: Drain CQEs, classify (recv batch vs non-recv inline)
        //   Pass 1: Vectorized AEAD batch decrypt (4-at-a-time AES-NI)
        //   Pass 2: Per-frame process_rx_frame → RxAction dispatch
        // Never interleave classify → crypto → I/O. Each phase runs
        // over the full batch, keeping the functional unit thermally hot.
        // ══════════════════════════════════════════════════════════

        // ── Pass 0: CQE Drain + Classify ───────────────────────
        reactor.ring.completion().sync();
        const MAX_CQE: usize = 128;
        let mut cqe_batch: [(i32, u32, u64); MAX_CQE] = [(0, 0, 0); MAX_CQE];
        let mut cqe_count = 0usize;
        for cqe in reactor.ring.completion() {
            if cqe_count < MAX_CQE {
                cqe_batch[cqe_count] = (cqe.result(), cqe.flags(), cqe.user_data());
                cqe_count += 1;
            }
        }

        // Separate recv CQEs (batch-processable) from non-recv (handle inline)
        let mut recv_bids: [u16; MAX_CQE] = [0; MAX_CQE];
        let mut recv_lens: [usize; MAX_CQE] = [0; MAX_CQE];
        let mut recv_flags: [u32; MAX_CQE] = [0; MAX_CQE];
        let mut recv_count: usize = 0;
        let mut multishot_needs_rearm = false;

        for ci in 0..cqe_count {
            let (result, flags, user_data) = cqe_batch[ci];
            let tag = user_data & 0xFFFF_FFFF;
            let bid_from_ud = ((user_data >> 32) & 0xFFFF) as u16;

            match tag {
                TAG_UDP_RECV_MULTISHOT => {
                    if result <= 0 {
                        reactor.multishot_active = false;
                        multishot_needs_rearm = true;
                        continue;
                    }
                    let bid = if flags & IORING_CQE_F_BUFFER != 0 {
                        ((flags >> 16) & 0xFFFF) as u16
                    } else { continue; };

                    recv_bids[recv_count] = bid;
                    recv_lens[recv_count] = result as usize;
                    recv_flags[recv_count] = flags;
                    recv_count += 1;
                    rx_count += 1;
                    rx_bytes += result as u64;

                    if flags & IORING_CQE_F_MORE == 0 {
                        reactor.multishot_active = false;
                        multishot_needs_rearm = true;
                    }
                }

                // Non-recv CQEs: cheap, handle inline
                TAG_TUN_READ => {
                    if result <= 0 {
                        reactor.arm_tun_read(tun_fd, bid_from_ud);
                        continue;
                    }
                    // [P1-02] STRICT USO MTU CLAMPING
                    // Defensively clamp io_uring reads to 1380 bytes bounds.
                    // Ensures frame size mathematically never exceeds 1442 bytes.
                    let payload_len = (result as usize).min(USO_MTU);
                    tun_read_count += 1;
                    tx_bytes += (62 + payload_len) as u64;
                    let frame_base = unsafe {
                        reactor.arena_base_ptr().add((bid_from_ud as usize) * crate::network::uring_reactor::FRAME_SIZE)
                    };
                    let frame = unsafe {
                        std::slice::from_raw_parts_mut(frame_base, 62 + payload_len)
                    };
                    frame[0..46].copy_from_slice(&hdr_template[0..46]);
                    frame[46..54].copy_from_slice(&seq_tx.to_le_bytes());
                    frame[54] = FLAG_TUNNEL;
                    frame[55..59].copy_from_slice(&(payload_len as u32).to_le_bytes());
                    frame[59..62].copy_from_slice(&hdr_template[59..62]);
                    if let NodeState::Established { ref cipher, .. } = state {
                        seal_frame(frame, cipher, seq_tx, DIR_NODE_TO_HUB);
                    }
                    seq_tx += 1;

                    // EDT PACING: Compute earliest departure time for this frame.
                    // Instead of immediate stage_udp_send, defer to the ring.
                    // Loop tail drains when release_ns <= now — zero-spin gating.
                    let total_frame_len = (62 + payload_len) as u32;
                    let release_ns = edt_pacer.pace(now, total_frame_len);

                    if !deferred_tx.push(frame_base, total_frame_len, bid_from_ud, release_ns) {
                        // Ring full — backpressure: force-drain oldest to make room.
                        // This maintains pipeline liveness under burst load.
                        let forced = deferred_tx.pop();
                        reactor.stage_udp_send(
                            forced.frame_ptr, forced.frame_len,
                            forced.bid, TAG_UDP_SEND_TUN,
                        );
                        tx_count += 1;
                        // Now push succeeds.
                        deferred_tx.push(frame_base, total_frame_len, bid_from_ud, release_ns);
                    }
                    last_tx_activity_ns = now;
                }

                TAG_TUN_WRITE => {
                    reactor.add_buffer_to_pbr(bid_from_ud);
                    reactor.commit_pbr();
                }

                TAG_UDP_SEND_ECHO | TAG_UDP_SEND_TUN => {
                    if tag == TAG_UDP_SEND_TUN && tun_fd >= 0 {
                        reactor.arm_tun_read(tun_fd, bid_from_ud);
                    }
                    reactor.submit();
                }

                _ => {}
            }
        }

        // ── Pass 1: Vectorized AEAD Batch Decrypt ──────────────
        // 4-at-a-time AES-NI/ARMv8-CE prefetch saturates crypto pipeline.
        // decrypt_one stamps PRE_DECRYPTED_MARKER (0x02) on success —
        // process_rx_frame recognizes it and skips both decrypt and
        // cleartext-reject. Failures keep 0x01 → scalar fallback.
        if recv_count > 0 {
            if let NodeState::Established { ref cipher, ref mut frame_count, ref established_ns, .. } = state {
                let mut enc_ptrs: [*mut u8; MAX_CQE] = [std::ptr::null_mut(); MAX_CQE];
                let mut enc_lens: [usize; MAX_CQE] = [0; MAX_CQE];
                let mut enc_count: usize = 0;

                for ri in 0..recv_count {
                    let bid = recv_bids[ri];
                    let len = recv_lens[ri];
                    let ptr = unsafe {
                        reactor.arena_base_ptr().add((bid as usize) * crate::network::uring_reactor::FRAME_SIZE)
                    };
                    // Encrypted frame: len >= ETH_HDR + 40, crypto flag == 0x01
                    if len >= ETH_HDR_SIZE + 40 {
                        let crypto_flag = unsafe { *ptr.add(ETH_HDR_SIZE + 2) };
                        if crypto_flag == 0x01 {
                            enc_ptrs[enc_count] = ptr;
                            enc_lens[enc_count] = len;
                            enc_count += 1;
                        }
                    }
                }

                if enc_count > 0 {
                    let mut decrypt_results = [false; MAX_CQE];
                    let ok = crate::cryptography::aead::decrypt_batch_ptrs(
                        &enc_ptrs, &enc_lens, enc_count, cipher, DIR_NODE_TO_HUB,
                        &mut decrypt_results[..enc_count],
                    );
                    *frame_count += ok as u64;
                    aead_ok_count += ok as u64;

                    // Rekey check after batch
                    if *frame_count >= REKEY_FRAME_LIMIT
                       || now.saturating_sub(*established_ns) > REKEY_TIME_LIMIT_NS {
                        eprintln!("[M13-NODE-PQC] Rekey threshold reached (batch). Re-initiating handshake.");
                        state = NodeState::Registering;
                    }
                }
            }
        }

        // ── Pass 2: Per-Frame RxAction Dispatch ────────────────
        // Frames with PRE_DECRYPTED_MARKER skip decrypt entirely.
        for ri in 0..recv_count {
            let bid = recv_bids[ri];
            let pkt_len = recv_lens[ri];

            let mut frame = reactor.get_frame(bid, pkt_len);
            let buf = frame.as_mut();

            hexdump.dump_rx(buf, now);

            if matches!(state, NodeState::Disconnected) {
                state = NodeState::Registering;
            }

            let action = process_rx_frame(buf, &mut state, &mut assembler,
                &mut hexdump, now, echo, &mut aead_fail_count);

            let mut bid_deferred = false;
            match action {
                RxAction::NeedHandshakeInit => {
                    state = initiate_handshake(
                        &sock, &src_mac, &hub_mac, &mut seq_tx, &mut hexdump, &cal,
                    );
                }
                RxAction::TunWrite { start, plen } => {
                    if tun_fd >= 0 {
                        let write_ptr = unsafe {
                            reactor.arena_base_ptr().add((bid as usize) * crate::network::uring_reactor::FRAME_SIZE + start)
                        };
                        reactor.stage_tun_write(tun_fd, write_ptr, plen as u32, bid);
                        reactor.submit();
                        tun_write_count += 1;
                        bid_deferred = true;
                    }
                }
                RxAction::Echo => {
                    if let Some(mut echo_frame) = build_echo_frame(buf, seq_tx) {
                        if let NodeState::Established { ref cipher, ref session_key, .. } = state {
                            if *session_key != [0u8; 32] {
                                seal_frame(&mut echo_frame, cipher, seq_tx, DIR_NODE_TO_HUB);
                            }
                        }
                        seq_tx += 1;
                        hexdump.dump_tx(&echo_frame, now);
                        if sock.send(&echo_frame).is_ok() { tx_count += 1; }
                    }
                }
                RxAction::HandshakeComplete { session_key, finished_payload } => {
                    let hs_flags = FLAG_CONTROL | FLAG_HANDSHAKE;
                    // DEFECT β FIXED: Closure captures sock, hexdump, tx_count.
                    let mut sent_frags = 0u64;
                    send_fragmented_udp(
                        &src_mac, &hub_mac,
                        &finished_payload, hs_flags,
                        &mut seq_tx,
                        |frame| {
                            hexdump.dump_tx(frame, now);
                            let _ = sock.send(frame);
                            tx_count += 1;
                            sent_frags += 1;
                        }
                    );
                    if cfg!(debug_assertions) {
                        eprintln!("[M13-NODE-PQC] Finished sent: {}B, {} fragments",
                            finished_payload.len(), sent_frags);
                    }
                    state = NodeState::Established {
                        session_key,
                        cipher: Box::new(aead::LessSafeKey::new(
                            aead::UnboundKey::new(&aead::AES_256_GCM, &session_key).unwrap()
                        )),
                        frame_count: 0,
                        established_ns: now,
                    };
                    if cfg!(debug_assertions) { eprintln!("[M13-NODE-PQC] → Established"); }
                    if tun.is_some() && !routes_installed {
                        setup_tunnel_routes(&hub_ip);
                        routes_installed = true;
                    }
                }
                RxAction::HandshakeFailed => {
                    eprintln!("[M13-NODE-PQC] Handshake failed → Disconnected");
                    state = NodeState::Disconnected;
                }
                RxAction::RekeyNeeded => {
                    state = NodeState::Registering;
                }
                RxAction::Drop => {}
            }

            if !bid_deferred {
                reactor.add_buffer_to_pbr(bid);
                reactor.commit_pbr();
            }
        }

        // Re-arm multishot recv if terminated (CQE_F_MORE==0)
        if multishot_needs_rearm {
            reactor.arm_multishot_recv();
        }

        // ── Handshake timeout ──────────────────────────────────
        if let NodeState::Handshaking { ref mut started_ns, ref client_hello_bytes, .. } = state {
            // SURGICAL PATCH: Replace 5-second constant with 250ms Micro-ARQ boundary.
            // Eradicates the 5-second dead-trap and ensures rapid retransmission.
            if now.saturating_sub(*started_ns) > HANDSHAKE_RETX_INTERVAL_NS {
                eprintln!("[M13-NODE-PQC] Handshake micro-timeout (250ms). Retransmitting...");

                let hs_flags = FLAG_CONTROL | FLAG_HANDSHAKE;
                let mut seq_cap = seq_tx;

                // Closure IoC execution prevents borrow checker collision
                send_fragmented_udp(
                    &src_mac, &hub_mac,
                    client_hello_bytes, hs_flags,
                    &mut seq_cap,
                    |frame| {
                        hexdump.dump_tx(frame, now);
                        let _ = sock.send(frame);
                        tx_count += 1;
                    }
                );

                seq_tx = seq_cap;
                *started_ns = now; // Reset timer without recomputing 10ms of NTT math
            }
        }

        // ── Keepalive (pre-Established only) ──────────────────
        if !matches!(state, NodeState::Established { .. })
            && (now.saturating_sub(last_keepalive_ns) > 100_000_000 || tx_count == 0) {
            last_keepalive_ns = now;
            let ka = build_m13_frame(&src_mac, &hub_mac, seq_tx, FLAG_CONTROL);
            seq_tx += 1;
            if sock.send(&ka).is_ok() { tx_count += 1; }
        }

        // ── Telemetry (1/sec) ─────────────────────────────────
        if now.saturating_sub(last_report_ns) > 1_000_000_000 {
            let state_label = match &state {
                NodeState::Registering => "Reg",
                NodeState::Handshaking { .. } => "HS",
                NodeState::Established { .. } => "Est",
                NodeState::Disconnected => "Disc",
            };
            let rx_kbps = (rx_bytes - prev_rx_bytes) * 8 / 1000;
            let tx_kbps = (tx_bytes - prev_tx_bytes) * 8 / 1000;
            prev_rx_bytes = rx_bytes;
            prev_tx_bytes = tx_bytes;
            eprintln!("[M13-N0] RX:{} TX:{} TUN_R:{} TUN_W:{} AEAD_OK:{} FAIL:{} State:{} Up:{}s DL:{}kbps UL:{}kbps EDT:paced={},defer={}",
                rx_count, tx_count, tun_read_count, tun_write_count, aead_ok_count, aead_fail_count, state_label,
                match &state { NodeState::Established { established_ns, .. } => (now - established_ns) / 1_000_000_000, _ => (now - start_ns) / 1_000_000_000 },
                rx_kbps, tx_kbps,
                edt_pacer.paced_count(), deferred_tx.len());
            last_report_ns = now;
            gc_counter += 1;
            if gc_counter.is_multiple_of(5) { assembler.gc(now); }

            // Idle detection: if no TX activity for >1s, reset pacer to prevent
            // burst-compensating all missed slots on next packet arrival.
            // Same pattern as Hub's EdtPacer usage — prevents stale last_tx_ns
            // from causing a burst of zero-delay departures after idle.
            if last_tx_activity_ns > 0 && now.saturating_sub(last_tx_activity_ns) > 1_000_000_000 {
                edt_pacer.reset(now);
                last_tx_activity_ns = 0;
            }
        }

        // ── EDT Deferred TX Drain ─────────────────────────────
        // Drain all entries whose release_ns <= now. EDT-gated: frames are
        // held until their computed departure time arrives, preventing WiFi
        // micro-burst DMA flooding. Monotonicity of pace() guarantees FIFO
        // ordering — once we hit a release_ns > now, all subsequent entries
        // are also in the future, so we stop.
        {
            let drain_now = rdtsc_ns(&cal);
            while deferred_tx.peek_release_ns() <= drain_now {
                let entry = deferred_tx.pop();
                reactor.stage_udp_send(
                    entry.frame_ptr, entry.frame_len,
                    entry.bid, TAG_UDP_SEND_TUN,
                );
                tx_count += 1;
            }
        }

        // Submit any pending SQEs (deferred TX + re-arms + TUN writes)
        reactor.submit();
        let _ = reactor.ring.submit_and_wait(0);
    }
    // Shutdown: flush all remaining deferred TX entries to prevent BID leaks.
    // Frames held in the ring own arena BIDs — submit them all regardless of release_ns.
    while deferred_tx.len() > 0 {
        let entry = deferred_tx.pop();
        reactor.stage_udp_send(
            entry.frame_ptr, entry.frame_len,
            entry.bid, TAG_UDP_SEND_TUN,
        );
        tx_count += 1;
    }
    reactor.submit();
    let _ = reactor.ring.submit_and_wait(0);

    if routes_installed {
        teardown_tunnel_routes(&hub_ip);
    }
    let final_up_s = match &state { NodeState::Established { established_ns, .. } => (rdtsc_ns(&cal) - established_ns) / 1_000_000_000, _ => (rdtsc_ns(&cal) - start_ns) / 1_000_000_000 };
    eprintln!("[M13-N0] Shutdown. RX:{} TX:{} TUN_R:{} TUN_W:{} AEAD_OK:{} FAIL:{} EDT:paced={} Up:{}s",
        rx_count, tx_count, tun_read_count, tun_write_count, aead_ok_count, aead_fail_count, edt_pacer.paced_count(), final_up_s);
}