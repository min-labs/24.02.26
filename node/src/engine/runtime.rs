// M13 NODE — ENGINE: RUNTIME MODULE
// Infrastructure: fatal exit, TSC fast clock, hexdump, and peer session state.
// Node uses UDP sockets (no AF_XDP) — no slab allocator, no SHM telemetry.

use std::time::Duration;
use ring::aead;

// ============================================================================
// PEER STATE — Session FSM
// ============================================================================

#[derive(Debug)]
pub enum NodeState {
    Disconnected,
    Registering,
    Handshaking {
        dk_bytes: Vec<u8>,
        session_nonce: [u8; 32],
        client_hello_bytes: Vec<u8>,
        our_pk: Vec<u8>,
        our_sk: Vec<u8>,
        started_ns: u64,
    },
    Established {
        session_key: [u8; 32],
        cipher: Box<aead::LessSafeKey>,
        frame_count: u64,
        established_ns: u64,
    },
}

// ============================================================================
// TSC FAST CLOCK
// ============================================================================

#[inline(always)]
pub fn clock_ns() -> u64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: FFI call with valid mutable reference to timespec.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

/// TSC-to-nanosecond calibration data. Computed once at boot, immutable after.
/// Conversion: ns = mono_base + ((rdtsc() - tsc_base) * mult) >> shift
/// The mult/shift pair encodes ns_per_tsc_tick as a fixed-point fraction.
#[derive(Clone, Copy)]
pub struct TscCal {
    pub tsc_base: u64,
    pub mono_base: u64,
    pub mult: u32,
    pub shift: u32,
    pub valid: bool,
}

impl TscCal {
    pub fn fallback() -> Self {
        TscCal { tsc_base: 0, mono_base: 0, mult: 0, shift: 0, valid: false }
    }
}

/// Raw TSC read. ~24 cycles on Skylake (~6.5ns at 3.7GHz).
#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub fn read_tsc() -> u64 {
    let lo: u32;
    let hi: u32;
    // SAFETY: Inline asm for TSC read or prefetch; no memory safety invariants beyond valid register use.
    unsafe {
        core::arch::asm!(
            "rdtsc",
            out("eax") lo,
            out("edx") hi,
            options(nostack, nomem, preserves_flags)
        );
    }
    ((hi as u64) << 32) | (lo as u64)
}

/// ARM equivalent: CNTVCT_EL0 (generic timer virtual count).
#[cfg(target_arch = "aarch64")]
#[inline(always)]
pub fn read_tsc() -> u64 {
    let cnt: u64;
    // SAFETY: Inline asm for TSC read or prefetch; no memory safety invariants beyond valid register use.
    unsafe {
        core::arch::asm!(
            "mrs {cnt}, CNTVCT_EL0",
            cnt = out(reg) cnt,
            options(nostack, nomem, preserves_flags)
        );
    }
    cnt
}

/// Fallback for non-x86/ARM: just use clock_gettime.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[inline(always)]
pub fn read_tsc() -> u64 { clock_ns() }

/// Convert raw TSC value to nanoseconds using pre-computed calibration.
/// Hot path: 1 subtract + 1 multiply (u128) + 1 shift + 1 add = ~5 cycles.
#[inline(always)]
pub fn rdtsc_ns(cal: &TscCal) -> u64 {
    if !cal.valid { return clock_ns(); }
    let delta = read_tsc().wrapping_sub(cal.tsc_base);
    cal.mono_base.wrapping_add(
        ((delta as u128 * cal.mult as u128) >> cal.shift) as u64
    )
}

/// Calibrate TSC against CLOCK_MONOTONIC. Two-point calibration over 100ms.
pub fn calibrate_tsc() -> TscCal {
    // Check invariant TSC support (CPUID leaf 0x80000007, bit 8)
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: Inline asm for TSC read or prefetch; no memory safety invariants beyond valid register use.
        let has_invariant_tsc = unsafe {
            let result: u32;
            core::arch::asm!(
                "push rbx",
                "mov eax, 0x80000007",
                "cpuid",
                "pop rbx",
                out("edx") result,
                out("eax") _,
                out("ecx") _,
                options(nomem)
            );
            (result >> 8) & 1 == 1
        };
        if !has_invariant_tsc {
            eprintln!("[M13-TSC] WARNING: CPU lacks invariant TSC. Using clock_gettime fallback.");
            return TscCal::fallback();
        }
    }

    // Warm up caches: 100 iterations (discard results)
    for _ in 0..100 {
        let _ = read_tsc();
        let _ = clock_ns();
    }

    // Two-point calibration over 100ms
    let tsc0 = read_tsc();
    let mono0 = clock_ns();
    std::thread::sleep(Duration::from_millis(100));
    let tsc1 = read_tsc();
    let mono1 = clock_ns();

    let tsc_delta = tsc1.wrapping_sub(tsc0);
    let mono_delta = mono1.saturating_sub(mono0);

    if tsc_delta == 0 || mono_delta == 0 {
        eprintln!("[M13-TSC] WARNING: TSC calibration failed (zero delta). Using fallback.");
        return TscCal::fallback();
    }

    // Compute ns_per_tick as fixed-point: mult / 2^shift
    let shift: u32 = 32;
    let mult = ((mono_delta as u128) << shift) / (tsc_delta as u128);
    if mult > u32::MAX as u128 {
        eprintln!("[M13-TSC] WARNING: TSC frequency too low for u32 mult. Using fallback.");
        return TscCal::fallback();
    }
    let mult = mult as u32;

    // Snapshot the base point for conversion
    let tsc_base = read_tsc();
    let mono_base = clock_ns();

    let cal = TscCal { tsc_base, mono_base, mult, shift, valid: true };

    // Validation: compare rdtsc_ns() vs clock_ns() over 1000 samples.
    let mut max_error: i64 = 0;
    for _ in 0..1000 {
        let tsc_time = rdtsc_ns(&cal) as i64;
        let mono_time = clock_ns() as i64;
        let err = (tsc_time - mono_time).abs();
        if err > max_error { max_error = err; }
    }

    let tsc_freq_mhz = (tsc_delta as u128 * 1000) / (mono_delta as u128);
    eprintln!("[M13-TSC] Calibrated: freq={}.{}MHz mult={} shift={} max_err={}ns",
        tsc_freq_mhz / 1000, tsc_freq_mhz % 1000, mult, shift, max_error);

    if max_error > 1000 {
        eprintln!("[M13-TSC] WARNING: Calibration error {}ns > 1µs. Using clock_gettime fallback.", max_error);
        return TscCal::fallback();
    }

    cal
}

// Fatal error codes
pub const E_UMEM_ALLOC_FAIL: i32 = 0x14;

/// Structured fatal exit. Identical semantics to Hub version — writev atomicity.
#[inline(never)]
pub fn fatal(code: i32, msg: &str) -> ! {
    let prefix = b"[M13-NODE FATAL 0x";
    let hex = [
        b"0123456789ABCDEF"[((code >> 4) & 0xF) as usize],
        b"0123456789ABCDEF"[(code & 0xF) as usize],
    ];
    let suffix = b"] ";
    let newline = b"\n";
    let iov = [
        libc::iovec { iov_base: prefix.as_ptr() as *mut _, iov_len: prefix.len() },
        libc::iovec { iov_base: hex.as_ptr() as *mut _, iov_len: 2 },
        libc::iovec { iov_base: suffix.as_ptr() as *mut _, iov_len: suffix.len() },
        libc::iovec { iov_base: msg.as_ptr() as *mut _, iov_len: msg.len() },
        libc::iovec { iov_base: newline.as_ptr() as *mut _, iov_len: 1 },
    ];
    // SAFETY: Caller ensures invariants documented at module level.
    unsafe { libc::writev(2, iov.as_ptr(), 5); }
    std::process::exit(code);
}

// ============================================================================
// HEXDUMP ENGINE (rate-limited wire inspection)
// ============================================================================

const HEXDUMP_INTERVAL_NS: u64 = 100_000_000; // 10/sec max

pub struct HexdumpState { pub enabled: bool, last_tx_ns: u64, last_rx_ns: u64 }
impl HexdumpState {
    pub fn new(enabled: bool) -> Self { HexdumpState { enabled, last_tx_ns: 0, last_rx_ns: 0 } }
    pub fn dump_tx(&mut self, data: &[u8], now_ns: u64) {
        if !self.enabled || now_ns.saturating_sub(self.last_tx_ns) < HEXDUMP_INTERVAL_NS { return; }
        self.last_tx_ns = now_ns;
        dump_frame("[NODE-TX]", data);
    }
    pub fn dump_rx(&mut self, data: &[u8], now_ns: u64) {
        if !self.enabled || now_ns.saturating_sub(self.last_rx_ns) < HEXDUMP_INTERVAL_NS { return; }
        self.last_rx_ns = now_ns;
        dump_frame("[NODE-RX]", data);
    }
}

#[allow(clippy::needless_range_loop)]
fn dump_frame(label: &str, data: &[u8]) {
    use crate::engine::protocol::{M13Header, ETH_HDR_SIZE, M13_HDR_SIZE};
    let cap = data.len().min(80);
    if cap < ETH_HDR_SIZE { return; }
    let dst = format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        data[0], data[1], data[2], data[3], data[4], data[5]);
    let src = format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        data[6], data[7], data[8], data[9], data[10], data[11]);
    let (seq, flags) = if cap >= ETH_HDR_SIZE + M13_HDR_SIZE {
        // SAFETY: Pointer cast within slice bounds; offset validated by length check above.
        let m13 = unsafe { &*(data.as_ptr().add(ETH_HDR_SIZE) as *const M13Header) };
        (m13.seq_id, m13.flags)
    } else { (0, 0) };
    eprintln!("{} seq={} flags=0x{:02X} len={} dst={} src={}", label, seq, flags, data.len(), dst, src);
    if cap >= 14 {
        eprint!("  [00..14] ETH  |"); for i in 0..14 { eprint!(" {:02X}", data[i]); } eprintln!();
    }
    if cap >= 16 {
        eprint!("  [14..16] MAGIC|"); eprint!(" {:02X} {:02X}", data[14], data[15]); eprintln!();
    }
    if cap >= 18 {
        eprint!("  [16..18] CRYPT|"); eprint!(" {:02X} {:02X}", data[16], data[17]);
        eprintln!("  (crypto_ver=0x{:02X}={})", data[16], if data[16] == 0 { "cleartext" } else { "encrypted" });
    }
    if cap >= 34 {
        eprint!("  [18..34] MAC  |"); for i in 18..34 { eprint!(" {:02X}", data[i]); } eprintln!();
    }
    if cap >= 46 {
        eprint!("  [34..46] NONCE|"); for i in 34..46 { eprint!(" {:02X}", data[i]); } eprintln!();
    }
    if cap >= 54 {
        eprint!("  [46..54] SEQ  |"); for i in 46..54 { eprint!(" {:02X}", data[i]); }
        eprintln!("  (LE: seq_id={})", seq);
    }
    if cap >= 55 { eprintln!("  [54..55] FLAGS| {:02X}", data[54]); }
    if cap >= 59 {
        let plen = if cap >= ETH_HDR_SIZE + M13_HDR_SIZE {
            // SAFETY: Pointer cast within slice bounds; offset validated by length check above.
            let m13 = unsafe { &*(data.as_ptr().add(ETH_HDR_SIZE) as *const M13Header) };
            m13.payload_len
        } else { 0 };
        eprint!("  [55..59] PLEN |"); for i in 55..59 { eprint!(" {:02X}", data[i]); }
        eprintln!("  (LE: payload_len={})", plen);
    }
    if cap >= 62 {
        eprint!("  [59..62] PAD  |"); for i in 59..62 { eprint!(" {:02X}", data[i]); } eprintln!();
    }
}

