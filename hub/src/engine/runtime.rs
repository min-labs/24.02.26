// M13 HUB — ENGINE: RUNTIME MODULE
// Infrastructure that supports the engine but isn't the protocol itself:
// fatal exit diagnostics, slab allocator, TSC fast clock, CPU management,
// telemetry (SHM counters + hexdump), and the cross-process monitor.

use std::ptr;
use std::mem;
use std::time::Duration;
use std::sync::atomic::{AtomicU32, AtomicU64};
use std::ffi::CString;
use libc::{
    mmap, shm_open, ftruncate, close,
    MAP_SHARED, PROT_READ, PROT_WRITE, MAP_FAILED,
    O_CREAT, O_RDWR, S_IRUSR, S_IWUSR,
    off_t,
};

// ============================================================================
// FATAL EXIT + DIAGNOSTIC ERROR CODES
// ============================================================================

// Convention: 0x10-0x1F = Boot, 0x20-0x2F = Runtime, 0x30-0x3F = Transport, 0x40-0x4F = Link

// Boot failures (engine refuses to start)
pub const E_NO_ISOLATED_CORES: i32  = 0x10;
pub const E_AFFINITY_FAIL: i32      = 0x11;
pub const E_AFFINITY_VERIFY: i32    = 0x13;
pub const E_UMEM_ALLOC_FAIL: i32    = 0x14;
pub const E_XSK_BIND_FAIL: i32      = 0x15;
pub const E_RING_SIZE_FAIL: i32     = 0x16;
pub const E_SHM_MAP_FAIL: i32       = 0x18;

/// Structured fatal exit. No heap allocation. No stack unwinding. No string formatting.
/// Writes fixed-format line to stderr via raw libc::write, then exits with code.
/// Output: "[M13 FATAL 0xHH] msg\n" (always ≤ 80 bytes on UART)
/// Uses writev() for atomicity — single syscall, no interleaving on concurrent fatals.
#[inline(never)]
pub fn fatal(code: i32, msg: &str) -> ! {
    let prefix = b"[M13 FATAL 0x";
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
    // SAFETY: writev(2, iov, 5) writes to stderr (fd 2, always open). All iov entries
    // point to stack-allocated byte arrays with correct lengths. No heap allocation.
    unsafe { libc::writev(2, iov.as_ptr(), 5); }
    std::process::exit(code);
}

// ============================================================================
// SLAB ALLOCATOR
// ============================================================================

/// Fixed-size stack-based slab allocator. O(1) alloc/free, zero branching on fast path.
/// Manages UMEM frame indices for AF_XDP zero-copy I/O.
#[repr(align(64))]
pub struct FixedSlab { stack: Box<[u32]>, top: usize, capacity: usize }
impl FixedSlab {
    pub fn new(capacity: usize) -> Self {
        let mut vec = Vec::with_capacity(capacity);
        for i in 0..capacity { vec.push(i as u32); }
        FixedSlab { stack: vec.into_boxed_slice(), top: capacity, capacity }
    }
    #[inline(always)] pub fn alloc(&mut self) -> Option<u32> {
        if self.top == 0 { return None; }
        self.top -= 1; // SAFETY: top was > 0, so top is now in [0..capacity), which is within stack bounds.
        unsafe { Some(*self.stack.get_unchecked(self.top)) }
    }
    // SAFETY: top < capacity guarantees top is valid index into stack.
    #[inline(always)] pub fn free(&mut self, idx: u32) {
        if self.top < self.capacity { unsafe { *self.stack.get_unchecked_mut(self.top) = idx; } self.top += 1; }
    }
    #[inline(always)] pub fn available(&self) -> usize { self.top }
}

// ============================================================================
// TSC FAST CLOCK
// Replaces clock_gettime(MONOTONIC) in the hot loop with raw rdtsc.
// Calibrated at boot against CLOCK_MONOTONIC. Fixed-point multiply+shift
// conversion — identical method to Linux kernel (arch/x86/kernel/tsc.c).
//
// Performance: rdtsc (~24 cycles) + conversion (~5 cycles) = ~29 cycles = ~7.8ns at 3.7GHz.
// Compare: clock_gettime vDSO = ~41 cycles = ~11-25ns.
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
    tsc_base: u64,
    mono_base: u64,
    pub(crate) mult: u32,
    pub(crate) shift: u32,
    valid: bool,
}

impl TscCal {
    /// Fallback calibration — rdtsc_ns() will call clock_ns() instead.
    pub fn fallback() -> Self {
        TscCal { tsc_base: 0, mono_base: 0, mult: 0, shift: 0, valid: false }
    }
}

/// Raw TSC read. ~24 cycles on Skylake (~6.5ns at 3.7GHz).
/// No serialization (lfence/rdtscp) — not needed for "what time is it?" queries.
/// OoO reordering error is ±2ns, irrelevant for 50µs deadlines.
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
/// Constant-rate, monotonic, unprivileged. Same calibration math applies.
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
/// Total with rdtsc: ~29 cycles = ~7.8ns at 3.7GHz.
#[inline(always)]
pub fn rdtsc_ns(cal: &TscCal) -> u64 {
    if !cal.valid { return clock_ns(); }
    let delta = read_tsc().wrapping_sub(cal.tsc_base);
    cal.mono_base.wrapping_add(
        ((delta as u128 * cal.mult as u128) >> cal.shift) as u64
    )
}

/// Two-point TSC calibration against CLOCK_MONOTONIC.
/// Runs for 100ms, comparing rdtsc deltas against kernel clock deltas.
/// Computes fixed-point mult/shift such that:
///   ns_per_tick = mult / 2^shift
/// After calibration, validates accuracy over 1000 samples.
/// Returns TscCal::fallback() if TSC is unreliable.
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
    // Choose shift = 32 for maximum precision with u32 mult.
    // mult = (mono_delta * 2^32) / tsc_delta
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
    // If any sample deviates by > 1µs, the calibration is bad.
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

    if max_error > 1000 { // > 1µs
        eprintln!("[M13-TSC] WARNING: Calibration error {}ns > 1µs. Using clock_gettime fallback.", max_error);
        return TscCal::fallback();
    }

    cal
}

// ============================================================================
// PREFETCH (HOT PATH CACHE HINT)
// ============================================================================

/// # Safety
/// `addr` must be a valid readable pointer. Prefetch is a hint — invalid addresses
/// cause no fault on x86_64/aarch64 but may pollute cache.
#[inline(always)]
pub unsafe fn prefetch_read_l1(addr: *const u8) {
    #[cfg(target_arch = "x86_64")]
    { core::arch::x86_64::_mm_prefetch(addr as *const i8, core::arch::x86_64::_MM_HINT_T0); }
    #[cfg(target_arch = "aarch64")]
    { core::arch::asm!("prfm pldl1keep, [{addr}]", addr = in(reg) addr, options(nostack, preserves_flags)); }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    { let _ = addr; }
}

// ============================================================================
// CPU MANAGEMENT (core pinning, affinity, IRQ fence, PMU lock)
// ============================================================================

pub fn discover_isolated_cores() -> Vec<usize> {
    if let Ok(mock) = std::env::var("M13_MOCK_CMDLINE") {
        if let Some(part) = mock.split_whitespace().find(|p| p.starts_with("isolcpus=")) {
            return parse_cpu_list(part.strip_prefix("isolcpus=").unwrap_or(""));
        }
        return Vec::new();
    }
    match std::fs::read_to_string("/sys/devices/system/cpu/isolated") {
        Ok(s) => parse_cpu_list(s.trim()), Err(_) => Vec::new(),
    }
}

pub fn parse_cpu_list(list: &str) -> Vec<usize> {
    let mut cores = Vec::new();
    if list.is_empty() { return cores; }
    for part in list.split(',') {
        if part.contains('-') {
            let r: Vec<&str> = part.split('-').collect();
            if r.len() == 2 {
                let s: usize = match r[0].parse() {
                    Ok(v) => v,
                    Err(_) => fatal(E_NO_ISOLATED_CORES, "Invalid CPU range in isolcpus"),
                };
                let e: usize = match r[1].parse() {
                    Ok(v) => v,
                    Err(_) => fatal(E_NO_ISOLATED_CORES, "Invalid CPU range in isolcpus"),
                };
                for i in s..=e { cores.push(i); }
            }
        } else if let Ok(id) = part.parse::<usize>() { cores.push(id); }
    }
    cores.sort(); cores.dedup(); cores
}

pub fn pin_to_core(core_id: usize) {
    // SAFETY: Type is repr(C) and all-zeroes is a valid bit pattern.
    unsafe {
        let mut cpuset: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_SET(core_id, &mut cpuset);
        if libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &cpuset) != 0 {
            fatal(E_AFFINITY_FAIL, "sched_setaffinity failed");
        }
    }
}

pub fn verify_affinity(expected_core: usize) {
    use std::io::BufRead;
    if std::env::var("M13_MOCK_CMDLINE").is_ok() { return; }
    // SAFETY: SYS_gettid always returns a valid TID on Linux.
    let tid = unsafe { libc::syscall(libc::SYS_gettid) };
    let path = format!("/proc/self/task/{}/status", tid);
    let file = match std::fs::File::open(&path) {
        Ok(f) => f, Err(_) => match std::fs::File::open("/proc/self/status") {
            Ok(f) => f, Err(_) => fatal(E_AFFINITY_VERIFY, "Cannot open status file"),
        }
    };
    for l in std::io::BufReader::new(file).lines().map_while(Result::ok) {
        if l.starts_with("Cpus_allowed_list:") {
            let mask = l.split_whitespace().last().unwrap_or("");
            if mask != expected_core.to_string() {
                fatal(E_AFFINITY_VERIFY, "Core affinity mismatch");
            }
            return;
        }
    }
    fatal(E_AFFINITY_VERIFY, "Could not verify affinity");
}

pub fn lock_pmu() {
    use std::io::{Write, Read, Seek, SeekFrom};
    if std::env::var("M13_MOCK_CMDLINE").is_ok() { return; }
    let mut file = match std::fs::OpenOptions::new().read(true).write(true).open("/dev/cpu_dma_latency") {
        Ok(f) => f,
        Err(e) => {
            eprintln!("[M13-EXEC] WARNING: PMU lock failed (open): {}. Continuing.", e);
            return;
        }
    };
    if file.write_all(&0i32.to_ne_bytes()).is_err() {
        eprintln!("[M13-EXEC] WARNING: PMU lock failed (write). Continuing.");
        return;
    }
    if file.seek(SeekFrom::Start(0)).is_err() {
        eprintln!("[M13-EXEC] WARNING: PMU lock failed (seek). Continuing.");
        return;
    }
    let mut buf = [0u8; 4];
    if file.read_exact(&mut buf).is_err() || i32::from_ne_bytes(buf) != 0 {
        eprintln!("[M13-EXEC] WARNING: PMU lock rejected (read!=0). Continuing.");
        return;
    }
    eprintln!("[M13-EXEC] PMU Locked: max_latency=0us (C0 only)");
    std::mem::forget(file);
}

pub fn fence_interrupts() {
    if std::env::var("M13_MOCK_CMDLINE").is_ok() { return; }

    let isolated = discover_isolated_cores();
    if isolated.is_empty() { return; }

    let nproc = match std::fs::read_to_string("/sys/devices/system/cpu/present") {
        Ok(s) => {
            let parts: Vec<&str> = s.trim().split('-').collect();
            match parts.last() {
                Some(n) => n.parse::<usize>().unwrap_or(0) + 1,
                None => 1,
            }
        }
        Err(_) => { eprintln!("[M13-EXEC] WARNING: Cannot read CPU topology, skipping IRQ fence"); return; }
    };

    let mut mask_bits = vec![0u8; nproc.div_ceil(8)];
    for cpu in 0..nproc {
        if !isolated.contains(&cpu) {
            mask_bits[cpu / 8] |= 1 << (cpu % 8);
        }
    }
    let mask_hex: String = mask_bits.iter().rev()
        .map(|b| format!("{:02x}", b))
        .collect::<String>()
        .trim_start_matches('0')
        .to_string();
    let mask_str = if mask_hex.is_empty() { "1".to_string() } else { mask_hex };

    eprintln!("[M13-EXEC] IRQ fence mask: 0x{} (isolating cores {:?} from interrupts)", mask_str, isolated);

    let _ = std::fs::write("/proc/irq/default_smp_affinity", format!("{}\n", mask_str));

    if let Ok(output) = std::process::Command::new("pgrep").arg("irqbalance").output() {
        if output.status.success() {
            eprintln!("[M13-EXEC] WARNING: irqbalance is running. It will fight the IRQ fence.");
            eprintln!("[M13-EXEC] WARNING: Run 'systemctl stop irqbalance' for optimal performance.");
        }
    }

    let irq_dir = match std::fs::read_dir("/proc/irq") {
        Ok(d) => d, Err(_) => { eprintln!("[M13-EXEC] WARNING: Cannot read /proc/irq, skipping IRQ fence"); return; }
    };
    let (mut fenced, mut skipped) = (0u32, 0u32);
    for entry in irq_dir {
        let entry = match entry { Ok(e) => e, Err(_) => continue };
        let name = entry.file_name();
        let name_str = match name.to_str() { Some(s) => s, None => continue };
        if !name_str.bytes().next().is_some_and(|b| b.is_ascii_digit()) { continue; }
        let affinity_path = format!("/proc/irq/{}/smp_affinity", name_str);
        match std::fs::write(&affinity_path, format!("{}\n", mask_str)) {
            Ok(_) => { fenced += 1; }
            Err(_) => { skipped += 1; }
        }
    }
    eprintln!("[M13-EXEC] Interrupt Fence: {} IRQs moved to housekeeping cores, {} immovable", fenced, skipped);
}

// ============================================================================
// TELEMETRY — SHM-mapped per-worker counters
// ============================================================================

pub const SHM_NAME_PREFIX: &str = "/m13_telem_";

#[repr(align(128))] pub struct CachePadded<T> { pub value: T }

/// Per-worker telemetry. Memory-mapped via /dev/shm for zero-copy cross-process reads.
/// All fields are AtomicU32/AtomicU64 with Relaxed ordering (diagnostic, not synchronization).
#[repr(C)]
pub struct Telemetry {
    pub tx_count: CachePadded<AtomicU64>, pub rx_count: CachePadded<AtomicU64>,
    pub drops: CachePadded<AtomicU64>, pub cycles: CachePadded<AtomicU64>,
    pub pid: CachePadded<AtomicU32>,
    // BBR state visible to monitor/executive via shared memory
    pub bbr_phase: CachePadded<AtomicU32>,       // BbrPhase as u32 (0=Startup,1=Drain,2=ProbeBW,3=ProbeRTT)
    pub bbr_calibrated: CachePadded<AtomicU32>,   // 0=calibrating, 1=calibrated
    pub bbr_btlbw_kbps: CachePadded<AtomicU64>,   // BtlBw in kbps (fits u64 easily)
    pub bbr_rtprop_us: CachePadded<AtomicU64>,    // RTprop in microseconds
    // Jitter buffer state visible to monitor/executive
    pub jbuf_depth_us: CachePadded<AtomicU64>,     // Current D_buf in microseconds
    pub jbuf_jitter_us: CachePadded<AtomicU64>,    // RFC 3550 EWMA jitter estimate (µs)
    pub jbuf_releases: CachePadded<AtomicU64>,     // Cumulative frames released from jitter buffer
    pub jbuf_drops: CachePadded<AtomicU64>,        // Cumulative frames dropped (late or overflow)
    // PQC security telemetry
    pub auth_fail: CachePadded<AtomicU64>,         // AEAD MAC verification failures (forgery/corruption)
    pub replay_drops: CachePadded<AtomicU64>,      // Anti-replay rejections (duplicate/ancient seq_id)
    pub handshake_ok: CachePadded<AtomicU64>,      // Successful PQC handshakes completed
    pub handshake_fail: CachePadded<AtomicU64>,    // Failed handshakes (sig fail, timeout, malformed)
    pub direction_fail: CachePadded<AtomicU64>,    // Direction binding rejections (reflection attacks)
    pub decrypt_ok: CachePadded<AtomicU64>,        // Frames successfully decrypted and authenticated
    // Per-stage pipeline timing (cumulative TSC cycles, Relaxed ordering).
    // Monitor converts to nanoseconds via TscCal for display.
    pub parse_tsc_total: CachePadded<AtomicU64>,
    pub decrypt_tsc_total: CachePadded<AtomicU64>,
    pub classify_tsc_total: CachePadded<AtomicU64>,
    pub scatter_tsc_total: CachePadded<AtomicU64>,
    pub tun_write_tsc_total: CachePadded<AtomicU64>,
}

/// Raw pointer wrapper for shared-memory telemetry.
/// Does NOT carry &mut semantics — prevents LLVM noalias miscompilation
/// when multiple processes mmap the same /dev/shm region.
/// Safety: one writer (engine thread) + N readers (monitor, executive) is
/// valid because all fields are Atomic. The wrapper makes the shared-memory
/// unsafety explicit rather than hidden behind &'static mut.
pub struct TelemetryPtr(*mut Telemetry);
unsafe impl Send for TelemetryPtr {}
impl std::ops::Deref for TelemetryPtr {
    type Target = Telemetry;
    // SAFETY: self.0 was returned by mmap() on a valid shm_open fd with size ≥ sizeof(Telemetry).
    // The mapping is MAP_SHARED and lives for the process lifetime. All fields are atomic —
    // concurrent reads from monitor and writes from workers are safe under Relaxed ordering.
    fn deref(&self) -> &Telemetry { unsafe { &*self.0 } }
}

impl Telemetry {
    pub fn map_worker(worker_idx: usize, is_owner: bool) -> TelemetryPtr {
        let name = format!("{}{}", SHM_NAME_PREFIX, worker_idx);
        match Self::map_named(&name, is_owner) {
            Some(t) => t,
            None => fatal(E_SHM_MAP_FAIL, "Telemetry shm map failed"),
        }
    }
    pub fn try_map_worker(worker_idx: usize) -> Option<TelemetryPtr> {
        let name = format!("{}{}", SHM_NAME_PREFIX, worker_idx);
        Self::map_named(&name, false)
    }
    fn map_named(name: &str, is_owner: bool) -> Option<TelemetryPtr> {
        // SAFETY: shm_open creates/opens a POSIX shared memory object. ftruncate sizes it to
        // sizeof(Telemetry). mmap maps it read-write. The returned pointer is valid for the
        // process lifetime (munmap is never called). All Telemetry fields are AtomicU64/AtomicU32.
        unsafe {
            let c_name = match CString::new(name) {
                Ok(c) => c,
                Err(_) => fatal(E_SHM_MAP_FAIL, "SHM name contains null byte"),
            };
            let mut fd = shm_open(c_name.as_ptr(), O_RDWR, 0);
            if is_owner {
                if fd < 0 { fd = shm_open(c_name.as_ptr(), O_CREAT | O_RDWR, S_IRUSR | S_IWUSR); }
                if fd < 0 { return None; }
                if ftruncate(fd, mem::size_of::<Telemetry>() as off_t) != 0 {
                    close(fd);
                    return None;
                }
            } else if fd < 0 { return None; }
            let ptr = mmap(ptr::null_mut(), mem::size_of::<Telemetry>(), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
            close(fd);
            if ptr == MAP_FAILED { return None; }
            if is_owner { ptr::write_bytes(ptr, 0, mem::size_of::<Telemetry>()); }
            Some(TelemetryPtr(ptr as *mut Telemetry))
        }
    }
}

// ============================================================================
// HEXDUMP ENGINE (rate-limited wire inspection)
// ============================================================================
const HEXDUMP_INTERVAL_NS: u64 = 100_000_000; // 100ms = 10/sec max

pub struct HexdumpState { enabled: bool, last_tx_ns: u64 }
impl HexdumpState {
    pub fn new(enabled: bool) -> Self { HexdumpState { enabled, last_tx_ns: 0 } }
    pub fn dump_tx(&mut self, frame: *const u8, len: usize, now_ns: u64) {
        if !self.enabled { return; }
        if now_ns.saturating_sub(self.last_tx_ns) < HEXDUMP_INTERVAL_NS { return; }
        self.last_tx_ns = now_ns;
        dump_frame("[HUB-TX]", frame, len);
    }
}

#[allow(clippy::needless_range_loop)]
pub fn dump_frame(label: &str, frame: *const u8, len: usize) {
    use crate::engine::protocol::*;
    let cap = len.min(80);
    // SAFETY: Pointer and length are valid; pointer comes from UMEM or kernel ring within bounds.
    let data = unsafe { std::slice::from_raw_parts(frame, cap) };
    let (seq, flags) = if cap >= ETH_HDR_SIZE + M13_HDR_SIZE {
        // SAFETY: Pointer arithmetic within UMEM bounds; offset validated by kernel ring descriptor.
        let m13 = unsafe { &*(frame.add(ETH_HDR_SIZE) as *const M13Header) };
        (m13.seq_id, m13.flags)
    } else { (0, 0) };
    let dst = if cap >= 6 { format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        data[0], data[1], data[2], data[3], data[4], data[5]) } else { "?".into() };
    let src = if cap >= 12 { format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        data[6], data[7], data[8], data[9], data[10], data[11]) } else { "?".into() };
    eprintln!("{} seq={} flags=0x{:02X} len={} dst={} src={}", label, seq, flags, len, dst, src);
    if cap >= 14 {
        eprint!("  [00..14] ETH  |"); for i in 0..14 { eprint!(" {:02X}", data[i]); } eprintln!();
    }
    if cap >= 16 { eprint!("  [14..16] MAGIC|"); eprint!(" {:02X} {:02X}", data[14], data[15]); eprintln!(); }
    if cap >= 18 {
        eprint!("  [16..18] CRYPT|"); eprint!(" {:02X} {:02X}", data[16], data[17]);
        eprintln!("  (crypto_ver=0x{:02X}={})", data[16], if data[16] == 0 { "cleartext" } else { "encrypted" });
    }
    if cap >= 34 { eprint!("  [18..34] MAC  |"); for i in 18..34 { eprint!(" {:02X}", data[i]); } eprintln!(); }
    if cap >= 46 { eprint!("  [34..46] NONCE|"); for i in 34..46 { eprint!(" {:02X}", data[i]); } eprintln!(); }
    if cap >= 54 {
        eprint!("  [46..54] SEQ  |"); for i in 46..54 { eprint!(" {:02X}", data[i]); }
        eprintln!("  (LE: seq_id={})", seq);
    }
    if cap >= 55 { eprintln!("  [54..55] FLAGS| {:02X}", data[54]); }
    if cap >= 59 {
        let plen = if cap >= ETH_HDR_SIZE + M13_HDR_SIZE {
            // SAFETY: Pointer arithmetic within UMEM bounds; offset validated by kernel ring descriptor.
            let m13 = unsafe { &*(frame.add(ETH_HDR_SIZE) as *const M13Header) }; m13.payload_len
        } else { 0 };
        eprint!("  [55..59] PLEN |"); for i in 55..59 { eprint!(" {:02X}", data[i]); }
        eprintln!("  (LE: payload_len={})", plen);
    }
    if cap >= 62 { eprint!("  [59..62] PAD  |"); for i in 59..62 { eprint!(" {:02X}", data[i]); } eprintln!(); }
}

// ============================================================================
// MONITOR (cross-process telemetry reader)
// ============================================================================
pub fn run_monitor(max_workers: usize) {
    use std::sync::atomic::Ordering;

    eprintln!("[M13-MONITOR] Scanning for active workers...");
    let mut workers = Vec::new();
    for i in 0..max_workers {
        if let Some(t) = Telemetry::try_map_worker(i) { workers.push(t); } else { break; }
    }
    if workers.is_empty() {
        eprintln!("[M13-MONITOR] No workers found. Waiting...");
        while workers.is_empty() {
            if let Some(t) = Telemetry::try_map_worker(0) { workers.push(t); break; }
            std::thread::sleep(Duration::from_millis(500));
        }
    }
    eprintln!("[M13-MONITOR] Attached to {} worker(s).", workers.len());
    eprintln!("---------------------------------------------------------------------");
    let mut last_tx = vec![0u64; workers.len()];
    let mut tids = vec![0u32; workers.len()];
    loop {
        let (mut ttx, mut trx, mut td, mut tpps) = (0u64, 0u64, 0u64, 0u64);
        let mut cs = String::new();
        for (i, w) in workers.iter().enumerate() {
            let tx = w.tx_count.value.load(Ordering::Relaxed);
            let rx = w.rx_count.value.load(Ordering::Relaxed);
            let d = w.drops.value.load(Ordering::Relaxed);
            let pps = tx - last_tx[i]; last_tx[i] = tx;
            ttx += tx; trx += rx; td += d; tpps += pps;
            if tids[i] == 0 { tids[i] = w.pid.value.load(Ordering::Relaxed); }
            if tids[i] != 0 {
                let (v, n) = read_ctxt_switches(tids[i]);
                if i > 0 { cs.push('|'); }
                cs.push_str(&format!("W{}:{}/{}", i, v, n));
            }
        }
        let jb_depth = workers[0].jbuf_depth_us.value.load(Ordering::Relaxed);
        let jb_jitter = workers[0].jbuf_jitter_us.value.load(Ordering::Relaxed);
        let jb_rel = workers[0].jbuf_releases.value.load(Ordering::Relaxed);
        let jb_drop = workers[0].jbuf_drops.value.load(Ordering::Relaxed);
        // Security counters
        let aead_ok = workers[0].decrypt_ok.value.load(Ordering::Relaxed);
        let aead_fail = workers[0].auth_fail.value.load(Ordering::Relaxed);
        let hs_ok = workers[0].handshake_ok.value.load(Ordering::Relaxed);
        let hs_fail = workers[0].handshake_fail.value.load(Ordering::Relaxed);
        // Per-stage cumulative TSC (raw cycles — divide by elapsed to get per-packet avg)
        let p_tsc = workers[0].parse_tsc_total.value.load(Ordering::Relaxed);
        let d_tsc = workers[0].decrypt_tsc_total.value.load(Ordering::Relaxed);
        let c_tsc = workers[0].classify_tsc_total.value.load(Ordering::Relaxed);
        let s_tsc = workers[0].scatter_tsc_total.value.load(Ordering::Relaxed);
        let t_tsc = workers[0].tun_write_tsc_total.value.load(Ordering::Relaxed);
        eprint!("\r[TELEM] TX:{:<12} RX:{:<12} DROP:{:<10} PPS:{:<10} AEAD:{}/{} HS:{}/{} JB:{}us/{}us R:{} D:{} TSC:P{}|D{}|C{}|S{}|T{} CTX:[{}]   ",
            ttx, trx, td, tpps, aead_ok, aead_fail,
            hs_ok, hs_fail,
            jb_depth, jb_jitter, jb_rel, jb_drop,
            p_tsc / 1000, d_tsc / 1000, c_tsc / 1000, s_tsc / 1000, t_tsc / 1000,
            cs);
        std::thread::sleep(Duration::from_secs(1));
    }
}

pub fn read_ctxt_switches(tid: u32) -> (u64, u64) {
    use std::io::BufRead;
    let path = format!("/proc/{}/status", tid);
    if let Ok(file) = std::fs::File::open(&path) {
        let (mut v, mut n) = (0u64, 0u64);
        for l in std::io::BufReader::new(file).lines().map_while(Result::ok) {
            if l.starts_with("voluntary_ctxt_switches:") {
                v = l.split_whitespace().nth(1).unwrap_or("0").parse().unwrap_or(0);
            } else if l.starts_with("nonvoluntary_ctxt_switches:") {
                n = l.split_whitespace().nth(1).unwrap_or("0").parse().unwrap_or(0);
            }
        }
        (v, n)
    } else { (0, 0) }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alloc_and_free() {
        let mut slab = FixedSlab::new(4);
        assert_eq!(slab.available(), 4);
        let a = slab.alloc().unwrap();
        assert_eq!(slab.available(), 3);
        slab.free(a);
        assert_eq!(slab.available(), 4);
    }

    #[test]
    fn exhaustion_returns_none() {
        let mut slab = FixedSlab::new(2);
        let _a = slab.alloc().unwrap();
        let _b = slab.alloc().unwrap();
        assert!(slab.alloc().is_none());
    }

    #[test]
    fn alloc_returns_unique_indices() {
        let mut slab = FixedSlab::new(8);
        let mut indices = Vec::new();
        for _ in 0..8 {
            indices.push(slab.alloc().unwrap());
        }
        indices.sort();
        indices.dedup();
        assert_eq!(indices.len(), 8);
    }

    #[test]
    fn free_then_realloc() {
        let mut slab = FixedSlab::new(1);
        let a = slab.alloc().unwrap();
        assert!(slab.alloc().is_none());
        slab.free(a);
        let b = slab.alloc().unwrap();
        assert_eq!(a, b); // LIFO: same index returned
    }
}
