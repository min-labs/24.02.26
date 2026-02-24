// M13 HUB — NETWORK: XDP ENGINE (REMEDIATION SPRINT R-01)
// ENFORCED DETERMINISM: ZERO MOCKING. STRICT HARDWARE ABORTS.
// AF_XDP zero-copy datapath engine. Owns UMEM, XSK socket, all rings.
// Lock-free SPSC ring operations with explicit memory barriers.

use libbpf_sys::{
    xsk_umem__create, xsk_socket__create, xsk_umem_config, xsk_socket_config,
    xsk_ring_prod, xsk_ring_cons, xdp_desc,
    XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
    bpf_map_update_elem,
};
use libc::{
    mmap, munmap, ioctl, socket, setsockopt, getsockopt,
    MAP_PRIVATE, MAP_ANONYMOUS, MAP_HUGETLB, MAP_POPULATE, MAP_LOCKED,
    PROT_READ, PROT_WRITE, MAP_FAILED,
    c_void, c_char, AF_INET, SOCK_DGRAM, SOL_SOCKET, MSG_DONTWAIT, sendto,
    SOL_XDP, close,
};
use std::ptr;
use std::mem;
use std::sync::atomic::{AtomicU32, Ordering, fence};
use std::ffi::CString;

use crate::engine::runtime::*;
use crate::engine::runtime::FixedSlab;
use crate::engine::runtime::Telemetry;

#[allow(non_upper_case_globals, non_camel_case_types, non_snake_case, dead_code)]
mod bindings { include!(concat!(env!("OUT_DIR"), "/bindings.rs")); }
use bindings::{ethtool_ringparam, ifreq, SIOCETHTOOL, ETHTOOL_GRINGPARAM};

pub const MAX_WORKERS: usize = 4;
pub const UMEM_SIZE: usize = 1024 * 1024 * 1024; // 1 GB physically locked memory
pub const FRAME_SIZE: u32 = 4096;
pub const SO_BUSY_POLL: i32 = 46;
pub const XDP_MMAP_OFFSETS: i32 = 1;



pub const XDP_ZEROCOPY: u16 = 1 << 2;
pub const XDP_USE_NEED_WAKEUP: u16 = 1 << 3;

// ============================================================================
// TX PATH TRAIT — Strict Hardware Abstraction
// ============================================================================

pub trait TxPath {
    fn available_slots(&mut self) -> u32;
    fn stage_tx(&mut self, frame_idx: u32, len: u32);
    fn stage_tx_addr(&mut self, addr: u64, len: u32);
    fn commit_tx(&mut self);
    fn kick_tx(&mut self);
}

/// AF_XDP zero-copy TX path. Submits frames directly from pinned UMEM to NIC PCIe BARs.
pub struct ZeroCopyTx { tx: RingProd, sock_fd: i32 }
impl TxPath for ZeroCopyTx {
    #[inline(always)] fn available_slots(&mut self) -> u32 { unsafe { self.tx.available() } }
    #[inline(always)] fn stage_tx(&mut self, frame_idx: u32, len: u32) { unsafe { self.tx.stage(frame_idx, len) } }
    #[inline(always)] fn stage_tx_addr(&mut self, addr: u64, len: u32) { unsafe { self.tx.stage_addr_desc(addr, len) } }
    #[inline(always)] fn commit_tx(&mut self) { unsafe { self.tx.commit() } }
    #[inline(always)] fn kick_tx(&mut self) { 
        unsafe { 
            // SURGICAL PATCH: Eradicate the conditional `if self.tx.needs_wakeup()`.
            // Unconditionally flush the hardware TX ring via sendto() to mathematically
            // guarantee transmission. Prevents VPP loop stranding when inline PQC stalls
            // (10ms ML-KEM/ML-DSA) desynchronize the kernel's ring wakeup flag.
            let res = sendto(self.sock_fd, ptr::null(), 0, MSG_DONTWAIT, ptr::null(), 0); 
            if res < 0 {
                let e = *libc::__errno_location();
                // EAGAIN, EBUSY (driver ring full), and ENOBUFS are transient backpressure states.
                // The hardware will drain the queue by the next polling tick.
                // ENXIO (device gone) or EBADF (fd invalidated) are permanent physical severances.
                if e != libc::EAGAIN && e != libc::EBUSY && e != libc::ENOBUFS {
                    fatal(E_XSK_BIND_FAIL, "kick_tx: Unrecoverable hardware error during DMA kick (ENXIO/EBADF).");
                }
            }
        } 
    }
}

// ============================================================================
// ENGINE (Strict Ownership of PCIe Mappings & UMEM)
// ============================================================================

pub struct Engine<T: TxPath> {
    umem_area: *mut u8,
    #[allow(dead_code)] _umem_handle: *mut libbpf_sys::xsk_umem,
    #[allow(dead_code)] sock_handle: *mut libbpf_sys::xsk_socket,
    cq: RingCons, rx: RingCons, fq: RingProd,
    pub tx_path: T,
    pub xdp_mode: String,
}
unsafe impl<T: TxPath> Send for Engine<T> {}

impl Engine<ZeroCopyTx> {
    pub fn new_zerocopy(if_name: &str, queue_id: i32, bpf_map_fd: i32) -> Self {
        if bpf_map_fd < 0 {
            // R-01: No graceful degradation. If BPF map fails, the steersman is dead.
            // Bypassing this mathematically guarantees black-holed packets.
            fatal(E_XSK_BIND_FAIL, "BPF Map FD invalid. XDP redirect physically impossible. Mock engines are strictly prohibited.");
        }

        check_nic_limits(if_name);

        // R-01: MAP_HUGETLB is mathematically required to prevent L2 TLB thrashing.
        // MAP_POPULATE pre-faults the pages, ensuring zero page-faults during datapath execution.
        // MAP_LOCKED pins the memory to RAM, preventing OS swap-out (which destroys DMA).
        let flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB | MAP_POPULATE | MAP_LOCKED;
        
        let umem_area = unsafe { mmap(ptr::null_mut(), UMEM_SIZE, PROT_READ | PROT_WRITE, flags, -1, 0) };
        if umem_area == MAP_FAILED { 
            // R-01: No fallback to 4KB pages. If HugePages are unavailable, the system geometry is invalid.
            fatal(E_UMEM_ALLOC_FAIL, "UMEM MAP_HUGETLB mmap failed. Ensure 'hugepages=600' kernel parameter is set (1GB UMEM / 2MB pages = 512 + headroom)."); 
        }

        let umem_cfg = xsk_umem_config { 
            fill_size: 4096, comp_size: 4096, frame_size: FRAME_SIZE, frame_headroom: 0, flags: 0 
        };
        let mut umem_handle: *mut libbpf_sys::xsk_umem = ptr::null_mut();
        let mut fq_def: xsk_ring_prod = unsafe { mem::zeroed() };
        let mut cq_def: xsk_ring_cons = unsafe { mem::zeroed() };
        
        let ret = unsafe { xsk_umem__create(&mut umem_handle, umem_area, UMEM_SIZE as u64, &mut fq_def, &mut cq_def, &umem_cfg) };
        if ret != 0 { fatal(E_UMEM_ALLOC_FAIL, "xsk_umem__create failed. Hardware DMA ring mapping rejected."); }

        let mut sock_cfg: xsk_socket_config = unsafe { mem::zeroed() };
        sock_cfg.rx_size = 2048; 
        sock_cfg.tx_size = 2048;
        sock_cfg.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD;
        sock_cfg.xdp_flags = 0;
        
        // MANDATE: XDP_ZEROCOPY strictly enforced. XDP_COPY is physically banned.
        // XDP_USE_NEED_WAKEUP enables the kernel to flag when a syscall is strictly necessary.
        sock_cfg.bind_flags = XDP_ZEROCOPY | XDP_USE_NEED_WAKEUP;

        let mut sock_handle: *mut libbpf_sys::xsk_socket = ptr::null_mut();
        let mut rx_def: xsk_ring_cons = unsafe { mem::zeroed() };
        let mut tx_def: xsk_ring_prod = unsafe { mem::zeroed() };
        
        let c_ifname = match CString::new(if_name) {
            Ok(c) => c,
            Err(_) => fatal(E_XSK_BIND_FAIL, "Interface name contains null byte"),
        };
        
        let ret = unsafe { xsk_socket__create(&mut sock_handle, c_ifname.as_ptr(), queue_id as u32, umem_handle, &mut rx_def, &mut tx_def, &sock_cfg) };
        if ret != 0 { 
            // R-01: If ZeroCopy fails, the NIC driver lacks AF_XDP native support. Abort.
            let errno = unsafe { *libc::__errno_location() };
            eprintln!("[M13-DIAG] xsk_socket__create returned {} (errno={}), bind_flags=0x{:x}, queue={}, iface={}", 
                ret, errno, sock_cfg.bind_flags, queue_id, if_name);
            fatal(E_XSK_BIND_FAIL, "xsk_socket__create failed. NIC lacks native XDP_ZEROCOPY support."); 
        }

        let sock_fd = unsafe { libbpf_sys::xsk_socket__fd(sock_handle) };
        
        // Wire the XSK socket file descriptor into the BPF XSKS_MAP.
        unsafe {
            let key = queue_id; 
            let val = sock_fd;
            let ret = bpf_map_update_elem(bpf_map_fd, &key as *const _ as *const c_void, &val as *const _ as *const c_void, 0);
            if ret != 0 { fatal(E_XSK_BIND_FAIL, "BPF map update failed (xsks_map). Steersman decoupling detected."); }
        }

        let poll_us: i32 = 50;
        let ret = unsafe { setsockopt(sock_fd, SOL_SOCKET, SO_BUSY_POLL, &poll_us as *const _ as *const c_void, 4) };
        if ret != 0 {
            // Non-fatal: busy poll is a performance hint. Kernel < 5.11 may not support it on AF_XDP.
            unsafe { libc::write(2, b"[M13-WARN] SO_BUSY_POLL not supported. Latency variance increased.\n".as_ptr() as _, 68); }
        }

        let mut offsets = XdpMmapOffsets::default();
        let mut optlen = mem::size_of::<XdpMmapOffsets>() as u32;
        let ret = unsafe { getsockopt(sock_fd, SOL_XDP, XDP_MMAP_OFFSETS, &mut offsets as *mut _ as *mut c_void, &mut optlen) };
        if ret != 0 { fatal(E_XSK_BIND_FAIL, "getsockopt XDP_MMAP_OFFSETS failed. Kernel ABI mismatch."); }

        unsafe {
            let tx_strategy = ZeroCopyTx { tx: RingProd::new(&tx_def), sock_fd };
            let rx_ring = RingCons::new(&rx_def);
            let fq_ring = RingProd::new(&fq_def);
            let cq_ring = RingCons::new(&cq_def);
            
            Engine { 
                umem_area: umem_area as *mut u8, 
                _umem_handle: umem_handle, 
                sock_handle, 
                cq: cq_ring, 
                rx: rx_ring, 
                fq: fq_ring, 
                tx_path: tx_strategy, 
                xdp_mode: "AF_XDP Native Zero-Copy".to_string() 
            }
        }
    }

    #[inline(always)] 
    pub fn get_frame_ptr(&self, idx: u32) -> *mut u8 { unsafe { self.umem_area.add((idx * FRAME_SIZE) as usize) } }
    #[inline(always)] pub fn umem_base(&self) -> *mut u8 { self.umem_area }

    #[inline(always)]
    pub fn recycle_tx(&mut self, allocator: &mut FixedSlab) -> usize { unsafe { self.cq.consume_addr(allocator) } }

    #[inline(always)]
    pub fn refill_rx(&mut self, allocator: &mut FixedSlab) {
        let count = unsafe { self.fq.available() } as usize;
        let batch = std::cmp::min(count, 16);
        if batch > 0 { self.refill_internal(allocator, batch); }
    }
    
    #[inline(always)]
    pub fn refill_rx_full(&mut self, allocator: &mut FixedSlab) {
        let count = unsafe { self.fq.available() } as usize;
        if count > 0 { self.refill_internal(allocator, count); }
    }
    
    #[inline(always)]
    fn refill_internal(&mut self, allocator: &mut FixedSlab, count: usize) {
        unsafe {
            let mut added = 0;
            for _ in 0..count {
                if let Some(idx) = allocator.alloc() {
                    self.fq.stage_addr((idx as u64) * (FRAME_SIZE as u64));
                    added += 1;
                } else { break; }
            }
            if added > 0 { self.fq.commit(); }
        }
    }

    #[inline(always)]
    pub fn poll_rx_batch(&mut self, out: &mut [xdp_desc], stats: &Telemetry) -> usize {
        unsafe { self.rx.consume_batch(out, out.len(), stats) }
    }
}

impl<T: TxPath> Drop for Engine<T> {
    fn drop(&mut self) { unsafe { munmap(self.umem_area as *mut c_void, UMEM_SIZE); } }
}

// ============================================================================
// RING OPERATIONS (Lock-free SPSC with explicit memory barriers)
// ============================================================================
struct RingProd { producer: *mut u32, consumer: *mut u32, ring: *mut c_void, mask: u32, cached_cons: u32, local_prod: u32 }
struct RingCons { producer: *mut u32, consumer: *mut u32, ring: *mut c_void, mask: u32 }

impl RingProd {
    unsafe fn new(r: *const xsk_ring_prod) -> Self {
        let prod_ptr = (*r).producer as *mut AtomicU32;
        let init_prod = (*prod_ptr).load(Ordering::Relaxed);
        RingProd { producer: (*r).producer, consumer: (*r).consumer, ring: (*r).ring, mask: (*r).mask, cached_cons: 0, local_prod: init_prod }
    }
    

    
    #[inline(always)] unsafe fn available(&mut self) -> u32 {
        self.cached_cons = (*(self.consumer as *mut AtomicU32)).load(Ordering::Acquire);
        (self.mask + 1).saturating_sub(self.local_prod.wrapping_sub(self.cached_cons))
    }
    
    #[inline(always)] unsafe fn stage(&mut self, frame_idx: u32, len: u32) {
        let desc = (self.ring as *mut xdp_desc).offset((self.local_prod & self.mask) as isize);
        (*desc).addr = (frame_idx as u64) * FRAME_SIZE as u64; (*desc).len = len; (*desc).options = 0;
        self.local_prod = self.local_prod.wrapping_add(1);
    }
    
    #[inline(always)] unsafe fn stage_addr(&mut self, addr: u64) {
        let ptr = (self.ring as *mut u64).offset((self.local_prod & self.mask) as isize);
        *ptr = addr;
        self.local_prod = self.local_prod.wrapping_add(1);
    }
    
    #[inline(always)] unsafe fn stage_addr_desc(&mut self, addr: u64, len: u32) {
        let desc = (self.ring as *mut xdp_desc).offset((self.local_prod & self.mask) as isize);
        (*desc).addr = addr; (*desc).len = len; (*desc).options = 0;
        self.local_prod = self.local_prod.wrapping_add(1);
    }
    
    #[inline(always)] unsafe fn commit(&mut self) {
        let prod_ptr = self.producer as *mut AtomicU32;
        fence(Ordering::Release);
        (*prod_ptr).store(self.local_prod, Ordering::Relaxed);
    }
}

impl RingCons {
    unsafe fn new(r: *const xsk_ring_cons) -> Self {
        RingCons { producer: (*r).producer, consumer: (*r).consumer, ring: (*r).ring, mask: (*r).mask }
    }
    
    #[inline(always)] unsafe fn consume_addr(&mut self, allocator: &mut FixedSlab) -> usize {
        let prod_ptr = self.producer as *mut AtomicU32;
        let cons_ptr = self.consumer as *mut AtomicU32;
        let cons_val = (*cons_ptr).load(Ordering::Relaxed);
        let prod_val = (*prod_ptr).load(Ordering::Relaxed);
        fence(Ordering::Acquire);
        let available = prod_val.wrapping_sub(cons_val);
        if available == 0 { return 0; }
        let addr_arr = self.ring as *mut u64;
        for i in 0..available {
            let addr = *addr_arr.offset(((cons_val + i) & self.mask) as isize);
            allocator.free((addr / FRAME_SIZE as u64) as u32);
        }
        (*cons_ptr).store(cons_val.wrapping_add(available), Ordering::Release);
        available as usize
    }
    
    #[inline(always)] unsafe fn consume_batch(&mut self, out: &mut [xdp_desc], limit: usize, stats: &Telemetry) -> usize {
        let prod_ptr = self.producer as *mut AtomicU32;
        let cons_ptr = self.consumer as *mut AtomicU32;
        let cons_val = (*cons_ptr).load(Ordering::Relaxed);
        let prod_val = (*prod_ptr).load(Ordering::Relaxed);
        fence(Ordering::Acquire);
        let available = prod_val.wrapping_sub(cons_val) as usize;
        if available == 0 { return 0; }
        let count = available.min(limit);
        let desc_arr = self.ring as *const xdp_desc;
        for (i, out_desc) in out.iter_mut().enumerate().take(count) {
            *out_desc = *desc_arr.add((cons_val.wrapping_add(i as u32) & self.mask) as usize);
        }
        (*cons_ptr).store(cons_val.wrapping_add(count as u32), Ordering::Release);
        stats.rx_count.value.fetch_add(count as u64, Ordering::Relaxed);
        count
    }
}

fn check_nic_limits(if_name: &str) {
    let fd = unsafe { socket(AF_INET, SOCK_DGRAM, 0) };
    if fd < 0 { fatal(E_RING_SIZE_FAIL, "Failed to open probe socket"); }
    
    let mut gring: ethtool_ringparam = unsafe { mem::zeroed() };
    gring.cmd = ETHTOOL_GRINGPARAM;
    let mut ifr: ifreq = unsafe { mem::zeroed() };
    if if_name.len() >= 16 { fatal(E_XSK_BIND_FAIL, "Interface name exceeds IFNAMSIZ"); }
    
    unsafe {
        ptr::copy_nonoverlapping(if_name.as_ptr() as *const c_char, ifr.ifr_ifrn.ifrn_name.as_mut_ptr(), if_name.len());
        ifr.ifr_ifru.ifru_data = &mut gring as *mut _ as *mut c_void;
    }
    
    let ret = unsafe { ioctl(fd, SIOCETHTOOL as u64, &mut ifr) };
    unsafe { close(fd); }
    
    // R-01 BREAKING CHANGE: M13_SIMULATION bypass permanently eradicated.
    // Developers must use veth pairs with native AF_XDP for local testing.
    if ret != 0 { fatal(E_RING_SIZE_FAIL, "SIOCETHTOOL ioctl failed. Hardware limits are strictly enforced (M13_SIMULATION eradicated)."); }
    if gring.tx_max_pending == 0 { fatal(E_RING_SIZE_FAIL, "SIOCETHTOOL query returned zero capacity."); }
    
    if gring.rx_max_pending > 0 && 2048 > gring.rx_max_pending { 
        fatal(E_RING_SIZE_FAIL, "NIC HW RX ring capacity insufficient for 2048 elements."); 
    }
    if gring.tx_max_pending > 0 && 2048 > gring.tx_max_pending { 
        fatal(E_RING_SIZE_FAIL, "NIC HW TX ring capacity insufficient for 2048 elements."); 
    }
}

#[repr(C)] #[derive(Default, Debug)] struct XdpMmapOffsets { rx: XdpRingOffset, tx: XdpRingOffset, fr: XdpRingOffset, cr: XdpRingOffset }
#[repr(C)] #[derive(Default, Debug)] struct XdpRingOffset { producer: u64, consumer: u64, desc: u64, flags: u64 }
