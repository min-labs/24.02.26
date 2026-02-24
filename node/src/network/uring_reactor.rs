// M13 NODE — NETWORK: IO_URING PBR REACTOR (REMEDIATION SPRINT R-02B)
// ZERO SYSCALL DATAPATH. IORING_SETUP_SQPOLL + PBR + MULTISHOT.
// MEMORY GEOMETRY ENFORCED: EXACT HUGETLB ARENA SIZING.

use io_uring::{IoUring, squeue, opcode, types};
use std::os::unix::io::{RawFd, AsRawFd};
use std::ptr::NonNull;
use std::sync::atomic::{AtomicU16, Ordering};
use libc::{mmap, munmap, MAP_HUGETLB, MAP_PRIVATE, MAP_ANONYMOUS, MAP_POPULATE, MAP_LOCKED, PROT_READ, PROT_WRITE, MAP_FAILED};
use crate::engine::runtime::{fatal, E_UMEM_ALLOC_FAIL};

const IORING_REGISTER_PBUF_RING: libc::c_uint = 22;
pub const IORING_CQE_F_BUFFER: u32 = 1 << 0;
pub const IORING_CQE_F_MORE: u32 = 1 << 1;

pub const FRAME_SIZE: usize = 2048;
pub const UDP_RING_ENTRIES: u32 = 4096;
pub const TUN_RX_ENTRIES: u32 = 64;
// EXACT GEOMETRY: Data allocation must encompass both rings.
pub const TOTAL_BIDS: u32 = UDP_RING_ENTRIES + TUN_RX_ENTRIES;

pub const PBR_BGID: u16 = 1;

// TAGS for Asynchronous Lifecycle Tracking (UAF Prevention)
pub const TAG_UDP_RECV_MULTISHOT: u64 = 1;
pub const TAG_TUN_READ: u64 = 2;
pub const TAG_TUN_WRITE: u64 = 3;
pub const TAG_UDP_SEND_ECHO: u64 = 4;
pub const TAG_UDP_SEND_TUN: u64 = 5;

#[repr(C)]
pub struct io_uring_buf {
    pub addr: u64,
    pub len: u32,
    pub bid: u16,
    pub resv: u16, // C-ABI WARNING: For bufs[0], this physically overlays the `tail` pointer. DO NOT WRITE.
}

#[repr(C)]
struct io_uring_buf_reg {
    ring_addr: u64,
    ring_entries: u32,
    bgid: u16,
    flags: u16,
    resv: [u64; 3],
}

pub struct UmemSlice<'a> {
    pub ptr: NonNull<u8>,
    pub len: usize,
    _marker: std::marker::PhantomData<&'a mut [u8]>,
}

impl<'a> UmemSlice<'a> {
    #[inline(always)]
    pub fn as_mut(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }
}

pub struct UringReactor {
    pub ring: IoUring,
    arena_base: *mut u8,
    arena_size: usize,
    pbr_ptr: *mut io_uring_buf,
    pbr_tail_ptr: *const AtomicU16,
    local_tail: u16,
    pbr_mask: u16,
    pub multishot_active: bool,
    sock_fd: RawFd,
}

impl UringReactor {
    pub fn new(sock_fd: RawFd, sq_thread_cpu: u32) -> Self {
        // Dynamic Memory Geometry Allocation. Strictly aligned to 2MB.
        let pbr_size = (UDP_RING_ENTRIES as usize * 16).next_multiple_of(2 * 1024 * 1024);
        let data_size = (TOTAL_BIDS as usize * FRAME_SIZE).next_multiple_of(2 * 1024 * 1024);
        let arena_size = pbr_size + data_size;

        let flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB | MAP_POPULATE | MAP_LOCKED;
        let arena_base = unsafe { mmap(std::ptr::null_mut(), arena_size, PROT_READ | PROT_WRITE, flags, -1, 0) };
        if arena_base == MAP_FAILED {
            fatal(E_UMEM_ALLOC_FAIL, "io_uring PBR MAP_HUGETLB failed. Verify kernel HugePage limits.");
        }

        let pbr_ptr = arena_base as *mut io_uring_buf;
        let pbr_tail_ptr = unsafe { (arena_base as *mut u8).add(14) as *const AtomicU16 }; // ABI Offset 14 is the atomic tail
        let data_base = unsafe { (arena_base as *mut u8).add(pbr_size) };

        let ring = IoUring::builder()
            .setup_sqpoll(2000)
            .setup_sqpoll_cpu(sq_thread_cpu)
            .setup_single_issuer()
            .setup_cqsize(TOTAL_BIDS * 2)
            .build(TOTAL_BIDS)
            .unwrap_or_else(|e| fatal(0x15, &format!("io_uring SQPOLL setup failed: {}", e)));

        let reg = io_uring_buf_reg {
            ring_addr: pbr_ptr as u64,
            ring_entries: UDP_RING_ENTRIES,
            bgid: PBR_BGID,
            flags: 0,
            resv: [0; 3],
        };

        let ret = unsafe {
            libc::syscall(
                libc::SYS_io_uring_register,
                ring.as_raw_fd(),
                IORING_REGISTER_PBUF_RING,
                &reg as *const _ as *const libc::c_void,
                1,
            )
        };

        if ret < 0 { fatal(0x15, "IORING_REGISTER_PBUF_RING failed. Kernel 6.12+ ABI mismatch."); }

        let mut reactor = Self {
            ring, arena_base: data_base, arena_size,
            pbr_ptr, pbr_tail_ptr, local_tail: 0,
            pbr_mask: (UDP_RING_ENTRIES - 1) as u16, sock_fd, multishot_active: false,
        };

        for i in 0..UDP_RING_ENTRIES as u16 { reactor.add_buffer_to_pbr(i); }
        reactor.commit_pbr();
        reactor.arm_multishot_recv();
        reactor
    }

    #[inline(always)]
    pub fn add_buffer_to_pbr(&mut self, bid: u16) {
        debug_assert!((bid as u32) < UDP_RING_ENTRIES, "CRITICAL: PBR BID overflow protection");
        unsafe {
            let index = (self.local_tail & self.pbr_mask) as usize;
            let entry = self.pbr_ptr.add(index);
            let addr = self.arena_base.add((bid as usize) * FRAME_SIZE) as u64;

            // MANDATE: Write unaligned explicitly bypassing `resv` to prevent tail corruption.
            std::ptr::write_unaligned(&mut (*entry).addr, addr);
            std::ptr::write_unaligned(&mut (*entry).len, FRAME_SIZE as u32);
            std::ptr::write_unaligned(&mut (*entry).bid, bid);

            self.local_tail = self.local_tail.wrapping_add(1);
        }
    }

    #[inline(always)]
    pub fn commit_pbr(&self) {
        unsafe { (*self.pbr_tail_ptr).store(self.local_tail, Ordering::Release); }
    }

    pub fn arm_multishot_recv(&mut self) {
        if self.multishot_active { return; }

        let recv_sqe = opcode::RecvMulti::new(types::Fd(self.sock_fd), PBR_BGID)
            .flags(libc::MSG_TRUNC | libc::MSG_DONTWAIT)
            .build()
            .flags(squeue::Flags::BUFFER_SELECT)
            .user_data(TAG_UDP_RECV_MULTISHOT);

        unsafe { while self.ring.submission().push(&recv_sqe).is_err() { self.submit(); } }
        self.submit();
        self.multishot_active = true;
    }

    #[inline(always)]
    pub fn arm_tun_read(&mut self, tun_fd: i32, bid: u16) {
        debug_assert!((bid as u32) >= UDP_RING_ENTRIES && (bid as u32) < TOTAL_BIDS, "CRITICAL: TUN BID invalid");
        let addr = unsafe { self.arena_base.add((bid as usize) * FRAME_SIZE) };

        // Zero-Copy Opt: Offset read by 62 bytes. Leaves room to prepend the M13 Header entirely in-place.
        let payload_addr = unsafe { addr.add(62) };
        
        // [P1-02] STRICT USO MTU CLAMPING (1380 bytes max payload from kernel)
        // Mathematically ensures frame length never exceeds 1442 bytes (62 + 1380), bypassing kernel IP fragmentation over WiFi.
        let max_payload = (FRAME_SIZE as u32 - 62).min(1380);

        let sqe = opcode::Read::new(types::Fd(tun_fd), payload_addr as *mut u8, max_payload)
            .build()
            .user_data(TAG_TUN_READ | ((bid as u64) << 32)); // Pack BID for deferred recycling

        unsafe { while self.ring.submission().push(&sqe).is_err() { self.submit(); } }
    }

    #[inline(always)]
    pub fn stage_tun_write(&mut self, tun_fd: i32, buf_ptr: *const u8, len: u32, bid: u16) {
        // Enforce Use-After-Free (UAF) prevention. Pack BID into upper 32-bits.
        let sqe = opcode::Write::new(types::Fd(tun_fd), buf_ptr, len)
            .build()
            .user_data(TAG_TUN_WRITE | ((bid as u64) << 32));
        unsafe { while self.ring.submission().push(&sqe).is_err() { self.submit(); } }
    }

    #[inline(always)]
    pub fn stage_udp_send(&mut self, buf_ptr: *const u8, len: u32, bid: u16, tag: u64) {
        let sqe = opcode::Send::new(types::Fd(self.sock_fd), buf_ptr, len)
            .flags(libc::MSG_DONTWAIT)
            .build()
            .user_data(tag | ((bid as u64) << 32));
        unsafe { while self.ring.submission().push(&sqe).is_err() { self.submit(); } }
    }

    #[inline(always)]
    pub fn submit(&mut self) {
        self.ring.submission().sync();
        if self.ring.submission().need_wakeup() { let _ = self.ring.submit(); }
    }

    #[inline(always)]
    pub fn get_frame(&self, bid: u16, len: usize) -> UmemSlice<'static> {
        let addr = unsafe { self.arena_base.add((bid as usize) * FRAME_SIZE) };
        UmemSlice { ptr: NonNull::new(addr).unwrap(), len, _marker: std::marker::PhantomData }
    }

    /// Returns the raw pointer to the arena data region (after PBR metadata).
    /// Used by the worker loop for in-place frame construction.
    #[inline(always)]
    pub fn arena_base_ptr(&self) -> *mut u8 {
        self.arena_base
    }
}

impl Drop for UringReactor {
    fn drop(&mut self) {
        unsafe {
            let pbr_size = (UDP_RING_ENTRIES as usize * 16).next_multiple_of(2 * 1024 * 1024);
            munmap(self.arena_base.sub(pbr_size) as *mut libc::c_void, self.arena_size);
        }
    }
}