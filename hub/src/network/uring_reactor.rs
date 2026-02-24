// M13 HUB — NETWORK: IO_URING PBR REACTOR [P1-04]
// ZERO SYSCALL DATAPATH FOR WiFi 7 (mac80211 AP Interfaces).
// Binds AF_PACKET raw socket to wlan0 to intercept exact Ethernet geometry identical to AF_XDP.

use io_uring::{IoUring, squeue, opcode, types};
use std::os::unix::io::{RawFd, AsRawFd};
use std::sync::atomic::{AtomicU16, Ordering};
use libc::{mmap, munmap, MAP_PRIVATE, MAP_ANONYMOUS, MAP_POPULATE, PROT_READ, PROT_WRITE, MAP_FAILED};
use libc::{socket, bind, sockaddr_ll, AF_PACKET, SOCK_RAW, ETH_P_ALL, if_nametoindex};
use std::ffi::CString;
use crate::engine::runtime::{fatal, E_UMEM_ALLOC_FAIL, E_XSK_BIND_FAIL};

const IORING_REGISTER_PBUF_RING: libc::c_uint = 22;
pub const IORING_CQE_F_BUFFER: u32 = 1 << 0;
pub const IORING_CQE_F_MORE: u32 = 1 << 1;

pub const UDP_RING_ENTRIES: u32 = 4096;
pub const PBR_BGID: u16 = 1;

// TAGS for Asynchronous Lifecycle Tracking
pub const TAG_RECV_MULTISHOT: u64 = 1;
pub const TAG_SEND_XDP_SLAB: u64 = 2; // Upper 32-bits = slab_idx

#[repr(C)]
pub struct io_uring_buf {
    pub addr: u64,
    pub len: u32,
    pub bid: u16,
    pub resv: u16,
}

#[repr(C)]
struct io_uring_buf_reg {
    ring_addr: u64,
    ring_entries: u32,
    bgid: u16,
    flags: u16,
    resv: [u64; 3],
}

pub struct UringReactor {
    pub ring: IoUring,
    pbr_ptr: *mut io_uring_buf,
    pbr_tail_ptr: *const AtomicU16,
    pbr_size: usize,
    local_tail: u16,
    pbr_mask: u16,
    pub sock_fd: RawFd,
    pub multishot_active: bool,
    pub ifindex: i32,
}

impl UringReactor {
    pub fn new(if_name: &str, sq_thread_cpu: u32) -> Self {
        // PBR Metadata requires contiguous allocation. We map this separately from UMEM.
        // It strictly requires 16 bytes per entry, aligned to 4KB pages.
        let pbr_size = (UDP_RING_ENTRIES as usize * 16).next_multiple_of(4096);
        let flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE;
        let arena_base = unsafe { mmap(std::ptr::null_mut(), pbr_size, PROT_READ | PROT_WRITE, flags, -1, 0) };
        if arena_base == MAP_FAILED {
            fatal(E_UMEM_ALLOC_FAIL, "Hub io_uring PBR metadata mmap failed.");
        }

        let pbr_ptr = arena_base as *mut io_uring_buf;
        let pbr_tail_ptr = unsafe { (arena_base as *mut u8).add(14) as *const AtomicU16 }; // ABI Offset 14

        let ring = IoUring::builder()
            .setup_sqpoll(2000)
            .setup_sqpoll_cpu(sq_thread_cpu)
            .setup_single_issuer()
            .setup_cqsize(UDP_RING_ENTRIES * 2)
            .build(UDP_RING_ENTRIES)
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

        let c_ifname = match CString::new(if_name) {
            Ok(c) => c,
            Err(_) => fatal(E_XSK_BIND_FAIL, "WiFi interface name contains null byte"),
        };
        let ifindex = unsafe { if_nametoindex(c_ifname.as_ptr()) } as i32;
        if ifindex == 0 { fatal(E_XSK_BIND_FAIL, "WiFi interface not found. Invalid parameter."); }

        // Bind raw AF_PACKET socket to capture exact Ethernet layer, identical to AF_XDP geometry
        let sock_fd = unsafe { socket(AF_PACKET, SOCK_RAW, (ETH_P_ALL as u16).to_be() as i32) };
        if sock_fd < 0 { fatal(E_XSK_BIND_FAIL, "AF_PACKET socket creation failed. Root required."); }

        unsafe {
            let mut saddr: sockaddr_ll = std::mem::zeroed();
            saddr.sll_family = AF_PACKET as u16;
            saddr.sll_protocol = (ETH_P_ALL as u16).to_be();
            saddr.sll_ifindex = ifindex;
            if bind(sock_fd, &saddr as *const _ as *const libc::sockaddr, std::mem::size_of::<sockaddr_ll>() as u32) < 0 {
                fatal(E_XSK_BIND_FAIL, "AF_PACKET bind failed.");
            }
        }

        Self {
            ring, pbr_size,
            pbr_ptr, pbr_tail_ptr, local_tail: 0,
            pbr_mask: (UDP_RING_ENTRIES - 1) as u16, sock_fd, multishot_active: false,
            ifindex,
        }
    }

    /// Pull free slabs from the Universal Slab Pool and provide them to io_uring PBR.
    /// Safely maps the identical 1GB UMEM memory into the io_uring buffers.
    #[inline(always)]
    pub fn replenish_pbr(&mut self, slab: &mut crate::engine::runtime::FixedSlab, umem_base: *mut u8, frame_size: u32) {
        let mut added = false;
        // Keep the ring well-stocked, but leave slabs for AF_XDP
        let target = UDP_RING_ENTRIES as u16 / 2;
        while self.local_tail.wrapping_sub(unsafe { (*self.pbr_tail_ptr).load(Ordering::Relaxed) }) < target {
            if let Some(idx) = slab.alloc() {
                self.add_buffer_to_pbr(idx as u16, idx, umem_base, frame_size);
                added = true;
            } else {
                break;
            }
        }
        if added {
            self.commit_pbr();
        }
    }

    #[inline(always)]
    fn add_buffer_to_pbr(&mut self, bid: u16, slab_idx: u32, umem_base: *mut u8, frame_size: u32) {
        unsafe {
            let index = (self.local_tail & self.pbr_mask) as usize;
            let entry = self.pbr_ptr.add(index);
            // Translate the slab index into an absolute physical address within the universal UMEM base
            let addr = umem_base.add((slab_idx as usize) * frame_size as usize) as u64;

            std::ptr::write_unaligned(&mut (*entry).addr, addr);
            std::ptr::write_unaligned(&mut (*entry).len, frame_size);
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
            .user_data(TAG_RECV_MULTISHOT);

        unsafe { while self.ring.submission().push(&recv_sqe).is_err() { self.submit(); } }
        self.submit();
        self.multishot_active = true;
    }

    /// Directly maps an AF_XDP UMEM slab pointer to the io_uring Send SQE.
    /// Tagged with TAG_SEND_XDP_SLAB to ensure memory is safely freed back to the AF_XDP allocator upon CQE return.
    #[inline(always)]
    pub fn stage_send_xdp_slab(&mut self, ptr: *const u8, len: u32, slab_idx: u32) {
        // Send raw Ethernet frame directly over AF_PACKET socket.
        let sqe = opcode::Send::new(types::Fd(self.sock_fd), ptr, len)
            .flags(libc::MSG_DONTWAIT)
            .build()
            .user_data(TAG_SEND_XDP_SLAB | ((slab_idx as u64) << 32));
        unsafe { while self.ring.submission().push(&sqe).is_err() { self.submit(); } }
    }

    #[inline(always)]
    pub fn submit(&mut self) {
        self.ring.submission().sync();
        if self.ring.submission().need_wakeup() { let _ = self.ring.submit(); }
    }

    /// Single pass CQE drain: returns RX descriptors and reclaims AF_XDP TX completions natively.
    #[inline(always)]
    pub fn drain_cqes(&mut self, slab: &mut crate::engine::runtime::FixedSlab, out_rx: &mut [(u64, u32)], frame_size: u32) -> usize {
        self.ring.completion().sync();
        let mut rx_count = 0usize;
        let mut rearm = false;

        for cqe in self.ring.completion() {
            let user_data = cqe.user_data();
            let tag = user_data & 0xFFFF_FFFF;

            match tag {
                TAG_RECV_MULTISHOT => {
                    let result = cqe.result();
                    let flags = cqe.flags();
                    if result <= 0 {
                        self.multishot_active = false;
                        rearm = true;
                        continue;
                    }
                    if flags & IORING_CQE_F_BUFFER != 0 {
                        let bid = ((flags >> 16) & 0xFFFF) as u16;
                        let slab_idx = bid as u32;
                        if rx_count < out_rx.len() {
                            // bid exactly equals slab_idx. Address is slab_idx * FRAME_SIZE.
                            out_rx[rx_count] = ((slab_idx as u64) * frame_size as u64, result as u32);
                            rx_count += 1;
                        } else {
                            // Drop if batch exceeds target limit, recycle slab immediately
                            slab.free(slab_idx);
                        }
                    }
                    if flags & IORING_CQE_F_MORE == 0 {
                        self.multishot_active = false;
                        rearm = true;
                    }
                }
                TAG_SEND_XDP_SLAB => {
                    let slab_idx = (user_data >> 32) as u32;
                    slab.free(slab_idx);
                }
                _ => {}
            }
        }

        if rearm { self.arm_multishot_recv(); }
        rx_count
    }
}

impl Drop for UringReactor {
    fn drop(&mut self) {
        unsafe {
            munmap(self.pbr_ptr as *mut libc::c_void, self.pbr_size);
            libc::close(self.sock_fd);
        }
    }
}