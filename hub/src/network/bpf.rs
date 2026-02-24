// M13 HUB — NETWORK: BPF STEERSMAN (REMEDIATION SPRINT R-01)
// Loads and attaches the eBPF XDP program that filters M13 traffic into AF_XDP UMEM.
// Enforces XDP_FLAGS_DRV_MODE. Graceful degradation to SKB mode is explicitly prohibited.

use libbpf_sys::{
    bpf_object, bpf_object__open_mem, bpf_object__load, bpf_object__find_program_by_name,
    bpf_program__fd, bpf_object__find_map_by_name, bpf_map__fd,
    bpf_set_link_xdp_fd,
    XDP_FLAGS_DRV_MODE, XDP_FLAGS_UPDATE_IF_NOEXIST,
};
use libc::{c_void, setrlimit, rlimit, RLIMIT_MEMLOCK, RLIM_INFINITY};
use std::mem;
use std::ffi::CString;

use crate::network::xdp::UMEM_SIZE;
use crate::engine::runtime::{fatal, E_SHM_MAP_FAIL, E_XSK_BIND_FAIL};

const BPF_OBJ_BYTES: &[u8] = include_bytes!(env!("BPF_OBJECT_PATH"));

/// BPF XDP steersman. Loads and attaches the eBPF program that filters
/// EtherType 0x88B5 (M13) traffic into AF_XDP UMEM. Detaches on Drop.
pub struct BpfSteersman { 
    #[allow(dead_code)] obj: *mut bpf_object, 
    map_fd: i32, 
    if_index: i32, 
    pub attach_mode: &'static str 
}

unsafe impl Send for BpfSteersman {}

impl BpfSteersman {
    /// Load the eBPF object and attach it to the network interface.
    /// Halts via `fatal()` if any hardware or kernel constraint is violated.
    pub fn load_and_attach(if_name: &str) -> Self {
        // Scope RLIMIT_MEMLOCK to UMEM + 16MB for BPF maps/programs.
        unsafe {
            let needed = (UMEM_SIZE + 16 * 1024 * 1024) as u64;
            let rlim = rlimit { rlim_cur: needed, rlim_max: needed };
            if setrlimit(RLIMIT_MEMLOCK, &rlim) != 0 {
                // Architectural justification: Policy scope change, not a physics degradation.
                // On kernels < 5.11 lacking native CAP_BPF limits, setrlimit fails due to 
                // /etc/security/limits.conf strictures. Over-allocating the memory lock budget 
                // via RLIM_INFINITY guarantees the memory remains pinned without compromising 
                // physical MAP_HUGETLB TLB performance.
                let rlim_inf = rlimit { rlim_cur: RLIM_INFINITY, rlim_max: RLIM_INFINITY };
                if setrlimit(RLIMIT_MEMLOCK, &rlim_inf) != 0 {
                    fatal(E_SHM_MAP_FAIL, "Failed to elevate RLIMIT_MEMLOCK. Kernel refused memory lock.");
                }
            }
        }

        let c_ifname = match CString::new(if_name) {
            Ok(c) => c,
            Err(_) => fatal(E_XSK_BIND_FAIL, "Interface name contains null byte boundary violation."),
        };

        // SAFETY: CString pointer is valid and null-terminated.
        let if_index = unsafe { libc::if_nametoindex(c_ifname.as_ptr()) } as i32;
        if if_index == 0 { 
            fatal(E_XSK_BIND_FAIL, "Interface not found. Physical NIC is absent or renamed.");
        }

        unsafe {
            let mut opts: libbpf_sys::bpf_object_open_opts = mem::zeroed();
            opts.sz = mem::size_of::<libbpf_sys::bpf_object_open_opts>() as u64;
            
            let obj = bpf_object__open_mem(BPF_OBJ_BYTES.as_ptr() as *const c_void, BPF_OBJ_BYTES.len() as u64, &opts);
            if obj.is_null() { 
                fatal(E_XSK_BIND_FAIL, "BPF object open failed. Invalid ELF header in BPF object.");
            }

            let ret = bpf_object__load(obj);
            if ret != 0 { 
                fatal(E_XSK_BIND_FAIL, "BPF object load failed. Kernel rejected eBPF bytecode (verifier error or lack of CAP_BPF).");
            }

            let prog_name = CString::new("m13_steersman").unwrap();
            let prog = bpf_object__find_program_by_name(obj, prog_name.as_ptr());
            if prog.is_null() { fatal(E_XSK_BIND_FAIL, "BPF program 'm13_steersman' not found in ELF."); }
            let prog_fd = bpf_program__fd(prog);

            let map_name = CString::new("xsks_map").unwrap();
            let map = bpf_object__find_map_by_name(obj, map_name.as_ptr());
            if map.is_null() { fatal(E_XSK_BIND_FAIL, "BPF map 'xsks_map' not found in ELF."); }
            let map_fd = bpf_map__fd(map);

            // MANDATE: Enforce Native Driver Mode (XDP_FLAGS_DRV_MODE)
            // SKB mode is incapable of line-rate execution and mathematically prohibited.
            let flags = XDP_FLAGS_DRV_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST;
            let attach_ret = bpf_set_link_xdp_fd(if_index, prog_fd, flags);
            
            if attach_ret != 0 { 
                fatal(E_XSK_BIND_FAIL, "BPF XDP attach failed. Physical NIC driver lacks Native XDP support, or an existing program is already bound.");
            }

            BpfSteersman { 
                obj, 
                map_fd, 
                if_index, 
                attach_mode: "Native (Driver) Mode" 
            }
        }
    }

    #[inline(always)]
    pub fn map_fd(&self) -> i32 { self.map_fd }
}

impl Drop for BpfSteersman { 
    fn drop(&mut self) { 
        unsafe { 
            if self.if_index > 0 { 
                libbpf_sys::bpf_set_link_xdp_fd(self.if_index, -1, 0); 
            } 
        } 
    } 
}
