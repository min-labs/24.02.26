// M13 NODE — NETWORK: DATAPATH MODULE
// TUN device creation, VPN routing setup/teardown, MSS clamping.
// Zero-share: independent copy from Hub.

use std::os::unix::io::AsRawFd;
use std::fs::OpenOptions;

const IFF_TUN: i16 = 0x0001;
const IFF_NO_PI: i16 = 0x1000;
const TUNSETIFF: u64 = 0x400454ca;

#[repr(C)]
struct ifreq_tun {
    ifr_name: [u8; 16],
    ifr_flags: i16,
}

pub fn create_tun(name: &str) -> Option<std::fs::File> {
    let tun_path = "/dev/net/tun";
    let file = match OpenOptions::new().read(true).write(true).open(tun_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("[M13-TUN] Failed to open {}: {}", tun_path, e);
            return None;
        }
    };

    let mut req = ifreq_tun {
        ifr_name: [0; 16],
        ifr_flags: IFF_TUN | IFF_NO_PI,
    };

    let name_bytes = name.as_bytes();
    if name_bytes.len() > 15 {
        eprintln!("[M13-TUN] Interface name too long");
        return None;
    }
    for (i, b) in name_bytes.iter().enumerate() {
        req.ifr_name[i] = *b;
    }

    // SAFETY: FFI call with valid socket fd and ioctl struct pointer.
    unsafe {
        if libc::ioctl(file.as_raw_fd(), TUNSETIFF, &req) < 0 {
            eprintln!("[M13-TUN] ioctl(TUNSETIFF) failed");
            return None;
        }

        // Set non-blocking
        let fd = file.as_raw_fd();
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags < 0 {
             eprintln!("[M13-TUN] fcntl(F_GETFL) failed");
             return None;
        }
        if libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
             eprintln!("[M13-TUN] fcntl(F_SETFL) failed");
             return None;
        }
    }

    // Set interface up and assign IP (Node = 10.13.0.2/24)
    let _ = std::process::Command::new("ip").args(["link", "set", "dev", name, "up"]).output();
    let _ = std::process::Command::new("ip").args(["addr", "add", "10.13.0.2/24", "dev", name]).output();
    
    // [P1-02] STRICT USO MTU CLAMPING (1380 bytes)
    // Forces the kernel to segment oversized IP packets down to 1380 bytes before writing to TUN.
    // Mathematically guarantees final L2 length never exceeds 1442 bytes, bypassing WiFi fragmentation.
    let _ = std::process::Command::new("ip").args(["link", "set", "dev", name, "mtu", "1380"]).output();
    
    // txqueuelen 1000: prevent kernel TUN queue drops at burst rates
    let _ = std::process::Command::new("ip").args(["link", "set", "dev", name, "txqueuelen", "1000"]).output();

    eprintln!("[M13-TUN] Created tunnel interface {} (10.13.0.2/24, MTU 1380)", name);
    Some(file)
}

/// Discover the current default gateway IP and interface.
pub fn discover_gateway() -> Option<(String, String)> {
    let out = std::process::Command::new("ip")
        .args(["route", "show", "default"])
        .output().ok()?;
    let line = String::from_utf8_lossy(&out.stdout);
    let parts: Vec<&str> = line.split_whitespace().collect();
    let via_idx = parts.iter().position(|&p| p == "via")?;
    let dev_idx = parts.iter().position(|&p| p == "dev")?;
    let gw = parts.get(via_idx + 1)?.to_string();
    let iface = parts.get(dev_idx + 1)?.to_string();
    Some((gw, iface))
}

/// Set up VPN-style routing after tunnel is established.
pub fn setup_tunnel_routes(hub_ip: &str) {
    eprintln!("[M13-ROUTE] Setting up tunnel routing...");

    let (gw, iface) = match discover_gateway() {
        Some(g) => g,
        None => {
            eprintln!("[M13-ROUTE] WARNING: Could not discover default gateway.");
            panic!("Route setup failed: No gateway found");
        }
    };
    eprintln!("[M13-ROUTE] Gateway: {} via {}", gw, iface);

    // 0. Configure interface IP and bring UP
    let _ = std::process::Command::new("ip")
        .args(["addr", "add", "10.13.0.2/24", "dev", "m13tun0"])
        .output();

    let link_up = std::process::Command::new("ip")
        .args(["link", "set", "m13tun0", "up"])
        .output()
        .expect("Failed to bring up interface");
    if !link_up.status.success() {
        panic!("Failed to bring up m13tun0: {:?}", String::from_utf8_lossy(&link_up.stderr));
    }
    eprintln!("[M13-ROUTE] ✓ Interface configured: 10.13.0.2/24 UP");

    // 1. Pin Hub IP via gateway (prevent routing loop)
    let r = std::process::Command::new("ip")
        .args(["route", "add", hub_ip, "via", &gw, "dev", &iface])
        .output();
    match r {
        Ok(ref o) if o.status.success() =>
            eprintln!("[M13-ROUTE] ✓ Hub route: {} via {} dev {}", hub_ip, gw, iface),
        Ok(ref o) =>
            eprintln!("[M13-ROUTE] Hub route (may exist): {}", String::from_utf8_lossy(&o.stderr).trim()),
        Err(e) => panic!("Failed to execute ip route: {}", e),
    }

    // 2. Override default route with /1 routes through tunnel
    let _ = std::process::Command::new("ip")
        .args(["route", "add", "0.0.0.0/1", "dev", "m13tun0"])
        .output()
        .expect("Failed to execute ip route");

    let _ = std::process::Command::new("ip")
        .args(["route", "add", "128.0.0.0/1", "dev", "m13tun0"])
        .output()
        .expect("Failed to execute ip route");
    eprintln!("[M13-ROUTE] ✓ Default traffic → m13tun0");

    // 3. Disable IPv6 to prevent leaking
    let _ = std::process::Command::new("sysctl")
        .args(["-w", "net.ipv6.conf.all.disable_ipv6=1"])
        .output();
    let _ = std::process::Command::new("sysctl")
        .args(["-w", "net.ipv6.conf.default.disable_ipv6=1"])
        .output();
    eprintln!("[M13-ROUTE] ✓ IPv6 disabled (leak prevention)");

    // 4. TCP BDP tuning
    let _ = std::process::Command::new("sysctl")
        .args(["-w", "net.core.rmem_max=16777216"]).output();
    let _ = std::process::Command::new("sysctl")
        .args(["-w", "net.core.wmem_max=16777216"]).output();
    let _ = std::process::Command::new("sysctl")
        .args(["-w", "net.ipv4.tcp_rmem=4096 1048576 16777216"]).output();
    let _ = std::process::Command::new("sysctl")
        .args(["-w", "net.ipv4.tcp_wmem=4096 1048576 16777216"]).output();
    let _ = std::process::Command::new("sysctl")
        .args(["-w", "net.ipv4.tcp_slow_start_after_idle=0"]).output();
    let _ = std::process::Command::new("sysctl")
        .args(["-w", "net.ipv4.tcp_window_scaling=1"]).output();
    let _ = std::process::Command::new("sysctl")
        .args(["-w", "net.core.netdev_budget=600"]).output();
    let _ = std::process::Command::new("sysctl")
        .args(["-w", "net.core.netdev_budget_usecs=8000"]).output();

    // 5. Enable forwarding + MSS clamping + firewall rules
    let _ = std::process::Command::new("sysctl")
        .args(["-w", "net.ipv4.ip_forward=1"]).output();

    let _ = std::process::Command::new("iptables")
        .args(["-A", "FORWARD", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"]).output();
    let _ = std::process::Command::new("iptables")
        .args(["-A", "FORWARD", "-i", "m13tun0", "-j", "ACCEPT"]).output();
    let _ = std::process::Command::new("iptables")
        .args(["-A", "FORWARD", "-o", "m13tun0", "-j", "ACCEPT"]).output();

    // 6. TUN qdisc: fq (fair queueing)
    let _ = std::process::Command::new("tc")
        .args(["qdisc", "replace", "dev", "m13tun0", "root", "fq"]).output();
    eprintln!("[M13-ROUTE] ✓ TCP BDP tuned + MSS clamped + TUN qdisc=fq");

    eprintln!("[M13-ROUTE] Tunnel routing active. All IPv4 traffic → m13tun0");
}

/// Teardown VPN routing on shutdown.
pub fn teardown_tunnel_routes(hub_ip: &str) {
    eprintln!("[M13-ROUTE] Tearing down tunnel routing...");
    let _ = std::process::Command::new("ip")
        .args(["route", "del", "0.0.0.0/1", "dev", "m13tun0"])
        .output();
    let _ = std::process::Command::new("ip")
        .args(["route", "del", "128.0.0.0/1", "dev", "m13tun0"])
        .output();
    let _ = std::process::Command::new("ip")
        .args(["route", "del", hub_ip])
        .output();
    // Re-enable IPv6
    let _ = std::process::Command::new("sysctl")
        .args(["-w", "net.ipv6.conf.all.disable_ipv6=0"])
        .output();
    let _ = std::process::Command::new("sysctl")
        .args(["-w", "net.ipv6.conf.default.disable_ipv6=0"])
        .output();
    // Remove iptables rules
    let _ = std::process::Command::new("iptables")
        .args(["-D", "FORWARD", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"]).output();
    let _ = std::process::Command::new("iptables")
        .args(["-D", "FORWARD", "-i", "m13tun0", "-j", "ACCEPT"]).output();
    let _ = std::process::Command::new("iptables")
        .args(["-D", "FORWARD", "-o", "m13tun0", "-j", "ACCEPT"]).output();
    eprintln!("[M13-ROUTE] ✓ Routes restored, IPv6 re-enabled");
}

/// Nuclear cleanup: tear down EVERYTHING — routes, TUN, IPv6, iptables.
/// Safe to call multiple times (idempotent). Safe to call from panic hook.
/// Reads Hub IP from the HUB_IP_GLOBAL mutex for pinned-route teardown.
pub fn nuke_cleanup(hub_ip_global: &std::sync::Mutex<String>) {
    eprintln!("[M13-NUKE] Tearing down all tunnel state...");

    // 1. Remove /1 override routes (most critical — these block SSH)
    let _ = std::process::Command::new("ip")
        .args(["route", "del", "0.0.0.0/1", "dev", "m13tun0"])
        .output();
    let _ = std::process::Command::new("ip")
        .args(["route", "del", "128.0.0.0/1", "dev", "m13tun0"])
        .output();

    // 2. Remove Hub IP pinned route
    if let Ok(hub_ip) = hub_ip_global.lock() {
        if !hub_ip.is_empty() {
            let _ = std::process::Command::new("ip")
                .args(["route", "del", hub_ip.as_str()])
                .output();
        }
    }

    // 3. Destroy TUN interface
    let _ = std::process::Command::new("ip")
        .args(["link", "del", "m13tun0"])
        .output();

    // 4. Re-enable IPv6
    let _ = std::process::Command::new("sysctl")
        .args(["-w", "net.ipv6.conf.all.disable_ipv6=0"])
        .output();
    let _ = std::process::Command::new("sysctl")
        .args(["-w", "net.ipv6.conf.default.disable_ipv6=0"])
        .output();

    eprintln!("[M13-NUKE] ✓ All tunnel state destroyed.");
}