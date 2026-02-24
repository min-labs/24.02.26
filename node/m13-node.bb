# M13 NODE — YOCTO/PETALINUX BITBAKE RECIPE
# TARGET HARDWARE: Xilinx Kria K26 SOM (Zynq UltraScale+ FPGA)
# CURRENT PHASE: Software testing on x86. FPGA deployment is final target.
#
# Node = drone leaf. 1 isolated core, 512MB UMEM, single-worker AF_XDP.

SUMMARY = "M13 Node — High-Frequency Kinetic Edge Fabric (Drone)"
LICENSE = "CLOSED"

inherit cargo systemd

# 1. SOURCE
SRC_URI = "file://m13"
S = "${WORKDIR}/m13/node"

# 2. KERNEL BOOT ARGUMENTS
#   isolcpus=1         -> Isolate core 1 for M13 worker (core 0 = Linux)
#   rcu_nocbs=1        -> No RCU callbacks on isolated core
#   nohz_full=1        -> No timer interrupts on isolated core
#   hugepagesz=2M      -> 2MB hugepages (drone has less RAM than Hub)
#   audit=0            -> Disable audit logging (latency)
APPEND += " isolcpus=1 rcu_nocbs=1 nohz_full=1 hugepagesz=2M default_hugepagesz=2M audit=0"

# 3. INSTALLATION
do_install() {
    install -d ${D}${bindir}
    install -m 0755 ${B}/target/aarch64-unknown-linux-gnu/release/m13-node ${D}${bindir}/m13-node
}

# 4. SYSTEMD SERVICE
SYSTEMD_SERVICE_${PN} = "m13-node.service"
