# M13 HUB — YOCTO/PETALINUX BITBAKE RECIPE
# TARGET HARDWARE: Xilinx Kria K26 SOM (Zynq UltraScale+ FPGA)
# CURRENT PHASE: Software testing on x86. FPGA deployment is final target.
#
# Hub = mothership. 4 isolated cores, 1GB hugepages, multi-worker AF_XDP.

SUMMARY = "M13 Hub — High-Frequency Kinetic Edge Fabric (Mothership)"
LICENSE = "CLOSED"

inherit cargo systemd

# 1. SOURCE
SRC_URI = "file://m13"
S = "${WORKDIR}/m13/hub"

# 2. KERNEL BOOT ARGUMENTS
#   isolcpus=1,2,3    -> Isolate cores 1-3 for M13 workers (core 0 = Linux)
#   rcu_nocbs=1,2,3   -> No RCU callbacks on isolated cores
#   nohz_full=1,2,3   -> No timer interrupts on isolated cores
#   hugepagesz=1G     -> 1GB hugepages for UMEM (1GB UMEM region)
#   audit=0           -> Disable audit logging (latency)
APPEND += " isolcpus=1,2,3 rcu_nocbs=1,2,3 nohz_full=1,2,3 hugepagesz=1G default_hugepagesz=1G audit=0"

# 3. INSTALLATION
do_install() {
    install -d ${D}${bindir}
    install -m 0755 ${B}/target/aarch64-unknown-linux-gnu/release/m13-hub ${D}${bindir}/m13-hub
}

# 4. SYSTEMD SERVICE
SYSTEMD_SERVICE_${PN} = "m13-hub.service"
