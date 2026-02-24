/* M13 HUB — P4 SILICON FIREWALL
 * TARGET HARDWARE: Xilinx Kria K26 SOM (Zynq UltraScale+ FPGA)
 * CURRENT PHASE: Software testing on x86. FPGA synthesis is final target.
 *
 * This P4 program defines the hardware packet parser and firewall that runs
 * on the FPGA fabric. It validates M13 wire protocol at wire speed before
 * any packet reaches the ARM CPU. Invalid packets are dropped in silicon.
 *
 * Hub-specific: accepts raw L2 (EtherType 0x88B5) and IPv4/UDP (port 443)
 * from N registered Nodes. Dual ingress path for datacenter + Internet.
 *
 * Sprint 5.14: Raw Ethernet (EtherType 0x88B5), magic+version validation.
 */

#include <core.p4>

#if defined(SIMULATION)
    #include <v1model.p4>
#endif

// ---------------------------------------------------------------------------
// 1. CONSTANTS & HEADERS
// ---------------------------------------------------------------------------
const bit<16> ETHERTYPE_M13  = 0x88B5; // IEEE 802.1 Local Experimental
const bit<16> ETHERTYPE_IPV4 = 0x0800; // IPv4 (UDP tunnel path)
const bit<8>  M13_MAGIC      = 0xD1;   // Wire protocol magic (signature[0])
const bit<8>  M13_VERSION_1  = 0x01;   // Phase 1 wire protocol version

header ethernet_h {
    bit<48> dstAddr; bit<48> srcAddr; bit<16> etherType;
}

header ipv4_h {
    bit<4> version; bit<4> ihl; bit<8> diffserv; bit<16> totalLen;
    bit<16> identification; bit<3> flags; bit<13> fragOffset;
    bit<8> ttl; bit<8> protocol; bit<16> hdrChecksum;
    bit<32> srcAddr; bit<32> dstAddr;
}

header udp_h {
    bit<16> srcPort; bit<16> dstPort; bit<16> length; bit<16> checksum;
}

// M13 wire header (aligned to 64-bit memory bus)
// signature[0] = magic (0xD1), signature[1] = version (0x01)
header m13_h {
    bit<8>   magic;        // 1B — must be 0xD1
    bit<8>   version;      // 1B — must be 0x01 for Phase 1
    bit<240> sig_reserved; // 30B — reserved for AEAD crypto fields
    bit<64>  sequence_id;  // 8B
    bit<8>   flags;        // 1B
    bit<32>  payload_len;  // 4B
    bit<24>  _padding;     // 3B (alignment)
}

struct headers {
    ethernet_h ethernet;
    ipv4_h     ipv4;
    udp_h      udp;
    m13_h      m13;
}

struct metadata { bit<1> drop_flag; }

// ---------------------------------------------------------------------------
// 2. PARSER
// Hub: dual path — raw L2 (EtherType 0x88B5) + IPv4/UDP (port 443)
// ---------------------------------------------------------------------------
parser M13HubParser(packet_in packet,
                    out headers hdr,
                    inout metadata meta,
                    inout standard_metadata_t standard_metadata) {

    state start { transition parse_ethernet; }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_M13  : parse_m13;
            ETHERTYPE_IPV4 : parse_ipv4;
            default        : accept;
        }
    }

    // Primary path: raw Ethernet → M13 header (datacenter mode)
    state parse_m13 {
        packet.extract(hdr.m13);
        transition accept;
    }

    // Secondary path: IPv4 → UDP (Internet tunnel mode)
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            8w17 : parse_udp;  // IPPROTO_UDP
            default : accept;
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }
}

// ---------------------------------------------------------------------------
// 3. PIPELINE (Wire-speed firewall)
// ---------------------------------------------------------------------------

control M13HubVerifyChecksum(inout headers h, inout metadata m) {
    apply { }
}

control M13HubIngress(inout headers hdr, inout metadata meta, inout standard_metadata_t sm) {
    apply {
        if (hdr.m13.isValid()) {
            // Wire protocol validation: magic + version must match
            if (hdr.m13.magic != M13_MAGIC || hdr.m13.version != M13_VERSION_1) {
                mark_to_drop(sm);
            }
            // Valid M13 packet — proceed to DMA / AF_XDP
        } else {
            // Non-M13 traffic reaching ingress — drop (fail-secure)
            mark_to_drop(sm);
        }
    }
}

control M13HubEgress(inout headers h, inout metadata m, inout standard_metadata_t sm) {
    apply { }
}

control M13HubComputeChecksum(inout headers h, inout metadata m) {
    apply { }
}

control M13HubDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.m13);
    }
}

// ---------------------------------------------------------------------------
// 4. ARCHITECTURE MAPPING
// ---------------------------------------------------------------------------
#if defined(SIMULATION)
    V1Switch(
        M13HubParser(),
        M13HubVerifyChecksum(),
        M13HubIngress(),
        M13HubEgress(),
        M13HubComputeChecksum(),
        M13HubDeparser()
    ) main;
#endif
