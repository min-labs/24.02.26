/* M13 NODE — P4 SILICON FIREWALL
 * TARGET HARDWARE: Xilinx Kria K26 SOM (Zynq UltraScale+ FPGA)
 * CURRENT PHASE: Software testing on x86. FPGA synthesis is final target.
 *
 * This P4 program defines the hardware packet parser and firewall that runs
 * on the FPGA fabric. It validates M13 wire protocol at wire speed before
 * any packet reaches the ARM CPU. Invalid packets are dropped in silicon.
 *
 * Node-specific: accepts raw L2 (EtherType 0x88B5) from a single Hub only.
 * Simpler than Hub — no IPv4/UDP path, no multi-peer table.
 */

#include <core.p4>

#if defined(SIMULATION)
    #include <v1model.p4>
#endif

// ---------------------------------------------------------------------------
// 1. CONSTANTS & HEADERS
// ---------------------------------------------------------------------------
const bit<16> ETHERTYPE_M13 = 0x88B5; // IEEE 802.1 Local Experimental
const bit<8>  M13_MAGIC     = 0xD1;   // Wire protocol magic (signature[0])
const bit<8>  M13_VERSION_1 = 0x01;   // Phase 1 wire protocol version

header ethernet_h {
    bit<48> dstAddr; bit<48> srcAddr; bit<16> etherType;
}

// M13 wire header (aligned to 64-bit memory bus)
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
    m13_h      m13;
}

struct metadata { bit<1> drop_flag; }

// ---------------------------------------------------------------------------
// 2. PARSER
// Node: single path — raw L2 (EtherType 0x88B5) only
// ---------------------------------------------------------------------------
parser M13NodeParser(packet_in packet,
                     out headers hdr,
                     inout metadata meta,
                     inout standard_metadata_t standard_metadata) {

    state start { transition parse_ethernet; }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_M13 : parse_m13;
            default       : accept;
        }
    }

    state parse_m13 {
        packet.extract(hdr.m13);
        transition accept;
    }
}

// ---------------------------------------------------------------------------
// 3. PIPELINE (Wire-speed firewall)
// ---------------------------------------------------------------------------

control M13NodeVerifyChecksum(inout headers h, inout metadata m) {
    apply { }
}

control M13NodeIngress(inout headers hdr, inout metadata meta, inout standard_metadata_t sm) {
    apply {
        if (hdr.m13.isValid()) {
            if (hdr.m13.magic != M13_MAGIC || hdr.m13.version != M13_VERSION_1) {
                mark_to_drop(sm);
            }
        } else {
            mark_to_drop(sm);
        }
    }
}

control M13NodeEgress(inout headers h, inout metadata m, inout standard_metadata_t sm) {
    apply { }
}

control M13NodeComputeChecksum(inout headers h, inout metadata m) {
    apply { }
}

control M13NodeDeparser(packet_out packet, in headers hdr) {
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
        M13NodeParser(),
        M13NodeVerifyChecksum(),
        M13NodeIngress(),
        M13NodeEgress(),
        M13NodeComputeChecksum(),
        M13NodeDeparser()
    ) main;
#endif
