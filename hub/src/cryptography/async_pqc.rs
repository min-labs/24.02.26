// M13 HUB — TRUE SPSC PQC OFFLOAD TO CORE 0 (WORLD-CLASS EDITION)
//
// Zero inline lattice math on the datapath. OSI layer decoupling:
//   Core 0 (PQC Worker): ML-KEM-1024 encapsulation + ML-DSA-87 verification
//   Core 1+ (Datapath):  L2/L3 framing with locally-learned hub_ip/gateway_mac
//
// Architecture:
//   1. Datapath reassembles handshake → copies to payload_arena[pidx]
//   2. Pushes slim PqcReq (32B) to SPSC ring
//   3. Core 0 pops, reads payload from arena, executes crypto
//   4. For ClientHello: writes FlatHubHandshakeState to hs_state_arena[pidx],
//      returns raw ServerHello payload in PqcResp
//   5. For Finished: reads FlatHubHandshakeState from hs_state_arena[pidx],
//      verifies ML-DSA signature, derives session key, returns in PqcResp
//   6. Datapath drains PqcResp, frames ServerHello with learned addresses,
//      or installs cipher for SessionEstablished
//
// Thermodynamic mandate:
//   ML-DSA-87 sign + ML-KEM-1024 encaps ≈ 15M cycles → ~10ms at 1.5 GHz.
//   During 10ms stall at 1 Gbps / 64B: ~14,800 packets arrive.
//   AF_XDP ring = 2,048 entries → ~12,750 packets tail-dropped.
//   This module eliminates that blast radius entirely.

use sha2::{Sha512, Digest};
use hkdf::Hkdf;

use crate::engine::protocol::*;
use crate::cryptography::handshake::process_client_hello_hub;
use crate::engine::runtime::pin_to_core;
use crate::engine::spsc::{Producer, Consumer, make_spsc};

// ============================================================================
// CONSTANTS
// ============================================================================

/// SPSC ring depth for PQC request/response.  Must be power of two.
pub const PQC_SPSC_DEPTH: usize = 64;

/// Maximum reassembled ClientHello payload (4194B + alignment headroom).
pub const MAX_CLIENT_HELLO_SIZE: usize = 4608;

/// Maximum reassembled Finished payload (4628B + alignment headroom).
pub const MAX_FINISHED_SIZE: usize = 4864;

/// Maximum ServerHello payload (8788B + headroom).
pub const MAX_SERVER_HELLO_SIZE: usize = 9216;

/// Unified max handshake payload size for the shared arena.
pub const MAX_HS_PAYLOAD_SIZE: usize = 9216;

// ============================================================================
// SEND-SAFE ARENA POINTERS
// ============================================================================
// Raw pointers are !Send by default. These wrappers assert safety for our
// arena pointers which have well-defined ownership semantics:
//   payload_arena: datapath writes before SPSC push, Core 0 reads after pop.
//   hs_state_arena: exclusively owned by Core 0 after thread spawn.

// ============================================================================
// FLAT HANDSHAKE STATE — Core 0 Local Arena
// ============================================================================

/// Flat, Copy-able handshake state stored in Core 0's arena.
/// Pre-computes `transcript2 = SHA-512(CH || SH)` at ClientHello time
/// so Finished verification never re-hashes ~13KB of data.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct FlatHubHandshakeState {
    pub node_pk_bytes: [u8; 2592],
    pub shared_secret: [u8; 32],
    pub session_nonce: [u8; 32],
    pub transcript2: [u8; 64],
    pub valid: bool,
}

impl FlatHubHandshakeState {
    pub const EMPTY: Self = Self {
        node_pk_bytes: [0u8; 2592],
        shared_secret: [0u8; 32],
        session_nonce: [0u8; 32],
        transcript2: [0u8; 64],
        valid: false,
    };
}

// ============================================================================
// PQC REQUEST — Datapath → PQC Worker (slim, 32-byte envelope)
// ============================================================================

/// Slim PQC request.  The payload resides in the shared `payload_arena[pidx]`.
/// The PQC worker reads it directly — zero data copied through the SPSC ring.
#[derive(Clone, Copy)]
#[repr(C, align(32))]
pub struct PqcReq {
    /// Peer index in PeerTable (also indexes into payload_arena).
    pub pidx: u16,
    /// Discriminant: 1 = ClientHello, 2 = Finished.
    pub msg_type: u8,
    pub _pad: u8,
    /// Actual payload length in payload_arena[pidx].
    pub payload_len: u32,
    /// Timestamp at enqueue time.
    pub rx_ns: u64,
}

impl PqcReq {
    pub const EMPTY: Self = PqcReq {
        pidx: 0,
        msg_type: 0,
        _pad: 0,
        payload_len: 0,
        rx_ns: 0,
    };
}

// ============================================================================
// PQC RESPONSE — PQC Worker → Datapath
// ============================================================================

/// PQC response envelope.  Carries raw crypto payload (NOT pre-framed).
/// The datapath frames with locally-learned hub_ip/gateway_mac (OSI decoupling).
#[derive(Clone, Copy)]
#[repr(C, align(64))]
pub struct PqcResp {
    /// Peer index (echo from request).
    pub pidx: u16,
    /// Response type: HS_SERVER_HELLO(0x02) or HS_FINISHED(0x03).
    pub msg_type: u8,
    /// 1 = success, 0 = failure.
    pub success: u8,
    /// Length of raw payload in response_payload (for ServerHello).
    pub response_len: u32,
    /// Raw M13 handshake payload (ServerHello only). NOT Ethernet-framed.
    pub response_payload: [u8; MAX_SERVER_HELLO_SIZE],
    /// Session key (for Finished/SessionEstablished only).
    pub session_key: [u8; 32],
}

impl PqcResp {
    pub const EMPTY: Self = PqcResp {
        pidx: 0,
        msg_type: 0,
        success: 0,
        response_len: 0,
        response_payload: [0u8; MAX_SERVER_HELLO_SIZE],
        session_key: [0u8; 32],
    };
}

// ============================================================================
// SPSC RING FACTORY
// ============================================================================

/// Create a pair of SPSC rings for PQC request/response.
pub fn make_pqc_spsc() -> (Producer<PqcReq>, Consumer<PqcReq>, Producer<PqcResp>, Consumer<PqcResp>) {
    let (req_prod, req_cons) = make_spsc::<PqcReq>(PQC_SPSC_DEPTH);
    let (resp_prod, resp_cons) = make_spsc::<PqcResp>(PQC_SPSC_DEPTH);
    (req_prod, req_cons, resp_prod, resp_cons)
}

// ============================================================================
// PQC WORKER THREAD — pinned to Core 0
// ============================================================================

/// PQC worker entry point.  Polls SPSC, performs PQC crypto, pushes responses.
/// Never returns under normal operation.
///
/// `payload_arena`: shared read-only pointer to reassembled handshake payloads.
///   Indexed by pidx. Written by the datapath before pushing PqcReq.
///
/// `hs_state_arena`: Core 0-local mutable pointer to handshake state.
///   Indexed by pidx. Written after ClientHello, read during Finished.
pub fn pqc_worker_thread(
    core_id: usize,
    mut req_cons: Consumer<PqcReq>,
    mut resp_prod: Producer<PqcResp>,
    payload_arena: *const [u8; MAX_HS_PAYLOAD_SIZE],
    hs_state_arena: *mut FlatHubHandshakeState,
    max_peers: usize,
) {
    pin_to_core(core_id);
    eprintln!("[M13-PQC-CTRL] Async PQC Control Plane online (Core {}). 15ms HoL eradicated.", core_id);

    let mut req_buf = [PqcReq::EMPTY; 4];

    loop {
        let n = req_cons.pop_batch(&mut req_buf);
        if n == 0 {
            std::thread::yield_now();
            continue;
        }

        for i in 0..n {
            let req = &req_buf[i];
            let pidx = req.pidx as usize;
            if pidx >= max_peers { continue; }

            let payload_len = (req.payload_len as usize).min(MAX_HS_PAYLOAD_SIZE);
            let payload = unsafe {
                let ptr = payload_arena.add(pidx) as *const u8;
                std::slice::from_raw_parts(ptr, payload_len)
            };

            let mut resp = PqcResp::EMPTY;
            resp.pidx = req.pidx;

            match req.msg_type {
                1 => {
                    // ================================================================
                    // ClientHello: ML-KEM-1024 encaps + ML-DSA-87 sign (~10ms)
                    // ================================================================
                    let mut dummy_seq = 0u64;
                    if let Some((hs, server_hello)) = process_client_hello_hub(payload, &mut dummy_seq, req.rx_ns) {
                        // Pre-compute transcript2 = SHA-512(CH || SH) for Finished pass
                        let mut hasher = Sha512::new();
                        hasher.update(&hs.client_hello_bytes);
                        hasher.update(&server_hello);
                        let transcript2: [u8; 64] = hasher.finalize().into();

                        // Write state to Core 0-local arena
                        let mut flat = FlatHubHandshakeState::EMPTY;
                        let pk_len = hs.node_pk_bytes.len().min(2592);
                        flat.node_pk_bytes[..pk_len].copy_from_slice(&hs.node_pk_bytes[..pk_len]);
                        flat.shared_secret = hs.shared_secret;
                        flat.session_nonce = hs.session_nonce;
                        flat.transcript2 = transcript2;
                        flat.valid = true;
                        unsafe { *hs_state_arena.add(pidx) = flat; }

                        // Copy raw ServerHello payload (NOT framed)
                        let sh_len = server_hello.len().min(MAX_SERVER_HELLO_SIZE);
                        resp.response_payload[..sh_len].copy_from_slice(&server_hello[..sh_len]);
                        resp.response_len = sh_len as u32;
                        resp.msg_type = HS_SERVER_HELLO;
                        resp.success = 1;

                        eprintln!("[M13-PQC-CTRL] ClientHello OK pidx={}, ServerHello={}B", pidx, sh_len);
                    } else {
                        resp.msg_type = HS_SERVER_HELLO;
                        resp.success = 0;
                        eprintln!("[M13-PQC-CTRL] ClientHello FAILED pidx={}", pidx);
                    }
                }
                2 => {
                    // ================================================================
                    // Finished: ML-DSA-87 verify (~5ms)
                    // ================================================================
                    let flat = unsafe { &*hs_state_arena.add(pidx) };
                    if !flat.valid {
                        resp.msg_type = HS_FINISHED;
                        resp.success = 0;
                        eprintln!("[M13-PQC-CTRL] Finished pidx={} — no valid hs_state", pidx);
                    } else if let Some(key) = process_finished_flat(
                        payload,
                        &flat.node_pk_bytes,
                        &flat.shared_secret,
                        &flat.session_nonce,
                        &flat.transcript2,
                    ) {
                        resp.session_key = key;
                        resp.msg_type = HS_FINISHED;
                        resp.success = 1;
                        // Invalidate arena slot
                        unsafe { (*hs_state_arena.add(pidx)).valid = false; }
                        eprintln!("[M13-PQC-CTRL] Finished OK pidx={}, session key derived", pidx);
                    } else {
                        resp.msg_type = HS_FINISHED;
                        resp.success = 0;
                        eprintln!("[M13-PQC-CTRL] Finished FAILED pidx={}", pidx);
                    }
                }
                _ => {
                    eprintln!("[M13-PQC-CTRL] Unknown msg_type={} pidx={}", req.msg_type, pidx);
                    continue;
                }
            }

            let pushed = resp_prod.push_batch(&[resp]);
            if pushed == 0 {
                eprintln!("[M13-PQC-CTRL] WARNING: resp SPSC full, dropping pidx={}", pidx);
            }
        }
    }
}

// ============================================================================
// ZERO-ALLOCATION FINISHED PROCESSING
// ============================================================================

/// Process Finished message using pre-computed transcript2 from ClientHello phase.
/// Zero heap allocations. Matches handshake.rs `process_finished_hub` logic exactly
/// but reads flat fields instead of HubHandshakeState (which contains Vec<u8>).
fn process_finished_flat(
    payload: &[u8],
    node_pk_bytes: &[u8; 2592],
    shared_secret: &[u8; 32],
    session_nonce: &[u8; 32],
    transcript2: &[u8; 64],
) -> Option<[u8; 32]> {
    use ml_dsa::MlDsa87;

    const EXPECTED_LEN: usize = 1 + 4627;
    if payload.len() < EXPECTED_LEN {
        eprintln!("[M13-PQC-CTRL] Finished too short: {} < {}", payload.len(), EXPECTED_LEN);
        return None;
    }
    if payload[0] != HS_FINISHED {
        eprintln!("[M13-PQC-CTRL] Expected Finished (0x03), got 0x{:02X}", payload[0]);
        return None;
    }

    let sig_node_bytes = &payload[1..4628];

    // Decode node pubkey (matches handshake.rs pattern)
    let pk_node_enc = match ml_dsa::EncodedVerifyingKey::<MlDsa87>::try_from(
        node_pk_bytes.as_slice()
    ) {
        Ok(enc) => enc,
        Err(_) => {
            eprintln!("[M13-PQC-CTRL] Failed to parse Node verifying key");
            return None;
        }
    };
    let pk_node = ml_dsa::VerifyingKey::<MlDsa87>::decode(&pk_node_enc);

    // Parse signature
    let sig_node = match ml_dsa::Signature::<MlDsa87>::try_from(sig_node_bytes) {
        Ok(sig) => sig,
        Err(_) => {
            eprintln!("[M13-PQC-CTRL] Failed to parse Node signature");
            return None;
        }
    };

    // Verify with pre-computed transcript2
    if !pk_node.verify_with_context(transcript2, b"M13-HS-v1", &sig_node) {
        eprintln!("[M13-PQC-CTRL] SECURITY FAILURE: Node signature verification failed!");
        return None;
    }
    eprintln!("[M13-PQC-CTRL] Node ML-DSA-87 signature verified ✓");

    // HKDF-SHA-512 session key derivation
    let hk = Hkdf::<Sha512>::new(Some(session_nonce), shared_secret);
    let mut session_key = [0u8; 32];
    if hk.expand(b"M13-PQC-SESSION-KEY-v1", &mut session_key).is_err() {
        eprintln!("[M13-PQC-CTRL] HKDF expand failed");
        return None;
    }
    eprintln!("[M13-PQC-CTRL] Session key derived via HKDF-SHA-512 (32B)");

    Some(session_key)
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::spsc::make_spsc;

    #[test]
    fn spsc_req_resp_roundtrip() {
        let (mut req_prod, mut req_cons) = make_spsc::<PqcReq>(PQC_SPSC_DEPTH);
        let (mut resp_prod, mut resp_cons) = make_spsc::<PqcResp>(PQC_SPSC_DEPTH);

        // Enqueue a ClientHello request (slim — pidx only, payload in arena)
        let req = PqcReq {
            pidx: 7,
            msg_type: 1,
            _pad: 0,
            payload_len: 4194,
            rx_ns: 1_000_000,
        };

        let pushed = req_prod.push_batch(&[req]);
        assert_eq!(pushed, 1);

        let mut buf = [PqcReq::EMPTY; 1];
        let popped = req_cons.pop_batch(&mut buf);
        assert_eq!(popped, 1);
        assert_eq!(buf[0].msg_type, 1);
        assert_eq!(buf[0].pidx, 7);
        assert_eq!(buf[0].payload_len, 4194);

        // Push a failure response
        let mut resp = PqcResp::EMPTY;
        resp.pidx = 7;
        resp.msg_type = HS_FINISHED;
        resp.success = 0;
        let pushed = resp_prod.push_batch(&[resp]);
        assert_eq!(pushed, 1);

        let mut rbuf = [PqcResp::EMPTY; 1];
        let popped = resp_cons.pop_batch(&mut rbuf);
        assert_eq!(popped, 1);
        assert_eq!(rbuf[0].success, 0);
        assert_eq!(rbuf[0].pidx, 7);
    }

    #[test]
    fn pqc_req_copy_semantics() {
        let req = PqcReq::EMPTY;
        let _copy = req;
        let _second = req;
        assert_eq!(_copy.msg_type, _second.msg_type);
    }

    #[test]
    fn pqc_resp_copy_semantics() {
        let resp = PqcResp::EMPTY;
        let _copy = resp;
        let _second = resp;
        assert_eq!(_copy.msg_type, _second.msg_type);
    }

    #[test]
    fn flat_hs_state_copy_semantics() {
        let state = FlatHubHandshakeState::EMPTY;
        let _copy = state;
        let _second = state;
        assert_eq!(_copy.valid, _second.valid);
    }

    #[test]
    fn concurrent_handshakes_queued() {
        let (mut req_prod, mut req_cons) = make_spsc::<PqcReq>(PQC_SPSC_DEPTH);

        let reqs: Vec<PqcReq> = (0..32u16).map(|i| {
            PqcReq {
                pidx: i,
                msg_type: 1,
                _pad: 0,
                payload_len: 100,
                rx_ns: 0,
            }
        }).collect();

        let pushed = req_prod.push_batch(&reqs);
        assert_eq!(pushed, 32);

        let mut out = vec![PqcReq::EMPTY; 32];
        let popped = req_cons.pop_batch(&mut out);
        assert_eq!(popped, 32);
        for (i, r) in out.iter().enumerate() {
            assert_eq!(r.pidx, i as u16);
        }
    }
}
