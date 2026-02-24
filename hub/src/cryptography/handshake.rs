// M13 HUB — PQC HANDSHAKE (HUB RESPONDER)
// ML-KEM-1024 key exchange + ML-DSA-87 mutual authentication.
// Session key = HKDF-SHA-512(salt=nonce, IKM=ML-KEM-ss, info="M13-PQC-SESSION-KEY-v1", L=32)
//
// Hub receives:
//   Msg 1 (ClientHello): type(1) + version(1) + nonce(32) + ek(1568) + pk_node(2592) = 4194 bytes
//   Msg 3 (Finished):    type(1) + sig_node(4627) = 4628 bytes
// Hub sends:
//   Msg 2 (ServerHello): type(1) + ct(1568) + pk_hub(2592) + sig_hub(4627) = 8788 bytes

use sha2::{Sha512, Digest};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use ml_kem::EncodedSizeUser;
use ml_kem::kem::Encapsulate;
use ml_dsa::{MlDsa87, KeyGen};

use crate::engine::protocol::*;

const PQC_CONTEXT: &[u8] = b"M13-HS-v1";
const PQC_INFO: &[u8] = b"M13-PQC-SESSION-KEY-v1";

/// Hub-side handshake state: stored between ClientHello and Finished processing.
pub struct HubHandshakeState {
    pub node_pk_bytes: Vec<u8>,
    pub shared_secret: [u8; 32],
    pub session_nonce: [u8; 32],
    pub client_hello_bytes: Vec<u8>,
    pub server_hello_bytes: Vec<u8>,
    pub _started_ns: u64,
}

/// Process a ClientHello (Msg 1) from a Node.
/// Encapsulates shared secret, signs transcript, builds ServerHello payload.
/// Returns (HubHandshakeState, server_hello_payload) for caller to frame.
pub fn process_client_hello_hub(
    reassembled: &[u8],
    _seq: &mut u64,
    now: u64,
) -> Option<(HubHandshakeState, Vec<u8>)> {
    const EXPECTED_LEN: usize = 1 + 1 + 32 + 1568 + 2592;
    if reassembled.len() < EXPECTED_LEN {
        eprintln!("[M13-HUB-PQC] ERROR: ClientHello too short: {} < {}", reassembled.len(), EXPECTED_LEN);
        return None;
    }
    if reassembled[0] != HS_CLIENT_HELLO {
        eprintln!("[M13-HUB-PQC] ERROR: Expected ClientHello (0x01), got 0x{:02X}", reassembled[0]);
        return None;
    }
    if reassembled[1] != 0x01 {
        eprintln!("[M13-HUB-PQC] ERROR: Unsupported protocol version: 0x{:02X}", reassembled[1]);
        return None;
    }

    eprintln!("[M13-HUB-PQC] Processing ClientHello ({}B, proto_v={})...", reassembled.len(), reassembled[1]);

    let mut session_nonce = [0u8; 32];
    session_nonce.copy_from_slice(&reassembled[2..34]);
    let ek_bytes = &reassembled[34..1602];
    let pk_node_bytes = &reassembled[1602..4194];

    let ek_enc = match ml_kem::Encoded::<ml_kem::kem::EncapsulationKey<ml_kem::MlKem1024Params>>::try_from(
        ek_bytes
    ) {
        Ok(enc) => enc,
        Err(_) => {
            eprintln!("[M13-HUB-PQC] ERROR: Failed to parse EncapsulationKey");
            return None;
        }
    };
    let ek = ml_kem::kem::EncapsulationKey::<ml_kem::MlKem1024Params>::from_bytes(&ek_enc);

    let (ct, ss) = match ek.encapsulate(&mut OsRng) {
        Ok((ct, ss)) => (ct, ss),
        Err(_) => {
            eprintln!("[M13-HUB-PQC] ERROR: ML-KEM encapsulation failed");
            return None;
        }
    };
    let ct_bytes_arr = ct;
    eprintln!("[M13-HUB-PQC] ML-KEM-1024 encapsulation successful (ct={}B, ss=32B)", ct_bytes_arr.len());

    let dsa_kp = MlDsa87::key_gen(&mut OsRng);
    let pk_hub = dsa_kp.verifying_key().encode();
    eprintln!("[M13-HUB-PQC] ML-DSA-87 identity generated (pk={}B)", pk_hub.len());

    let mut hasher = Sha512::new();
    hasher.update(reassembled);
    hasher.update(ct_bytes_arr.as_slice());
    let transcript: [u8; 64] = hasher.finalize().into();

    let sig_hub = match dsa_kp.signing_key().sign_deterministic(&transcript, PQC_CONTEXT) {
        Ok(sig) => sig,
        Err(_) => {
            eprintln!("[M13-HUB-PQC] ERROR: ML-DSA signing failed");
            return None;
        }
    };
    let sig_hub_bytes = sig_hub.encode();
    eprintln!("[M13-HUB-PQC] Hub signature generated ({}B)", sig_hub_bytes.len());

    let mut server_hello = Vec::with_capacity(1 + ct_bytes_arr.len() + pk_hub.len() + sig_hub_bytes.len());
    server_hello.push(HS_SERVER_HELLO);
    server_hello.extend_from_slice(ct_bytes_arr.as_slice());
    server_hello.extend_from_slice(&pk_hub);
    server_hello.extend_from_slice(&sig_hub_bytes);

    eprintln!("[M13-HUB-PQC] ServerHello built: {}B payload", server_hello.len());

    let mut ss_arr = [0u8; 32];
    ss_arr.copy_from_slice(&ss);
    Some((HubHandshakeState {
        node_pk_bytes: pk_node_bytes.to_vec(),
        shared_secret: ss_arr,
        session_nonce,
        client_hello_bytes: reassembled.to_vec(),
        server_hello_bytes: server_hello.clone(),
        _started_ns: now,
    }, server_hello))
}

/// Process a Finished message (Msg 3) from a Node.
/// Verifies Node's ML-DSA-87 signature, derives session key via HKDF-SHA-512.
/// Returns session_key on success.
pub fn process_finished_hub(
    reassembled: &[u8],
    hs_state: &HubHandshakeState,
) -> Option<[u8; 32]> {
    const EXPECTED_LEN: usize = 1 + 4627;
    if reassembled.len() < EXPECTED_LEN {
        eprintln!("[M13-HUB-PQC] ERROR: Finished too short: {} < {}", reassembled.len(), EXPECTED_LEN);
        return None;
    }
    if reassembled[0] != HS_FINISHED {
        eprintln!("[M13-HUB-PQC] ERROR: Expected Finished (0x03), got 0x{:02X}", reassembled[0]);
        return None;
    }

    eprintln!("[M13-HUB-PQC] Processing Finished ({}B)...", reassembled.len());

    let sig_node_bytes = &reassembled[1..4628];

    let mut hasher = Sha512::new();
    hasher.update(&hs_state.client_hello_bytes);
    hasher.update(&hs_state.server_hello_bytes);
    let transcript2: [u8; 64] = hasher.finalize().into();

    let pk_node_enc = match ml_dsa::EncodedVerifyingKey::<MlDsa87>::try_from(
        hs_state.node_pk_bytes.as_slice()
    ) {
        Ok(enc) => enc,
        Err(_) => {
            eprintln!("[M13-HUB-PQC] ERROR: Failed to parse Node verifying key");
            return None;
        }
    };
    let pk_node = ml_dsa::VerifyingKey::<MlDsa87>::decode(&pk_node_enc);

    let sig_node = match ml_dsa::Signature::<MlDsa87>::try_from(sig_node_bytes) {
        Ok(sig) => sig,
        Err(_) => {
            eprintln!("[M13-HUB-PQC] ERROR: Failed to parse Node signature");
            return None;
        }
    };

    if !pk_node.verify_with_context(&transcript2, PQC_CONTEXT, &sig_node) {
        eprintln!("[M13-HUB-PQC] SECURITY FAILURE: Node signature verification failed!");
        eprintln!("[M13-HUB-PQC] Possible MITM attack — aborting handshake");
        return None;
    }
    eprintln!("[M13-HUB-PQC] Node ML-DSA-87 signature verified ✓");

    let hk = Hkdf::<Sha512>::new(Some(&hs_state.session_nonce), &hs_state.shared_secret);
    let mut session_key = [0u8; 32];
    hk.expand(PQC_INFO, &mut session_key)
        .expect("HKDF-SHA-512 expand failed (L=32 ≤ 255*64)");
    eprintln!("[M13-HUB-PQC] Session key derived via HKDF-SHA-512 (32B)");

    Some(session_key)
}
