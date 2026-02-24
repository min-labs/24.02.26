// M13 NODE — Cryptography: PQC Handshake
// ML-KEM-1024 + ML-DSA-87 handshake initiation and processing.

use std::net::UdpSocket;
use sha2::{Sha512, Digest};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use ml_kem::{MlKem1024, KemCore, EncodedSizeUser};
use ml_kem::kem::Decapsulate;
use ml_dsa::{MlDsa87, KeyGen};

use crate::engine::runtime::NodeState;
use crate::engine::protocol::*;
use crate::engine::runtime::{TscCal, rdtsc_ns};
use crate::engine::runtime::HexdumpState;
use crate::engine::protocol::send_fragmented_udp;

pub const PQC_CONTEXT: &[u8] = b"M13-HS-v1";
pub const PQC_INFO: &[u8] = b"M13-PQC-SESSION-KEY-v1";

/// Initiate PQC handshake over UDP: generate keys, build ClientHello, send fragments.
pub fn initiate_handshake(
    sock: &UdpSocket,
    src_mac: &[u8; 6],
    dst_mac: &[u8; 6],
    seq: &mut u64,
    hexdump: &mut HexdumpState,
    cal: &TscCal,
) -> NodeState {
    let now = rdtsc_ns(cal);
    eprintln!("[M13-NODE-PQC] Initiating PQC handshake...");

    let (dk, ek) = MlKem1024::generate(&mut OsRng);
    let ek_bytes = ek.as_bytes();
    eprintln!("[M13-NODE-PQC] ML-KEM-1024 keypair generated (ek={}B)", ek_bytes.len());

    let dsa_kp = MlDsa87::key_gen(&mut OsRng);
    let pk_dsa = dsa_kp.verifying_key().encode();
    let sk_dsa = dsa_kp.signing_key().encode();
    eprintln!("[M13-NODE-PQC] ML-DSA-87 identity generated (pk={}B)", pk_dsa.len());

    let mut session_nonce = [0u8; 32];
    use rand::RngCore;
    OsRng.fill_bytes(&mut session_nonce);

    let mut payload = Vec::with_capacity(1 + 1 + 32 + ek_bytes.len() + pk_dsa.len());
    payload.push(HS_CLIENT_HELLO);
    payload.push(0x01);
    payload.extend_from_slice(&session_nonce);
    payload.extend_from_slice(&ek_bytes);
    payload.extend_from_slice(&pk_dsa);

    let flags = FLAG_CONTROL | FLAG_HANDSHAKE;
    // DEFECT β FIXED: sock, hexdump, cal captured by closure environment.
    let mut sent_frags = 0u64;
    send_fragmented_udp(
        src_mac, dst_mac, &payload, flags, seq,
        |frame| {
            let now = crate::engine::runtime::rdtsc_ns(cal);
            hexdump.dump_tx(frame, now);
            if sock.send(frame).is_ok() { sent_frags += 1; }
        }
    );
    eprintln!("[M13-NODE-PQC] ClientHello sent: {}B payload, {} fragments", payload.len(), sent_frags);

    let dk_bytes = dk.as_bytes().to_vec();

    NodeState::Handshaking {
        dk_bytes,
        session_nonce,
        client_hello_bytes: payload,
        our_pk: pk_dsa.to_vec(),
        our_sk: sk_dsa.to_vec(),
        started_ns: now,
    }
}

/// Process a reassembled ServerHello from the Hub.
/// Returns Some((session_key, Finished_payload)) on success.
pub fn process_handshake_node(
    reassembled: &[u8],
    state: &NodeState,
) -> Option<([u8; 32], Vec<u8>)> {
    let (dk_bytes, session_nonce, client_hello_bytes, _our_pk, our_sk, _started_ns) = match state {
        NodeState::Handshaking {
            dk_bytes, session_nonce, client_hello_bytes, our_pk, our_sk, started_ns
        } => (dk_bytes, session_nonce, client_hello_bytes, our_pk, our_sk, started_ns),
        _ => {
            eprintln!("[M13-NODE-PQC] ERROR: Handshake message received but not in Handshaking state");
            return None;
        }
    };

    if reassembled.is_empty() || reassembled[0] != HS_SERVER_HELLO {
        eprintln!("[M13-NODE-PQC] ERROR: Expected ServerHello (0x02), got 0x{:02X}",
            reassembled.first().copied().unwrap_or(0));
        return None;
    }

    const EXPECTED_LEN: usize = 1 + 1568 + 2592 + 4627; // 8788
    if reassembled.len() < EXPECTED_LEN {
        eprintln!("[M13-NODE-PQC] ERROR: ServerHello too short: {} < {}", reassembled.len(), EXPECTED_LEN);
        return None;
    }

    eprintln!("[M13-NODE-PQC] Processing ServerHello ({}B)...", reassembled.len());

    let ct_bytes = &reassembled[1..1569];
    let pk_hub_bytes = &reassembled[1569..4161];
    let sig_hub_bytes = &reassembled[4161..8788];

    // Reconstruct DecapsulationKey
    let dk_slice: &[u8] = dk_bytes.as_slice();
    let dk_encoded = ml_kem::Encoded::<ml_kem::kem::DecapsulationKey<ml_kem::MlKem1024Params>>::try_from(
        dk_slice
    );
    let dk_encoded = match dk_encoded {
        Ok(enc) => enc,
        Err(_) => {
            eprintln!("[M13-NODE-PQC] ERROR: Failed to parse stored DecapsulationKey");
            return None;
        }
    };
    let dk = ml_kem::kem::DecapsulationKey::<ml_kem::MlKem1024Params>::from_bytes(&dk_encoded);

    let ct = match ml_kem::Ciphertext::<MlKem1024>::try_from(ct_bytes) {
        Ok(ct) => ct,
        Err(_) => {
            eprintln!("[M13-NODE-PQC] ERROR: Failed to parse ML-KEM ciphertext");
            return None;
        }
    };

    let ss = match dk.decapsulate(&ct) {
        Ok(ss) => ss,
        Err(_) => {
            eprintln!("[M13-NODE-PQC] ERROR: ML-KEM decapsulation failed");
            return None;
        }
    };
    eprintln!("[M13-NODE-PQC] ML-KEM-1024 decapsulation successful (ss=32B)");

    // Verify Hub's signature over transcript = SHA-512(ClientHello || ct)
    let mut hasher = Sha512::new();
    hasher.update(client_hello_bytes);
    hasher.update(ct_bytes);
    let transcript: [u8; 64] = hasher.finalize().into();

    let pk_hub_enc = match ml_dsa::EncodedVerifyingKey::<MlDsa87>::try_from(pk_hub_bytes) {
        Ok(enc) => enc,
        Err(_) => {
            eprintln!("[M13-NODE-PQC] ERROR: Failed to parse Hub verifying key");
            return None;
        }
    };
    let pk_hub = ml_dsa::VerifyingKey::<MlDsa87>::decode(&pk_hub_enc);

    let sig_hub = match ml_dsa::Signature::<MlDsa87>::try_from(sig_hub_bytes) {
        Ok(sig) => sig,
        Err(_) => {
            eprintln!("[M13-NODE-PQC] ERROR: Failed to parse Hub signature");
            return None;
        }
    };

    if !pk_hub.verify_with_context(&transcript, PQC_CONTEXT, &sig_hub) {
        eprintln!("[M13-NODE-PQC] SECURITY FAILURE: Hub signature verification failed!");
        eprintln!("[M13-NODE-PQC] Possible MITM attack — aborting handshake");
        return None;
    }
    eprintln!("[M13-NODE-PQC] Hub ML-DSA-87 signature verified ✓");

    // Derive session key: HKDF-SHA-512(salt=nonce, IKM=ss, info=PQC_INFO, L=32)
    let hk = Hkdf::<Sha512>::new(Some(session_nonce), &ss);
    let mut session_key = [0u8; 32];
    hk.expand(PQC_INFO, &mut session_key)
        .expect("HKDF-SHA-512 expand failed (L=32 ≤ 255*64)");
    eprintln!("[M13-NODE-PQC] Session key derived via HKDF-SHA-512 (32B)");

    // Sign full transcript for Finished: SHA-512(ClientHello || ServerHello)
    let mut hasher2 = Sha512::new();
    hasher2.update(client_hello_bytes);
    hasher2.update(reassembled);
    let transcript2: [u8; 64] = hasher2.finalize().into();

    let sk_slice: &[u8] = our_sk.as_slice();
    let sk_enc = match ml_dsa::EncodedSigningKey::<MlDsa87>::try_from(sk_slice) {
        Ok(enc) => enc,
        Err(_) => {
            eprintln!("[M13-NODE-PQC] ERROR: Failed to reconstruct our signing key");
            return None;
        }
    };
    let sk = ml_dsa::SigningKey::<MlDsa87>::decode(&sk_enc);

    let sig_node = match sk.sign_deterministic(&transcript2, PQC_CONTEXT) {
        Ok(sig) => sig,
        Err(_) => {
            eprintln!("[M13-NODE-PQC] ERROR: ML-DSA signing failed");
            return None;
        }
    };
    let sig_node_bytes = sig_node.encode();
    eprintln!("[M13-NODE-PQC] Node signature generated ({}B)", sig_node_bytes.len());

    let mut finished = Vec::with_capacity(1 + sig_node_bytes.len());
    finished.push(HS_FINISHED);
    finished.extend_from_slice(&sig_node_bytes);

    Some((session_key, finished))
}
