// M13 HUB — CRYPTOGRAPHY MODULE
// AES-256-GCM AEAD (data plane) + ML-KEM-1024/ML-DSA-87 PQC handshake (control plane).

pub mod aead;
pub mod handshake;
pub mod async_pqc;
