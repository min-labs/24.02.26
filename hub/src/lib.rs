// M13 HUB — CRATE ROOT (LIBRARY)
// World-class VPP architecture: genuine graph-based vector packet processing.
//
// Module hierarchy:
//   engine/protocol  — Wire format, peer table, fragmentation, scheduler,
//                      jitter buffer, receiver state, feedback production
//   engine/runtime   — TSC clock, CPU pinning, telemetry (SHM), fatal exit, slab allocator
//   network/         — AF_XDP engine, BPF steersman, VPP pipeline, datapath graph nodes
//   cryptography/    — AES-256-GCM AEAD, PQC handshake (ML-KEM + ML-DSA)

pub mod cryptography;
pub mod network;
pub mod engine;
