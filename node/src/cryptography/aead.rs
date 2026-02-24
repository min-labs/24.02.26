// M13 NODE — CRYPTOGRAPHY: AEAD MODULE
// AES-256-GCM seal/open for M13 frames — scalar + vectorized batch.
// Zero-share: independent copy from Hub.
//
// Scalar API:   seal_frame, open_frame (single frame)
// Batch API:    decrypt_batch_ptrs, encrypt_batch_ptrs (4-at-a-time, AES-NI/ARMv8-CE saturating)

use ring::aead;
use crate::engine::protocol::ETH_HDR_SIZE;

// ============================================================================
// SCALAR API — Single-frame seal/open
// ============================================================================

/// Seal (encrypt+authenticate) an M13 frame in-place.
pub fn seal_frame(frame: &mut [u8], lsk: &aead::LessSafeKey, seq: u64, direction: u8) {
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[0..8].copy_from_slice(&seq.to_le_bytes());
    nonce_bytes[8] = direction;
    let sig = ETH_HDR_SIZE;
    frame[sig+2] = 0x01; frame[sig+3] = 0x00;
    frame[sig+20..sig+32].copy_from_slice(&nonce_bytes);
    let pt = sig + 32;
    let nonce = aead::Nonce::try_assume_unique_for_key(&nonce_bytes).unwrap();
    let aad_bytes: [u8; 4] = frame[sig..sig+4].try_into().unwrap();
    let aad = aead::Aad::from(aad_bytes);
    let tag = lsk.seal_in_place_separate_tag(nonce, aad, &mut frame[pt..]).unwrap();
    frame[sig+4..sig+20].copy_from_slice(tag.as_ref());
}

/// Open (verify+decrypt) an M13 frame in-place. Returns true if authentic.
pub fn open_frame(frame: &mut [u8], lsk: &aead::LessSafeKey, our_dir: u8) -> bool {
    let sig = ETH_HDR_SIZE;
    if frame.len() < sig + 32 + 8 { return false; }
    if frame[sig+2] != 0x01 { return false; }
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(&frame[sig+20..sig+32]);
    if nonce_bytes[8] == our_dir { return false; } // reflection guard
    let mut wire_tag_bytes = [0u8; 16];
    wire_tag_bytes.copy_from_slice(&frame[sig+4..sig+20]);
    let pt = sig + 32;
    let nonce = aead::Nonce::try_assume_unique_for_key(&nonce_bytes).unwrap();
    let aad_bytes: [u8; 4] = frame[sig..sig+4].try_into().unwrap();
    let aad = aead::Aad::from(&aad_bytes);
    let tag = aead::Tag::from(wire_tag_bytes);
    lsk.open_in_place_separate_tag(nonce, aad, tag, &mut frame[pt..], 0..).is_ok()
}

// ============================================================================
// BATCH API — Vectorized, zero-alloc, AES-NI/ARMv8-CE saturating
// ============================================================================

/// Marker value for pre-decrypted frames.
/// Batch decrypt sets this instead of `0x01` (encrypted) or `0x00` (cleartext).
/// `process_rx_frame` recognizes this and skips both decrypt and cleartext-reject.
pub const PRE_DECRYPTED_MARKER: u8 = 0x02;

/// Prefetch a cache line for read.
#[inline(always)]
unsafe fn prefetch_read_l1(ptr: *const u8) {
    #[cfg(target_arch = "x86_64")]
    {
        std::arch::x86_64::_mm_prefetch(ptr as *const i8, std::arch::x86_64::_MM_HINT_T0);
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = ptr;
    }
}

/// Vectorized AEAD decrypt for up to `count` frames using a single cipher.
/// Uses 4-at-a-time prefetch to saturate AES-NI (x86) / ARMv8 Crypto Extensions (aarch64) pipeline.
///
/// Returns number of successful decryptions.
#[inline]
pub fn decrypt_batch_ptrs(
    ptrs: &[*mut u8],
    lens: &[usize],
    count: usize,
    cipher: &aead::LessSafeKey,
    direction: u8,
    results: &mut [bool],
) -> usize {
    let n = count;
    let mut ok_count = 0usize;
    let mut i = 0;

    while i + 4 <= n {
        if i + 8 <= n {
            for k in 4..8 {
                // SAFETY: Prefetch is advisory; no memory safety impact.
                unsafe { prefetch_read_l1(ptrs[i + k]); }
            }
        }
        for j in 0..4 {
            // SAFETY: Caller guarantees ptrs[idx] is valid for lens[idx] bytes.
            let frame = unsafe { std::slice::from_raw_parts_mut(ptrs[i + j], lens[i + j]) };
            let ok = decrypt_one(frame, cipher, direction);
            results[i + j] = ok;
            if ok { ok_count += 1; }
        }
        i += 4;
    }

    while i < n {
        let frame = unsafe { std::slice::from_raw_parts_mut(ptrs[i], lens[i]) };
        let ok = decrypt_one(frame, cipher, direction);
        results[i] = ok;
        if ok { ok_count += 1; }
        i += 1;
    }

    ok_count
}

/// Decrypt one frame in-place. Returns true if authentic.
/// On success, stamps `PRE_DECRYPTED_MARKER` at `frame[ETH_HDR_SIZE + 2]`.
#[inline(always)]
fn decrypt_one(frame: &mut [u8], cipher: &aead::LessSafeKey, our_dir: u8) -> bool {
    let sig = ETH_HDR_SIZE;
    if frame.len() < sig + 32 + 8 { return false; }
    if frame[sig + 2] != 0x01 { return false; }

    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(&frame[sig + 20..sig + 32]);
    if nonce_bytes[8] == our_dir { return false; }

    let mut wire_tag_bytes = [0u8; 16];
    wire_tag_bytes.copy_from_slice(&frame[sig + 4..sig + 20]);

    let pt = sig + 32;
    let nonce = aead::Nonce::try_assume_unique_for_key(&nonce_bytes).unwrap();
    let aad_bytes: [u8; 4] = frame[sig..sig + 4].try_into().unwrap();
    let aad = aead::Aad::from(&aad_bytes);
    let tag = aead::Tag::from(wire_tag_bytes);
    let ok = aead::LessSafeKey::open_in_place_separate_tag(
        cipher, nonce, aad, tag, &mut frame[pt..], 0..,
    ).is_ok();

    if ok {
        frame[sig + 2] = PRE_DECRYPTED_MARKER;
    }

    ok
}

/// Vectorized AEAD encrypt for up to `count` frames using a single cipher.
/// Uses 4-at-a-time prefetch to saturate AES-NI (x86) / ARMv8 Crypto Extensions (aarch64) pipeline.
///
/// Returns number of frames encrypted.
#[inline]
pub fn encrypt_batch_ptrs(
    ptrs: &[*mut u8],
    lens: &[usize],
    count: usize,
    cipher: &aead::LessSafeKey,
    direction: u8,
    seq_base: u64,
) -> usize {
    let n = count;
    let mut i = 0;

    while i + 4 <= n {
        if i + 8 <= n {
            for k in 4..8 {
                // SAFETY: Prefetch is advisory; no memory safety impact.
                unsafe { prefetch_read_l1(ptrs[i + k]); }
            }
        }
        for j in 0..4 {
            let seq = seq_base + (i + j) as u64;
            // SAFETY: Caller guarantees ptrs[idx] is valid for lens[idx] bytes.
            let frame = unsafe { std::slice::from_raw_parts_mut(ptrs[i + j], lens[i + j]) };
            encrypt_one(frame, cipher, seq, direction);
        }
        i += 4;
    }

    while i < n {
        let seq = seq_base + i as u64;
        let frame = unsafe { std::slice::from_raw_parts_mut(ptrs[i], lens[i]) };
        encrypt_one(frame, cipher, seq, direction);
        i += 1;
    }

    n
}

/// Encrypt one frame in-place.
#[inline(always)]
fn encrypt_one(frame: &mut [u8], cipher: &aead::LessSafeKey, seq: u64, direction: u8) {
    let sig = ETH_HDR_SIZE;
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[0..8].copy_from_slice(&seq.to_le_bytes());
    nonce_bytes[8] = direction;

    frame[sig + 2] = 0x01;
    frame[sig + 3] = 0x00;
    frame[sig + 20..sig + 32].copy_from_slice(&nonce_bytes);

    let pt = sig + 32;
    let nonce = aead::Nonce::try_assume_unique_for_key(&nonce_bytes).unwrap();
    let aad_bytes: [u8; 4] = frame[sig..sig + 4].try_into().unwrap();
    let aad = aead::Aad::from(aad_bytes);
    let tag = cipher.seal_in_place_separate_tag(nonce, aad, &mut frame[pt..]).unwrap();
    frame[sig + 4..sig + 20].copy_from_slice(tag.as_ref());
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_key(key_bytes: &[u8; 32]) -> aead::LessSafeKey {
        let ubk = aead::UnboundKey::new(&aead::AES_256_GCM, key_bytes).unwrap();
        aead::LessSafeKey::new(ubk)
    }

    fn make_frame(payload_len: usize) -> Vec<u8> {
        vec![0u8; 14 + 48 + payload_len]
    }

    #[test]
    fn seal_open_roundtrip() {
        let key = make_key(&[0x42u8; 32]);
        let mut frame = make_frame(64);
        frame[14] = 0xD1; frame[15] = 0x01;
        for i in 0..16 { frame[14 + 32 + i] = (i as u8) + 1; }
        let original = frame[46..62].to_vec();
        seal_frame(&mut frame, &key, 1, 0x01);
        assert_eq!(frame[16], 0x01);
        assert!(open_frame(&mut frame, &key, 0x00));
        assert_eq!(&frame[46..62], &original[..]);
    }

    #[test]
    fn tamper_detected() {
        let key = make_key(&[0x42u8; 32]);
        let mut frame = make_frame(64);
        frame[14] = 0xD1; frame[15] = 0x01;
        seal_frame(&mut frame, &key, 2, 0x01);
        frame[46] ^= 0xFF;
        assert!(!open_frame(&mut frame, &key, 0x00));
    }

    #[test]
    fn wrong_key_rejected() {
        let key1 = make_key(&[0x42u8; 32]);
        let key2 = make_key(&[0x99u8; 32]);
        let mut frame = make_frame(64);
        frame[14] = 0xD1; frame[15] = 0x01;
        seal_frame(&mut frame, &key1, 3, 0x01);
        assert!(!open_frame(&mut frame, &key2, 0x00));
    }

    #[test]
    fn reflection_guard() {
        let key = make_key(&[0x42u8; 32]);
        let mut frame = make_frame(64);
        frame[14] = 0xD1; frame[15] = 0x01;
        seal_frame(&mut frame, &key, 4, 0x01);
        assert!(!open_frame(&mut frame, &key, 0x01));
    }

    #[test]
    fn batch_encrypt_decrypt_roundtrip() {
        let key = make_key(&[0x42u8; 32]);
        let mut frames: Vec<Vec<u8>> = (0..8).map(|i| {
            let mut f = make_frame(64);
            f[14] = 0xD1; f[15] = 0x01;
            f[46..54].copy_from_slice(&(i as u64).to_le_bytes());
            for j in 0..64 { f[62 + j] = (i * 10 + j) as u8; }
            f
        }).collect();

        let originals: Vec<Vec<u8>> = frames.iter().map(|f| f[62..126].to_vec()).collect();

        let mut ptrs: [*mut u8; 8] = [std::ptr::null_mut(); 8];
        let mut lens: [usize; 8] = [0; 8];
        for i in 0..8 {
            lens[i] = frames[i].len();
            ptrs[i] = frames[i].as_mut_ptr();
        }
        let count = encrypt_batch_ptrs(&ptrs, &lens, 8, &key, 0x01, 0);
        assert_eq!(count, 8);

        for f in &frames {
            assert_eq!(f[16], 0x01);
        }

        let mut results = [false; 8];
        for i in 0..8 { ptrs[i] = frames[i].as_mut_ptr(); }
        let ok = decrypt_batch_ptrs(&ptrs, &lens, 8, &key, 0x00, &mut results);
        assert_eq!(ok, 8);

        for i in 0..8 {
            assert!(results[i], "frame {} failed decrypt", i);
            assert_eq!(frames[i][16], PRE_DECRYPTED_MARKER, "frame {} missing pre-decrypted marker", i);
            assert_eq!(&frames[i][62..126], &originals[i][..], "payload mismatch frame {}", i);
        }
    }

    #[test]
    fn batch_decrypt_tamper_detected() {
        let key = make_key(&[0x42u8; 32]);
        let mut frames: Vec<Vec<u8>> = (0..4).map(|i| {
            let mut f = make_frame(64);
            f[14] = 0xD1; f[15] = 0x01;
            f[46..54].copy_from_slice(&(i as u64).to_le_bytes());
            f
        }).collect();

        let mut ptrs: [*mut u8; 4] = [std::ptr::null_mut(); 4];
        let mut lens: [usize; 4] = [0; 4];
        for i in 0..4 {
            lens[i] = frames[i].len();
            ptrs[i] = frames[i].as_mut_ptr();
        }
        encrypt_batch_ptrs(&ptrs, &lens, 4, &key, 0x01, 0);

        frames[2][62] ^= 0xFF;

        let mut results = [false; 4];
        for i in 0..4 { ptrs[i] = frames[i].as_mut_ptr(); }
        let ok = decrypt_batch_ptrs(&ptrs, &lens, 4, &key, 0x00, &mut results);
        assert_eq!(ok, 3);
        assert!(results[0]);
        assert!(results[1]);
        assert!(!results[2]);
        assert_eq!(frames[2][16], 0x01);
        assert!(results[3]);
        assert_eq!(frames[3][16], PRE_DECRYPTED_MARKER);
    }

    #[test]
    fn batch_compat_with_scalar() {
        let key = make_key(&[0x42u8; 32]);
        let mut frame = make_frame(64);
        frame[14] = 0xD1; frame[15] = 0x01;
        frame[46..54].copy_from_slice(&42u64.to_le_bytes());
        for i in 0..64 { frame[62 + i] = i as u8; }
        let original = frame[62..126].to_vec();

        let flen = frame.len();
        let ptrs = [frame.as_mut_ptr()];
        let lens = [flen];
        encrypt_batch_ptrs(&ptrs, &lens, 1, &key, 0x01, 42);

        assert!(open_frame(&mut frame, &key, 0x00));
        assert_eq!(&frame[62..126], &original[..]);
    }

    #[test]
    fn scalar_encrypt_batch_decrypt_compat() {
        let key = make_key(&[0x42u8; 32]);
        let mut frame = make_frame(64);
        frame[14] = 0xD1; frame[15] = 0x01;
        for i in 0..64 { frame[62 + i] = i as u8; }
        let original = frame[62..126].to_vec();

        seal_frame(&mut frame, &key, 99, 0x01);

        let flen = frame.len();
        let ptrs = [frame.as_mut_ptr()];
        let lens = [flen];
        let mut results = [false; 1];
        let ok = decrypt_batch_ptrs(&ptrs, &lens, 1, &key, 0x00, &mut results);
        assert_eq!(ok, 1);
        assert!(results[0]);
        assert_eq!(frame[16], PRE_DECRYPTED_MARKER);
        assert_eq!(&frame[62..126], &original[..]);
    }
}
