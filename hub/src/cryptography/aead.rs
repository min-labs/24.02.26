// M13 HUB — AES-256-GCM AEAD
// x86: AES-NI hw accel (~4-10 GiB/s). ARM A53 (K26): ARMv8 Crypto Extensions.
// Future: FPGA AES-GCM IP core for line-rate offload. Wire format unchanged.
//
// Nonce layout: seq_id(8) || direction(1) || zeros(3) = 12 bytes
// AAD: signature[0..4] (magic + version + crypto_ver + reserved)
// Encrypted region: M13Header bytes [32..48] (seq_id, flags, payload_len, padding)

use ring::aead;

/// Encrypt a frame in-place. Writes AEAD tag into signature[4..20], nonce into [20..32].
/// Sets signature[2] = 0x01 (encrypted marker).
pub fn seal_frame(frame: &mut [u8], lsk: &aead::LessSafeKey, seq: u64, direction: u8, offset: usize) {
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[0..8].copy_from_slice(&seq.to_le_bytes());
    nonce_bytes[8] = direction;
    let sig = offset;
    frame[sig+2] = 0x01; frame[sig+3] = 0x00;
    frame[sig+20..sig+32].copy_from_slice(&nonce_bytes);
    let pt = sig + 32;
    let nonce = aead::Nonce::try_assume_unique_for_key(&nonce_bytes).unwrap();
    let aad_bytes: [u8; 4] = frame[sig..sig+4].try_into().unwrap();
    let aad = aead::Aad::from(aad_bytes);
    let tag = lsk.seal_in_place_separate_tag(nonce, aad, &mut frame[pt..]).unwrap();
    frame[sig+4..sig+20].copy_from_slice(tag.as_ref());
}

/// Decrypt a frame in-place. Verifies AEAD tag. Returns false on auth failure.
/// Reflection guard: rejects frames where nonce direction byte == our_dir.
pub fn open_frame(frame: &mut [u8], lsk: &aead::LessSafeKey, our_dir: u8, offset: usize) -> bool {
    let sig = offset;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn make_key(key_bytes: &[u8; 32]) -> aead::LessSafeKey {
        let ubk = aead::UnboundKey::new(&aead::AES_256_GCM, key_bytes).unwrap();
        aead::LessSafeKey::new(ubk)
    }

    fn make_frame(offset: usize) -> Vec<u8> {
        // Minimum: offset + signature(32) + encrypted_region(16)
        vec![0u8; offset + 48 + 64]
    }

    #[test]
    fn seal_open_roundtrip() {
        let key = make_key(&[0x42u8; 32]);
        let offset = 14; // ETH_HDR_SIZE
        let mut frame = make_frame(offset);
        // Set magic/version
        frame[offset] = 0xD1; frame[offset+1] = 0x01;
        // Write known plaintext pattern
        for i in 0..16 { frame[offset + 32 + i] = (i as u8) + 1; }
        let original = frame[offset+32..offset+48].to_vec();

        seal_frame(&mut frame, &key, 1, 0x00, offset);
        // After seal, encrypted marker should be set
        assert_eq!(frame[offset+2], 0x01);

        // Open with correct key and opposite direction
        assert!(open_frame(&mut frame, &key, 0x01, offset));
        assert_eq!(&frame[offset+32..offset+48], &original[..]);
    }

    #[test]
    fn tamper_detected() {
        let key = make_key(&[0x42u8; 32]);
        let offset = 14;
        let mut frame = make_frame(offset);
        frame[offset] = 0xD1; frame[offset+1] = 0x01;
        seal_frame(&mut frame, &key, 2, 0x00, offset);
        // Tamper with ciphertext
        frame[offset + 32] ^= 0xFF;
        assert!(!open_frame(&mut frame, &key, 0x01, offset));
    }

    #[test]
    fn wrong_key_rejected() {
        let key1 = make_key(&[0x42u8; 32]);
        let key2 = make_key(&[0x99u8; 32]);
        let offset = 14;
        let mut frame = make_frame(offset);
        frame[offset] = 0xD1; frame[offset+1] = 0x01;
        seal_frame(&mut frame, &key1, 3, 0x00, offset);
        assert!(!open_frame(&mut frame, &key2, 0x01, offset));
    }

    #[test]
    fn reflection_guard() {
        let key = make_key(&[0x42u8; 32]);
        let offset = 14;
        let mut frame = make_frame(offset);
        frame[offset] = 0xD1; frame[offset+1] = 0x01;
        seal_frame(&mut frame, &key, 4, 0x00, offset);
        // Open with SAME direction → should be rejected
        assert!(!open_frame(&mut frame, &key, 0x00, offset));
    }
}
