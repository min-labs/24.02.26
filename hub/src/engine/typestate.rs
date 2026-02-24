// M13 HUB — COMPILE-TIME TYPESTATE MACHINE + ADVERSARIAL INGRESS SHIELDS
//
// Zero-sized marker types enforce legal peer lifecycle transitions at compile
// time.  The adversarial guard functions are branchless #[inline(always)]
// predicates called from the hot path (process_fragment, rx_parse_raw) to
// reject malformed frames before any unsafe pointer arithmetic occurs.
//
// Runtime cost: zero bytes added to PeerSlot (pure phantom/ZST).
// Cache impact: none — guards are register-only comparisons.

use core::marker::PhantomData;
use crate::engine::protocol::{PeerSlot, PeerLifecycle, MAX_FRAGMENTS, M13_HDR_SIZE};

// ============================================================================
// SEALED TRAIT — prevent downstream impl
// ============================================================================

mod sealed { pub trait Sealed {} }

/// Marker trait for peer lifecycle states.  Sealed to prevent external impl.
pub trait PeerState: sealed::Sealed + Copy + 'static {
    /// Runtime discriminant that maps to PeerLifecycle enum.
    const DISCRIMINANT: PeerLifecycle;
}

// ============================================================================
// ZERO-SIZED STATE MARKERS
// ============================================================================

#[derive(Clone, Copy, Debug)]
pub struct Empty;
impl sealed::Sealed for Empty {}
impl PeerState for Empty { const DISCRIMINANT: PeerLifecycle = PeerLifecycle::Empty; }

#[derive(Clone, Copy, Debug)]
pub struct Registered;
impl sealed::Sealed for Registered {}
impl PeerState for Registered { const DISCRIMINANT: PeerLifecycle = PeerLifecycle::Registered; }

#[derive(Clone, Copy, Debug)]
pub struct Handshaking;
impl sealed::Sealed for Handshaking {}
impl PeerState for Handshaking { const DISCRIMINANT: PeerLifecycle = PeerLifecycle::Handshaking; }

#[derive(Clone, Copy, Debug)]
pub struct Established;
impl sealed::Sealed for Established {}
impl PeerState for Established { const DISCRIMINANT: PeerLifecycle = PeerLifecycle::Established; }

// ============================================================================
// TYPED PEER WRAPPER — compile-time field access guard
// ============================================================================

/// Zero-cost wrapper that constrains which PeerSlot fields are accessible
/// based on the compile-time lifecycle state `S`.  The PhantomData marker
/// adds zero bytes; the inner reference is a raw pointer-width borrow.
pub struct TypedPeer<'a, S: PeerState> {
    pub slot: &'a mut PeerSlot,
    _state: PhantomData<S>,
}

impl<'a, S: PeerState> TypedPeer<'a, S> {
    /// Wrap a PeerSlot reference with compile-time state.
    /// # Safety
    /// Caller must ensure the runtime lifecycle matches `S::DISCRIMINANT`.
    #[inline(always)]
    pub unsafe fn from_raw(slot: &'a mut PeerSlot) -> Self {
        debug_assert_eq!(
            slot.lifecycle, S::DISCRIMINANT,
            "TypedPeer: runtime lifecycle {:?} does not match compile-time state {:?}",
            slot.lifecycle, S::DISCRIMINANT,
        );
        TypedPeer { slot, _state: PhantomData }
    }

    /// Read-only access to address (always valid).
    #[inline(always)]
    pub fn addr(&self) -> &crate::engine::protocol::PeerAddr { &self.slot.addr }

    /// Read-only access to MAC (always valid).
    #[inline(always)]
    pub fn mac(&self) -> &[u8; 6] { &self.slot.mac }
}

// ----- State-specific accessors -----

impl<'a> TypedPeer<'a, Empty> {
    /// Transition: Empty → Registered.  Sets addr, mac, lifecycle.
    #[inline(always)]
    pub fn register(self, addr: crate::engine::protocol::PeerAddr, mac: [u8; 6]) -> TypedPeer<'a, Registered> {
        self.slot.addr = addr;
        self.slot.mac = mac;
        self.slot.lifecycle = PeerLifecycle::Registered;
        TypedPeer { slot: self.slot, _state: PhantomData }
    }
}

impl<'a> TypedPeer<'a, Registered> {
    /// Transition: Registered → Handshaking.
    #[inline(always)]
    pub fn begin_handshake(self) -> TypedPeer<'a, Handshaking> {
        self.slot.lifecycle = PeerLifecycle::Handshaking;
        TypedPeer { slot: self.slot, _state: PhantomData }
    }
}

impl<'a> TypedPeer<'a, Handshaking> {
    /// Transition: Handshaking → Established.  Installs session key.
    #[inline(always)]
    pub fn establish(self, session_key: [u8; 32]) -> TypedPeer<'a, Established> {
        self.slot.session_key = session_key;
        self.slot.frame_count = 0;
        self.slot.lifecycle = PeerLifecycle::Established;
        TypedPeer { slot: self.slot, _state: PhantomData }
    }

    /// Transition: Handshaking → Empty (failed handshake, evict peer).
    #[inline(always)]
    pub fn fail(self) -> TypedPeer<'a, Empty> {
        self.slot.reset_session();
        self.slot.lifecycle = PeerLifecycle::Empty;
        TypedPeer { slot: self.slot, _state: PhantomData }
    }
}

impl<'a> TypedPeer<'a, Established> {
    /// Read session key (only available in Established state).
    #[inline(always)]
    pub fn session_key(&self) -> &[u8; 32] { &self.slot.session_key }

    /// Increment and return sequence number.
    #[inline(always)]
    pub fn next_seq(&mut self) -> u64 { self.slot.next_seq() }

    /// Increment frame count, return current value.
    #[inline(always)]
    pub fn tick_frame(&mut self) -> u64 {
        let c = self.slot.frame_count;
        self.slot.frame_count = c.wrapping_add(1);
        c
    }
}

// ============================================================================
// ADVERSARIAL INGRESS SHIELDS — branchless validation predicates
// ============================================================================

/// Validate fragment index/total before any reassembly.
/// Returns `true` if the fragment metadata is within legal bounds.
///
/// Branchless: the three comparisons compile to `cmp + setb` on x86_64
/// (no conditional branches, no BHT pollution).
///
/// Invariants enforced:
///   - `total > 0` (zero-fragment messages are invalid)
///   - `total <= MAX_FRAGMENTS` (prevents oversized reassembly)
///   - `index < total` (prevents OOB slot write)
#[inline(always)]
pub const fn validate_frag_index(index: u8, total: u8) -> bool {
    total > 0 && total <= MAX_FRAGMENTS && index < total
}

/// Validate that the M13 header region [offset .. offset + M13_HDR_SIZE]
/// fits within the UMEM frame.  Prevents OOB reads on malformed packets.
///
/// Branchless: single unsigned comparison after addition.
#[inline(always)]
pub const fn validate_m13_offset(offset: u16, frame_len: u32) -> bool {
    (offset as u32).saturating_add(M13_HDR_SIZE as u32) <= frame_len
}

/// Validate that fragment data region fits within the frame.
/// Prevents OOB slice construction from attacker-controlled offsets.
#[inline(always)]
pub const fn validate_frag_data_bounds(
    m13_offset: u16,
    frag_data_len: u16,
    frame_len: u32,
) -> bool {
    let frag_region_end = (m13_offset as u32)
        .saturating_add(M13_HDR_SIZE as u32)
        .saturating_add(8) // FRAG_HDR_SIZE
        .saturating_add(frag_data_len as u32);
    frag_region_end <= frame_len
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frag_index_valid_cases() {
        // index=0, total=1 → single fragment, valid
        assert!(validate_frag_index(0, 1));
        // index=6, total=7 → last of 7 (ServerHello), valid
        assert!(validate_frag_index(6, 7));
        // index=0, total=MAX_FRAGMENTS → max size, valid
        assert!(validate_frag_index(0, MAX_FRAGMENTS));
        // index=MAX_FRAGMENTS-1, total=MAX_FRAGMENTS → last slot, valid
        assert!(validate_frag_index(MAX_FRAGMENTS - 1, MAX_FRAGMENTS));
    }

    #[test]
    fn frag_index_adversarial_cases() {
        // index >= total → OOB
        assert!(!validate_frag_index(3, 3));
        assert!(!validate_frag_index(7, 3));
        assert!(!validate_frag_index(255, 1));
        // total = 0 → invalid
        assert!(!validate_frag_index(0, 0));
        // total > MAX_FRAGMENTS → oversized
        assert!(!validate_frag_index(0, MAX_FRAGMENTS + 1));
        assert!(!validate_frag_index(0, 255));
    }

    #[test]
    fn m13_offset_valid() {
        // Normal UDP encap: offset=56, framelen=1500 → 56+48=104 ≤ 1500
        assert!(validate_m13_offset(56, 1500));
        // L2 direct: offset=14, framelen=1514
        assert!(validate_m13_offset(14, 1514));
        // Exact boundary
        assert!(validate_m13_offset(0, M13_HDR_SIZE as u32));
    }

    #[test]
    fn m13_offset_adversarial() {
        // Offset pushes header past frame end
        assert!(!validate_m13_offset(1500, 1500));
        // Frame too short for header
        assert!(!validate_m13_offset(0, 47)); // M13_HDR_SIZE = 48
        // Overflow attempt
        assert!(!validate_m13_offset(u16::MAX, 100));
    }

    #[test]
    fn frag_data_bounds_valid() {
        // m13_offset=56, M13_HDR=48, FRAG_HDR=8, frag_data=1380, total=56+48+8+1380=1492 ≤ 1500
        assert!(validate_frag_data_bounds(56, 1380, 1500));
    }

    #[test]
    fn frag_data_bounds_adversarial() {
        // frag_data_len pushes past frame
        assert!(!validate_frag_data_bounds(56, 1500, 1500));
        // Zero-length frame
        assert!(!validate_frag_data_bounds(0, 1, 0));
    }
}
