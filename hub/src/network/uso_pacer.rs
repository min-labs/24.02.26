// M13 HUB — USO MTU SLICER & EDT HARDWARE PACER
//
// EDT (Earliest Departure Time) pacing prevents PCIe DMA flooding by
// enforcing a minimum inter-packet gap at the TSC granularity.  This
// prevents micro-burst buffer overflows in both the NIC TX ring and
// downstream switch ASICs.
//
// USO (Userspace Segmentation Offload) slices oversized payloads into
// MTU-sized fragments for zero-copy iteration.
//
// Threading: Called from datapath core.  Zero heap.  Zero syscall.
// Timing: TSC spin-loop (rdtsc/cntvct_el0) — sub-microsecond accuracy.

use crate::engine::runtime::TscCal;

// ============================================================================
// CONSTANTS
// ============================================================================

/// Default USO MTU (bytes).  1380 = 1500 - IP(20) - UDP(8) - M13(48) - FragHdr(8) - ETH(14) + headroom.
/// This matches the fragment chunk size used throughout the protocol.
pub const USO_MTU: usize = 1380;

/// Minimum inter-packet gap in TSC ticks for 1 Gbps Ethernet.
/// At 1 Gbps with 1500-byte frames: 12 µs/packet → at 1.5 GHz TSC = 18000 ticks.
/// We use a configurable value initialized from link rate.
const DEFAULT_IPG_NS: u64 = 12_000; // 12 µs — 1500B frame at 1 Gbps

// ============================================================================
// TSC CONVERSION HELPER
// ============================================================================





// ============================================================================
// EDT PACER
// ============================================================================

/// Earliest Departure Time pacer.
/// Tracks the TSC value at which the next packet may depart.
/// If the current time is before `next_departure_tsc`, the pacer
/// spins until the deadline is met.
///
/// Memory: 24 bytes (3 × u64).  Fits in a single cache line with room to spare.
/// V4: Zero-spin Earliest Departure Time pacer.
/// Returns a `release_ns` timestamp instead of spin-waiting.
/// The scheduler gates on `release_ns` with non-blocking head-of-line checks.
///
/// Memory: 24 bytes (3 × u64).  Fits in a single cache line with room to spare.
pub struct EdtPacer {
    /// Nanosecond timestamp of last scheduled departure.
    last_tx_ns: u64,
    /// Nanoseconds per byte at configured link rate.
    ns_per_byte: u64,
    /// Number of packets paced (telemetry counter).
    paced_count: u64,
}

impl EdtPacer {
    /// V4: Create a new pacer calibrated for the given link rate.
    /// `_cal`: TSC calibration (retained for API compatibility, unused in zero-spin mode).
    /// `link_bps`: Link speed in bits per second (e.g., 100_000_000 for 100 Mbps).
    pub fn new(_cal: &TscCal, link_bps: u64) -> Self {
        let ns_per_byte = if link_bps > 0 {
            // 8 bits per byte, 1e9 ns per second
            (8 * 1_000_000_000) / link_bps
        } else {
            DEFAULT_IPG_NS  // ~120ns fallback
        };

        EdtPacer {
            last_tx_ns: 0,
            ns_per_byte: ns_per_byte.max(1),
            paced_count: 0,
        }
    }

    /// Create a pacer with a fixed inter-packet gap in nanoseconds.
    /// Useful for testing without TSC calibration.
    pub fn with_fixed_gap_ns(gap_ns: u64, _cal: &TscCal) -> Self {
        EdtPacer {
            last_tx_ns: 0,
            ns_per_byte: gap_ns.max(1),
            paced_count: 0,
        }
    }

    /// V4: Zero-spin pacing — compute release time, don't block.
    /// Returns `release_ns` for the scheduler to gate on.
    ///
    /// `now_ns`: Current monotonic time in nanoseconds.
    /// `frame_bytes`: Size of this specific frame in bytes (dynamic per-packet).
    #[inline(always)]
    pub fn pace(&mut self, now_ns: u64, frame_bytes: u32) -> u64 {
        let delay_ns = (frame_bytes as u64) * self.ns_per_byte;
        let release_ns = self.last_tx_ns.max(now_ns) + delay_ns;
        self.last_tx_ns = release_ns;
        self.paced_count += 1;
        release_ns
    }

    /// Reset the departure timestamp to `now` (used after idle periods
    /// to prevent burst-compensating all missed slots).
    #[inline(always)]
    pub fn reset(&mut self, now_ns: u64) {
        self.last_tx_ns = now_ns;
    }

    /// Number of packets paced since creation.
    #[inline(always)]
    pub fn paced_count(&self) -> u64 { self.paced_count }

    /// Current nanoseconds per byte.
    #[inline(always)]
    pub fn ns_per_byte(&self) -> u64 { self.ns_per_byte }

    /// Update link rate dynamically (e.g., for congestion control).
    #[inline(always)]
    pub fn set_link_bps(&mut self, link_bps: u64) {
        self.ns_per_byte = if link_bps > 0 {
            ((8 * 1_000_000_000) / link_bps).max(1)
        } else {
            DEFAULT_IPG_NS
        };
    }
}

// ============================================================================
// USO SLICER — ZERO-COPY MTU FRAGMENTATION ITERATOR
// ============================================================================

/// Zero-copy iterator that yields MTU-sized slices of a payload.
/// No allocation.  Just pointer arithmetic on the input slice.
pub struct UsoSliceIter<'a> {
    payload: &'a [u8],
    offset: usize,
    mtu: usize,
}

impl<'a> UsoSliceIter<'a> {
    /// Create a new USO slicer for the given payload and MTU.
    #[inline(always)]
    pub fn new(payload: &'a [u8], mtu: usize) -> Self {
        UsoSliceIter { payload, offset: 0, mtu: mtu.max(1) }
    }

    /// Number of total slices.
    #[inline(always)]
    pub fn total_slices(&self) -> usize {
        if self.payload.is_empty() { return 0; }
        (self.payload.len() + self.mtu - 1) / self.mtu
    }
}

impl<'a> Iterator for UsoSliceIter<'a> {
    type Item = &'a [u8];

    #[inline(always)]
    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.payload.len() {
            return None;
        }
        let end = (self.offset + self.mtu).min(self.payload.len());
        let slice = &self.payload[self.offset..end];
        self.offset = end;
        Some(slice)
    }

    #[inline(always)]
    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = if self.offset >= self.payload.len() {
            0
        } else {
            (self.payload.len() - self.offset + self.mtu - 1) / self.mtu
        };
        (remaining, Some(remaining))
    }
}

impl<'a> ExactSizeIterator for UsoSliceIter<'a> {}

/// Convenience function: slice payload into MTU-sized chunks.
#[inline]
pub fn slice_uso(payload: &[u8], mtu: usize) -> UsoSliceIter<'_> {
    UsoSliceIter::new(payload, mtu)
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uso_slicing_exact() {
        let data = [0xAB; 4140]; // 3 × 1380 exactly
        let slices: Vec<&[u8]> = slice_uso(&data, 1380).collect();
        assert_eq!(slices.len(), 3);
        for s in &slices {
            assert_eq!(s.len(), 1380);
        }
    }

    #[test]
    fn uso_slicing_remainder() {
        let data = [0xCD; 4000]; // 2 × 1380 + 1240 remainder
        let slices: Vec<&[u8]> = slice_uso(&data, 1380).collect();
        assert_eq!(slices.len(), 3);
        assert_eq!(slices[0].len(), 1380);
        assert_eq!(slices[1].len(), 1380);
        assert_eq!(slices[2].len(), 1240);
    }

    #[test]
    fn uso_slicing_single() {
        let data = [0xEF; 100];
        let slices: Vec<&[u8]> = slice_uso(&data, 1380).collect();
        assert_eq!(slices.len(), 1);
        assert_eq!(slices[0].len(), 100);
    }

    #[test]
    fn uso_slicing_empty() {
        let data: [u8; 0] = [];
        let slices: Vec<&[u8]> = slice_uso(&data, 1380).collect();
        assert_eq!(slices.len(), 0);
    }

    #[test]
    fn uso_total_slices_matches_iter() {
        for payload_len in [0, 1, 1379, 1380, 1381, 4140, 8788, 9216] {
            let data = vec![0u8; payload_len];
            let iter = slice_uso(&data, 1380);
            let expected = iter.total_slices();
            let actual = iter.count();
            assert_eq!(expected, actual, "Mismatch for payload_len={}", payload_len);
        }
    }

    #[test]
    fn uso_server_hello_fragmentation() {
        // ServerHello = 8788 bytes → ⌈8788/1380⌉ = 7 fragments
        let data = [0x02; 8788];
        let slices: Vec<&[u8]> = slice_uso(&data, 1380).collect();
        assert_eq!(slices.len(), 7);
        assert_eq!(slices[0].len(), 1380);
        assert_eq!(slices[5].len(), 1380);
        assert_eq!(slices[6].len(), 8788 - 6 * 1380); // 508 bytes
    }

    #[test]
    fn pacer_struct_size() {
        // EDT pacer must fit comfortably in cache
        assert!(core::mem::size_of::<EdtPacer>() <= 64, "EdtPacer exceeds 1 cache line");
    }
}
