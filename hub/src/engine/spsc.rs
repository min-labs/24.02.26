// M13 HUB — ENGINE: SPSC LOCK-FREE RING (REMEDIATION SPRINT R-02A)
// Architecture: Wait-Free, Zero-Allocation, Bulk Batching, AXI False-Sharing Immune.
//
// Used to decouple VFS syscalls (TUN read/write) from the AF_XDP datapath core.
// The Datapath thread (Core 2) and TUN Housekeeping thread (Core N) exchange
// PacketDesc indices and free-slab IDs through these rings with zero contention.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Hardware Cache-Line Padding.
/// 128 bytes guarantees immunity from L1d False Sharing and adjacent
/// hardware spatial prefetcher intersections (128-byte stride on ARM Cortex-A53,
/// 128-byte pair on Intel Spatial Prefetcher).
#[repr(C, align(128))]
struct CachePadded<T> {
    value: T,
}

#[allow(dead_code)]
pub struct SpscRing<T> {
    head: CachePadded<AtomicUsize>, // Producer-written, Consumer-read
    tail: CachePadded<AtomicUsize>, // Consumer-written, Producer-read
    capacity: usize,
    mask: usize,
    buffer: *mut T,
}

// SAFETY: The ring buffer is designed for single-producer single-consumer use.
// Send is required to move Producer/Consumer across thread boundaries.
// Sync is required because both threads hold Arc<SpscRing<T>> references.
unsafe impl<T: Send> Send for SpscRing<T> {}
unsafe impl<T: Send> Sync for SpscRing<T> {}

impl<T> Drop for SpscRing<T> {
    fn drop(&mut self) {
        // Recover the Vec allocation. Length 0 because we manage elements manually.
        // PacketDesc and u32 are Copy types with no Drop impl, so no element cleanup needed.
        unsafe { let _ = Vec::from_raw_parts(self.buffer, 0, self.capacity); }
    }
}

pub struct Producer<T> {
    ring: Arc<SpscRing<T>>,
    local_head: usize,
    local_tail: usize, // DPDK-style cache: avoids cross-core Acquire on every push
    capacity: usize,
    mask: usize,
}

pub struct Consumer<T> {
    ring: Arc<SpscRing<T>>,
    local_head: usize, // DPDK-style cache: avoids cross-core Acquire on every pop
    local_tail: usize,
    mask: usize,
}

// SAFETY: Producer and Consumer are each used by exactly one thread.
unsafe impl<T: Send> Send for Producer<T> {}
unsafe impl<T: Send> Send for Consumer<T> {}

/// Create a new SPSC ring pair. Capacity must be a power of two.
pub fn make_spsc<T: Copy>(capacity: usize) -> (Producer<T>, Consumer<T>) {
    assert!(capacity.is_power_of_two(), "[FATAL] SPSC capacity must be a power of two");
    let mut vec = Vec::with_capacity(capacity);
    let buffer = vec.as_mut_ptr();
    std::mem::forget(vec);

    let ring = Arc::new(SpscRing {
        head: CachePadded { value: AtomicUsize::new(0) },
        tail: CachePadded { value: AtomicUsize::new(0) },
        capacity,
        mask: capacity - 1,
        buffer,
    });

    (
        Producer { ring: ring.clone(), local_head: 0, local_tail: 0, capacity, mask: capacity - 1 },
        Consumer { ring, local_head: 0, local_tail: 0, mask: capacity - 1 },
    )
}

impl<T: Copy> Producer<T> {
    /// Returns the number of free slots currently available for pushing.
    /// Refreshes the cached tail from the consumer to get latest physical availability.
    #[inline(always)]
    pub fn available(&mut self) -> usize {
        self.local_tail = self.ring.tail.value.load(Ordering::Acquire);
        self.capacity - self.local_head.wrapping_sub(self.local_tail)
    }

    /// Batch push elements. Amortizes the atomic Release store over N items,
    /// emitting exactly ONE memory barrier per batch instead of N.
    /// Returns the number of items successfully pushed.
    #[inline(always)]
    pub fn push_batch(&mut self, items: &[T]) -> usize {
        let n = items.len();
        if n == 0 { return 0; }

        // DPDK Optimization: Only cross the interconnect (Acquire) if local cache
        // says the ring is too full for the requested batch.
        let mut available = self.capacity - self.local_head.wrapping_sub(self.local_tail);
        if available < n {
            self.local_tail = self.ring.tail.value.load(Ordering::Acquire);
            available = self.capacity - self.local_head.wrapping_sub(self.local_tail);
        }

        let to_push = std::cmp::min(n, available);
        if to_push == 0 { return 0; }

        for i in 0..to_push {
            // SAFETY: index is masked to buffer bounds; buffer is valid for capacity elements.
            unsafe { self.ring.buffer.add((self.local_head + i) & self.mask).write(items[i]); }
        }

        self.local_head = self.local_head.wrapping_add(to_push);
        // Single Release barrier for the entire batch — publish all writes atomically.
        self.ring.head.value.store(self.local_head, Ordering::Release);
        to_push
    }
}

impl<T: Copy> Consumer<T> {
    /// Batch pop elements. Returns the number of items successfully popped.
    #[inline(always)]
    pub fn pop_batch(&mut self, out: &mut [T]) -> usize {
        let n = out.len();
        if n == 0 { return 0; }

        let mut available = self.local_head.wrapping_sub(self.local_tail);
        if available == 0 {
            self.local_head = self.ring.head.value.load(Ordering::Acquire);
            available = self.local_head.wrapping_sub(self.local_tail);
        }

        let to_pop = std::cmp::min(n, available);
        if to_pop == 0 { return 0; }

        for i in 0..to_pop {
            // SAFETY: index is masked to buffer bounds; buffer is valid for capacity elements.
            out[i] = unsafe { self.ring.buffer.add((self.local_tail + i) & self.mask).read() };
        }

        self.local_tail = self.local_tail.wrapping_add(to_pop);
        // Single Release barrier for the entire batch.
        self.ring.tail.value.store(self.local_tail, Ordering::Release);
        to_pop
    }
}
