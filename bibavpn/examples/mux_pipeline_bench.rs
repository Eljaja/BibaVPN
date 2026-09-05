//! Opt-in: cargo run -p bibavpn --release --example mux_pipeline_bench
//! Compile the production modules directly to exercise crate-private helpers without
//! expanding the library API for a benchmark. Both paths use the current RNG.
//! Includes read-scratch -> command payload and command -> serialized wire copies;
//! excludes network/TLS/WebSocket masking and receive-side work.
#[allow(dead_code)]
#[path = "../src/crypto_layer.rs"]
mod crypto_layer;
#[allow(dead_code)]
#[path = "../src/frame.rs"]
mod frame;
use bytes::Bytes;
use crypto_layer::SessionCrypto;
use frame::{AdaptivePadState, PadMode, PreparedFrame};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;
struct Counting;
static ALLOCS: AtomicUsize = AtomicUsize::new(0);
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.realloc(p, l, n) }
    }
}
#[global_allocator]
static A: Counting = Counting;
fn main() {
    for size in [1400, 16384, 65536] {
        let scratch = vec![19; size];
        let count = 64 * 1024 * 1024 / size;
        for fused in [false, true] {
            let c = SessionCrypto::new("bench-key", "bench", &[1; 32], &[2; 32], 32);
            let mut record = Vec::with_capacity(size + 9);
            let mut padded = Vec::with_capacity(size + 9 + 5 + 255);
            let mut adaptive = AdaptivePadState::default();
            let mut header = [0u8; 9];
            header[..4].copy_from_slice(&1u32.to_be_bytes());
            header[4] = 2;
            header[5..].copy_from_slice(&(size as u32).to_be_bytes());
            let _ = c.seal_client_to_server(b"warmup").unwrap();
            ALLOCS.store(0, Ordering::Relaxed);
            let now = Instant::now();
            for _ in 0..count {
                let payload = std::hint::black_box(&scratch).to_vec();
                let wire = if fused {
                    let parts: &[&[u8]] = &[&header, &payload];
                    let frame =
                        PreparedFrame::new(parts, 255, PadMode::Random, Some(&mut adaptive))
                            .unwrap();
                    c.seal_frame(true, &frame).unwrap()
                } else {
                    record.clear();
                    record.extend_from_slice(&header);
                    record.extend_from_slice(&payload);
                    frame::write_padded_frame_with_mode_state(
                        &mut padded,
                        &record,
                        255,
                        PadMode::Random,
                        Some(&mut adaptive),
                    )
                    .unwrap();
                    c.seal_client_to_server(&padded).unwrap()
                };
                std::hint::black_box(Bytes::from(wire));
            }
            let elapsed = now.elapsed().as_secs_f64();
            let allocs = ALLOCS.load(Ordering::Relaxed);
            println!(
                "path={} bytes={} frames={} Mbps={:.2} allocs_per_frame={:.3}",
                if fused { "fused" } else { "legacy" },
                size,
                count,
                count as f64 * size as f64 * 8.0 / elapsed / 1e6,
                allocs as f64 / count as f64
            );
        }
    }
}
