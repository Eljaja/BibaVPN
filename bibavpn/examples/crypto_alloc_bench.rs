//! Opt-in microbenchmark: cargo run -p bibavpn --release --example crypto_alloc_bench
//! Counts allocator calls only during public seal loops; never a production allocator.
use bibavpn::crypto_layer::SessionCrypto;
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
    for size in [1400, 16384, 65536, 262000] {
        let c = SessionCrypto::new("bench-key", "bench", &[1; 32], &[2; 32], 32);
        let payload = vec![19; size];
        let _ = c.seal_client_to_server(&payload).unwrap();
        let count = (256 * 1024 * 1024 / size).max(100);
        ALLOCS.store(0, Ordering::Relaxed);
        let now = Instant::now();
        for _ in 0..count {
            std::hint::black_box(
                c.seal_client_to_server(std::hint::black_box(&payload))
                    .unwrap(),
            );
        }
        let elapsed = now.elapsed().as_secs_f64();
        let allocs = ALLOCS.load(Ordering::Relaxed);
        println!(
            "{{\"bytes\":{size},\"frames\":{count},\"Mbps\":{:.2},\"allocs_per_frame\":{:.3}}}",
            count as f64 * size as f64 * 8.0 / elapsed / 1e6,
            allocs as f64 / count as f64
        );
    }
}
