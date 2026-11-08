use prismid_native::collect_native_anchor;
use std::time::Instant;

fn main() {
    let t0 = Instant::now();
    let anchor = collect_native_anchor();
    let first_elapsed = t0.elapsed();

    let t1 = Instant::now();
    let _cached = collect_native_anchor();
    let cached_elapsed = t1.elapsed();

    println!(
        r#"{{"anchor":{},"benchmark":{{"initial_collect_ms":{:.3},"oncelock_cached_ns":{}}}}}"#,
        anchor.to_json_string(),
        first_elapsed.as_secs_f64() * 1000.0,
        cached_elapsed.as_nanos()
    );
}
