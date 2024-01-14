export RUSTFLAGS="-C target-feature=+avx2,+fma"
RUSTFLAGS="-C target-cpu=native -C opt-level=3 -A dead_code" cargo run --release
