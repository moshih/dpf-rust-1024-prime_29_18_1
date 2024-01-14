export RUSTFLAGS="--emit=asm -C target-feature=+avx2,+fma -C target-cpu=native -C target-feature=+aes,+ssse3,,+fma -C opt-level=3"
RUSTFLAGS="-C target-cpu=native -C opt-level=3" cargo run --release
