.PHONY: generate build test test-all run clean check benchmark

# Generate code from slaspec (~30s)
generate:
	cargo run -p rsleigh-generate

# Build all crates (~3.5 min parallel)
build: generate
	cargo build -p test-harness

# Run golden tests
test: generate
	cargo test -p test-harness

# Run all tests (golden + decompiler unit tests)
test-all: generate
	cargo test -p test-harness
	cargo test -p rsleigh-decompile

# Quick check — compile decompiler + CLI without codegen
check:
	cargo check -p rsleigh-decompile
	cargo check -p rsleigh-cli

# Build CLI in release mode
release:
	cargo build -p rsleigh-cli --release

# Run benchmark suite (requires test_bin directory)
benchmark: release
	python3 scripts/benchmark.py

# Run the test-harness binary (prints P-code)
run: build
	cargo run -p test-harness

# Clean everything
clean:
	cargo clean
	rm -rf generated/*/out/
