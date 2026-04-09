.PHONY: generate build test run clean

# Generate code from slaspec (~30s)
generate:
	cargo run -p rsleigh-generate

# Build all crates (~3.5 min parallel)
build: generate
	cargo build -p test-harness

# Run golden tests
test: generate
	cargo test -p test-harness

# Run the test-harness binary (prints P-code)
run: build
	cargo run -p test-harness

# Clean everything
clean:
	cargo clean
	rm -rf generated/*/out/
