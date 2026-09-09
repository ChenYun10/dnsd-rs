.PHONY: build release test run fmt clean

build:
	cargo build

release:
	cargo build --release

test:
	cargo test

run:
	cargo run

fmt:
	cargo fmt

clean:
	cargo clean
