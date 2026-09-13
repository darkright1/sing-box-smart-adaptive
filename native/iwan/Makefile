TARGET ?= x86_64-unknown-linux-gnu

.PHONY: build test clean

test:
	cargo test --manifest-path Cargo.toml

build:
	cargo build --manifest-path Cargo.toml --release --target $(TARGET)

clean:
	cargo clean --manifest-path Cargo.toml
