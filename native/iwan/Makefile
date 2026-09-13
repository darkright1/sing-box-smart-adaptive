TARGET ?= x86_64-unknown-linux-gnu

.PHONY: build test abi-check clean

test:
	cargo test --manifest-path Cargo.toml
	$(MAKE) abi-check

abi-check:
	$(CC) -std=c11 -Wall -Wextra -Werror -I include -fsyntax-only tests/abi_layout.c

build:
	cargo build --manifest-path Cargo.toml --release --target $(TARGET)
	@mkdir -p target/release
	@cp target/$(TARGET)/release/libiwan_native.a target/release/libiwan_native.a

clean:
	cargo clean --manifest-path Cargo.toml
