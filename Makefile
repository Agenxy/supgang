CARGO ?= cargo

.PHONY: all check install test

all: check

check:
	$(CARGO) run --locked --package supgang-quality -- all

test:
	$(CARGO) test --locked --workspace --all-targets

install:
	$(CARGO) install --locked --path crates/supgang-cli
