CARGO ?= cargo
INSTALL_ROOT ?= $(HOME)/.local
INSTALL_BIN := $(INSTALL_ROOT)/bin/supgang

.PHONY: all check install test

all: check

check:
	$(CARGO) run --locked --package supgang-quality -- all

test:
	$(CARGO) test --locked --workspace --all-targets

install:
	$(CARGO) install --frozen --force --root "$(INSTALL_ROOT)" --path crates/supgang-cli
	"$(INSTALL_BIN)" --version
