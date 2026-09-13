CARGO ?= cargo
INSTALL_ROOT ?= $(HOME)/.local
INSTALL_BIN := $(INSTALL_ROOT)/bin/supgang
MACOS_CODESIGN_IDENTITY ?=

.PHONY: all check install test

all: check

check:
	$(CARGO) run --locked --package supgang-quality -- all

test:
	$(CARGO) test --locked --workspace --all-targets

install:
ifeq ($(shell uname -s),Darwin)
ifneq ($(strip $(MACOS_CODESIGN_IDENTITY)),)
	@printf '%s\n' "$(MACOS_CODESIGN_IDENTITY)" | /usr/bin/grep -Eq '^[0-9A-Fa-f]{40}$$' || { printf '%s\n' 'MACOS_CODESIGN_IDENTITY must be an exact 40-character identity hash.' >&2; exit 2; }
endif
endif
	$(CARGO) install --frozen --force --root "$(INSTALL_ROOT)" --path crates/supgang-cli
ifeq ($(shell uname -s),Darwin)
ifneq ($(strip $(MACOS_CODESIGN_IDENTITY)),)
	/usr/bin/codesign --force --sign "$(MACOS_CODESIGN_IDENTITY)" --identifier "org.agenxy.supgang.runtime" --options runtime --timestamp=none "$(INSTALL_BIN)"
	/usr/bin/codesign --verify --strict --verbose=2 "$(INSTALL_BIN)"
endif
endif
	"$(INSTALL_BIN)" --version
