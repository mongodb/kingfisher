SHELL := /usr/bin/env bash
.SHELLFLAGS := -eu -o pipefail -c

# Detect project name from Cargo.toml
PROJECT_NAME := $(shell grep '^name' Cargo.toml | cut -d '"' -f 2)

# Determine OS and whether to use gtar on darwin
OS := $(shell uname)
ifneq ($(OS),darwin)
  USE_GTAR := 0
  TAR_CMD := tar
  TAR_OPTS := $(shell if tar --help 2>/dev/null | grep -q -- '--no-xattrs'; then echo '--no-xattrs -czf'; else echo '-czf'; fi)
else
  ifneq ($(shell command -v gtar 2>/dev/null),)
    USE_GTAR := 1
    TAR_CMD := gtar
    TAR_OPTS := --no-xattrs -czf
  else
    USE_GTAR := 0
    TAR_CMD := tar
    TAR_OPTS := -czf
  endif
endif

ifeq ($(OS),darwin)
  export HOMEBREW_NO_INSTALL_CLEANUP=1
  export HOMEBREW_NO_ENV_HINTS=1
endif

  # detect host architecture and map to our target suffixes
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_M),x86_64)
  ARCH := x64
else ifeq ($(UNAME_M),amd64)
  ARCH := x64
else ifeq ($(UNAME_M),arm64)
  ARCH := arm64
else ifeq ($(UNAME_M),aarch64)
  ARCH := arm64
else
  $(error Unsupported architecture: $(UNAME_M))
endif

ARCHIVE_CMD = $(TAR_CMD) $(TAR_OPTS)
SUDO_CMD := $(shell command -v sudo 2>/dev/null)

.PHONY: default help create-dockerignore ubuntu-x64 ubuntu-arm64 linux-x64 linux-arm64 darwin-arm64 darwin-x64 windows-x64 windows \
        linux darwin all list-archives check-docker check-rust clean tests

default: help

help:
	@echo "Available targets:"
	@echo "  create-dockerignore"
	@echo "  linux-x64"
	@echo "  linux-arm64"
	@echo "  linux"
	@echo "  darwin-arm64"
	@echo "  darwin-x64"
	@echo "  darwin"
	@echo "  windows-x64"
	@echo "  windows"
	@echo "  all"
	@echo "  list-archives"
	@echo "  tests"

create-dockerignore:
	@echo "target/" > .dockerignore
	@echo ".git/" >> .dockerignore
	@echo ".vscode/" >> .dockerignore
	@echo "bin/" >> .dockerignore


.PHONY: setup-zig
setup-zig:
	@command -v zig >/dev/null 2>&1 || { \
	  echo "⬇️  Installing Zig 0.14.0 …"; \
	  if $(SUDO_CMD) apt-get update -qq && \
	     $(SUDO_CMD) apt-get install -y --no-install-recommends zig 2>/dev/null ; then \
	    echo "✓ Zig installed via apt"; \
	  else \
	    echo "⚠️  Package 'zig' not in apt repos – falling back to manual install"; \
	    arch=$$(uname -m); \
	    case "$$arch" in \
	      x86_64)   pkg=zig-linux-x86_64-0.14.0 ;; \
	      aarch64|arm64) pkg=zig-linux-aarch64-0.14.0 ;; \
	      *) echo "Unsupported architecture: $$arch"; exit 1 ;; \
	    esac; \
	    curl -L -o /tmp/zig.tar.xz https://ziglang.org/download/0.14.0/$${pkg}.tar.xz; \
	    tar -C /tmp -xf /tmp/zig.tar.xz; \
	    $(SUDO_CMD) mv /tmp/$${pkg} /opt/zig; \
	    $(SUDO_CMD) ln -sf /opt/zig/zig /usr/local/bin/zig; \
	    echo "✓ Zig installed to /usr/local/bin/zig"; \
	  fi; \
	}

	@if [ -f "$$HOME/.cargo/env" ]; then . $$HOME/.cargo/env; fi && \
	(cargo zigbuild --help >/dev/null 2>&1 || { \
		echo "⬇️  Installing cargo-zigbuild …"; \
		cargo install --locked cargo-zigbuild; \
	})


# =============  BAREMETAL BUILDS (Check Rust first, install if missing)  =============
#

# -------------------------------------------------------------------------------------------------
# ubuntu-x64 — native static build for x86_64-unknown-linux-musl via Zig. Tested on Ubuntu 24.04.
# -------------------------------------------------------------------------------------------------
ubuntu-x64: setup-zig   # ensures Zig & cargo-zigbuild exist
	@echo "Checking Rust toolchain…"
	@$(MAKE) check-rust || { \
	    echo "🦀  Installing Rust 1.85.0 …"; \
	    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y; \
	    . $$HOME/.cargo/env; \
	    rustup toolchain install 1.85.0; \
	    rustup default 1.85.0; \
	}

	@echo "📦  Installing build dependencies (musl, cmake, etc.)…"
	@$(SUDO_CMD) DEBIAN_FRONTEND=noninteractive apt-get update -qq
	@$(SUDO_CMD) DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
	    build-essential musl-tools musl-dev cmake pkg-config \
	    zlib1g-dev libbz2-dev liblzma-dev libboost-all-dev \
	    patch perl ragel

	@echo "🔨  Building $(PROJECT_NAME) for x86_64-unknown-linux-musl …"
	@. $$HOME/.cargo/env && \
	    rustup target add x86_64-unknown-linux-musl && \
	    export PKG_CONFIG_ALLOW_CROSS=1 && \
	    cargo zigbuild --release --target x86_64-unknown-linux-musl

	@echo "🗜️   Packaging archive …"
	@cd target/x86_64-unknown-linux-musl/release && \
	    find ./$(PROJECT_NAME) -type f -executable -exec sha256sum {} \; > CHECKSUM.txt
	@mkdir -p target/release
	@cp target/x86_64-unknown-linux-musl/release/$(PROJECT_NAME) target/release/
	@cp target/x86_64-unknown-linux-musl/release/CHECKSUM.txt target/release/CHECKSUM-linux-x64.txt
	@cd target/release && \
	    rm -rf $(PROJECT_NAME)-linux-x64.tgz && \
	    $(ARCHIVE_CMD) $(PROJECT_NAME)-linux-x64.tgz $(PROJECT_NAME) CHECKSUM-linux-x64.txt && \
	    sha256sum $(PROJECT_NAME)-linux-x64.tgz >> CHECKSUM-linux-x64.txt

	$(MAKE) list-archives


# -------------------------------------------------------------------------------------------------
# ubuntu-arm64 — native cross-compile to aarch64-unknown-linux-musl via Zig. Tested on Ubuntu 24.04.
# -------------------------------------------------------------------------------------------------
ubuntu-arm64: setup-zig   # ensures Zig & cargo-zigbuild exist
	@echo "Checking Rust toolchain…"
	@$(MAKE) check-rust || { \
	    echo "🦀  Installing Rust 1.85.0 …"; \
	    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y; \
	    . $$HOME/.cargo/env; \
	    rustup toolchain install 1.85.0; \
	    rustup default 1.85.0; \
	}

	@echo "📦  Installing build dependencies (musl, cmake, etc.)…"
	@$(SUDO_CMD) DEBIAN_FRONTEND=noninteractive apt-get update -qq
	@$(SUDO_CMD) DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
	    build-essential musl-tools musl-dev cmake pkg-config \
	    zlib1g-dev libbz2-dev liblzma-dev libboost-all-dev \
	    patch perl ragel

	@echo "🔨  Building $(PROJECT_NAME) for aarch64-unknown-linux-musl …"
	@. $$HOME/.cargo/env && \
	    rustup target add aarch64-unknown-linux-musl && \
	    export PKG_CONFIG_ALLOW_CROSS=1 && \
	    cargo zigbuild --release --target aarch64-unknown-linux-musl

	@echo "🗜️   Packaging archive …"
	@cd target/aarch64-unknown-linux-musl/release && \
	    find ./$(PROJECT_NAME) -type f -executable -exec sha256sum {} \; > CHECKSUM.txt
	@mkdir -p target/release
	@cp target/aarch64-unknown-linux-musl/release/$(PROJECT_NAME) target/release/
	@cp target/aarch64-unknown-linux-musl/release/CHECKSUM.txt target/release/CHECKSUM-linux-arm64.txt
	@cd target/release && \
	    rm -rf $(PROJECT_NAME)-linux-arm64.tgz && \
	    $(ARCHIVE_CMD) $(PROJECT_NAME)-linux-arm64.tgz $(PROJECT_NAME) CHECKSUM-linux-arm64.txt && \
	    sha256sum $(PROJECT_NAME)-linux-arm64.tgz >> CHECKSUM-linux-arm64.txt

	$(MAKE) list-archives


darwin-arm64:
	@echo "Checking Rust for darwin-arm64..."
	@$(MAKE) check-rust || ( \
		echo "Rust not found or out-of-date. Installing via Homebrew..." && \
		brew install rust \
	)
	@brew install boost cmake gcc libpcap pkg-config ragel sqlite coreutils gnu-tar || true
	@rustup target add aarch64-apple-darwin
	cargo build --release --target aarch64-apple-darwin --features system-alloc
	@cd target/aarch64-apple-darwin/release && \
		find ./$(PROJECT_NAME) -type f -not -name "*.d" -not -name "*.rlib" -exec shasum -a 256 {} \; > CHECKSUM.txt
	@mkdir -p target/release
	@cp target/aarch64-apple-darwin/release/$(PROJECT_NAME) target/release/
	@cp target/aarch64-apple-darwin/release/CHECKSUM.txt target/release/CHECKSUM-darwin-arm64.txt
	@cd target/release && \
	    rm -rf $(PROJECT_NAME)-darwin-arm64.tgz && \
		$(ARCHIVE_CMD) $(PROJECT_NAME)-darwin-arm64.tgz $(PROJECT_NAME) CHECKSUM-darwin-arm64.txt && \
		if [ -f $(PROJECT_NAME)-darwin-arm64.tgz ]; then \
		  shasum -a 256 $(PROJECT_NAME)-darwin-arm64.tgz >> CHECKSUM-darwin-arm64.txt; \
		fi
	$(MAKE) list-archives

darwin-x64:
	@echo "Checking Rust for darwin-x64..."
	@$(MAKE) check-rust || ( \
		echo "Rust not found or out-of-date. Installing via Homebrew..." && \
		brew install rust \
	)
	@brew install boost cmake gcc libpcap pkg-config ragel sqlite coreutils gnu-tar || true
	@rustup target add x86_64-apple-darwin
	source $$HOME/.cargo/env && cargo build --release --target x86_64-apple-darwin --features system-alloc
	@cd target/x86_64-apple-darwin/release && \
		find ./$(PROJECT_NAME) -type f -not -name "*.d" -not -name "*.rlib" -exec shasum -a 256 {} \; > CHECKSUM.txt
	@mkdir -p target/release
	@cp target/x86_64-apple-darwin/release/$(PROJECT_NAME) target/release/
	@cp target/x86_64-apple-darwin/release/CHECKSUM.txt target/release/CHECKSUM-darwin-x64.txt
	@cd target/release && \
	    rm -rf $(PROJECT_NAME)-darwin-x64.tgz && \
		$(ARCHIVE_CMD) $(PROJECT_NAME)-darwin-x64.tgz $(PROJECT_NAME) CHECKSUM-darwin-x64.txt && \
		if [ -f $(PROJECT_NAME)-darwin-x64.tgz ]; then \
		  shasum -a 256 $(PROJECT_NAME)-darwin-x64.tgz >> CHECKSUM-darwin-x64.txt; \
		fi
	$(MAKE) list-archives

windows-x64:
ifeq ($(OS),Windows_NT)
	@echo "Detected Windows host."
else
	$(error "This target can only run on Windows.")
endif
	buildwin.bat -force
#
# =============  DOCKER-BASED BUILDS =============
# #

linux-x64: check-docker create-dockerignore
	@mkdir -p target/release
	docker run --platform linux/amd64 --rm \
	  -v "$$(pwd):/src" -w /src rust:1.85-alpine sh -eu -c '\
		apk add --no-cache \
		    musl-dev \
		    gcc g++ make cmake pkgconfig \
		    zlib-dev  zlib-static \
		    bzip2-dev bzip2-static \
		    xz-dev    xz-static \
		    boost-dev linux-headers \
		    patch perl ragel && \
	        git openssl-dev curl && \
		\
		cargo test --workspace --all-targets --release ; \
		\
		rustup target add x86_64-unknown-linux-musl && \
		\
		export PKG_CONFIG_ALLOW_CROSS=1 ; \
		export RUSTFLAGS="-C target-feature=+crt-static" ; \
		\
		cargo build --release --target x86_64-unknown-linux-musl && \
		cd target/x86_64-unknown-linux-musl/release && \
		find "./$(PROJECT_NAME)" -type f -executable \
		     -not -name "*.d" -not -name "*.rlib" \
		     -exec sha256sum {} \; > CHECKSUM.txt \
	'
	@cd target/release && \
	  rm -rf $(PROJECT_NAME)-linux-x64.tgz && \
	  cp ../x86_64-unknown-linux-musl/release/$(PROJECT_NAME) . && \
	  cp ../x86_64-unknown-linux-musl/release/CHECKSUM.txt CHECKSUM-linux-x64.txt && \
	  tar --no-xattrs -czf $(PROJECT_NAME)-linux-x64.tgz \
	      $(PROJECT_NAME) CHECKSUM-linux-x64.txt && \
	  rm $(PROJECT_NAME) && \
	  sha256sum $(PROJECT_NAME)-linux-x64.tgz >> CHECKSUM-linux-x64.txt
	$(MAKE) list-archives

linux-arm64: check-docker create-dockerignore
	@mkdir -p target/release
	docker run --platform linux/arm64 --rm \
	  -v "$$(pwd):/src" -w /src rust:1.85-alpine sh -eu -c '\
		apk add --no-cache \
		    musl-dev \
		    gcc g++ make cmake pkgconfig \
		    zlib-dev  zlib-static \
		    bzip2-dev bzip2-static \
		    xz-dev    xz-static \
		    boost-dev linux-headers \
		    patch perl ragel && \
	        git openssl-dev curl && \
		\
		rustup target add aarch64-unknown-linux-musl && \
		\
		cargo test --workspace --all-targets --release ; \
		\
		export PKG_CONFIG_ALLOW_CROSS=1 ; \
		export RUSTFLAGS="-C target-feature=+crt-static" ; \
		\
		cargo build --release --target aarch64-unknown-linux-musl && \
		\
		cd target/aarch64-unknown-linux-musl/release && \
		find "./$(PROJECT_NAME)" -type f -executable \
		     -not -name "*.d" -not -name "*.rlib" \
		     -exec sha256sum {} \; > CHECKSUM.txt \
	'
	@cd target/release && \
	  rm -rf $(PROJECT_NAME)-linux-arm64.tgz && \
	  cp ../aarch64-unknown-linux-musl/release/$(PROJECT_NAME) . && \
	  cp ../aarch64-unknown-linux-musl/release/CHECKSUM.txt CHECKSUM-linux-arm64.txt && \
	  tar --no-xattrs -czf $(PROJECT_NAME)-linux-arm64.tgz \
	      $(PROJECT_NAME) CHECKSUM-linux-arm64.txt && \
	  rm $(PROJECT_NAME) && \
	  sha256sum $(PROJECT_NAME)-linux-arm64.tgz >> CHECKSUM-linux-arm64.txt
	$(MAKE) list-archives


# =============  AGGREGATE TARGETS  =============
#

windows: windows-x64
	@echo "# Windows builds:" > target/release/CHECKSUMS-windows.txt
	@echo -e "\n# x86_64-windows build:" >> target/release/CHECKSUMS-windows.txt
	@cat target/release/CHECKSUM-windows-x64.txt >> target/release/CHECKSUMS-windows.txt
	@echo -e "\nBuilt Windows archives:"
	@ls -lh target/release/*.tgz
	@echo -e "\nWindows Checksums:"
	@cat target/release/CHECKSUMS-windows.txt

linux:
	$(MAKE) linux-$(ARCH)

linux-all: linux-x64 linux-arm64
	@echo "# Linux builds:" > target/release/CHECKSUMS-linux.txt
	@echo -e "\n# x86_64-linux build:" >> target/release/CHECKSUMS-linux.txt
	@cat target/release/CHECKSUM-linux-x64.txt >> target/release/CHECKSUMS-linux.txt
	@echo -e "\n# arm64-linux build:" >> target/release/CHECKSUMS-linux.txt
	@cat target/release/CHECKSUM-linux-arm64.txt >> target/release/CHECKSUMS-linux.txt
	@echo -e "\nBuilt Linux archives:"
	@ls -lh target/release/*.tgz
	@echo -e "\nLinux Checksums:"
	@cat target/release/CHECKSUMS-linux.txt

darwin:
	$(MAKE) darwin-$(ARCH)

darwin-all: darwin-arm64 darwin-x64
	@echo "# darwin builds:" > target/release/CHECKSUMS-darwin.txt
	@echo -e "\n# arm64-darwin build:" >> target/release/CHECKSUMS-darwin.txt
	@cat target/release/CHECKSUM-darwin-arm64.txt >> target/release/CHECKSUMS-darwin.txt
	@echo -e "\n# x86_64-darwin build:" >> target/release/CHECKSUMS-darwin.txt
	@cat target/release/CHECKSUM-darwin-x64.txt >> target/release/CHECKSUMS-darwin.txt
	@echo -e "\nBuilt darwin archives:"
	@ls -lh target/release/*.tgz
	@echo -e "\ndarwin Checksums:"
	@cat target/release/CHECKSUMS-darwin.txt

all: linux darwin
	@echo "# All builds:" > target/release/CHECKSUMS.txt
	@echo -e "\n# Linux builds:" >> target/release/CHECKSUMS.txt
	@cat target/release/CHECKSUMS-linux.txt >> target/release/CHECKSUMS.txt
	@echo -e "\n# darwin builds:" >> target/release/CHECKSUMS.txt
	@cat target/release/CHECKSUMS-darwin.txt >> target/release/CHECKSUMS.txt
	@echo -e "\nBuilt archives:"
	@ls -lh target/release/*.tgz
	@echo -e "\nCombined Checksums:"
	@cat target/release/CHECKSUMS.txt

list-archives:
	@echo -e "\n=== Built archives ==="
	@found=0; \
	for f in target/release/*.tgz; do \
	  if [ -e "$$f" ]; then \
	    found=1; \
	    realpath "$$f"; \
	  fi; \
	done; \
	if [ $$found -eq 0 ]; then \
	  echo "No archives found."; \
	fi

check-docker:
	@command -v docker >/dev/null 2>&1 || { \
	  echo "Docker is not installed. Please install Docker."; \
	  exit 1; \
	}

check-rust:
	@version=$$(rustc --version 2>/dev/null | awk '{print $$2}'); \
	if [ -z "$$version" ]; then \
	  echo "Rust not found."; \
	  exit 1; \
	fi; \
	required=1.85.0; \
	if [ $$(printf '%s\n' "$$required" "$$version" | sort -V | head -n1) != "$$required" ]; then \
	  echo "Rust version $$version is older than required $$required."; \
	  exit 1; \
	else \
	  echo "Rust version $$version is acceptable."; \
	fi

tests:
	@echo "🔍 checking for cargo-nextest …"
	@if command -v cargo-nextest >/dev/null 2>&1; then \
	    echo "✅ cargo-nextest already present"; \
	else \
	    echo "📦 installing cargo-nextest …"; \
	    cargo install --locked cargo-nextest || { \
	        echo "⚠️  install failed – falling back to cargo test"; \
	        cargo test --workspace --all-targets; exit $$?; }; \
	fi

clean:
	@echo "Cleaning build artifacts..."
	cargo clean
	rm -f .dockerignore

notices:
	@echo "Generating third-party notices..."
	@cargo install cargo-bundle-licenses
	@cargo bundle-licenses --format yaml --output THIRD_PARTY_NOTICES

evergreen-patch:
	@evergreen patch --project kingfisher --variants all --tasks build