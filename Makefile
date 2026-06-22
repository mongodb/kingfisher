SHELL := /usr/bin/env bash
.SHELLFLAGS := -eu -o pipefail -c

PROJECT_NAME := kingfisher
ZIG_VERSION ?= 0.15.1

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

# uname reports MSYS_NT*/MINGW*/CYGWIN* under Windows POSIX shells.
IS_WINDOWS_HOST := 0
ifneq (,$(filter Windows_NT MSYS_NT% MINGW% CYGWIN_NT%,$(OS)))
  IS_WINDOWS_HOST := 1
endif

ifeq ($(OS),darwin)
  export HOMEBREW_NO_INSTALL_CLEANUP=1
  export HOMEBREW_NO_ENV_HINTS=1
  export HOMEBREW_NO_AUTO_UPDATE=1
endif

# Detect host architecture and map to our target suffixes.
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

.PHONY: \
        default help create-dockerignore setup-zig \
        ubuntu-x64 ubuntu-arm64 linux-x64 linux-arm64 linux linux-all \
        darwin-arm64 darwin-x64 darwin-dev darwin darwin-all \
        require-windows-host windows-x64 windows-arm64 windows-test-x64 windows-test-arm64 windows-test windows \
        all list-archives check-docker check-rust clean tests audit-deps fuzz \
        dockerfile docs-build docs-serve docs-clean notices

default: help

help:
	@echo "Available targets:"
	@echo "  linux              Build Linux archive for current host arch via Docker"
	@echo "  linux-x64          Build Linux x64 archive via Docker"
	@echo "  linux-arm64        Build Linux arm64 archive via Docker"
	@echo "  linux-all          Build Linux x64 and arm64 archives via Docker"
	@echo "  ubuntu-x64         Build Linux x64 archive with Zig on Ubuntu"
	@echo "  ubuntu-arm64       Build Linux arm64 archive with Zig on Ubuntu"
	@echo "  darwin             Build macOS archive for current host arch"
	@echo "  darwin-x64         Build macOS x64 archive"
	@echo "  darwin-arm64       Build macOS arm64 archive"
	@echo "  darwin-all         Build macOS x64 and arm64 archives"
	@echo "  darwin-dev         Build a macOS arm64 dev binary"
	@echo "  windows-x64        Build Windows x64 archive from MSYS2"
	@echo "  windows-arm64      Build Windows arm64 archive from MSYS2"
	@echo "  windows            Build Windows x64 and arm64 archives"
	@echo "  windows-test       Test Windows x64 and arm64 targets from MSYS2"
	@echo "  all                Build Linux and macOS multi-arch archives"
	@echo "  list-archives      Print built tgz/zip archives"
	@echo "  create-dockerignore"
	@echo "  dockerfile         Build Docker images"
	@echo "  tests              Run cargo-nextest when available, otherwise cargo test"
	@echo "  audit-deps         Run cargo-audit to report vulnerable dependencies"
	@echo "  fuzz               Run fuzz targets (FUZZ_SECONDS=N to control duration, default 60s)"
	@echo "  docs-build         Build the documentation site"
	@echo "  docs-serve         Serve the documentation site locally"
	@echo "  notices            Generate third-party notices"
	@echo "  clean              Remove build artifacts"

create-dockerignore:
	@printf '%s\n' target/ .git/ .vscode/ bin/ > .dockerignore


setup-zig:
	@install_manual_zig() { \
	  arch=$$(uname -m); \
	  case "$$arch" in \
	    x86_64)   arch_tag=x86_64 ;; \
	    aarch64|arm64) arch_tag=aarch64 ;; \
	    *) echo "Unsupported architecture: $$arch"; exit 1 ;; \
	  esac; \
	  url_new="https://ziglang.org/download/$(ZIG_VERSION)/zig-$${arch_tag}-linux-$(ZIG_VERSION).tar.xz"; \
	  url_old="https://ziglang.org/download/$(ZIG_VERSION)/zig-linux-$${arch_tag}-$(ZIG_VERSION).tar.xz"; \
	  if ! curl -fL --retry 3 --retry-delay 2 -o /tmp/zig.tar.xz "$$url_new"; then \
	    echo "↩️  New Zig filename pattern failed, trying legacy pattern"; \
	    curl -fL --retry 3 --retry-delay 2 -o /tmp/zig.tar.xz "$$url_old"; \
	  fi; \
	  xz -t /tmp/zig.tar.xz >/dev/null 2>&1 || { \
	    echo "Downloaded Zig archive is invalid (not a tar.xz)."; \
	    ls -lh /tmp/zig.tar.xz || true; \
	    exit 1; \
	  }; \
	  tar -C /tmp -xf /tmp/zig.tar.xz; \
	  tar -tf /tmp/zig.tar.xz > /tmp/zig-contents.txt; \
	  IFS=/ read -r zig_dir _ < /tmp/zig-contents.txt; \
	  [ -n "$$zig_dir" ] || { echo "Could not determine Zig extract directory"; exit 1; }; \
	  $(SUDO_CMD) rm -rf /opt/zig; \
	  $(SUDO_CMD) mv "/tmp/$${zig_dir}" /opt/zig; \
	  $(SUDO_CMD) ln -sf /opt/zig/zig /usr/local/bin/zig; \
	  echo "✓ Zig $(ZIG_VERSION) installed to /usr/local/bin/zig"; \
	}; \
	installed_zig=$$(zig version 2>/dev/null || true); \
	if [ "$$installed_zig" = "$(ZIG_VERSION)" ]; then \
	  echo "✓ Zig $(ZIG_VERSION) already installed"; \
	else \
	  echo "⬇️  Installing Zig $(ZIG_VERSION) …"; \
	  if $(SUDO_CMD) apt-get update -qq && \
	     $(SUDO_CMD) apt-get install -y --no-install-recommends zig 2>/dev/null ; then \
	    apt_zig=$$(zig version 2>/dev/null || true); \
	    if [ "$$apt_zig" = "$(ZIG_VERSION)" ]; then \
	      echo "✓ Zig $(ZIG_VERSION) installed via apt"; \
	    else \
	      echo "⚠️  apt installed Zig '$$apt_zig' (need $(ZIG_VERSION)) – falling back to manual install"; \
	      install_manual_zig; \
	    fi; \
	  else \
	    echo "⚠️  Package 'zig' not in apt repos – falling back to manual install"; \
	    install_manual_zig; \
	  fi; \
	fi

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
            echo "🦀  Installing Rust 1.96.0 …"; \
	    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y; \
	    . $$HOME/.cargo/env; \
            rustup toolchain install 1.96.0; \
            rustup default 1.96.0; \
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
            echo "🦀  Installing Rust 1.96.0 …"; \
	    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y; \
	    . $$HOME/.cargo/env; \
            rustup toolchain install 1.96.0; \
            rustup default 1.96.0; \
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
	@brew list cmake >/dev/null 2>&1 || brew install cmake
	@brew list boost >/dev/null 2>&1 || brew install boost
	@brew install gcc libpcap pkg-config ragel sqlite coreutils gnu-tar
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

darwin-dev:
	cargo build --profile=dev --target aarch64-apple-darwin --features system-alloc

darwin-x64:
	@echo "Checking Rust for darwin-x64..."
	@$(MAKE) check-rust || ( \
		echo "Rust not found or out-of-date. Installing via Homebrew..." && \
		brew install rust \
	)
	@brew list cmake >/dev/null 2>&1 || brew install cmake
	@brew list boost >/dev/null 2>&1 || brew install boost
	@brew install gcc libpcap pkg-config ragel sqlite coreutils gnu-tar
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

require-windows-host:
ifeq ($(IS_WINDOWS_HOST),1)
	@echo "Detected Windows host."
else
	$(error "This target can only run on Windows.")
endif

# Windows x64 build path for MSYS2/MinGW (GNU toolchain + vectorscan from source)
windows-x64: require-windows-host
	@bash -eu -o pipefail -c '\
	  command -v pacman >/dev/null 2>&1 || { \
	    echo "MSYS2 pacman not found. Run this target from an MSYS2 MinGW64 shell."; \
	    exit 1; \
	  }; \
	  case "$${MSYSTEM:-}" in \
	    MINGW64) ;; \
	    MSYS) \
	      echo "MSYSTEM=MSYS detected; continuing with /mingw64 toolchain for testing."; \
	      export PATH=/mingw64/bin:$$PATH; \
	      ;; \
	    *) \
	      echo "MSYSTEM=$${MSYSTEM:-unset}. Continuing by forcing /mingw64 toolchain path."; \
	      export PATH=/mingw64/bin:$$PATH; \
	      ;; \
	  esac; \
	  echo "Ensuring MinGW build dependencies are installed..."; \
	  pacman --noconfirm --needed -S \
	    mingw-w64-x86_64-toolchain \
	    mingw-w64-x86_64-cmake \
	    mingw-w64-x86_64-boost \
	    mingw-w64-x86_64-pkgconf \
	    mingw-w64-x86_64-ragel \
	    mingw-w64-x86_64-pcre2 \
	    mingw-w64-x86_64-zlib \
	    mingw-w64-x86_64-python \
	    git make; \
	  repo_root="$$(pwd)"; \
	  vectorscan_src="$$repo_root/vendor/vectorscan-rs/vectorscan-rs-sys/vectorscan"; \
	  build_dir=/tmp/vectorscan-build; \
	  rm -rf "$$build_dir"; \
	  mkdir -p "$$build_dir"; \
	  cd "$$build_dir"; \
	  cmake "$$vectorscan_src" \
	    -G "MinGW Makefiles" \
	    -DCMAKE_BUILD_TYPE=Release \
	    -DBUILD_SHARED_LIBS=OFF \
	    -DBUILD_STATIC_LIBS=ON \
	    -DBUILD_UNIT=OFF \
	    -DBUILD_TOOLS=OFF \
	    -DFAT_RUNTIME=OFF \
	    -DCMAKE_C_COMPILER=gcc \
	    -DCMAKE_CXX_COMPILER=g++ \
	    -DCMAKE_INSTALL_PREFIX=/mingw64; \
	  mingw32-make -j$$(nproc); \
	  mingw32-make install; \
	  mkdir -p /mingw64/lib/pkgconfig; \
	  if [ -f /mingw64/include/hs/hs.h ]; then \
	    hs_include=/mingw64/include/hs; \
	  else \
	    hs_include=/mingw64/include; \
	  fi; \
	  printf "%s\n" \
	    "prefix=/mingw64" \
	    "exec_prefix=\$${prefix}" \
	    "libdir=\$${prefix}/lib" \
	    "includedir=$$hs_include" \
	    "" \
	    "Name: libhs" \
	    "Description: Vectorscan regex library (Hyperscan fork)" \
	    "Version: 5.4.12" \
	    "Libs: -L\$${libdir} -lhs" \
	    "Cflags: -I\$${includedir}" \
	    > /mingw64/lib/pkgconfig/libhs.pc; \
	  export PKG_CONFIG_ALLOW_CROSS=1; \
	  export PKG_CONFIG_PATH=/mingw64/lib/pkgconfig; \
	  export PKG_CONFIG_LIBDIR=/mingw64/lib/pkgconfig; \
	  pkg-config --cflags --libs libhs; \
	  if ! command -v rustup >/dev/null 2>&1 && ! command -v rustup.exe >/dev/null 2>&1; then \
	    cargo_home_candidate=""; \
	    if [ -n "$${USERPROFILE:-}" ]; then \
	      cargo_home_candidate="$$(cygpath -u "$${USERPROFILE}")/.cargo/bin"; \
	    elif [ -n "$${HOMEDRIVE:-}" ] && [ -n "$${HOMEPATH:-}" ]; then \
	      cargo_home_candidate="$$(cygpath -u "$${HOMEDRIVE}$${HOMEPATH}")/.cargo/bin"; \
	    fi; \
	    if [ -n "$$cargo_home_candidate" ] && [ -d "$$cargo_home_candidate" ]; then \
	      echo "Adding Rust toolchain path: $$cargo_home_candidate"; \
	      export PATH="$$cargo_home_candidate:$$PATH"; \
	    fi; \
	  fi; \
	  if command -v rustup >/dev/null 2>&1; then \
	    RUSTUP_BIN=rustup; \
	  elif command -v rustup.exe >/dev/null 2>&1; then \
	    RUSTUP_BIN=rustup.exe; \
	  else \
	    echo "rustup not found. Install Rust via rustup and ensure ~/.cargo/bin is on PATH."; \
	    exit 1; \
	  fi; \
	  if command -v cargo >/dev/null 2>&1; then \
	    CARGO_BIN=cargo; \
	  elif command -v cargo.exe >/dev/null 2>&1; then \
	    CARGO_BIN=cargo.exe; \
	  else \
	    echo "cargo not found. Install Rust via rustup and ensure ~/.cargo/bin is on PATH."; \
	    exit 1; \
	  fi; \
	  cd "$$repo_root"; \
	  export HYPERSCAN_ROOT="$$(cygpath -m /mingw64)"; \
	  export LIBRARY_PATH="/mingw64/lib:$${LIBRARY_PATH:-}"; \
	  export CPATH="/mingw64/include:$${CPATH:-}"; \
	  extra_native_lib_dirs="-L native=/mingw64/lib"; \
	  if command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then \
	    libgcc_a_path="$$(x86_64-w64-mingw32-gcc -print-libgcc-file-name 2>/dev/null || true)"; \
	    if [ -n "$$libgcc_a_path" ] && [ -f "$$libgcc_a_path" ]; then \
	      libgcc_dir="$$(dirname "$$libgcc_a_path")"; \
	      extra_native_lib_dirs="$$extra_native_lib_dirs -L native=$$libgcc_dir"; \
	      echo "Using libgcc from $$libgcc_dir"; \
	    fi; \
	  fi; \
	  export RUSTFLAGS="$${RUSTFLAGS:-} $$extra_native_lib_dirs -C target-feature=+crt-static -C link-arg=-static"; \
	  echo "Using HYPERSCAN_ROOT=$$HYPERSCAN_ROOT"; \
	  "$$RUSTUP_BIN" target add x86_64-pc-windows-gnu; \
	  export LIBHS_NO_PKG_CONFIG=1; \
	  if [ "$${WINDOWS_ONLY_DEPS:-0}" = "1" ]; then \
	    echo "WINDOWS_ONLY_DEPS=1 set; skipping cargo build and packaging."; \
	    exit 0; \
	  fi; \
	  "$$CARGO_BIN" build --release --target x86_64-pc-windows-gnu; \
	  mkdir -p target/release; \
	  cp target/x86_64-pc-windows-gnu/release/$(PROJECT_NAME).exe target/release/$(PROJECT_NAME).exe; \
	  cd target/release; \
	  sha256sum $(PROJECT_NAME).exe > CHECKSUM-windows-x64.txt; \
	  rm -f $(PROJECT_NAME)-windows-x64.zip; \
	  powershell.exe -NoProfile -Command "Compress-Archive -Path '\''$(PROJECT_NAME).exe'\'','\''CHECKSUM-windows-x64.txt'\'' -DestinationPath '\''$(PROJECT_NAME)-windows-x64.zip'\'' -Force"; \
	  sha256sum $(PROJECT_NAME)-windows-x64.zip >> CHECKSUM-windows-x64.txt; \
	  echo "Built binary: target/release/$(PROJECT_NAME).exe"; \
	  echo "Built archive: target/release/$(PROJECT_NAME)-windows-x64.zip"; \
	'

# Windows ARM64 build path for MSYS2/clangarm64 (GNU/LLVM MinGW)
windows-arm64: require-windows-host
	@bash -eu -o pipefail -c '\
	  command -v pacman >/dev/null 2>&1 || { \
	    echo "MSYS2 pacman not found. Run this target from an MSYS2 shell."; \
	    exit 1; \
	  }; \
	  case "$${MSYSTEM:-}" in \
	    CLANGARM64) ;; \
	    MINGW64|MSYS) \
	      echo "MSYSTEM=$${MSYSTEM:-unset} detected; using /clangarm64 cross toolchain for ARM64."; \
	      export PATH=/clangarm64/bin:$$PATH; \
	      ;; \
	    *) \
	      echo "MSYSTEM=$${MSYSTEM:-unset}. Continuing by forcing /clangarm64 toolchain path."; \
	      export PATH=/clangarm64/bin:$$PATH; \
	      ;; \
	  esac; \
	  echo "Ensuring ARM64 MinGW/clang dependencies are installed..."; \
	  pacman --noconfirm --needed -S \
	    mingw-w64-clang-aarch64-toolchain \
	    mingw-w64-clang-aarch64-cmake \
	    mingw-w64-clang-aarch64-boost \
	    mingw-w64-clang-aarch64-pkgconf \
	    mingw-w64-clang-aarch64-ragel \
	    mingw-w64-clang-aarch64-pcre2 \
	    mingw-w64-clang-aarch64-zlib \
	    mingw-w64-clang-aarch64-python \
	    git make; \
	  repo_root="$$(pwd)"; \
	  vectorscan_src="$$repo_root/vendor/vectorscan-rs/vectorscan-rs-sys/vectorscan"; \
	  build_dir=/tmp/vectorscan-arm64-build; \
	  rm -rf "$$build_dir"; \
	  mkdir -p "$$build_dir"; \
	  cd "$$build_dir"; \
	  cmake "$$vectorscan_src" \
	    -G "MinGW Makefiles" \
	    -DCMAKE_BUILD_TYPE=Release \
	    -DBUILD_SHARED_LIBS=OFF \
	    -DBUILD_STATIC_LIBS=ON \
	    -DBUILD_UNIT=OFF \
	    -DBUILD_TOOLS=OFF \
	    -DFAT_RUNTIME=OFF \
	    -DCMAKE_SYSTEM_NAME=Windows \
	    -DCMAKE_SYSTEM_PROCESSOR=ARM64 \
	    -DCMAKE_C_COMPILER=clang \
	    -DCMAKE_CXX_COMPILER=clang++ \
	    -DCMAKE_INSTALL_PREFIX=/clangarm64; \
	  mingw32-make -j$$(nproc); \
	  mingw32-make install; \
	  mkdir -p /clangarm64/lib/pkgconfig; \
	  if [ -f /clangarm64/include/hs/hs.h ]; then \
	    hs_include=/clangarm64/include/hs; \
	  else \
	    hs_include=/clangarm64/include; \
	  fi; \
	  printf "%s\n" \
	    "prefix=/clangarm64" \
	    "exec_prefix=\$${prefix}" \
	    "libdir=\$${prefix}/lib" \
	    "includedir=$$hs_include" \
	    "" \
	    "Name: libhs" \
	    "Description: Vectorscan regex library (Hyperscan fork)" \
	    "Version: 5.4.12" \
	    "Libs: -L\$${libdir} -lhs" \
	    "Cflags: -I\$${includedir}" \
	    > /clangarm64/lib/pkgconfig/libhs.pc; \
	  export PKG_CONFIG_ALLOW_CROSS=1; \
	  export PKG_CONFIG_PATH=/clangarm64/lib/pkgconfig; \
	  export PKG_CONFIG_LIBDIR=/clangarm64/lib/pkgconfig; \
	  pkg-config --cflags --libs libhs; \
	  if ! command -v rustup >/dev/null 2>&1 && ! command -v rustup.exe >/dev/null 2>&1; then \
	    cargo_home_candidate=""; \
	    if [ -n "$${USERPROFILE:-}" ]; then \
	      cargo_home_candidate="$$(cygpath -u "$${USERPROFILE}")/.cargo/bin"; \
	    elif [ -n "$${HOMEDRIVE:-}" ] && [ -n "$${HOMEPATH:-}" ]; then \
	      cargo_home_candidate="$$(cygpath -u "$${HOMEDRIVE}$${HOMEPATH}")/.cargo/bin"; \
	    fi; \
	    if [ -n "$$cargo_home_candidate" ] && [ -d "$$cargo_home_candidate" ]; then \
	      echo "Adding Rust toolchain path: $$cargo_home_candidate"; \
	      export PATH="$$cargo_home_candidate:$$PATH"; \
	    fi; \
	  fi; \
	  if command -v rustup >/dev/null 2>&1; then \
	    RUSTUP_BIN=rustup; \
	  elif command -v rustup.exe >/dev/null 2>&1; then \
	    RUSTUP_BIN=rustup.exe; \
	  else \
	    echo "rustup not found. Install Rust via rustup and ensure ~/.cargo/bin is on PATH."; \
	    exit 1; \
	  fi; \
	  if command -v cargo >/dev/null 2>&1; then \
	    CARGO_BIN=cargo; \
	  elif command -v cargo.exe >/dev/null 2>&1; then \
	    CARGO_BIN=cargo.exe; \
	  else \
	    echo "cargo not found. Install Rust via rustup and ensure ~/.cargo/bin is on PATH."; \
	    exit 1; \
	  fi; \
	  cd "$$repo_root"; \
	  export HYPERSCAN_ROOT="$$(cygpath -m /clangarm64)"; \
	  export LIBRARY_PATH="/clangarm64/lib:$${LIBRARY_PATH:-}"; \
	  export CPATH="/clangarm64/include:$${CPATH:-}"; \
	  export RUSTFLAGS="$${RUSTFLAGS:-} -L native=/clangarm64/lib -C target-feature=+crt-static -C link-arg=-static"; \
	  echo "Using HYPERSCAN_ROOT=$$HYPERSCAN_ROOT"; \
	  "$$RUSTUP_BIN" target add aarch64-pc-windows-gnullvm; \
	  export LIBHS_NO_PKG_CONFIG=1; \
	  if [ "$${WINDOWS_ONLY_DEPS:-0}" = "1" ]; then \
	    echo "WINDOWS_ONLY_DEPS=1 set; skipping cargo build and packaging."; \
	    exit 0; \
	  fi; \
	  "$$CARGO_BIN" build --release --target aarch64-pc-windows-gnullvm; \
	  mkdir -p target/release; \
	  cp target/aarch64-pc-windows-gnullvm/release/$(PROJECT_NAME).exe target/release/$(PROJECT_NAME).exe; \
	  cd target/release; \
	  sha256sum $(PROJECT_NAME).exe > CHECKSUM-windows-arm64.txt; \
	  rm -f $(PROJECT_NAME)-windows-arm64.zip; \
	  powershell.exe -NoProfile -Command "Compress-Archive -Path '\''$(PROJECT_NAME).exe'\'','\''CHECKSUM-windows-arm64.txt'\'' -DestinationPath '\''$(PROJECT_NAME)-windows-arm64.zip'\'' -Force"; \
	  sha256sum $(PROJECT_NAME)-windows-arm64.zip >> CHECKSUM-windows-arm64.txt; \
	  echo "Built binary: target/release/$(PROJECT_NAME).exe"; \
	  echo "Built archive: target/release/$(PROJECT_NAME)-windows-arm64.zip"; \
	'

windows-test-x64: require-windows-host
	@bash -eu -o pipefail -c '\
	  case "$${MSYSTEM:-}" in \
	    MINGW64) toolchain_root=/mingw64; target_triple=x86_64-pc-windows-gnu ;; \
	    MSYS) export PATH=/mingw64/bin:$$PATH; toolchain_root=/mingw64; target_triple=x86_64-pc-windows-gnu ;; \
	    *) echo "Run this target from an MSYS2 MinGW64 shell."; exit 1 ;; \
	  esac; \
	  export LIBHS_NO_PKG_CONFIG=1; \
	  export HYPERSCAN_ROOT="$$(cygpath -m "$$toolchain_root")"; \
	  export PKG_CONFIG_ALLOW_CROSS=1; \
	  export PKG_CONFIG_PATH="$$toolchain_root/lib/pkgconfig"; \
	  export PKG_CONFIG_LIBDIR="$$toolchain_root/lib/pkgconfig"; \
	  if ! command -v cargo >/dev/null 2>&1 && [ -n "$${USERPROFILE:-}" ]; then \
	    cargo_home_candidate="$$(cygpath -u "$${USERPROFILE}")/.cargo/bin"; \
	    if [ -d "$$cargo_home_candidate" ]; then \
	      export PATH="$$cargo_home_candidate:$$PATH"; \
	    fi; \
	  fi; \
	  extra_native_lib_dirs="-L native=/mingw64/lib"; \
	  if command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then \
	    libgcc_a_path="$$(x86_64-w64-mingw32-gcc -print-libgcc-file-name 2>/dev/null || true)"; \
	    if [ -n "$$libgcc_a_path" ] && [ -f "$$libgcc_a_path" ]; then \
	      libgcc_dir="$$(dirname "$$libgcc_a_path")"; \
	      extra_native_lib_dirs="$$extra_native_lib_dirs -L native=$$libgcc_dir"; \
	      echo "Using libgcc from $$libgcc_dir"; \
	    fi; \
	  fi; \
	  export RUSTFLAGS="$${RUSTFLAGS:-} $$extra_native_lib_dirs -C target-feature=+crt-static -C link-arg=-static"; \
	  echo "▶ cargo test --release --workspace --all-targets --target $$target_triple"; \
	  cargo test --release --workspace --all-targets --target "$$target_triple"; \
	'

windows-test-arm64: require-windows-host
	@bash -eu -o pipefail -c '\
	  case "$${MSYSTEM:-}" in \
	    CLANGARM64) toolchain_root=/clangarm64; target_triple=aarch64-pc-windows-gnullvm ;; \
	    MINGW64|MSYS) export PATH=/clangarm64/bin:$$PATH; toolchain_root=/clangarm64; target_triple=aarch64-pc-windows-gnullvm ;; \
	    *) echo "Run this target from an MSYS2 CLANGARM64 shell."; exit 1 ;; \
	  esac; \
	  export LIBHS_NO_PKG_CONFIG=1; \
	  export HYPERSCAN_ROOT="$$(cygpath -m "$$toolchain_root")"; \
	  export PKG_CONFIG_ALLOW_CROSS=1; \
	  export PKG_CONFIG_PATH="$$toolchain_root/lib/pkgconfig"; \
	  export PKG_CONFIG_LIBDIR="$$toolchain_root/lib/pkgconfig"; \
	  if ! command -v cargo >/dev/null 2>&1 && [ -n "$${USERPROFILE:-}" ]; then \
	    cargo_home_candidate="$$(cygpath -u "$${USERPROFILE}")/.cargo/bin"; \
	    if [ -d "$$cargo_home_candidate" ]; then \
	      export PATH="$$cargo_home_candidate:$$PATH"; \
	    fi; \
	  fi; \
	  export RUSTFLAGS="$${RUSTFLAGS:-} -L native=/clangarm64/lib -C target-feature=+crt-static -C link-arg=-static"; \
	  echo "▶ cargo test --release --workspace --all-targets --target $$target_triple"; \
	  cargo test --release --workspace --all-targets --target "$$target_triple"; \
	'

windows-test: windows-test-x64 windows-test-arm64
#
# =============  DOCKER-BASED BUILDS =============
# #

linux-x64: check-docker create-dockerignore
	@mkdir -p target/release
	docker run --platform linux/amd64 --rm \
          -v "$$(pwd):/src" -w /src rust:1.96-alpine sh -eu -c '\
		apk add --no-cache \
		    musl-dev \
		    gcc g++ make cmake pkgconfig \
		    zlib-dev  zlib-static \
		    bzip2-dev bzip2-static \
		    xz-dev    xz-static \
		    boost-dev linux-headers \
		    patch perl ragel \
	        git openssl-dev curl && \
		\
		cargo test --workspace --all-targets ; \
		\
		rustup target add x86_64-unknown-linux-musl && \
		\
		export PKG_CONFIG_ALLOW_CROSS=1 ; \
		export RUSTFLAGS="-C target-feature=+crt-static" ; \
		\
		cargo build --release --target x86_64-unknown-linux-musl && \
		cd target/x86_64-unknown-linux-musl/release && \
	    sha256sum kingfisher > CHECKSUM.txt && \
	    tar -czf /src/target/release/kingfisher-linux-x64.tgz \
	        kingfisher CHECKSUM.txt \
	'
	$(MAKE) list-archives

linux-arm64: check-docker create-dockerignore
	@mkdir -p target/release
	docker run --platform linux/arm64 --rm \
          -v "$$(pwd):/src" -w /src rust:1.96-alpine sh -eu -c '\
		apk add --no-cache \
		    musl-dev \
		    gcc g++ make cmake pkgconfig \
		    zlib-dev  zlib-static \
		    bzip2-dev bzip2-static \
		    xz-dev    xz-static \
		    boost-dev linux-headers \
		    patch perl ragel \
	        git openssl-dev curl && \
		\
		rustup target add aarch64-unknown-linux-musl && \
		\
		cargo test --workspace --all-targets ; \
		\
		export PKG_CONFIG_ALLOW_CROSS=1 ; \
		export RUSTFLAGS="-C target-feature=+crt-static" ; \
		\
		cargo build --release --target aarch64-unknown-linux-musl && \
		\
		cd target/aarch64-unknown-linux-musl/release && \
	    sha256sum kingfisher > CHECKSUM.txt && \
	    tar -czf /src/target/release/kingfisher-linux-arm64.tgz \
	        kingfisher CHECKSUM.txt \
	'
	$(MAKE) list-archives


# =============  AGGREGATE TARGETS  =============
#

windows: windows-x64 windows-arm64
	@echo "# Windows builds:" > target/release/CHECKSUMS-windows.txt
	@echo -e "\n# x86_64-windows build:" >> target/release/CHECKSUMS-windows.txt
	@cat target/release/CHECKSUM-windows-x64.txt >> target/release/CHECKSUMS-windows.txt
	@echo -e "\n# arm64-windows build:" >> target/release/CHECKSUMS-windows.txt
	@cat target/release/CHECKSUM-windows-arm64.txt >> target/release/CHECKSUMS-windows.txt
	@echo -e "\nBuilt Windows archives:"
	@ls -lh target/release/*.zip
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

all: linux-all darwin-all
	@echo "# All builds:" > target/release/CHECKSUMS.txt
	@echo -e "\n# Linux builds:" >> target/release/CHECKSUMS.txt
	@cat target/release/CHECKSUMS-linux.txt >> target/release/CHECKSUMS.txt
	@echo -e "\n# darwin builds:" >> target/release/CHECKSUMS.txt
	@cat target/release/CHECKSUMS-darwin.txt >> target/release/CHECKSUMS.txt
	@echo -e "\nBuilt archives:"
	@ls -lh target/release/*.tgz
	@echo -e "\nCombined Checksums:"
	@cat target/release/CHECKSUMS.txt

dockerfile:
# Build for the host architecture (default)
	docker build -f docker/Dockerfile -t kingfisher:latest .

# Cross‑build for arm64 from an x64 machine
	docker buildx build -f docker/Dockerfile --platform linux/arm64 -t kingfisher:arm64 .

list-archives:
	@echo -e "\n=== Built archives ==="
	@found=0; \
	for f in target/release/*.tgz target/release/*.zip; do \
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
        required=1.96.0; \
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
	    cargo install --locked cargo-nextest || true; \
	fi
	@echo "▶ running tests …"; \
	if command -v cargo-nextest >/dev/null 2>&1; then \
	    cargo nextest run --workspace --all-targets; \
	else \
	    echo "⚠️  cargo-nextest unavailable – falling back to cargo test"; \
	    cargo test --workspace --all-targets; \
	fi

audit-deps:
	@echo "🔍 checking for cargo-audit …"
	@if command -v cargo-audit >/dev/null 2>&1; then \
	    echo "✅ cargo-audit already present"; \
	else \
	    echo "📦 installing cargo-audit …"; \
	    cargo install --locked cargo-audit; \
	fi
	@echo "▶ auditing dependency vulnerabilities …"
	@cargo audit

fuzz:
	@echo "🐛 Running fuzz targets (cargo-fuzz required, nightly Rust required)…"
	@command -v cargo-fuzz >/dev/null 2>&1 || { \
		echo "📦 installing cargo-fuzz …"; \
		cargo install cargo-fuzz; \
	}
	@rustup toolchain list | grep -q nightly || { \
		echo "📦 installing nightly toolchain …"; \
		rustup toolchain install nightly; \
	}
	@fuzz_seconds=$${FUZZ_SECONDS:-60}; \
	NIGHTLY_PATH="$$HOME/.rustup/toolchains/nightly-$$(rustc -vV | awk '/^host:/{print $$2}')/bin"; \
	if [ ! -d "$$NIGHTLY_PATH" ]; then \
		echo "❌ Nightly toolchain not found at $$NIGHTLY_PATH"; \
		exit 1; \
	fi; \
	export PATH="$$NIGHTLY_PATH:$$PATH"; \
	echo "Using rustc: $$(which rustc) ($$(rustc --version))"; \
	for target in fuzz_entropy fuzz_location fuzz_base64 fuzz_span; do \
		echo "▶ fuzzing $$target for $${fuzz_seconds}s …"; \
		cargo fuzz run $$target -- \
			-max_total_time=$${fuzz_seconds} \
			-max_len=4096 || { echo "❌ $$target found a crash"; exit 1; }; \
		echo "✅ $$target passed"; \
	done
	@echo "🎉 All fuzz targets passed"

# =============  DOCUMENTATION  =============

DOCS_REQUIREMENTS := docs-site/requirements.txt

docs-build:
	@echo "📝 Preparing documentation…"
	@uv run --with-requirements $(DOCS_REQUIREMENTS) \
		python3 docs-site/scripts/prepare-docs.py
	@uv run --with-requirements $(DOCS_REQUIREMENTS) \
		python3 docs-site/scripts/generate-rules-page.py
	@echo "🔨 Building site…"
	@cd docs-site && uv run --with-requirements requirements.txt \
		mkdocs build
	@echo "✅ Site built at docs-site/site/"

docs-serve:
	@echo "📝 Preparing documentation…"
	@uv run --with-requirements $(DOCS_REQUIREMENTS) \
		python3 docs-site/scripts/prepare-docs.py
	@uv run --with-requirements $(DOCS_REQUIREMENTS) \
		python3 docs-site/scripts/generate-rules-page.py
	@echo "🌐 Starting dev server at http://127.0.0.1:8000/"
	@cd docs-site && uv run --with-requirements requirements.txt \
		mkdocs serve

docs-clean:
	@rm -rf docs-site/site
	@echo "🧹 Cleaned docs-site/site/"

clean:
	@echo "Cleaning build artifacts..."
	cargo clean
	rm -f .dockerignore
	rm -rf docs-site/site

notices:
	@echo "Generating third-party notices..."
	@cargo install cargo-bundle-licenses
	@cargo bundle-licenses --format yaml --output THIRD_PARTY_NOTICES
