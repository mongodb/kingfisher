# kingfisher-secret-scanner-linux-arm64-gnu

Internal optional native package for `kingfisher-secret-scanner`, GNU/Linux ARM64.
Install the main SDK package rather than this package directly.

Requires Node.js 22.13.0+ (22.x), 24.x or 26.x, glibc **2.35+**, and a GCC 11-compatible
libstdc++ runtime providing **GLIBCXX_3.4.29 / CXXABI_1.3.13** or newer.
Release CI audits imported ELF symbol versions and shared-library dependencies.
This is not a musl/Alpine or manylinux/glibc 2.28 build.

See the [SDK guide](https://github.com/mongodb/kingfisher/blob/main/docs/JAVASCRIPT.md).
Published release packages include `LICENSE*`, `NOTICE*`, and
`THIRD_PARTY_NOTICES` alongside the addon. Release staging copies and verifies
these canonical SDK notices; the private source-tree platform directories
are not publishable packages.
