# kingfisher-secret-scanner-darwin-arm64

Internal optional native package for `kingfisher-secret-scanner`, macOS Apple Silicon ARM64.
Install the main SDK package rather than this package directly.

Requires Node.js 22.13.0+ (22.x), 24.x or 26.x on a macOS version supported by that Node
release. The addon deployment target is macOS 11; this does not lower Node's own
OS requirements. No compiler is needed at install time.

See the [SDK guide](https://github.com/mongodb/kingfisher/blob/main/docs/JAVASCRIPT.md).
Published release packages include `LICENSE*`, `NOTICE*`, and
`THIRD_PARTY_NOTICES` alongside the addon. Release staging copies and verifies
these canonical SDK notices; the private source-tree platform directories
are not publishable packages.
