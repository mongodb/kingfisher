/// Pack static-PIE relocations without changing code generation or disabling ASLR.
/// The Linux x64 release toolchain's musl CRT supports DT_RELR.
pub fn pack_relative_relocations(target: &str, profile: &str, target_features: &str) -> bool {
    target == "x86_64-unknown-linux-musl"
        && profile == "release"
        && target_features.split(',').any(|feature| feature == "crt-static")
}

#[cfg(test)]
mod tests {
    use super::pack_relative_relocations;

    #[test]
    fn packs_only_static_linux_x64_releases() {
        assert!(pack_relative_relocations(
            "x86_64-unknown-linux-musl",
            "release",
            "crt-static,sse,sse2"
        ));
        assert!(!pack_relative_relocations("x86_64-unknown-linux-musl", "debug", "crt-static"));
        assert!(!pack_relative_relocations("x86_64-unknown-linux-musl", "release", "sse,sse2"));
        assert!(!pack_relative_relocations(
            "x86_64-unknown-linux-musl",
            "release",
            "not-crt-static"
        ));
        for target in [
            "aarch64-unknown-linux-musl",
            "x86_64-unknown-linux-gnu",
            "x86_64-apple-darwin",
            "aarch64-apple-darwin",
            "x86_64-pc-windows-gnu",
            "aarch64-pc-windows-gnullvm",
        ] {
            assert!(!pack_relative_relocations(target, "release", "crt-static"), "{target}");
        }
    }
}
