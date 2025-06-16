#[cfg_attr(not(target_os = "windows"), allow(unused_imports))]
#[cfg(not(target_os = "windows"))]
use std::{fs::File, process::Command};

use std::path::PathBuf;

/// Get the environment variable with the given name, panicking if it is not set.
#[cfg(not(target_os = "windows"))]
fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("`{}` should be set in the environment", name))
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=vectorscan.patch");

    #[cfg(target_os = "windows")]
    {
        // Force LIBHS_NO_PKG_CONFIG=1 for any commands this build script spawns
        std::env::set_var("LIBHS_NO_PKG_CONFIG", "1");

        // Also propagate it so the compiler sees it during subsequent steps:
        println!("cargo:rustc-env=LIBHS_NO_PKG_CONFIG=1");
        
        // If HYPERSCAN_ROOT not set, try to find hs_runtime.lib by searching typical vcpkg layouts
        if std::env::var_os("HYPERSCAN_ROOT").is_none() {
            if let Some(hs_lib) = find_hs_runtime_lib() {
                // hs_lib typically ends with ...\installed\x64-windows(-static)\lib\hs_runtime.lib
                let lib_dir = hs_lib.parent().expect("no parent directory?");
                if lib_dir.file_name().unwrap() == "lib" {
                    let trip_dir = lib_dir.parent().expect("no triple directory?");
                    let trip_name = trip_dir.file_name().unwrap().to_string_lossy();
                    if trip_name == "x64-windows" || trip_name == "x64-windows-static" {
                        let installed_dir = trip_dir.parent().expect("no installed dir?");
                        if installed_dir.file_name().unwrap() == "installed" {
                            // That’s our root
                            std::env::set_var("HYPERSCAN_ROOT", trip_dir);
                        }
                    }
                }
            }
        }

        // Now read HYPERSCAN_ROOT (which might be auto-set above)
        let hs_root = std::env::var("HYPERSCAN_ROOT").unwrap_or_else(|_| {
            panic!("Could not locate hs_runtime.lib; please set HYPERSCAN_ROOT manually.")
        });

        // Link to the static library
        println!("cargo:rustc-link-search=native={}/lib", hs_root);
        println!("cargo:rustc-link-lib=static=hs");

        // Expect user to have installed Hyperscan via vcpkg:
        //   .\vcpkg.exe install hyperscan:x64-windows-static pkgconf
        // and set:
        //   set LIBHS_NO_PKG_CONFIG=1
        //   set HYPERSCAN_ROOT=C:\dev\vcpkg\installed\x64-windows-static
        // Require user to explicitly tell us not to use pkg-config
        if std::env::var_os("LIBHS_NO_PKG_CONFIG").is_none() {
            panic!("Set LIBHS_NO_PKG_CONFIG=1 on Windows when using vcpkg");
        }

        let hs_root = std::env::var("HYPERSCAN_ROOT").unwrap();
        println!("cargo:rustc-link-search=native={}/lib", hs_root);
        println!("cargo:rustc-link-lib=static=hs");

        let target_env_kind = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
        if target_env_kind == "msvc" {
            // MSVC typically links in its own runtime automatically
        } else {
            println!("cargo:rustc-link-lib=stdc++");
        }

        // Generate or copy bindings
        #[cfg(feature = "bindgen")]
        {
            let include_dir = format!("{}/include", hs_root);
            let config = bindgen::Builder::default()
                .allowlist_function("hs_.*")
                .allowlist_type("hs_.*")
                .allowlist_var("HS_.*")
                .header("wrapper.h")
                .clang_arg(format!("-I{}", include_dir));
            config
                .generate()
                .expect("Unable to generate bindings")
                .write_to_file(PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("bindings.rs"))
                .expect("Failed to write bindings");
        }
        #[cfg(not(feature = "bindgen"))]
        {
            std::fs::copy(
                "src/bindings.rs",
                PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("bindings.rs"),
            )
            .expect("Failed to write Rust bindings");
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        use std::fs::File;
        use std::process::Command;

        let manifest_dir = PathBuf::from(env("CARGO_MANIFEST_DIR"));
        let out_dir = PathBuf::from(env("OUT_DIR"));
        let include_dir = out_dir
            .join("include")
            .into_os_string()
            .into_string()
            .unwrap();

        // Choose appropriate C++ runtime library for *nix
        {
            let compiler_version_out = String::from_utf8(
                Command::new("c++")
                    .args(["-v"])
                    .output()
                    .expect("Failed to get C++ compiler version")
                    .stderr,
            )
            .unwrap();

            if compiler_version_out.contains("gcc") {
                println!("cargo:rustc-link-lib=stdc++");
            } else if compiler_version_out.contains("clang") {
                println!("cargo:rustc-link-lib=c++");
            } else {
                panic!("No compatible compiler found: either clang or gcc is needed");
            }
        }

        const VERSION: &str = "5.4.11";
        let tarball_path = manifest_dir.join(format!("{VERSION}.tar.gz"));
        let vectorscan_src_dir = out_dir.join(format!("vectorscan-vectorscan-{VERSION}"));
        let patchfile = manifest_dir.join("vectorscan.patch");

        // Extract release tarball
        {
            match std::fs::remove_dir_all(&vectorscan_src_dir) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => panic!("Failed to clean Vectorscan source directory: {e}"),
            }
            let infile =
                File::open(tarball_path).expect("Failed to open Vectorscan release tarball");
            let gz = flate2::read::GzDecoder::new(infile);
            let mut tar = tar::Archive::new(gz);
            tar.unpack(&out_dir)
                .expect("Could not unpack Vectorscan source files");
            eprintln!("Tarball extracted to {}", out_dir.display());
        }

        eprintln!(
            "Vectorscan source directory is at {}",
            vectorscan_src_dir.display()
        );

        // Apply patch
        {
            let patch_input = File::open(&patchfile).expect("Failed to open patchfile");
            let output = Command::new("patch")
                .args(["-p1"])
                .current_dir(&vectorscan_src_dir)
                .stdin(patch_input)
                .output()
                .expect("Failed to apply patchfile");
            assert!(output.status.success());
            eprintln!(
                "Successfully applied patches to {}",
                vectorscan_src_dir.display()
            );
        }

        // Build with cmake
        {
            let mut cfg = cmake::Config::new(&vectorscan_src_dir);

            macro_rules! cfg_define_feature {
                ($cmake_feature: tt, $cargo_feature: tt) => {
                    cfg.define(
                        $cmake_feature,
                        if cfg!(feature = $cargo_feature) {
                            "ON"
                        } else {
                            "OFF"
                        },
                    )
                };
            }

            let profile = match env("OPT_LEVEL").as_str() {
                "0" => "Debug",
                "s" | "z" => "MinSizeRel",
                _ => "Release",
            };

            cfg.profile(profile)
                .define("CMAKE_INSTALL_INCLUDEDIR", &include_dir)
                .define("CMAKE_VERBOSE_MAKEFILE", "ON")
                .define("BUILD_SHARED_LIBS", "OFF")
                .define("BUILD_STATIC_LIBS", "ON")
                .define("FAT_RUNTIME", "OFF")
                .define("WARNINGS_AS_ERRORS", "OFF")
                .define("BUILD_EXAMPLES", "OFF")
                .define("BUILD_BENCHMARKS", "OFF")
                .define("BUILD_DOC", "OFF")
                .define("BUILD_TOOLS", "OFF");

            cfg_define_feature!("BUILD_UNIT", "unit_hyperscan");
            cfg_define_feature!("USE_CPU_NAIVE", "cpu_native");

            if cfg!(feature = "asan") {
                cfg.define("SANITIZE", "address");
            }

            if cfg!(feature = "simd_specialization") {
                macro_rules! x86_64_feature {
                    ($feature: tt) => {{
                        #[cfg(target_arch = "x86_64")]
                        {
                            if std::arch::is_x86_feature_detected!($feature) {
                                "ON"
                            } else {
                                "OFF"
                            }
                        }
                        #[cfg(not(target_arch = "x86_64"))]
                        {
                            "OFF"
                        }
                    }};
                }
                macro_rules! aarch64_feature {
                    ($feature: tt) => {{
                        #[cfg(target_arch = "aarch64")]
                        {
                            if std::arch::is_aarch64_feature_detected!($feature) {
                                "ON"
                            } else {
                                "OFF"
                            }
                        }
                        #[cfg(not(target_arch = "aarch64"))]
                        {
                            "OFF"
                        }
                    }};
                }
                cfg.define("BUILD_AVX2", x86_64_feature!("avx2"));
                cfg.define("BUILD_AVX512", x86_64_feature!("avx512vbmi"));
                cfg.define("BUILD_AVX512VBMI", x86_64_feature!("avx512vbmi"));
                cfg.define("BUILD_SVE", aarch64_feature!("sve"));
                cfg.define("BUILD_SVE2", aarch64_feature!("sve2"));
                cfg.define("BUILD_SVE2_BITPERM", aarch64_feature!("sve2-bitperm"));
            } else {
                cfg.define("BUILD_AVX2", "OFF")
                    .define("BUILD_AVX512", "OFF")
                    .define("BUILD_AVX512VBMI", "OFF")
                    .define("BUILD_SVE", "OFF")
                    .define("BUILD_SVE2", "OFF")
                    .define("BUILD_SVE2_BITPERM", "OFF");
            }

            let dst = cfg.build();
            println!("cargo:rustc-link-lib=static=hs");
            println!("cargo:rustc-link-search={}", dst.join("lib").display());
            println!("cargo:rustc-link-search={}", dst.join("lib64").display());
        }

        // Run hyperscan unit test suite
        #[cfg(feature = "unit_hyperscan")]
        {
            let unittests = out_dir.join("build").join("bin").join("unit-hyperscan");
            match Command::new(unittests).status() {
                Ok(rc) if rc.success() => {}
                Ok(rc) => panic!("Failed to run unit tests: exit with code {rc}"),
                Err(e) => panic!("Failed to run unit tests: {e}"),
            }
        }

        // Bindgen or copy bindings
        #[cfg(feature = "bindgen")]
        {
            let config = bindgen::Builder::default()
                .allowlist_function("hs_.*")
                .allowlist_type("hs_.*")
                .allowlist_var("HS_.*")
                .header("wrapper.h")
                .clang_arg(format!("-I{}", &include_dir));
            config
                .generate()
                .expect("Unable to generate bindings")
                .write_to_file(out_dir.join("bindings.rs"))
                .expect("Failed to write Rust bindings to Vectorscan");
        }
        #[cfg(not(feature = "bindgen"))]
        {
            std::fs::copy("src/bindings.rs", out_dir.join("bindings.rs"))
                .expect("Failed to write Rust bindings to Vectorscan");
        }
    }
}

#[cfg(target_os = "windows")]
fn find_hs_runtime_lib() -> Option<std::path::PathBuf> {
    // Try a small set of known vcpkg locations
    let vcpkg_root = std::env::var("VCPKG_ROOT").ok();
    let vcpkg_temp = std::env::var("TEMP")
        .map(|temp| format!("{}\\vcpkg", temp))
        .ok();
    let candidates = [
        vcpkg_root.as_deref().unwrap_or("C:\\vcpkg"),
        vcpkg_temp.as_deref().unwrap_or("C:\\vcpkg"),
        r"C:\dev\vcpkg",
    ];

    for base in candidates {
        for arch_trip in ["x64-windows-static", "x64-windows"] {
            let lib_candidate = std::path::Path::new(base)
                .join("installed")
                .join(arch_trip)
                .join("lib")
                .join("hs_runtime.lib");
            if lib_candidate.exists() {
                return Some(lib_candidate);
            }
        }
    }
    None
}
