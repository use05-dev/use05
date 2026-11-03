//! On macOS, compile the Secure Enclave bridge (touchid/touchid.swift) into the binary, for the
//! Touch ID approver key. Without a Swift compiler the build goes on without it, says so, and
//! 05 offers the passphrase-protected key instead. Nothing happens on other systems.

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=touchid/touchid.swift");
    println!("cargo:rerun-if-env-changed=USE05_NO_TOUCH_ID");
    println!("cargo:rerun-if-env-changed=USE05_REQUIRE_TOUCH_ID");
    println!("cargo::rustc-check-cfg=cfg(use05_touch_id)");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") || env::var_os("USE05_NO_TOUCH_ID").is_some() {
        return;
    }
    let arch = match env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("aarch64") => "arm64",
        Ok("x86_64") => "x86_64",
        _ => return,
    };
    let out = PathBuf::from(env::var("OUT_DIR").expect("cargo sets OUT_DIR"));
    let lib = out.join("libuse05touchid.a");
    let built = Command::new("xcrun")
        .args(["swiftc", "-O", "-parse-as-library", "-emit-library", "-static", "-module-name", "Use05TouchId", "-target"])
        .arg(format!("{arch}-apple-macos12"))
        .arg("touchid/touchid.swift")
        .arg("-o")
        .arg(&lib)
        .status();
    if !built.is_ok_and(|s| s.success()) {
        // Release builds set this, so a macOS release never ships without Touch ID by accident.
        if env::var_os("USE05_REQUIRE_TOUCH_ID").is_some() {
            panic!("USE05_REQUIRE_TOUCH_ID is set, but touchid/touchid.swift did not compile");
        }
        println!("cargo:warning=no Swift compiler: this build of 05 has no Touch ID approver key (the passphrase key still works)");
        return;
    }
    // Where the Swift runtime libraries are, to link against; at run time they come from macOS.
    let toolchain = Command::new("xcrun")
        .args(["--find", "swiftc"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|p| PathBuf::from(p.trim()))
        .and_then(|p| p.parent().and_then(|bin| bin.parent()).map(|usr| usr.join("lib/swift/macosx")));
    if let Some(dir) = toolchain {
        println!("cargo:rustc-link-search=native={}", dir.display());
    }
    let sdk = Command::new("xcrun").args(["--show-sdk-path"]).output().ok().and_then(|o| String::from_utf8(o.stdout).ok());
    if let Some(sdk) = sdk {
        println!("cargo:rustc-link-search=native={}/usr/lib/swift", sdk.trim());
    }
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=use05touchid");
    for framework in ["Foundation", "CryptoKit", "LocalAuthentication", "Security"] {
        println!("cargo:rustc-link-lib=framework={framework}");
    }
    println!("cargo:rustc-link-arg=-Wl,-rpath,/usr/lib/swift");
    println!("cargo:rustc-cfg=use05_touch_id");
}
