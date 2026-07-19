use std::{env, path::PathBuf, process::Command};

fn main() {
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let source = manifest_dir.join("../../bpf/xprobe.bpf.c");
    let output = PathBuf::from(env::var_os("OUT_DIR").expect("out dir")).join("xprobe.bpf.o");
    let clang = env::var_os("CLANG").unwrap_or_else(|| "clang".into());

    println!("cargo:rerun-if-changed={}", source.display());
    println!("cargo:rerun-if-env-changed=CLANG");

    let status = Command::new(clang)
        .args([
            "-target",
            "bpf",
            "-D__TARGET_ARCH_x86",
            "-I/usr/include/x86_64-linux-gnu",
            "-O2",
            "-g",
            "-Wall",
            "-Werror",
            "-c",
        ])
        .arg(&source)
        .arg("-o")
        .arg(&output)
        .status()
        .expect("failed to execute clang for the eBPF program");

    assert!(
        status.success(),
        "clang failed to compile {}",
        source.display()
    );
}
