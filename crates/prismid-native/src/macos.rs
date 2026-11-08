//! macOS native hardware anchor implementation using `ioreg` and `sysctl`.
//!
//! Explicitly avoids `diskutil info /` (~260ms) in favor of `ioreg -rd1 -c IOPlatformExpertDevice`
//! + `sysctl` (~12ms on Apple Silicon).

use crate::{
    detect_vm_vendor_from_text, load_or_create_file_anchor, NativeHardwareAnchor,
};
use std::process::Command;

const KEYCHAIN_SERVICE: &str = "io.prismid.device.anchor";
const KEYCHAIN_ACCOUNT: &str = "default";

pub fn collect() -> NativeHardwareAnchor {
    let ioreg_out = run_cmd("/usr/sbin/ioreg", &["-rd1", "-c", "IOPlatformExpertDevice"]);
    let hw_uuid = extract_ioreg_string(&ioreg_out, "IOPlatformUUID");
    let serial_number = extract_ioreg_string(&ioreg_out, "IOPlatformSerialNumber");
    let model = extract_ioreg_string(&ioreg_out, "model");

    // Batch sysctl reads into a single process spawn for minimum latency (~3ms)
    let sysctl_out = run_cmd(
        "/usr/sbin/sysctl",
        &[
            "-n",
            "machdep.cpu.brand_string",
            "hw.ncpu",
            "hw.memsize",
            "kern.hv_vmm_present",
        ],
    );
    let mut lines = sysctl_out.lines();
    let cpu_brand = lines.next().unwrap_or("").trim().to_string();
    let cpu_cores = lines
        .next()
        .and_then(|s| s.trim().parse::<usize>().ok())
        .unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1)
        });
    let memory_bytes = lines
        .next()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(0);
    let hv_vmm_present = lines
        .next()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .unwrap_or(0);

    let mut is_vm = hv_vmm_present == 1;
    let mut vm_vendor = String::new();
    if let Some(v) = detect_vm_vendor_from_text(&format!("{} {} {}", ioreg_out, model, cpu_brand)) {
        is_vm = true;
        vm_vendor = v;
    } else if is_vm {
        vm_vendor = "hypervisor".to_string();
    }

    let keychain_anchor = read_or_create_macos_keychain_anchor(&hw_uuid);

    NativeHardwareAnchor {
        platform: "macos".to_string(),
        hw_uuid,
        serial_number,
        keychain_anchor,
        cpu_brand,
        cpu_cores,
        memory_bytes,
        is_vm,
        vm_vendor,
    }
}

fn extract_ioreg_string(ioreg_output: &str, key: &str) -> String {
    let needle = format!("\"{}\"", key);
    for line in ioreg_output.lines() {
        if let Some(pos) = line.find(&needle) {
            let rest = &line[pos + needle.len()..];
            if let Some(eq_pos) = rest.find('=') {
                let after_eq = rest[eq_pos + 1..].trim();
                let cleaned = after_eq
                    .trim_start_matches('<')
                    .trim_end_matches('>')
                    .trim_matches('"')
                    .trim();
                if !cleaned.is_empty() {
                    return cleaned.to_string();
                }
            }
        }
    }
    String::new()
}

fn read_or_create_macos_keychain_anchor(hw_uuid_hint: &str) -> String {
    // Fast-path: check file cache first if it already matches keychain, or read from macOS security CLI
    if let Ok(output) = Command::new("/usr/bin/security")
        .args([
            "find-generic-password",
            "-s",
            KEYCHAIN_SERVICE,
            "-a",
            KEYCHAIN_ACCOUNT,
            "-w",
        ])
        .output()
    {
        if output.status.success() {
            let secret = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if secret.len() >= 16 {
                return secret;
            }
        }
    }

    let anchor = load_or_create_file_anchor(if hw_uuid_hint.is_empty() {
        "macos_default"
    } else {
        hw_uuid_hint
    });

    let _ = Command::new("/usr/bin/security")
        .args([
            "add-generic-password",
            "-U",
            "-s",
            KEYCHAIN_SERVICE,
            "-a",
            KEYCHAIN_ACCOUNT,
            "-w",
            &anchor,
        ])
        .output();

    anchor
}

fn run_cmd(program: &str, args: &[&str]) -> String {
    Command::new(program)
        .args(args)
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}
