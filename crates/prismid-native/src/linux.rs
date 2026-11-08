//! Linux native hardware anchor implementation (`/etc/machine-id`, DMI UUID, and `/proc/cpuinfo`).

use crate::{
    detect_vm_vendor_from_text, load_or_create_file_anchor, NativeHardwareAnchor,
};
use std::fs;

pub fn collect() -> NativeHardwareAnchor {
    let hw_uuid = read_trimmed("/etc/machine-id")
        .or_else(|| read_trimmed("/var/lib/dbus/machine-id"))
        .unwrap_or_default();

    let serial_number = read_trimmed("/sys/class/dmi/id/product_uuid")
        .or_else(|| read_trimmed("/sys/class/dmi/id/product_serial"))
        .or_else(|| read_trimmed("/sys/class/dmi/id/board_serial"))
        .unwrap_or_else(|| hw_uuid.clone());

    let sys_vendor = read_trimmed("/sys/class/dmi/id/sys_vendor").unwrap_or_default();
    let product_name = read_trimmed("/sys/class/dmi/id/product_name").unwrap_or_default();

    let cpuinfo = fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    let cpu_brand = parse_cpu_brand(&cpuinfo);
    let cpu_cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let memory_bytes = parse_memtotal_bytes();

    let mut is_vm = cpuinfo
        .lines()
        .any(|l| l.starts_with("flags") && l.contains(" hypervisor"));
    let mut vm_vendor = String::new();
    if let Some(v) =
        detect_vm_vendor_from_text(&format!("{} {} {}", sys_vendor, product_name, cpuinfo))
    {
        is_vm = true;
        vm_vendor = v;
    } else if is_vm {
        vm_vendor = "hypervisor".to_string();
    }

    let keychain_anchor = load_or_create_file_anchor(if hw_uuid.is_empty() {
        "linux_default"
    } else {
        &hw_uuid
    });

    NativeHardwareAnchor {
        platform: "linux".to_string(),
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

fn read_trimmed(path: &str) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn parse_cpu_brand(cpuinfo: &str) -> String {
    for line in cpuinfo.lines() {
        if line.starts_with("model name") || line.starts_with("Processor") {
            if let Some(pos) = line.find(':') {
                let val = line[pos + 1..].trim();
                if !val.is_empty() {
                    return val.to_string();
                }
            }
        }
    }
    String::new()
}

fn parse_memtotal_bytes() -> u64 {
    let meminfo = fs::read_to_string("/proc/meminfo").unwrap_or_default();
    for line in meminfo.lines() {
        if line.starts_with("MemTotal:") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                if let Ok(kb) = parts[1].parse::<u64>() {
                    return kb * 1024;
                }
            }
        }
    }
    0
}
