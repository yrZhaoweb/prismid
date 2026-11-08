//! Windows native hardware anchor implementation (`MachineGuid`, SMBIOS UUID, and Hypervisor detection).

use crate::{
    detect_vm_vendor_from_text, load_or_create_file_anchor, NativeHardwareAnchor,
};
use std::process::Command;

pub fn collect() -> NativeHardwareAnchor {
    let reg_out = run_cmd(
        "reg",
        &[
            "query",
            r"HKLM\SOFTWARE\Microsoft\Cryptography",
            "/v",
            "MachineGuid",
        ],
    );
    let hw_uuid = parse_reg_value(&reg_out, "MachineGuid");

    let wmic_out = run_cmd(
        "powershell",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Get-CimInstance -ClassName Win32_ComputerSystemProduct | Select-Object -ExpandProperty UUID; Get-CimInstance -ClassName Win32_BIOS | Select-Object -ExpandProperty SerialNumber; Get-CimInstance -ClassName Win32_Processor | Select-Object -ExpandProperty Name; Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty TotalPhysicalMemory; Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty HypervisorPresent; Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty Manufacturer",
        ],
    );
    let mut lines = wmic_out.lines().map(str::trim).filter(|s| !s.is_empty());
    let serial_number = lines.next().unwrap_or("").to_string();
    let _bios_serial = lines.next().unwrap_or("");
    let cpu_brand = lines.next().unwrap_or("").to_string();
    let memory_bytes = lines
        .next()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);
    let hypervisor_str = lines.next().unwrap_or("");
    let manufacturer = lines.next().unwrap_or("");

    let cpu_cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);

    let mut is_vm = hypervisor_str.eq_ignore_ascii_case("true");
    let mut vm_vendor = String::new();
    if let Some(v) = detect_vm_vendor_from_text(&format!("{} {}", manufacturer, wmic_out)) {
        is_vm = true;
        vm_vendor = v;
    } else if is_vm {
        vm_vendor = "hypervisor".to_string();
    }

    let keychain_anchor = load_or_create_file_anchor(if hw_uuid.is_empty() {
        "windows_default"
    } else {
        &hw_uuid
    });

    NativeHardwareAnchor {
        platform: "windows".to_string(),
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

fn parse_reg_value(output: &str, key: &str) -> String {
    for line in output.lines() {
        if line.contains(key) {
            if let Some(last) = line.split_whitespace().last() {
                return last.trim().to_string();
            }
        }
    }
    String::new()
}

fn run_cmd(program: &str, args: &[&str]) -> String {
    Command::new(program)
        .args(args)
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}
