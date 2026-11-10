//! Windows native hardware anchor implementation (`MachineGuid`, SMBIOS UUID, BIOS SerialNumber,
//! HKCU Registry / user-profile persistent anchor, and Hypervisor detection).

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

    let cim_out = run_cmd(
        "powershell",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Get-CimInstance -ClassName Win32_ComputerSystemProduct | Select-Object -ExpandProperty UUID; Get-CimInstance -ClassName Win32_BIOS | Select-Object -ExpandProperty SerialNumber; Get-CimInstance -ClassName Win32_Processor | Select-Object -ExpandProperty Name; Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty TotalPhysicalMemory; Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty HypervisorPresent; Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty Manufacturer",
        ],
    );

    let cpu_cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);

    let mut parsed = parse_windows_cim_output(&reg_out, &cim_out, cpu_cores);
    parsed.keychain_anchor = load_or_create_windows_anchor(&parsed.hw_uuid);
    parsed
}

pub(crate) fn is_oem_placeholder(val: &str) -> bool {
    let lower = val.trim().to_ascii_lowercase();
    lower.is_empty()
        || lower == "0"
        || lower == "none"
        || lower.contains("to be filled")
        || lower.contains("default string")
        || lower.contains("system serial number")
        || lower.contains("not specified")
}

pub(crate) fn parse_windows_cim_output(
    reg_out: &str,
    cim_out: &str,
    cpu_cores: usize,
) -> NativeHardwareAnchor {
    let mut hw_uuid = parse_reg_value(reg_out, "MachineGuid");

    let mut lines = cim_out.lines().map(str::trim).filter(|s| !s.is_empty());
    let smbios_uuid = lines.next().unwrap_or("").to_string();
    let bios_serial = lines.next().unwrap_or("").to_string();
    let cpu_brand = lines.next().unwrap_or("").to_string();
    let memory_bytes = lines
        .next()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);
    let hypervisor_str = lines.next().unwrap_or("");
    let manufacturer = lines.next().unwrap_or("");

    if hw_uuid.is_empty() && !is_oem_placeholder(&smbios_uuid) {
        hw_uuid = smbios_uuid.clone();
    }

    let serial_number = match (
        !is_oem_placeholder(&bios_serial),
        !is_oem_placeholder(&smbios_uuid),
    ) {
        (true, true) if !bios_serial.eq_ignore_ascii_case(&smbios_uuid) => {
            format!("{}:{}", bios_serial, smbios_uuid)
        }
        (true, _) => bios_serial,
        (false, true) => smbios_uuid,
        (false, false) => String::new(),
    };

    let mut is_vm = hypervisor_str.eq_ignore_ascii_case("true");
    let mut vm_vendor = String::new();
    if let Some(v) = detect_vm_vendor_from_text(&format!("{} {}", manufacturer, cim_out)) {
        is_vm = true;
        vm_vendor = v;
    } else if is_vm {
        vm_vendor = "hypervisor".to_string();
    }

    NativeHardwareAnchor {
        platform: "windows".to_string(),
        hw_uuid,
        serial_number,
        keychain_anchor: String::new(),
        cpu_brand,
        cpu_cores,
        memory_bytes,
        is_vm,
        vm_vendor,
    }
}

fn load_or_create_windows_anchor(hw_uuid: &str) -> String {
    let reg_key = r"HKCU\Software\PrismID";
    let existing = run_cmd("reg", &["query", reg_key, "/v", "DeviceAnchor"]);
    let parsed = parse_reg_value(&existing, "DeviceAnchor");
    if parsed.len() >= 32 && parsed.chars().all(|c| c.is_ascii_hexdigit()) {
        return parsed.to_ascii_lowercase();
    }

    let seed = if hw_uuid.is_empty() {
        "windows_default"
    } else {
        hw_uuid
    };
    let anchor = load_or_create_file_anchor(seed);
    let _ = run_cmd(
        "reg",
        &[
            "add",
            reg_key,
            "/v",
            "DeviceAnchor",
            "/t",
            "REG_SZ",
            "/d",
            &anchor,
            "/f",
        ],
    );
    anchor
}

pub(crate) fn parse_reg_value(output: &str, key: &str) -> String {
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
