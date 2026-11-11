//! Windows native hardware anchor implementation (`MachineGuid`, SMBIOS UUID, BIOS SerialNumber,
//! HKCU Registry / user-profile persistent anchor, and guest VM detection).
//!
//! Note on Windows 11 VBS / Credential Guard / WSL2:
//! `Win32_ComputerSystem.HypervisorPresent` is `True` on bare-metal Windows 11 hosts whenever
//! Virtualization-Based Security (VBS), Memory Integrity (HVCI), or WSL2/Hyper-V platform is
//! enabled. Therefore `HypervisorPresent` alone is NEVER treated as sufficient proof of a guest VM;
//! it must be corroborated by guest hardware/BIOS/model signatures (e.g. `"Virtual Machine"`,
//! `"VMware"`, `"VirtualBox"`, `"QEMU"`, `"KVM"`, `"Parallels"`, `"Xen"`, `"Amazon EC2"`, etc.).

use crate::{
    detect_vm_vendor_from_text, load_or_create_file_anchor, run_cmd_with_timeout,
    NativeHardwareAnchor,
};
use std::time::Duration;

const REG_TIMEOUT: Duration = Duration::from_millis(300);
const CIM_TIMEOUT: Duration = Duration::from_millis(1500);

pub fn collect() -> NativeHardwareAnchor {
    let reg_out = run_cmd(
        "reg",
        &[
            "query",
            r"HKLM\SOFTWARE\Microsoft\Cryptography",
            "/v",
            "MachineGuid",
        ],
        REG_TIMEOUT,
    );

    let cim_out = run_cmd(
        "powershell",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "$cs = Get-CimInstance -ClassName Win32_ComputerSystem; Get-CimInstance -ClassName Win32_ComputerSystemProduct | Select-Object -ExpandProperty UUID; Get-CimInstance -ClassName Win32_BIOS | Select-Object -ExpandProperty SerialNumber; Get-CimInstance -ClassName Win32_Processor | Select-Object -ExpandProperty Name | Select-Object -First 1; $cs.TotalPhysicalMemory; $cs.HypervisorPresent; $cs.Manufacturer; $cs.Model",
        ],
        CIM_TIMEOUT,
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

fn detect_windows_guest_vm(manufacturer: &str, model: &str, full_cim_text: &str, hypervisor_present: bool) -> (bool, String) {
    if let Some(vendor) = detect_vm_vendor_from_text(&format!("{} {} {}", manufacturer, model, full_cim_text)) {
        return (true, vendor);
    }

    let mfg_lower = manufacturer.trim().to_ascii_lowercase();
    let model_lower = model.trim().to_ascii_lowercase();

    // Microsoft Hyper-V / Azure guest VMs report Manufacturer="Microsoft Corporation" and Model="Virtual Machine"
    // (whereas bare-metal Surface devices report Model="Surface Laptop ...", "Surface Pro ...", etc.).
    if model_lower.contains("virtual machine")
        || model_lower.contains("hvm domu")
        || model_lower == "virtual"
        || (mfg_lower.contains("microsoft") && model_lower.contains("hyper-v"))
    {
        return (true, "hyperv".to_string());
    }

    // Do NOT flag bare-metal Windows 11 VBS / Credential Guard / WSL2 hosts where HypervisorPresent=True
    // unless Manufacturer itself explicitly denotes a generic virtual platform.
    if hypervisor_present
        && (mfg_lower == "innotek gmbh"
            || mfg_lower == "red hat"
            || mfg_lower.contains("virtual"))
    {
        return (true, "hypervisor".to_string());
    }

    (false, String::new())
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
    let model = lines.next().unwrap_or("");

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

    let hypervisor_present = hypervisor_str.eq_ignore_ascii_case("true");
    let (is_vm, vm_vendor) =
        detect_windows_guest_vm(manufacturer, model, cim_out, hypervisor_present);

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
    let existing = run_cmd("reg", &["query", reg_key, "/v", "DeviceAnchor"], REG_TIMEOUT);
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
        REG_TIMEOUT,
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

fn run_cmd(program: &str, args: &[&str], timeout: Duration) -> String {
    run_cmd_with_timeout(program, args, timeout)
        .map(|(_, out)| out)
        .unwrap_or_default()
}
