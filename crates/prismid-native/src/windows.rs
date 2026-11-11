//! Windows native hardware anchor implementation (`MachineGuid`, SMBIOS UUID, BIOS SerialNumber,
//! HKCU Registry / user-profile persistent anchor, and guest VM detection).
//!
//! Primary collection uses direct zero-subprocess Win32 FFI (`advapi32` Registry APIs with
//! `KEY_WOW64_64KEY`, `kernel32` `GetSystemFirmwareTable('RSMB')` raw SMBIOS parser, and
//! `GlobalMemoryStatusEx`) completing in **< 1ms** without spawning `powershell.exe` or `reg.exe`
//! (eliminating EDR false alarms and GUI console-window flashes). Hidden (`CREATE_NO_WINDOW`)
//! subprocesses are retained solely as a defensive fallback if Win32 APIs are blocked.
//!
//! Note on Windows 11 VBS / Credential Guard / WSL2:
//! `HypervisorPresent` is `True` on bare-metal Windows 11 hosts whenever Virtualization-Based
//! Security (VBS), Memory Integrity (HVCI), or WSL2/Hyper-V platform is enabled. Therefore
//! `HypervisorPresent` alone is NEVER treated as sufficient proof of a guest VM; it must be
//! corroborated by guest hardware/BIOS/model signatures (e.g. `"Virtual Machine"`, `"VMware"`,
//! `"VirtualBox"`, `"QEMU"`, `"KVM"`, `"Parallels"`, `"Xen"`, `"Amazon EC2"`, etc.).

#![cfg_attr(not(target_os = "windows"), allow(dead_code))]

use crate::{
    detect_vm_vendor_from_text, load_or_create_file_anchor, run_cmd_with_timeout,
    NativeHardwareAnchor,
};
use std::time::Duration;

const REG_TIMEOUT: Duration = Duration::from_millis(300);
const CIM_TIMEOUT: Duration = Duration::from_millis(1500);

/// Parsed fields extracted from a raw Windows `'RSMB'` (`RawSMBIOSData`) firmware buffer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SmbiosInfo {
    pub manufacturer: String,
    pub model: String,
    pub serial_number: String,
    pub uuid: String,
}

pub fn collect() -> NativeHardwareAnchor {
    let cpu_cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);

    #[cfg(target_os = "windows")]
    {
        if let Some(mut native) = collect_win32_native(cpu_cores) {
            native.keychain_anchor = load_or_create_windows_anchor(&native.hw_uuid);
            return native;
        }
    }

    collect_subprocess_fallback(cpu_cores)
}

fn collect_subprocess_fallback(cpu_cores: usize) -> NativeHardwareAnchor {
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
            "-WindowStyle",
            "Hidden",
            "-Command",
            "$cs = Get-CimInstance -ClassName Win32_ComputerSystem; Get-CimInstance -ClassName Win32_ComputerSystemProduct | Select-Object -ExpandProperty UUID; Get-CimInstance -ClassName Win32_BIOS | Select-Object -ExpandProperty SerialNumber; Get-CimInstance -ClassName Win32_Processor | Select-Object -ExpandProperty Name | Select-Object -First 1; $cs.TotalPhysicalMemory; $cs.HypervisorPresent; $cs.Manufacturer; $cs.Model",
        ],
        CIM_TIMEOUT,
    );

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

pub(crate) fn combine_serial_and_uuid(bios_serial: &str, smbios_uuid: &str) -> String {
    match (
        !is_oem_placeholder(bios_serial),
        !is_oem_placeholder(smbios_uuid),
    ) {
        (true, true) if !bios_serial.eq_ignore_ascii_case(smbios_uuid) => {
            format!("{}:{}", bios_serial, smbios_uuid)
        }
        (true, _) => bios_serial.to_string(),
        (false, true) => smbios_uuid.to_string(),
        (false, false) => String::new(),
    }
}

pub(crate) fn detect_windows_guest_vm(
    manufacturer: &str,
    model: &str,
    full_context_text: &str,
    hypervisor_present: bool,
) -> (bool, String) {
    if let Some(vendor) = detect_vm_vendor_from_text(&format!(
        "{} {} {}",
        manufacturer, model, full_context_text
    )) {
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

/// Parses a raw Windows `'RSMB'` (`RawSMBIOSData`) buffer per DMTF DSP0134 (SMBIOS 2.6+).
///
/// Layout of `RawSMBIOSData`:
/// - `[0]`: `Used20CallingMethod`
/// - `[1]`: `SMBIOSMajorVersion`
/// - `[2]`: `SMBIOSMinorVersion`
/// - `[3]`: `DmiRevision`
/// - `[4..8]`: `Length` (u32 little-endian)
/// - `[8..8+Length]`: Sequence of SMBIOS structures (`[type, len, handle_lo, handle_hi, ...]` + NUL-terminated string table).
pub(crate) fn parse_raw_smbios_table(raw: &[u8]) -> SmbiosInfo {
    let mut info = SmbiosInfo::default();
    if raw.len() < 8 {
        return info;
    }

    let declared_len = u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]) as usize;
    let table_end = 8usize.saturating_add(declared_len).min(raw.len());
    let data = &raw[8..table_end];

    let mut baseboard_serial = String::new();
    let mut cursor = 0usize;

    while cursor + 4 <= data.len() {
        let struct_type = data[cursor];
        let formatted_len = data[cursor + 1] as usize;
        if formatted_len < 4 || cursor + formatted_len > data.len() {
            break;
        }
        let formatted = &data[cursor..cursor + formatted_len];

        // Parse string-set following the formatted section (terminated by double-NUL `\0\0`).
        let mut strings: Vec<&str> = Vec::new();
        let mut str_pos = cursor + formatted_len;
        if str_pos + 1 < data.len() && data[str_pos] == 0 && data[str_pos + 1] == 0 {
            cursor = str_pos + 2;
        } else {
            while str_pos < data.len() {
                if data[str_pos] == 0 {
                    // Empty string terminates the string-set
                    str_pos += 1;
                    break;
                }
                let start = str_pos;
                while str_pos < data.len() && data[str_pos] != 0 {
                    str_pos += 1;
                }
                if let Ok(s) = std::str::from_utf8(&data[start..str_pos]) {
                    strings.push(s.trim());
                } else {
                    strings.push("");
                }
                if str_pos < data.len() && data[str_pos] == 0 {
                    str_pos += 1;
                }
            }
            cursor = str_pos;
        }

        let get_str = |idx_offset: usize| -> String {
            if idx_offset >= formatted.len() {
                return String::new();
            }
            let one_based = formatted[idx_offset] as usize;
            if one_based == 0 || one_based > strings.len() {
                String::new()
            } else {
                strings[one_based - 1].to_string()
            }
        };

        match struct_type {
            // Type 1: System Information
            1 => {
                let mfg = get_str(0x04);
                let product = get_str(0x05);
                let serial = get_str(0x07);
                if !mfg.is_empty() && info.manufacturer.is_empty() {
                    info.manufacturer = mfg;
                }
                if !product.is_empty() && info.model.is_empty() {
                    info.model = product;
                }
                if !is_oem_placeholder(&serial) && info.serial_number.is_empty() {
                    info.serial_number = serial;
                }
                if formatted.len() >= 0x18 && info.uuid.is_empty() {
                    if let Some(uuid_str) = format_smbios_uuid(&formatted[0x08..0x18]) {
                        info.uuid = uuid_str;
                    }
                }
            }
            // Type 2: Baseboard (Motherboard) Information — fallback serial number
            2 => {
                let serial = get_str(0x07);
                if !is_oem_placeholder(&serial) && baseboard_serial.is_empty() {
                    baseboard_serial = serial;
                }
            }
            // Type 127: End-of-Table
            127 => break,
            _ => {}
        }
    }

    if info.serial_number.is_empty() && !baseboard_serial.is_empty() {
        info.serial_number = baseboard_serial;
    }
    info
}

fn format_smbios_uuid(bytes: &[u8]) -> Option<String> {
    if bytes.len() != 16 {
        return None;
    }
    if bytes.iter().all(|&b| b == 0x00) || bytes.iter().all(|&b| b == 0xFF) {
        return None;
    }
    // SMBIOS 2.6+ mixed-endian UUID encoding: first 3 fields are little-endian, last 8 bytes big-endian.
    let d1 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let d2 = u16::from_le_bytes([bytes[4], bytes[5]]);
    let d3 = u16::from_le_bytes([bytes[6], bytes[7]]);
    Some(format!(
        "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        d1,
        d2,
        d3,
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    ))
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

    let serial_number = combine_serial_and_uuid(&bios_serial, &smbios_uuid);

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
    #[cfg(target_os = "windows")]
    {
        if let Some(existing) = win32_ffi::reg_read_hkcu_sz(r"Software\PrismID", "DeviceAnchor") {
            let trimmed = existing.trim();
            if trimmed.len() >= 32 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
                return trimmed.to_ascii_lowercase();
            }
        }
        let seed = if hw_uuid.is_empty() {
            "windows_default"
        } else {
            hw_uuid
        };
        let anchor = load_or_create_file_anchor(seed);
        let _ = win32_ffi::reg_write_hkcu_sz(r"Software\PrismID", "DeviceAnchor", &anchor);
        return anchor;
    }

    #[cfg(not(target_os = "windows"))]
    {
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

#[cfg(target_os = "windows")]
fn collect_win32_native(cpu_cores: usize) -> Option<NativeHardwareAnchor> {
    let mut hw_uuid = win32_ffi::reg_read_hklm_sz(
        r"SOFTWARE\Microsoft\Cryptography",
        "MachineGuid",
    )
    .unwrap_or_default();

    let cpu_brand = win32_ffi::reg_read_hklm_sz(
        r"HARDWARE\DESCRIPTION\System\CentralProcessor\0",
        "ProcessorNameString",
    )
    .unwrap_or_default();

    let smbios = win32_ffi::read_raw_smbios()
        .map(|buf| parse_raw_smbios_table(&buf))
        .unwrap_or_default();

    if hw_uuid.is_empty() && !is_oem_placeholder(&smbios.uuid) {
        hw_uuid = smbios.uuid.clone();
    }

    if hw_uuid.is_empty() && smbios.serial_number.is_empty() {
        return None;
    }

    let serial_number = combine_serial_and_uuid(&smbios.serial_number, &smbios.uuid);
    let memory_bytes = win32_ffi::total_physical_memory_bytes();
    let hypervisor_present = win32_ffi::is_hypervisor_present();
    let (is_vm, vm_vendor) = detect_windows_guest_vm(
        &smbios.manufacturer,
        &smbios.model,
        &cpu_brand,
        hypervisor_present,
    );

    Some(NativeHardwareAnchor {
        platform: "windows".to_string(),
        hw_uuid,
        serial_number,
        keychain_anchor: String::new(),
        cpu_brand,
        cpu_cores,
        memory_bytes,
        is_vm,
        vm_vendor,
    })
}

#[cfg(target_os = "windows")]
mod win32_ffi {
    use core::ffi::c_void;

    type HKEY = isize;
    const HKEY_CURRENT_USER: HKEY = -2147483647i32 as isize; // 0x80000001
    const HKEY_LOCAL_MACHINE: HKEY = -2147483646i32 as isize; // 0x80000002

    const KEY_QUERY_VALUE: u32 = 0x0001;
    const KEY_SET_VALUE: u32 = 0x0002;
    const KEY_WOW64_64KEY: u32 = 0x0100;
    const REG_SZ: u32 = 1;
    const REG_EXPAND_SZ: u32 = 2;
    const ERROR_SUCCESS: i32 = 0;
    const RSMB_PROVIDER_SIGNATURE: u32 = 0x5253_4D42; // 'RSMB'
    const PF_VIRT_FIRMWARE_ENABLED: u32 = 21;

    #[repr(C)]
    struct MemoryStatusEx {
        dw_length: u32,
        dw_memory_load: u32,
        ull_total_phys: u64,
        ull_avail_phys: u64,
        ull_total_page_file: u64,
        ull_avail_page_file: u64,
        ull_total_virtual: u64,
        ull_avail_virtual: u64,
        ull_avail_extended_virtual: u64,
    }

    #[link(name = "advapi32")]
    extern "system" {
        fn RegOpenKeyExW(
            h_key: HKEY,
            lp_sub_key: *const u16,
            ul_options: u32,
            sam_desired: u32,
            phk_result: *mut HKEY,
        ) -> i32;

        fn RegCreateKeyExW(
            h_key: HKEY,
            lp_sub_key: *const u16,
            reserved: u32,
            lp_class: *const u16,
            dw_options: u32,
            sam_desired: u32,
            lp_security_attributes: *const c_void,
            phk_result: *mut HKEY,
            lpdw_disposition: *mut u32,
        ) -> i32;

        fn RegQueryValueExW(
            h_key: HKEY,
            lp_value_name: *const u16,
            lp_reserved: *mut u32,
            lp_type: *mut u32,
            lp_data: *mut u8,
            lpcb_data: *mut u32,
        ) -> i32;

        fn RegSetValueExW(
            h_key: HKEY,
            lp_value_name: *const u16,
            reserved: u32,
            dw_type: u32,
            lp_data: *const u8,
            cb_data: u32,
        ) -> i32;

        fn RegCloseKey(h_key: HKEY) -> i32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetSystemFirmwareTable(
            firmware_table_provider_signature: u32,
            firmware_table_id: u32,
            p_firmware_table_buffer: *mut u8,
            buffer_size: u32,
        ) -> u32;

        fn GlobalMemoryStatusEx(lp_buffer: *mut MemoryStatusEx) -> i32;
        fn IsProcessorFeaturePresent(processor_feature: u32) -> i32;
    }

    fn to_wide_nul(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(core::iter::once(0)).collect()
    }

    fn reg_read_sz(root: HKEY, subkey: &str, value_name: &str, sam_extra: u32) -> Option<String> {
        let wide_subkey = to_wide_nul(subkey);
        let wide_val = to_wide_nul(value_name);
        let mut hkey: HKEY = 0;

        let rc = unsafe {
            RegOpenKeyExW(
                root,
                wide_subkey.as_ptr(),
                0,
                KEY_QUERY_VALUE | sam_extra,
                &mut hkey,
            )
        };
        if rc != ERROR_SUCCESS || hkey == 0 {
            return None;
        }

        let mut val_type: u32 = 0;
        let mut byte_len: u32 = 0;
        let rc_size = unsafe {
            RegQueryValueExW(
                hkey,
                wide_val.as_ptr(),
                core::ptr::null_mut(),
                &mut val_type,
                core::ptr::null_mut(),
                &mut byte_len,
            )
        };
        if rc_size != ERROR_SUCCESS
            || (val_type != REG_SZ && val_type != REG_EXPAND_SZ)
            || byte_len == 0
            || byte_len > 16384
        {
            unsafe {
                let _ = RegCloseKey(hkey);
            }
            return None;
        }

        let u16_len = ((byte_len as usize) + 1) / 2;
        let mut buf = vec![0u16; u16_len];
        let mut actual_bytes = (u16_len * 2) as u32;
        let rc_read = unsafe {
            RegQueryValueExW(
                hkey,
                wide_val.as_ptr(),
                core::ptr::null_mut(),
                &mut val_type,
                buf.as_mut_ptr() as *mut u8,
                &mut actual_bytes,
            )
        };
        unsafe {
            let _ = RegCloseKey(hkey);
        }
        if rc_read != ERROR_SUCCESS {
            return None;
        }

        let used_u16 = (actual_bytes as usize) / 2;
        let slice = &buf[..used_u16.min(buf.len())];
        let end = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());
        let decoded = String::from_utf16_lossy(&slice[..end]).trim().to_string();
        if decoded.is_empty() {
            None
        } else {
            Some(decoded)
        }
    }

    pub(super) fn reg_read_hklm_sz(subkey: &str, value_name: &str) -> Option<String> {
        reg_read_sz(HKEY_LOCAL_MACHINE, subkey, value_name, KEY_WOW64_64KEY)
            .or_else(|| reg_read_sz(HKEY_LOCAL_MACHINE, subkey, value_name, 0))
    }

    pub(super) fn reg_read_hkcu_sz(subkey: &str, value_name: &str) -> Option<String> {
        reg_read_sz(HKEY_CURRENT_USER, subkey, value_name, 0)
    }

    pub(super) fn reg_write_hkcu_sz(subkey: &str, value_name: &str, value: &str) -> bool {
        let wide_subkey = to_wide_nul(subkey);
        let wide_val_name = to_wide_nul(value_name);
        let wide_data = to_wide_nul(value);
        let mut hkey: HKEY = 0;

        let rc = unsafe {
            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                wide_subkey.as_ptr(),
                0,
                core::ptr::null(),
                0,
                KEY_SET_VALUE | KEY_QUERY_VALUE,
                core::ptr::null(),
                &mut hkey,
                core::ptr::null_mut(),
            )
        };
        if rc != ERROR_SUCCESS || hkey == 0 {
            return false;
        }

        let rc_set = unsafe {
            RegSetValueExW(
                hkey,
                wide_val_name.as_ptr(),
                0,
                REG_SZ,
                wide_data.as_ptr() as *const u8,
                (wide_data.len() * 2) as u32,
            )
        };
        unsafe {
            let _ = RegCloseKey(hkey);
        }
        rc_set == ERROR_SUCCESS
    }

    pub(super) fn read_raw_smbios() -> Option<Vec<u8>> {
        let needed = unsafe {
            GetSystemFirmwareTable(RSMB_PROVIDER_SIGNATURE, 0, core::ptr::null_mut(), 0)
        };
        if needed < 8 || needed > 1_048_576 {
            return None;
        }
        let mut buf = vec![0u8; needed as usize];
        let written = unsafe {
            GetSystemFirmwareTable(RSMB_PROVIDER_SIGNATURE, 0, buf.as_mut_ptr(), needed)
        };
        if written == 0 || written > needed {
            return None;
        }
        buf.truncate(written as usize);
        Some(buf)
    }

    pub(super) fn total_physical_memory_bytes() -> u64 {
        let mut mem = MemoryStatusEx {
            dw_length: core::mem::size_of::<MemoryStatusEx>() as u32,
            dw_memory_load: 0,
            ull_total_phys: 0,
            ull_avail_phys: 0,
            ull_total_page_file: 0,
            ull_avail_page_file: 0,
            ull_total_virtual: 0,
            ull_avail_virtual: 0,
            ull_avail_extended_virtual: 0,
        };
        let ok = unsafe { GlobalMemoryStatusEx(&mut mem) };
        if ok != 0 {
            mem.ull_total_phys
        } else {
            0
        }
    }

    pub(super) fn is_hypervisor_present() -> bool {
        #[cfg(target_arch = "x86_64")]
        {
            let cpuid = unsafe { core::arch::x86_64::__cpuid(1) };
            if (cpuid.ecx & (1 << 31)) != 0 {
                return true;
            }
        }
        #[cfg(target_arch = "x86")]
        {
            let cpuid = unsafe { core::arch::x86::__cpuid(1) };
            if (cpuid.ecx & (1 << 31)) != 0 {
                return true;
            }
        }
        unsafe { IsProcessorFeaturePresent(PF_VIRT_FIRMWARE_ENABLED) != 0 }
    }
}
