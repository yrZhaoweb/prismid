//! `prismid-native` collects out-of-sandbox native motherboard UUIDs, hardware serial numbers,
//! OS keychain persistent anchors, and hypervisor virtual machine indicators across macOS,
//! Windows, and Linux.
//!
//! Results are cached in a process-wide [`std::sync::OnceLock`] so that the initial collection
//! completes in ~12ms (on macOS via direct `IOKit` + `sysctlbyname` + non-interactive
//! `Security.framework` FFI without spawning `/usr/bin/security`, with owner-only `0600`
//! file-anchor fallback when OS Keychain is unavailable or locked) and all subsequent invocations
//! execute in **0ms**.

use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

pub mod linux;
pub mod macos;
pub mod windows;

/// Out-of-sandbox native hardware anchor structure matching the PrismID wire protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NativeHardwareAnchor {
    /// Canonical OS platform name (`"macos"`, `"windows"`, or `"linux"`).
    pub platform: String,
    /// Motherboard / platform hardware UUID (`IOPlatformUUID`, `MachineGuid`, or `/etc/machine-id`).
    pub hw_uuid: String,
    /// Hardware serial number or SMBIOS product UUID.
    pub serial_number: String,
    /// Cross-uninstall persistent anchor stored in OS Keychain / Credential Manager (or `0600` file fallback).
    pub keychain_anchor: String,
    /// CPU brand string (e.g., `"Apple M1 Pro"`).
    pub cpu_brand: String,
    /// Logical CPU core count.
    pub cpu_cores: usize,
    /// Total physical RAM in bytes.
    pub memory_bytes: u64,
    /// True if a guest virtual machine environment is detected.
    pub is_vm: bool,
    /// Detected virtual machine vendor (e.g., `"vmware"`, `"parallels"`, `"virtualbox"`, `"qemu"`, `"hyperv"`), or empty.
    pub vm_vendor: String,
}

impl NativeHardwareAnchor {
    /// Serializes the anchor into a compact RFC 8259 JSON string without requiring external JSON crates.
    pub fn to_json_string(&self) -> String {
        format!(
            r#"{{"platform":"{}","hw_uuid":"{}","serial_number":"{}","keychain_anchor":"{}","cpu_brand":"{}","cpu_cores":{},"memory_bytes":{},"is_vm":{},"vm_vendor":"{}"}}"#,
            escape_json(&self.platform),
            escape_json(&self.hw_uuid),
            escape_json(&self.serial_number),
            escape_json(&self.keychain_anchor),
            escape_json(&self.cpu_brand),
            self.cpu_cores,
            self.memory_bytes,
            if self.is_vm { "true" } else { "false" },
            escape_json(&self.vm_vendor),
        )
    }
}

static ANCHOR_CACHE: OnceLock<NativeHardwareAnchor> = OnceLock::new();

/// Returns a reference to the process-cached [`NativeHardwareAnchor`].
///
/// The first call collects native hardware traits (~12ms on macOS); all subsequent calls
/// return immediately from [`OnceLock`] in 0ms.
pub fn collect_native_anchor() -> &'static NativeHardwareAnchor {
    ANCHOR_CACHE.get_or_init(collect_native_anchor_uncached)
}

/// Collects a fresh [`NativeHardwareAnchor`] for the current target OS without caching.
pub fn collect_native_anchor_uncached() -> NativeHardwareAnchor {
    #[cfg(target_os = "macos")]
    {
        macos::collect()
    }
    #[cfg(target_os = "windows")]
    {
        windows::collect()
    }
    #[cfg(target_os = "linux")]
    {
        linux::collect()
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        NativeHardwareAnchor {
            platform: std::env::consts::OS.to_string(),
            hw_uuid: String::new(),
            serial_number: String::new(),
            keychain_anchor: String::new(),
            cpu_brand: String::new(),
            cpu_cores: std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1),
            memory_bytes: 0,
            is_vm: false,
            vm_vendor: String::new(),
        }
    }
}

pub(crate) fn detect_vm_vendor_from_text(text: &str) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    for (needle, label) in [
        ("vmware", "vmware"),
        ("virtualbox", "virtualbox"),
        ("vbox", "virtualbox"),
        ("parallels", "parallels"),
        ("qemu", "qemu"),
        ("kvm", "kvm"),
        ("virtio", "virtio"),
        ("xen", "xen"),
        ("bochs", "bochs"),
        ("bhyve", "bhyve"),
        ("amazon ec2", "aws_ec2"),
        ("google compute engine", "gcp_gce"),
        ("openstack", "openstack"),
        ("nutanix", "nutanix"),
        ("proxmox", "proxmox"),
        ("virtualmac", "apple_virtualization"),
        ("apple virtualization", "apple_virtualization"),
    ] {
        if lower.contains(needle) {
            return Some(label.to_string());
        }
    }
    None
}

/// Executes an external command with a hard wall-clock timeout so locked keychains,
/// GUI authorization prompts, or hung WMI providers never stall the host application.
pub(crate) fn run_cmd_with_timeout(
    program: &str,
    args: &[&str],
    timeout: Duration,
) -> Option<(bool, String)> {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }

    let mut child = cmd.spawn().ok()?;

    let mut stdout = child.stdout.take()?;
    let reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout.read_to_end(&mut buf);
        String::from_utf8_lossy(&buf).into_owned()
    });

    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let out = reader.join().unwrap_or_default();
                return Some((status.success(), out));
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                std::thread::sleep(Duration::from_millis(2));
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}

fn sanitize_anchor_key(service_key: &str) -> String {
    let cleaned: String = service_key
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .take(64)
        .collect();
    if cleaned.is_empty() {
        "default".to_string()
    } else {
        cleaned
    }
}

fn anchor_file_path(service_key: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    let base_dir = std::env::var_os("PRISMID_ANCHOR_DIR")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .or_else(|| std::env::var_os("USERPROFILE"))
                .map(|p| std::path::PathBuf::from(p).join(".config").join("prismid"))
        })
        .unwrap_or_else(|| std::env::temp_dir().join("prismid"));

    let file_path = base_dir.join(format!(".anchor_{}", sanitize_anchor_key(service_key)));
    (base_dir, file_path)
}

pub(crate) fn read_existing_file_anchor(service_key: &str) -> Option<String> {
    let (_, file_path) = anchor_file_path(service_key);
    read_existing_file_anchor_at(&file_path)
}

fn read_existing_file_anchor_at(file_path: &std::path::Path) -> Option<String> {
    let existing = std::fs::read_to_string(file_path).ok()?;
    let trimmed = existing.trim();
    if trimmed.len() >= 32 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(file_path, std::fs::Permissions::from_mode(0o600));
        }
        Some(trimmed.to_ascii_lowercase())
    } else {
        None
    }
}

pub(crate) fn write_file_anchor_restricted(service_key: &str, value: &str) {
    let (dir, file_path) = anchor_file_path(service_key);
    write_file_anchor_restricted_at(&dir, &file_path, value);
}

fn write_file_anchor_restricted_at(
    dir: &std::path::Path,
    file_path: &std::path::Path,
    value: &str,
) {
    let _ = std::fs::create_dir_all(dir);
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(file_path)
        {
            let _ = f.write_all(value.as_bytes());
            let _ = std::fs::set_permissions(file_path, std::fs::Permissions::from_mode(0o600));
        }
    }
    #[cfg(not(unix))]
    {
        let _ = std::fs::write(file_path, value);
    }
}

pub(crate) fn load_or_create_file_anchor(service_key: &str) -> String {
    let (dir, file_path) = anchor_file_path(service_key);
    load_or_create_file_anchor_in_dir(&dir, &file_path, service_key)
}

fn load_or_create_file_anchor_in_dir(
    dir: &std::path::Path,
    file_path: &std::path::Path,
    service_key: &str,
) -> String {
    if let Some(existing) = read_existing_file_anchor_at(file_path) {
        return existing;
    }
    let generated = generate_deterministic_or_random_hex32(service_key);
    write_file_anchor_restricted_at(dir, file_path, &generated);
    generated
}

#[cfg(target_os = "windows")]
#[link(name = "bcrypt")]
extern "system" {
    fn BCryptGenRandom(
        h_algorithm: *mut core::ffi::c_void,
        pb_buffer: *mut u8,
        cb_buffer: u32,
        dw_flags: u32,
    ) -> i32;
}

pub(crate) fn generate_deterministic_or_random_hex32(seed_hint: &str) -> String {
    let mut buf = [0u8; 16];
    #[cfg(unix)]
    {
        if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
            if f.read_exact(&mut buf).is_ok() {
                return bytes_to_hex(&buf);
            }
        }
    }
    #[cfg(target_os = "windows")]
    {
        // BCRYPT_USE_SYSTEM_PREFERRED_RNG = 0x00000002, STATUS_SUCCESS = 0
        let status = unsafe {
            BCryptGenRandom(
                core::ptr::null_mut(),
                buf.as_mut_ptr(),
                buf.len() as u32,
                0x00000002,
            )
        };
        if status == 0 && buf.iter().any(|&b| b != 0) {
            return bytes_to_hex(&buf);
        }
    }
    // Emergency fallback only if OS CSPRNG is unavailable
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id() as u128;
    let mut h1: u64 = 0xcbf29ce484222325;
    let mut h2: u64 = 0x84222325cbf29ce4;
    for b in seed_hint.as_bytes() {
        h1 ^= *b as u64;
        h1 = h1.wrapping_mul(0x100000001b3);
    }
    for b in (nanos ^ (pid << 64)).to_le_bytes() {
        h2 ^= b as u64;
        h2 = h2.wrapping_mul(0x100000001b3);
    }
    buf[..8].copy_from_slice(&h1.to_le_bytes());
    buf[8..].copy_from_slice(&h2.to_le_bytes());
    bytes_to_hex(&buf)
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

pub(crate) fn escape_json(s: &str) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn test_collect_native_anchor_and_oncelock_cache() {
        let t0 = Instant::now();
        let first = collect_native_anchor();
        let first_elapsed = t0.elapsed();

        let t1 = Instant::now();
        let second = collect_native_anchor();
        let second_elapsed = t1.elapsed();

        assert_eq!(first, second);
        assert!(!first.platform.is_empty());
        assert!(first.cpu_cores >= 1);
        assert!(!first.keychain_anchor.is_empty());

        #[cfg(target_os = "macos")]
        {
            assert_eq!(first.platform, "macos");
            assert!(
                !first.hw_uuid.is_empty(),
                "expected non-empty IOPlatformUUID on macOS"
            );
            assert!(
                !first.serial_number.is_empty(),
                "expected non-empty IOPlatformSerialNumber on macOS"
            );
            assert!(
                first_elapsed.as_millis() < 500,
                "initial macOS collection took {:?} (must stay bounded)",
                first_elapsed
            );
        }

        assert!(
            second_elapsed.as_micros() < 500,
            "OnceLock cached call should be ~0ms, took {:?}",
            second_elapsed
        );

        let json_str = first.to_json_string();
        assert!(json_str.contains(&first.hw_uuid));
    }

    #[test]
    fn test_windows_parser_vbs_bare_metal_vs_guest_vms() {
        let reg_out = r#"
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography
    MachineGuid    REG_SZ    d1b2c3d4-e5f6-4789-abcd-112233445566
"#;
        // 1. Bare-metal desktop without hypervisor
        let cim_out = "4C4C4544-0059-3410-8053-B8C04F4A3132\nSN-BIOS-998877\nAMD Ryzen 9 7950X\n34359738368\nFalse\nASUS\nROG Crosshair X670E\n";
        let parsed = windows::parse_windows_cim_output(reg_out, cim_out, 16);
        assert_eq!(parsed.platform, "windows");
        assert_eq!(parsed.hw_uuid, "d1b2c3d4-e5f6-4789-abcd-112233445566");
        assert_eq!(
            parsed.serial_number,
            "SN-BIOS-998877:4C4C4544-0059-3410-8053-B8C04F4A3132"
        );
        assert_eq!(parsed.cpu_brand, "AMD Ryzen 9 7950X");
        assert_eq!(parsed.memory_bytes, 34359738368);
        assert!(!parsed.is_vm);
        assert_eq!(parsed.vm_vendor, "");

        // 2. Windows 11 Enterprise bare-metal laptop with VBS / Credential Guard / WSL2 enabled!
        // HypervisorPresent is True, Manufacturer is Dell or Microsoft Surface — MUST NOT be flagged as VM!
        let cim_win11_vbs_dell = "4C4C4544-0059-3410-8053-B8C04F4A3132\nDELL-SVC-7711\n13th Gen Intel Core i7-1370P\n34359738368\nTrue\nDell Inc.\nLatitude 7440\n";
        let parsed_dell_vbs = windows::parse_windows_cim_output(reg_out, cim_win11_vbs_dell, 16);
        assert!(
            !parsed_dell_vbs.is_vm,
            "Windows 11 VBS/WSL2 on Dell bare-metal must not be flagged as VM"
        );
        assert_eq!(parsed_dell_vbs.vm_vendor, "");

        let cim_surface_vbs = "99887766-5544-3322-1100-AABBCCDDEEFF\nSURF-001122\nSnapdragon X Elite\n17179869184\nTrue\nMicrosoft Corporation\nSurface Laptop 7th Edition\n";
        let parsed_surface = windows::parse_windows_cim_output(reg_out, cim_surface_vbs, 12);
        assert!(
            !parsed_surface.is_vm,
            "Microsoft Surface bare-metal with VBS must not be flagged as VM"
        );

        // 3. Actual Microsoft Hyper-V Guest VM (Manufacturer=Microsoft Corporation, Model=Virtual Machine)
        let cim_hyperv_guest = "11112222-3333-4444-5555-666677778888\n7788-9900-1122\nAMD EPYC 7763\n8589934592\nTrue\nMicrosoft Corporation\nVirtual Machine\n";
        let parsed_hyperv = windows::parse_windows_cim_output(reg_out, cim_hyperv_guest, 4);
        assert!(parsed_hyperv.is_vm);
        assert_eq!(parsed_hyperv.vm_vendor, "hyperv");

        // 4. OEM placeholder BIOS serial + VMware guest (6-line legacy format compatibility)
        let cim_oem = "4C4C4544-0059-3410-8053-B8C04F4A3132\nTo be filled by O.E.M.\nIntel Core i9\n17179869184\nTrue\nVMware, Inc.\n";
        let parsed_vm = windows::parse_windows_cim_output(reg_out, cim_oem, 8);
        assert_eq!(
            parsed_vm.serial_number,
            "4C4C4544-0059-3410-8053-B8C04F4A3132"
        );
        assert!(parsed_vm.is_vm);
        assert_eq!(parsed_vm.vm_vendor, "vmware");
    }

    #[test]
    fn test_escape_json_rfc8259_control_chars() {
        let anchor = NativeHardwareAnchor {
            platform: "linux".to_string(),
            hw_uuid: "abc\x00\x07\x08\x0c\x1f\"\\xyz".to_string(),
            serial_number: "sn\n\r\t1".to_string(),
            keychain_anchor: "0123456789abcdef0123456789abcdef".to_string(),
            cpu_brand: "Test CPU".to_string(),
            cpu_cores: 4,
            memory_bytes: 1024,
            is_vm: false,
            vm_vendor: String::new(),
        };
        let encoded = anchor.to_json_string();
        assert!(encoded.contains(r#"abc\u0000\u0007\b\f\u001f\"\\xyz"#));
        assert!(encoded.contains(r#"sn\n\r\t1"#));
    }

    #[test]
    fn test_command_timeout_and_file_anchor_permissions() {
        // Verify hung subprocess is killed cleanly within bounded timeout
        #[cfg(unix)]
        {
            let t0 = Instant::now();
            let res = run_cmd_with_timeout("/bin/sleep", &["5"], Duration::from_millis(40));
            assert!(res.is_none(), "expected sleep subprocess to time out");
            assert!(
                t0.elapsed() < Duration::from_millis(500),
                "timeout should terminate promptly, took {:?}",
                t0.elapsed()
            );
        }

        // Verify file anchor permissions are owner-only (0600) on Unix
        let tmp_dir = std::env::temp_dir().join(format!("prismid_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp_dir);
        let anchor_file = tmp_dir.join(".anchor_perm_check_test");
        let generated =
            load_or_create_file_anchor_in_dir(&tmp_dir, &anchor_file, "perm_check_test");
        assert_eq!(generated.len(), 32);
        let reloaded = load_or_create_file_anchor_in_dir(&tmp_dir, &anchor_file, "perm_check_test");
        assert_eq!(generated, reloaded);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let file_meta = std::fs::metadata(&anchor_file).unwrap();
            assert_eq!(file_meta.permissions().mode() & 0o777, 0o600);
            let dir_meta = std::fs::metadata(&tmp_dir).unwrap();
            assert_eq!(dir_meta.permissions().mode() & 0o777, 0o700);
        }
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_windows_raw_smbios_parser_and_mixed_endian_uuid() {
        // Construct a synthetic Windows 'RSMB' RawSMBIOSData buffer:
        // - Type 0 (BIOS Info, empty string set \0\0)
        // - Type 1 (System Info: Manufacturer="Dell Inc.", Product="XPS 15 9530",
        //           Serial="To be filled by O.E.M." -> falls back to Baseboard Type 2,
        //           SMBIOS 2.6+ mixed-endian UUID = 00112233-4455-6677-8899-AABBCCDDEEFF)
        // - Type 2 (Baseboard Info: Serial="MB-DELL-CN778899")
        // - Type 127 (End-of-Table)
        let mut structures = Vec::new();

        // Type 0: header [0, 4, 0x00, 0x00] + double NUL
        structures.extend_from_slice(&[0, 4, 0x00, 0x00, 0x00, 0x00]);

        // Type 1: length 0x19 (25 bytes)
        let mut type1 = vec![0u8; 0x19];
        type1[0] = 1; // System Information
        type1[1] = 0x19;
        type1[0x04] = 1; // string 1: Manufacturer
        type1[0x05] = 2; // string 2: Product Name
        type1[0x07] = 3; // string 3: Serial Number (OEM placeholder)
        // UUID bytes [0x08..0x18]: 00112233-4455-6677-8899-AABBCCDDEEFF
        // LE d1=0x00112233 -> [0x33, 0x22, 0x11, 0x00]
        // LE d2=0x4455     -> [0x55, 0x44]
        // LE d3=0x6677     -> [0x77, 0x66]
        // BE [8..16]       -> [0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]
        type1[0x08..0x18].copy_from_slice(&[
            0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF,
        ]);
        structures.extend_from_slice(&type1);
        structures.extend_from_slice(b"Dell Inc.\0XPS 15 9530\0To be filled by O.E.M.\0\0");

        // Type 2: Baseboard Info (length 8, serial at 0x07 = string 1)
        let mut type2 = vec![0u8; 8];
        type2[0] = 2;
        type2[1] = 8;
        type2[0x07] = 1;
        structures.extend_from_slice(&type2);
        structures.extend_from_slice(b"MB-DELL-CN778899\0\0");

        // Type 127: End of table
        structures.extend_from_slice(&[127, 4, 0xFF, 0xFF, 0x00, 0x00]);

        let mut raw = Vec::new();
        raw.extend_from_slice(&[0, 3, 4, 0]); // SMBIOS 3.4
        raw.extend_from_slice(&(structures.len() as u32).to_le_bytes());
        raw.extend_from_slice(&structures);

        let info = windows::parse_raw_smbios_table(&raw);
        assert_eq!(info.manufacturer, "Dell Inc.");
        assert_eq!(info.model, "XPS 15 9530");
        assert_eq!(info.serial_number, "MB-DELL-CN778899");
        assert_eq!(info.uuid, "00112233-4455-6677-8899-AABBCCDDEEFF");
        assert_eq!(
            windows::combine_serial_and_uuid(&info.serial_number, &info.uuid),
            "MB-DELL-CN778899:00112233-4455-6677-8899-AABBCCDDEEFF"
        );

        // Verify truncated / empty / all-FF UUID buffers never panic
        assert_eq!(
            windows::parse_raw_smbios_table(&[]),
            windows::SmbiosInfo::default()
        );
        assert_eq!(
            windows::parse_raw_smbios_table(&[0, 3, 0, 0, 255, 0, 0, 0, 1, 20]),
            windows::SmbiosInfo::default()
        );
    }
}
