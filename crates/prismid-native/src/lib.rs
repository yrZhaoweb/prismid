//! `prismid-native` collects out-of-sandbox native motherboard UUIDs, hardware serial numbers,
//! OS keychain persistent anchors, and hypervisor virtual machine indicators across macOS,
//! Windows, and Linux.
//!
//! Results are cached in a process-wide [`std::sync::OnceLock`] so that the initial collection
//! completes in ~12ms (on macOS via `ioreg` + `sysctl`, avoiding slow `diskutil` calls) and
//! all subsequent invocations execute in **0ms**.

use std::sync::OnceLock;

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
    /// Cross-uninstall persistent anchor stored in OS Keychain / Credential Manager.
    pub keychain_anchor: String,
    /// CPU brand string (e.g., `"Apple M1 Pro"`).
    pub cpu_brand: String,
    /// Logical CPU core count.
    pub cpu_cores: usize,
    /// Total physical RAM in bytes.
    pub memory_bytes: u64,
    /// True if a hypervisor or virtual machine environment is detected.
    pub is_vm: bool,
    /// Detected virtual machine vendor (e.g., `"vmware"`, `"parallels"`, `"virtualbox"`, `"qemu"`), or empty.
    pub vm_vendor: String,
}

impl NativeHardwareAnchor {
    /// Serializes the anchor into a compact JSON string without requiring external JSON crates.
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
        ("virtualmac", "apple_virtualization"),
        ("apple virtualization", "apple_virtualization"),
    ] {
        if lower.contains(needle) {
            return Some(label.to_string());
        }
    }
    None
}

pub(crate) fn load_or_create_file_anchor(service_key: &str) -> String {
    let base_dir = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(std::path::PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);

    let dir = base_dir.join(".config").join("prismid");
    let _ = std::fs::create_dir_all(&dir);
    let file_path = dir.join(format!(".anchor_{}", service_key));

    if let Ok(existing) = std::fs::read_to_string(&file_path) {
        let trimmed = existing.trim();
        if trimmed.len() >= 32 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
            return trimmed.to_ascii_lowercase();
        }
    }

    let generated = generate_deterministic_or_random_hex32(service_key);
    let _ = std::fs::write(&file_path, &generated);
    generated
}

pub(crate) fn generate_deterministic_or_random_hex32(seed_hint: &str) -> String {
    let mut buf = [0u8; 16];
    #[cfg(unix)]
    {
        use std::io::Read;
        if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
            if f.read_exact(&mut buf).is_ok() {
                return bytes_to_hex(&buf);
            }
        }
    }
    // Fallback mixing timestamp, process ID, and seed_hint via FNV-1a 64-bit
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

fn escape_json(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {}
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
                first_elapsed.as_millis() < 200,
                "initial macOS collection took {:?} (must avoid slow diskutil)",
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
    fn test_windows_parser_and_bios_serial_preservation() {
        let reg_out = r#"
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography
    MachineGuid    REG_SZ    d1b2c3d4-e5f6-4789-abcd-112233445566
"#;
        let cim_out = "4C4C4544-0059-3410-8053-B8C04F4A3132\nSN-BIOS-998877\nAMD Ryzen 9 7950X\n34359738368\nFalse\nASUS\n";
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

        // OEM placeholder BIOS serial falls back cleanly to SMBIOS UUID
        let cim_oem = "4C4C4544-0059-3410-8053-B8C04F4A3132\nTo be filled by O.E.M.\nIntel Core i9\n17179869184\nTrue\nVMware, Inc.\n";
        let parsed_vm = windows::parse_windows_cim_output(reg_out, cim_oem, 8);
        assert_eq!(
            parsed_vm.serial_number,
            "4C4C4544-0059-3410-8053-B8C04F4A3132"
        );
        assert!(parsed_vm.is_vm);
        assert_eq!(parsed_vm.vm_vendor, "vmware");
    }
}
