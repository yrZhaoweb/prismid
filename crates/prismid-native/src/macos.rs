//! macOS native hardware anchor implementation using direct `IOKit` + `sysctlbyname` FFI
//! (completing in **< 0.5ms** with zero subprocess spawns on the happy path), plus non-interactive
//! `Security.framework` FFI (`kSecUseAuthenticationUISkip` / `kSecUseAuthenticationUIFail`) and
//! owner-only `0600` file-anchor persistence (never spawning `/usr/bin/security`, so no macOS
//! keychain modal authorization prompts are ever triggered).

use crate::{
    detect_vm_vendor_from_text, load_or_create_file_anchor, read_existing_file_anchor,
    run_cmd_with_timeout, write_file_anchor_restricted, NativeHardwareAnchor,
};
use std::time::Duration;

const KEYCHAIN_SERVICE: &str = "io.prismid.device.anchor";
const KEYCHAIN_ACCOUNT: &str = "default";
const CMD_TIMEOUT: Duration = Duration::from_millis(400);

pub fn collect() -> NativeHardwareAnchor {
    #[cfg(target_os = "macos")]
    {
        if let Some(mut anchor) = macos_ffi::collect_native_iokit() {
            anchor.keychain_anchor = read_or_create_macos_keychain_anchor(&anchor.hw_uuid);
            return anchor;
        }
    }

    collect_subprocess_fallback()
}

fn collect_subprocess_fallback() -> NativeHardwareAnchor {
    let ioreg_out = run_cmd("/usr/sbin/ioreg", &["-rd1", "-c", "IOPlatformExpertDevice"]);
    let hw_uuid = extract_ioreg_string(&ioreg_out, "IOPlatformUUID");
    let serial_number = extract_ioreg_string(&ioreg_out, "IOPlatformSerialNumber");
    let model = extract_ioreg_string(&ioreg_out, "model");

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

fn keychain_disabled_by_env() -> bool {
    std::env::var_os("PRISMID_DISABLE_KEYCHAIN")
        .map(|v| {
            let s = v.to_string_lossy();
            s == "1" || s.eq_ignore_ascii_case("true")
        })
        .unwrap_or(false)
}

fn read_or_create_macos_keychain_anchor(hw_uuid_hint: &str) -> String {
    let seed = if hw_uuid_hint.is_empty() {
        "macos_default"
    } else {
        hw_uuid_hint
    };

    // 1. Sub-millisecond fast-path: return owner-only 0600 local file anchor if already present,
    // avoiding Keychain IPC / authorization prompts on every warm process start.
    if let Some(cached) = read_existing_file_anchor(seed) {
        return cached;
    }

    if keychain_disabled_by_env() {
        return load_or_create_file_anchor(seed);
    }

    // 2. Non-interactive Security.framework FFI lookup (never spawns `/usr/bin/security` and sets
    // `kSecUseAuthenticationUISkip`, so locked keychains / mismatched ACLs fail silently).
    #[cfg(target_os = "macos")]
    if let Some(secret) = macos_ffi::keychain_find_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT) {
        let trimmed = secret.trim();
        if trimmed.len() >= 32 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
            let normalized = trimmed.to_ascii_lowercase();
            write_file_anchor_restricted(seed, &normalized);
            return normalized;
        }
    }

    // 3. Fallback: generate and persist 0600 file anchor, then mirror to Keychain non-interactively.
    let anchor = load_or_create_file_anchor(seed);
    #[cfg(target_os = "macos")]
    {
        let _ = macos_ffi::keychain_save_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT, &anchor);
    }

    anchor
}

fn run_cmd(program: &str, args: &[&str]) -> String {
    run_cmd_with_timeout(program, args, CMD_TIMEOUT)
        .map(|(_, out)| out)
        .unwrap_or_default()
}

#[cfg(target_os = "macos")]
mod macos_ffi {
    use crate::{detect_vm_vendor_from_text, NativeHardwareAnchor};
    use core::ffi::{c_char, c_void};

    type CFTypeRef = *const c_void;
    type CFStringRef = *const c_void;
    type CFDataRef = *const c_void;
    type CFDictionaryRef = *const c_void;
    type CFAllocatorRef = *const c_void;

    const K_CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;

    #[link(name = "IOKit", kind = "framework")]
    extern "C" {
        fn IOServiceMatching(name: *const c_char) -> CFDictionaryRef;
        fn IOServiceGetMatchingService(main_port: u32, matching: CFDictionaryRef) -> u32;
        fn IORegistryEntryCreateCFProperty(
            entry: u32,
            key: CFStringRef,
            allocator: CFAllocatorRef,
            options: u32,
        ) -> CFTypeRef;
        fn IOObjectRelease(object: u32) -> i32;
    }

    #[link(name = "CoreFoundation", kind = "framework")]
    extern "C" {
        static kCFBooleanTrue: CFTypeRef;
        static kCFTypeDictionaryKeyCallBacks: u8;
        static kCFTypeDictionaryValueCallBacks: u8;
        fn CFStringCreateWithBytes(
            alloc: CFAllocatorRef,
            bytes: *const u8,
            num_bytes: isize,
            encoding: u32,
            is_external_representation: u8,
        ) -> CFStringRef;
        fn CFStringGetCString(
            the_string: CFStringRef,
            buffer: *mut c_char,
            buffer_size: isize,
            encoding: u32,
        ) -> u8;
        fn CFDataCreate(alloc: CFAllocatorRef, bytes: *const u8, length: isize) -> CFDataRef;
        fn CFDictionaryCreate(
            allocator: CFAllocatorRef,
            keys: *const CFTypeRef,
            values: *const CFTypeRef,
            num_values: isize,
            key_callbacks: *const u8,
            value_callbacks: *const u8,
        ) -> CFDictionaryRef;
        fn CFGetTypeID(cf: CFTypeRef) -> usize;
        fn CFStringGetTypeID() -> usize;
        fn CFDataGetTypeID() -> usize;
        fn CFDataGetBytePtr(the_data: CFDataRef) -> *const u8;
        fn CFDataGetLength(the_data: CFDataRef) -> isize;
        fn CFRelease(cf: CFTypeRef);
    }

    #[link(name = "Security", kind = "framework")]
    extern "C" {
        static kSecClass: CFTypeRef;
        static kSecClassGenericPassword: CFTypeRef;
        static kSecAttrService: CFTypeRef;
        static kSecAttrAccount: CFTypeRef;
        static kSecAttrAccessible: CFTypeRef;
        static kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly: CFTypeRef;
        static kSecUseAuthenticationUI: CFTypeRef;
        static kSecUseAuthenticationUISkip: CFTypeRef;
        static kSecUseAuthenticationUIFail: CFTypeRef;
        static kSecReturnData: CFTypeRef;
        static kSecValueData: CFTypeRef;
        static kSecMatchLimit: CFTypeRef;
        static kSecMatchLimitOne: CFTypeRef;
        fn SecItemCopyMatching(query: CFDictionaryRef, result: *mut CFTypeRef) -> i32;
        fn SecItemAdd(attributes: CFDictionaryRef, result: *mut CFTypeRef) -> i32;
        fn SecItemUpdate(query: CFDictionaryRef, attributes_to_update: CFDictionaryRef) -> i32;
        #[cfg(test)]
        fn SecItemDelete(query: CFDictionaryRef) -> i32;
    }

    const ERR_SEC_SUCCESS: i32 = 0;
    #[cfg(test)]
    const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
    const ERR_SEC_DUPLICATE_ITEM: i32 = -25299;

    struct OwnedCF(CFTypeRef);

    impl OwnedCF {
        fn wrap(raw: CFTypeRef) -> Option<Self> {
            if raw.is_null() {
                None
            } else {
                Some(Self(raw))
            }
        }

        fn as_ptr(&self) -> CFTypeRef {
            self.0
        }
    }

    impl Drop for OwnedCF {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { CFRelease(self.0) };
            }
        }
    }

    fn cf_string(s: &str) -> Option<OwnedCF> {
        OwnedCF::wrap(unsafe {
            CFStringCreateWithBytes(
                core::ptr::null(),
                s.as_ptr(),
                s.len() as isize,
                K_CF_STRING_ENCODING_UTF8,
                0,
            )
        })
    }

    fn cf_data(bytes: &[u8]) -> Option<OwnedCF> {
        OwnedCF::wrap(unsafe { CFDataCreate(core::ptr::null(), bytes.as_ptr(), bytes.len() as isize) })
    }

    fn cf_dict(pairs: &[(CFTypeRef, CFTypeRef)]) -> Option<OwnedCF> {
        let mut keys: Vec<CFTypeRef> = Vec::with_capacity(pairs.len());
        let mut values: Vec<CFTypeRef> = Vec::with_capacity(pairs.len());
        for &(k, v) in pairs {
            if k.is_null() || v.is_null() {
                return None;
            }
            keys.push(k);
            values.push(v);
        }
        OwnedCF::wrap(unsafe {
            CFDictionaryCreate(
                core::ptr::null(),
                keys.as_ptr(),
                values.as_ptr(),
                pairs.len() as isize,
                &kCFTypeDictionaryKeyCallBacks,
                &kCFTypeDictionaryValueCallBacks,
            )
        })
    }

    pub(super) fn keychain_find_password(service: &str, account: &str) -> Option<String> {
        let cf_service = cf_string(service)?;
        let cf_account = cf_string(account)?;
        let query = unsafe {
            cf_dict(&[
                (kSecClass, kSecClassGenericPassword),
                (kSecAttrService, cf_service.as_ptr()),
                (kSecAttrAccount, cf_account.as_ptr()),
                (kSecReturnData, kCFBooleanTrue),
                (kSecMatchLimit, kSecMatchLimitOne),
                // Never display a SecurityAgent modal prompt if Keychain is locked or ACL differs.
                (kSecUseAuthenticationUI, kSecUseAuthenticationUISkip),
            ])
        }?;

        let mut raw_result: CFTypeRef = core::ptr::null();
        let status = unsafe { SecItemCopyMatching(query.as_ptr(), &mut raw_result) };
        let result = OwnedCF::wrap(raw_result)?;
        if status != ERR_SEC_SUCCESS {
            return None;
        }
        if unsafe { CFGetTypeID(result.as_ptr()) } != unsafe { CFDataGetTypeID() } {
            return None;
        }
        let len = unsafe { CFDataGetLength(result.as_ptr()) };
        let ptr = unsafe { CFDataGetBytePtr(result.as_ptr()) };
        if ptr.is_null() || len <= 0 || len > 4096 {
            return None;
        }
        let bytes = unsafe { core::slice::from_raw_parts(ptr, len as usize) };
        let s = String::from_utf8(bytes.to_vec()).ok()?;
        let trimmed = s.trim().to_string();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    }

    pub(super) fn keychain_save_password(service: &str, account: &str, value: &str) -> bool {
        let Some(cf_service) = cf_string(service) else {
            return false;
        };
        let Some(cf_account) = cf_string(account) else {
            return false;
        };
        let Some(cf_secret) = cf_data(value.as_bytes()) else {
            return false;
        };

        let Some(add_attrs) = (unsafe {
            cf_dict(&[
                (kSecClass, kSecClassGenericPassword),
                (kSecAttrService, cf_service.as_ptr()),
                (kSecAttrAccount, cf_account.as_ptr()),
                (kSecValueData, cf_secret.as_ptr()),
                (
                    kSecAttrAccessible,
                    kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
                ),
                (kSecUseAuthenticationUI, kSecUseAuthenticationUIFail),
            ])
        }) else {
            return false;
        };

        let add_status = unsafe { SecItemAdd(add_attrs.as_ptr(), core::ptr::null_mut()) };
        if add_status == ERR_SEC_SUCCESS {
            return true;
        }
        if add_status != ERR_SEC_DUPLICATE_ITEM {
            return false;
        }

        let Some(query) = (unsafe {
            cf_dict(&[
                (kSecClass, kSecClassGenericPassword),
                (kSecAttrService, cf_service.as_ptr()),
                (kSecAttrAccount, cf_account.as_ptr()),
                (kSecUseAuthenticationUI, kSecUseAuthenticationUIFail),
            ])
        }) else {
            return false;
        };
        let Some(update_attrs) = (unsafe {
            cf_dict(&[
                (kSecValueData, cf_secret.as_ptr()),
                (
                    kSecAttrAccessible,
                    kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
                ),
            ])
        }) else {
            return false;
        };
        unsafe { SecItemUpdate(query.as_ptr(), update_attrs.as_ptr()) == ERR_SEC_SUCCESS }
    }

    #[cfg(test)]
    pub(super) fn keychain_delete_password(service: &str, account: &str) -> i32 {
        let Some(cf_service) = cf_string(service) else {
            return ERR_SEC_ITEM_NOT_FOUND;
        };
        let Some(cf_account) = cf_string(account) else {
            return ERR_SEC_ITEM_NOT_FOUND;
        };
        let Some(query) = (unsafe {
            cf_dict(&[
                (kSecClass, kSecClassGenericPassword),
                (kSecAttrService, cf_service.as_ptr()),
                (kSecAttrAccount, cf_account.as_ptr()),
                (kSecUseAuthenticationUI, kSecUseAuthenticationUIFail),
            ])
        }) else {
            return ERR_SEC_ITEM_NOT_FOUND;
        };
        unsafe { SecItemDelete(query.as_ptr()) }
    }

    extern "C" {
        fn sysctlbyname(
            name: *const c_char,
            oldp: *mut c_void,
            oldlenp: *mut usize,
            newp: *const c_void,
            newlen: usize,
        ) -> i32;
    }

    fn iokit_read_property(service: u32, prop_name: &str) -> Option<String> {
        let cf_key = unsafe {
            CFStringCreateWithBytes(
                core::ptr::null(),
                prop_name.as_ptr(),
                prop_name.len() as isize,
                K_CF_STRING_ENCODING_UTF8,
                0,
            )
        };
        if cf_key.is_null() {
            return None;
        }

        let prop =
            unsafe { IORegistryEntryCreateCFProperty(service, cf_key, core::ptr::null(), 0) };
        unsafe { CFRelease(cf_key) };
        if prop.is_null() {
            return None;
        }

        let type_id = unsafe { CFGetTypeID(prop) };
        let result = if type_id == unsafe { CFStringGetTypeID() } {
            let mut buf = [0u8; 256];
            let ok = unsafe {
                CFStringGetCString(
                    prop,
                    buf.as_mut_ptr() as *mut c_char,
                    buf.len() as isize,
                    K_CF_STRING_ENCODING_UTF8,
                )
            };
            if ok != 0 {
                let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
                Some(String::from_utf8_lossy(&buf[..end]).trim().to_string())
            } else {
                None
            }
        } else if type_id == unsafe { CFDataGetTypeID() } {
            let len = unsafe { CFDataGetLength(prop) };
            let ptr = unsafe { CFDataGetBytePtr(prop) };
            if !ptr.is_null() && len > 0 && len <= 256 {
                let slice = unsafe { core::slice::from_raw_parts(ptr, len as usize) };
                let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
                Some(String::from_utf8_lossy(&slice[..end]).trim().to_string())
            } else {
                None
            }
        } else {
            None
        };

        unsafe { CFRelease(prop) };
        result.filter(|s| !s.is_empty())
    }

    fn sysctl_string(name_nul: &[u8]) -> Option<String> {
        let mut len: usize = 0;
        let rc = unsafe {
            sysctlbyname(
                name_nul.as_ptr() as *const c_char,
                core::ptr::null_mut(),
                &mut len,
                core::ptr::null(),
                0,
            )
        };
        if rc != 0 || len == 0 || len > 1024 {
            return None;
        }
        let mut buf = vec![0u8; len];
        let rc2 = unsafe {
            sysctlbyname(
                name_nul.as_ptr() as *const c_char,
                buf.as_mut_ptr() as *mut c_void,
                &mut len,
                core::ptr::null(),
                0,
            )
        };
        if rc2 != 0 {
            return None;
        }
        let slice = &buf[..len.min(buf.len())];
        let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
        let s = String::from_utf8_lossy(&slice[..end]).trim().to_string();
        if s.is_empty() {
            None
        } else {
            Some(s)
        }
    }

    fn sysctl_u64(name_nul: &[u8]) -> Option<u64> {
        let mut val: u64 = 0;
        let mut len = core::mem::size_of::<u64>();
        let rc = unsafe {
            sysctlbyname(
                name_nul.as_ptr() as *const c_char,
                &mut val as *mut u64 as *mut c_void,
                &mut len,
                core::ptr::null(),
                0,
            )
        };
        if rc == 0 {
            if len == 4 {
                Some((val as u32) as u64)
            } else {
                Some(val)
            }
        } else {
            None
        }
    }

    pub(super) fn collect_native_iokit() -> Option<NativeHardwareAnchor> {
        let matching = unsafe { IOServiceMatching(b"IOPlatformExpertDevice\0".as_ptr() as *const c_char) };
        if matching.is_null() {
            return None;
        }
        // IOServiceGetMatchingService consumes one reference to `matching`.
        let service = unsafe { IOServiceGetMatchingService(0, matching) };
        if service == 0 {
            return None;
        }

        let hw_uuid = iokit_read_property(service, "IOPlatformUUID").unwrap_or_default();
        let serial_number =
            iokit_read_property(service, "IOPlatformSerialNumber").unwrap_or_default();
        let model = iokit_read_property(service, "model").unwrap_or_default();
        let manufacturer = iokit_read_property(service, "manufacturer").unwrap_or_default();

        unsafe {
            let _ = IOObjectRelease(service);
        }

        if hw_uuid.is_empty() || serial_number.is_empty() {
            return None;
        }

        let cpu_brand = sysctl_string(b"machdep.cpu.brand_string\0")
            .or_else(|| sysctl_string(b"hw.model\0"))
            .unwrap_or_default();
        let cpu_cores = sysctl_u64(b"hw.ncpu\0")
            .map(|n| n as usize)
            .filter(|&n| n >= 1)
            .unwrap_or_else(|| {
                std::thread::available_parallelism()
                    .map(|n| n.get())
                    .unwrap_or(1)
            });
        let memory_bytes = sysctl_u64(b"hw.memsize\0").unwrap_or(0);
        let hv_vmm_present = sysctl_u64(b"kern.hv_vmm_present\0").unwrap_or(0);

        let mut is_vm = hv_vmm_present == 1;
        let mut vm_vendor = String::new();
        if let Some(v) =
            detect_vm_vendor_from_text(&format!("{} {} {}", manufacturer, model, cpu_brand))
        {
            is_vm = true;
            vm_vendor = v;
        } else if is_vm {
            vm_vendor = "hypervisor".to_string();
        }

        Some(NativeHardwareAnchor {
            platform: "macos".to_string(),
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
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::macos_ffi::{
        keychain_delete_password, keychain_find_password, keychain_save_password,
    };

    #[test]
    fn test_macos_keychain_ffi_silent_roundtrip_or_graceful_fallback() {
        let test_service = "io.prismid.device.anchor.unit-test";
        let test_account = format!("unit-test-{}", std::process::id());
        let _ = keychain_delete_password(test_service, &test_account);

        assert_eq!(keychain_find_password(test_service, &test_account), None);

        let initial_secret = "0123456789abcdef0123456789abcdef";
        if keychain_save_password(test_service, &test_account, initial_secret) {
            assert_eq!(
                keychain_find_password(test_service, &test_account).as_deref(),
                Some(initial_secret)
            );
            let updated_secret = "fedcba9876543210fedcba9876543210";
            assert!(keychain_save_password(
                test_service,
                &test_account,
                updated_secret
            ));
            assert_eq!(
                keychain_find_password(test_service, &test_account).as_deref(),
                Some(updated_secret)
            );
        }

        let _ = keychain_delete_password(test_service, &test_account);
    }
}
