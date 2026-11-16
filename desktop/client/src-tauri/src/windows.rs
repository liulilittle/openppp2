use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProxySettings {
    pub flags: u32,
    pub server: String,
    pub bypass: String,
    pub pac: String,
}

#[derive(Serialize, Deserialize)]
struct ProxyBackup {
    #[serde(default = "proxy_backup_version")]
    version: u32,
    #[serde(default = "proxy_backup_owner")]
    owner: String,
    original: ProxySettings,
    applied: ProxySettings,
}

const PROXY_BACKUP_SCHEMA: u32 = 1;

fn proxy_backup_version() -> u32 {
    PROXY_BACKUP_SCHEMA
}

fn proxy_backup_owner() -> String {
    "openppp2-desktop".into()
}

pub fn apply_proxy(path: &Path, address: &str) -> Result<(), String> {
    apply_proxy_with(path, address, query_proxy, set_proxy)
}

fn apply_proxy_with(
    path: &Path,
    address: &str,
    mut query: impl FnMut() -> Result<ProxySettings, String>,
    mut set: impl FnMut(&ProxySettings) -> Result<(), String>,
) -> Result<(), String> {
    let endpoint: std::net::SocketAddr =
        address.parse().map_err(|_| "Invalid HTTP proxy address")?;
    if !endpoint.ip().is_loopback() || endpoint.port() == 0 {
        return Err("System proxy requires a loopback HTTP listener".into());
    }
    if path.exists() {
        restore_proxy_with(path, false, &mut query, &mut set)?;
    }
    let original = query()?;
    let applied = ProxySettings {
        flags: 3,
        server: format!("http={address};https={address}"),
        bypass: "<local>".into(),
        pac: String::new(),
    };
    crate::storage::write(
        path,
        &serde_json::to_vec(&ProxyBackup {
            version: PROXY_BACKUP_SCHEMA,
            owner: proxy_backup_owner(),
            original,
            applied: applied.clone(),
        })
        .map_err(|e| e.to_string())?,
    )?;
    set(&applied)?;
    if query()? != applied {
        return Err("System proxy apply was not confirmed; recovery backup retained".into());
    }
    Ok(())
}

pub fn restore_proxy(path: &Path, force: bool) -> Result<(), String> {
    restore_proxy_with(path, force, query_proxy, set_proxy)
}

fn restore_proxy_with(
    path: &Path,
    force: bool,
    mut query: impl FnMut() -> Result<ProxySettings, String>,
    mut set: impl FnMut(&ProxySettings) -> Result<(), String>,
) -> Result<(), String> {
    if !path.exists() {
        return Ok(());
    }
    let backup: ProxyBackup =
        serde_json::from_slice(&std::fs::read(path).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    if backup.version != PROXY_BACKUP_SCHEMA || backup.owner != proxy_backup_owner() {
        return Err("Unsupported or foreign system proxy recovery record".into());
    }
    let current = query()?;
    if current == backup.original {
        return std::fs::remove_file(path).map_err(|e| e.to_string());
    }
    if !force && current != backup.applied {
        return Err("System proxy changed outside OpenPPP2; recovery backup retained".into());
    }
    set(&backup.original)?;
    if query()? != backup.original {
        return Err("System proxy restore was not confirmed; recovery backup retained".into());
    }
    std::fs::remove_file(path).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    #[test]
    fn proxy_recovery_preserves_external_changes_and_pac() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("proxy.json");
        let original = ProxySettings {
            flags: 5,
            server: "original:1234".into(),
            bypass: "localhost".into(),
            pac: "https://example.test/proxy.pac".into(),
        };
        let current = RefCell::new(original.clone());
        let query = || Ok(current.borrow().clone());
        let set = |value: &ProxySettings| {
            *current.borrow_mut() = value.clone();
            Ok(())
        };
        apply_proxy_with(&path, "127.0.0.1:8080", query, set).unwrap();
        assert!(path.exists());
        current.borrow_mut().server = "other:2080".into();
        assert!(restore_proxy_with(&path, false, query, set).is_err());
        assert_eq!(current.borrow().server, "other:2080");
        assert!(path.exists());
        restore_proxy_with(&path, true, query, set).unwrap();
        assert_eq!(*current.borrow(), original);
        assert!(!path.exists());
        apply_proxy_with(&path, "127.0.0.1:8080", query, set).unwrap();
        restore_proxy_with(&path, false, query, set).unwrap();
        assert_eq!(*current.borrow(), original);
        assert!(apply_proxy_with(&path, "0.0.0.0:8080", query, set).is_err());
    }

    #[test]
    fn proxy_apply_requires_readback_and_keeps_snapshot_on_mismatch() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("proxy.json");
        let original = ProxySettings {
            flags: 1,
            server: "direct:80".into(),
            bypass: "<local>".into(),
            pac: "https://example.test/original.pac".into(),
        };
        let current = RefCell::new(original.clone());
        let query = || Ok(current.borrow().clone());
        let set = |_value: &ProxySettings| Ok(());

        let result = apply_proxy_with(&path, "127.0.0.1:8080", query, set);
        assert!(result.is_err());
        assert!(path.exists());
    }

    #[test]
    fn proxy_restore_keeps_snapshot_when_readback_fails() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("proxy.json");
        let original = ProxySettings {
            flags: 0,
            server: String::new(),
            bypass: String::new(),
            pac: String::new(),
        };
        let current = RefCell::new(original.clone());
        let query = || Ok(current.borrow().clone());
        let set = |value: &ProxySettings| {
            *current.borrow_mut() = value.clone();
            Ok(())
        };
        apply_proxy_with(&path, "127.0.0.1:8080", query, set).unwrap();
        *current.borrow_mut() = ProxySettings {
            flags: 3,
            server: "http=127.0.0.1:8080;https=127.0.0.1:8080".into(),
            bypass: "<local>".into(),
            pac: String::new(),
        };
        let set_without_restore = |_value: &ProxySettings| Ok(());
        let result = restore_proxy_with(&path, false, query, set_without_restore);
        assert!(result.is_err());
        assert!(path.exists());
    }
    #[cfg(windows)]
    #[test]
    fn native_proxy_query_is_read_only() {
        let settings = query_proxy().unwrap();
        assert_ne!(settings.flags, 0);
    }
}

#[cfg(windows)]
mod native {
    use super::*;
    use std::ffi::c_void;
    use std::os::windows::process::CommandExt;
    use std::process::Command;
    #[repr(C)]
    union OptionValue {
        flags: u32,
        text: *mut u16,
        time: u64,
    }
    #[repr(C)]
    struct InternetOption {
        option: u32,
        value: OptionValue,
    }
    #[repr(C)]
    struct OptionList {
        size: u32,
        connection: *mut u16,
        count: u32,
        error: u32,
        options: *mut InternetOption,
    }
    #[link(name = "wininet")]
    extern "system" {
        fn InternetQueryOptionW(
            handle: *mut c_void,
            option: u32,
            buffer: *mut c_void,
            length: *mut u32,
        ) -> i32;
        fn InternetSetOptionW(
            handle: *mut c_void,
            option: u32,
            buffer: *mut c_void,
            length: u32,
        ) -> i32;
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn GlobalFree(memory: *mut c_void) -> *mut c_void;
        fn CreateMutexW(attributes: *mut c_void, owner: i32, name: *const u16) -> *mut c_void;
        fn GetLastError() -> u32;
        fn CloseHandle(handle: *mut c_void) -> i32;
    }
    #[link(name = "user32")]
    extern "system" {
        fn FindWindowW(class: *const u16, title: *const u16) -> *mut c_void;
        fn ShowWindow(window: *mut c_void, command: i32) -> i32;
        fn SetForegroundWindow(window: *mut c_void) -> i32;
        fn MessageBoxW(window: *mut c_void, text: *const u16, caption: *const u16, kind: u32) -> i32;
    }
    /// Brings the running client's window forward, including one hidden in the tray.
    /// Falls back to a message box when the window cannot be found.
    pub fn activate_existing(title: &str, fallback: &str) {
        unsafe {
            let window = FindWindowW(std::ptr::null(), wide(title).as_ptr());
            if !window.is_null() {
                ShowWindow(window, 5); // SW_SHOW: tray-hidden windows
                ShowWindow(window, 9); // SW_RESTORE: minimized windows
                SetForegroundWindow(window);
                return;
            }
            MessageBoxW(
                std::ptr::null_mut(),
                wide(fallback).as_ptr(),
                wide(title).as_ptr(),
                0x40, // MB_ICONINFORMATION
            );
        }
    }
    pub struct InstanceGuard(isize);
    impl Drop for InstanceGuard {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0 as *mut c_void);
            }
        }
    }
    pub fn instance(name: &str, allow_handoff: bool) -> Result<InstanceGuard, String> {
        unsafe {
            let handle = CreateMutexW(std::ptr::null_mut(), 0, wide(name).as_ptr());
            if handle.is_null() {
                return Err(std::io::Error::last_os_error().to_string());
            }
            if GetLastError() == 183 && !allow_handoff {
                CloseHandle(handle);
                return Err(ALREADY_RUNNING.into());
            }
            Ok(InstanceGuard(handle as isize))
        }
    }
    #[link(name = "shell32")]
    extern "system" {
        fn IsUserAnAdmin() -> i32;
        fn ShellExecuteW(
            window: *mut c_void,
            verb: *const u16,
            file: *const u16,
            args: *const u16,
            directory: *const u16,
            show: i32,
        ) -> isize;
    }
    pub fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(Some(0)).collect()
    }
    unsafe fn text(pointer: *mut u16) -> String {
        if pointer.is_null() {
            return String::new();
        }
        let mut length = 0;
        while *pointer.add(length) != 0 {
            length += 1;
        }
        let result = String::from_utf16_lossy(std::slice::from_raw_parts(pointer, length));
        GlobalFree(pointer.cast());
        result
    }
    pub fn query_proxy() -> Result<ProxySettings, String> {
        let mut options = [1, 2, 3, 4].map(|option| InternetOption {
            option,
            value: OptionValue { time: 0 },
        });
        let mut list = OptionList {
            size: std::mem::size_of::<OptionList>() as u32,
            connection: std::ptr::null_mut(),
            count: 4,
            error: 0,
            options: options.as_mut_ptr(),
        };
        let mut size = list.size;
        unsafe {
            if InternetQueryOptionW(
                std::ptr::null_mut(),
                75,
                (&mut list as *mut OptionList).cast(),
                &mut size,
            ) == 0
            {
                return Err(std::io::Error::last_os_error().to_string());
            }
            Ok(ProxySettings {
                flags: options[0].value.flags,
                server: text(options[1].value.text),
                bypass: text(options[2].value.text),
                pac: text(options[3].value.text),
            })
        }
    }
    pub fn set_proxy(settings: &ProxySettings) -> Result<(), String> {
        let mut strings = [
            wide(&settings.server),
            wide(&settings.bypass),
            wide(&settings.pac),
        ];
        let mut options = [
            InternetOption {
                option: 1,
                value: OptionValue {
                    flags: settings.flags,
                },
            },
            InternetOption {
                option: 2,
                value: OptionValue {
                    text: strings[0].as_mut_ptr(),
                },
            },
            InternetOption {
                option: 3,
                value: OptionValue {
                    text: strings[1].as_mut_ptr(),
                },
            },
            InternetOption {
                option: 4,
                value: OptionValue {
                    text: strings[2].as_mut_ptr(),
                },
            },
        ];
        let mut list = OptionList {
            size: std::mem::size_of::<OptionList>() as u32,
            connection: std::ptr::null_mut(),
            count: 4,
            error: 0,
            options: options.as_mut_ptr(),
        };
        unsafe {
            if InternetSetOptionW(
                std::ptr::null_mut(),
                75,
                (&mut list as *mut OptionList).cast(),
                list.size,
            ) == 0
            {
                return Err(std::io::Error::last_os_error().to_string());
            }
            for option in [39, 37] {
                if InternetSetOptionW(std::ptr::null_mut(), option, std::ptr::null_mut(), 0) == 0 {
                    return Err(std::io::Error::last_os_error().to_string());
                }
            }
        }
        Ok(())
    }
    pub fn administrator() -> bool {
        unsafe { IsUserAnAdmin() != 0 }
    }
    pub fn elevate(ready: &Path) -> Result<(), String> {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let args = format!("--elevated-ready=\"{}\"", ready.display());
        let result = unsafe {
            ShellExecuteW(
                std::ptr::null_mut(),
                wide("runas").as_ptr(),
                wide(&exe.to_string_lossy()).as_ptr(),
                wide(&args).as_ptr(),
                std::ptr::null(),
                1,
            )
        };
        if result <= 32 {
            return Err("Elevation was cancelled or failed".into());
        }
        Ok(())
    }
    pub fn autostart(enabled: bool) -> Result<(), String> {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let mut command = Command::new("reg.exe");
        command.creation_flags(0x0800_0000);
        let key = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";
        if enabled {
            command.args([
                "add",
                key,
                "/v",
                "OpenPPP2Client",
                "/t",
                "REG_SZ",
                "/d",
                &format!("\"{}\"", exe.display()),
                "/f",
            ]);
        } else {
            let exists = Command::new("reg.exe")
                .args(["query", key, "/v", "OpenPPP2Client"])
                .creation_flags(0x0800_0000)
                .output()
                .map_err(|e| e.to_string())?;
            if !exists.status.success() {
                return Ok(());
            }
            command.args(["delete", key, "/v", "OpenPPP2Client", "/f"]);
        }
        let result = command.output().map_err(|e| e.to_string())?;
        if !result.status.success() {
            return Err(String::from_utf8_lossy(&result.stderr).into_owned());
        }
        Ok(())
    }
    pub fn pick_executable() -> Result<Option<String>, String> {
        // The script is fixed; paths and configuration are never interpolated into PowerShell.
        let output = Command::new("powershell.exe").creation_flags(0x0800_0000).args(["-NoProfile", "-STA", "-Command", "Add-Type -AssemblyName System.Windows.Forms; $dialog = New-Object System.Windows.Forms.OpenFileDialog; $dialog.Filter = 'ppp executable|*.exe'; if ($dialog.ShowDialog() -eq 'OK') { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8; [Console]::Write($dialog.FileName) }"]).output().map_err(|e| e.to_string())?;
        if !output.status.success() {
            return Err("File dialog failed".into());
        }
        let path = String::from_utf8_lossy(&output.stdout)
            .trim()
            .trim_start_matches('\u{feff}')
            .to_owned();
        Ok((!path.is_empty()).then_some(path))
    }
}

pub const ALREADY_RUNNING: &str = "OpenPPP2 Client is already running";

#[cfg(windows)]
pub use native::{
    activate_existing, administrator, autostart, elevate, instance, pick_executable, query_proxy,
    set_proxy, InstanceGuard,
};
#[cfg(not(windows))]
pub fn activate_existing(_: &str, _: &str) {}
#[cfg(not(windows))]
pub struct InstanceGuard;
#[cfg(not(windows))]
pub fn instance(_: &str, _: bool) -> Result<InstanceGuard, String> {
    Ok(InstanceGuard)
}
#[cfg(not(windows))]
pub fn query_proxy() -> Result<ProxySettings, String> {
    Err("Windows only".into())
}
#[cfg(not(windows))]
pub fn set_proxy(_: &ProxySettings) -> Result<(), String> {
    Err("Windows only".into())
}
#[cfg(not(windows))]
pub fn administrator() -> bool {
    false
}
#[cfg(not(windows))]
pub fn autostart(_: bool) -> Result<(), String> {
    Err("Windows only".into())
}
#[cfg(not(windows))]
pub fn elevate(_: &Path) -> Result<(), String> {
    Err("Windows only".into())
}
#[cfg(not(windows))]
pub fn pick_executable() -> Result<Option<String>, String> {
    Err("Windows only".into())
}
