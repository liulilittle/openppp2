use serde_json::{json, Value};
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub fn inspect(path: &Path) -> Result<Value, String> {
    let mut command = Command::new(path);
    command
        .arg("--help")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000);
    }
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            let version = file_version(path).ok_or_else(|| error.to_string())?;
            return Ok(file_version_probe_info(path, &version, &error.to_string()));
        }
    };
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let readers = [
        std::thread::spawn(move || {
            let mut text = String::new();
            let _ = stdout.take(1024 * 1024).read_to_string(&mut text);
            text
        }),
        std::thread::spawn(move || {
            let mut text = String::new();
            let _ = stderr.take(1024 * 1024).read_to_string(&mut text);
            text
        }),
    ];
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if child.try_wait().map_err(|e| e.to_string())?.is_some() {
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err("Kernel help probe timed out".into());
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    let help = readers
        .into_iter()
        .map(|r| r.join().unwrap_or_default())
        .collect::<Vec<_>>()
        .join("\n");
    let version = help
        .lines()
        .find(|line| line.to_ascii_lowercase().contains("version"))
        .map(|line| line.trim().to_owned())
        .or_else(|| file_version(path))
        .unwrap_or_else(|| "Unknown".into());
    let has_help = !help.trim().is_empty();
    let flag = |name: &str| has_help.then(|| help.contains(name));
    Ok(json!({
        "path": path, "version": version, "helpAvailable": has_help,
        "statsSupported": flag("--stats-json"),
        "muxTurboSupported": flag("--mux-mode-turbo"),
        "proxySupported": flag("proxy"),
        "tcpStackSupported": flag("--tcp-stack"),
        "tunIpv6Supported": flag("--tun-ipv6"),
        "policySupported": policy_supported(&version),
    }))
}

fn file_version_probe_info(path: &Path, version: &str, error: &str) -> Value {
    json!({
        "path": path, "version": version, "helpAvailable": false,
        "probeError": error, "statsSupported": null,
        "muxTurboSupported": null, "proxySupported": null,
        "tcpStackSupported": null, "tunIpv6Supported": null,
        "policySupported": policy_supported(version),
    })
}

/// `ppp policy` ships from 2.1.7 and is absent from `--help`. Never probe it by
/// running the subcommand: older kernels ignore the unknown word and start a client.
pub fn policy_supported(version: &str) -> Option<bool> {
    let numbers = version
        .split(|c: char| !c.is_ascii_digit() && c != '.')
        .find(|part| part.matches('.').count() >= 2)?
        .split('.')
        .map(|part| part.parse::<u32>().ok())
        .collect::<Option<Vec<_>>>()?;
    Some(numbers[..3] >= [2, 1, 7][..])
}

#[cfg(windows)]
fn file_version(path: &Path) -> Option<String> {
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    #[link(name = "version")]
    extern "system" {
        fn GetFileVersionInfoSizeW(path: *const u16, handle: *mut u32) -> u32;
        fn GetFileVersionInfoW(path: *const u16, handle: u32, size: u32, data: *mut c_void) -> i32;
        fn VerQueryValueW(
            data: *const c_void,
            key: *const u16,
            value: *mut *mut c_void,
            length: *mut u32,
        ) -> i32;
    }
    let path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut handle = 0;
    unsafe {
        let size = GetFileVersionInfoSizeW(path.as_ptr(), &mut handle);
        if size == 0 {
            return None;
        }
        let mut buffer = vec![0u8; size as usize];
        if GetFileVersionInfoW(path.as_ptr(), 0, size, buffer.as_mut_ptr().cast()) == 0 {
            return None;
        }
        let mut pointer = std::ptr::null_mut();
        let mut length = 0;
        if VerQueryValueW(
            buffer.as_ptr().cast(),
            [92u16, 0].as_ptr(),
            &mut pointer,
            &mut length,
        ) == 0
            || length < 52
            || pointer.is_null()
        {
            return None;
        }
        let info = std::ptr::read_unaligned(pointer.cast::<[u32; 13]>());
        if info[0] != 0xfeef04bd {
            return None;
        }
        Some(format!(
            "{}.{}.{}.{}",
            info[2] >> 16,
            info[2] & 65535,
            info[3] >> 16,
            info[3] & 65535
        ))
    }
}
#[cfg(not(windows))]
fn file_version(_: &Path) -> Option<String> {
    None
}

pub fn redact(mut value: Value) -> Value {
    fn visit(value: &mut Value) {
        match value {
            Value::Object(fields) => {
                for (key, value) in fields {
                    if key.to_ascii_lowercase().contains("key") && !value.is_object()
                        || key.to_ascii_lowercase().contains("password")
                        || key.to_ascii_lowercase().contains("token")
                    {
                        *value = json!("[redacted]");
                    } else {
                        visit(value);
                    }
                }
            }
            Value::Array(values) => {
                for value in values {
                    visit(value);
                }
            }
            _ => {}
        }
    }
    visit(&mut value);
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_version_fallback_preserves_policy_capability_when_help_cannot_spawn() {
        for (version, supported) in [("2.1.7.0", Some(true)), ("2.1.6.0", Some(false)), ("Unknown", None)] {
            let info = file_version_probe_info(
                Path::new("ppp.exe"), version, "Access is denied (os error 5)");
            assert_eq!(info["helpAvailable"], false);
            assert_eq!(info["policySupported"].as_bool(), supported);
            assert_eq!(info["version"], version);
            assert!(info["probeError"].as_str().unwrap().contains("os error 5"));
            assert!(info["statsSupported"].is_null());
            assert!(info["tcpStackSupported"].is_null());
        }
    }
}
