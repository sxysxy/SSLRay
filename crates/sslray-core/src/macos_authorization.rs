//! One-shot elevation through the host's existing policy. No PAM or authorization
//! database changes, password collection, or app-side biometric authentication.
use super::ElevationMethod;
use objc2::{
    msg_send,
    rc::{Retained, autoreleasepool},
    runtime::{AnyClass, AnyObject, Bool},
};
use std::{ffi::OsString, fs::File, io::Read, path::Path, process::Command};

#[link(name = "LocalAuthentication", kind = "framework")]
unsafe extern "C" {}

const MAX_PAM_BYTES: usize = 16 * 1024;
const ADMIN_SCRIPT: &str = "on run argv\nset shellCommand to quoted form of item 1 of argv\nrepeat with i from 2 to count of argv\nset shellCommand to shellCommand & \" \" & (quoted form of item i of argv)\nend repeat\ndo shell script shellCommand with administrator privileges\nend run";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LaunchKind {
    Biometric,
    Password,
}

fn choose_launch(method: ElevationMethod, pam: bool, touch_id: bool) -> LaunchKind {
    if method == ElevationMethod::Automatic && pam && touch_id {
        LaunchKind::Biometric
    } else {
        LaunchKind::Password
    }
}

pub(super) fn launch_command(
    executable: &Path,
    arguments: &[OsString],
    method: ElevationMethod,
) -> (Command, bool) {
    // A forced password retry does not probe biometrics. Availability is only a
    // hint for choosing the system provider; sudo still enforces authorization.
    let pam = method == ElevationMethod::Automatic && host_pam_prefers_touch_id();
    let available = pam && touch_id_available();
    let kind = choose_launch(method, pam, available);
    (
        command_for(kind, executable, arguments),
        kind == LaunchKind::Biometric,
    )
}

fn command_for(kind: LaunchKind, executable: &Path, arguments: &[OsString]) -> Command {
    match kind {
        LaunchKind::Biometric => {
            let mut command = Command::new("/usr/bin/sudo");
            // -k WITH a command ignores and does not update cached credentials.
            // -S avoids tty/askpass discovery. The caller supplies /dev/null as
            // stdin, so password fallback in PAM receives EOF, never a password.
            command.args(["-k", "-S", "-p", "", "--"]);
            command.arg(executable).args(arguments);
            command
        }
        LaunchKind::Password => {
            // Each value remains a separate argv item. AppleScript performs
            // native shell quoting; no path or token becomes script source.
            let mut command = Command::new("/usr/bin/osascript");
            command
                .arg("-e")
                .arg(ADMIN_SCRIPT)
                .arg(executable)
                .args(arguments);
            command
        }
    }
}

fn touch_id_available() -> bool {
    autoreleasepool(|_| {
        let Some(class) = AnyClass::get(c"LAContext") else {
            return false;
        };
        // SAFETY: These selectors and their signatures are public LAContext
        // APIs (macOS 10.12.2 / 10.13.2, below our 11.0 minimum). The context is
        // retained for all calls. NSError** is an optional output and may be nil.
        // canEvaluatePolicy only checks availability; evaluatePolicy is not used.
        let context: Option<Retained<AnyObject>> = unsafe { msg_send![class, new] };
        let Some(context) = context else {
            return false;
        };
        let available: Bool = unsafe {
            msg_send![&*context, canEvaluatePolicy: 1_isize, error: std::ptr::null_mut::<*mut AnyObject>()]
        };
        if !available.as_bool() {
            return false;
        }
        // LAPolicyDeviceOwnerAuthenticationWithBiometrics = 1;
        // LABiometryTypeTouchID = 1. Do not label another modality as Touch ID.
        let biometry_type: isize = unsafe { msg_send![&*context, biometryType] };
        biometry_type == 1
    })
}

fn read_pam_file(path: &Path) -> std::io::Result<Option<String>> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let mut content = String::new();
    file.take((MAX_PAM_BYTES + 1) as u64)
        .read_to_string(&mut content)?;
    if content.len() > MAX_PAM_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "PAM policy exceeds read limit",
        ));
    }
    Ok(Some(content))
}

fn host_pam_prefers_touch_id() -> bool {
    let Ok(Some(sudo)) = read_pam_file(Path::new("/etc/pam.d/sudo")) else {
        return false;
    };
    let local = if auth_entries(&sudo).any(|entry| entry == ["auth", "include", "sudo_local"]) {
        match read_pam_file(Path::new("/etc/pam.d/sudo_local")) {
            Ok(local) => local,
            Err(_) => return false,
        }
    } else {
        None
    };
    pam_prefers_touch_id(&sudo, local.as_deref())
}

fn auth_entries(content: &str) -> impl Iterator<Item = Vec<&str>> {
    content.lines().filter_map(|line| {
        let fields: Vec<_> = line
            .split('#')
            .next()
            .unwrap_or_default()
            .split_whitespace()
            .collect();
        (fields.first() == Some(&"auth")).then_some(fields)
    })
}

fn is_touch_id(entry: &[&str]) -> bool {
    matches!(
        entry,
        ["auth", "sufficient", "pam_tid.so"] | ["auth", "sufficient", "/usr/lib/pam/pam_tid.so"]
    )
}

fn pam_prefers_touch_id(sudo: &str, local: Option<&str>) -> bool {
    if sudo.len() > MAX_PAM_BYTES || local.is_some_and(|local| local.len() > MAX_PAM_BYTES) {
        return false;
    }
    for entry in auth_entries(sudo) {
        if entry == ["auth", "include", "sudo_local"] {
            // Only the documented local override is expanded, once. Other or
            // complex policies use the system password route conservatively.
            if let Some(first) = local.and_then(|local| auth_entries(local).next()) {
                return is_touch_id(&first);
            }
        } else {
            // Touch ID must precede any other auth module. A merely present
            // pam_tid after a required password module cannot make this work.
            return is_touch_id(&entry);
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn automatic_requires_both_host_policy_and_available_touch_id() {
        for method in [ElevationMethod::Automatic, ElevationMethod::Password] {
            for pam in [false, true] {
                for available in [false, true] {
                    assert_eq!(
                        choose_launch(method, pam, available) == LaunchKind::Biometric,
                        method == ElevationMethod::Automatic && pam && available
                    );
                }
            }
        }
    }

    #[test]
    fn pam_accepts_enabled_first_module_in_main_or_explicit_local_override() {
        assert!(pam_prefers_touch_id(
            "# policy\nauth\tsufficient\tpam_tid.so # Touch ID\nauth required pam_opendirectory.so",
            None
        ));
        assert!(pam_prefers_touch_id(
            "auth include sudo_local\nauth required pam_opendirectory.so",
            Some("auth sufficient pam_tid.so\n")
        ));
        assert!(pam_prefers_touch_id(
            "auth include sudo_local\nauth sufficient pam_tid.so\n",
            None
        ));
        assert!(pam_prefers_touch_id(
            "auth include sudo_local\nauth sufficient /usr/lib/pam/pam_tid.so",
            Some("# no override\n")
        ));
    }

    #[test]
    fn pam_rejects_comments_unknown_includes_and_password_before_touch_id() {
        for sudo in [
            "# auth sufficient pam_tid.so\nauth required pam_opendirectory.so",
            "auth required pam_tid.so",
            "auth sufficient pam_tid.so.invalid",
            "auth include custom_policy\nauth sufficient pam_tid.so",
            "auth required pam_opendirectory.so\nauth sufficient pam_tid.so",
            "auth include sudo_local\nauth sufficient pam_tid.so",
            "account sufficient pam_tid.so",
        ] {
            assert!(
                !pam_prefers_touch_id(sudo, Some("auth required pam_opendirectory.so")),
                "{sudo}"
            );
        }
        assert!(!pam_prefers_touch_id(
            "auth include sudo_local",
            Some("auth include sudo_local")
        ));
        assert!(!pam_prefers_touch_id(&"x".repeat(MAX_PAM_BYTES + 1), None));
    }

    #[test]
    fn sudo_argv_is_one_execution_without_shell_askpass_or_noninteractive_mode() {
        let executable = Path::new("/Applications/Space 'quoted'/SSLRay.app/Contents/MacOS/SSLRay");
        let arguments: Vec<OsString> = [
            "--helper",
            "--socket",
            "/tmp/space 'quote'/helper.sock",
            "--token",
            &"a".repeat(64),
        ]
        .map(Into::into)
        .to_vec();
        let command = command_for(LaunchKind::Biometric, executable, &arguments);
        assert_eq!(command.get_program(), "/usr/bin/sudo");
        let args: Vec<_> = command.get_args().collect();
        assert_eq!(&args[..5], &["-k", "-S", "-p", "", "--"]);
        assert_eq!(args[5], executable.as_os_str());
        assert_eq!(&args[6..], arguments.as_slice());
        assert!(
            !args
                .iter()
                .any(|arg| *arg == "-A" || *arg == "-n" || *arg == "-K")
        );
    }

    #[test]
    fn password_argv_keeps_paths_and_tokens_out_of_applescript_source() {
        let executable = Path::new("/Applications/Space 'quoted'/SSLRay");
        let arguments = vec![
            OsString::from("--socket"),
            OsString::from("/tmp/quote ' $() space/helper.sock"),
        ];
        let command = command_for(LaunchKind::Password, executable, &arguments);
        assert_eq!(command.get_program(), "/usr/bin/osascript");
        let args: Vec<_> = command.get_args().collect();
        assert_eq!(args[0], "-e");
        assert_eq!(args[1], ADMIN_SCRIPT);
        assert_eq!(args[2], executable.as_os_str());
        assert_eq!(&args[3..], arguments.as_slice());
        assert!(!ADMIN_SCRIPT.contains("/Applications/Space"));
    }
}
