//! Release GUI/helper processes never allocate a console. CLI invocations may
//! attach their parent's console, while preserving inherited redirected handles.
use std::ffi::OsString;

fn is_cli_invocation(arguments: impl IntoIterator<Item = OsString>) -> bool {
    let mut has_arguments = false;
    for argument in arguments {
        if argument == "--helper" {
            return false;
        }
        has_arguments = true;
    }
    has_arguments
}

#[cfg(all(windows, not(debug_assertions), not(test)))]
pub(super) fn prepare_for_cli() {
    if is_cli_invocation(std::env::args_os().skip(1)) {
        native::attach_parent_preserving_redirects();
    }
}

#[cfg(all(windows, not(debug_assertions), not(test)))]
mod native {
    use std::{ffi::c_void, ptr};
    type Handle = *mut c_void;
    const STANDARD_HANDLES: [u32; 3] = [(-10i32) as u32, (-11i32) as u32, (-12i32) as u32];
    const ATTACH_PARENT_PROCESS: u32 = u32::MAX;
    const DUPLICATE_SAME_ACCESS: u32 = 2;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn AttachConsole(process: u32) -> i32;
        fn GetStdHandle(kind: u32) -> Handle;
        fn SetStdHandle(kind: u32, handle: Handle) -> i32;
        fn GetConsoleMode(handle: Handle, mode: *mut u32) -> i32;
        fn GetHandleInformation(handle: Handle, flags: *mut u32) -> i32;
        fn GetCurrentProcess() -> Handle;
        fn DuplicateHandle(
            source_process: Handle,
            source: Handle,
            target_process: Handle,
            target: *mut Handle,
            access: u32,
            inherit: i32,
            options: u32,
        ) -> i32;
        fn CloseHandle(handle: Handle) -> i32;
    }

    pub(super) fn attach_parent_preserving_redirects() {
        let mut saved = [ptr::null_mut(); 3];
        // SAFETY: this API returns a borrowed process pseudo-handle.
        let process = unsafe { GetCurrentProcess() };
        for (index, kind) in STANDARD_HANDLES.into_iter().enumerate() {
            // SAFETY: constants name the three process standard-handle slots.
            let handle = unsafe { GetStdHandle(kind) };
            if handle.is_null() || handle as isize == -1 {
                continue;
            }
            let mut flags = 0;
            let mut mode = 0;
            // Preserve every valid non-console handle: pipes, files and NUL.
            // Do not close or take ownership of the parent's original handles.
            if unsafe { GetHandleInformation(handle, &mut flags) } == 0
                || unsafe { GetConsoleMode(handle, &mut mode) } != 0
            {
                continue;
            }
            // SAFETY: duplicate the live redirected handle before AttachConsole
            // can replace the standard-handle table. The clone is not inherited.
            if unsafe {
                DuplicateHandle(
                    process,
                    handle,
                    process,
                    &mut saved[index],
                    0,
                    0,
                    DUPLICATE_SAME_ACCESS,
                )
            } == 0
            {
                // Do not risk replacing a redirect that could not be preserved.
                close_saved(saved);
                return;
            }
        }
        // SAFETY: attaches only an existing parent console, never allocates a
        // new window. It runs before clap/stdio caching and Ctrl-C registration.
        if unsafe { AttachConsole(ATTACH_PARENT_PROCESS) } == 0 {
            close_saved(saved);
            return; // No parent console or already attached: keep original I/O.
        }
        for (kind, handle) in STANDARD_HANDLES.into_iter().zip(saved) {
            if !handle.is_null() {
                // SAFETY: install the owned duplicate in the process table. Its
                // lifetime is now the process's standard stream; do not close it.
                let _ = unsafe { SetStdHandle(kind, handle) };
            }
        }
    }

    fn close_saved(handles: [Handle; 3]) {
        for handle in handles {
            if !handle.is_null() {
                // SAFETY: only owned duplicates that were never installed.
                unsafe { CloseHandle(handle) };
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn cli(arguments: &[&str]) -> bool {
        is_cli_invocation(arguments.iter().map(OsString::from))
    }
    #[test]
    fn gui_and_helper_never_attach_a_console() {
        assert!(!cli(&[]));
        assert!(!cli(&[
            "--helper",
            "--port",
            "1234",
            "--token",
            "synthetic"
        ]));
        assert!(!cli(&[
            "--parent-pid",
            "5678",
            "--helper",
            "--port",
            "1234"
        ]));
    }
    #[test]
    fn subcommands_help_version_and_invalid_cli_can_use_the_parent_console() {
        for arguments in [
            &["capabilities"][..],
            &["--help"],
            &["--version"],
            &["connect", "--profile", "synthetic.json", "--password-stdin"],
            &["unknown-command"],
        ] {
            assert!(cli(arguments));
        }
    }
}
