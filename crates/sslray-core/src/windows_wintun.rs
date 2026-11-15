//! Authenticate official Wintun bytes before loading executable DLL code.
//! Pins are from the unmodified official 0.14.1 archive; see third_party/wintun.
//! Never call the binding's load_from_path: its preliminary path lookup executes
//! DllMain before signature verification.
use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use std::{io::Read, path::Path};

const MAX_DLL_BYTES: u64 = 16 * 1024 * 1024;

fn official_sha256(architecture: &str) -> Result<&'static str> {
    match architecture {
        "x86_64" => Ok("e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce"),
        "x86" => Ok("d694fa46ab4cfebcb2632d094c7aa97278eef2f8052438621766d863ae98a931"),
        "aarch64" => Ok("f7ba89005544be9d85231a9e0d5f23b2d15b3311667e2dad0debd344918a3f80"),
        "arm" => Ok("daad267411ecdc70a0535e274d2c3e9da3d0084bdac7662cb8424dd4a031b4d9"),
        _ => anyhow::bail!("Unsupported Windows Wintun architecture"),
    }
}

fn validate_path(path: &Path, executable_directory: &Path) -> Result<()> {
    ensure!(path.is_absolute(), "Wintun path must be absolute");
    ensure!(
        path.parent() == Some(executable_directory)
            && path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.eq_ignore_ascii_case("wintun.dll")),
        "Wintun must be a file beside the SSLRay executable"
    );
    Ok(())
}

fn verify_bytes(reader: &mut impl Read, expected: &str) -> Result<()> {
    let mut digest = Sha256::new();
    let mut count = 0u64;
    let mut bytes = [0u8; 16 * 1024];
    loop {
        let n = reader
            .read(&mut bytes)
            .context("Reading locked Wintun binary")?;
        if n == 0 {
            break;
        }
        count += n as u64;
        ensure!(
            count <= MAX_DLL_BYTES,
            "Wintun binary exceeds the size limit"
        );
        digest.update(&bytes[..n]);
    }
    ensure!(
        count > 0 && hex::encode(digest.finalize()) == expected,
        "Wintun binary does not match the official version and architecture; refusing to load"
    );
    Ok(())
}

// Keep the trust operations in their actual execution order. Tests inject a
// loader to verify that neither a hash nor a signature failure can execute it.
fn after_verification<T>(
    reader: &mut impl Read,
    expected: &str,
    verify_signature: impl FnOnce() -> Result<()>,
    load: impl FnOnce() -> Result<T>,
) -> Result<T> {
    verify_bytes(reader, expected)?;
    verify_signature()?;
    load()
}

#[cfg(windows)]
pub(super) fn load() -> Result<wintun_bindings::Wintun> {
    let executable = std::env::current_exe()?.canonicalize()?;
    let directory = executable
        .parent()
        .context("Missing executable directory")?;
    let path = directory.join("wintun.dll");
    validate_path(&path, directory)?;
    let expected = official_sha256(std::env::consts::ARCH)?;
    let locked = native::LockedBinary::open(&path)?;
    let mut reader = &locked.file;
    after_verification(
        &mut reader,
        expected,
        || native::verify_signature(&path, &locked.file),
        || {
            // SAFETY: exact official architecture-specific bytes and Authenticode
            // were verified while file/directory handles prevent replacement.
            // Only Windows system directories resolve its imported dependencies.
            let library = unsafe {
                libloading::os::windows::Library::load_with_flags(
                    &path,
                    libloading::os::windows::LOAD_LIBRARY_SEARCH_SYSTEM32,
                )
            }
            .context("Loading authenticated Wintun binary")?;
            // SAFETY: only the pinned official Wintun API is accepted above.
            // This constructor resolves exports without repeating path loading.
            unsafe { wintun_bindings::load_from_library(library) }
                .map_err(|error| anyhow::anyhow!("Resolving authenticated Wintun API: {error}"))
        },
    )
    // `locked` remains alive until the DLL is mapped and all exports resolve.
}

#[cfg(windows)]
mod native {
    use super::*;
    use std::{
        fs::{File, OpenOptions},
        io::Seek,
        mem::size_of,
        os::windows::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt},
            io::AsRawHandle,
        },
        path::{Component, Prefix},
        ptr,
    };
    use windows_sys::Win32::{
        Security::WinTrust::{
            WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO,
            WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE,
            WTD_STATEACTION_VERIFY, WTD_UI_NONE, WinVerifyTrust,
        },
        Storage::FileSystem::{
            FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
            FILE_SHARE_READ, FILE_SHARE_WRITE,
        },
    };

    pub(super) struct LockedBinary {
        pub(super) file: File,
        _directories: Vec<File>,
    }

    impl LockedBinary {
        pub(super) fn open(path: &Path) -> Result<Self> {
            // Release packages are local files. Do not load code from UNC shares
            // or device namespaces, even if the path is otherwise absolute.
            ensure!(
                matches!(path.components().next(), Some(Component::Prefix(prefix))
                    if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))),
                "Wintun must be loaded from a local drive"
            );
            // Lock ancestors from the volume root down. Denying directory delete
            // prevents a path component being renamed/replaced after validation;
            // sharing directory reads/writes leaves other files usable.
            let parents: Vec<_> = path
                .parent()
                .context("Missing Wintun directory")?
                .ancestors()
                .collect();
            ensure!(
                parents.len() <= 128,
                "Wintun directory nesting exceeds the limit"
            );
            let mut directories = Vec::with_capacity(parents.len());
            for parent in parents.into_iter().rev() {
                let directory = OpenOptions::new()
                    .read(true)
                    .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
                    .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
                    .open(parent)
                    .context("Locking Wintun directory against replacement")?;
                let metadata = directory.metadata()?;
                ensure!(
                    metadata.is_dir()
                        && metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0,
                    "Wintun directory must not be a reparse point"
                );
                directories.push(directory);
            }
            let file = OpenOptions::new()
                .read(true)
                .share_mode(FILE_SHARE_READ)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                .open(path)
                .context("Opening and locking Wintun binary")?;
            let metadata = file.metadata()?;
            ensure!(
                metadata.is_file()
                    && metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0,
                "Wintun binary must be a regular file"
            );
            ensure!(
                (1..=MAX_DLL_BYTES).contains(&metadata.len()),
                "Wintun binary has an invalid size"
            );
            Ok(Self {
                file,
                _directories: directories,
            })
        }
    }

    pub(super) fn verify_signature(path: &Path, file: &File) -> Result<()> {
        let mut position = file;
        position
            .rewind()
            .context("Rewinding locked Wintun binary")?;
        let mut name: Vec<_> = path.as_os_str().encode_wide().collect();
        ensure!(!name.contains(&0), "Wintun path contains NUL");
        name.push(0);
        let mut file_info = WINTRUST_FILE_INFO {
            cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: name.as_ptr(),
            hFile: file.as_raw_handle(),
            pgKnownSubject: ptr::null_mut(),
        };
        let mut trust = WINTRUST_DATA {
            cbStruct: size_of::<WINTRUST_DATA>() as u32,
            dwUIChoice: WTD_UI_NONE,
            fdwRevocationChecks: WTD_REVOKE_NONE,
            dwUnionChoice: WTD_CHOICE_FILE,
            Anonymous: WINTRUST_DATA_0 {
                pFile: &mut file_info,
            },
            dwStateAction: WTD_STATEACTION_VERIFY,
            // The exact release hash is the primary binary identity. Verify the
            // embedded signature under local Windows trust policy, without UI
            // or network retrieval; do not claim an online revocation check.
            dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL,
            ..Default::default()
        };
        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        // SAFETY: SDK-defined initialized structures, live read-only file handle,
        // NUL-terminated path, and WTD_UI_NONE keep validation non-interactive.
        let result = unsafe {
            WinVerifyTrust(
                ptr::null_mut(),
                &mut action,
                ptr::from_mut(&mut trust).cast(),
            )
        };
        // Trust-provider state must be released on both success and failure.
        trust.dwStateAction = WTD_STATEACTION_CLOSE;
        // SAFETY: same live structures and state returned by the preceding call.
        let _ = unsafe {
            WinVerifyTrust(
                ptr::null_mut(),
                &mut action,
                ptr::from_mut(&mut trust).cast(),
            )
        };
        ensure!(
            result == 0,
            "Wintun signature verification failed (0x{:08x})",
            result as u32
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn architecture_pins_are_complete_distinct_and_reject_unknown_architectures() {
        let pins: Vec<_> = ["x86_64", "x86", "aarch64", "arm"]
            .into_iter()
            .map(|architecture| official_sha256(architecture).unwrap())
            .collect();
        for (index, pin) in pins.iter().enumerate() {
            assert_eq!(hex::decode(pin).unwrap().len(), 32);
            assert!(!pins[..index].contains(pin));
        }
        assert!(official_sha256("riscv64").is_err());
    }

    #[test]
    fn only_the_exact_absolute_adjacent_dll_path_is_accepted() {
        let directory = std::env::temp_dir().join("sslray-loader-test");
        assert!(validate_path(&directory.join("wintun.dll"), &directory).is_ok());
        assert!(validate_path(&directory.join("WINTUN.DLL"), &directory).is_ok());
        assert!(validate_path(Path::new("wintun.dll"), &directory).is_err());
        assert!(validate_path(&directory.join("other.dll"), &directory).is_err());
        assert!(validate_path(&directory.join("nested/wintun.dll"), &directory).is_err());
    }

    #[test]
    fn hash_and_signature_failures_cannot_reach_the_loader() {
        let expected = hex::encode(Sha256::digest(b"synthetic trusted bytes"));
        let signature_called = Cell::new(false);
        let load_called = Cell::new(false);
        let result = after_verification(
            &mut &b"modified bytes"[..],
            &expected,
            || {
                signature_called.set(true);
                Ok(())
            },
            || {
                load_called.set(true);
                Ok(())
            },
        );
        assert!(result.is_err());
        assert!(!signature_called.get() && !load_called.get());
        let result = after_verification(
            &mut &b"synthetic trusted bytes"[..],
            &expected,
            || anyhow::bail!("Synthetic signature policy rejection"),
            || {
                load_called.set(true);
                Ok(())
            },
        );
        assert!(result.is_err());
        assert!(!load_called.get());
        let order = Cell::new(0);
        after_verification(
            &mut &b"synthetic trusted bytes"[..],
            &expected,
            || {
                order.set(1);
                Ok(())
            },
            || {
                assert_eq!(order.get(), 1);
                order.set(2);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(order.get(), 2);
    }

    #[test]
    fn empty_oversized_and_unreadable_inputs_are_rejected_before_loading() {
        let expected = hex::encode(Sha256::digest([]));
        assert!(verify_bytes(&mut &[][..], &expected).is_err());
        assert!(verify_bytes(&mut std::io::repeat(0).take(MAX_DLL_BYTES + 1), &expected).is_err());
        struct Unreadable;
        impl Read for Unreadable {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("Synthetic read failure"))
            }
        }
        assert!(verify_bytes(&mut Unreadable, &expected).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn native_file_lock_denies_replacement_and_unsigned_files_never_load() {
        use std::fs::{self, OpenOptions};
        let directory =
            std::env::temp_dir().join(format!("sslray-wintun-test-{}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("wintun.dll");
        fs::write(&path, b"Synthetic unsigned DLL fixture").unwrap();
        {
            let _writer = OpenOptions::new().write(true).open(&path).unwrap();
            assert!(native::LockedBinary::open(&path.canonicalize().unwrap()).is_err());
        }
        {
            let locked = native::LockedBinary::open(&path.canonicalize().unwrap()).unwrap();
            assert!(OpenOptions::new().write(true).open(&path).is_err());
            assert!(fs::remove_file(&path).is_err());
            assert!(fs::rename(&directory, directory.with_extension("renamed")).is_err());
            let expected = hex::encode(Sha256::digest(b"Synthetic unsigned DLL fixture"));
            let called = Cell::new(false);
            let mut reader = &locked.file;
            assert!(
                after_verification(
                    &mut reader,
                    &expected,
                    || native::verify_signature(&path, &locked.file),
                    || {
                        called.set(true);
                        Ok(())
                    }
                )
                .is_err()
            );
            assert!(!called.get());
        }
        fs::remove_file(path).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn native_unc_and_device_paths_are_rejected_before_file_access() {
        for path in [
            r"\\unreachable.invalid\share\wintun.dll",
            r"\\?\UNC\unreachable.invalid\share\wintun.dll",
            r"\\.\pipe\wintun.dll",
        ] {
            let error = native::LockedBinary::open(Path::new(path)).err().unwrap();
            assert!(error.to_string().contains("local drive"));
        }
    }
}
