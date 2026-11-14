//! Named GUI profiles. Password persistence requires an explicit UI opt-in.
//! Base64 only obscures the saved text; it is not encryption. OTPs are never
//! part of this format. The CLI still uses single-profile files.

use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::Error as _,
    ser::{Error as _, SerializeStruct},
};
use sslray_core::config::{Profile, RouteMode};
use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::Path,
};
use zeroize::{Zeroize, Zeroizing};

const FORMAT_VERSION: u32 = 1;
const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_PROFILES: usize = 1024;
const MAX_NAME_CHARS: usize = 80;
const LIBRARY_FILE: &str = "profiles.json";

#[derive(Clone)]
pub struct ProfileEntry {
    pub id: u64,
    pub profile: Profile,
    pub saved_password: Option<String>,
}

impl Serialize for ProfileEntry {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        validate_saved_password(self.saved_password.as_deref()).map_err(S::Error::custom)?;
        let encoded = self
            .saved_password
            .as_ref()
            .map(|password| Zeroizing::new(STANDARD.encode(password.as_bytes())));
        let mut entry =
            serializer.serialize_struct("ProfileEntry", 2 + usize::from(encoded.is_some()))?;
        entry.serialize_field("id", &self.id)?;
        entry.serialize_field("profile", &self.profile)?;
        if let Some(encoded) = &encoded {
            entry.serialize_field("saved_password_base64", encoded.as_str())?;
        }
        entry.end()
    }
}

impl<'de> Deserialize<'de> for ProfileEntry {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let mut raw = RawProfileEntry::deserialize(deserializer)?;
        if raw.saved_password.present && raw.saved_password_base64.present {
            return Err(D::Error::custom("Conflicting saved password fields"));
        }
        let mut password = if raw.saved_password_base64.present {
            match raw.saved_password_base64.value.as_deref() {
                Some(encoded) => {
                    let mut decoded = decode_password(encoded).map_err(D::Error::custom)?;
                    Zeroizing::new(Some(std::mem::take(&mut *decoded)))
                }
                None => Zeroizing::new(None),
            }
        } else {
            Zeroizing::new(raw.saved_password.value.take())
        };
        validate_saved_password(password.as_deref()).map_err(D::Error::custom)?;
        Ok(Self {
            id: raw.id,
            profile: std::mem::take(&mut raw.profile),
            saved_password: password.take(),
        })
    }
}

// Presence distinguishes absent fields from explicit JSON null. Each field
// guards its string even if a later field fails before RawProfileEntry exists.
#[derive(Default)]
struct PasswordField {
    present: bool,
    value: Zeroizing<Option<String>>,
}

impl<'de> Deserialize<'de> for PasswordField {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        Ok(Self {
            present: true,
            value: Zeroizing::new(Option::<String>::deserialize(deserializer)?),
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProfileEntry {
    id: u64,
    profile: Profile,
    #[serde(default)]
    saved_password: PasswordField,
    #[serde(default)]
    saved_password_base64: PasswordField,
}

impl Drop for RawProfileEntry {
    fn drop(&mut self) {
        self.profile.zeroize();
    }
}

fn decode_password(encoded: &str) -> Result<Zeroizing<String>> {
    // 1,024 plaintext bytes need at most 1,368 standard Base64 characters.
    ensure!(encoded.len() <= 1368, "Invalid saved password Base64");
    let mut decoded = Zeroizing::new(Vec::new());
    STANDARD
        .decode_vec(encoded, &mut decoded)
        .map_err(|_| anyhow::anyhow!("Invalid saved password Base64"))?;
    let canonical = Zeroizing::new(STANDARD.encode(decoded.as_slice()));
    ensure!(
        canonical.as_str() == encoded,
        "Invalid saved password Base64"
    );
    let password = std::str::from_utf8(&decoded)
        .map_err(|_| anyhow::anyhow!("Saved password is not valid UTF-8"))?;
    validate_saved_password(Some(password))?;
    Ok(Zeroizing::new(password.to_owned()))
}

impl Drop for ProfileEntry {
    fn drop(&mut self) {
        self.saved_password.zeroize();
        self.profile.zeroize();
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileLibrary {
    version: u32,
    pub selected_id: u64,
    pub entries: Vec<ProfileEntry>,
}

impl Default for ProfileLibrary {
    fn default() -> Self {
        Self {
            version: FORMAT_VERSION,
            selected_id: 1,
            entries: vec![ProfileEntry {
                id: 1,
                profile: Profile::default(),
                saved_password: None,
            }],
        }
    }
}

impl ProfileLibrary {
    /// Migrate the old single-profile file only when no library exists. The
    /// original is retained unchanged; malformed files are never overwritten.
    pub fn load(directory: &Path) -> Result<Self> {
        let path = directory.join(LIBRARY_FILE);
        if path.try_exists()? {
            let mut library: Self = serde_json::from_slice(&read_bounded(&path)?)
                .map_err(|error| json_error("profile library", &error))?;
            for entry in &mut library.entries {
                normalize(&mut entry.profile);
            }
            library.validate()?;
            return Ok(library);
        }

        let legacy = directory.join("profile.json");
        if !legacy.try_exists()? {
            return Ok(Self::default());
        }
        let mut profile: Profile = serde_json::from_slice(&read_bounded(&legacy)?)
            .map_err(|error| json_error("legacy profile", &error))?;
        normalize(&mut profile);
        let library = Self {
            entries: vec![ProfileEntry {
                id: 1,
                profile,
                saved_password: None,
            }],
            ..Self::default()
        };
        library.validate()?;
        library.save(directory)?;
        Ok(library)
    }

    /// Write a complete replacement before renaming it into place. Secrets
    /// from the OpenVPN execution-only representation must never reach disk.
    pub fn save(&self, directory: &Path) -> Result<()> {
        self.validate()?;
        let data = Zeroizing::new(serde_json::to_vec_pretty(self)?);
        ensure!(
            data.len() as u64 <= MAX_FILE_BYTES,
            "Profile library is too large"
        );
        fs::create_dir_all(directory)?;
        let random = getrandom::u64()?;
        let temporary = directory.join(format!(".profiles-{random:016x}.tmp"));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut output = options.open(&temporary)?;
        let result = (|| {
            output.write_all(&data)?;
            output.sync_all()?;
            drop(output);
            fs::rename(&temporary, directory.join(LIBRARY_FILE))?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    pub fn selected(&self) -> &ProfileEntry {
        self.entries
            .iter()
            .find(|entry| entry.id == self.selected_id)
            .expect("profile library selection is validated before use")
    }

    pub fn select(&mut self, id: u64) -> Result<()> {
        ensure!(
            self.entries.iter().any(|entry| entry.id == id),
            "Unknown profile ID"
        );
        self.selected_id = id;
        Ok(())
    }

    pub fn update_selected(&mut self, mut profile: Profile) -> Result<()> {
        normalize(&mut profile);
        self.validate_profile(&profile, Some(self.selected_id))?;
        let entry = self
            .entries
            .iter_mut()
            .find(|entry| entry.id == self.selected_id)
            .context("Unknown profile ID")?;
        entry.profile = profile;
        Ok(())
    }

    pub fn insert(&mut self, mut profile: Profile) -> Result<u64> {
        normalize(&mut profile);
        ensure!(
            self.entries.len() < MAX_PROFILES,
            "Too many connection profiles"
        );
        self.validate_profile(&profile, None)?;
        let id = self
            .entries
            .iter()
            .map(|entry| entry.id)
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .context("Profile ID range exhausted")?;
        self.entries.push(ProfileEntry {
            id,
            profile,
            saved_password: None,
        });
        self.selected_id = id;
        Ok(id)
    }

    /// Retain a password only after the user has opted into local storage.
    /// `save` writes reversible Base64 text, which provides no encryption.
    pub fn set_saved_password(&mut self, password: Option<String>) -> Result<()> {
        let mut password = Zeroizing::new(password);
        validate_saved_password(password.as_deref())?;
        let entry = self
            .entries
            .iter_mut()
            .find(|entry| entry.id == self.selected_id)
            .context("Unknown profile ID")?;
        entry.saved_password.zeroize();
        entry.saved_password = password.take();
        Ok(())
    }

    pub fn remove_selected(&mut self) -> Result<()> {
        ensure!(
            self.entries.len() > 1,
            "Keep at least one connection profile"
        );
        let index = self
            .entries
            .iter()
            .position(|entry| entry.id == self.selected_id)
            .context("Unknown profile ID")?;
        self.entries.remove(index);
        self.selected_id = self.entries[index.min(self.entries.len() - 1)].id;
        Ok(())
    }

    /// Find an available display name without using a display name as identity.
    pub fn unique_name(&self, base: &str) -> String {
        let base: String = base
            .trim()
            .chars()
            .filter(|character| !character.is_control())
            .take(MAX_NAME_CHARS)
            .collect();
        let base = if base.is_empty() { "VPN" } else { &base };
        if !self.name_exists(base, None) {
            return base.to_owned();
        }
        for number in 2.. {
            let suffix = format!(" ({number})");
            let prefix: String = base
                .chars()
                .take(MAX_NAME_CHARS - suffix.chars().count())
                .collect();
            let name = format!("{prefix}{suffix}");
            if !self.name_exists(&name, None) {
                return name;
            }
        }
        unreachable!("a finite library always has a free name")
    }

    pub fn is_current_profile(&self, profile: &Profile) -> bool {
        serde_json::to_vec(profile)
            .ok()
            .zip(serde_json::to_vec(&self.selected().profile).ok())
            .is_some_and(|(draft, saved)| draft == saved)
    }

    fn name_exists(&self, name: &str, except: Option<u64>) -> bool {
        let key = name.to_lowercase();
        self.entries
            .iter()
            .any(|entry| Some(entry.id) != except && entry.profile.name.to_lowercase() == key)
    }

    fn validate_profile(&self, profile: &Profile, except: Option<u64>) -> Result<()> {
        validate_profile(profile)?;
        ensure!(
            !self.name_exists(&profile.name, except),
            "A profile with this name already exists"
        );
        Ok(())
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            self.version == FORMAT_VERSION,
            "Unsupported profile library version"
        );
        ensure!(
            !self.entries.is_empty(),
            "Keep at least one connection profile"
        );
        ensure!(
            self.entries.len() <= MAX_PROFILES,
            "Too many connection profiles"
        );
        let mut ids = HashSet::new();
        let mut names = HashSet::new();
        for entry in &self.entries {
            ensure!(
                entry.id != 0 && ids.insert(entry.id),
                "Invalid or duplicate profile ID"
            );
            validate_profile(&entry.profile)?;
            validate_saved_password(entry.saved_password.as_deref())?;
            ensure!(
                names.insert(entry.profile.name.to_lowercase()),
                "A profile with this name already exists"
            );
        }
        ensure!(
            ids.contains(&self.selected_id),
            "Unknown selected profile ID"
        );
        Ok(())
    }
}

fn normalize(profile: &mut Profile) {
    profile.name = profile.name.trim().to_owned();
    profile.route_mode = profile.effective_route_mode();
    profile.use_server_routes = profile.route_mode != RouteMode::ManualOnly;
}

fn validate_profile(profile: &Profile) -> Result<()> {
    ensure!(!profile.name.trim().is_empty(), "Profile name is required");
    ensure!(
        profile.name.chars().count() <= MAX_NAME_CHARS,
        "Profile name must be at most 80 characters"
    );
    ensure!(
        !profile.name.chars().any(char::is_control),
        "Profile name cannot contain control characters"
    );
    ensure!(
        !profile.openvpn_config.starts_with("sslray-openvpn-v1:"),
        "Prepared OpenVPN configuration cannot be saved"
    );
    profile.validate()
}

fn validate_saved_password(password: Option<&str>) -> Result<()> {
    ensure!(
        password.is_none_or(|password| {
            !password.is_empty() && password.len() <= 1024 && !password.contains('\0')
        }),
        "Saved password must be 1–1024 bytes and contain no null characters"
    );
    Ok(())
}

fn json_error(kind: &str, error: &serde_json::Error) -> anyhow::Error {
    // serde errors can embed offending string values. A saved password must
    // not be copied into a notice or log while diagnosing corrupt input.
    anyhow::anyhow!(
        "Invalid {kind} JSON at line {} column {}",
        error.line(),
        error.column()
    )
}

fn read_bounded(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let mut data = Zeroizing::new(Vec::new());
    File::open(path)?
        .take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut data)?;
    ensure!(
        data.len() as u64 <= MAX_FILE_BYTES,
        "Profile library is too large"
    );
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sslray_core::config::{TransportMode, VpnProtocol};
    use std::path::PathBuf;

    struct TestDirectory(PathBuf);
    impl TestDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "sslray-profiles-test-{}-{:016x}",
                std::process::id(),
                getrandom::u64().unwrap()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn independent_profiles_and_selection_survive_roundtrip() {
        let directory = TestDirectory::new();
        let mut library = ProfileLibrary::default();
        let cisco = Profile {
            name: "Office Cisco".into(),
            protocol: VpnProtocol::Cisco,
            host: "cisco.example.com".into(),
            port: 443,
            transport: TransportMode::Tls,
            username: "other-user".into(),
            route_mode: RouteMode::ManualOnly,
            routes: vec!["192.0.2.0/24".into()],
            ..Profile::default()
        };
        let second = library.insert(cisco).unwrap();
        library.save(&directory.0).unwrap();
        let mut loaded = ProfileLibrary::load(&directory.0).unwrap();
        assert_eq!(loaded.selected_id, second);
        assert_eq!(loaded.selected().profile.protocol, VpnProtocol::Cisco);
        assert_eq!(loaded.selected().profile.routes, ["192.0.2.0/24"]);
        loaded.select(1).unwrap();
        assert_eq!(loaded.selected().profile.protocol, VpnProtocol::Huawei);
        assert!(loaded.selected().profile.routes.is_empty());
        assert!(loaded.selected().profile.username.is_empty());
        loaded.save(&directory.0).unwrap();
        assert_eq!(ProfileLibrary::load(&directory.0).unwrap().selected_id, 1);
    }

    #[test]
    fn renaming_checks_names_and_keeps_identity() {
        let mut library = ProfileLibrary::default();
        let mut profile = library.selected().profile.clone();
        profile.name = "  办公网  ".into();
        library.update_selected(profile).unwrap();
        assert_eq!(library.selected().profile.name, "办公网");
        assert_eq!(library.selected_id, 1);
        let name = library.unique_name("办公网");
        assert_eq!(name, "办公网 (2)");
        let id = library
            .insert(Profile {
                name,
                ..Profile::default()
            })
            .unwrap();
        let mut collision = library.selected().profile.clone();
        collision.name = "办公网".into();
        assert!(library.update_selected(collision).is_err());
        assert_eq!(library.selected_id, id);
        assert_eq!(library.selected().profile.name, "办公网 (2)");
        assert!(
            library
                .insert(Profile {
                    name: "COMPANY VPN".into(),
                    ..Profile::default()
                })
                .is_ok()
        );
        assert!(
            library
                .insert(Profile {
                    name: "company vpn".into(),
                    ..Profile::default()
                })
                .is_err()
        );
        for name in ["", " \t", "bad\nname", &"x".repeat(81)] {
            let profile = Profile {
                name: name.into(),
                ..Profile::default()
            };
            assert!(library.update_selected(profile).is_err());
        }
    }

    #[test]
    fn deleting_selects_neighbor_but_keeps_one_profile() {
        let mut library = ProfileLibrary::default();
        assert!(library.remove_selected().is_err());
        let id = library
            .insert(Profile {
                name: "Second".into(),
                ..Profile::default()
            })
            .unwrap();
        library.remove_selected().unwrap();
        assert_eq!(library.selected_id, 1);
        assert!(library.select(id).is_err());
        assert_eq!(library.entries.len(), 1);
    }

    #[test]
    fn legacy_migration_is_once_only_and_preserves_source() {
        let directory = TestDirectory::new();
        let profile = Profile {
            name: "Old profile".into(),
            use_server_routes: false,
            ..Profile::default()
        };
        let original = serde_json::to_vec_pretty(&profile).unwrap();
        fs::write(directory.0.join("profile.json"), &original).unwrap();
        let mut library = ProfileLibrary::load(&directory.0).unwrap();
        assert_eq!(library.selected().profile.route_mode, RouteMode::ManualOnly);
        assert_eq!(
            fs::read(directory.0.join("profile.json")).unwrap(),
            original
        );
        library
            .update_selected(Profile {
                name: "New name".into(),
                ..Profile::default()
            })
            .unwrap();
        library.save(&directory.0).unwrap();
        assert_eq!(
            ProfileLibrary::load(&directory.0)
                .unwrap()
                .selected()
                .profile
                .name,
            "New name"
        );
    }

    #[test]
    fn corrupt_and_unsupported_inputs_are_not_replaced() {
        let directory = TestDirectory::new();
        let path = directory.0.join(LIBRARY_FILE);
        for bytes in [
            b"{broken".as_slice(),
            br#"{"version":2,"selected_id":1,"entries":[]}"#,
            br#"{"version":1,"selected_id":1,"entries":[{"id":1,"profile":{}},{"id":1,"profile":{}}]}"#,
            br#"{"version":1,"selected_id":2,"entries":[{"id":1,"profile":{}}]}"#,
            br#"{"version":1,"selected_id":1,"entries":[{"id":1,"profile":{}}],"password":"forbidden"}"#,
        ] {
            fs::write(&path, bytes).unwrap();
            assert!(ProfileLibrary::load(&directory.0).is_err());
            assert_eq!(fs::read(&path).unwrap(), bytes);
        }
        fs::remove_file(&path).unwrap();
        fs::write(directory.0.join("profile.json"), b"not-json").unwrap();
        assert!(ProfileLibrary::load(&directory.0).is_err());
        assert!(!path.exists());
    }

    #[test]
    fn drafts_are_detected_and_prepared_private_material_is_rejected() {
        let mut library = ProfileLibrary::default();
        let mut draft = library.selected().profile.clone();
        assert!(library.is_current_profile(&draft));
        draft.host = "changed.example.com".into();
        assert!(!library.is_current_profile(&draft));
        library.update_selected(draft).unwrap();
        let private = Profile {
            protocol: VpnProtocol::OpenVpn,
            openvpn_config: "sslray-openvpn-v1:private-material".into(),
            ..library.selected().profile.clone()
        };
        assert!(library.update_selected(private).is_err());
        let directory = TestDirectory::new();
        library.save(&directory.0).unwrap();
        let json = fs::read_to_string(directory.0.join(LIBRARY_FILE)).unwrap();
        assert!(!json.contains("private-material"));
        assert!(!json.contains("\"password\"") && !json.contains("\"otp\""));
    }

    #[test]
    fn passwords_are_opt_in_per_profile_and_can_be_forgotten() {
        let directory = TestDirectory::new();
        let mut library = ProfileLibrary::default();
        assert!(library.selected().saved_password.is_none());
        library.save(&directory.0).unwrap();
        assert!(
            !fs::read_to_string(directory.0.join(LIBRARY_FILE))
                .unwrap()
                .contains("saved_password")
        );
        library
            .set_saved_password(Some("synthetic-test-password".into()))
            .unwrap();
        library.save(&directory.0).unwrap();
        let json = fs::read_to_string(directory.0.join(LIBRARY_FILE)).unwrap();
        assert!(!json.contains("synthetic-test-password"));
        assert!(!json.contains("\"saved_password\""));
        assert!(json.contains("\"saved_password_base64\""));
        let mut loaded = ProfileLibrary::load(&directory.0).unwrap();
        assert!(loaded.selected().saved_password.as_deref() == Some("synthetic-test-password"));
        loaded
            .insert(Profile {
                name: "Second".into(),
                ..Profile::default()
            })
            .unwrap();
        assert!(loaded.selected().saved_password.is_none());
        let second_id = loaded.selected_id;
        loaded
            .set_saved_password(Some("second-synthetic-password".into()))
            .unwrap();
        loaded.save(&directory.0).unwrap();
        loaded = ProfileLibrary::load(&directory.0).unwrap();
        assert!(loaded.selected().saved_password.as_deref() == Some("second-synthetic-password"));
        loaded.select(1).unwrap();
        assert!(loaded.selected().saved_password.as_deref() == Some("synthetic-test-password"));
        loaded.set_saved_password(None).unwrap();
        loaded.save(&directory.0).unwrap();
        assert!(
            ProfileLibrary::load(&directory.0)
                .unwrap()
                .selected()
                .saved_password
                .is_none()
        );
        let json = fs::read_to_string(directory.0.join(LIBRARY_FILE)).unwrap();
        assert!(!json.contains("synthetic-test-password"));
        assert!(!json.contains("second-synthetic-password"));
        loaded.select(second_id).unwrap();
        assert!(loaded.selected().saved_password.as_deref() == Some("second-synthetic-password"));
    }

    #[test]
    fn legacy_plaintext_password_is_reencoded_on_the_next_save() {
        let directory = TestDirectory::new();
        let path = directory.0.join(LIBRARY_FILE);
        let original = br#"{"version":1,"selected_id":1,"entries":[{"id":1,"profile":{},"saved_password":"old-synthetic-password"}]}"#;
        fs::write(&path, original).unwrap();
        let library = ProfileLibrary::load(&directory.0).unwrap();
        assert!(library.selected().saved_password.as_deref() == Some("old-synthetic-password"));
        assert!(fs::read(&path).unwrap() == original);
        library.save(&directory.0).unwrap();
        let serialized = fs::read_to_string(&path).unwrap();
        assert!(!serialized.contains("old-synthetic-password"));
        assert!(!serialized.contains("\"saved_password\""));
        assert!(serialized.contains("\"saved_password_base64\""));
        let loaded = ProfileLibrary::load(&directory.0).unwrap();
        assert!(loaded.selected().saved_password.as_deref() == Some("old-synthetic-password"));
    }

    #[test]
    fn encoded_passwords_reject_noncanonical_or_conflicting_input_without_echo() {
        let directory = TestDirectory::new();
        let path = directory.0.join(LIBRARY_FILE);
        let invalid_values = [
            serde_json::json!({"saved_password_base64":"synthetic-invalid-base64!"}),
            serde_json::json!({"saved_password_base64":"YQ"}),
            serde_json::json!({"saved_password_base64":"YR=="}),
            serde_json::json!({"saved_password_base64":"YQ==\n"}),
            serde_json::json!({"saved_password_base64":"_w=="}),
            serde_json::json!({"saved_password_base64":"/w=="}),
            serde_json::json!({"saved_password_base64":"AA=="}),
            serde_json::json!({"saved_password_base64":""}),
            serde_json::json!({"saved_password_base64":STANDARD.encode(vec![b'x';1025])}),
            serde_json::json!({"saved_password":"old-synthetic-secret","saved_password_base64":"YQ=="}),
            serde_json::json!({"saved_password":null,"saved_password_base64":"YQ=="}),
            serde_json::json!({"saved_password":"old-synthetic-secret","saved_password_base64":null}),
        ];
        for fields in invalid_values {
            let mut entry = serde_json::json!({"id":1,"profile":{}});
            entry
                .as_object_mut()
                .unwrap()
                .extend(fields.as_object().unwrap().clone());
            let document = serde_json::json!({"version":1,"selected_id":1,"entries":[entry]});
            let bytes = serde_json::to_vec(&document).unwrap();
            fs::write(&path, &bytes).unwrap();
            let error = ProfileLibrary::load(&directory.0).err().unwrap();
            let message = format!("{error:#}");
            assert!(!message.contains("synthetic"));
            assert!(!message.contains("YQ=="));
            assert!(fs::read(&path).unwrap() == bytes);
        }
    }

    #[test]
    fn base64_roundtrip_keeps_utf8_and_maximum_password_length() {
        let directory = TestDirectory::new();
        let mut library = ProfileLibrary::default();
        for password in ["测试🔑+1".to_owned(), format!("{}x", "密".repeat(341))] {
            assert!(password.len() <= 1024);
            library.set_saved_password(Some(password.clone())).unwrap();
            library.save(&directory.0).unwrap();
            let loaded = ProfileLibrary::load(&directory.0).unwrap();
            assert!(loaded.selected().saved_password.as_deref() == Some(password.as_str()));
            let json = fs::read_to_string(directory.0.join(LIBRARY_FILE)).unwrap();
            assert!(!json.contains(&password));
        }
    }

    #[test]
    fn invalid_password_does_not_replace_the_saved_value() {
        let mut library = ProfileLibrary::default();
        library
            .set_saved_password(Some("synthetic-test-password".into()))
            .unwrap();
        for password in [String::new(), "x".repeat(1025), "bad\0value".into()] {
            assert!(library.set_saved_password(Some(password)).is_err());
            assert!(
                library.selected().saved_password.as_deref() == Some("synthetic-test-password")
            );
        }
    }

    #[test]
    fn malformed_input_diagnostics_do_not_echo_passwords() {
        let directory = TestDirectory::new();
        fs::write(
            directory.0.join(LIBRARY_FILE),
            br#"{"version":1,"selected_id":"synthetic-secret-do-not-echo","entries":[]}"#,
        )
        .unwrap();
        let error = ProfileLibrary::load(&directory.0).err().unwrap();
        assert!(!format!("{error:#}").contains("synthetic-secret-do-not-echo"));
    }

    #[cfg(unix)]
    #[test]
    fn replacing_a_library_keeps_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let directory = TestDirectory::new();
        let library = ProfileLibrary::default();
        library.save(&directory.0).unwrap();
        let path = directory.0.join(LIBRARY_FILE);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        library.save(&directory.0).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 1);
    }

    #[test]
    fn oversized_input_is_rejected_before_deserialization() {
        let directory = TestDirectory::new();
        fs::write(
            directory.0.join(LIBRARY_FILE),
            vec![b' '; MAX_FILE_BYTES as usize + 1],
        )
        .unwrap();
        assert!(ProfileLibrary::load(&directory.0).is_err());
    }
}
