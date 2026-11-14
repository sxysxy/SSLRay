//! Bind a certificate decision to the exact endpoint and connection policy.
//! A temporary certificate pin is applied only to a connection copy.

use sslray_core::config::{CryptoMode, Profile, TransportMode, VpnProtocol};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificateTarget {
    pub profile_id: u64,
    pub protocol: VpnProtocol,
    pub host: String,
    pub port: u16,
    pub crypto: CryptoMode,
    pub transport: TransportMode,
    pub configured_pin: String,
}

impl CertificateTarget {
    pub fn new(profile_id: u64, profile: &Profile) -> Self {
        Self {
            profile_id,
            protocol: profile.protocol,
            host: profile.host.clone(),
            port: profile.port,
            crypto: profile.crypto,
            transport: profile.transport,
            configured_pin: profile.certificate_sha256.clone(),
        }
    }

    pub fn endpoint(&self) -> String {
        if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

pub struct CertificateApproval {
    pub target: CertificateTarget,
    pub certificate_sha256: Option<String>,
}

impl CertificateApproval {
    /// Return a connection-only copy if this decision still matches the
    /// selected profile. Existing pins can never be replaced by an approval.
    pub fn connection_profile(&self, profile_id: u64, profile: &Profile) -> Option<Profile> {
        if self.target != CertificateTarget::new(profile_id, profile) {
            return None;
        }
        if let Some(pin) = &self.certificate_sha256
            && (!self.target.configured_pin.is_empty()
                || pin.len() != 64
                || !pin.bytes().all(|byte| byte.is_ascii_hexdigit()))
        {
            return None;
        }
        let mut connection = profile.clone();
        if let Some(pin) = &self.certificate_sha256 {
            connection.certificate_sha256.clone_from(pin);
        }
        Some(connection)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temporary_approval(profile_id: u64, profile: &Profile) -> CertificateApproval {
        CertificateApproval {
            target: CertificateTarget::new(profile_id, profile),
            certificate_sha256: Some("a1".repeat(32)),
        }
    }

    #[test]
    fn changing_any_bound_target_field_invalidates_approval() {
        let profile = Profile::default();
        let approval = temporary_approval(7, &profile);
        assert!(approval.connection_profile(7, &profile).is_some());
        assert!(approval.connection_profile(8, &profile).is_none());
        let changes: [fn(&mut Profile); 6] = [
            |profile| profile.host = "another.example".into(),
            |profile| profile.port += 1,
            |profile| profile.protocol = VpnProtocol::Cisco,
            |profile| profile.crypto = CryptoMode::GmTls13,
            |profile| profile.transport = TransportMode::Tls,
            |profile| profile.certificate_sha256 = "b2".repeat(32),
        ];
        for change in changes {
            let mut changed = profile.clone();
            change(&mut changed);
            assert!(approval.connection_profile(7, &changed).is_none());
        }
    }

    #[test]
    fn session_pin_changes_only_the_connection_copy() {
        let profile = Profile {
            username: "synthetic-user".into(),
            routes: vec!["192.0.2.0/24".into()],
            ..Profile::default()
        };
        let before = serde_json::to_value(&profile).unwrap();
        let approval = temporary_approval(7, &profile);
        let connection = approval.connection_profile(7, &profile).unwrap();
        assert_eq!(connection.certificate_sha256, "a1".repeat(32));
        assert_eq!(serde_json::to_value(&profile).unwrap(), before);
        let mut expected = before;
        expected["certificate_sha256"] = serde_json::Value::String("a1".repeat(32));
        assert_eq!(serde_json::to_value(&connection).unwrap(), expected);
    }

    #[test]
    fn temporary_pin_requires_exactly_64_ascii_hex_digits() {
        let profile = Profile::default();
        for pin in [
            String::new(),
            "a".repeat(63),
            "a".repeat(65),
            "g".repeat(64),
            "aa:".repeat(21) + "a",
            "a".repeat(63) + "\n",
            "Ａ".repeat(64),
        ] {
            let approval = CertificateApproval {
                target: CertificateTarget::new(7, &profile),
                certificate_sha256: Some(pin),
            };
            assert!(approval.connection_profile(7, &profile).is_none());
        }
        let approval = CertificateApproval {
            target: CertificateTarget::new(7, &profile),
            certificate_sha256: Some("AbCdEf0123456789".repeat(4)),
        };
        assert!(approval.connection_profile(7, &profile).is_some());
    }

    #[test]
    fn an_approval_cannot_replace_even_a_matching_existing_pin() {
        let profile = Profile {
            certificate_sha256: "a1".repeat(32),
            ..Profile::default()
        };
        let approval = temporary_approval(7, &profile);
        assert!(approval.connection_profile(7, &profile).is_none());
        assert_eq!(profile.certificate_sha256, "a1".repeat(32));
    }

    #[test]
    fn trusted_certificate_keeps_the_original_ca_policy_without_a_pin() {
        let profile = Profile::default();
        let approval = CertificateApproval {
            target: CertificateTarget::new(7, &profile),
            certificate_sha256: None,
        };
        let connection = approval.connection_profile(7, &profile).unwrap();
        assert!(connection.certificate_sha256.is_empty());
        assert_eq!(
            serde_json::to_value(&connection).unwrap(),
            serde_json::to_value(&profile).unwrap()
        );
    }

    #[test]
    fn endpoint_brackets_ipv6_addresses() {
        for (host, expected) in [
            ("vpn.example", "vpn.example:4433"),
            ("192.0.2.1", "192.0.2.1:4433"),
            ("2001:db8::1", "[2001:db8::1]:4433"),
            ("[2001:db8::1]", "[2001:db8::1]:4433"),
        ] {
            let profile = Profile {
                host: host.into(),
                ..Profile::default()
            };
            assert_eq!(CertificateTarget::new(7, &profile).endpoint(), expected);
        }
    }
}
