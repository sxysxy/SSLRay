use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransportMode {
    #[default]
    Auto,
    Tls,
    Udp,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CryptoMode {
    #[default]
    Standard,
    GmTls13,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VpnProtocol {
    #[default]
    Huawei,
    Cisco,
    OpenVpn,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RouteMode {
    #[default]
    GatewayOnly,
    Merge,
    ManualOnly,
    FullTunnel,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Profile {
    pub protocol: VpnProtocol,
    pub openvpn_config: String,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub certificate_sha256: String,
    pub transport: TransportMode,
    pub crypto: CryptoMode,
    pub routes: Vec<String>,
    pub use_server_routes: bool,
    /// Retained for reading older profiles; transport is negotiated per connection.
    /// This field no longer enables or disables legacy CHIV UDP.
    pub allow_legacy_udp: bool,
    pub route_mode: RouteMode,
    pub mtu: u16,
}
impl Default for Profile {
    fn default() -> Self {
        Self {
            protocol: VpnProtocol::Huawei,
            openvpn_config: String::new(),
            name: "Company VPN".into(),
            host: "vpn-bj.metaradio.tech".into(),
            port: 4433,
            username: String::new(),
            certificate_sha256: String::new(),
            transport: TransportMode::Auto,
            crypto: CryptoMode::Standard,
            routes: vec![],
            use_server_routes: true,
            allow_legacy_udp: false,
            route_mode: RouteMode::GatewayOnly,
            mtu: 1400,
        }
    }
}
impl Profile {
    pub fn effective_route_mode(&self) -> RouteMode {
        if matches!(self.route_mode, RouteMode::GatewayOnly | RouteMode::Merge)
            && !self.use_server_routes
        {
            RouteMode::ManualOnly
        } else {
            self.route_mode
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.crypto != CryptoMode::GmTls13 || self.transport != TransportMode::Udp,
            "Strict GM TLS mode cannot use AES UDP transport; select TLS or Auto"
        );
        if self.protocol == VpnProtocol::OpenVpn {
            ensure!(
                !self.openvpn_config.is_empty()
                    && self.openvpn_config.len()
                        <= if self.openvpn_config.starts_with("sslray-openvpn-v1:") {
                            256 * 1024
                        } else {
                            4096
                        }
                    && !self.openvpn_config.contains('\0'),
                "Select an OpenVPN .ovpn configuration file"
            );
            ensure!(
                self.crypto == CryptoMode::Standard,
                "OpenVPN does not support the GM TLS mode; select standard cryptography"
            );
        }
        ensure!(
            self.protocol != VpnProtocol::Cisco || self.transport != TransportMode::Udp,
            "Cisco currently supports TLS/CSTP only; select TLS or Auto"
        );
        if self.protocol != VpnProtocol::OpenVpn {
            ensure!(
                !self.host.is_empty() && self.host.len() <= 253,
                "Invalid gateway host"
            );
            ensure!(
                self.host
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b".-:".contains(&c)),
                "Gateway must be a hostname or IP address"
            );
            ensure!(self.port > 0, "Invalid gateway port");
        }
        ensure!((576..=1500).contains(&self.mtu), "MTU must be 576..1500");
        ensure!(
            self.username.len() <= 256 && !self.username.contains(['\r', '\n']),
            "Invalid username"
        );
        if !self.certificate_sha256.is_empty() {
            let pin = self.certificate_sha256.replace(':', "");
            ensure!(
                pin.len() == 64 && pin.bytes().all(|b| b.is_ascii_hexdigit()),
                "Certificate pin must be a SHA-256 fingerprint"
            );
        }
        if matches!(
            self.effective_route_mode(),
            RouteMode::Merge | RouteMode::ManualOnly
        ) {
            for route in &self.routes {
                let _: crate::platform::Ipv4Route = route.parse()?;
            }
        }
        Ok(())
    }
}

impl std::fmt::Debug for Profile {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Profile")
            .field("protocol", &self.protocol)
            .field("name", &self.name)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("route_mode", &self.route_mode)
            .field("transport", &self.transport)
            .field("crypto", &self.crypto)
            .field("openvpn_configured", &!self.openvpn_config.is_empty())
            .finish_non_exhaustive()
    }
}

impl zeroize::Zeroize for Profile {
    fn zeroize(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.openvpn_config);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_profile_uses_only_gateway_routes_without_full_tunnel() {
        let profile: Profile = serde_json::from_str("{}").unwrap();
        assert_eq!(profile.route_mode, RouteMode::GatewayOnly);
        assert!(profile.use_server_routes && profile.routes.is_empty());
        assert_eq!(profile.protocol, VpnProtocol::Huawei);
    }

    #[test]
    fn inactive_manual_routes_are_ignored_but_legacy_manual_policy_is_preserved() {
        let mut profile = Profile {
            routes: vec!["invalid inactive value".into()],
            ..Profile::default()
        };
        profile.validate().unwrap();
        profile.use_server_routes = false;
        assert_eq!(profile.effective_route_mode(), RouteMode::ManualOnly);
        assert!(profile.validate().is_err());
    }

    #[test]
    fn old_legacy_udp_flags_remain_readable_without_changing_transport_policy() {
        for flag in [false, true] {
            let profile: Profile = serde_json::from_str(&format!(
                r#"{{"allow_legacy_udp":{flag},"transport":"auto"}}"#
            ))
            .unwrap();
            assert_eq!(profile.allow_legacy_udp, flag);
            assert_eq!(profile.transport, TransportMode::Auto);
            profile.validate().unwrap();
        }
    }

    #[test]
    fn strict_gm_udp_fails_during_profile_validation() {
        let mut profile = Profile {
            crypto: CryptoMode::GmTls13,
            transport: TransportMode::Udp,
            ..Profile::default()
        };
        assert!(
            profile
                .validate()
                .unwrap_err()
                .to_string()
                .contains("GM TLS")
        );
        profile.transport = TransportMode::Auto;
        profile.validate().unwrap();
        profile.transport = TransportMode::Tls;
        profile.validate().unwrap();
    }
}
