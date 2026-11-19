use crate::{
    config::{Profile, RouteMode, VpnProtocol},
    gateway::{Gateway, valid_ipv4},
    platform::{Ipv4Route, RouteGuard, Tunnel},
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    io::ErrorKind,
    net::{IpAddr, Ipv4Addr, ToSocketAddrs},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    Status {
        message: String,
    },
    Connected {
        interface: String,
        address: String,
        cipher: String,
        transport: String,
    },
    Stats {
        tx_bytes: u64,
        rx_bytes: u64,
        elapsed_secs: u64,
    },
    Routes {
        advertised_routes: Vec<String>,
        applied_routes: Vec<String>,
    },
    Challenge {
        method: String,
    },
    Disconnected,
    Error {
        message: String,
    },
}

/// Runs in the privileged helper; GUI credentials are consumed by the gateway only.
pub fn run(
    profile: &Profile,
    password: &str,
    otp: Option<&str>,
    cancel: Arc<AtomicBool>,
    emit: impl FnMut(Event),
) -> Result<()> {
    run_with_challenge(profile, password, cancel, emit, |_| {
        if let Some(otp) = otp {
            Ok(zeroize::Zeroizing::new(otp.to_owned()))
        } else {
            Err(crate::gateway::AuthError::ChallengeRequired.into())
        }
    })
}

pub fn run_with_challenge(
    profile: &Profile,
    password: &str,
    cancel: Arc<AtomicBool>,
    mut emit: impl FnMut(Event),
    challenge: impl FnMut(&str) -> Result<zeroize::Zeroizing<String>>,
) -> Result<()> {
    profile.validate()?;
    let mode = profile.effective_route_mode();
    let manual_routes = if matches!(mode, RouteMode::Merge | RouteMode::ManualOnly) {
        profile.routes.as_slice()
    } else {
        &[]
    };
    let mut routes: Vec<Ipv4Route> = manual_routes
        .iter()
        .map(|r| r.parse())
        .collect::<Result<_>>()?;
    let mut endpoints: Vec<_> = if profile.protocol == VpnProtocol::OpenVpn {
        vec![] // The .ovpn engine supplies its actual selected socket peer below.
    } else {
        (profile.host.as_str(), profile.port)
            .to_socket_addrs()?
            .filter_map(|a| {
                if let IpAddr::V4(ip) = a.ip() {
                    Some(ip)
                } else {
                    None
                }
            })
            .collect()
    };
    // Never install a route which would recursively capture the outer tunnel.
    for r in &routes {
        ensure!(
            !endpoints.iter().any(|ip| r.contains(*ip)),
            "A requested route contains the VPN gateway; use narrower split routes"
        );
    }
    if cancel.load(Ordering::Relaxed) {
        return Ok(());
    }
    emit(Event::Status {
        message: match profile.protocol {
            VpnProtocol::Huawei => "Authenticating with Huawei NEM gateway",
            VpnProtocol::Cisco => "Authenticating with Cisco AnyConnect gateway",
            VpnProtocol::OpenVpn => "Authenticating with OpenVPN server",
        }
        .into(),
    });
    let mut gateway = Gateway::connect_with_callbacks(profile, password, challenge, |message| {
        emit(Event::Status {
            message: message.into(),
        });
    })?;
    let session_result: Result<()> = (|| {
        if cancel.load(Ordering::Relaxed) {
            return Ok(());
        }
        for address in gateway.outer_ipv4_addresses()? {
            if !endpoints.contains(&address) {
                endpoints.push(address);
            }
        }
        for route in &routes {
            ensure!(
                !endpoints.iter().any(|ip| route.contains(*ip)),
                "A requested route contains the actual VPN peer; use narrower split routes"
            );
        }
        emit(Event::Routes {
            advertised_routes: gateway.routes.clone(),
            applied_routes: vec![],
        });
        if matches!(mode, RouteMode::GatewayOnly | RouteMode::Merge) {
            for value in &gateway.routes {
                let Ok(route) = value.parse::<Ipv4Route>() else {
                    emit(Event::Status {
                        message: format!("Skipped unsupported server route {value}"),
                    });
                    continue;
                };
                if matches!(route.to_string().as_str(), "0.0.0.0/1" | "128.0.0.0/1") {
                    emit(Event::Status {
                        message: format!(
                            "Skipped server default-route overlay {value}; select Full Tunnel to route all IPv4 traffic"
                        ),
                    });
                    continue;
                }
                if endpoints.iter().any(|ip| route.contains(*ip)) {
                    emit(Event::Status {
                        message: format!("Skipped server route {value} covering outer VPN gateway"),
                    });
                } else if !routes.contains(&route) {
                    routes.push(route);
                }
            }
        }
        emit(Event::Status {
            message: format!(
                "Creating virtual interface with {} split routes",
                routes.len()
            ),
        });
        let mtu = profile
            .mtu
            .min(gateway.negotiated_mtu.unwrap_or(profile.mtu));
        let mut tunnel = Tunnel::create(gateway.vip, mtu)?;
        let mut guard = if mode == RouteMode::FullTunnel {
            RouteGuard::install_full(tunnel.name(), &endpoints)?
        } else {
            RouteGuard::install(
                tunnel.name(),
                &routes,
                endpoints.first().copied().unwrap_or(gateway.vip),
            )?
        };
        emit(Event::Routes {
            advertised_routes: gateway.routes.clone(),
            applied_routes: if mode == RouteMode::FullTunnel {
                vec!["0.0.0.0/1".into(), "128.0.0.0/1".into()]
            } else {
                routes.iter().map(ToString::to_string).collect()
            },
        });
        emit(Event::Connected {
            interface: tunnel.name().into(),
            address: gateway.vip.to_string(),
            cipher: gateway.cipher.clone(),
            transport: gateway.transport.clone(),
        });
        emit(Event::Status {
            message: format!("Negotiated transport: {}", gateway.transport),
        });
        if routes.is_empty() && mode != RouteMode::FullTunnel {
            emit(Event::Status {
                message:
                    "No split routes configured; add company CIDRs in Settings to carry traffic"
                        .into(),
            });
        }
        let started = Instant::now();
        let (mut tx, mut rx) = (0u64, 0u64);
        let mut last_stats = Instant::now();
        let mut business_activity = BusinessReadBudget::default();
        let mut packet = vec![0u8; 65536];
        let required_source = gateway
            .requires_assigned_ipv4_source()
            .then_some(gateway.vip);
        let mut source_drops = SourceDropCounter::default();
        let result: Result<()> = (|| {
            while !cancel.load(Ordering::Relaxed) {
                for _ in 0..32 {
                    match tunnel.read_packet(&mut packet) {
                        Ok(0) => break,
                        Ok(n) => {
                            if packet[0] >> 4 == 4 {
                                let sent =
                                    forward_tun_ipv4(&packet[..n], required_source, |bytes| {
                                        gateway.send_packet(bytes)
                                    })?;
                                if sent != 0 {
                                    tx += sent as u64;
                                    business_activity.record(Instant::now());
                                } else if let Some(message) = source_drops.record(Instant::now()) {
                                    emit(Event::Status { message });
                                }
                            }
                        }
                        Err(e)
                            if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) =>
                        {
                            break;
                        }
                        Err(e) => return Err(e.into()),
                    }
                }
                gateway.set_read_budget(business_activity.at(Instant::now()))?;
                gateway.keepalive()?;
                if let Some(data) = gateway.read_packet()? {
                    business_activity.record(Instant::now());
                    let n = tunnel.write_packet(&data)?;
                    ensure!(n == data.len(), "Incomplete virtual interface packet write");
                    rx += n as u64;
                }
                if last_stats.elapsed() >= Duration::from_secs(1) {
                    emit(Event::Stats {
                        tx_bytes: tx,
                        rx_bytes: rx,
                        elapsed_secs: started.elapsed().as_secs(),
                    });
                    last_stats = Instant::now();
                }
            }
            Ok(())
        })();
        guard.cleanup()?;
        emit(Event::Routes {
            advertised_routes: gateway.routes.clone(),
            applied_routes: vec![],
        });
        result?;
        Ok(())
    })();
    gateway.disconnect();
    session_result?;
    emit(Event::Disconnected);
    Ok(())
}

/// Discard only a valid foreign-source packet for a channel that requires VIP.
/// Other channels keep their existing policy; backend and I/O failures propagate.
fn forward_tun_ipv4(
    packet: &[u8],
    required_source: Option<Ipv4Addr>,
    send: impl FnOnce(&[u8]) -> Result<()>,
) -> Result<usize> {
    ensure!(
        valid_ipv4(packet),
        "TUN supplied malformed or unsupported IPv4 packet"
    );
    if required_source.is_some_and(|assigned| packet[12..16] != assigned.octets()) {
        return Ok(0);
    }
    send(packet)?;
    Ok(packet.len())
}

#[derive(Default)]
struct SourceDropCounter {
    total: u64,
    last_report: Option<Instant>,
}
impl SourceDropCounter {
    fn record(&mut self, now: Instant) -> Option<String> {
        self.total = self.total.saturating_add(1);
        if self
            .last_report
            .is_none_or(|last| now.saturating_duration_since(last) >= Duration::from_secs(30))
        {
            self.last_report = Some(now);
            Some(format!(
                "Dropped local IPv4 packets outside the assigned VPN source address (total {})",
                self.total
            ))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod source_drop_tests {
    use super::*;
    fn packet(source: Ipv4Addr) -> Vec<u8> {
        let mut bytes = vec![0; 28];
        bytes[0] = 0x45;
        bytes[2..4].copy_from_slice(&28u16.to_be_bytes());
        bytes[12..16].copy_from_slice(&source.octets());
        bytes[16..20].copy_from_slice(&[192, 0, 2, 1]);
        bytes
    }
    #[test]
    fn required_source_drop_is_not_sent_or_counted_and_next_valid_packet_survives() {
        let assigned = Ipv4Addr::new(192, 0, 2, 2);
        let wrong = packet(Ipv4Addr::new(192, 0, 2, 99));
        let valid = packet(assigned);
        let mut sent = Vec::new();
        let rejected = forward_tun_ipv4(&wrong, Some(assigned), |bytes| {
            sent.push(bytes.to_vec());
            Ok(())
        })
        .unwrap();
        assert_eq!(rejected, 0);
        assert!(sent.is_empty());
        let forwarded = forward_tun_ipv4(&valid, Some(assigned), |bytes| {
            sent.push(bytes.to_vec());
            Ok(())
        })
        .unwrap();
        assert_eq!(forwarded, valid.len());
        assert_eq!(sent, [valid]);
    }
    #[test]
    fn no_source_requirement_preserves_packet_and_backend_policy() {
        let foreign = packet(Ipv4Addr::new(192, 0, 2, 99));
        let mut sent = Vec::new();
        let bytes = forward_tun_ipv4(&foreign, None, |packet| {
            sent.push(packet.to_vec());
            Ok(())
        })
        .unwrap();
        assert_eq!(bytes, foreign.len());
        assert_eq!(sent.as_slice(), std::slice::from_ref(&foreign));
        let error = forward_tun_ipv4(&foreign, None, |_| {
            Err(anyhow::anyhow!("synthetic backend source policy"))
        })
        .unwrap_err();
        assert_eq!(error.to_string(), "synthetic backend source policy");
    }
    #[test]
    fn malformed_packet_and_real_send_error_remain_fatal_for_both_policies() {
        let assigned = Ipv4Addr::new(192, 0, 2, 2);
        for required_source in [None, Some(assigned)] {
            let mut malformed = packet(Ipv4Addr::new(192, 0, 2, 99));
            malformed[3] = 29;
            let mut called = false;
            let error = forward_tun_ipv4(&malformed, required_source, |_| {
                called = true;
                Ok(())
            })
            .unwrap_err();
            assert_eq!(
                error.to_string(),
                "TUN supplied malformed or unsupported IPv4 packet"
            );
            assert!(!called);
            let error = forward_tun_ipv4(&packet(assigned), required_source, |_| {
                Err(anyhow::anyhow!("synthetic socket failure"))
            })
            .unwrap_err();
            assert_eq!(error.to_string(), "synthetic socket failure");
        }
    }
    #[test]
    fn drop_warning_counts_all_drops_is_rate_limited_and_contains_count_only() {
        let start = Instant::now();
        let mut count = SourceDropCounter::default();
        assert_eq!(
            count.record(start).as_deref(),
            Some("Dropped local IPv4 packets outside the assigned VPN source address (total 1)")
        );
        for _ in 0..1000 {
            assert!(count.record(start + Duration::from_secs(1)).is_none());
        }
        assert!(
            count
                .record(start + Duration::from_millis(29_999))
                .is_none()
        );
        assert_eq!(
            count.record(start + Duration::from_secs(30)).as_deref(),
            Some("Dropped local IPv4 packets outside the assigned VPN source address (total 1003)")
        );
        count.total = u64::MAX;
        assert_eq!(
            count.record(start + Duration::from_secs(60)).unwrap(),
            format!(
                "Dropped local IPv4 packets outside the assigned VPN source address (total {})",
                u64::MAX
            )
        );
    }
}

const BUSINESS_ACTIVE_WINDOW: Duration = Duration::from_millis(500);
#[derive(Default)]
struct BusinessReadBudget {
    last_business: Option<Instant>,
}
impl BusinessReadBudget {
    fn record(&mut self, now: Instant) {
        self.last_business = Some(now);
    }
    fn at(&self, now: Instant) -> Duration {
        if self
            .last_business
            .is_some_and(|last| now.saturating_duration_since(last) < BUSINESS_ACTIVE_WINDOW)
        {
            Duration::from_millis(1)
        } else {
            Duration::from_millis(50)
        }
    }
}

#[cfg(test)]
mod business_budget_tests {
    use super::*;
    #[test]
    fn activity_window_expires_instead_of_polling_fast_forever() {
        let now = Instant::now();
        let mut budget = BusinessReadBudget::default();
        assert_eq!(budget.at(now), Duration::from_millis(50));
        budget.record(now);
        assert_eq!(
            budget.at(now + Duration::from_millis(499)),
            Duration::from_millis(1)
        );
        assert_eq!(
            budget.at(now + Duration::from_millis(500)),
            Duration::from_millis(50)
        );
        assert_eq!(
            budget.at(now + Duration::from_secs(15)),
            Duration::from_millis(50)
        );
    }
    #[test]
    fn business_receive_restarts_window_for_late_kernel_ack() {
        let now = Instant::now();
        let mut budget = BusinessReadBudget::default();
        budget.record(now);
        budget.record(now + Duration::from_millis(450));
        assert_eq!(
            budget.at(now + Duration::from_millis(700)),
            Duration::from_millis(1)
        );
        assert_eq!(
            budget.at(now + Duration::from_millis(950)),
            Duration::from_millis(50)
        );
    }
    #[test]
    fn recurring_idle_queries_do_not_renew_activity() {
        let now = Instant::now();
        let mut budget = BusinessReadBudget::default();
        budget.record(now);
        for second in 1..=60 {
            // Control ACKs/probes yield no business packet and do not call record.
            assert_eq!(
                budget.at(now + Duration::from_secs(second)),
                Duration::from_millis(50)
            );
        }
    }
}
