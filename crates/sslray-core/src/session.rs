use crate::{
    config::{Profile, RouteMode, VpnProtocol},
    gateway::Gateway,
    platform::{Ipv4Route, RouteGuard, Tunnel},
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    io::ErrorKind,
    net::{IpAddr, ToSocketAddrs},
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
        let mut packet = vec![0u8; 65536];
        let result: Result<()> = (|| {
            while !cancel.load(Ordering::Relaxed) {
                let mut outgoing = false;
                for _ in 0..32 {
                    match tunnel.read_packet(&mut packet) {
                        Ok(0) => break,
                        Ok(n) => {
                            if packet[0] >> 4 == 4 {
                                gateway.send_packet(&packet[..n])?;
                                tx += n as u64;
                                outgoing = true;
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
                gateway.set_read_budget(Duration::from_millis(if outgoing { 1 } else { 50 }))?;
                gateway.keepalive()?;
                if let Some(data) = gateway.read_packet()? {
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
