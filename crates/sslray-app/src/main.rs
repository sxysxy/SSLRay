#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![cfg_attr(
    all(windows, not(debug_assertions), not(test)),
    windows_subsystem = "windows"
)]

mod certificate_gate;
mod certificate_ui;
mod diagnostics;
mod error_ui;
mod i18n;
mod profiles;
mod runtime;
mod system_info;
mod tray;
mod ui;
#[cfg(any(test, all(windows, not(debug_assertions))))]
mod windows_console;

use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};
use sslray_core::{
    config::{CryptoMode, Profile, TransportMode, VpnProtocol},
    crypto,
    gateway::Gateway,
};
use std::{
    io::{BufRead, Read},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(name = "sslray", version, about = "Native Rust Huawei SSL VPN client")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
    #[arg(long, hide = true)]
    helper: bool,
    #[arg(long, hide = true)]
    port: Option<u16>,
    #[arg(long, hide = true)]
    token: Option<String>,
    #[arg(long, hide = true)]
    socket: Option<PathBuf>,
    #[arg(long, hide = true)]
    parent_pid: Option<u32>,
}
#[derive(Subcommand)]
enum Command {
    /// Discover a gateway certificate without sending credentials.
    Inspect {
        #[arg(long, default_value = "vpn-bj.metaradio.tech")]
        host: String,
        #[arg(long, default_value_t = 4433)]
        port: u16,
    },
    /// Show linked TLS backend and actual GM capabilities.
    Capabilities,
    /// Authenticate and establish both TLS channels; no interface or routes changed.
    AuthTest {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        otp: bool,
        #[arg(long)]
        password_stdin: bool,
    },
    /// Run a VPN in the foreground (requests administrator access when necessary).
    Connect {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        otp: bool,
        #[arg(long)]
        password_stdin: bool,
    },
    /// Write a credential-free example connection profile.
    Example {
        #[arg(long)]
        output: PathBuf,
    },
}
fn load_profile(path: &PathBuf) -> Result<Profile> {
    let p: Profile = serde_json::from_slice(&std::fs::read(path)?)?;
    p.validate()?;
    Ok(p)
}
fn credentials(
    with_otp: bool,
    stdin: bool,
    allow_empty: bool,
) -> Result<(Zeroizing<String>, Option<Zeroizing<String>>)> {
    let password = if stdin {
        let mut line = Zeroizing::new(String::new());
        std::io::stdin().lock().take(1026).read_line(&mut line)?;
        Zeroizing::new(line.trim_end_matches(['\r', '\n']).to_owned())
    } else {
        Zeroizing::new(rpassword::prompt_password("VPN password: ")?)
    };
    ensure!(
        (allow_empty || !password.is_empty()) && password.len() <= 1024 && !password.contains('\0'),
        "Password must be at most 1024 bytes, without NUL characters; password authentication requires a nonempty value"
    );
    let otp = if with_otp {
        Some(Zeroizing::new(rpassword::prompt_password(
            "Temporary second password: ",
        )?))
    } else {
        None
    };
    Ok((password, otp))
}
fn main() -> Result<()> {
    #[cfg(all(windows, not(debug_assertions), not(test)))]
    windows_console::prepare_for_cli();
    let cli = Cli::parse();
    if cli.helper {
        return runtime::helper(
            cli.port,
            cli.socket.as_deref(),
            cli.parent_pid,
            &cli.token.context("Missing helper token")?,
        );
    }
    match cli.command {
        None => ui::run(),
        Some(Command::Capabilities) => {
            println!("{}", serde_json::to_string_pretty(&crypto::capabilities())?);
            Ok(())
        }
        Some(Command::Inspect { host, port }) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&crypto::inspect(&Profile {
                    host,
                    port,
                    ..Profile::default()
                })?)?
            );
            Ok(())
        }
        Some(Command::Example { output }) => {
            let p = Profile {
                username: "your-username".into(),
                transport: TransportMode::Tls,
                crypto: CryptoMode::Standard,
                ..Profile::default()
            };
            std::fs::write(output, serde_json::to_string_pretty(&p)?)?;
            Ok(())
        }
        Some(Command::AuthTest {
            profile,
            otp,
            password_stdin,
        }) => {
            let p = Zeroizing::new(sslray_core::openvpn::prepare(&load_profile(&profile)?)?);
            let (password, otp) =
                credentials(otp, password_stdin, p.protocol == VpnProtocol::OpenVpn)?;
            let mut gateway = Gateway::connect(&p, &password, otp.as_ref().map(|s| s.as_str()))?;
            println!(
                "{}",
                serde_json::json!({"authenticated":true,"data_channel":true,"address":gateway.vip.to_string(),"cipher":gateway.cipher,"network_changed":false})
            );
            gateway.disconnect();
            Ok(())
        }
        Some(Command::Connect {
            profile,
            otp,
            password_stdin,
        }) => {
            let p = load_profile(&profile)?;
            let (password, otp) =
                credentials(otp, password_stdin, p.protocol == VpnProtocol::OpenVpn)?;
            let cancel = Arc::new(AtomicBool::new(false));
            let signal = cancel.clone();
            ctrlc::set_handler(move || signal.store(true, Ordering::Relaxed))?;
            runtime::foreground(p, password, otp, cancel)
        }
    }
}
