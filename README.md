# SSLRay

**English** | [简体中文](README.zh-CN.md)

A Rust SSL VPN desktop client with an egui interface, named profiles, a system tray, background operation, Chinese/English localization, and light/dark themes. See the [platform validation record](docs/VALIDATION.md) for the tested scope of version 0.1.0.

Licensed under **GPL-3.0-or-later** with the [Wintun linking permission](LICENSE-WINTUN-EXCEPTION). See [LICENSE](LICENSE), [COPYRIGHT](COPYRIGHT), and the [third-party notices](docs/THIRD-PARTY.md).

| Protocol | Implementation | Validated environment |
| --- | --- | --- |
| Huawei SecoClient / UniVPN NEM | TLS, experimental UDP, recognized second-password challenges | Real gateway device: TLS/legacy UDP IP round trips and SSH through utun |
| Cisco AnyConnect | XML authentication and TLS/CSTP; no DTLS yet | Local ocserv; no Cisco hardware testing |
| OpenVPN | Native Rust engine, certificate/password authentication, TCP/UDP | Local OpenVPN 2.6.20, UDP / AES-256-GCM |

Only IPv4 traffic is carried. System DNS changes, a kill switch, and automatic reconnection are not implemented. RFC 8998 TLS 1.3 (SM2/SM3/SM4) requires support from both the cryptographic backend and gateway; OpenVPN does not support this mode. TLCP dual certificates and USBKey support are not implemented. See [validation status](docs/VALIDATION.md) for the tested scope.

## Build and run

Requires Rust 1.95+ and the [platform dependencies](docs/PLATFORMS.md). The platform wrappers compile the pinned official OpenSSL submodule and link it statically, without Homebrew OpenSSL.

```sh
git submodule update --init third_party/openssl
./scripts/cargo-macos.sh run -p sslray --locked
```

The complete source archive contains OpenSSL; its Git initialization step can be skipped.

Build a macOS development bundle with the same backend:

```sh
./scripts/bundle-macos.sh
open dist/SSLRay.app
```

The script collects licenses, includes the shared application icon, and applies an ad-hoc signature. The default Apple Silicon deployment target is macOS 11.0; older systems still require runtime validation. Public macOS distribution additionally needs Developer ID signing and notarization.

| Platform | Cargo wrapper | Packaging |
| --- | --- | --- |
| macOS | `scripts/cargo-macos.sh` | `scripts/bundle-macos.sh` → `.app` |
| Linux | `scripts/cargo-linux.sh` | [Linux build](docs/LINUX-BUILD.md) → `.tar.gz` |
| Windows x64 | `scripts/cargo-windows.ps1` | [Windows build](docs/WINDOWS-BUILD.md) → ZIP with the official Wintun DLL |

## Connect

1. Create a uniquely named profile in **Settings**. Enter the gateway and account for Huawei/Cisco, or use **Browse…** to select an OpenVPN `.ovpn` file.
2. Huawei/Cisco verify certificates by default. For self-signed, expired, or name-mismatched certificates, review the warning and fingerprint before continuing. **Remember this certificate** saves its fingerprint to the selected profile; changed certificates are rejected. OpenVPN follows its `.ovpn` CA/server identity policy.
3. By default, only valid gateway-advertised split routes are used; the manual list is empty. Full tunnel requires explicit selection. Advertised and applied routes are shown separately as read-only lists.
4. Save the profile, select it by name in **Overview**, and connect. A missing main password is requested for that connection. OTPs may be entered in advance or when the gateway sends a challenge.
5. The first connection requests administrator authorization. The helper can be reused within the same app process. New connections require authorization again after 10 minutes idle or a one-hour authorization lifetime; an active tunnel is not interrupted. Failed authorization can be retried manually.

Profiles can be duplicated, renamed, or deleted; switching prompts you to handle unsaved changes. **Application settings** contains appearance, language, the active SSLRay adapter, and the software version. When the tray is available, closing the window hides it; quitting the app ends the session.

Main passwords are not saved by default. Enabling **Save main password locally** stores **Base64** in local `profiles.json`; the confirmation shows its full path. Base64 is reversible, not encryption, and the stored configuration is not uploaded to the cloud. **OTPs are never saved.** See [system and configuration details](docs/PLATFORMS.md) for migration, permissions, and routing policies.

Standard mode automatically negotiates legacy Huawei CHIV3 UDP when available; Auto returns to TLS if negotiation fails. CHIV3 uses AES-128-CBC without a per-packet MAC; TLS remains selectable. GM uses TLS and never downgrades its algorithms.

## Command line

On macOS, replace `cargo` below with `./scripts/cargo-macos.sh` to use the project backend.

```sh
cargo run -p sslray -- capabilities
cargo run -p sslray -- inspect --host vpn.example.com --port 443
cargo run -p sslray -- example --output profile.json
cargo run -p sslray -- auth-test --profile profile.json
cargo run -p sslray -- connect --profile profile.json
```

`auth-test` does not modify host interfaces or routes. `connect` runs in the foreground; Ctrl-C disconnects and cleans up. The CLI uses a single-profile JSON file and a hidden password prompt; automation can use `--password-stdin`, and `--otp` requests a second password. Do not put credentials in command arguments, environment variables, or version control.

## Development and documentation

The macOS Cargo wrapper also accepts `test`, `clippy`, and other Cargo commands.

`sslray-core` is the protocol, cryptography, interface, and routing library. `sslray-app` provides the GUI/CLI and manages a privileged helper subprocess of the same executable over authenticated local IPC. The helper calls core to run the tunnel; the UI remains unprivileged.

```sh
cargo fmt --all -- --check
cargo test --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
```

- [Platforms, authorization, and routing](docs/PLATFORMS.md)
- [Huawei NEM](docs/HWNEM.md) · [Cisco](docs/CISCO.md) · [OpenVPN](docs/OPENVPN.md)
- [GM TLS backend](docs/GM-VALIDATION.md)
- [Validation status and reproduction](docs/VALIDATION.md)
- [Third-party sources and licenses](docs/THIRD-PARTY.md)
