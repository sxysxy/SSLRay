# Native OpenVPN backend

SSLRay embeds the Omnitun 0.4.5 Rust engine without invoking an external `openvpn` executable. Its three crates are pinned to commit `d117595bdf1700faf14410e83cfd9676b7d5834d` under MIT OR Apache-2.0; provenance, original licenses and modifications are in [Third-party sources](THIRD-PARTY.md). See [README](../README.md) and [PLATFORMS.md](PLATFORMS.md) for builds and platform privileges.

## Configuration and security boundaries

Select OpenVPN and specify an `.ovpn` path. Certificate authentication may leave username/password empty; password authentication uses `auth-user-pass` without a file argument. The UI saves the original path, not imported private keys. Main passwords can optionally be saved as Base64 in `profiles.json` (reversible, not encryption); OTPs are never saved.

`openvpn::prepare` reads configuration in the unprivileged process and sends a per-connection memory copy over authenticated IPC; the helper refuses to read paths directly. Referenced CA, certificate, private-key and static-key files must stay within the `.ovpn` directory or its children, including resolved symlinks. Inline `<ca>`, `<cert>`, `<key>`, `<tls-auth>` and `<tls-crypt>` blocks are supported. Limits are 128 KiB per file and 256 KiB after preparation. Temporary configuration and session secrets are cleared on release on a best-effort basis; debug output and public errors do not expose credentials, private keys or server authentication details.

CA mode checks the chain against the specified CA, validity and server usage; `remote-cert-tls server` is enabled by default. Supported identity policies are `verify-x509-name` with `subject`, `name` or `name-prefix`, and exact SHA-256 `peer-fingerprint`. The UI fingerprint overrides the file's list. These rules differ from HTTPS hostname verification; disabling verification is not a substitute. Client keys must match their certificates: RSA (up to 8192 bits) and ECDSA P-256/P-384 are supported; encrypted PEM, PKCS#12 and system certificate-store selection are not.

| Area | Supported scope |
|---|---|
| Network | TLS client, `dev tun`, inner/outer IPv4; UDP/UDP4, TCP/TCP4 client, sequential attempts across multiple `remote` entries |
| Cryptography | TLS 1.2/1.3, `tls-auth`, `tls-crypt`; AES-256-GCM, AES-128-GCM and ChaCha20-Poly1305 data channels; unnegotiated algorithms rejected |
| Authentication | Username/password, client certificate or both; SCRV1 static challenges, CRV1 dynamic challenges (up to three rounds), server auth-token |
| Session/routing | Keepalive, rekeying, replay protection; pushed IPv4/MTU/routes/DNS, local `route`, `route-nopull`, `tun-mtu` |

OTPs are obtained through a callback for each challenge. Subsequent authentication uses the server auth-token; without a token, challenge answers are cleared, and reauthentication ends the connection and requires a fresh code instead of replaying an OTP. The full server MFA matrix remains unverified.

Unsupported: TAP, IPv6, CBC data channels, static-key mode, `tls-crypt-v2`, proxies, compressed data, Web/SAML, CR_TEXT and unimplemented TLS-version constraints. Scripts/plugins are not executed, password files are not read, and unknown security directives are rejected. Only compatibility framing with uncompressed data is accepted. This protocol uses rustls/ring and does not support GM TLS.

An IPv4 session can receive unsolicited IPv6 neighbor-discovery traffic from a server TUN. Complete IPv6 packets are discarded without ending the IPv4 session; packet length checks, a bounded batch and the read deadline still apply. Malformed IPv4/IPv6 or non-IP data remains an error. This does not enable IPv6 connectivity or routing.

Routing protects the actual socket peer and follows SSLRay's shared policy; pushed `redirect-gateway` does not enable a full tunnel without explicit selection. Connection setup has a 120-second budget. Disconnect removes session routes before closing the engine/interface, waiting at most three seconds for the background thread. System DNS calls cannot be forcibly interrupted but do not hold VPN credentials.

## Local reproduction

macOS Apple Silicon passed certificate authentication, CA/CN policies, AES-256-GCM/UDP ICMP round trips and wrong-fingerprint rejection against Docker OpenVPN 2.6.20 / OpenSSL 3.3.7. The following two tests do not create a host TUN or modify host routes; separate system utun/split-routing results are in [VALIDATION.md](VALIDATION.md).

On 2026-11-15, the final native Linux and Windows executables also passed mutual-certificate UDP / AES-256-GCM against a temporary OpenVPN 2.7.0 reference server. Linux used the privileged CLI with explicit sudo, host `tun0`, VIP `10.88.0.2`, MTU 1400 and only `10.88.0.1/32`: ping 2/2, TX/RX 168 bytes each, SIGINT exit 0 and matching route/interface baselines after cleanup. Windows used the GUI, real UAC and official Wintun 0.14.1 with the same VIP/MTU and single manual `/32`: 8/8 replies in the first session, disconnect cleanup, then 2/2 after reconnecting with the same elevated helper and no new UAC. Final disconnect cleaned up again; SSLRay installed no default route, and outer connectivity and the original default route were preserved.

These reference tests used fresh certificate fixtures and no company VPN account. They establish this tested certificate/UDP combination and host interface/route handling, not company Huawei access, general hardware compatibility, Linux desktop polkit interaction or every OpenVPN option. TCP, password/MFA, `tls-auth`/`tls-crypt`, long-running rekeying and other algorithm/server combinations still need interoperability validation. Detailed boundaries and evidence locations are in [VALIDATION.md](VALIDATION.md).

```sh
docker compose -f tests/vpn-lab/compose.yaml up -d --build openvpn
cargo test -p sslray-core --test openvpn_interop -- --ignored --nocapture
docker compose -f tests/vpn-lab/compose.yaml stop openvpn
```

Run from the repository root and wait for the container service to be ready before testing. The lab exposes only UDP `127.0.0.1:1194`; certificates/private keys stay in ignored `work/openvpn-lab`. Certificates expire after two days; stop the service and move the old state directory aside before regenerating them. Ordinary tests run neither these interoperability tests nor the vendored crate unit tests outside the main workspace.
