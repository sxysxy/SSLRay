# Omnitun OpenVPN backend

Source: https://github.com/GarageDeveloper/omnitun
Revision: `d117595bdf1700faf14410e83cfd9676b7d5834d`
Upstream version: 0.4.5
License: MIT OR Apache-2.0 (both original license files retained).

Only the vpn-openvpn, vpn-core and vpn-tls crates are vendored. No upstream
GUI, daemon, platform implementation, installers or third-party binary is included.
The original copyright notice is in LICENSE-MIT.

Local changes:
- Manifests expand original workspace metadata/dependencies into explicit values
  and sibling paths, leaving the backend independent of Omnitun's other crates.
- Packet delivery uses bounded channels and drops congested packets instead of
  blocking control processing. SSLRay's enclosing runner cancels socket futures.
- Engine exposes metadata from the connected socket, including peer and cipher.
- Authentication errors omit server-provided reason text, and tracing is compiled
  out (`max_level_off`) to avoid logging credentials or control-session tokens.
- Temporary static keys and pushed tokens are erased on Drop.
- SCRV1/CRV1 answers are erased after authentication unless replaced by auth-token;
  later reauthentication without such a token requires a fresh session and OTP.
- Unix errno-only checks in vpn-core/net.rs are gated for non-Unix compilation.
- A server-selected data cipher must occur in the profile's offered cipher list.

The vpn-core crate retains its complete, self-contained 17-source module closure
to preserve its existing validation/types/tests. Only these three internal crates
are required; their external dependencies remain normal Cargo dependencies pinned
by SSLRay's root Cargo.lock. No upstream importer or application storage is reused.

SSLRay owns .ovpn loading, password/OTP prompts, client-key signing, utun and routes.
No upstream IPC daemon or credential persistence is used.

The original `vpn-openvpn/tests/data/prf-vector.txt` public unit-test vector is
retained. An isolated build of the vendored vpn-openvpn library tests passed
18/18 on macOS arm64 on 2026-11-14, including local OTP-reuse and unoffered-cipher regression tests.
