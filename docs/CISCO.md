# Cisco / AnyConnect TLS backend

SSLRay implements XML authentication and CSTP in Rust without invoking `openconnect`, browser automation or host-scan scripts. Normal PKI validation or the selected pin is checked before credentials; subsequent TLS channels must present the same leaf certificate. Redirects are limited to the configured HTTPS origin before secret submission. Rejected credentials are never retried automatically.

Supported: username/password forms, hidden/opaque state, a selected/default tunnel group, one secondary-password/OTP challenge, CSTP IPv4 packets, DPD, keepalive and disconnect. Server IPv4 routes, split exclusions, DNS and MTU are validated; interface MTU is bounded by both server and profile limits.

Auto uses TLS/CSTP; explicit UDP fails before authentication. DTLS, compression, IPv6 forwarding, browser SSO, host-scan, client-certificate-only authentication, password/PIN changes and arbitrary forms are unsupported. Rekey deadlines require reconnection. Valid unsolicited IPv6 neighbor discovery is discarded, not forwarded.

## Verification and reproduction

Local ocserv 1.6.0 / GnuTLS 3.8.13 passed password authentication, pushed network parameters, encrypted ICMP/DNS round trips and rejection of a wrong pin before credential transmission. XML/CSTP fixtures additionally cover OTP, DPD, partial frames and credential replay prevention. **No Cisco ASA appliance has been tested.** Current system-integration results are in [VALIDATION.md](VALIDATION.md); routing and privilege handling are in [PLATFORMS.md](PLATFORMS.md).

From the repository root, with Docker running:

```sh
python3 tests/vpn-lab/setup-ocserv.py
cargo test -p sslray-core --test cisco_interop -- --ignored
docker stop sslray-ocserv-lab
```

Setup generates private credentials/certificates under ignored `work/ocserv-lab` and checks reused port bindings. Wait for the service to be ready before testing. The lab exposes only TCP `127.0.0.1:1443`, disables UDP, uses `10.91.0.0/24` and local DNS, and does not change host routes or create a host VPN interface. Both real-server tests are ignored in the ordinary suite; run setup before using the Compose service directly.

Protocol references: [OpenConnect technical documentation](https://www.infradead.org/openconnect/technical.html), [protocol draft](https://gitlab.com/openconnect/protocol/-/blob/master/draft-openconnect.xml), [Cisco connection flow](https://www.cisco.com/c/en/us/support/docs/security/anyconnect-secure-mobility-client-v4x/222430-understanding-the-anyconnect-ssl-vpn-con.pdf), [ocserv manual](https://www.infradead.org/ocserv/manual.html). This is an independent implementation, not copied OpenConnect source.
