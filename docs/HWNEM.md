# Huawei NEM implementation

SSLRay implements the observed Huawei/SecoClient/UniVPN IPv4 network-extension protocol in Rust. This document describes interoperability with specific firmware, not a universal standard for Huawei SSL VPN products. Legacy and NEM v1 are separate dialects.

## Common conventions

- Every TLS connection first validates system PKI or the configured SHA-256 pin of the leaf certificate's DER encoding. New authentication, tunnel and OTP connections must also present the same leaf certificate. A fingerprint obtained during discovery does not establish trust by itself.
- FirstConnect is 340 bytes: the 16-byte prefix `fe fc ef be c1 92 a4 d6 00 00 00 00 00 1d 01 44`, followed by OS[64], authentication domain[256], and `00 01 00 00`. The current request writes `Mac64` at offset 16. The domain starts at offset 80, defaults to the gateway hostname, and strings are zero-padded.
- FirstConnect sends no credentials. The firmware of the real gateway device returns legacy command `0x1d` with 776 metadata bytes; v1 returns an eight-byte frame header, command `00`, and a four-byte zero status. The response selects the parser.
- Multibyte integers are big-endian unless stated otherwise. Both TLS decoders retain partial frames across read timeouts, bound lengths, and fail if frame assembly exceeds 30 seconds. Credentials, cookies, tokens and keys are not logged.

## Legacy: authentication and TLS data

Legacy command numbers are decimal. The 16-byte frame header is followed by a payload of the declared length:

| Offset | Length | Content |
|---|---|---|
| 0 | 8 | Magic: `fe fc ef be c1 92 a4 d6` |
| 8 | 4 | UserID |
| 12 | 2 | Command |
| 14 | 2 | Payload length |

Outbound headers and payloads must be combined before writing to TLS, because older firmware may reject separate header-only TLS records. The firmware of the real gateway device requires one narrow compatibility rule: **command `6` with little-endian length bytes `14 00` carries a 20-byte payload**, not big-endian 5120. Only this ACL response is normalized; other responses and all requests remain big-endian.

Authentication, discovery and the NEM tunnel each use a fresh TLS connection. Native authentication proceeds as follows:

1. Send `GET /netextension/netextensionlogin.html` with query parameters `SelectLanguage=0`, `UserName`, `Password`, `MacAddress`, and `SVN_Seco_AaA=1`, retaining the trailing `&`. URL-query-escape the raw username and password; the portal's Base64/form POST to `/login.html` cannot substitute for this request.
2. Parse the authentication structure after `f0 f0 f0 f0`, with a maximum of 1024 bytes for the entire record. Parse an HTTP body only when an HTTP wrapper is explicitly present. Validate status, UserID and the bounds of every consumed field. The cookie field is at most 64 bytes; a shorter record may terminate it with NUL.
3. Close authentication TLS before opening NEM TLS. First send command `6` with the authenticated UserID in the header and a four-byte zero payload. After receiving command `6`, send command `3` (REQVIP) with an empty payload and the same UserID. Do not substitute the authentication SessionID for the zero word.
4. Configuration parsing supports the observed 952/956-byte and 12472/12476-byte layouts: IPv4/netmask at 0/4, DNS at 160/164/168, and route count at 180 or 184. Each following network/mask/opaque entry is 12 bytes, with at most 1024 slots; firmware of the real gateway device uses 64 slots. The count must fit the actual layout. Noncontiguous masks and noncanonical networks are rejected.
5. TLS data command `2` carries a complete IPv4 packet. Empty command `7` keeps the session alive, and a kickout command terminates it. Explicit disconnect or tunnel-setup failure after authentication attempts a bounded native HTTPS logout. Destructors only close connections and erase secrets; they do not open new network connections.

Legacy SMS is triggered specifically by a big-endian `u16 == 1` at authentication-structure offset `0x32`; this field is handled even when the primary status is negative. After the callback supplies a code, a fresh TLS connection with the same certificate sends `GET /checkrdsverificationcode.html` with VTID, UserID, SessionID, escaped SMSCode, and the `SVN_SessionID` cookie. The code is at most 31 UTF-8 bytes and is submitted once. Success requires a cleared SMS flag, accepted status and valid UserID. Offset `0x18 == 1` instead indicates HostID device authentication, which is unsupported.

## Legacy CHIV UDP

After legacy protocol detection, standard-cryptography Auto and explicit UDP negotiate CHIV mode `3` automatically. The old JSON field `allow_legacy_udp` remains readable but no longer controls negotiation; the profile is not changed. TLS selection and strict GM mode do not attempt legacy UDP. CHIV uses **AES-128-CBC without a packet authentication tag** and exposes the inner IPv4 header. Source filtering and IV deduplication do not provide cryptographic integrity; the UI labels this transport accordingly.

Over TLS, send command `13` with payload `00 00 00 04`, requiring response mode `00 00 00 03` and a 16-byte key. Then send command `26` with the same payload to obtain the UDP port. UDP uses the verified TLS peer's IP and the negotiated port.

| Offset | Length | Content |
|---|---|---|
| 0 | 8 | Legacy magic |
| 8 | 1 | Direction: client sends `2`, gateway sends `1` |
| 9 | 1 | Header length `28` |
| 10 | 1 | **Opaque byte; reception must not require zero**. The client sends zero |
| 11 | 1 | IV length `16` |
| 12 | 16 | IV: client uses big-endian UserID[4] + secure random bytes[12]; gateway IV need not contain UserID |
| 28 | 20 | Original IPv4 header |
| 48 | Variable | CBC ciphertext: remaining IP bytes, zero-padded to a 16-byte boundary, without PKCS#7 |

The plaintext IPv4 total length determines the valid decrypted length. Business packets retain their original addresses. Inbound business packets must target the assigned VIP, and recent duplicate IVs are rejected.

The connection probe places NEM command `14` inside a synthetic IPv4 packet. Within three seconds it must receive an ACK that decrypts to the exact NEM magic and command `15`. This synthetic packet has a specific quirk: the native client byte-swaps the already-network-order result of `inet_addr()` again, reversing the destination bytes of the TLS peer's IPv4 address. The stored native gateway string has already been resolved to a numeric IP. **Business IP packets are not byte-swapped, and synthetic ACK addresses are not validated against the VIP.**

The TLS control channel continues keepalives and processes session termination. Static-IV mode `2` is rejected. In Auto, unavailable CHIV negotiation or a failed UDP probe sends empty command `16` on the same authenticated NEM TLS connection and continues with TLS; the native switch does not require an ACK. Late outstanding key/port replies and an optional switch reply are drained once each. Explicit UDP reports failure. Invalid framing, TLS/identity errors and session termination remain fatal, with no repeated password authentication. CHIV is not a GM cryptography data plane.

## NEM v1: authentication and TLS data

In this section, v1 command numbers are hexadecimal. The frame header is 8 bytes, and TLVs use `type:u16 + length:u16 + value[length]`. Truncated TLVs fail immediately.

| Offset | Length | Content |
|---|---|---|
| 0 | 4 | Magic: `c1 92 a4 d6` |
| 4 | 1 | Version `01` |
| 5 | 1 | Command |
| 6 | 2 | Payload length, maximum 65535 |

1. After FirstConnect succeeds, send control command `01`: the padded authentication domain, four zero bytes, username TLV `1`, password TLV `2`, and MAC-string TLV `3`. Username and password escape `%`, `&`, and `+` as `%25`, `%26`, and `%2B` and end in NUL. The MAC is a locally administered identifier deterministically derived from the account and gateway, formatted as `XXXX-XXXX-XXXX`.
2. The authentication response requires a four-byte zero status. Parse TLVs from payload offset 8; the first 32 bytes of type `3` form the session token.
3. Send command `03` with the token. The response's first status byte must be zero. Parse configuration TLVs from offset 4: type `1` is IPv4[4]+prefix[1], type `6` is a sequence of network[4]+prefix[1], and type `4` is 140-byte DNS metadata (suffix[128]+three IPv4 addresses). Invalid networks are rejected.
4. Open a separate TLS data connection with the same certificate. Send command `64` with the token, requiring response `64` and payload `00`. Command `66` carries eight zero bytes followed by a complete IPv4 packet; validate IP version, header length and total length.
5. Every 10 seconds, control command `06` carries the token and elapsed milliseconds modulo 2³². Every 15 seconds, data command `65` sends an empty payload. Drain control responses independently; closing either TLS channel ends the session.

v1 SMS: authentication status `1` with TLV `2` of exactly length `1` and value `01` retains control TLS and invokes the code callback. Command `02` carries `01` followed by a NUL-padded 32-byte code field (at most 31 UTF-8 bytes). The response is still authentication command `01` and must have status `0`. The token may be retained from the primary response or replaced by the secondary response. Unknown methods, repeated challenges and rejected challenges fail; passwords are not concatenated and credentials are not retried automatically.

## NEM v1 AES-GCM UDP

Auto attempts this mode only when authenticated REQVIP supplies TLV `8` (32-byte key) and `9` (2-byte port). The destination IP is fixed to the control TLS peer.

1. Control command `09` carries token[32] + mode `02`, requiring response `09` and payload `00`.
2. Send encrypted, empty-payload NEM command `07` through the connected UDP socket, requiring an authenticated, empty-payload `08` ACK within three seconds. Business command `66` carries raw IPv4 directly, without the TLS data plane's eight-zero-byte prefix.
3. Retain TLS token keepalives. Check UDP `07/08` every 15 seconds; an ACK timeout exceeding 60 seconds ends the session.
4. Without key/port, Auto uses TLS. After a failed probe, control command `09` must switch to mode `01` and receive confirmation before opening the TLS data channel. Explicit UDP instead returns an error. Authentication rejection or transport-switch rejection does not trigger a retry through another transport.

| Offset | Length | Content |
|---|---|---|
| 0 | 4 | `01 02 00 00` |
| 4 | 4 | Assigned client IPv4 |
| 8 | 12 | Reserved zero bytes emitted by the client |
| 20 | 16 | Secure random IV; GCM uses only the first **12** bytes as the nonce |
| 36 | 16 | GCM tag |
| 52 | Variable | Encrypted complete NEM frame |

Both directions use the negotiated 32-byte key, AES-256-GCM, a 16-byte tag and empty AAD; the plaintext envelope is not added as AAD. Verify the tag before checking the exact NEM length/version. The socket filters source IP/port, and the outer IPv4 must match the VIP. Invalid headers/tags, recent duplicate nonces and reflected outbound packets are dropped. The 8192-entry nonce cache provides only bounded replay mitigation; no sequence number has been observed in the protocol.

## Support and validation boundaries

- Legacy TLS and CHIV UDP have completed real IP round trips through the real gateway device. See [validation records](VALIDATION.md), [system interfaces](PLATFORMS.md), and [README](../README.md) for testing, platforms and operation. v1 UDP and both SMS paths remain primarily covered by local protocol fixtures; these do not establish live interoperability with the target firmware.
- Strict GM cryptography mode uses RFC 8998 TLS 1.3, not the TLCP/NTLS dual-certificate protocol. GM Auto uses TLS; GM + explicit UDP fails before credentials are sent and does not fall back to AES. SM4 UDP is not implemented. See [GM validation](GM-VALIDATION.md).
- Other firmware/domain aliases, client certificates, IPv6, proxies, compression, browser SSO, other MFA, session renewal, roaming and long-term stability still need interoperability validation. Installing system DNS settings belongs to the platform layer.
- Older vendor documentation calls fast mode QUIC; this does not establish compatibility with IETF QUIC v1, HTTP/3, MASQUE or DTLS.

## Sources and copyright

- UniVPN Connect, pinned commit: [`docs/protocol.md`](https://github.com/Bruce-lhq/univpn-connect/blob/954274ba3b0a061b844279311afd9350f203ba7f/docs/protocol.md), [MIT Python reference](https://github.com/Bruce-lhq/univpn-connect/blob/954274ba3b0a061b844279311afd9350f203ba7f/univpn_forward/protocol.py), [license](https://github.com/Bruce-lhq/univpn-connect/blob/954274ba3b0a061b844279311afd9350f203ba7f/LICENSE).
- [OpenConnect's protocol list](https://www.infradead.org/openconnect/protocols.html) does not list Huawei; [Huawei SSL VPN overview](https://info.support.huawei.com/info-finder/encyclopedia/en/detail?action=queryEntityDetail&keyword=SSL+VPN).
- Huawei SecoClient Administrator Guide, issue 18 (2020-07-06), page 49: [vendor-authored PDF mirror](https://packages.zmops.cn/base/vpn/secoclient/HUAWEI%20SecoClient%E5%AE%A2%E6%88%B7%E7%AB%AF%20%E7%AE%A1%E7%90%86%E5%91%98%E6%8C%87%E5%8D%97.pdf).

Additional legacy, SMS and UDP wire facts come from read-only inspection of the installed UniVPNCS client: legacy header `0x100066dd0`, REQVIP `0x100050ad0/0x100051180`, CHIV key/probe/CBC/send/recv `0x10004bca0/0x10004c840/0x10004be40/0x10004bf30/0x100044605/0x10004ee10`; v1 SMS `0x10002b630/0x1000244e0/0x100024e46`, GCM `0x10004c010/0x10004f6e0`. These offsets identify observations of that specific binary only. The Rust implementation is independent; vendor binaries, disassembly and OpenConnect C/LGPL patches are not distributed.

The referenced Python implementation's MIT notice is retained unchanged:

> MIT License
>
> Copyright (c) 2026 UniVPN TCP Forward Contributors
>
> Permission is hereby granted, free of charge, to any person obtaining a copy
> of this software and associated documentation files (the "Software"), to deal
> in the Software without restriction, including without limitation the rights
> to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
> copies of the Software, and to permit persons to whom the Software is
> furnished to do so, subject to the following conditions:
>
> The above copyright notice and this permission notice shall be included in all
> copies or substantial portions of the Software.
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
> IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
> FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
> AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
> LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
> OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
> SOFTWARE.
