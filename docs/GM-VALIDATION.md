# GM cryptographic backend and validation

`gm_tls13` strictly uses [RFC 8998](https://www.rfc-editor.org/rfc/rfc8998.html): TLS 1.3, SM2 key exchange/signatures, SM3 and SM4-GCM/CCM. It restricts the algorithm combination before connecting, checks the negotiated suite afterward, and fails before sending credentials if capabilities are insufficient. It is not TLCP/NTLS; dual-certificate clients are unsupported.

Huawei NEM v1 uses AES-256-GCM and legacy CHIV3 uses AES-128-CBC; neither is an SM4 data channel. GM Auto therefore uses TLS only, and explicit UDP fails. OpenVPN does not support GM TLS. An AES tunnel must not be presented as a GM tunnel.

## Detection and reproduction

```sh
./scripts/cargo-macos.sh run -p sslray -- capabilities
./scripts/cargo-macos.sh test -p sslray-core --test gm_tls -- --nocapture
```

These macOS commands use the pinned project OpenSSL source. On Linux/Windows, use `cargo` with a compatible native backend.

Use the linked library's actual `gm_tls13` capabilities and handshake tests, not its OpenSSL/Tongsuo product name. The integration test uses the VPN's `crypto::connect`, generates temporary SM2/SM3 certificates, and verifies local handshakes, SM2 certificates and application-data round trips for both `TLS_SM4_GCM_SM3` and `TLS_SM4_CCM_SM3`. Unsupported backends report a skip reason; a skipped test is not a successful handshake.

On 2026-11-15, the macOS arm64 build passed the integration test for both suites using the project's static OpenSSL 4.0.3 backend, compiled with a macOS 11.0 deployment target. Earlier checks also passed with OpenSSL 4.0.2 and Tongsuo 8.5.0 CLI loopback handshakes and SM3/SM4 vectors. These results do not establish GM TLS support or a working GM VPN data path on a real gateway device, or runtime compatibility with macOS 11. The full upstream cryptographic test suites were not run. See [VALIDATION.md](VALIDATION.md) for overall validation status.

## Optional static Tongsuo build

The local build used the [official 8.5.0 archive](https://codeload.github.com/Tongsuo-Project/Tongsuo/tar.gz/refs/tags/8.5.0), tag commit `80cfbe3eb194a4d30da90742273c305ad4d096be`, SHA-256 `505085d457214e5662ea7109c3919fb75f695edf74c91ec6f690da0e58c07dea`. Run this macOS arm64 configuration inside the extracted `work/tongsuo-src`; it installs into an ignored directory, not globally:

```sh
perl ./Configure darwin64-arm64-cc --prefix="$PWD/../tongsuo-install" \
  --libdir=lib --openssldir="$PWD/../tongsuo-install/ssl" \
  no-shared no-tests enable-ntls enable-sm2 enable-sm3 enable-sm4
make -j8 build_sw
make install_sw
```

Return to the repository root and retest with a separate build directory. Static linking does not require `DYLD_LIBRARY_PATH`:

```sh
OPENSSL_DIR="$PWD/work/tongsuo-install" OPENSSL_STATIC=1 \
  cargo test -p sslray-core --target-dir target/tongsuo --test gm_tls -- --nocapture
```

Linux/Windows require a backend built for their system and architecture; the local libraries cannot be reused. Packaging rules are in [PLATFORMS.md](PLATFORMS.md). Build references: [Source compilation](https://www.tongsuo.net/en/docs/compilation/source-compilation/), [GM TLS 1.3](https://github.com/Tongsuo-Project/Tongsuo/wiki/TLS1.3---%E5%9B%BD%E5%AF%86%E5%8D%95%E8%AF%81%E4%B9%A6).
