# Linux x86_64 构建与发布

`cargo-linux.sh`、`build-tls-linux.sh` 和 `bundle-linux.sh` 使用项目固定的 OpenSSL 源码，从独立 `work/` 目录构建静态后端，不依赖系统 OpenSSL 开发库，不安装系统包、注册服务或修改路由。构建目标是原生 `x86_64-unknown-linux-gnu`；其它架构需另行验证。

需要 Rust 1.95+、Python 3.11+、含 `IPC::Cmd` 的 Perl、GCC、GNU make/binutils、pkg-config，以及应用使用的 GTK 3 开发包。目标 glibc 默认上限 2.28，因此应在 glibc 2.28 的构建环境中编译。新发行版主机直接编译后再修改版本声明无法降低 ABI 要求，检查器会拒绝超过上限的符号或遗留构建机 RPATH。

```sh
git submodule update --init third_party/openssl
./scripts/cargo-linux.sh test --workspace --locked
./scripts/bundle-linux.sh
```

后端配置为 `linux-x86_64 -fPIC -march=x86-64 -mtune=generic no-shared no-module no-tests enable-sm2 enable-sm3 enable-sm4`；程序集使用运行时 CPU 探测，不针对构建主机启用 `-march=native`。默认并行度为 8，可用 `SSLRAY_BUILD_JOBS` 与 `CARGO_BUILD_JOBS` 调整。源码固定检查同时适用于有 Git 的 checkout 和保留完整文件/执行位的源码导出；不要用会省略 OpenSSL `export-ignore` 文件的普通 `git archive` 代替完整源码。

构建入口固定设置本次进程的 `OPENSSL_DIR`、`OPENSSL_STATIC`、target 对应变量及实际许可源码目录。OpenSSL 位于 `work/openssl-linux-x86_64-glibc2.28/install`，Cargo 默认输出到 `work/linux-x86_64-glibc2.28-target`。每次重新核对固定源码与 SM4 TLS 1.3 能力；实际主程序通过 `readelf` 检查 x86_64、最高 GLIBC 符号、不含动态 OpenSSL 与构建机绝对 RPATH。

`bundle-linux.sh [输出目录]` 默认生成 `dist/SSLRay-<版本>-linux-x86_64/` 及 `.tar.gz`。包含启动器、二进制、SVG 图标、desktop 模板、项目的 LICENSE/COPYRIGHT/附加许可、第三方许可、ELF/加密能力记录与 SHA-256。打包后解压对比全部文件；已有同名版本时拒绝覆盖。

这是使用系统 GUI 运行库的 tar 包。GTK 3、X11/Wayland、OpenGL、glibc 2.28+ 由目标系统提供；托盘需 Ayatana AppIndicator 或兼容 AppIndicator 库及桌面支持。连接需 `/dev/net/tun`、iproute2、polkit/pkexec 与桌面认证代理。CLI 在无显示环境中可运行；连接仍需合法的系统提权方式。解压和启动应用不会自动安装服务或 desktop 文件，不会自动保存密码或连接 VPN。

可在普通用户的 Podman 容器中提供这些构建依赖。发布记录应保存基础镜像 ID、Rust/GCC/Python 版本和实际 GLIBC 检查结果。容器只挂载本次隔离源码和缓存，不挂载用户主目录或应用配置；无需 `--privileged` 或主机网络。只有明确进行虚拟网卡验收时才按独立测试计划申请宿主权限。

GUI 验收可使用 Xvfb/Mesa，但应将 `XDG_CONFIG_HOME`、`XDG_CACHE_HOME` 和临时运行目录指向本次合成数据目录，保留原 `HOME`，不访问真实连接配置。ABI 检查不代表已在全部 Linux 发行版、桌面或 GPU 上完成运行验证；以发布时的实际验收记录为准。
