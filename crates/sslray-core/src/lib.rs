#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

mod backend;
mod cisco;
pub mod config;
pub mod crypto;
pub mod gateway;
pub mod identity;
pub mod legacy_http;
pub mod legacy_native;
pub mod openvpn;
pub mod platform;
pub mod session;
#[cfg(windows)]
pub mod windows_peer;
#[cfg(windows)]
mod windows_roots;
#[cfg(any(windows, test))]
mod windows_wintun;
