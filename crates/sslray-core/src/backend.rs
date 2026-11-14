//! Packet-oriented adapters for additional native VPN protocols.
use anyhow::Result;
use std::{net::Ipv4Addr, time::Duration};

pub(crate) trait PacketBackend: Send {
    fn send_packet(&mut self, packet: &[u8]) -> Result<()>;
    fn read_packet(&mut self) -> Result<Option<Vec<u8>>>;
    fn set_read_budget(&self, budget: Duration) -> Result<()>;
    fn keepalive(&mut self) -> Result<()>;
    fn outer_ipv4_addresses(&self) -> Result<Vec<Ipv4Addr>>;
    /// Explicit, bounded protocol logout and worker shutdown.
    fn disconnect(&mut self);
    /// Local cancellation/socket closure only; safe to call again from Drop.
    fn close(&mut self);
}

pub(crate) struct BackendConnection {
    pub vip: Ipv4Addr,
    pub routes: Vec<String>,
    pub dns: Vec<Ipv4Addr>,
    pub cipher: String,
    pub transport: String,
    pub negotiated_mtu: Option<u16>,
    pub channel: Box<dyn PacketBackend>,
}
