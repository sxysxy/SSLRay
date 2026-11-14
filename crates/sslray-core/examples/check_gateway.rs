//! Read-only network check. No TUN or route modifications.
use anyhow::Result;
use sslray_core::{config::Profile, gateway::Gateway};
use zeroize::Zeroizing;
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    let p: Profile = serde_json::from_slice(&std::fs::read(&args[1])?)?;
    if args.get(2).map(String::as_str) == Some("probe") {
        println!("{}", Gateway::probe(&p)?);
        return Ok(());
    }
    let mut password = Zeroizing::new(String::new());
    std::io::stdin().read_line(&mut password)?;
    let mut g = Gateway::connect(&p, password.trim_end_matches(['\n', '\r']), None)?;
    println!(
        "Authenticated; virtual IPv4 {}; cipher {}; server routes {:?}",
        g.vip, g.cipher, g.routes
    );
    g.disconnect();
    Ok(())
}
