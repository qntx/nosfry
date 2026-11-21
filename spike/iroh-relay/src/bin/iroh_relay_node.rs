//! nosfry relay served on plain TCP and over iroh QUIC connections:
//! ALPN `nosfry/http1`, where each bidirectional stream carries one
//! HTTP/1.1 connection (design (i)).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context as _, Result};
use clap::Parser;
use iroh::endpoint::Connection;
use iroh_relay_spike::{
    BiStream, direct_addr, endpoint, relay_server, secret_key, serve_stream, tcp_accept_loop,
    ticket,
};
use nosfry::config::Config;
use tokio::net::TcpListener;
use tracing::{info, warn};

/// Every iroh client gets this synthetic `ConnectInfo`: the real peer
/// is an `EndpointId`, not a socket address.
const SYNTHETIC_PEER: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

#[derive(Parser)]
#[command(about = "nosfry relay over TCP + iroh (ALPN nosfry/http1)")]
struct Cli {
    /// nosfry config file.
    #[arg(long)]
    config: PathBuf,
    /// Persistent iroh secret key file (created 0600 on first run).
    #[arg(long)]
    key: PathBuf,
    /// Disable all IP transports: reachable over relays only.
    #[arg(long)]
    relay_only: bool,
    /// Use only this relay server URL instead of the n0 defaults
    /// (e.g. `http://127.0.0.1:3340` for `iroh-relay --dev`).
    #[arg(long)]
    relay_url: Option<String>,
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    if let Err(err) = run(cli).await {
        eprintln!("error: {err:?}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

async fn run(cli: Cli) -> Result<()> {
    let config = Config::load(&cli.config)?;
    let bind = (config.relay.bind, config.relay.port);
    let keepalive = config.relay.tcp_keepalive;
    let (_server, router) = relay_server(config)?;
    let listener = TcpListener::bind(bind).await?;
    info!(addr = %listener.local_addr()?, "TCP listener up");
    println!("READY tcp={}", listener.local_addr()?);
    println!("PID={}", std::process::id());
    tokio::spawn(tcp_accept_loop(listener, router.clone(), keepalive));

    let key = secret_key(&cli.key)?;
    let ep = endpoint(&key, cli.relay_only, cli.relay_url.as_deref(), false)
        .await
        .context("iroh endpoint")?;
    println!("ENDPOINT_ID={}", ep.id());
    // Bound sockets are known immediately; the relay addr shows up
    // after the home relay connects.
    let addr = direct_addr(&ep);
    println!("DIRECT_TICKET=ticket:{}", ticket(&addr));
    for socket in ep.bound_sockets() {
        println!("BOUND_SOCKET={socket}");
    }
    // The relay address appears once the home relay is connected;
    // print the full ticket (relay + any IP addrs) when it does.
    let online_ep = ep.clone();
    tokio::spawn(async move {
        online_ep.online().await;
        println!("ONLINE_TICKET=ticket:{}", ticket(&online_ep.addr()));
    });

    loop {
        tokio::select! {
            incoming = ep.accept() => {
                let Some(incoming) = incoming else { break };
                let router = router.clone();
                tokio::spawn(async move {
                    match incoming.accept() {
                        Ok(accepting) => match accepting.await {
                            Ok(conn) => {
                                let remote = conn.remote_id();
                                info!(%remote, "iroh connection accepted");
                                log_paths(&conn);
                                serve_connection(conn, router).await;
                            }
                            Err(err) => warn!(%err, "iroh handshake failed"),
                        },
                        Err(err) => warn!(%err, "iroh accept failed"),
                    }
                });
            }
            res = tokio::signal::ctrl_c() => {
                res?;
                info!("shutdown");
                break;
            }
        }
    }
    Ok(())
}

/// Log the live paths (direct IP vs relay) for one connection.
fn log_paths(conn: &Connection) {
    for path in conn.paths().iter() {
        info!(
            remote = %path.remote_addr(),
            kind = if path.is_relay() { "relay" } else { "ip" },
            selected = path.is_selected(),
            "connection path"
        );
    }
}

/// Serve every bidirectional stream on one QUIC connection as an
/// independent HTTP/1.1 connection, concurrently.
async fn serve_connection(conn: Connection, router: axum::Router) {
    loop {
        match conn.accept_bi().await {
            Ok((send, recv)) => {
                serve_stream(BiStream { recv, send }, router.clone(), SYNTHETIC_PEER);
            }
            Err(_) => break,
        }
    }
}
