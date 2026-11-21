//! iroh→TCP gateway (design (ii)): accepts plain TCP connections and
//! forwards each over one bidirectional QUIC stream on a single cached
//! connection to the iroh relay node. Lets unmodified clients use
//! `ws://127.0.0.1:<port>` against an iroh-hosted relay.

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context as _, Result};
use clap::Parser;
use iroh::Endpoint;
use iroh::endpoint::Connection;
use iroh_relay_spike::{ALPN, BiStream, endpoint, parse_peer, secret_key};
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tracing::{info, warn};

#[derive(Parser)]
#[command(about = "TCP<->iroh gateway for the nosfry spike")]
struct Cli {
    /// `<endpoint-id>` (z32) or `ticket:<hex>` of the relay node.
    peer: String,
    /// Local TCP listen address (e.g. `127.0.0.1:8080`).
    #[arg(long)]
    listen: String,
    /// Ephemeral secret key file (created 0600 on first run).
    #[arg(long, default_value = "gateway-key")]
    key: PathBuf,
    /// Disable all IP transports: reach the node over relays only.
    #[arg(long)]
    relay_only: bool,
    /// Use only this relay server URL instead of the n0 defaults.
    #[arg(long)]
    relay_url: Option<String>,
    /// Disable relay servers completely: force direct IP paths.
    #[arg(long)]
    no_relay: bool,
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

/// One cached QUIC connection; re-dialed when it dies.
struct Upstream {
    addr: iroh::EndpointAddr,
    conn: Mutex<Option<Connection>>,
    endpoint: Endpoint,
}

impl Upstream {
    async fn connection(&self) -> Result<Connection> {
        let mut guard = self.conn.lock().await;
        if let Some(conn) = guard.as_ref()
            && conn.close_reason().is_none()
        {
            return Ok(conn.clone());
        }
        let conn = self
            .endpoint
            .connect(self.addr.clone(), ALPN)
            .await
            .context("iroh connect")?;
        info!(remote = %conn.remote_id(), "gateway connected to node");
        for path in conn.paths().iter() {
            info!(
                remote = %path.remote_addr(),
                kind = if path.is_relay() { "relay" } else { "ip" },
                selected = path.is_selected(),
                "gateway path"
            );
        }
        *guard = Some(conn.clone());
        Ok(conn)
    }
}

async fn run(cli: Cli) -> Result<()> {
    let peer = parse_peer(&cli.peer)?;
    let key = secret_key(&cli.key)?;
    let ep = endpoint(&key, cli.relay_only, cli.relay_url.as_deref(), cli.no_relay).await?;
    println!("GATEWAY_ENDPOINT_ID={}", ep.id());
    let upstream = std::sync::Arc::new(Upstream {
        addr: peer,
        conn: Mutex::new(None),
        endpoint: ep,
    });

    // Warm the cached connection so the first client does not pay the
    // dial in its own request path (and to surface dial errors early).
    upstream.connection().await?;

    let listener = TcpListener::bind(&cli.listen).await?;
    println!("READY listen={}", listener.local_addr()?);
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (tcp, peer) = accepted.context("accept")?;
                info!(%peer, "TCP client accepted");
                let upstream = upstream.clone();
                tokio::spawn(async move {
                    if let Err(err) = forward(upstream, tcp).await {
                        warn!(%err, %peer, "forwarding failed");
                    }
                });
            }
            res = tokio::signal::ctrl_c() => {
                res?;
                break;
            }
        }
    }
    Ok(())
}

/// Forward one TCP connection over one bi stream of the cached QUIC
/// connection. `copy_bidirectional` propagates FIN both ways; the QUIC
/// stream's send-side FIN is the exact analogue of TCP half-close.
async fn forward(upstream: std::sync::Arc<Upstream>, mut tcp: TcpStream) -> Result<()> {
    let conn = upstream.connection().await?;
    let (send, recv) = conn.open_bi().await.context("open_bi")?;
    let mut stream = BiStream { recv, send };
    copy_bidirectional(&mut tcp, &mut stream).await?;
    Ok(())
}
