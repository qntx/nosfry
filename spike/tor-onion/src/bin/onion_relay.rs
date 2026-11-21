//! nosfry relay served both on plain TCP and as a Tor onion service,
//! hosted in-process with Arti (`arti-client` + `tor-hsservice`).
//!
//! Every accepted onion stream is served by the exact hyper wiring
//! nosfry uses for TCP, with a synthetic `127.0.0.1:0` peer address
//! (see README for the per-IP limiter implications).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

use anyhow::{Context as _, Result, anyhow, bail};
use arti_client::config::TorClientConfigBuilder;
use arti_client::{DataStream, TorClient};
use clap::Parser;
use futures::StreamExt as _;
use nosfry::config::Config;
use safelog::DisplayRedacted as _;
use tokio::net::TcpListener;
use tor_cell::relaycell::msg::{Connected, End, EndReason};
use tor_hsservice::{HsNickname, OnionServiceConfig, RunningOnionService, handle_rend_requests};
use tor_onion_spike::{relay_server, serve_stream, tcp_accept_loop};
use tor_proto::stream::IncomingStreamRequest;
use tracing::{info, warn};

/// Every onion client gets this synthetic `ConnectInfo`: the real peer
/// is an anonymous rendezvous circuit with no address to report.
const SYNTHETIC_PEER: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

/// Virtual port the onion service answers; everything else is rejected.
const VIRT_PORT: u16 = 80;

#[derive(Parser)]
#[command(about = "nosfry relay over TCP + Tor onion service (Arti)")]
struct Cli {
    /// nosfry config file.
    #[arg(long)]
    config: PathBuf,
    /// Arti state/cache root; `<dir>/state` and `<dir>/cache` hold the
    /// persistent Arti data (including the onion service keys).
    #[arg(long)]
    state_dir: PathBuf,
}

#[tokio::main]
async fn main() -> ExitCode {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("install rustls ring CryptoProvider");
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

    // RSS sampling point: Arti not yet started.
    println!("MARK before_arti");

    let arti_config = TorClientConfigBuilder::from_directories(
        cli.state_dir.join("state"),
        cli.state_dir.join("cache"),
    )
    .build()
    .context("arti config")?;

    let boot = Instant::now();
    let client = TorClient::builder()
        .config(arti_config)
        .create_bootstrapped()
        .await
        .context("arti bootstrap")?;
    println!("TIMING arti_bootstrap_secs={:.3}", boot.elapsed().as_secs_f64());
    println!("MARK arti_bootstrapped");

    let svc_config = OnionServiceConfig::builder()
        .nickname("nosfry".parse::<HsNickname>().map_err(|e| anyhow!("{e}"))?)
        .build()
        .context("onion service config")?;
    let launched = Instant::now();
    let Some((service, rend_requests)) = client
        .launch_onion_service(svc_config)
        .context("launch onion service")?
    else {
        bail!("onion service disabled in config");
    };
    let address = service
        .onion_address()
        .ok_or_else(|| anyhow!("no onion address in keystore"))?;
    let address = address.display_unredacted().to_string();
    println!("ONION_ADDRESS={address}");
    info!(%address, "onion service launched");

    tokio::spawn(log_status(service, launched));

    let mut streams = std::pin::pin!(handle_rend_requests(rend_requests));
    loop {
        tokio::select! {
            request = streams.next() => {
                let Some(request) = request else { break };
                handle_stream_request(request, router.clone());
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

/// Accept `BEGIN` requests on the virtual port and serve each accepted
/// `DataStream` through the same hyper path as TCP connections.
fn handle_stream_request(
    request: tor_hsservice::StreamRequest,
    router: axum::Router,
) {
    match request.request() {
        IncomingStreamRequest::Begin(begin) if begin.port() == VIRT_PORT => {
            tokio::spawn(async move {
                match request.accept(Connected::new_empty()).await {
                    Ok(stream) => {
                        info!("onion stream accepted (peer is a rendezvous circuit)");
                        serve_onion_stream(stream, router);
                    }
                    Err(err) => warn!(%err, "failed to accept onion stream"),
                }
            });
        }
        _ => {
            tokio::spawn(async move {
                if let Err(err) = request
                    .reject(End::new_with_reason(EndReason::DONE))
                    .await
                {
                    warn!(%err, "failed to reject onion stream");
                }
            });
        }
    }
}

fn serve_onion_stream(stream: DataStream, router: axum::Router) {
    serve_stream(stream, router, SYNTHETIC_PEER);
}

/// Log every onion-service status transition with elapsed time since
/// launch; prints the launch→Running timing line for the harness.
async fn log_status(service: std::sync::Arc<RunningOnionService>, launched: Instant) {
    let mut events = std::pin::pin!(service.status_events());
    while let Some(status) = events.next().await {
        let state = status.state();
        info!(?state, elapsed = launched.elapsed().as_secs_f64(), "onion service status");
        if state.is_fully_reachable() {
            println!(
                "TIMING launch_to_running_secs={:.3}",
                launched.elapsed().as_secs_f64()
            );
        }
    }
}
