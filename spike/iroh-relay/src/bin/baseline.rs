//! TCP-only nosfry relay: the feature-off baseline for size/build
//! comparisons.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use iroh_relay_spike::{relay_server, tcp_accept_loop};
use nosfry::config::Config;
use tokio::net::TcpListener;

#[derive(Parser)]
#[command(about = "nosfry relay, plain TCP only")]
struct Cli {
    /// nosfry config file.
    #[arg(long)]
    config: PathBuf,
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

async fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::load(&cli.config)?;
    let bind = (config.relay.bind, config.relay.port);
    let keepalive = config.relay.tcp_keepalive;
    let (_server, router) = relay_server(config)?;
    let listener = TcpListener::bind(bind).await?;
    tracing::info!(addr = %listener.local_addr()?, "TCP listener up");
    tokio::select! {
        () = tcp_accept_loop(listener, router, keepalive) => {},
        res = tokio::signal::ctrl_c() => { res?; },
    }
    Ok(())
}
