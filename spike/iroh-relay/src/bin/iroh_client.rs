//! Native iroh client for the spike: dials the relay node over the
//! `nosfry/http1` ALPN, runs a WebSocket handshake on one bi stream,
//! publishes a signed kind-1 event, waits for `OK true`, REQs it back,
//! and reports connect/handshake/publish timings.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result, bail};
use clap::Parser;
use futures::{SinkExt as _, StreamExt as _};
use iroh_relay_spike::{ALPN, BiStream, endpoint, parse_peer, secret_key};
use serde_json::{Value, json};
use tokio_tungstenite::tungstenite::Message;

#[derive(Parser)]
#[command(about = "nosfry client over iroh (ALPN nosfry/http1)")]
struct Cli {
    /// `<endpoint-id>` (z32) or `ticket:<hex>` of the relay node.
    peer: String,
    /// Ephemeral secret key file (created 0600 on first run).
    #[arg(long, default_value = "client-key")]
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
    /// Number of connect+handshake timing repetitions.
    #[arg(long, default_value_t = 5)]
    reps: usize,
    /// Publish->OK latency samples on the last connection.
    #[arg(long, default_value_t = 12)]
    samples: usize,
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

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

async fn run(cli: Cli) -> Result<()> {
    let peer = parse_peer(&cli.peer)?;
    let key = secret_key(&cli.key)?;
    let bind = Instant::now();
    let ep = endpoint(&key, cli.relay_only, cli.relay_url.as_deref(), cli.no_relay).await?;
    println!("TIMING endpoint_bind_ms={:.1}", bind.elapsed().as_secs_f64() * 1000.0);
    println!("ENDPOINT_ID={}", ep.id());

    let url = format!("ws://{}/", peer.id);
    for rep in 0..cli.reps {
        let t0 = Instant::now();
        let conn = ep
            .connect(peer.clone(), ALPN)
            .await
            .context("iroh connect")?;
        let connect_ms = t0.elapsed().as_secs_f64() * 1000.0;
        println!("CONNECT {rep} {connect_ms:.1}ms");
        for path in conn.paths().iter() {
            println!(
                "PATH {rep} remote={} kind={} selected={}",
                path.remote_addr(),
                if path.is_relay() { "relay" } else { "ip" },
                path.is_selected()
            );
        }
        let t1 = Instant::now();
        let (send, recv) = conn.open_bi().await.context("open_bi")?;
        let (mut ws, _) =
            tokio_tungstenite::client_async(&url, BiStream { recv, send })
                .await
                .context("websocket handshake")?;
        let ws_ms = t1.elapsed().as_secs_f64() * 1000.0;
        println!("WS_HANDSHAKE {rep} {ws_ms:.1}ms");
        println!("TOTAL_CONNECT {rep} {:.1}ms", connect_ms + ws_ms);

        if rep == 0 {
            publish_and_req(&mut ws).await?;
        }
        if rep + 1 == cli.reps {
            latency_samples(&mut ws, cli.samples).await?;
        }
        conn.close(0u32.into(), b"done");
    }
    Ok(())
}

/// Publish one signed kind-1 event, require `OK true`, then REQ it by
/// id and require the EVENT back plus EOSE.
async fn publish_and_req(
    ws: &mut tokio_tungstenite::WebSocketStream<BiStream>,
) -> Result<()> {
    let event = nosfry_core::sign::event(
        &nosfry_core::sign::key(1),
        1,
        now_secs(),
        &json!([]),
        "hello over iroh",
    );
    let id = Value::from(event.id().to_string());
    let publish = format!("[\"EVENT\",{}]", event.json());
    ws.send(Message::text(publish)).await?;
    let ok = next_text(ws).await?;
    println!("PUBLISH_OK={ok}");
    if !ok.contains("true") {
        bail!("publish rejected: {ok}");
    }
    let req = format!("[\"REQ\",\"spike\",{{\"ids\":[{id}]}}]");
    ws.send(Message::text(req)).await?;
    let mut got_event = false;
    let mut got_eose = false;
    for _ in 0..8 {
        let msg = next_text(ws).await?;
        println!("RESP={msg}");
        if msg.starts_with("[\"EVENT\",\"spike\"") {
            got_event = true;
        }
        if msg.starts_with("[\"EOSE\",\"spike\"") {
            got_eose = true;
            break;
        }
    }
    if !got_event || !got_eose {
        bail!("REQ incomplete: event={got_event} eose={got_eose}");
    }
    println!("REQ_RESULT=event+eose");
    Ok(())
}

/// `n` publish→OK round trips on one connection; prints each sample
/// and a p50/max summary.
async fn latency_samples(
    ws: &mut tokio_tungstenite::WebSocketStream<BiStream>,
    n: usize,
) -> Result<()> {
    let mut samples = Vec::with_capacity(n);
    for i in 0..n {
        let event = nosfry_core::sign::event(
            &nosfry_core::sign::key(2),
            1,
            now_secs(),
            &json!([["t", &format!("lat-{i}")]]),
            &format!("latency sample {i}"),
        );
        let publish = format!("[\"EVENT\",{}]", event.json());
        let start = Instant::now();
        ws.send(Message::text(publish)).await?;
        let ok = next_text(ws).await?;
        let ms = start.elapsed().as_secs_f64() * 1000.0;
        if !ok.contains("true") {
            bail!("publish {i} rejected: {ok}");
        }
        samples.push(ms);
        println!("RTT_SAMPLE {i} {ms:.1}ms");
    }
    samples.sort_by(f64::total_cmp);
    let p50 = samples[samples.len() / 2];
    let max = samples[samples.len() - 1];
    println!("TIMING publish_ok_p50_ms={p50:.1}");
    println!("TIMING publish_ok_max_ms={max:.1}");
    Ok(())
}

async fn next_text(
    ws: &mut tokio_tungstenite::WebSocketStream<BiStream>,
) -> Result<String> {
    loop {
        let Some(frame) = ws.next().await else {
            bail!("websocket closed");
        };
        let frame = frame?;
        if let Message::Text(text) = frame {
            return Ok(text.to_string());
        }
    }
}
