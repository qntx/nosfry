//! Tor onion client for the spike: a separate Arti client that dials
//! the relay's onion address, does a WebSocket handshake, publishes a
//! signed kind-1 event, waits for `OK true`, REQs it back, and fetches
//! NIP-11 over a plain HTTP GET.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result, bail};
use arti_client::config::TorClientConfigBuilder;
use arti_client::{DataStream, TorClient};
use clap::Parser;
use futures::{SinkExt as _, StreamExt as _};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio_tungstenite::tungstenite::Message;
use tor_rtcompat::PreferredRuntime;
use tracing::info;

#[derive(Parser)]
#[command(about = "nosfry client over Tor onion (Arti)")]
struct Cli {
    /// Onion address of the relay (`<base32>.onion`).
    address: String,
    /// Arti state/cache root for THIS client (separate from the relay).
    #[arg(long)]
    state_dir: PathBuf,
    /// Poll connect+handshake every 2s until the first success, then
    /// continue with the normal flow. Reports time-to-first-success.
    #[arg(long)]
    probe: bool,
    /// Open N WebSocket connections and hold them open (for RSS
    /// measurements). Disables the publish/REQ flow.
    #[arg(long)]
    hold: Option<usize>,
}

type Client = TorClient<PreferredRuntime>;

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

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

async fn connect(client: &Client, address: &str) -> Result<DataStream> {
    client
        .connect((address, 80))
        .await
        .context("onion connect")
}

async fn run(cli: Cli) -> Result<()> {
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

    let address = cli.address.trim_end_matches(".onion");
    let address = format!("{address}.onion");

    if let Some(n) = cli.hold {
        return hold_connections(&client, &address, n).await;
    }

    let started = Instant::now();
    let stream = loop {
        match connect(&client, &address).await {
            Ok(stream) => break stream,
            Err(err) => {
                if !cli.probe {
                    return Err(err);
                }
                info!(%err, "connect attempt failed; retrying in 2s");
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    };
    if cli.probe {
        println!(
            "TIMING first_connect_secs={:.3}",
            started.elapsed().as_secs_f64()
        );
    }

    // NIP-11 over a plain HTTP GET on its own stream.
    nip11(&client, &address).await?;

    // WebSocket handshake over the Tor stream, then publish + REQ.
    let hs = Instant::now();
    let (mut ws, _response) =
        tokio_tungstenite::client_async(format!("ws://{address}/"), stream)
            .await
            .context("websocket handshake")?;
    if cli.probe {
        println!(
            "TIMING first_ws_handshake_secs={:.3}",
            started.elapsed().as_secs_f64()
        );
    }
    info!(elapsed = hs.elapsed().as_secs_f64(), "ws handshake done");

    publish_and_req(&mut ws).await?;
    latency_samples(&mut ws, 12).await?;
    Ok(())
}

/// Open `n` WebSocket connections and park them until ctrl-c.
async fn hold_connections(client: &Client, address: &str, n: usize) -> Result<()> {
    let url = format!("ws://{address}/");
    let mut sockets = Vec::with_capacity(n);
    for i in 0..n {
        let stream = connect(client, address).await?;
        let (ws, _) = tokio_tungstenite::client_async(url.as_str(), stream)
            .await
            .context("websocket handshake")?;
        sockets.push(ws);
        info!(i, "held connection up");
    }
    println!("HELD {n}");
    tokio::signal::ctrl_c().await?;
    Ok(())
}

/// HTTP GET `/` with `Accept: application/nostr+json` and print the
/// response status line plus the NIP-11 document.
async fn nip11(client: &Client, address: &str) -> Result<()> {
    let mut stream = connect(client, address).await?;
    let request = format!(
        "GET / HTTP/1.1\r\nHost: {address}\r\nAccept: application/nostr+json\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await?;
    // `DataWriter` buffers writes into relay cells; unlike a TCP
    // socket, `write_all` alone does not send a partial cell.
    stream.flush().await?;
    // When the service side drops its accepted `DataStream` after
    // `Connection: close`, arti sends an END cell with reason MISC,
    // which this client's `DataReader` surfaces as an error rather than
    // EOF (only END(DONE) maps to `Ok(0)`). Stop reading as soon as the
    // complete response has arrived; tolerate a terminating error if
    // the response is already complete.
    let mut response = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match stream.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                response.extend_from_slice(&buf[..n]);
                if http_response_complete(&response) {
                    break;
                }
            }
            Err(err) => {
                if http_response_complete(&response) {
                    break;
                }
                return Err(err).context("read nip11 response");
            }
        }
    }
    let text = String::from_utf8_lossy(&response);
    let status = text.lines().next().unwrap_or("<empty>");
    println!("NIP11_STATUS={status}");
    if let Some((_, body)) = text.split_once("\r\n\r\n") {
        println!("NIP11_BODY={body}");
    }
    Ok(())
}

/// True once `buf` holds complete HTTP/1.1 headers plus the body bytes
/// promised by `Content-Length` (or headers alone when absent).
fn http_response_complete(buf: &[u8]) -> bool {
    let Some(header_end) = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
    else {
        return false;
    };
    let headers = String::from_utf8_lossy(&buf[..header_end]).to_lowercase();
    let content_length = headers
        .lines()
        .find_map(|line| line.strip_prefix("content-length:"))
        .and_then(|v| v.trim().parse::<usize>().ok());
    match content_length {
        Some(len) => buf.len() - header_end >= len,
        None => true,
    }
}

/// Publish one signed kind-1 event, require `OK true`, then REQ it by
/// id and require the EVENT back plus EOSE.
async fn publish_and_req(
    ws: &mut tokio_tungstenite::WebSocketStream<DataStream>,
) -> Result<()> {
    let event = nosfry_core::sign::event(
        &nosfry_core::sign::key(1),
        1,
        now_secs(),
        &json!([]),
        "hello over tor",
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
    ws: &mut tokio_tungstenite::WebSocketStream<DataStream>,
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
    ws: &mut tokio_tungstenite::WebSocketStream<DataStream>,
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
