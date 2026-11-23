//! Bridge local TCP clients onto a nosfry embedded onion listener:
//! `onion_bridge <onion-host> <local-port>` listens on
//! `127.0.0.1:<local-port>` and pipes each connection to
//! `<onion-host>:80` over Tor.
//!
//! For conformance runs through the onion address:
//!
//! ```sh
//! cargo run -p nosfry --features onion --example onion_bridge -- \
//!     <addr>.onion 17878 &
//! crates/nosfry-conformance/run.sh remote ws://127.0.0.1:17878
//! ```

#![allow(
    clippy::print_stderr,
    unused_crate_dependencies,
    reason = "progress goes to stderr; deps cover the whole package"
)]

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use arti_client::TorClient;
use futures_util::StreamExt as _;
use tokio::net::{TcpListener, TcpStream};
use tor_rtcompat::PreferredRuntime;

type Client = TorClient<PreferredRuntime>;

/// One bridged connection: dial the onion service and splice.
#[allow(
    clippy::future_not_send,
    reason = "Arti client futures are not Send; all connections share one task"
)]
async fn pipe(client: Arc<Client>, mut inbound: TcpStream, host: String) {
    // Erase the connect future: `TorClient`'s concrete type graph
    // overflows the auto-trait solver when it is stored in this
    // future.
    let connecting: Pin<Box<dyn Future<Output = arti_client::Result<arti_client::DataStream>>>> =
        Box::pin(client.connect((host.clone(), 80u16)));
    let Ok(mut outbound) = connecting
        .await
        .inspect_err(|err| eprintln!("connect {host}: {err}"))
    else {
        return;
    };
    tokio::io::copy_bidirectional(&mut inbound, &mut outbound)
        .await
        .ok();
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let host = args
        .next()
        .ok_or("usage: onion_bridge <onion-host> <local-port>")?;
    let port: u16 = args
        .next()
        .ok_or("usage: onion_bridge <onion-host> <local-port>")?
        .parse()?;

    let client =
        TorClient::create_bootstrapped(arti_client::config::TorClientConfig::default()).await?;
    let listener = TcpListener::bind(("127.0.0.1", port)).await?;
    eprintln!("bridging 127.0.0.1:{port} -> {host}:80 over tor");

    // Arti's client futures are not `Send`; every connection is
    // driven cooperatively in this one current-thread task.
    let mut pending = futures_util::stream::FuturesUnordered::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (inbound, _) = accepted?;
                pending.push(pipe(Arc::clone(&client), inbound, host.clone()));
            }
            Some(()) = pending.next() => {}
        }
    }
}
