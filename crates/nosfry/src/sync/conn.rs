//! The client WebSocket: text frames in and out, with NIP-42 AUTH
//! handled transparently — a challenge is answered immediately when a
//! key is loaded, and the `OK` for the AUTH event is consumed here so
//! the engine only sees its `auth_epoch` advance.

use std::time::Duration;

use futures_util::SinkExt;
use nosfry_core::client::RelayMessage;
use nosfry_core::event::EventId;
use secp256k1::Keypair;
use tokio::io::{AsyncRead, AsyncWrite};
use yawc::{Frame, OpCode, WebSocket};

use super::{SyncError, auth, now_secs};

/// Peer messages the engine consumes, owned.
#[derive(Debug)]
pub(crate) enum Msg {
    /// `EVENT` for `sub`, carrying the raw event JSON.
    Event {
        /// Subscription id.
        sub: String,
        /// Raw event object JSON.
        json: String,
    },
    /// `OK` for a published (non-AUTH) event.
    Ok {
        /// The event id answered.
        id: EventId,
        /// Whether the peer accepted it.
        accepted: bool,
        /// The NIP-01 message.
        message: String,
        /// `rate-limited` retry hint, milliseconds.
        retry_after_ms: Option<u64>,
    },
    /// `EOSE` for `sub`.
    Eose {
        /// Subscription id.
        sub: String,
    },
    /// `CLOSED` for `sub`.
    Closed {
        /// Subscription id.
        sub: String,
        /// The NIP-01 message.
        message: String,
        /// `rate-limited` retry hint, milliseconds.
        retry_after_ms: Option<u64>,
    },
    /// `NOTICE`.
    Notice {
        /// The relay's message.
        message: String,
    },
    /// `NEG-MSG` for `sub`, payload hex-decoded.
    Neg {
        /// Subscription id.
        sub: String,
        /// The decoded negentropy message.
        msg: Vec<u8>,
    },
    /// `NEG-ERR` for `sub`.
    NegErr {
        /// Subscription id.
        sub: String,
        /// The NIP-01 message.
        message: String,
        /// The optional `blocked:` result cap.
        limit: Option<u64>,
    },
    /// NIP-42 AUTH just succeeded — the engine requeues the open
    /// window.
    Authed,
}

/// Peer-supplied strings in errors and logs are truncated to this.
const PEER_STR_MAX: usize = 200;

/// Truncate a peer string for an error or log line.
pub(crate) fn trunc(s: &str) -> &str {
    if s.len() <= PEER_STR_MAX {
        return s;
    }
    let mut end = PEER_STR_MAX;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// The client connection: a `yawc::WebSocket` plus NIP-42 state.
pub(crate) struct RelayConn<S> {
    ws: WebSocket<S>,
    /// The peer URL as given — the AUTH event's `relay` tag.
    url: String,
    /// Loaded `--auth-key-file` key, if any.
    key: Option<Keypair>,
    /// The latest challenge the peer sent.
    challenge: Option<String>,
    /// The AUTH event id awaiting its `OK`.
    pending_auth: Option<EventId>,
    /// AUTH succeeded.
    authed: bool,
    /// Bumped each time AUTH succeeds; a window opened before an
    /// advance is reconciled again.
    auth_epoch: u64,
}

impl<S> RelayConn<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    /// Wrap `ws`; `key` answers NIP-42 challenges when present.
    pub(crate) const fn new(ws: WebSocket<S>, url: String, key: Option<Keypair>) -> Self {
        Self {
            ws,
            url,
            key,
            challenge: None,
            pending_auth: None,
            authed: false,
            auth_epoch: 0,
        }
    }

    /// Whether authentication succeeded on this connection.
    pub(crate) const fn authed(&self) -> bool {
        self.authed
    }

    /// The auth epoch (see `auth_epoch`).
    pub(crate) const fn auth_epoch(&self) -> u64 {
        self.auth_epoch
    }

    /// An `AUTH` reply was sent whose `OK` has not arrived yet.
    pub(crate) const fn auth_pending(&self) -> bool {
        self.pending_auth.is_some()
    }

    /// Whether a key was loaded (the peer may still not have asked).
    pub(crate) const fn has_key(&self) -> bool {
        self.key.is_some()
    }

    /// Send one text frame.
    ///
    /// # Errors
    ///
    /// [`SyncError::Lost`] on a socket write failure.
    pub(crate) async fn send(&mut self, text: &str) -> Result<(), SyncError> {
        self.ws
            .send(Frame::text(text.to_owned()))
            .await
            .map_err(|err| SyncError::Lost(err.to_string()))
    }

    /// The next engine-relevant message within `timeout`: pings are
    /// answered (yawc auto-queues the pong; `poll_ready` flushes it),
    /// pongs and unknown verbs are skipped, `NOTICE`s pass through
    /// for the NIP-77 support check, `AUTH` challenges are answered
    /// here, and the AUTH `OK` never escapes.
    ///
    /// # Errors
    ///
    /// [`SyncError::Stalled`] when nothing arrives in `timeout`,
    /// [`SyncError::Closed`] when the peer closes or ends the stream,
    /// [`SyncError::Lost`] on a socket or protocol error, and
    /// [`SyncError::AuthRefused`] when the peer rejects the AUTH
    /// event.
    pub(crate) async fn recv(&mut self, timeout: Duration) -> Result<Msg, SyncError> {
        loop {
            if let Some(msg) = self.recv_one(timeout).await? {
                return Ok(msg);
            }
        }
    }

    /// Read one frame and classify it: `Ok(None)` for pings, pongs,
    /// ignored verbs, and consumed AUTH flows.
    async fn recv_one(&mut self, timeout: Duration) -> Result<Option<Msg>, SyncError> {
        // `poll_next_frame` keeps transport errors (the `Stream`
        // impl swallows them); pings are auto-ponged by yawc and
        // never surface here.
        let frame = tokio::time::timeout(
            timeout,
            futures_util::future::poll_fn(|cx| self.ws.poll_next_frame(cx)),
        )
        .await
        .map_err(|_| SyncError::Stalled(timeout.as_secs()))?
        .map_err(|err| SyncError::Lost(err.to_string()))?;
        match frame.opcode() {
            OpCode::Text => {}
            OpCode::Close => {
                // Let the close handshake answer flush.
                drop(SinkExt::close(&mut self.ws).await);
                return Err(SyncError::Closed);
            }
            _ => return Ok(None),
        }
        let text = std::str::from_utf8(frame.payload())
            .map_err(|_| SyncError::Lost("malformed utf-8".to_owned()))?;
        let parsed = RelayMessage::parse(text)
            .map_err(|err| SyncError::Lost(format!("malformed frame: {err}")))?;
        self.dispatch(parsed).await
    }

    /// Map a parsed relay message to an engine [`Msg`]: `AUTH`
    /// challenges and their `OK`s are answered here and never escape,
    /// unknown verbs return `None`.
    async fn dispatch(&mut self, msg: RelayMessage<'_>) -> Result<Option<Msg>, SyncError> {
        let out = match msg {
            RelayMessage::Auth { challenge } => {
                self.on_challenge(challenge).await?;
                return Ok(None);
            }
            RelayMessage::Ok {
                id,
                accepted,
                message,
                ..
            } if self.pending_auth == Some(id) => {
                self.pending_auth = None;
                if !accepted {
                    return Err(SyncError::AuthRefused(trunc(&message).to_owned()));
                }
                self.authed = true;
                self.auth_epoch += 1;
                tracing::info!("peer authentication succeeded");
                Msg::Authed
            }
            RelayMessage::Event { sub, event } => Msg::Event {
                sub: sub.to_owned(),
                json: event.get().to_owned(),
            },
            RelayMessage::Ok {
                id,
                accepted,
                message,
                retry_after_ms,
            } => Msg::Ok {
                id,
                accepted,
                message,
                retry_after_ms,
            },
            RelayMessage::Eose { sub } => Msg::Eose { sub },
            RelayMessage::Closed {
                sub,
                message,
                retry_after_ms,
            } => Msg::Closed {
                sub,
                message,
                retry_after_ms,
            },
            RelayMessage::Notice { message } => {
                tracing::warn!("peer NOTICE: {}", trunc(&message));
                Msg::Notice { message }
            }
            RelayMessage::NegMsg { sub, msg } => Msg::Neg { sub, msg },
            RelayMessage::NegErr {
                sub,
                message,
                limit,
            } => Msg::NegErr {
                sub,
                message,
                limit,
            },
            _ => return Ok(None),
        };
        Ok(Some(out))
    }

    /// Answer an `AUTH` challenge: sign and send `["AUTH", <22242>]`
    /// when a key is loaded, else just remember the peer asked.
    async fn on_challenge(&mut self, challenge: String) -> Result<(), SyncError> {
        self.challenge = Some(challenge.clone());
        let Some(key) = &self.key else {
            tracing::debug!("peer sent an AUTH challenge; no --auth-key-file given");
            return Ok(());
        };
        let (id, json) = auth::auth_event(key, &self.url, &challenge, now_secs())?;
        self.send(&format!("[\"AUTH\",{json}]")).await?;
        self.pending_auth = Some(id);
        Ok(())
    }
}
