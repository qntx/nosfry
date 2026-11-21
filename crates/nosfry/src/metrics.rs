//! Prometheus metrics: fixed, lock-free counters rendered in the text
//! exposition format for `GET /metrics`.
//!
//! Every label set is fixed and bounded — `verb` labels index the
//! `ClientVerb`/`RelayVerb` enums, `outcome` indexes [`EventOutcome`],
//! and `kind` gets at most [`MAX_KIND_SERIES`] own series with the
//! rest counting under `kind="other"` — and counting sits on the
//! per-message hot path, so storage is flat arrays of atomics: no
//! locks, no allocation, all `Relaxed`.

use std::fmt::Write as _;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use nosfry_core::message::{ClientVerb, RelayVerb};
use nosfry_core::store::WriteOutcome;

/// Kinds that get their own `nostr_events_total{kind}` series —
/// first-seen, stable for the process lifetime. Every further kind
/// counts under `kind="other"`, keeping the label set bounded no
/// matter what the store holds.
const MAX_KIND_SERIES: u64 = 256;

/// One store operation for `nosfry_store_errors_total{op}`.
#[derive(Debug, Clone, Copy)]
pub(crate) enum StoreOp {
    /// A batched `Store::write` commit.
    Write,
    /// The periodic expiry sweep.
    Expire,
    /// One stored-event scan step.
    Scan,
    /// A NIP-62 vanish sweep.
    Vanish,
    /// A NIP-86 management write.
    Moderate,
}

impl StoreOp {
    /// Every op in render order.
    const ALL: [Self; 5] = [
        Self::Write,
        Self::Expire,
        Self::Scan,
        Self::Vanish,
        Self::Moderate,
    ];

    /// The `op` label value.
    const fn as_str(self) -> &'static str {
        match self {
            Self::Write => "write",
            Self::Expire => "expire",
            Self::Scan => "scan",
            Self::Vanish => "vanish",
            Self::Moderate => "moderate",
        }
    }
}

/// One verified-EVENT publish outcome for
/// `nosfry_event_outcomes_total{outcome}` — where a publish that
/// passed verification stopped. Pre-verification refusals
/// (`invalid:`, `restricted:`, `rate-limited:`) are session-level and
/// counted under `nosfry_rate_limited_total` instead.
#[derive(Debug, Clone, Copy)]
pub(crate) enum EventOutcome {
    /// Persisted to the store.
    Stored,
    /// Ephemeral kind — broadcast, never written.
    Ephemeral,
    /// The id was already stored.
    Duplicate,
    /// An equal-or-newer replaceable/addressable version is stored.
    Superseded,
    /// A stored kind-5 deletion blocks it.
    Deleted,
    /// A NIP-62 vanish point covers it.
    Vanished,
    /// The NIP-86 snapshot refused it.
    Moderated,
    /// The write-policy plugin rejected or shadow-rejected it.
    Policy,
    /// The writer queue charge, send, or commit failed.
    Error,
}

impl EventOutcome {
    /// Every outcome in render order.
    const ALL: [Self; 9] = [
        Self::Stored,
        Self::Ephemeral,
        Self::Duplicate,
        Self::Superseded,
        Self::Deleted,
        Self::Vanished,
        Self::Moderated,
        Self::Policy,
        Self::Error,
    ];

    /// The `outcome` label value.
    const fn as_str(self) -> &'static str {
        match self {
            Self::Stored => "stored",
            Self::Ephemeral => "ephemeral",
            Self::Duplicate => "duplicate",
            Self::Superseded => "superseded",
            Self::Deleted => "deleted",
            Self::Vanished => "vanished",
            Self::Moderated => "moderated",
            Self::Policy => "policy",
            Self::Error => "error",
        }
    }

    /// The outcome label for a store [`WriteOutcome`] (`Ephemeral` is
    /// mapped for completeness — the native writer never sees one:
    /// connections broadcast ephemeral events themselves).
    pub(crate) const fn of(outcome: WriteOutcome) -> Self {
        match outcome {
            WriteOutcome::Stored { .. } => Self::Stored,
            WriteOutcome::Duplicate => Self::Duplicate,
            WriteOutcome::Superseded => Self::Superseded,
            WriteOutcome::Ephemeral => Self::Ephemeral,
            WriteOutcome::Deleted => Self::Deleted,
            WriteOutcome::Vanished => Self::Vanished,
        }
    }
}

/// Process-wide counters, shared as `Arc<Metrics>`.
#[derive(Debug)]
pub(crate) struct Metrics {
    /// `nostr_client_messages_total{verb}`.
    client: [AtomicU64; ClientVerb::ALL.len()],
    /// `nostr_relay_messages_total{verb}` — only frames actually
    /// written to a socket count.
    relay: [AtomicU64; RelayVerb::ALL.len()],
    /// `nosfry_rate_limited_total{verb}`.
    rate_limited: [AtomicU64; ClientVerb::ALL.len()],
    /// `nostr_events_total{kind}` — one counter per u16 (512 KiB,
    /// allocated once), used only by kinds holding an own series.
    events: Box<[AtomicU64]>,
    /// Per-kind "has its own series" flag, set the first time a kind
    /// is persisted while fewer than [`MAX_KIND_SERIES`] flags exist.
    /// A kind never moves between its own series and `other`, so the
    /// counters stay monotonic.
    own_kind: Box<[AtomicBool]>,
    /// Own series handed out so far (compare-exchange assigned).
    kinds_assigned: AtomicU64,
    /// `nostr_events_total{kind="other"}`.
    events_other: AtomicU64,
    /// `nosfry_event_outcomes_total{outcome}`.
    outcomes: [AtomicU64; EventOutcome::ALL.len()],
    /// `nosfry_connections_rejected_total`.
    rejected: AtomicU64,
    /// `nosfry_store_errors_total{op}`.
    store_errors: [AtomicU64; StoreOp::ALL.len()],
}

impl Metrics {
    /// All counters at zero.
    pub(crate) fn new() -> Self {
        Self {
            client: [const { AtomicU64::new(0) }; ClientVerb::ALL.len()],
            relay: [const { AtomicU64::new(0) }; RelayVerb::ALL.len()],
            rate_limited: [const { AtomicU64::new(0) }; ClientVerb::ALL.len()],
            events: (0..=u16::MAX)
                .map(|_| AtomicU64::new(0))
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            own_kind: (0..=u16::MAX)
                .map(|_| AtomicBool::new(false))
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            kinds_assigned: AtomicU64::new(0),
            events_other: AtomicU64::new(0),
            outcomes: [const { AtomicU64::new(0) }; EventOutcome::ALL.len()],
            rejected: AtomicU64::new(0),
            store_errors: [const { AtomicU64::new(0) }; StoreOp::ALL.len()],
        }
    }

    /// One inbound text frame with a recognized client verb, counted
    /// even when the message is then rejected.
    pub(crate) fn client_message(&self, verb: ClientVerb) {
        if let Some(counter) = self.client.get(verb as usize) {
            counter.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// One frame written to a client socket.
    pub(crate) fn relay_message(&self, verb: RelayVerb) {
        if let Some(counter) = self.relay.get(verb as usize) {
            counter.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// One message refused by a session rate limit.
    pub(crate) fn rate_limited(&self, verb: ClientVerb) {
        if let Some(counter) = self.rate_limited.get(verb as usize) {
            counter.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// One event persisted to the store — the writer counts it, so
    /// duplicates, deletions, and refusals never inflate the series
    /// (strfry counts on `EventWriteStatus::Written` the same way).
    /// The first [`MAX_KIND_SERIES`] kinds ever persisted get their
    /// own series; every later kind counts under `kind="other"`.
    pub(crate) fn event(&self, kind: u16) {
        if self.claim_kind_series(kind) {
            self.events[usize::from(kind)].fetch_add(1, Ordering::Relaxed);
        } else {
            self.events_other.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Whether `kind` holds — or can still claim — its own series.
    /// Assignment is a compare-exchange on [`Self::kinds_assigned`],
    /// so racing first-seens waste at most a slot, never overbook.
    fn claim_kind_series(&self, kind: u16) -> bool {
        let flag = &self.own_kind[usize::from(kind)];
        loop {
            if flag.load(Ordering::Relaxed) {
                return true;
            }
            let assigned = self.kinds_assigned.load(Ordering::Relaxed);
            if assigned >= MAX_KIND_SERIES {
                return false;
            }
            if self
                .kinds_assigned
                .compare_exchange(assigned, assigned + 1, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                flag.store(true, Ordering::Relaxed);
                return true;
            }
        }
    }

    /// One verified publish's outcome.
    pub(crate) fn event_outcome(&self, outcome: EventOutcome) {
        if let Some(counter) = self.outcomes.get(outcome as usize) {
            counter.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// One WebSocket upgrade refused by the connection caps.
    pub(crate) fn connection_rejected(&self) {
        self.rejected.fetch_add(1, Ordering::Relaxed);
    }

    /// One failed store operation.
    pub(crate) fn store_error(&self, op: StoreOp) {
        if let Some(counter) = self.store_errors.get(op as usize) {
            counter.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Render the Prometheus text exposition format (0.0.4);
    /// `connections` is the live gauge read from the connection
    /// limiter, `outbound_pending` the process-wide pending
    /// outbound bytes, `sync_memory` the reserved sync-storage
    /// bytes, and `subscription_bytes` the charged live-subscription
    /// bytes. Counter series at zero are omitted; the gauges are
    /// always emitted.
    pub(crate) fn render(
        &self,
        connections: usize,
        outbound_pending: usize,
        sync_memory: usize,
        subscription_bytes: usize,
    ) -> String {
        let mut out = String::with_capacity(2 * 1024);
        family(
            &mut out,
            "nostr_client_messages_total",
            "Inbound client messages by verb.",
            "counter",
        );
        for (verb, counter) in ClientVerb::ALL.iter().zip(&self.client) {
            verb_series(
                &mut out,
                "nostr_client_messages_total",
                verb.as_str(),
                counter,
            );
        }
        family(
            &mut out,
            "nostr_relay_messages_total",
            "Frames written to clients by verb.",
            "counter",
        );
        for (verb, counter) in RelayVerb::ALL.iter().zip(&self.relay) {
            verb_series(
                &mut out,
                "nostr_relay_messages_total",
                verb.as_str(),
                counter,
            );
        }
        family(
            &mut out,
            "nostr_events_total",
            "Events persisted to the store by kind.",
            "counter",
        );
        for (kind, flag) in self.own_kind.iter().enumerate() {
            if flag.load(Ordering::Relaxed) {
                let value = self.events[kind].load(Ordering::Relaxed);
                if value > 0 {
                    writeln!(out, "nostr_events_total{{kind=\"{kind}\"}} {value}").ok();
                }
            }
        }
        let other = self.events_other.load(Ordering::Relaxed);
        if other > 0 {
            writeln!(out, "nostr_events_total{{kind=\"other\"}} {other}").ok();
        }
        family(
            &mut out,
            "nosfry_event_outcomes_total",
            "Verified EVENT publishes by outcome.",
            "counter",
        );
        for (outcome, counter) in EventOutcome::ALL.iter().zip(&self.outcomes) {
            let value = counter.load(Ordering::Relaxed);
            if value > 0 {
                writeln!(
                    out,
                    "nosfry_event_outcomes_total{{outcome=\"{}\"}} {value}",
                    outcome.as_str()
                )
                .ok();
            }
        }
        family(
            &mut out,
            "nosfry_rate_limited_total",
            "Messages refused by the session rate limits.",
            "counter",
        );
        for (verb, counter) in ClientVerb::ALL.iter().zip(&self.rate_limited) {
            verb_series(
                &mut out,
                "nosfry_rate_limited_total",
                verb.as_str(),
                counter,
            );
        }
        family(
            &mut out,
            "nosfry_connections_rejected_total",
            "Upgrades refused by the connection caps.",
            "counter",
        );
        let rejected = self.rejected.load(Ordering::Relaxed);
        if rejected > 0 {
            writeln!(out, "nosfry_connections_rejected_total {rejected}").ok();
        }
        family(
            &mut out,
            "nosfry_store_errors_total",
            "Failed store operations by op.",
            "counter",
        );
        for (op, counter) in StoreOp::ALL.iter().zip(&self.store_errors) {
            let value = counter.load(Ordering::Relaxed);
            if value > 0 {
                writeln!(
                    out,
                    "nosfry_store_errors_total{{op=\"{}\"}} {value}",
                    op.as_str()
                )
                .ok();
            }
        }
        family(
            &mut out,
            "nosfry_connections",
            "Current WebSocket connections.",
            "gauge",
        );
        writeln!(out, "nosfry_connections {connections}").ok();
        family(
            &mut out,
            "nosfry_outbound_pending_bytes",
            "Pending outbound bytes across all connections.",
            "gauge",
        );
        writeln!(out, "nosfry_outbound_pending_bytes {outbound_pending}").ok();
        family(
            &mut out,
            "nosfry_sync_memory_bytes",
            "Bytes reserved for sealed negentropy sync storages.",
            "gauge",
        );
        writeln!(out, "nosfry_sync_memory_bytes {sync_memory}").ok();
        family(
            &mut out,
            "nosfry_subscription_bytes",
            "Estimated live-subscription bytes charged to the budget.",
            "gauge",
        );
        writeln!(out, "nosfry_subscription_bytes {subscription_bytes}").ok();
        out
    }
}

/// `# HELP`/`# TYPE` header lines for one family.
fn family(out: &mut String, name: &str, help: &str, kind: &str) {
    writeln!(out, "# HELP {name} {help}").ok();
    writeln!(out, "# TYPE {name} {kind}").ok();
}

/// One `{verb="..."}` counter line, omitted while at zero.
fn verb_series(out: &mut String, name: &str, verb: &str, counter: &AtomicU64) {
    let value = counter.load(Ordering::Relaxed);
    if value > 0 {
        writeln!(out, "{name}{{verb=\"{verb}\"}} {value}").ok();
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "unit tests may panic on failure")]
mod tests {
    use super::*;

    #[test]
    fn empty_render_has_families_and_gauge_only() {
        let out = Metrics::new().render(0, 0, 0, 0);
        assert!(out.contains("# HELP nostr_client_messages_total"));
        assert!(out.contains("# TYPE nostr_events_total counter"));
        assert!(out.ends_with("nosfry_subscription_bytes 0\n"));
        assert!(!out.contains('{'), "no series while every counter is 0");
    }

    /// 300 distinct kinds: the first `MAX_KIND_SERIES` (256) keep their
    /// own series, the remaining 44 count under `kind="other"`, and a
    /// kind never migrates between the two.
    #[test]
    fn kind_label_cap_overflows_to_other() {
        let metrics = Metrics::new();
        for kind in 0..300u16 {
            metrics.event(kind);
        }
        let out = metrics.render(0, 0, 0, 0);
        let series: Vec<_> = out
            .lines()
            .filter(|line| line.starts_with("nostr_events_total{"))
            .collect();
        assert_eq!(series.len(), MAX_KIND_SERIES as usize + 1, "{out}");
        for (kind, line) in series[..256].iter().enumerate() {
            assert_eq!(
                *line,
                format!("nostr_events_total{{kind=\"{kind}\"}} 1"),
                "{out}"
            );
        }
        assert_eq!(series[256], "nostr_events_total{kind=\"other\"} 44");
        // An already-capped kind keeps counting under "other"; an own
        // series stays its own.
        metrics.event(400);
        metrics.event(0);
        let out = metrics.render(0, 0, 0, 0);
        assert!(out.contains("nostr_events_total{kind=\"0\"} 2"), "{out}");
        assert!(
            out.contains("nostr_events_total{kind=\"other\"} 45"),
            "{out}"
        );
        assert!(!out.contains("kind=\"400\""), "{out}");
    }

    #[test]
    fn render_exact_text() {
        let metrics = Metrics::new();
        metrics.client_message(ClientVerb::Event);
        metrics.client_message(ClientVerb::Event);
        metrics.client_message(ClientVerb::Req);
        metrics.relay_message(RelayVerb::Ok);
        metrics.relay_message(RelayVerb::Eose);
        metrics.relay_message(RelayVerb::Auth);
        metrics.event(1);
        metrics.event(7);
        metrics.event_outcome(EventOutcome::Stored);
        metrics.event_outcome(EventOutcome::Duplicate);
        metrics.event_outcome(EventOutcome::Moderated);
        metrics.rate_limited(ClientVerb::Event);
        metrics.connection_rejected();
        metrics.store_error(StoreOp::Write);
        metrics.store_error(StoreOp::Scan);
        metrics.store_error(StoreOp::Scan);
        assert_eq!(
            metrics.render(3, 512, 0, 7),
            "# HELP nostr_client_messages_total Inbound client messages by verb.\n\
             # TYPE nostr_client_messages_total counter\n\
             nostr_client_messages_total{verb=\"EVENT\"} 2\n\
             nostr_client_messages_total{verb=\"REQ\"} 1\n\
             # HELP nostr_relay_messages_total Frames written to clients by verb.\n\
             # TYPE nostr_relay_messages_total counter\n\
             nostr_relay_messages_total{verb=\"EOSE\"} 1\n\
             nostr_relay_messages_total{verb=\"OK\"} 1\n\
             nostr_relay_messages_total{verb=\"AUTH\"} 1\n\
             # HELP nostr_events_total Events persisted to the store by kind.\n\
             # TYPE nostr_events_total counter\n\
             nostr_events_total{kind=\"1\"} 1\n\
             nostr_events_total{kind=\"7\"} 1\n\
             # HELP nosfry_event_outcomes_total Verified EVENT publishes by outcome.\n\
             # TYPE nosfry_event_outcomes_total counter\n\
             nosfry_event_outcomes_total{outcome=\"stored\"} 1\n\
             nosfry_event_outcomes_total{outcome=\"duplicate\"} 1\n\
             nosfry_event_outcomes_total{outcome=\"moderated\"} 1\n\
             # HELP nosfry_rate_limited_total Messages refused by the session rate limits.\n\
             # TYPE nosfry_rate_limited_total counter\n\
             nosfry_rate_limited_total{verb=\"EVENT\"} 1\n\
             # HELP nosfry_connections_rejected_total Upgrades refused by the connection caps.\n\
             # TYPE nosfry_connections_rejected_total counter\n\
             nosfry_connections_rejected_total 1\n\
             # HELP nosfry_store_errors_total Failed store operations by op.\n\
             # TYPE nosfry_store_errors_total counter\n\
             nosfry_store_errors_total{op=\"write\"} 1\n\
             nosfry_store_errors_total{op=\"scan\"} 2\n\
             # HELP nosfry_connections Current WebSocket connections.\n\
             # TYPE nosfry_connections gauge\n\
             nosfry_connections 3\n\
             # HELP nosfry_outbound_pending_bytes Pending outbound bytes across all connections.\n\
             # TYPE nosfry_outbound_pending_bytes gauge\n\
             nosfry_outbound_pending_bytes 512\n\
             # HELP nosfry_sync_memory_bytes Bytes reserved for sealed negentropy sync storages.\n\
             # TYPE nosfry_sync_memory_bytes gauge\n\
             nosfry_sync_memory_bytes 0\n\
             # HELP nosfry_subscription_bytes Estimated live-subscription bytes charged to the budget.\n\
             # TYPE nosfry_subscription_bytes gauge\n\
             nosfry_subscription_bytes 7\n"
        );
    }
}
