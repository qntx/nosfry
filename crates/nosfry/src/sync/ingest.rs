//! The download write path: every event the peer sends passes the
//! same wire validation a network `EVENT` gets, then moderation and
//! the write-policy plugin, before [`Store::write`]. Refusals are
//! counted (`refused_local` for our rules, `refused_remote` for peer
//! misbehavior), logged at debug with id and reason — never content.

use std::collections::HashSet;
use std::sync::Arc;

use nosfry_core::auth::AUTH_KIND;
use nosfry_core::event::{Event, EventId, UnverifiedEvent};
use nosfry_core::filter::Filter;
use nosfry_core::limits::Limits;
use nosfry_core::policy::Decision;
use nosfry_core::store::WriteOutcome;
use nosfry_lmdb::{Store, StoreError};

use super::{SyncError, SyncStats};
use crate::policy::WritePolicy;

/// Index entries per `vanish_step` while draining (import's cap).
const VANISH_STEP: usize = 10_000;

/// What the download write path shares: the store, the local limits,
/// the peer URL (write-policy `sourceInfo`), and the plugin.
pub(crate) struct Ctx<'a> {
    /// The local store.
    pub(crate) store: &'a Store,
    /// Session limits from the local config.
    pub(crate) limits: &'a Limits,
    /// The peer URL as given.
    pub(crate) url: &'a str,
    /// The configured write-policy plugin, if any.
    pub(crate) policy: Option<&'a WritePolicy>,
}

/// Ingest one downloaded batch: validate each event, write the
/// survivors in a single transaction, and drain queued vanish work.
/// `requested` is the id set the batch's `REQ` asked for; the return
/// is how many distinct requested ids the peer actually delivered —
/// refusals count, missing ids do not (the caller fails them).
///
/// # Errors
///
/// [`SyncError::Store`] on an LMDB failure; refusals are tallies,
/// never errors.
pub(crate) async fn batch(
    ctx: &Ctx<'_>,
    jsons: &[String],
    requested: &HashSet<EventId>,
    filter: &Filter,
    now: u64,
    stats: &mut SyncStats,
) -> Result<u64, SyncError> {
    // The moderation snapshot is re-read per batch so bans made
    // through a running relay apply to the next batch.
    let moderation = ctx.store.moderation().map_err(SyncError::Store)?;
    let mut matched = HashSet::new();
    let mut accepted: Vec<Arc<Event>> = Vec::with_capacity(jsons.len());
    for json in jsons {
        match check(ctx, json, requested, filter, now, &moderation).await {
            Ok(event) => {
                matched.insert(event.id());
                accepted.push(event);
            }
            Err(drop) => tally_drop(&drop, &mut matched, stats),
        }
    }
    let delivered = u64::try_from(matched.len()).unwrap_or(u64::MAX);
    if accepted.is_empty() {
        return Ok(delivered);
    }
    let written = ctx
        .store
        .write(&accepted, ctx.limits.auth.names())
        .map_err(SyncError::Store)?;
    for outcome in &written.outcomes {
        match outcome {
            WriteOutcome::Stored { .. } => stats.downloaded += 1,
            WriteOutcome::Duplicate => stats.duplicates += 1,
            WriteOutcome::Superseded | WriteOutcome::Deleted | WriteOutcome::Vanished => {
                stats.superseded_or_deleted += 1;
            }
            WriteOutcome::Ephemeral => {}
        }
    }
    if written.vanish_pending {
        drain_vanish(ctx.store)?;
    }
    Ok(delivered)
}

/// Drain queued NIP-62 vanish work like `import` does.
fn drain_vanish(store: &Store) -> Result<(), StoreError> {
    while store.vanish_step(VANISH_STEP)?.more {}
    Ok(())
}

/// Count one refused download toward the blaming side.
fn tally_drop(refusal: &Refusal, matched: &mut HashSet<EventId>, stats: &mut SyncStats) {
    if let Some(id) = refusal.id {
        matched.insert(id);
        tracing::debug!(%id, reason = %refusal.reason, "refused downloaded event");
    } else {
        tracing::debug!(reason = %refusal.reason, "refused downloaded event");
    }
    if refusal.remote {
        stats.refused_remote += 1;
    } else {
        stats.refused_local += 1;
    }
}

/// A refused event and which side to blame.
struct Refusal {
    /// The parsed id when known (a delivered-but-refused event still
    /// counts as delivered).
    id: Option<EventId>,
    /// Debug-log reason.
    reason: String,
    /// `true` = `refused_remote`, `false` = `refused_local`.
    remote: bool,
}

impl Refusal {
    const fn remote(id: Option<EventId>, reason: String) -> Self {
        Self {
            id,
            reason,
            remote: true,
        }
    }

    const fn local(id: Option<EventId>, reason: String) -> Self {
        Self {
            id,
            reason,
            remote: false,
        }
    }
}

/// Run the full wire-validation list on one event, in order; `Err`
/// carries the refusal, `Ok` a verified event ready for
/// `Store::write`.
async fn check(
    ctx: &Ctx<'_>,
    json: &str,
    requested: &HashSet<EventId>,
    filter: &Filter,
    now: u64,
    moderation: &nosfry_core::moderation::Moderation,
) -> Result<Arc<Event>, Refusal> {
    // (1) Canonical parse + event limits.
    let unverified = UnverifiedEvent::parse(json, &ctx.limits.event)
        .map_err(|err| Refusal::remote(None, err.reason()))?;
    // (2) The id must have been requested.
    let id = unverified.id();
    if !requested.contains(&id) {
        return Err(Refusal::remote(Some(id), "unrequested event id".to_owned()));
    }
    // (3) Not too far in the future (no past bound: backfill is the
    // purpose).
    if unverified.created_at()
        > now.saturating_add(ctx.limits.event.reject_events_newer_than_seconds)
    {
        return Err(Refusal::local(
            Some(id),
            "created_at is too far in the future".to_owned(),
        ));
    }
    // (4) AUTH kind, ephemeral kinds, already-expired events.
    if unverified.kind() == AUTH_KIND {
        return Err(Refusal::local(Some(id), "kind 22242".to_owned()));
    }
    if unverified.kind().is_ephemeral() {
        return Err(Refusal::local(Some(id), "ephemeral kind".to_owned()));
    }
    if unverified.expiration().is_some_and(|at| at <= now) {
        return Err(Refusal::local(Some(id), "event has expired".to_owned()));
    }
    // (5) NIP-70 protected events and reposts embedding them.
    if unverified.is_protected() {
        return Err(Refusal::local(
            Some(id),
            "event marked as protected".to_owned(),
        ));
    }
    if unverified.embeds_protected() {
        return Err(Refusal::local(
            Some(id),
            "reposts can't embed protected events".to_owned(),
        ));
    }
    // (6) The `[relay.access]` write gate for an unauthenticated
    // writer — the same verdict the session applies: a gated kind
    // AUTH cannot fix is refused when AUTH is disabled, and every
    // `authenticated`/`author` write rule refuses the sync peer,
    // which is never an authenticated author.
    if let Some(refusal) =
        ctx.limits
            .auth
            .write_gate(unverified.kind().0, &unverified.pubkey(), &[])
    {
        return Err(Refusal::local(
            Some(id),
            refusal.detail(unverified.kind().0),
        ));
    }
    // (7) The BIP-340 signature — never skipped.
    let event = unverified
        .verify(&ctx.limits.event)
        .map_err(|err| Refusal::remote(Some(id), err.reason()))?;
    // (8) The window filter.
    if !filter.matches(event.packed()) {
        return Err(Refusal::remote(
            Some(id),
            "event does not match the window filter".to_owned(),
        ));
    }
    let event = Arc::new(event);
    // NIP-62 requests naming this relay skip moderation and policy.
    let vanish = event.requests_vanish(ctx.limits.auth.names());
    // (9) NIP-86 moderation.
    if !vanish && let Some(reason) = ctx.limits.auth.access().write_blocked(moderation, &event) {
        return Err(Refusal::local(Some(id), reason.to_owned()));
    }
    // (10) The write-policy plugin, `sourceType` `Sync`.
    if !vanish
        && let Some(policy) = ctx.policy
        && !matches!(policy.check_sync(&event, ctx.url).await, Decision::Accept)
    {
        return Err(Refusal::local(
            Some(id),
            "rejected by write policy".to_owned(),
        ));
    }
    Ok(event)
}
