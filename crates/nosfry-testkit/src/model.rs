//! The naive in-memory model both differential suites compare
//! against: `Store::write` with NIP-09, scans, and NIP-40 expiry,
//! expressed without indexes.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use nosfry_core::auth::ReadGate;
use nosfry_core::deletion::DeletionTarget;
use nosfry_core::event::{Event, EventId, PublicKey, cmp_newest_first, supersedes};
use nosfry_core::filter::Filter;
use nosfry_core::url::RelayUrl;

/// The store's state model: stored events plus the deletion blocks a
/// kind 5 leaves behind.
#[derive(Debug, Default)]
pub struct Model {
    /// Stored events by seq.
    pub stored: HashMap<u64, Arc<Event>>,
    by_id: HashMap<EventId, u64>,
    by_addr: HashMap<[u8; 32], u64>,
    /// `id ‖ author` → seqs of the kind-5 events blocking it.
    blocked_ids: HashMap<(EventId, PublicKey), HashSet<u64>>,
    /// `address` → `(created_at, seq)` of the kind-5 events blocking it.
    blocked_addrs: HashMap<[u8; 32], Vec<(u64, u64)>>,
    /// NIP-62 vanish points: author → max honored `created_at` `T`.
    /// The model applies the sweep eagerly on write; the point is
    /// permanent so later equal-or-older publishes stay blocked.
    vanish: HashMap<PublicKey, u64>,
}

/// Remove `seq` from the model, lifting the blocks it carried.
fn model_delete_seq(m: &mut Model, seq: u64) {
    let Some(ev) = m.stored.remove(&seq) else {
        return;
    };
    m.by_id.remove(&ev.id());
    if let Some(addr) = ev.address()
        && m.by_addr.get(&addr) == Some(&seq)
    {
        m.by_addr.remove(&addr);
    }
    for target in ev.deletion_targets() {
        match target {
            DeletionTarget::Event(id) => {
                if let Some(set) = m.blocked_ids.get_mut(&(*id, ev.pubkey())) {
                    set.remove(&seq);
                }
            }
            DeletionTarget::Address(addr) => {
                if let Some(list) = m.blocked_addrs.get_mut(addr) {
                    list.retain(|(_, s)| *s != seq);
                }
            }
        }
    }
}

/// Whether a NIP-62 vanish point covers `ev`: the author's `T`
/// blocks its events with `created_at <= T` (kind 62 exempt, checked
/// by the caller), and a kind-1059 gift wrap is blocked by the
/// `p`-tagged recipient's `T`.
fn vanish_blocked(m: &Model, ev: &Event) -> bool {
    if m.vanish
        .get(&ev.pubkey())
        .is_some_and(|t| ev.created_at() <= *t)
    {
        return true;
    }
    ev.kind().0 == 1059
        && ev.packed().tags().any(|(name, value)| {
            name == b'p'
                && <&[u8; 32]>::try_from(value).is_ok_and(|pk| {
                    m.vanish
                        .get(&PublicKey(*pk))
                        .is_some_and(|t| ev.created_at() <= *t)
                })
        })
}

/// Raise `ev`'s author vanish point to `ev.created_at` when the
/// request honors this relay, then apply the sweep — also reached
/// for a superseded kind 62 whose storage is skipped.
fn raise_vanish(m: &mut Model, ev: &Event, service_url: Option<&RelayUrl>) {
    if !ev.requests_vanish(service_url) {
        return;
    }
    let point = m.vanish.entry(ev.pubkey()).or_insert(0);
    *point = (*point).max(ev.created_at());
    let t = *point;
    apply_vanish(m, &ev.pubkey(), t);
}

/// Apply the NIP-62 sweep `t` demands for `author` right away —
/// where the real stores queue it for `vanish_step`, the model
/// deletes at once. Kind 62 survives; only kind-1059 wraps (not
/// mere `p` mentions) are removed for the author.
fn apply_vanish(m: &mut Model, author: &PublicKey, t: u64) {
    let doomed: Vec<u64> = m
        .stored
        .iter()
        .filter(|(_, ev)| {
            if ev.created_at() > t {
                return false;
            }
            if ev.pubkey() == *author {
                return ev.kind().0 != 62;
            }
            ev.kind().0 == 1059
                && ev.packed().tags().any(|(name, value)| {
                    name == b'p' && <&[u8; 32]>::try_from(value).is_ok_and(|pk| *pk == author.0)
                })
        })
        .map(|(seq, _)| *seq)
        .collect();
    for seq in doomed {
        model_delete_seq(m, seq);
    }
}

/// Model `Store::write` in arrival order, NIP-09 and NIP-62
/// included; `service_url` decides which kind-62 `relay` tags this
/// relay honors.
///
/// # Panics
///
/// Panics when the address index references a missing seq — a model
/// bug, never reachable from valid inputs.
#[must_use]
pub fn model_store(events: &[Arc<Event>], service_url: Option<&RelayUrl>) -> Model {
    let mut m = Model::default();
    let mut next_seq = 1u64;
    for ev in events {
        if ev.kind().0 != 62 && vanish_blocked(&m, ev) {
            continue;
        }
        if ev.kind().is_ephemeral() || m.by_id.contains_key(&ev.id()) {
            continue;
        }
        // NIP-62 bookkeeping: only the author's newest request to
        // vanish is stored — a newer stored one supersedes the
        // incoming event, a newer incoming one replaces the rest.
        if ev.kind().0 == 62 {
            let stored62: Vec<u64> = m
                .stored
                .iter()
                .filter(|(_, e)| e.pubkey() == ev.pubkey() && e.kind().0 == 62)
                .map(|(seq, _)| *seq)
                .collect();
            if stored62.iter().any(|&seq| {
                let old = &m.stored[&seq];
                supersedes((old.created_at(), &old.id()), (ev.created_at(), &ev.id()))
            }) {
                // Superseded but still honored — bookkeeping storage
                // is independent of the vanish request itself.
                raise_vanish(&mut m, ev, service_url);
                continue;
            }
            for seq in stored62 {
                model_delete_seq(&mut m, seq);
            }
        }
        if !matches!(ev.kind().0, 5 | 62)
            && m.blocked_ids
                .get(&(ev.id(), ev.pubkey()))
                .is_some_and(|set| !set.is_empty())
        {
            continue; // Deleted by an earlier e target
        }
        if let Some(addr) = ev.address()
            && m.blocked_addrs
                .get(&addr)
                .is_some_and(|list| list.iter().any(|(ca, _)| *ca >= ev.created_at()))
        {
            continue; // Deleted by an earlier a target
        }
        if let Some(addr) = ev.address()
            && let Some(&old_seq) = m.by_addr.get(&addr)
        {
            let old = m
                .stored
                .get(&old_seq)
                .unwrap_or_else(|| panic!("model: missing seq {old_seq}"));
            if !supersedes((ev.created_at(), &ev.id()), (old.created_at(), &old.id())) {
                continue;
            }
            model_delete_seq(&mut m, old_seq);
        }
        let seq = next_seq;
        next_seq += 1;
        m.stored.insert(seq, Arc::clone(ev));
        m.by_id.insert(ev.id(), seq);
        if let Some(addr) = ev.address() {
            m.by_addr.insert(addr, seq);
        }
        if ev.kind().0 == 5 {
            model_apply_deletions(&mut m, ev, seq);
        }
        // NIP-62: raise the vanish point and apply the sweep now —
        // same-batch events stored earlier are covered too.
        raise_vanish(&mut m, ev, service_url);
    }
    m
}

/// Model a stored kind 5: register its blocks, then delete its targets.
fn model_apply_deletions(m: &mut Model, ev: &Event, seq: u64) {
    for target in ev.deletion_targets() {
        match target {
            DeletionTarget::Event(id) => {
                m.blocked_ids
                    .entry((*id, ev.pubkey()))
                    .or_default()
                    .insert(seq);
            }
            DeletionTarget::Address(addr) => {
                m.blocked_addrs
                    .entry(*addr)
                    .or_default()
                    .push((ev.created_at(), seq));
            }
        }
    }
    let targets: Vec<DeletionTarget> = ev.deletion_targets().to_vec();
    for target in targets {
        let tseq = match target {
            DeletionTarget::Event(id) => m.by_id.get(&id).copied(),
            DeletionTarget::Address(addr) => m.by_addr.get(&addr).copied(),
        };
        let Some(tseq) = tseq else {
            continue;
        };
        let deletable = m.stored.get(&tseq).is_some_and(|t| {
            t.pubkey() == ev.pubkey()
                && match target {
                    // NIP-09/NIP-62: deletions and requests to vanish
                    // are never deletable.
                    DeletionTarget::Event(_) => !matches!(t.kind().0, 5 | 62),
                    DeletionTarget::Address(_) => t.created_at() <= ev.created_at(),
                }
        });
        if deletable {
            model_delete_seq(m, tseq);
        }
    }
}

/// Model `Store::expire`: every event with `expiration <= now` goes.
pub fn model_expire(m: &mut Model, now: u64) {
    let due: Vec<u64> = m
        .stored
        .iter()
        .filter(|(_, ev)| ev.expiration().is_some_and(|exp| exp <= now))
        .map(|(seq, _)| *seq)
        .collect();
    for seq in due {
        model_delete_seq(m, seq);
    }
}

/// The per-filter match list [`model_scan`] and [`model_records`]
/// share: match, sort newest first, truncate to the effective limit.
/// Events with `expiration <= now` are hidden and never counted, and
/// `gate` filters every candidate like the real scans do.
fn model_matched<S: std::hash::BuildHasher>(
    stored: &HashMap<u64, Arc<Event>, S>,
    filter: &Filter,
    snapshot: u64,
    gate: &ReadGate,
    max_limit: u64,
    now: u64,
) -> Vec<(u64, EventId, u64)> {
    let limit = filter.effective_limit(max_limit);
    if filter.is_impossible() || limit == 0 {
        return Vec::new();
    }
    let mut matched: Vec<(u64, EventId, u64)> = stored
        .iter()
        .filter(|(seq, ev)| {
            **seq <= snapshot
                && ev.expiration().is_none_or(|exp| exp > now)
                && gate.allows(ev.packed())
                && filter.matches(ev.packed())
        })
        .map(|(seq, ev)| (ev.created_at(), ev.id(), *seq))
        .collect();
    matched.sort_by(|a, b| cmp_newest_first((a.0, &a.1), (b.0, &b.1)));
    matched.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
    matched
}

/// Naive scan: per filter, match, sort newest first, truncate, dedup.
#[must_use]
pub fn model_scan<S: std::hash::BuildHasher>(
    stored: &HashMap<u64, Arc<Event>, S>,
    filters: &[Filter],
    snapshot: u64,
    gate: &ReadGate,
    max_limit: u64,
    now: u64,
) -> Vec<String> {
    let mut emitted = HashSet::new();
    let mut out = Vec::new();
    for filter in filters {
        for (_, _, seq) in model_matched(stored, filter, snapshot, gate, max_limit, now) {
            // Already-emitted seqs consume the limit but are not sent twice.
            if !emitted.insert(seq) {
                continue;
            }
            out.push(
                stored
                    .get(&seq)
                    .map_or_else(String::new, |e| e.json().to_owned()),
            );
        }
    }
    out
}

/// [`model_scan`] without the payload: the `(created_at, id)` of each
/// emitted event in the same order — the NIP-77 record answer.
#[must_use]
pub fn model_records<S: std::hash::BuildHasher>(
    stored: &HashMap<u64, Arc<Event>, S>,
    filters: &[Filter],
    snapshot: u64,
    gate: &ReadGate,
    max_limit: u64,
    now: u64,
) -> Vec<(u64, EventId)> {
    let mut emitted = HashSet::new();
    let mut out = Vec::new();
    for filter in filters {
        for (created_at, id, seq) in model_matched(stored, filter, snapshot, gate, max_limit, now) {
            if emitted.insert(seq) {
                out.push((created_at, id));
            }
        }
    }
    out
}

/// The true count `CountScan` must return: unique stored seqs
/// matching at least one filter, visible at `snapshot`/`now`/`gate`.
///
/// `Scan`'s union is not the reference: `Filter::intrinsic_limit`
/// caps replaceable/addressable author+kind queries at
/// `kinds × authors × #d values`, which is a serving optimization a
/// true count must not inherit.
#[must_use]
pub fn model_union<S: std::hash::BuildHasher>(
    stored: &HashMap<u64, Arc<Event>, S>,
    filters: &[Filter],
    snapshot: u64,
    gate: &ReadGate,
    now: u64,
) -> usize {
    let mut seen = HashSet::new();
    for (seq, ev) in stored {
        if *seq <= snapshot
            && ev.expiration().is_none_or(|exp| exp > now)
            && gate.allows(ev.packed())
            && filters.iter().any(|f| f.matches(ev.packed()))
        {
            seen.insert(*seq);
        }
    }
    seen.len()
}
