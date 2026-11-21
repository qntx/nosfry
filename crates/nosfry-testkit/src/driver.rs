//! The differential driver: one generated case replayed identically
//! against a real store and the in-memory [`Model`].

use std::sync::Arc;

use nosfry_core::auth::{AuthRules, ReadGate};
use nosfry_core::event::{Event, EventId, PublicKey};
use nosfry_core::filter::Filter;
use nosfry_core::hll::Hll;
use nosfry_core::moderation::{InfoField, ModOp, Moderation};
use nosfry_core::sign::{event, keys, pubkey_hex};
use nosfry_core::store::WriteOutcome;
use nosfry_core::url::RelayUrl;
use proptest::prelude::*;
use serde_json::json;

use crate::model::{Model, model_expire, model_records, model_scan, model_store, model_union};
use crate::spec::{EventSpec, FilterSpec, SERVICE_URL, build_event, filter_json};

/// One event store under test. Implementations translate each call
/// into their store's API; panics and unwraps are the driver's way of
/// saying the store itself failed.
pub trait StoreDriver {
    /// Store `events`; one outcome per input, in arrival order.
    fn write(&mut self, events: &[Arc<Event>]) -> Vec<WriteOutcome>;

    /// The seq bound covering everything written so far.
    fn snapshot(&mut self) -> u64;

    /// The event JSONs `filters` emit under `gate`, bounded by
    /// `snapshot` and `max_limit`, at `now`.
    fn scan(
        &mut self,
        filters: Arc<[Filter]>,
        gate: &ReadGate,
        snapshot: u64,
        max_limit: u64,
        now: u64,
    ) -> Vec<String>;

    /// The `(created_at, id)` records `filters` emit under `gate`,
    /// bounded by `snapshot` and `max_limit`, at `now` — the NIP-77
    /// record view of [`StoreDriver::scan`], uncapped rows.
    fn records(
        &mut self,
        filters: Arc<[Filter]>,
        gate: &ReadGate,
        snapshot: u64,
        max_limit: u64,
        now: u64,
    ) -> StoreRecords;

    /// The union `filters` match at `snapshot`/`now` under `gate`,
    /// counted — a filter `limit` does not apply. `Hll::for_filters`
    /// decides sketch eligibility; the driver runs its count
    /// uncapped and to completion.
    fn count(&mut self, filters: Arc<[Filter]>, gate: &ReadGate, snapshot: u64, now: u64) -> Count;

    /// Sweep events expired at `now`.
    fn expire(&mut self, now: u64);

    /// Drain every queued NIP-62 vanish sweep with a small step
    /// limit so resumption is exercised.
    fn drain_vanish(&mut self);

    /// Apply one NIP-86 `op`, returning the rebuilt snapshot.
    fn moderate(&mut self, op: ModOp) -> Moderation;
}

/// The records [`StoreDriver::records`] reports, mirrored per store.
#[derive(Debug)]
pub struct StoreRecords {
    /// Matching `(created_at, id)` rows, per filter newest-first.
    pub records: Vec<(u64, EventId)>,
    /// The store's row budget stopped the scan early.
    pub budget_exhausted: bool,
}

/// The count [`StoreDriver::count`] reports, mirrored per store.
#[derive(Debug)]
pub struct Count {
    /// Events counted (the exact union, or a partial count when
    /// `approximate`).
    pub count: u64,
    /// `true` when the store's budget stopped the count early.
    pub approximate: bool,
    /// The HLL registers of counted authors, when the query was
    /// eligible for a sketch.
    pub hll: Option<[u8; 256]>,
}

/// A fully materialized differential case: the events to store, the
/// write batches to drain, and the filters to query.
#[derive(Debug)]
pub struct Case {
    /// Verified events, in write order.
    pub events: Vec<Arc<Event>>,
    /// Hex ids of `events`, position-aligned.
    pub ids: Vec<String>,
    /// Write-batch sizes drained in order before the rest.
    pub batches: Vec<usize>,
    /// The filters to query (`e`/`id` references resolved in `ids`).
    pub filter_specs: Vec<FilterSpec>,
    /// The `max_limit` passed to every scan.
    pub max_limit: u64,
    /// `now` for the pre-expiry scan.
    pub now: u64,
    /// `now` for the post-expiry scan.
    pub now2: u64,
}

/// Materialize one generated case. The two-pass build makes `e`/`a`
/// tag references point at real event ids.
#[must_use]
pub fn build_case(
    specs: &[EventSpec],
    batches: Vec<usize>,
    filter_specs: Vec<FilterSpec>,
    max_limit: u64,
    now: u64,
    now2: u64,
) -> Case {
    // Build events; ids depend on the tags so we need two passes.
    // The second pass's ids are what filters should reference.
    let placeholder = vec!["00".repeat(32)];
    let draft_ids: Vec<String> = specs
        .iter()
        .map(|s| build_event(s, &placeholder, specs))
        .map(|e| format!("{}", e.id()))
        .collect();
    let draft: Vec<Arc<Event>> = specs
        .iter()
        .map(|s| build_event(s, &draft_ids, specs))
        .collect();
    let tagged_ids: Vec<String> = draft.iter().map(|e| format!("{}", e.id())).collect();
    let events: Vec<Arc<Event>> = specs
        .iter()
        .map(|s| build_event(s, &tagged_ids, specs))
        .collect();
    let ids: Vec<String> = events.iter().map(|e| format!("{}", e.id())).collect();
    Case {
        events,
        ids,
        batches,
        filter_specs,
        max_limit,
        now,
        now2,
    }
}

/// Model state left after `check`, for store-specific extra
/// assertions (e.g. the LMDB COUNT scans).
#[derive(Debug)]
pub struct Aftermath {
    /// The reference model after `expire` ran at `now`.
    pub model: Model,
    /// The seq bound after the expiry sweep.
    pub snapshot: u64,
}

/// The gate the shared restricted scan applies: kind 3 is restricted
/// to involved keys and the authed set is the first pool signer, the
/// same rules the LMDB COUNT check uses.
fn restricted_gate() -> ReadGate {
    let rules = AuthRules::new(Some(RelayUrl::parse(SERVICE_URL).unwrap()), &[3], true);
    let authed: Arc<[PublicKey]> = Arc::from(vec![PublicKey(
        keys()[0].x_only_public_key().0.to_byte_array(),
    )]);
    ReadGate::new(Arc::new(rules), authed)
}

/// Run the shared write/scan/expire/scan assertions: every batch's
/// outcomes are checked, then both a pre- and post-expiry scan must
/// equal the model's answer — with and without a [`ReadGate`].
///
/// # Panics
///
/// Panics if a filter spec fails to serialize or parse.
///
/// # Errors
///
/// Fails the proptest case on any divergence.
pub fn check(store: &mut impl StoreDriver, case: &Case) -> Result<Aftermath, TestCaseError> {
    // Write in random batch splits.
    let mut all: Vec<Arc<Event>> = case.events.clone();
    for chunk in &case.batches {
        let take = all.len().min(*chunk);
        let batch: Vec<Arc<Event>> = all.drain(..take).collect();
        let outcomes = store.write(&batch);
        prop_assert_eq!(outcomes.len(), batch.len());
        for outcome in &outcomes {
            let known = matches!(
                outcome,
                WriteOutcome::Stored { .. }
                    | WriteOutcome::Duplicate
                    | WriteOutcome::Superseded
                    | WriteOutcome::Ephemeral
                    | WriteOutcome::Deleted
                    | WriteOutcome::Vanished
            );
            prop_assert!(known, "unknown outcome {outcome:?}");
        }
    }
    let outcomes = store.write(&all);
    prop_assert_eq!(outcomes.len(), all.len());

    // Drain queued vanish sweeps with a tiny step limit so the
    // persisted resume cursor is exercised; the model applied the
    // deletions eagerly while storing.
    store.drain_vanish();
    let service_url =
        RelayUrl::parse(SERVICE_URL).map_err(|e| TestCaseError::reject(e.to_string()))?;
    let mut stored = model_store(&case.events, Some(&service_url));

    let filters: Arc<[Filter]> = Arc::from(
        case.filter_specs
            .iter()
            .map(|s| serde_json::to_string(&filter_json(s, &case.ids)).unwrap())
            .map(|j| Filter::parse(&j).unwrap())
            .collect::<Vec<_>>(),
    );

    let snapshot = store.snapshot();
    let expected = model_scan(
        &stored.stored,
        &filters,
        snapshot,
        &ReadGate::default(),
        case.max_limit,
        case.now,
    );
    let got = store.scan(
        Arc::clone(&filters),
        &ReadGate::default(),
        snapshot,
        case.max_limit,
        case.now,
    );
    prop_assert_eq!(got, expected);

    // A restricted gate must shrink the scan exactly as it shrinks
    // the model's answer.
    let gate = restricted_gate();
    let expected_gated = model_scan(
        &stored.stored,
        &filters,
        snapshot,
        &gate,
        case.max_limit,
        case.now,
    );
    let got_gated = store.scan(
        Arc::clone(&filters),
        &gate,
        snapshot,
        case.max_limit,
        case.now,
    );
    prop_assert_eq!(got_gated, expected_gated);

    // The record view of the same scan must equal the model's
    // records — under the open and the restricted gate.
    records_checks(store, case, &stored, &filters, snapshot, &gate)?;

    // After `expire`, a scan must still match the swept model.
    store.expire(case.now);
    model_expire(&mut stored, case.now);
    let swept = store.snapshot();
    let expected_swept = model_scan(
        &stored.stored,
        &filters,
        swept,
        &ReadGate::default(),
        case.max_limit,
        case.now2,
    );
    let got_swept = store.scan(
        filters,
        &ReadGate::default(),
        swept,
        case.max_limit,
        case.now2,
    );
    prop_assert_eq!(got_swept, expected_swept);

    count_checks(store, case, &stored, swept, &gate);

    Ok(Aftermath {
        model: stored,
        snapshot,
    })
}

/// The `records` assertions of [`check`]: the record view under the
/// open and the restricted gate equals the model's records, and the
/// uncapped scan never reports an exhausted row budget.
///
/// # Errors
///
/// Fails the proptest case on any divergence.
fn records_checks(
    store: &mut impl StoreDriver,
    case: &Case,
    stored: &Model,
    filters: &Arc<[Filter]>,
    snapshot: u64,
    gate: &ReadGate,
) -> Result<(), TestCaseError> {
    for g in [ReadGate::default(), gate.clone()] {
        let recs = store.records(Arc::clone(filters), &g, snapshot, case.max_limit, case.now);
        prop_assert!(!recs.budget_exhausted, "uncapped records scan exhausted");
        prop_assert_eq!(
            recs.records,
            model_records(
                &stored.stored,
                filters,
                snapshot,
                &g,
                case.max_limit,
                case.now
            )
        );
    }
    Ok(())
}

/// The COUNT assertions of [`check`]: the union under an open and a
/// restricted gate, plus the HLL sketch of an eligible filter set.
///
/// # Panics
///
/// Panics on any divergence — a failure fails the proptest case.
fn count_checks(
    store: &mut impl StoreDriver,
    case: &Case,
    stored: &Model,
    swept: u64,
    gate: &ReadGate,
) {
    // COUNT ignores `limit`: it must equal the deduplicated union a
    // limit-less scan returns.
    let unlimited: Arc<[Filter]> = Arc::from(
        case.filter_specs
            .iter()
            .map(|s| {
                let mut json = filter_json(s, &case.ids);
                json.remove("limit");
                Filter::parse(&serde_json::to_string(&json).unwrap()).unwrap()
            })
            .collect::<Vec<_>>(),
    );
    let union = model_union(
        &stored.stored,
        &unlimited,
        swept,
        &ReadGate::default(),
        case.now2,
    );
    let counted = store.count(
        Arc::clone(&unlimited),
        &ReadGate::default(),
        swept,
        case.now2,
    );
    assert!(!counted.approximate, "uncapped count marked approximate");
    assert_eq!(counted.count, union as u64, "count != model union");

    let union_gated = model_union(&stored.stored, &unlimited, swept, gate, case.now2);
    let counted_gated = store.count(unlimited, gate, swept, case.now2);
    assert!(
        !counted_gated.approximate,
        "uncapped count marked approximate"
    );
    assert_eq!(
        counted_gated.count, union_gated as u64,
        "gated count != model union"
    );

    // An HLL-eligible COUNT (one filter, one tag condition, one
    // value) returns exactly the sketch the model computes over the
    // union's authors.
    let eligible: Arc<[Filter]> = Arc::from(vec![
        Filter::parse(&format!("{{\"#p\":[\"{}\"]}}", pubkey_hex(0))).unwrap(),
    ]);
    let mut sketch = Hll::for_filters(&eligible)
        .unwrap_or_else(|| panic!("single tag-value filter set is HLL-eligible"));
    let mut hits = 0u64;
    for (seq, ev) in &stored.stored {
        if *seq <= swept
            && ev.expiration().is_none_or(|exp| exp > case.now2)
            && eligible[0].matches(ev.packed())
        {
            sketch.add(&ev.pubkey());
            hits += 1;
        }
    }
    let sketched = store.count(eligible, &ReadGate::default(), swept, case.now2);
    assert!(!sketched.approximate, "uncapped count marked approximate");
    assert_eq!(sketched.count, hits, "eligible count != model union");
    assert_eq!(
        sketched.hll,
        Some(*sketch.registers()),
        "hll registers != model sketch"
    );
}

/// A deterministic NIP-86 script every store must replay to the same
/// [`Moderation`] snapshots.
///
/// Each [`ModOp`], the ban↔allow and allow↔disallow exclusivity rules
/// (and that `unban`/`unallow` only clear their own state), reason
/// storage, the NIP-11 info overrides, and `BanEvent` deleting the
/// stored event.
///
/// # Panics
///
/// Panics on any divergence.
pub fn moderation_check(store: &mut impl StoreDriver) {
    let a = PublicKey::from_hex(&pubkey_hex(0)).unwrap();
    let b = PublicKey::from_hex(&pubkey_hex(1)).unwrap();

    let note = event(&keys()[0], 1, 1_700_000_000, &serde_json::json!([]), "note");
    assert!(
        matches!(
            store.write(std::slice::from_ref(&note)).first(),
            Some(WriteOutcome::Stored { .. })
        ),
        "the scripted event did not store"
    );

    moderate_pubkeys(store, a);
    moderate_event(store, note.id());
    moderate_kinds(store);
    moderate_ips(store);
    moderate_info(store);

    // The final snapshot: exactly this state, nothing more.
    let snapshot = store.moderate(ModOp::BanPubkey {
        pubkey: b,
        reason: None,
    });
    let mut expected = Moderation::default();
    expected.banned_pubkeys.insert(a, None);
    expected.banned_pubkeys.insert(b, None);
    expected.disallowed_kinds.insert(4);
    expected.allowed_kinds.insert(9);
    expected
        .blocked_ips
        .insert("2001:db8::1".parse().unwrap(), None);
    expected.name = Some(Box::from("relay-name"));
    expected.description = Some(Box::from("relay-desc"));
    expected.icon = Some(Box::from("https://icon"));
    assert_eq!(snapshot, expected, "final moderation snapshot diverged");
}

/// `banpubkey` stores the reason, `allowpubkey` replaces the ban
/// (exclusivity) and `unban` leaves the allow entry; `unallow` leaves
/// a ban untouched. Ends with `a` banned, no reason.
fn moderate_pubkeys(store: &mut dyn StoreDriver, a: PublicKey) {
    let banned = store.moderate(ModOp::BanPubkey {
        pubkey: a,
        reason: Some("spam".to_owned()),
    });
    assert_eq!(
        banned.banned_pubkeys.get(&a).map(|r| r.as_deref()),
        Some(Some("spam")),
        "banned pubkey lost its reason"
    );
    let allowed = store.moderate(ModOp::AllowPubkey {
        pubkey: a,
        reason: Some("vip".to_owned()),
    });
    assert!(
        !allowed.banned_pubkeys.contains_key(&a),
        "allow did not drop the ban"
    );
    assert_eq!(
        allowed.allowed_pubkeys.get(&a).map(|r| r.as_deref()),
        Some(Some("vip")),
        "allowed pubkey lost its reason"
    );
    let unbanned = store.moderate(ModOp::UnbanPubkey { pubkey: a });
    assert_eq!(
        unbanned.allowed_pubkeys.get(&a).map(|r| r.as_deref()),
        Some(Some("vip")),
        "unban cleared the allow entry"
    );
    let unallowed = store.moderate(ModOp::UnallowPubkey { pubkey: a });
    assert!(
        unallowed.allowed_pubkeys.is_empty(),
        "unallow left the allow entry"
    );
    store.moderate(ModOp::BanPubkey {
        pubkey: a,
        reason: None,
    });
    let snapshot = store.moderate(ModOp::UnallowPubkey { pubkey: a });
    assert!(
        snapshot.banned_pubkeys.contains_key(&a),
        "unallow cleared the ban"
    );
}

/// `banevent` records the ban and deletes the stored event (the store
/// layer does not gate republishes — the session does). Ends with the
/// ban list empty.
fn moderate_event(store: &mut dyn StoreDriver, id: EventId) {
    let ids_filter: Arc<[Filter]> = Arc::from(vec![
        Filter::parse(&format!("{{\"ids\":[\"{id}\"]}}")).unwrap(),
    ]);
    let banned = store.moderate(ModOp::BanEvent {
        id,
        reason: Some("bad".to_owned()),
    });
    assert_eq!(
        banned.banned_events.get(&id).map(|r| r.as_deref()),
        Some(Some("bad")),
        "banned event lost its reason"
    );
    assert!(
        store
            .scan(
                Arc::clone(&ids_filter),
                &ReadGate::default(),
                u64::MAX,
                10,
                u64::MAX,
            )
            .is_empty(),
        "banevent did not delete the stored event"
    );
    let unbanned = store.moderate(ModOp::UnbanEvent { id });
    assert!(unbanned.banned_events.is_empty(), "unbanevent left the ban");
}

/// Kind exclusivity: `disallow` replaces `allow` and vice versa.
/// Ends with kind 4 disallowed and kind 9 allowed.
fn moderate_kinds(store: &mut dyn StoreDriver) {
    store.moderate(ModOp::AllowKind { kind: 4 });
    let disallowed = store.moderate(ModOp::DisallowKind { kind: 4 });
    assert!(
        !disallowed.allowed_kinds.contains(&4),
        "disallow left the allow"
    );
    assert!(
        disallowed.disallowed_kinds.contains(&4),
        "disallow did not record"
    );
    store.moderate(ModOp::DisallowKind { kind: 9 });
    let allowed = store.moderate(ModOp::AllowKind { kind: 9 });
    assert!(
        !allowed.disallowed_kinds.contains(&9),
        "allow left the disallow"
    );
    assert!(allowed.allowed_kinds.contains(&9), "allow did not record");
}

/// IPs persist in canonical form, with and without a reason. Ends
/// with only the v6 address blocked.
fn moderate_ips(store: &mut dyn StoreDriver) {
    let v4: std::net::IpAddr = "192.0.2.1".parse().unwrap();
    let v6: std::net::IpAddr = "2001:db8::1".parse().unwrap();
    store.moderate(ModOp::BlockIp {
        ip: v4,
        reason: Some("vpn".to_owned()),
    });
    store.moderate(ModOp::BlockIp {
        ip: v6,
        reason: None,
    });
    let unblocked = store.moderate(ModOp::UnblockIp { ip: v4 });
    assert!(
        !unblocked.blocked_ips.contains_key(&v4),
        "unblockip left the block"
    );
}

/// The NIP-11 info overrides persist in `mod_info`.
fn moderate_info(store: &mut dyn StoreDriver) {
    for (field, value) in [
        (InfoField::Name, "relay-name"),
        (InfoField::Description, "relay-desc"),
        (InfoField::Icon, "https://icon"),
    ] {
        store.moderate(ModOp::SetInfo {
            field,
            value: value.to_owned(),
        });
    }
}

/// Whether `id` is served by an `ids` scan against `store`.
fn served(store: &mut dyn StoreDriver, id: &EventId) -> usize {
    let filters: Arc<[Filter]> = Arc::from(vec![
        Filter::parse(&format!("{{\"ids\":[\"{id}\"]}}")).unwrap(),
    ]);
    store
        .scan(filters, &ReadGate::default(), u64::MAX, 10, u64::MAX)
        .len()
}

/// One event written alone, answering its single outcome.
fn write_one(store: &mut dyn StoreDriver, ev: &Arc<Event>) -> WriteOutcome {
    store
        .write(std::slice::from_ref(ev))
        .first()
        .copied()
        .unwrap_or_else(|| panic!("no outcome for {}", ev.id()))
}

/// A deterministic NIP-09/NIP-59 deletion script for every store.
///
/// Same-author deletion, the wrap recipient's deletion (first and
/// non-first `p` values), a third party's no-op, `p`-tagged non-1059
/// immunity, kinds 5/62 immunity, the re-publish block and its lift
/// when the carrier expires, and ephemeral 21059 never consulting
/// blocks.
///
/// # Panics
///
/// Panics on any divergence.
pub fn deletion_check(store: &mut impl StoreDriver) {
    let pool = keys();
    let (w, r, x) = (&pool[3], &pool[0], &pool[2]);
    let (w_hex, r_hex, r2_hex) = (pubkey_hex(3), pubkey_hex(0), pubkey_hex(1));
    let wrap = event(w, 1059, 100, &json!([["p", r_hex]]), "wrap");
    let wrap2 = event(w, 1059, 101, &json!([["p", r2_hex], ["p", r_hex]]), "wrap2");
    let dm = event(w, 4, 102, &json!([["p", r_hex]]), "dm");
    let note = event(r, 1, 103, &json!([]), "note");
    let carrier = event(x, 5, 104, &json!([["e", "00".repeat(32)]]), "del");
    let vanish = event(r, 62, 105, &json!([]), "vanish");
    let eph = event(r, 21059, 106, &json!([["p", w_hex]]), "eph");
    for ev in [&wrap, &wrap2, &dm, &note, &carrier, &vanish] {
        assert!(
            matches!(write_one(store, ev), WriteOutcome::Stored { .. }),
            "{} did not store",
            ev.id()
        );
    }

    // A third party's kind 5 on the wraps deletes nothing.
    let foreign = event(
        x,
        5,
        200,
        &json!([
            ["e", wrap.id().to_string()],
            ["e", wrap2.id().to_string()],
            ["k", "1059"]
        ]),
        "",
    );
    assert!(
        matches!(write_one(store, &foreign), WriteOutcome::Stored { .. }),
        "third-party kind 5 refused"
    );
    assert_eq!(served(store, &wrap.id()), 1, "foreign kind 5 deleted");
    assert_eq!(served(store, &wrap2.id()), 1, "foreign kind 5 deleted");

    // The `p` recipient's kind 5 deletes both wraps — `wrap2` via
    // its non-first `p` value — plus its own note, but not the
    // kind-4 DM, not the kind-5 carrier, not the kind-62 request,
    // and it registers a block for the ephemeral id.
    let del = event(
        r,
        5,
        300,
        &json!([
            ["e", wrap.id().to_string()],
            ["e", wrap2.id().to_string()],
            ["e", dm.id().to_string()],
            ["e", note.id().to_string()],
            ["e", carrier.id().to_string()],
            ["e", vanish.id().to_string()],
            ["e", eph.id().to_string()],
            ["k", "1059"],
            ["expiration", "400"]
        ]),
        "",
    );
    assert!(
        matches!(write_one(store, &del), WriteOutcome::Stored { .. }),
        "recipient kind 5 refused"
    );
    for (ev, want) in [
        (&wrap, 0),
        (&wrap2, 0),
        (&note, 0),
        (&dm, 1),
        (&carrier, 1),
        (&vanish, 1),
    ] {
        assert_eq!(served(store, &ev.id()), want, "{}", ev.id());
    }

    // The ephemeral never consults the block row the kind 5 wrote.
    assert_eq!(
        write_one(store, &eph),
        WriteOutcome::Ephemeral,
        "ephemeral consulted a deletion block"
    );

    // Re-publication of the wrap stays blocked until the carrier
    // kind 5 expires.
    assert_eq!(
        write_one(store, &wrap),
        WriteOutcome::Deleted,
        "re-publish not blocked"
    );
    store.expire(400);
    assert!(
        matches!(write_one(store, &wrap), WriteOutcome::Stored { .. }),
        "carrier expiry did not lift the block"
    );
}
