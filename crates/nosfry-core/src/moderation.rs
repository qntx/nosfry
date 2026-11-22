//! NIP-86 moderation state shared by every store.
//!
//! The [`ModOp`] vocabulary, the NIP-11 [`InfoField`]s, and the
//! in-memory [`Moderation`] snapshot hot paths check. Stores persist
//! the `mod_*` tables and rebuild the snapshot; lookups never touch
//! storage.

use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;

use crate::event::{EventId, PublicKey};

/// A NIP-86 management operation applied by a store's `moderate`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModOp {
    /// Ban `pubkey` (also drops its allow entry).
    BanPubkey {
        /// The author to ban.
        pubkey: PublicKey,
        /// Optional operator note, returned by `listbannedpubkeys`.
        reason: Option<String>,
    },
    /// Remove `pubkey`'s ban (does not touch an allow entry).
    UnbanPubkey {
        /// The author to unban.
        pubkey: PublicKey,
    },
    /// Allow-list `pubkey` (also drops its ban).
    AllowPubkey {
        /// The author to allow.
        pubkey: PublicKey,
        /// Optional operator note.
        reason: Option<String>,
    },
    /// Remove `pubkey` from the allow list (does not touch a ban).
    UnallowPubkey {
        /// The author to remove.
        pubkey: PublicKey,
    },
    /// Ban `id` and delete the stored event in the same transaction.
    BanEvent {
        /// The event id to ban.
        id: EventId,
        /// Optional operator note.
        reason: Option<String>,
    },
    /// Remove `id` from the ban list.
    UnbanEvent {
        /// The event id to unban.
        id: EventId,
    },
    /// Allow `kind` (also drops a disallow entry).
    AllowKind {
        /// The kind number.
        kind: u16,
    },
    /// Disallow `kind` (also drops an allow entry).
    DisallowKind {
        /// The kind number.
        kind: u16,
    },
    /// Block `ip` from connecting; stored in canonical form.
    BlockIp {
        /// The address to block.
        ip: IpAddr,
        /// Optional operator note.
        reason: Option<String>,
    },
    /// Remove `ip` from the block list.
    UnblockIp {
        /// The address to unblock.
        ip: IpAddr,
    },
    /// Override a NIP-11 info field (takes precedence over config).
    SetInfo {
        /// Which field.
        field: InfoField,
        /// The new value; an empty string overrides with empty.
        value: String,
    },
}

/// A NIP-11 info field writable through [`ModOp::SetInfo`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InfoField {
    /// `changerelayname`.
    Name,
    /// `changerelaydescription`.
    Description,
    /// `changerelayicon`.
    Icon,
}

impl InfoField {
    /// The `mod_info` storage key.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Name => "name",
            Self::Description => "description",
            Self::Icon => "icon",
        }
    }
}

/// The full NIP-86 state, loaded at startup and rebuilt after every
/// applied [`ModOp`]. Hot paths read a snapshot — lookups never touch
/// storage.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Moderation {
    /// `mod_pubkeys` rows with the banned state, pubkey → reason.
    pub banned_pubkeys: HashMap<PublicKey, Option<Box<str>>>,
    /// `mod_pubkeys` rows with the allowed state. Non-empty switches
    /// the relay to allow-list mode.
    pub allowed_pubkeys: HashMap<PublicKey, Option<Box<str>>>,
    /// `mod_events` rows, event id → reason.
    pub banned_events: HashMap<EventId, Option<Box<str>>>,
    /// `mod_kinds` rows with the allowed state. Non-empty switches the
    /// relay to allow-list mode for kinds.
    pub allowed_kinds: BTreeSet<u16>,
    /// `mod_kinds` rows with the disallowed state.
    pub disallowed_kinds: BTreeSet<u16>,
    /// `mod_ips` rows, canonical address → reason.
    pub blocked_ips: HashMap<IpAddr, Option<Box<str>>>,
    /// `mod_info["name"]` NIP-11 override.
    pub name: Option<Box<str>>,
    /// `mod_info["description"]` NIP-11 override.
    pub description: Option<Box<str>>,
    /// `mod_info["icon"]` NIP-11 override.
    pub icon: Option<Box<str>>,
}

impl Moderation {
    /// Whether the allow-lists refuse unlisted writes — a non-empty
    /// `allowed_pubkeys` or `allowed_kinds`. This is the NIP-11
    /// `limitation.restricted_writes` flag.
    #[must_use]
    pub fn restricts_writes(&self) -> bool {
        !self.allowed_pubkeys.is_empty() || !self.allowed_kinds.is_empty()
    }

    /// Whether `ip` is on the block list.
    #[must_use]
    pub fn ip_blocked(&self, ip: &IpAddr) -> bool {
        self.blocked_ips.contains_key(ip)
    }
}
