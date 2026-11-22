//! Outcomes shared by the event stores (LMDB, SQL).

/// Outcome of writing one event, in arrival order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteOutcome {
    /// Stored under a fresh sequence number.
    Stored {
        /// The assigned sequence number.
        seq: u64,
    },
    /// The id was already stored.
    Duplicate,
    /// An equal-or-better replaceable/addressable version is stored.
    Superseded,
    /// Ephemeral kind; nothing written.
    Ephemeral,
    /// A stored same-author kind-5 event deleted (or blocks) this event.
    Deleted,
    /// The author's NIP-62 request to vanish covers this event
    /// (`created_at <= T`), or it is a kind-1059 gift wrap `p`-tagged
    /// to a vanished pubkey.
    Vanished,
}

impl WriteOutcome {
    /// The `OK` reply's `(accepted, message)` for this outcome —
    /// exhaustive so a new variant cannot slip in silently.
    #[must_use]
    pub const fn ok_reply(self) -> (bool, &'static str) {
        match self {
            Self::Stored { .. } | Self::Ephemeral => (true, ""),
            Self::Duplicate => (true, "duplicate: have this event"),
            Self::Superseded => (false, "duplicate: have a newer version"),
            Self::Deleted => (false, "blocked: deleted by its author"),
            Self::Vanished => (false, "blocked: request to vanish"),
        }
    }
}

/// How completely a stored-event scan covered its filters — the
/// NIP-67 `finish`/`more` hint inputs. `Default` reports nothing,
/// which is always a safe answer.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Completion {
    /// Every filter ran its candidates dry (or was impossible) with
    /// no limit cut and no budget cut: all matching stored events
    /// were sent.
    pub exhausted: bool,
    /// A visible matching stored event was provably left unsent.
    pub more: bool,
}
