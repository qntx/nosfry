//! Blossom blob server (BUD-01/02/06/11/12/13) for the nosfry relay.
//!
//! Two layers, split by the `server` cargo feature: the protocol
//! layer — [`auth`] (BUD-11 authorization tokens), [`range`]
//! (single-range `Range` headers), [`path`] (`/<sha256>[.ext]` and
//! `/list/<pubkey>` paths plus the [`struct@Hash`] newtype), and [`mime`]
//! (content-type rules) — is always compiled and stays sans-I/O.
//! With `server` comes the serving half: [`store`] (the
//! [`BlobStore`] trait and the filesystem + LMDB
//! [`FsStore`]), [`http`] (the axum surface),
//! [`metrics`], and [`policy`].
#![cfg_attr(
    test,
    allow(
        unused_crate_dependencies,
        reason = "dev-deps are exercised by the test code of each feature set"
    )
)]

#[cfg(feature = "server")]
use bytes as _;
#[cfg(feature = "server")]
use serde as _;
use serde_json as _;
use sha2 as _;

pub mod auth;
pub mod mime;
pub mod path;
pub mod range;

#[cfg(feature = "server")]
pub mod fs;
#[cfg(feature = "server")]
pub mod http;
#[cfg(feature = "server")]
pub mod metrics;
#[cfg(feature = "server")]
pub mod policy;
#[cfg(feature = "server")]
pub mod store;

#[cfg(feature = "server")]
pub use fs::{FsStore, GcReport, MAX_REASON_BYTES, Mode, VerifyReport};
#[cfg(feature = "server")]
pub use http::{Shared, router};
#[cfg(feature = "server")]
pub use metrics::{Class, Endpoint, Metrics, RejectReason};
pub use path::Hash;
#[cfg(feature = "server")]
pub use policy::{KeyPermit, Policy, Settings, Slot, Slots, UPLOADS_PER_PUBKEY};
#[cfg(feature = "server")]
pub use store::{
    BlobMeta, BlobStat, BlobStore, Commit, CommitError, ListError, ListQuery, NewBlob, Precheck,
    Quota, Removal, StoreError, Usage,
};
