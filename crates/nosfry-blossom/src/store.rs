//! The [`BlobStore`] trait and its shared types.
//!
//! The serve path goes through the trait; administration (`nosfry
//! blob …` and tests) uses [`FsStore`](crate::fs::FsStore)'s inherent
//! blocking methods, which are safe to run against a store a live
//! server also holds — every mutation is one LMDB write transaction,
//! and the LMDB writer lock serializes writers across processes.

use std::future::Future;

use nosfry_core::event::PublicKey;
use tokio::io::{AsyncRead, AsyncSeek, AsyncWrite};

use crate::path::Hash;

/// Stored blob metadata (the `blobs` row).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobMeta {
    /// The blob's SHA-256.
    pub hash: Hash,
    /// Size in bytes.
    pub size: u64,
    /// Normalized content type.
    pub mime: String,
    /// Upload unix time — the owner's own upload time in list
    /// results, the first upload otherwise.
    pub uploaded: u64,
}

/// A blob plus its administration view (`stat`/`list` output).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobStat {
    /// The blob row (`uploaded` is the first upload's time; in
    /// `list_owner` results it is *that* owner's time).
    pub meta: BlobMeta,
    /// Every owner with its upload time, oldest first.
    pub owners: Vec<(PublicKey, u64)>,
    /// `Some((banned_at, reason))` when the hash is banned.
    pub banned: Option<(u64, String)>,
    /// Whether the content file exists under `blobs/`.
    pub file_present: bool,
}

/// What an upload contributes when committed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewBlob {
    /// Computed SHA-256 of the staged body.
    pub hash: Hash,
    /// Exact body size.
    pub size: u64,
    /// Normalized content type.
    pub mime: String,
    /// Uploading pubkey.
    pub owner: PublicKey,
    /// Upload unix time.
    pub now: u64,
}

/// Per-owner and global limits checked at commit (and advisory at
/// request admission).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Quota {
    /// Owner byte cap.
    pub bytes: u64,
    /// Owner blob-count cap.
    pub blobs: u64,
    /// Global stored-bytes cap (`info.total.bytes`).
    pub total_bytes: u64,
}

/// Byte and blob totals — one owner's `usage` row or the `info`
/// `total` row.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Usage {
    /// Byte total.
    pub bytes: u64,
    /// Blob total.
    pub blobs: u64,
}

/// The upload precheck: ban/ownership/existence plus the advisory
/// usage figures the admission checks apply.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Precheck {
    /// The hash is banned (authoritative answer — the commit re-checks).
    pub banned: bool,
    /// `owner` already owns this hash.
    pub owned: bool,
    /// The blob row exists at all.
    pub exists: bool,
    /// The owner's current usage.
    pub usage: Usage,
    /// The global totals.
    pub total: Usage,
}

/// Commit result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Commit {
    /// The blob did not exist; file and metadata were created.
    Created(BlobMeta),
    /// The blob (or the ownership) already existed; only ownership
    /// rows may have been added.
    Existed(BlobMeta),
}

/// A commit can still be refused — the admission checks are
/// advisory, these are authoritative.
#[derive(Debug, thiserror::Error)]
pub enum CommitError {
    /// The hash is banned.
    #[error("blob is banned")]
    Banned,
    /// The owner's quota is exhausted.
    #[error("quota exceeded")]
    Quota,
    /// The global byte cap is reached.
    #[error("storage is full")]
    Full,
    /// The underlying store failed.
    #[error("{0}")]
    Store(#[from] StoreError),
}

impl From<std::io::Error> for CommitError {
    fn from(err: std::io::Error) -> Self {
        Self::Store(err.into())
    }
}

impl From<heed::Error> for CommitError {
    fn from(err: heed::Error) -> Self {
        Self::Store(err.into())
    }
}

/// The owner-removal result of `DELETE /<sha256>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Removal {
    /// The blob does not exist (404).
    NotFound,
    /// It exists but the pubkey does not own it (403).
    NotOwner,
    /// The ownership was removed; `last` says whether that deleted
    /// the blob itself.
    Removed {
        /// The last owner left: the file moved to trash and the
        /// `blobs` row is gone.
        last: bool,
    },
}

/// One `/list/<pubkey>` query.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ListQuery {
    /// The `sha256` of the previous page's last blob, excluded from
    /// this page ([`ListError::BadCursor`] when the pubkey does not
    /// own it).
    pub cursor: Option<Hash>,
    /// Page cap (already validated/clamped to `1..=1000`).
    pub limit: usize,
    /// Only blobs the owner uploaded at or after this time.
    pub since: Option<u64>,
    /// Only blobs the owner uploaded at or before this time.
    pub until: Option<u64>,
}

/// `list` failures beyond the generic [`StoreError`].
#[derive(Debug, thiserror::Error)]
pub enum ListError {
    /// The cursor is not one of this pubkey's blobs (400).
    #[error("bad cursor")]
    BadCursor,
    /// The underlying store failed.
    #[error("{0}")]
    Store(#[from] StoreError),
}

impl From<heed::Error> for ListError {
    fn from(err: heed::Error) -> Self {
        Self::Store(err.into())
    }
}

/// Everything the store can fail with.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    /// Filesystem failure.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// LMDB failure.
    #[error("lmdb: {0}")]
    Heed(#[from] heed::Error),
    /// `Mode::Serve` found the store's `lock` held by another process.
    #[error("blob store {0} is in use by another process")]
    Locked(String),
    /// The `info.version` row names a store format this build does
    /// not read.
    #[error("blob store format version {0}, expected 1")]
    Format(u32),
    /// A row does not decode; the message names what.
    #[error("corrupt store: {0}")]
    Corrupt(&'static str),
    /// A caller-supplied value is out of range (e.g. a ban reason
    /// over 1024 bytes).
    #[error("{0}")]
    Value(&'static str),
}

/// The serve-path storage contract, generic over where blob bytes
/// live (a later Workers edition implements it over object storage).
pub trait BlobStore: Send + Sync + 'static {
    /// Async handle to one blob's bytes.
    type Reader: AsyncRead + AsyncSeek + Unpin + Send + 'static;
    /// Async sink for one in-progress upload.
    type Staging: AsyncWrite + Unpin + Send + 'static;

    /// Metadata plus an open read handle, `None` when the hash is
    /// unknown. The reader starts at offset 0.
    fn open_blob(
        &self,
        hash: &Hash,
    ) -> impl Future<Output = Result<Option<(BlobMeta, Self::Reader)>, StoreError>> + Send;

    /// Metadata only, `None` when the hash is unknown.
    fn stat(
        &self,
        hash: &Hash,
    ) -> impl Future<Output = Result<Option<BlobMeta>, StoreError>> + Send;

    /// The admission precheck for one `(hash, owner)` upload.
    fn check(
        &self,
        hash: &Hash,
        owner: &PublicKey,
    ) -> impl Future<Output = Result<Precheck, StoreError>> + Send;

    /// A fresh staging sink (unlinked on drop unless committed).
    fn stage(&self) -> impl Future<Output = Result<Self::Staging, StoreError>> + Send;

    /// `fsync` the staged bytes before commit.
    fn sync(
        &self,
        staging: &mut Self::Staging,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Commit the staged upload under one write transaction —
    /// authoritatively re-checking ban, ownership, quota, and the
    /// global cap. The hash in `blob` is trusted (already verified
    /// against the received bytes and the token's `x` tags).
    fn commit(
        &self,
        staging: Self::Staging,
        blob: NewBlob,
        limits: Quota,
    ) -> impl Future<Output = Result<Commit, CommitError>> + Send;

    /// Remove `owner`'s ownership of `hash`, deleting the blob
    /// itself when that was the last owner.
    fn remove_owner(
        &self,
        hash: &Hash,
        owner: &PublicKey,
    ) -> impl Future<Output = Result<Removal, StoreError>> + Send;

    /// One owner's blobs, newest first.
    fn list(
        &self,
        owner: &PublicKey,
        query: ListQuery,
    ) -> impl Future<Output = Result<Vec<BlobMeta>, ListError>> + Send;

    /// The global `info.total` — cheap, synchronous, for metrics.
    ///
    /// # Errors
    ///
    /// [`StoreError`] on read failure or corruption.
    fn totals(&self) -> Result<Usage, StoreError>;
}
