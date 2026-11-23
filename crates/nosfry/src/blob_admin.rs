//! `nosfry blob <cmd>` store administration.
//!
//! Each command takes an opened [`FsStore`] (see [`open`]) plus
//! explicit inputs so tests can drive them directly; `main` only
//! wires argv and stdio. The commands run in [`Mode::Admin`] — no
//! store lock — so they work alongside a live server; LMDB's
//! writer lock serializes any overlap.

use std::io::Write;
use std::path::{Path, PathBuf};

use nosfry_blossom::{FsStore, GcReport, Hash, Mode, StoreError, VerifyReport};
use nosfry_core::event::PublicKey;

/// `nosfry blob <cmd>` failures.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BlobError {
    /// Nothing was ever created under `[blossom] dir`.
    #[error("no blossom blob store at {0}")]
    NoStore(PathBuf),
    /// Blob-store failure.
    #[error("blob store: {0}")]
    Store(#[from] StoreError),
    /// I/O failure on stdout.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// A hex argument did not parse.
    #[error("{what}: expected 64 lowercase hex digits")]
    Hex {
        /// Which argument failed (`pubkey` or `sha256`).
        what: &'static str,
    },
}

/// Open `dir`'s store in [`Mode::Admin`] — no lock, trash
/// recovery — or fail when no `data.mdb` exists yet. Does not
/// require `[blossom] enabled`.
///
/// # Errors
///
/// [`BlobError::NoStore`] when `dir/meta/data.mdb` is absent,
/// [`BlobError::Store`] otherwise.
pub fn open(dir: &Path) -> Result<FsStore, BlobError> {
    if !dir.join("meta").join("data.mdb").is_file() {
        return Err(BlobError::NoStore(dir.to_path_buf()));
    }
    Ok(FsStore::open(dir, Mode::Admin)?)
}

/// Parse a `list --owner` argument.
///
/// # Errors
///
/// [`BlobError::Hex`] when `hex` is not 64 lowercase hex digits.
pub fn pubkey(hex: &str) -> Result<PublicKey, BlobError> {
    PublicKey::from_hex(hex).ok_or(BlobError::Hex { what: "pubkey" })
}

/// Parse a `<sha256>` argument.
///
/// # Errors
///
/// [`BlobError::Hex`] when `hex` is not 64 lowercase hex digits.
pub fn hash(hex: &str) -> Result<Hash, BlobError> {
    Hash::from_hex(hex).ok_or(BlobError::Hex { what: "sha256" })
}

/// `nosfry blob list`: one JSON line per blob — `sha256`, `size`,
/// `type`, `uploaded`, `owners` count — hash-ascending, or
/// newest-first for `--owner`. Returns the line count.
///
/// # Errors
///
/// [`BlobError::Store`] on read failure, [`BlobError::Io`] on write.
pub fn list(
    store: &FsStore,
    owner: Option<&PublicKey>,
    after: Option<&Hash>,
    limit: usize,
    out: &mut impl Write,
) -> Result<usize, BlobError> {
    let stats = match owner {
        Some(owner) => store.list_owner(owner, limit)?,
        None => store.list_all(limit, after.copied())?,
    };
    let count = stats.len();
    for stat in &stats {
        let line = serde_json::json!({
            "sha256": stat.meta.hash.to_string(),
            "size": stat.meta.size,
            "type": stat.meta.mime,
            "uploaded": stat.meta.uploaded,
            "owners": stat.owners.len(),
        });
        writeln!(out, "{line}")?;
    }
    Ok(count)
}

/// `nosfry blob stat`: one JSON object — meta, owners with upload
/// times, ban, file presence — or `false` when the hash is absent.
///
/// # Errors
///
/// [`BlobError::Store`] on read failure, [`BlobError::Io`] on write.
pub fn stat(store: &FsStore, hash: &Hash, out: &mut impl Write) -> Result<bool, BlobError> {
    let Some(stat) = store.stat_full(hash)? else {
        return Ok(false);
    };
    let owners: Vec<serde_json::Value> = stat
        .owners
        .iter()
        .map(|(owner, uploaded)| {
            serde_json::json!({
                "pubkey": owner.to_string(),
                "uploaded": uploaded,
            })
        })
        .collect();
    let body = serde_json::json!({
        "sha256": stat.meta.hash.to_string(),
        "size": stat.meta.size,
        "type": stat.meta.mime,
        "uploaded": stat.meta.uploaded,
        "owners": owners,
        "banned": stat
            .banned
            .map(|(at, reason)| serde_json::json!({ "at": at, "reason": reason })),
        "file_present": stat.file_present,
    });
    writeln!(out, "{body}")?;
    Ok(true)
}

/// `nosfry blob delete`: remove `hash` for every owner; `false`
/// when absent (the caller exits 1).
///
/// # Errors
///
/// [`BlobError::Store`] on failure.
pub fn delete(store: &FsStore, hash: &Hash) -> Result<bool, BlobError> {
    Ok(store.delete(hash)?)
}

/// `nosfry blob ban`: ban `hash` and delete its content in one
/// transaction (lands whether or not the blob exists).
///
/// # Errors
///
/// [`BlobError::Store`] on failure or an overlong reason.
pub fn ban(store: &FsStore, hash: &Hash, reason: &str) -> Result<(), BlobError> {
    store.ban(hash, reason, nosfry_blossom::http::unix_now())?;
    Ok(())
}

/// `nosfry blob unban`; `false` when `hash` was not banned.
///
/// # Errors
///
/// [`BlobError::Store`] on failure.
pub fn unban(store: &FsStore, hash: &Hash) -> Result<bool, BlobError> {
    Ok(store.unban(hash)?)
}

/// `nosfry blob gc`: print the [`GcReport`] as JSON.
///
/// # Errors
///
/// [`BlobError::Store`] on failure, [`BlobError::Io`] on write.
pub fn gc(store: &FsStore, out: &mut impl Write) -> Result<GcReport, BlobError> {
    let report = store.gc()?;
    let body = serde_json::json!({
        "orphans_removed": report.orphans_removed,
        "tmp_removed": report.tmp_removed,
        "trash_recovered": report.trash_recovered,
        "missing_files": report
            .missing_files
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
    });
    writeln!(out, "{body}")?;
    Ok(report)
}

/// `nosfry blob verify`: re-hash every file and check accounting.
///
/// Prints the [`VerifyReport`] as JSON and returns `false` when any
/// problem was found (the caller exits 1). `progress` gets the
/// checked-file count after each file.
///
/// # Errors
///
/// [`BlobError::Store`] on failure, [`BlobError::Io`] on write.
pub fn verify(
    store: &FsStore,
    progress: impl FnMut(u64),
    out: &mut impl Write,
) -> Result<bool, BlobError> {
    let report = store.verify(progress)?;
    let body = serde_json::json!({
        "checked": report.checked,
        "bad_hash": report
            .bad_hash
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        "missing": report
            .missing
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        "accounting_errors": report.accounting_errors,
    });
    writeln!(out, "{body}")?;
    let VerifyReport {
        bad_hash,
        missing,
        accounting_errors,
        ..
    } = report;
    Ok(bad_hash.is_empty() && missing.is_empty() && accounting_errors.is_empty())
}
