//! The filesystem + LMDB blob store.
//!
//! Layout (format version 1):
//!
//! ```text
//! <dir>/lock                     # held by the serving process
//! <dir>/blobs/<h[0..2]>/<h[2..4]>/<sha256hex>   # blobs, mode 0644
//! <dir>/tmp/<random>.part        # uploads in flight
//! <dir>/trash/<sha256hex>        # blobs being deleted
//! <dir>/meta/data.mdb, lock.mdb  # LMDB metadata
//! ```
//!
//! Tables: `blobs` hash → `size|uploaded|type`, `owners` hash‖pubkey
//! → uploaded, `by_owner` pubkey‖~uploaded‖hash → `()` (newest
//! first), `usage` pubkey → `bytes|blobs`, `bans` hash →
//! `banned_at|reason`, `info` `version`/`total`. Every mutation is
//! one write transaction, so a CLI process and a live server
//! serialize on LMDB's writer lock and file renames race nothing.
//!
//! Upload durability (see `commit`): stage to `tmp/`, hash while
//! streaming, `sync_all`, then inside the write txn re-check ban /
//! ownership / quota / cap, `rename` into `blobs/`, write the rows,
//! and commit. Before the rename only a tmp file exists (swept at
//! open); after it but before commit an orphan file exists with no
//! metadata — invisible (every read goes through metadata), adopted
//! by a re-upload, removed by `gc`. Deletes move the file to
//! `trash/` inside the txn and unlink it after commit; a crash in
//! between is undone by `recover_trash` on the next open.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::ops::Bound;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use heed::types::Bytes;
use heed::{CommitOrAbort, Database, Env, EnvOpenOptions, RoTxn, RwTxn, WithoutTls};
use nosfry_core::event::PublicKey;
use sha2::{Digest, Sha256};

use crate::path::Hash;
use crate::store::{
    BlobMeta, BlobStat, BlobStore, Commit, CommitError, ListError, ListQuery, NewBlob, Precheck,
    Quota, Removal, StoreError, Usage,
};

/// The on-disk format version (`info` `version` row).
const FORMAT_VERSION: u32 = 1;

/// LMDB map size: address space only — the file grows on demand.
const MAP_SIZE: usize = 1 << 36;

/// Ban reason cap (`bans` value tail).
pub const MAX_REASON_BYTES: usize = 1024;

/// A freshly opened store: `Mode::Serve` takes the exclusive `lock`
/// and sweeps `tmp/`; `Mode::Admin` (the CLI) takes no lock so it can
/// run alongside a live server — LMDB's writer lock serializes them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// The serving process: exclusive `lock`, `tmp/` sweep, trash
    /// recovery.
    Serve,
    /// An administration command: no lock, trash recovery only.
    Admin,
}

type BytesDb = Database<'static, Bytes, Bytes>;

/// Named databases opened at [`FsStore::open`], in creation order.
/// `info` must stay last: the format check reads it before the rest
/// are used.
const DB_NAMES: [&str; 6] = ["blobs", "owners", "by_owner", "usage", "bans", "info"];

/// One `usage` / `info.total` row: `bytes u64 BE | blobs u64 BE`.
fn usage_encode(usage: Usage) -> [u8; 16] {
    let mut row = [0u8; 16];
    row[..8].copy_from_slice(&usage.bytes.to_be_bytes());
    row[8..].copy_from_slice(&usage.blobs.to_be_bytes());
    row
}

fn usage_decode(row: &[u8]) -> Result<Usage, StoreError> {
    let (bytes, blobs) = row
        .split_at_checked(8)
        .ok_or(StoreError::Corrupt("short usage row"))?;
    Ok(Usage {
        bytes: u64::from_be_bytes(bytes.try_into().map_err(|_| StoreError::Corrupt("usage"))?),
        blobs: u64::from_be_bytes(blobs.try_into().map_err(|_| StoreError::Corrupt("usage"))?),
    })
}

/// One `blobs` row: `size | uploaded | type`.
fn meta_encode(meta: &BlobMeta) -> Vec<u8> {
    let mut row = Vec::with_capacity(16 + meta.mime.len());
    row.extend_from_slice(&meta.size.to_be_bytes());
    row.extend_from_slice(&meta.uploaded.to_be_bytes());
    row.extend_from_slice(meta.mime.as_bytes());
    row
}

fn meta_decode(hash: Hash, row: &[u8]) -> Result<BlobMeta, StoreError> {
    let (nums, mime) = row
        .split_at_checked(16)
        .ok_or(StoreError::Corrupt("short blob row"))?;
    let (size, uploaded) = nums
        .split_at_checked(8)
        .ok_or(StoreError::Corrupt("blob"))?;
    Ok(BlobMeta {
        hash,
        size: u64::from_be_bytes(size.try_into().map_err(|_| StoreError::Corrupt("blob"))?),
        uploaded: u64::from_be_bytes(
            uploaded
                .try_into()
                .map_err(|_| StoreError::Corrupt("blob"))?,
        ),
        mime: str::from_utf8(mime)
            .map_err(|_| StoreError::Corrupt("blob mime not utf-8"))?
            .to_owned(),
    })
}

/// `by_owner` key: pubkey ‖ `(u64::MAX - uploaded)` BE ‖ hash.
fn by_owner_key(pubkey: &PublicKey, uploaded: u64, hash: &Hash) -> [u8; 72] {
    let mut key = [0u8; 72];
    key[..32].copy_from_slice(&pubkey.0);
    key[32..40].copy_from_slice(&(u64::MAX - uploaded).to_be_bytes());
    key[40..].copy_from_slice(&hash.0);
    key
}

/// `owners` key: hash ‖ pubkey.
fn owners_key(hash: &Hash, pubkey: &PublicKey) -> [u8; 64] {
    let mut key = [0u8; 64];
    key[..32].copy_from_slice(&hash.0);
    key[32..].copy_from_slice(&pubkey.0);
    key
}

/// fsync a directory (unix): one `fsync` on its fd. Off unix there is
/// no directory handle to sync; the rename itself still lands in the
/// directory entry table.
fn sync_dir(path: &Path) -> Result<(), StoreError> {
    #[cfg(unix)]
    File::open(path)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// `flock` the `lock` file when it can be taken at all (`None` —
/// server mode never dropped the file).
fn try_lock(path: &Path) -> Result<File, StoreError> {
    let file = File::options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(std::fs::TryLockError::WouldBlock) => {
            Err(StoreError::Locked(path.display().to_string()))
        }
        Err(std::fs::TryLockError::Error(err)) => Err(err.into()),
    }
}

/// The two fanout shards of a hash's content path.
fn shard_hex(hash: &Hash) -> (String, String) {
    let hex = hash.to_string();
    let mut chars = hex.chars();
    let top: String = chars.by_ref().take(2).collect();
    let mid: String = chars.by_ref().take(2).collect();
    (top, mid)
}

/// The directory a hash's content lives in.
fn blob_dir(dir: &Path, hash: &Hash) -> PathBuf {
    let (top, mid) = shard_hex(hash);
    dir.join("blobs").join(top).join(mid)
}

/// Where a hash's content lives.
fn blob_path(dir: &Path, hash: &Hash) -> PathBuf {
    blob_dir(dir, hash).join(hash.to_string())
}

/// `blobs/`, `tmp/`, `trash/`, `meta/` exist.
fn ensure_dirs(dir: &Path) -> Result<(), StoreError> {
    for sub in ["blobs", "tmp", "trash", "meta"] {
        std::fs::create_dir_all(dir.join(sub))?;
    }
    Ok(())
}

/// The format gate inside [`FsStore::open`]'s create-and-commit
/// closure: writes `version` on first open and returns
/// `Some(StoreError::Format)` when the stored version differs, so
/// the caller aborts the transaction.
fn check_format(
    info: Database<'_, Bytes, Bytes>,
    wtxn: &mut RwTxn<'_>,
) -> Result<Option<StoreError>, StoreError> {
    match info.get(wtxn, b"version")? {
        None => info.put(wtxn, b"version", &FORMAT_VERSION.to_be_bytes())?,
        Some(row) if row == FORMAT_VERSION.to_be_bytes() => {}
        Some(row) => {
            let version = row.try_into().map_or(u32::MAX, u32::from_be_bytes);
            return Ok(Some(StoreError::Format(version)));
        }
    }
    Ok(None)
}

/// Shared store state (cheap to clone for `spawn_blocking`).
struct Inner {
    dir: PathBuf,
    env: Env<WithoutTls>,
    blobs: BytesDb,
    owners: BytesDb,
    by_owner: BytesDb,
    usage: BytesDb,
    bans: BytesDb,
    info: BytesDb,
    /// Held for the process lifetime in `Mode::Serve`.
    lock: Option<File>,
}

/// The filesystem + LMDB blob store.
#[derive(Clone)]
pub struct FsStore {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for FsStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FsStore")
            .field("dir", &self.inner.dir)
            .finish_non_exhaustive()
    }
}

/// One in-progress upload's staging file; unlinked on drop unless
/// [`FsStore::commit`] consumed it.
#[derive(Debug)]
pub struct Staging {
    file: tokio::fs::File,
    path: PathBuf,
    done: bool,
}

static STAGE_SEQ: AtomicU64 = AtomicU64::new(0);

impl tokio::io::AsyncWrite for Staging {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.file).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.file).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.file).poll_shutdown(cx)
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        if !self.done {
            std::fs::remove_file(&self.path).ok();
        }
    }
}

impl Inner {
    /// `stat` inside one read txn.
    fn stat_txn(
        &self,
        txn: &RoTxn<'_, WithoutTls>,
        hash: &Hash,
    ) -> Result<Option<BlobMeta>, StoreError> {
        self.blobs
            .get(txn, &hash.0)?
            .map(|row| meta_decode(*hash, row))
            .transpose()
    }

    /// The `usage` row of one pubkey (zeros when absent).
    fn owner_usage(
        &self,
        txn: &RoTxn<'_, WithoutTls>,
        pubkey: &PublicKey,
    ) -> Result<Usage, StoreError> {
        self.usage
            .get(txn, &pubkey.0)?
            .map_or_else(|| Ok(Usage::default()), usage_decode)
    }

    /// The `info.total` row (zeros when absent — empty store).
    fn total_txn(&self, txn: &RoTxn<'_, WithoutTls>) -> Result<Usage, StoreError> {
        self.info
            .get(txn, b"total")?
            .map_or_else(|| Ok(Usage::default()), usage_decode)
    }

    /// Whether any `owners` row starts with `hash` — i.e. the blob
    /// still has an owner.
    fn has_owner(&self, txn: &RoTxn<'_, WithoutTls>, hash: &Hash) -> Result<bool, StoreError> {
        Ok(self
            .owners
            .get_greater_than_or_equal_to(txn, hash.0.as_slice())?
            .is_some_and(|(key, _)| key.starts_with(hash.0.as_slice())))
    }

    /// Every owner of `hash` with its upload time.
    fn owners_of(
        &self,
        txn: &RoTxn<'_, WithoutTls>,
        hash: &Hash,
    ) -> Result<Vec<(PublicKey, u64)>, StoreError> {
        let mut out = Vec::new();
        let bounds = (Bound::Included(hash.0.as_slice()), Bound::Unbounded);
        for entry in self.owners.range(txn, &bounds)? {
            let (key, row) = entry?;
            if !key.starts_with(&hash.0) {
                break;
            }
            let pubkey = PublicKey(
                key.get(32..64)
                    .ok_or(StoreError::Corrupt("short owners key"))?
                    .try_into()
                    .map_err(|_| StoreError::Corrupt("owners key"))?,
            );
            let uploaded = u64::from_be_bytes(
                row.try_into()
                    .map_err(|_| StoreError::Corrupt("owners row"))?,
            );
            out.push((pubkey, uploaded));
        }
        Ok(out)
    }

    /// Undo a delete/ban interrupted between `rename` and `commit` —
    /// a `trash/<hash>` file while its `blobs` row lives moves back;
    /// one whose row committed away is unlinked. Called inside a
    /// write txn so the row check and the file move stay serialized
    /// with live deletes. Returns the moves made.
    fn recover_trash(&self, txn: &RoTxn<'_, WithoutTls>) -> Result<u32, StoreError> {
        let mut moved = 0;
        for entry in std::fs::read_dir(self.dir.join("trash"))? {
            let name = entry?.file_name();
            let Some(name) = name.to_str() else { continue };
            let Some(hash) = Hash::from_hex(name) else {
                continue;
            };
            if self.blobs.get(txn, &hash.0)?.is_none() {
                std::fs::remove_file(self.dir.join("trash").join(name))?;
                moved += 1;
                continue;
            }
            let to = blob_path(&self.dir, &hash);
            if let Some(parent) = to.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::rename(self.dir.join("trash").join(name), &to)?;
            if let Some(parent) = to.parent() {
                sync_dir(parent)?;
            }
            moved += 1;
        }
        if moved > 0 {
            sync_dir(&self.dir.join("trash"))?;
        }
        Ok(moved)
    }

    /// Delete `hash` for every owner inside `txn`; on the last owner
    /// the file moves to `trash/` (unlinked by the caller after
    /// commit). Returns `trash/<hash>` when the blob itself went.
    fn delete_in_txn(
        &self,
        txn: &mut RwTxn<'_>,
        hash: &Hash,
        meta: &BlobMeta,
    ) -> Result<Option<PathBuf>, StoreError> {
        for (pubkey, uploaded) in self.owners_of(txn, hash)? {
            self.charge_usage(txn, &pubkey, -meta.size.cast_signed(), -1)?;
            self.owners.delete(txn, &owners_key(hash, &pubkey))?;
            self.by_owner
                .delete(txn, &by_owner_key(&pubkey, uploaded, hash))?;
        }
        self.blobs.delete(txn, &hash.0)?;
        self.charge_total(txn, -meta.size.cast_signed(), -1)?;
        let to = self.dir.join("trash").join(hash.to_string());
        let from = blob_path(&self.dir, hash);
        if let Err(err) = std::fs::rename(&from, &to) {
            if err.kind() == std::io::ErrorKind::NotFound {
                return Ok(None);
            }
            return Err(err.into());
        }
        if let Some(parent) = from.parent() {
            sync_dir(parent)?;
        }
        sync_dir(&self.dir.join("trash"))?;
        Ok(Some(to))
    }

    /// Apply `bytes`/`blobs` deltas to one owner's `usage` row.
    fn charge_usage(
        &self,
        txn: &mut RwTxn<'_>,
        pubkey: &PublicKey,
        bytes: i64,
        blobs: i64,
    ) -> Result<(), StoreError> {
        let mut usage = self.owner_usage(txn, pubkey)?;
        usage.bytes = usage.bytes.saturating_add_signed(bytes);
        usage.blobs = usage.blobs.saturating_add_signed(blobs);
        self.usage.put(txn, &pubkey.0, &usage_encode(usage))?;
        Ok(())
    }

    /// Apply deltas to `info.total`.
    fn charge_total(&self, txn: &mut RwTxn<'_>, bytes: i64, blobs: i64) -> Result<(), StoreError> {
        let mut total = self.total_txn(txn)?;
        total.bytes = total.bytes.saturating_add_signed(bytes);
        total.blobs = total.blobs.saturating_add_signed(blobs);
        self.info.put(txn, b"total", &usage_encode(total))?;
        Ok(())
    }
}

/// Sweep `tmp/` when the lock is (or can be) held — `hold` is the
/// already-held `Mode::Serve` lock; `None` takes it briefly, which
/// fails with [`StoreError::Locked`] beside a live server. Returns
/// files removed.
fn sweep_tmp(dir: &Path, hold: Option<&File>) -> Result<u64, StoreError> {
    let _owned = if hold.is_none() {
        Some(try_lock(&dir.join("lock"))?)
    } else {
        None
    };
    let mut removed = 0;
    for entry in std::fs::read_dir(dir.join("tmp"))? {
        let path = entry?.path();
        if path.is_file() {
            std::fs::remove_file(path)?;
            removed += 1;
        }
    }
    Ok(removed)
}

/// Walk `depth` levels of directories collecting `(hash, path)` for
/// every hash-named file.
fn collect_files(dir: &Path, depth: u8, out: &mut Vec<(Hash, PathBuf)>) -> Result<(), StoreError> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if depth > 0 {
            collect_files(&path, depth - 1, out)?;
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if let Some(hash) = Hash::from_hex(name) {
            out.push((hash, path));
        }
    }
    Ok(())
}

/// `bans` row: `banned_at u64 BE | reason utf8`.
fn ban_encode(at: u64, reason: &str) -> Vec<u8> {
    let mut row = Vec::with_capacity(8 + reason.len());
    row.extend_from_slice(&at.to_be_bytes());
    row.extend_from_slice(reason.as_bytes());
    row
}

fn ban_decode(row: &[u8]) -> Result<(u64, String), StoreError> {
    let (at, reason) = row
        .split_at_checked(8)
        .ok_or(StoreError::Corrupt("short ban row"))?;
    Ok((
        u64::from_be_bytes(at.try_into().map_err(|_| StoreError::Corrupt("ban"))?),
        std::str::from_utf8(reason)
            .map_err(|_| StoreError::Corrupt("ban reason not utf-8"))?
            .to_owned(),
    ))
}

impl FsStore {
    /// Open a store at `dir` (creating it and format-version 1 when
    /// absent; any other version refuses). `Mode::Serve` also takes
    /// `lock` and sweeps `tmp/`; both modes run trash recovery.
    ///
    /// # Errors
    ///
    /// [`StoreError::Locked`] when another process serves `dir`,
    /// [`StoreError::Format`] on a format mismatch, or
    /// [`StoreError::Io`]/[`StoreError::Heed`] underneath.
    #[expect(
        unsafe_code,
        reason = "heed maps the database file: the caller must not open the same env twice in one process nor let other code modify the files incompatibly"
    )]
    pub fn open(dir: &Path, mode: Mode) -> Result<Self, StoreError> {
        ensure_dirs(dir)?;
        let lock = (mode == Mode::Serve)
            .then(|| try_lock(&dir.join("lock")))
            .transpose()?;
        let env = {
            let mut options = EnvOpenOptions::new().read_txn_without_tls();
            options.map_size(MAP_SIZE).max_dbs(8);
            // SAFETY: the env is not opened twice in one process by
            // this store, and nothing else modifies the files
            // incompatibly.
            unsafe { options.open(dir.join("meta"))? }
        };
        env.clear_stale_readers()?;
        let wtxn = env.write_txn()?;
        let [blobs, owners, by_owner, usage, bans, info] = Result::from(
            env.create_databases_and_commit(wtxn, |dbo, wtxn| -> Result<_, StoreError> {
                let dbs: [Database<'_, Bytes, Bytes>; 6] = DB_NAMES
                    .iter()
                    .map(|name| dbo.create_database::<Bytes, Bytes>(wtxn, Some(name)))
                    .collect::<Result<Vec<_>, _>>()?
                    .try_into()
                    .map_err(|_| StoreError::Corrupt("named db count"))?;
                if let Some(err) = check_format(dbs[5], wtxn)? {
                    return Ok(CommitOrAbort::Abort(err));
                }
                Ok(CommitOrAbort::Commit(dbs))
            })?,
        )?;
        let store = Inner {
            dir: dir.to_path_buf(),
            env,
            blobs,
            owners,
            by_owner,
            usage,
            bans,
            info,
            lock,
        };
        {
            let txn = store.env.write_txn()?;
            store.recover_trash(&txn)?;
            txn.commit()?;
        }
        if mode == Mode::Serve {
            sweep_tmp(dir, store.lock.as_ref())?;
        }
        Ok(Self {
            inner: Arc::new(store),
        })
    }

    /// `hash`'s administration view: meta, owners, ban, file
    /// presence.
    ///
    /// # Errors
    ///
    /// [`StoreError`] on read failure or corruption.
    pub fn stat_full(&self, hash: &Hash) -> Result<Option<BlobStat>, StoreError> {
        let txn = self.inner.env.read_txn()?;
        let Some(meta) = self.inner.stat_txn(&txn, hash)? else {
            return Ok(None);
        };
        let banned = self
            .inner
            .bans
            .get(&txn, &hash.0)?
            .map(ban_decode)
            .transpose()?;
        Ok(Some(BlobStat {
            file_present: blob_path(&self.inner.dir, hash).is_file(),
            owners: self.inner.owners_of(&txn, hash)?,
            banned,
            meta,
        }))
    }

    /// Every blob row, hash-ascending, after `after` (exclusive),
    /// capped at `limit` — for `nosfry blob list`.
    ///
    /// # Errors
    ///
    /// [`StoreError`] on read failure or corruption.
    pub fn list_all(&self, limit: usize, after: Option<Hash>) -> Result<Vec<BlobStat>, StoreError> {
        let txn = self.inner.env.read_txn()?;
        let lower = after.map(|hash| hash.0);
        let bounds = lower
            .as_ref()
            .map_or((Bound::Unbounded, Bound::Unbounded), |key| {
                (Bound::Excluded(key.as_slice()), Bound::Unbounded)
            });
        let mut out = Vec::new();
        for entry in self.inner.blobs.range(&txn, &bounds)? {
            let (key, row) = entry?;
            let hash = Hash(
                key.try_into()
                    .map_err(|_| StoreError::Corrupt("blob key"))?,
            );
            let meta = meta_decode(hash, row)?;
            out.push(BlobStat {
                file_present: blob_path(&self.inner.dir, &hash).is_file(),
                owners: self.inner.owners_of(&txn, &hash)?,
                banned: self
                    .inner
                    .bans
                    .get(&txn, &hash.0)?
                    .map(ban_decode)
                    .transpose()?,
                meta,
            });
            if out.len() >= limit {
                break;
            }
        }
        Ok(out)
    }

    /// `owner`'s blobs, newest-first, capped at `limit` — for
    /// `nosfry blob list --owner`.
    ///
    /// # Errors
    ///
    /// [`StoreError`] on read failure or corruption.
    pub fn list_owner(&self, owner: &PublicKey, limit: usize) -> Result<Vec<BlobStat>, StoreError> {
        let txn = self.inner.env.read_txn()?;
        let mut start = [0u8; 72];
        start[..32].copy_from_slice(&owner.0);
        let bounds = (Bound::Included(start.as_slice()), Bound::Unbounded);
        let mut out = Vec::new();
        for entry in self.inner.by_owner.range(&txn, &bounds)? {
            let (key, _) = entry?;
            if !key.starts_with(&owner.0) {
                break;
            }
            let hash = Hash(
                key.get(40..72)
                    .ok_or(StoreError::Corrupt("by_owner key"))?
                    .try_into()
                    .map_err(|_| StoreError::Corrupt("by_owner key"))?,
            );
            let uploaded = u64::MAX
                - u64::from_be_bytes(
                    key.get(32..40)
                        .ok_or(StoreError::Corrupt("by_owner key"))?
                        .try_into()
                        .map_err(|_| StoreError::Corrupt("by_owner key"))?,
                );
            out.push((hash, uploaded));
            if out.len() >= limit {
                break;
            }
        }
        let mut stats = Vec::with_capacity(out.len());
        for (hash, uploaded) in out {
            let mut stat = self
                .inner
                .stat_txn(&txn, &hash)?
                .map(|meta| BlobStat {
                    file_present: blob_path(&self.inner.dir, &hash).is_file(),
                    owners: Vec::new(),
                    banned: None,
                    meta,
                })
                .ok_or(StoreError::Corrupt("by_owner without blob"))?;
            stat.meta.uploaded = uploaded;
            stat.owners = self.inner.owners_of(&txn, &hash)?;
            stat.banned = self
                .inner
                .bans
                .get(&txn, &hash.0)?
                .map(ban_decode)
                .transpose()?;
            stats.push(stat);
        }
        Ok(stats)
    }

    /// Delete `hash` for every owner; `false` when absent.
    ///
    /// # Errors
    ///
    /// [`StoreError`] on failure. A partial state cannot persist:
    /// the metadata change and the `trash/` move are one commit.
    pub fn delete(&self, hash: &Hash) -> Result<bool, StoreError> {
        let mut txn = self.inner.env.write_txn()?;
        let Some(meta) = self.inner.stat_txn(&txn, hash)? else {
            txn.abort();
            return Ok(false);
        };
        let trash = self.inner.delete_in_txn(&mut txn, hash, &meta)?;
        txn.commit()?;
        if let Some(path) = trash {
            std::fs::remove_file(path).ok();
        }
        Ok(true)
    }

    /// Ban `hash` and delete the blob in one transaction (the ban
    /// lands even when nothing was stored).
    ///
    /// # Errors
    ///
    /// [`StoreError::Value`] when `reason` exceeds
    /// [`MAX_REASON_BYTES`], [`StoreError`] on failure.
    pub fn ban(&self, hash: &Hash, reason: &str, now: u64) -> Result<(), StoreError> {
        if reason.len() > MAX_REASON_BYTES {
            return Err(StoreError::Value("ban reason over 1024 bytes"));
        }
        let mut txn = self.inner.env.write_txn()?;
        self.inner
            .bans
            .put(&mut txn, &hash.0, &ban_encode(now, reason))?;
        let trash = match self.inner.stat_txn(&txn, hash)? {
            Some(meta) => self.inner.delete_in_txn(&mut txn, hash, &meta)?,
            None => None,
        };
        txn.commit()?;
        if let Some(path) = trash {
            std::fs::remove_file(path).ok();
        }
        Ok(())
    }

    /// Drop a `bans` row; `false` when `hash` was not banned.
    ///
    /// # Errors
    ///
    /// [`StoreError`] on failure.
    pub fn unban(&self, hash: &Hash) -> Result<bool, StoreError> {
        let mut txn = self.inner.env.write_txn()?;
        let had = self.inner.bans.delete(&mut txn, &hash.0)?;
        txn.commit()?;
        Ok(had)
    }

    /// Every `bans` row.
    ///
    /// # Errors
    ///
    /// [`StoreError`] on read failure or corruption.
    pub fn bans(&self) -> Result<Vec<(Hash, u64, String)>, StoreError> {
        let txn = self.inner.env.read_txn()?;
        let mut out = Vec::new();
        for entry in self.inner.bans.iter(&txn)? {
            let (key, row) = entry?;
            let (at, reason) = ban_decode(row)?;
            out.push((
                Hash(key.try_into().map_err(|_| StoreError::Corrupt("ban key"))?),
                at,
                reason,
            ));
        }
        Ok(out)
    }

    /// The `info.total` row.
    ///
    /// # Errors
    ///
    /// [`StoreError`] on read failure or corruption.
    pub fn usage(&self) -> Result<Usage, StoreError> {
        let txn = self.inner.env.read_txn()?;
        self.inner.total_txn(&txn)
    }
}

/// `nosfry blob gc` output.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct GcReport {
    /// `blobs/` files unlinked because no `blobs` row names them.
    pub orphans_removed: u64,
    /// `tmp/` files swept (only with the store lock held).
    pub tmp_removed: u64,
    /// `trash/` files moved back or unlinked at open.
    pub trash_recovered: u64,
    /// `blobs` rows whose file is missing.
    pub missing_files: Vec<Hash>,
}

/// `nosfry blob verify` output.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct VerifyReport {
    /// Files re-hashed.
    pub checked: u64,
    /// Files whose content hash differs from their key.
    pub bad_hash: Vec<Hash>,
    /// `blobs` rows whose file is missing.
    pub missing: Vec<Hash>,
    /// `usage`/`info.total` recomputation mismatches, described.
    pub accounting_errors: Vec<String>,
}

impl FsStore {
    /// Collect content files under `blobs/` as `(hash, path)`.
    fn blob_files(&self) -> Result<Vec<(Hash, PathBuf)>, StoreError> {
        let mut out = Vec::new();
        collect_files(&self.inner.dir.join("blobs"), 2, &mut out)?;
        Ok(out)
    }

    /// `nosfry blob gc`: trash recovery, orphan files (one write txn
    /// each — check the row is absent, unlink, abort — so it is safe
    /// beside a running server), `tmp/` only when the lock is held,
    /// and a list of `blobs` rows whose file is gone.
    ///
    /// # Errors
    ///
    /// [`StoreError`] on failure.
    pub fn gc(&self) -> Result<GcReport, StoreError> {
        let mut report = GcReport::default();
        {
            let txn = self.inner.env.write_txn()?;
            report.trash_recovered = u64::from(self.inner.recover_trash(&txn)?);
            txn.commit()?;
        }
        for (hash, path) in self.blob_files()? {
            let txn = self.inner.env.write_txn()?;
            if self.inner.blobs.get(&txn, &hash.0)?.is_none() {
                std::fs::remove_file(path)?;
                report.orphans_removed += 1;
            }
            txn.abort();
        }
        // `tmp/` is swept only while the store lock is held —
        // `Mode::Serve` holds it for the process lifetime; an admin
        // sweep takes it only when no server runs.
        match sweep_tmp(&self.inner.dir, self.inner.lock.as_ref()) {
            Ok(removed) => report.tmp_removed = removed,
            Err(StoreError::Locked(_)) => {}
            Err(err) => return Err(err),
        }
        let txn = self.inner.env.read_txn()?;
        for entry in self.inner.blobs.iter(&txn)? {
            let (key, _) = entry?;
            if !blob_path(
                &self.inner.dir,
                &Hash(
                    key.try_into()
                        .map_err(|_| StoreError::Corrupt("blob key"))?,
                ),
            )
            .is_file()
            {
                report.missing_files.push(Hash(
                    key.try_into()
                        .map_err(|_| StoreError::Corrupt("blob key"))?,
                ));
            }
        }
        Ok(report)
    }

    /// `nosfry blob verify`: re-hash every stored file (64 KiB
    /// buffer, `progress` after each) and recompute `usage` /
    /// `info.total` from `owners`/`blobs`, reporting mismatches.
    ///
    /// # Errors
    ///
    /// [`StoreError`] on failure.
    pub fn verify(&self, mut progress: impl FnMut(u64)) -> Result<VerifyReport, StoreError> {
        let txn = self.inner.env.read_txn()?;
        let mut report = VerifyReport::default();
        let mut expected_total = Usage::default();
        let mut per_owner: BTreeMap<PublicKey, Usage> = BTreeMap::new();
        for entry in self.inner.blobs.iter(&txn)? {
            let (key, row) = entry?;
            let hash = Hash(
                key.try_into()
                    .map_err(|_| StoreError::Corrupt("blob key"))?,
            );
            let meta = meta_decode(hash, row)?;
            expected_total.bytes = expected_total.bytes.saturating_add(meta.size);
            expected_total.blobs += 1;
            for (pubkey, _) in self.inner.owners_of(&txn, &hash)? {
                let usage = per_owner.entry(pubkey).or_default();
                usage.bytes = usage.bytes.saturating_add(meta.size);
                usage.blobs += 1;
            }
            let path = blob_path(&self.inner.dir, &hash);
            match read_digest(&path)? {
                Some(got) if got != hash => report.bad_hash.push(hash),
                Some(_) => {}
                None => report.missing.push(hash),
            }
            report.checked += 1;
            progress(report.checked);
        }
        // Every usage row must equal the recomputation, and no owner
        // row may name a missing blob (caught implicitly: the row set
        // compared below is exact both ways).
        let mut seen = BTreeSet::new();
        for entry in self.inner.usage.iter(&txn)? {
            let (key, row) = entry?;
            let pubkey = PublicKey(
                key.try_into()
                    .map_err(|_| StoreError::Corrupt("usage key"))?,
            );
            seen.insert(pubkey);
            let stored = usage_decode(row)?;
            let want = per_owner.get(&pubkey).copied().unwrap_or_default();
            if stored != want {
                report.accounting_errors.push(format!(
                    "usage {pubkey}: stored {stored:?} != computed {want:?}"
                ));
            }
        }
        for pubkey in per_owner.keys() {
            if !seen.contains(pubkey) {
                report
                    .accounting_errors
                    .push(format!("usage {pubkey}: row missing"));
            }
        }
        let stored_total = self.inner.total_txn(&txn)?;
        if stored_total != expected_total {
            report.accounting_errors.push(format!(
                "total: stored {stored_total:?} != computed {expected_total:?}"
            ));
        }
        Ok(report)
    }
}

/// Hash a file's contents, `None` when absent.
fn read_digest(path: &Path) -> Result<Option<Hash>, StoreError> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err.into()),
    };
    let mut hasher = Sha256::new();
    std::io::copy(
        &mut std::io::BufReader::with_capacity(64 * 1024, file),
        &mut HasherWrite {
            hasher: &mut hasher,
        },
    )?;
    let got: [u8; 32] = hasher.finalize().into();
    Ok(Some(Hash(got)))
}

/// `std::io::Write` shim feeding a `Sha256`.
struct HasherWrite<'a> {
    hasher: &'a mut Sha256,
}

impl std::io::Write for HasherWrite<'_> {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.hasher.update(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl BlobStore for FsStore {
    type Reader = tokio::fs::File;
    type Staging = Staging;

    async fn open_blob(
        &self,
        hash: &Hash,
    ) -> Result<Option<(BlobMeta, tokio::fs::File)>, StoreError> {
        let Some(meta) = self.stat(hash).await? else {
            return Ok(None);
        };
        let file = match tokio::fs::File::open(blob_path(&self.inner.dir, hash)).await {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err.into()),
        };
        Ok(Some((meta, file)))
    }

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "the BlobStore contract is async; LMDB reads are cheap"
    )]
    async fn stat(&self, hash: &Hash) -> Result<Option<BlobMeta>, StoreError> {
        let txn = self.inner.env.read_txn()?;
        self.inner.stat_txn(&txn, hash)
    }

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "the BlobStore contract is async; LMDB reads are cheap"
    )]
    async fn check(&self, hash: &Hash, owner: &PublicKey) -> Result<Precheck, StoreError> {
        let txn = self.inner.env.read_txn()?;
        Ok(Precheck {
            banned: self.inner.bans.get(&txn, &hash.0)?.is_some(),
            owned: self
                .inner
                .owners
                .get(&txn, &owners_key(hash, owner))?
                .is_some(),
            exists: self.inner.blobs.get(&txn, &hash.0)?.is_some(),
            usage: self.inner.owner_usage(&txn, owner)?,
            total: self.inner.total_txn(&txn)?,
        })
    }

    async fn stage(&self) -> Result<Staging, StoreError> {
        // Unique-enough names: pid, sequence, time; O_EXCL retries on
        // a collision.
        let pid = std::process::id();
        for _ in 0..64 {
            let seq = STAGE_SEQ.fetch_add(1, Ordering::Relaxed);
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |dur| dur.subsec_nanos());
            let name = format!("{pid:04x}{seq:06x}{nanos:08x}")
                .chars()
                .take(16)
                .collect::<String>();
            let path = self.inner.dir.join("tmp").join(format!("{name}.part"));
            match tokio::fs::File::create_new(&path).await {
                Ok(file) => {
                    return Ok(Staging {
                        file,
                        path,
                        done: false,
                    });
                }
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(err) => return Err(err.into()),
            }
        }
        Err(StoreError::Value("could not create a staging file"))
    }

    async fn sync(&self, staging: &mut Staging) -> Result<(), StoreError> {
        staging.file.sync_all().await?;
        Ok(())
    }

    async fn commit(
        &self,
        mut staging: Staging,
        blob: NewBlob,
        limits: Quota,
    ) -> Result<Commit, CommitError> {
        let inner = Arc::clone(&self.inner);
        let path = std::mem::take(&mut staging.path);
        staging.done = true; // the blocking commit owns the file now
        let dir = inner.dir.clone();
        tokio::task::spawn_blocking(move || inner.commit_staged(&path, &dir, &blob, limits))
            .await
            .map_err(|_| StoreError::Value("commit task failed"))?
    }

    async fn remove_owner(&self, hash: &Hash, owner: &PublicKey) -> Result<Removal, StoreError> {
        let inner = Arc::clone(&self.inner);
        let hash = *hash;
        let owner = *owner;
        tokio::task::spawn_blocking(move || inner.remove_owner_sync(&hash, &owner))
            .await
            .map_err(|_| StoreError::Value("delete task failed"))?
    }

    async fn list(&self, owner: &PublicKey, query: ListQuery) -> Result<Vec<BlobMeta>, ListError> {
        let inner = Arc::clone(&self.inner);
        let owner = *owner;
        tokio::task::spawn_blocking(move || inner.list_sync(&owner, &query))
            .await
            .map_err(|_| ListError::Store(StoreError::Value("list task failed")))?
    }

    fn totals(&self) -> Result<Usage, StoreError> {
        self.usage()
    }
}

impl Inner {
    /// The serve-path commit — steps a–e of the upload write path,
    /// all inside one write txn so LMDB's cross-process writer lock
    /// serializes them with CLI deletes/bans/gc.
    fn commit_staged(
        &self,
        tmp: &Path,
        dir: &Path,
        blob: &NewBlob,
        limits: Quota,
    ) -> Result<Commit, CommitError> {
        let mut txn = self.env.write_txn()?;
        // a. The ban check is authoritative here.
        if self.bans.get(&txn, &blob.hash.0)?.is_some() {
            txn.abort();
            std::fs::remove_file(tmp).ok();
            return Err(CommitError::Banned);
        }
        let owner_key = owners_key(&blob.hash, &blob.owner);
        // b. Already owned: nothing to do but report it.
        if self.owners.get(&txn, &owner_key)?.is_some() {
            let meta = self
                .stat_txn(&txn, &blob.hash)?
                .ok_or(StoreError::Corrupt("owner without blob row"))?;
            txn.abort();
            std::fs::remove_file(tmp).ok();
            return Ok(Commit::Existed(meta));
        }
        // c. Per-owner quota, charged the full size.
        let usage = self.owner_usage(&txn, &blob.owner)?;
        if usage.bytes.saturating_add(blob.size) > limits.bytes
            || usage.blobs.saturating_add(1) > limits.blobs
        {
            txn.abort();
            std::fs::remove_file(tmp).ok();
            return Err(CommitError::Quota);
        }
        let result = if let Some(existing) = self.stat_txn(&txn, &blob.hash)? {
            // d. Shared content: only ownership rows are added — the
            // staged file is duplicate bytes and is unlinked. The
            // descriptor reports this owner's upload time.
            self.charge_owner_rows(&mut txn, blob, blob.now)?;
            std::fs::remove_file(tmp).ok();
            Commit::Existed(BlobMeta {
                uploaded: blob.now,
                ..existing
            })
        } else {
            // The physical byte cap counts once per stored blob.
            let total = self.total_txn(&txn)?;
            if total.bytes.saturating_add(blob.size) > limits.total_bytes {
                txn.abort();
                std::fs::remove_file(tmp).ok();
                return Err(CommitError::Full);
            }
            let meta = BlobMeta {
                hash: blob.hash,
                size: blob.size,
                mime: blob.mime.clone(),
                uploaded: blob.now,
            };
            if let Err(err) = self.commit_file(&mut txn, tmp, dir, &meta, blob) {
                // Nothing was committed: drop the staged file (or its
                // destination when the failure came after rename).
                txn.abort();
                std::fs::remove_file(tmp).ok();
                std::fs::remove_file(blob_path(dir, &blob.hash)).ok();
                return Err(err);
            }
            Commit::Created(meta)
        };
        // e. One commit lands rows and file placement together.
        txn.commit()?;
        Ok(result)
    }

    /// Write `meta` + ownership rows and move `tmp` into `blobs/`.
    fn commit_file(
        &self,
        txn: &mut RwTxn<'_>,
        tmp: &Path,
        dir: &Path,
        meta: &BlobMeta,
        blob: &NewBlob,
    ) -> Result<(), CommitError> {
        let to = blob_path(dir, &blob.hash);
        let parent = to.parent().ok_or(StoreError::Corrupt("blob path"))?;
        let (top, _mid) = shard_hex(&blob.hash);
        let level1 = dir.join("blobs").join(top);
        if !level1.exists() {
            std::fs::create_dir(&level1)?;
            sync_dir(&dir.join("blobs"))?;
        }
        if !parent.exists() {
            std::fs::create_dir(parent)?;
            sync_dir(&level1)?;
        }
        std::fs::rename(tmp, &to)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&to, std::fs::Permissions::from_mode(0o644))?;
        }
        sync_dir(parent)?;
        self.blobs.put(txn, &blob.hash.0, &meta_encode(meta))?;
        self.charge_owner_rows(txn, blob, meta.uploaded)?;
        self.charge_total(txn, meta.size.cast_signed(), 1)?;
        Ok(())
    }

    /// The `owners`/`by_owner`/`usage` rows of one new ownership.
    fn charge_owner_rows(
        &self,
        txn: &mut RwTxn<'_>,
        blob: &NewBlob,
        uploaded: u64,
    ) -> Result<(), StoreError> {
        self.owners.put(
            txn,
            &owners_key(&blob.hash, &blob.owner),
            &uploaded.to_be_bytes(),
        )?;
        self.by_owner
            .put(txn, &by_owner_key(&blob.owner, uploaded, &blob.hash), &[])?;
        self.charge_usage(txn, &blob.owner, blob.size.cast_signed(), 1)?;
        Ok(())
    }

    /// `remove_owner` off the runtime.
    fn remove_owner_sync(&self, hash: &Hash, owner: &PublicKey) -> Result<Removal, StoreError> {
        let mut txn = self.env.write_txn()?;
        let Some(meta) = self.stat_txn(&txn, hash)? else {
            txn.abort();
            return Ok(Removal::NotFound);
        };
        let key = owners_key(hash, owner);
        let Some(row) = self.owners.get(&txn, &key)? else {
            txn.abort();
            return Ok(Removal::NotOwner);
        };
        let uploaded = u64::from_be_bytes(
            row.try_into()
                .map_err(|_| StoreError::Corrupt("owners row"))?,
        );
        self.charge_usage(&mut txn, owner, -meta.size.cast_signed(), -1)?;
        self.owners.delete(&mut txn, &key)?;
        self.by_owner
            .delete(&mut txn, &by_owner_key(owner, uploaded, hash))?;
        let last = !self.has_owner(&txn, hash)?;
        let trash = if last {
            self.delete_in_txn(&mut txn, hash, &meta)?
        } else {
            None
        };
        txn.commit()?;
        if let Some(path) = trash {
            std::fs::remove_file(path).ok();
        }
        Ok(Removal::Removed { last })
    }

    /// `list` off the runtime: one read txn over `by_owner`.
    fn list_sync(&self, owner: &PublicKey, query: &ListQuery) -> Result<Vec<BlobMeta>, ListError> {
        let txn = self.env.read_txn()?;
        if query.limit == 0 {
            return Ok(Vec::new());
        }
        // A cursor must name one of this owner's blobs; its key
        // bounds the page start exclusively. `until` seeks to the
        // first key at-or-before that timestamp (newest-first order)
        // instead of scanning. With both, whichever key sorts later
        // wins.
        let cursor_key = match query.cursor {
            Some(cursor) => {
                let row = self
                    .owners
                    .get(&txn, &owners_key(&cursor, owner))?
                    .ok_or(ListError::BadCursor)?;
                let uploaded = u64::from_be_bytes(
                    row.try_into()
                        .map_err(|_| ListError::Store(StoreError::Corrupt("owners row")))?,
                );
                Some(by_owner_key(owner, uploaded, &cursor))
            }
            None => None,
        };
        let until_key = query
            .until
            .map(|until| by_owner_key(owner, until, &Hash([0; 32])));
        let mut prefix = [0u8; 72];
        prefix[..32].copy_from_slice(&owner.0);
        let (start, exclusive) = match (cursor_key, until_key) {
            (Some(cursor), Some(until)) => {
                if cursor > until {
                    (cursor, true)
                } else {
                    (until, false)
                }
            }
            (Some(cursor), None) => (cursor, true),
            (None, Some(until)) => (until, false),
            (None, None) => (prefix, false),
        };
        let bounds = (
            if exclusive {
                Bound::Excluded(start.as_slice())
            } else {
                Bound::Included(start.as_slice())
            },
            Bound::Unbounded,
        );
        let mut out = Vec::new();
        for entry in self.by_owner.range(&txn, &bounds)? {
            let (key, _) = entry?;
            if !key.starts_with(&owner.0) {
                break;
            }
            let rev = u64::from_be_bytes(
                key.get(32..40)
                    .ok_or(ListError::Store(StoreError::Corrupt("by_owner key")))?
                    .try_into()
                    .map_err(|_| ListError::Store(StoreError::Corrupt("by_owner key")))?,
            );
            let uploaded = u64::MAX - rev;
            if query.since.is_some_and(|since| uploaded < since) {
                break; // ordered newest-first — the rest is older
            }
            let hash = Hash(
                key.get(40..72)
                    .ok_or(ListError::Store(StoreError::Corrupt("by_owner key")))?
                    .try_into()
                    .map_err(|_| ListError::Store(StoreError::Corrupt("by_owner key")))?,
            );
            let mut meta =
                self.stat_txn(&txn, &hash)?
                    .ok_or(ListError::Store(StoreError::Corrupt(
                        "by_owner without blob",
                    )))?;
            meta.uploaded = uploaded;
            out.push(meta);
            if out.len() >= query.limit {
                break;
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncWriteExt as _;

    use super::*;

    const LIMITS: Quota = Quota {
        bytes: 1_000_000,
        blobs: 100,
        total_bytes: 10_000_000,
    };

    fn pubkey(n: u8) -> PublicKey {
        PublicKey([n; 32])
    }

    fn digest(body: &[u8]) -> Hash {
        Hash(Sha256::digest(body).into())
    }

    /// Stage+commit `body` for `owner`.
    async fn put(store: &FsStore, owner: u8, body: &[u8], now: u64) -> Commit {
        let mut staging = store.stage().await.unwrap();
        staging.write_all(body).await.unwrap();
        store.sync(&mut staging).await.unwrap();
        store
            .commit(
                staging,
                NewBlob {
                    hash: digest(body),
                    size: body.len() as u64,
                    mime: "text/plain".to_owned(),
                    owner: pubkey(owner),
                    now,
                },
                LIMITS,
            )
            .await
            .unwrap()
    }

    fn store(dir: &tempfile::TempDir) -> FsStore {
        FsStore::open(dir.path(), Mode::Serve).unwrap()
    }

    /// Commit, dedupe as a second owner, ownership rows, totals.
    #[tokio::test]
    async fn commit_dedupe_owners() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(&dir);
        let body = b"hello blossom";
        let first = put(&store, 1, body, 100).await;
        assert!(matches!(first, Commit::Created(ref m) if m.size == 13));
        // Same owner again: Existed, no second ownership row.
        let again = put(&store, 1, body, 200).await;
        assert!(matches!(again, Commit::Existed(ref m) if m.uploaded == 100));
        // Second owner: Existed, this owner's upload time reported.
        let second = put(&store, 2, body, 300).await;
        assert!(matches!(second, Commit::Existed(ref m) if m.uploaded == 300));
        let stat = store.stat_full(&digest(body)).unwrap().unwrap();
        assert_eq!(stat.owners.len(), 2);
        assert!(stat.file_present);
        assert_eq!(
            store.usage().unwrap(),
            Usage {
                bytes: 13,
                blobs: 1
            }
        );
        // Per-owner usage: both owners carry the bytes.
        let query = ListQuery {
            limit: 100,
            ..ListQuery::default()
        };
        let one = store.list(&pubkey(1), query).await.unwrap();
        let two = store.list(&pubkey(2), query).await.unwrap();
        assert_eq!(one.len(), 1);
        assert_eq!(two.first().unwrap().uploaded, 300);
        // The blob reads back through the trait.
        let (meta, mut reader) = store.open_blob(&digest(body)).await.unwrap().unwrap();
        assert_eq!(meta.mime, "text/plain");
        let mut buf = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut reader, &mut buf)
            .await
            .unwrap();
        assert_eq!(buf, body);
    }

    /// Quota and the global cap refuse at commit.
    #[tokio::test]
    async fn quota_and_cap() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(&dir);
        let tight = Quota {
            bytes: 10,
            blobs: 1,
            total_bytes: 15,
        };
        let body = b"0123456789";
        put(&store, 1, body, 1).await;
        // Second blob over the owner's byte quota.
        let staging = store.stage().await.unwrap();
        let err = store
            .commit(
                staging,
                NewBlob {
                    hash: digest(b"other"),
                    size: 5,
                    mime: "x".to_owned(),
                    owner: pubkey(1),
                    now: 2,
                },
                tight,
            )
            .await;
        assert!(matches!(err, Err(CommitError::Quota)));
        // A different owner fits quota but exceeds the global cap
        // (10 stored + 10 more > 15).
        let staging2 = store.stage().await.unwrap();
        let err2 = store
            .commit(
                staging2,
                NewBlob {
                    hash: digest(b"other-blob"),
                    size: 10,
                    mime: "x".to_owned(),
                    owner: pubkey(2),
                    now: 2,
                },
                tight,
            )
            .await;
        assert!(matches!(err2, Err(CommitError::Full)));
    }

    /// Ban in one txn deletes the blob and refuses re-upload.
    #[tokio::test]
    async fn ban_deletes_and_refuses() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(&dir);
        let body = b"banned content";
        put(&store, 1, body, 1).await;
        store.ban(&digest(body), "csam", 50).unwrap();
        assert!(store.stat_full(&digest(body)).unwrap().is_none());
        assert!(store.check(&digest(body), &pubkey(1)).await.unwrap().banned);
        let staging = store.stage().await.unwrap();
        let err = store
            .commit(
                staging,
                NewBlob {
                    hash: digest(body),
                    size: body.len() as u64,
                    mime: "x".to_owned(),
                    owner: pubkey(1),
                    now: 2,
                },
                LIMITS,
            )
            .await;
        assert!(matches!(err, Err(CommitError::Banned)));
        // Banning a hash that was never stored still lands the row.
        let ghost = digest(b"never stored");
        store.ban(&ghost, "", 60).unwrap();
        assert!(store.bans().unwrap().iter().any(|(h, _, _)| *h == ghost));
        store.unban(&ghost).unwrap();
        assert!(!store.bans().unwrap().iter().any(|(h, _, _)| *h == ghost));
    }

    /// Owner removal: non-owner, last-owner delete, file gone.
    #[tokio::test]
    async fn delete_paths() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(&dir);
        let body = b"mine and yours";
        put(&store, 1, body, 1).await;
        put(&store, 2, body, 2).await;
        assert_eq!(
            store.remove_owner(&digest(body), &pubkey(9)).await.unwrap(),
            Removal::NotOwner
        );
        assert_eq!(
            store
                .remove_owner(&digest(b"gone"), &pubkey(1))
                .await
                .unwrap(),
            Removal::NotFound
        );
        assert_eq!(
            store.remove_owner(&digest(body), &pubkey(1)).await.unwrap(),
            Removal::Removed { last: false }
        );
        assert!(store.stat(&digest(body)).await.unwrap().is_some());
        assert_eq!(
            store.remove_owner(&digest(body), &pubkey(2)).await.unwrap(),
            Removal::Removed { last: true }
        );
        assert!(store.stat(&digest(body)).await.unwrap().is_none());
        assert!(!blob_path(dir.path(), &digest(body)).exists());
        assert_eq!(store.usage().unwrap(), Usage { bytes: 0, blobs: 0 });
    }

    /// A `trash/` file whose `blobs` row lives moves back at open;
    /// one whose row went is unlinked. `tmp/` files are swept.
    #[tokio::test]
    async fn trash_recovery_and_tmp_sweep() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(&dir);
        let body = b"recover me";
        put(&store, 1, body, 1).await;
        // Simulate a crash between rename and unlink.
        std::fs::create_dir_all(dir.path().join("trash")).unwrap();
        std::fs::copy(
            blob_path(dir.path(), &digest(body)),
            dir.path().join("trash").join(digest(body).to_string()),
        )
        .unwrap();
        std::fs::remove_file(blob_path(dir.path(), &digest(body))).unwrap();
        // A trash file with no row is just swept.
        std::fs::write(
            dir.path().join("trash").join(digest(b"dead").to_string()),
            b"x",
        )
        .unwrap();
        // A staging file is swept on Serve open.
        std::fs::write(dir.path().join("tmp").join("aa.part"), b"x").unwrap();
        drop(store);
        let reopened = FsStore::open(dir.path(), Mode::Serve).unwrap();
        assert!(blob_path(dir.path(), &digest(body)).is_file());
        assert!(
            !dir.path()
                .join("trash")
                .join(digest(b"dead").to_string())
                .exists()
        );
        assert!(!dir.path().join("tmp").join("aa.part").exists());
        drop(reopened);
        // A second Serve open is refused while one holds the lock —
        // in-process it fails earlier on heed's own EnvAlreadyOpened.
        let held = FsStore::open(dir.path(), Mode::Serve).unwrap();
        assert!(matches!(
            FsStore::open(dir.path(), Mode::Serve),
            Err(StoreError::Locked(_) | StoreError::Heed(_))
        ));
        // Admin mode coexists across processes (heed forbids two
        // envs on one path inside a single process — test the
        // sequential case here).
        drop(held);
        FsStore::open(dir.path(), Mode::Admin).unwrap();
    }

    /// gc removes orphan files and reports missing metadata files.
    #[tokio::test]
    async fn gc_orphans() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(&dir);
        let body = b"tracked";
        put(&store, 1, body, 1).await;
        // Plant an orphan file whose hash has no row.
        let orphan = digest(b"orphan");
        let orphan_path = blob_path(dir.path(), &orphan);
        std::fs::create_dir_all(orphan_path.parent().unwrap()).unwrap();
        std::fs::write(&orphan_path, b"orphan").unwrap();
        // And delete a tracked file out from under the metadata.
        std::fs::remove_file(blob_path(dir.path(), &digest(body))).unwrap();
        let report = store.gc().unwrap();
        assert_eq!(report.orphans_removed, 1);
        assert_eq!(report.missing_files, vec![digest(body)]);
        assert!(!orphan_path.exists());
    }

    /// verify: clean store is clean; corrupted file and bookkeeping
    /// drift are reported.
    #[tokio::test]
    async fn verify_accounting() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(&dir);
        let body = b"verify me";
        put(&store, 1, body, 1).await;
        let report = store.verify(|_| {}).unwrap();
        assert_eq!(report.checked, 1);
        assert_eq!(report.bad_hash, []);
        assert_eq!(report.missing, []);
        assert_eq!(report.accounting_errors, Vec::<String>::new());
        // Corrupt the content file: hash mismatch is reported.
        std::fs::write(blob_path(dir.path(), &digest(body)), b"corrupted!").unwrap();
        let report2 = store.verify(|_| {}).unwrap();
        assert_eq!(report2.bad_hash, vec![digest(body)]);
    }

    /// `/list` paging: newest-first, cursor exclusion, since/until,
    /// limit, bad cursor.
    #[tokio::test]
    async fn list_paging() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(&dir);
        for i in 0..5_u8 {
            put(&store, 1, &[b'a' + i], u64::from(i) + 1).await;
        }
        put(&store, 2, b"not mine", 1).await;
        let all = store
            .list(
                &pubkey(1),
                ListQuery {
                    limit: 100,
                    ..ListQuery::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(all.len(), 5);
        assert_eq!(all.first().unwrap().uploaded, 5);
        // Cursor: page after the newest.
        let page = store
            .list(
                &pubkey(1),
                ListQuery {
                    cursor: Some(all.first().unwrap().hash),
                    limit: 2,
                    ..ListQuery::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(page.len(), 2);
        assert_eq!(page.first().unwrap().uploaded, 4);
        // since/until.
        let window = store
            .list(
                &pubkey(1),
                ListQuery {
                    since: Some(2),
                    until: Some(3),
                    limit: 100,
                    ..ListQuery::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(window.len(), 2);
        // A cursor this pubkey does not own.
        assert!(matches!(
            store
                .list(
                    &pubkey(1),
                    ListQuery {
                        cursor: Some(digest(b"not mine")),
                        limit: 10,
                        ..ListQuery::default()
                    },
                )
                .await,
            Err(ListError::BadCursor)
        ));
    }

    /// Cursor pages walk every blob exactly once, newest-first, even
    /// across equal `uploaded` stamps; `until`/`since` windows bound
    /// the seek, and cursor+until combine.
    #[tokio::test]
    async fn list_cursor_seeks() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(&dir);
        // 7 blobs; two share the same `uploaded` stamp.
        let uploaded = [6_u64, 5, 4, 3, 3, 2, 1];
        for (i, stamp) in uploaded.iter().enumerate() {
            put(&store, 1, &[b'b', u8::try_from(i).unwrap()], *stamp).await;
        }
        let owner = pubkey(1);
        let fetch = |cursor: Option<Hash>, since: Option<u64>, until: Option<u64>| {
            store.list(
                &owner,
                ListQuery {
                    cursor,
                    since,
                    until,
                    limit: 3,
                },
            )
        };
        // Pages of 3, 3, 1 — all 7 exactly once, in listed order.
        let all = store
            .list(
                &pubkey(1),
                ListQuery {
                    limit: 100,
                    ..ListQuery::default()
                },
            )
            .await
            .unwrap();
        let mut seen = Vec::new();
        let mut cursor = None;
        for want in [3, 3, 1] {
            let page = fetch(cursor, None, None).await.unwrap();
            assert_eq!(page.len(), want);
            cursor = Some(page.last().unwrap().hash);
            seen.extend(page);
        }
        assert_eq!(fetch(cursor, None, None).await.unwrap().len(), 0);
        assert_eq!(
            seen.iter().map(|m| m.hash).collect::<Vec<_>>(),
            all.iter().map(|m| m.hash).collect::<Vec<_>>()
        );
        assert!(
            seen.windows(2)
                .all(|w| w.first().unwrap().uploaded >= w.last().unwrap().uploaded)
        );
        // `until` alone: entries t<=4 are {4,3,3,2,1} — 3 + 2.
        let first = fetch(None, None, Some(4)).await.unwrap();
        assert_eq!(first.len(), 3);
        assert!(first.iter().all(|m| m.uploaded <= 4));
        let second = fetch(Some(first.last().unwrap().hash), None, Some(4))
            .await
            .unwrap();
        assert_eq!(second.len(), 2);
        // `since` + `until` window: {4,3,3}.
        let window = fetch(None, Some(3), Some(4)).await.unwrap();
        assert_eq!(window.len(), 3);
        assert!(window.iter().all(|m| (3..=4).contains(&m.uploaded)));
        // Cursor older than the `until` boundary: cursor wins and the
        // `until` bound is already implied — {2,1}.
        let tail = fetch(Some(window.last().unwrap().hash), None, Some(5))
            .await
            .unwrap();
        assert_eq!(tail.len(), 2);
        assert!(tail.iter().all(|m| m.uploaded <= 2));
    }

    /// The on-disk bytes are format v1: the env holds exactly
    /// `DB_NAMES`, and one row of each table matches the module-docs
    /// encoding byte for byte.
    #[tokio::test]
    async fn format_v1_golden_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(&dir);
        let body = b"hello blossom";
        let hash = digest(body);
        let owner = pubkey(7);
        let uploaded = 1_700_000_000u64;
        assert!(matches!(
            put(&store, 7, body, uploaded).await,
            Commit::Created(_)
        ));
        let ghost = digest(b"ghost blob");
        store.ban(&ghost, "spam", 42).unwrap();

        let txn = store.inner.env.read_txn().unwrap();
        Result::from(
            store
                .inner
                .env
                .open_databases_and_commit(txn, |dbo, rtxn| -> Result<_, StoreError> {
                    // LMDB stores every named-database name as a key of
                    // the unnamed database.
                    let main = dbo
                        .open_database::<Bytes, Bytes>(rtxn, None)?
                        .ok_or(StoreError::Corrupt("no unnamed db"))?;
                    let names = main
                        .iter(rtxn)?
                        .map(|row| row.map(|(name, _)| name.to_vec()))
                        .collect::<Result<BTreeSet<_>, heed::Error>>()?;
                    assert_eq!(
                        names,
                        DB_NAMES
                            .iter()
                            .map(|name| name.as_bytes().to_vec())
                            .collect::<BTreeSet<_>>()
                    );

                    let inner = &store.inner;
                    // `info`: `version` u32 BE; `total` a usage row.
                    assert_eq!(
                        inner.info.get(rtxn, b"version")?,
                        Some(&[0x00, 0x00, 0x00, 0x01][..])
                    );
                    let total_row = [0, 0, 0, 0, 0, 0, 0, 13, 0, 0, 0, 0, 0, 0, 0, 1];
                    assert_eq!(inner.info.get(rtxn, b"total")?, Some(&total_row[..]));
                    // `blobs`: hash → size|uploaded|type.
                    let mut blobs_row = Vec::new();
                    blobs_row.extend_from_slice(&13u64.to_be_bytes());
                    blobs_row.extend_from_slice(&uploaded.to_be_bytes());
                    blobs_row.extend_from_slice(b"text/plain");
                    assert_eq!(inner.blobs.get(rtxn, &hash.0)?, Some(&blobs_row[..]));
                    // `owners`: hash‖pubkey → uploaded.
                    let mut owners_expect = Vec::new();
                    owners_expect.extend_from_slice(&hash.0);
                    owners_expect.extend_from_slice(&owner.0);
                    assert_eq!(
                        inner.owners.get(rtxn, &owners_expect)?,
                        Some(&uploaded.to_be_bytes()[..])
                    );
                    // `by_owner`: pubkey‖(u64::MAX-uploaded)‖hash → ().
                    let mut by_owner_expect = Vec::new();
                    by_owner_expect.extend_from_slice(&owner.0);
                    by_owner_expect.extend_from_slice(&(u64::MAX - uploaded).to_be_bytes());
                    by_owner_expect.extend_from_slice(&hash.0);
                    assert_eq!(inner.by_owner.get(rtxn, &by_owner_expect)?, Some(&[][..]));
                    // `usage`: pubkey → bytes|blobs.
                    assert_eq!(inner.usage.get(rtxn, &owner.0)?, Some(&total_row[..]));
                    // `bans`: hash → banned_at|reason.
                    let mut bans_row = Vec::new();
                    bans_row.extend_from_slice(&42u64.to_be_bytes());
                    bans_row.extend_from_slice(b"spam");
                    assert_eq!(inner.bans.get(rtxn, &ghost.0)?, Some(&bans_row[..]));

                    Ok(CommitOrAbort::<_, ()>::Commit(()))
                })
                .unwrap(),
        )
        .unwrap();
    }
}
