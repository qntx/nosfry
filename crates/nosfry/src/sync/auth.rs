//! NIP-42 client authentication: load the `--auth-key-file` secret
//! key and sign the kind-22242 AUTH event. The key is only ever read
//! from a file (never a flag or the environment), its content never
//! appears in errors, and logs name only its public key.

use std::path::Path;

use nosfry_core::auth::AUTH_KIND;
use nosfry_core::event::{EventId, PublicKey, UnverifiedEvent, serialize_for_id};
use secp256k1::{Keypair, SecretKey, schnorr};

use super::SyncError;

/// Load a key file: exactly 64 lowercase hex characters plus optional
/// trailing whitespace. On unix the file must not be readable by
/// group or others.
///
/// # Errors
///
/// [`SyncError::Io`] on read failure, [`SyncError::KeyFile`] on bad
/// contents or permissions — never carrying the file's content.
pub(crate) fn load_key(path: &Path) -> Result<Keypair, SyncError> {
    let text = std::fs::read_to_string(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)?.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(SyncError::KeyFile(format!(
                "{} is group/other-readable; chmod 600 it",
                path.display()
            )));
        }
    }
    let hex = text.trim_end();
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(SyncError::KeyFile(
            "expected exactly 64 hex characters".to_owned(),
        ));
    }
    let mut bytes = [0u8; 32];
    faster_hex::hex_decode(hex.as_bytes(), &mut bytes)
        .map_err(|_| SyncError::KeyFile("invalid hex".to_owned()))?;
    let secret = SecretKey::from_secret_bytes(bytes)
        .map_err(|_| SyncError::KeyFile("not a valid secret key".to_owned()))?;
    Ok(Keypair::from_secret_key(&secret))
}

/// Build and sign the kind-22242 AUTH event answering `challenge`:
/// the `relay` tag is the peer URL as given. Returns `(id, json)`;
/// the event is self-checked through `UnverifiedEvent` before it is
/// handed out.
///
/// # Errors
///
/// [`SyncError::KeyFile`] when entropy is unavailable or the built
/// event fails its own verification (a bug, not user input).
pub(crate) fn auth_event(
    keypair: &Keypair,
    relay_url: &str,
    challenge: &str,
    created_at: u64,
) -> Result<(EventId, String), SyncError> {
    let pubkey = PublicKey(keypair.x_only_public_key().0.to_byte_array());
    let tags = vec![
        vec!["relay".to_owned(), relay_url.to_owned()],
        vec!["challenge".to_owned(), challenge.to_owned()],
    ];
    let preimage = serialize_for_id(&pubkey, created_at, AUTH_KIND, &tags, "");
    let id = nosfry_core::event::event_id(preimage.as_bytes());
    let mut aux = [0u8; 32];
    getrandom::fill(&mut aux)
        .map_err(|err| SyncError::KeyFile(format!("entropy unavailable: {err}")))?;
    let sig = schnorr::sign_with_aux_rand(&id.0, keypair, &aux);
    let json = serde_json::json!({
        "id": id.to_string(),
        "pubkey": pubkey.to_string(),
        "created_at": created_at,
        "kind": AUTH_KIND.0,
        "tags": tags,
        "content": "",
        "sig": faster_hex::hex_string(&sig.to_byte_array()),
    })
    .to_string();
    // Cheap insurance: parse and verify what was just built.
    UnverifiedEvent::parse(&json, &nosfry_core::event::EventLimits::default())
        .and_then(|event| event.verify(&nosfry_core::event::EventLimits::default()))
        .map_err(|err| SyncError::KeyFile(format!("built AUTH event failed self-check: {err}")))?;
    Ok((id, json))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "unit tests may panic on failure"
)]
mod tests {
    use super::*;

    fn write_key(dir: &Path, name: &str, contents: &str) -> std::path::PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn load_key_accepts_64_hex() {
        let dir = tempfile::tempdir().unwrap();
        let key = Keypair::from_secret_key(&SecretKey::from_secret_bytes([7u8; 32]).unwrap());
        let path = write_key(
            dir.path(),
            "k",
            &format!("{}\n", faster_hex::hex_string(&key.to_secret_bytes())),
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let loaded = load_key(&path).unwrap();
        assert_eq!(loaded.to_secret_bytes(), key.to_secret_bytes());
    }

    #[cfg(unix)]
    #[test]
    fn load_key_refuses_group_readable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = write_key(dir.path(), "k", &"ab".repeat(32));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = load_key(&path).err().unwrap().to_string();
        assert!(err.contains("chmod 600"), "{err}");
        assert!(!err.contains("abab"), "{err}");
    }

    #[test]
    fn load_key_refuses_bad_contents() {
        let dir = tempfile::tempdir().unwrap();
        for contents in ["ab", &"ab".repeat(33), &"zz".repeat(32)] {
            let path = write_key(dir.path(), "k", contents);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            }
            let err = load_key(&path).err().unwrap().to_string();
            assert!(!err.contains(contents), "{err}");
        }
    }

    #[test]
    fn auth_event_verifies_with_tags() {
        let key = Keypair::from_secret_key(&SecretKey::from_secret_bytes([9u8; 32]).unwrap());
        let (id, json) =
            auth_event(&key, "ws://127.0.0.1:7777", "challenge-1", 1_700_000_000).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.get("kind"), Some(&serde_json::json!(22242)));
        assert_eq!(
            parsed.get("tags"),
            Some(&serde_json::json!([
                ["relay", "ws://127.0.0.1:7777"],
                ["challenge", "challenge-1"]
            ]))
        );
        let unverified =
            UnverifiedEvent::parse(&json, &nosfry_core::event::EventLimits::default()).unwrap();
        assert_eq!(unverified.id(), id);
        unverified
            .verify(&nosfry_core::event::EventLimits::default())
            .unwrap();
    }
}
