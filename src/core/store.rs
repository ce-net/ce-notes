//! Local, per-device persistence for CE Notes, encrypted at rest under a device-local key.
//!
//! Layout, rooted at `<data_dir>/ce-notes/`:
//! ```text
//! ce-notes/
//!   <space_id>/
//!     space.json     SpaceMeta, sealed at rest (a stolen disk without the node key yields nothing)
//!     index.ydoc     the per-space index CRDT snapshot (sealed)
//!     <note_id>.ydoc the note body CRDT snapshot (sealed)
//!     applied.json   { writer_id: drained_count } per merge-log, for resume (sealed)
//!     attachments/<cid>  decrypted attachment cache (lazy; plaintext, lives only on this device)
//! ```
//!
//! The at-rest key is derived from the node identity secret, so it is the *same device-local key*
//! across runs and unique per device. We reuse the [`crypto`](super::crypto) AEAD with a fixed epoch
//! for at-rest sealing.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Serialize;
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};

use super::crypto::{NONCE_LEN, SpaceKey, open, seal};
use super::model::SpaceMeta;

/// At-rest epoch tag (distinct from any space key epoch; the at-rest key is a different key).
const AT_REST_EPOCH: u32 = 0;
const AT_REST_LABEL: &[u8] = b"ce-notes-at-rest-v1";

/// A device-local store. Holds the data root and the at-rest sealing key.
pub struct Store {
    root: PathBuf,
    at_rest_key: SpaceKey,
}

impl Store {
    /// Open (creating if needed) the store under `<data_dir>/ce-notes`, deriving the at-rest key
    /// from the node identity secret.
    pub fn open(data_dir: &Path, node_secret: &[u8; 32]) -> Result<Store> {
        let root = data_dir.join("ce-notes");
        std::fs::create_dir_all(&root).with_context(|| format!("create {}", root.display()))?;
        // Derive a 32-byte at-rest key from the node secret, domain-separated from everything else.
        let mut h = Sha256::new();
        h.update(AT_REST_LABEL);
        h.update(node_secret);
        let key: [u8; 32] = h.finalize().into();
        Ok(Store { root, at_rest_key: SpaceKey::from_bytes(key) })
    }

    /// The data root (`<data_dir>/ce-notes`).
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn space_dir(&self, space_id: &str) -> PathBuf {
        self.root.join(space_id)
    }

    fn ensure_space_dir(&self, space_id: &str) -> Result<PathBuf> {
        let dir = self.space_dir(space_id);
        std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
        Ok(dir)
    }

    /// List the space ids that have local state.
    pub fn list_space_ids(&self) -> Result<Vec<String>> {
        let mut ids = Vec::new();
        if !self.root.exists() {
            return Ok(ids);
        }
        for entry in std::fs::read_dir(&self.root)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                if let Some(name) = entry.file_name().to_str() {
                    if entry.path().join("space.json").exists() {
                        ids.push(name.to_string());
                    }
                }
            }
        }
        ids.sort();
        Ok(ids)
    }

    /// Persist space metadata (sealed at rest).
    pub fn save_meta(&self, meta: &SpaceMeta) -> Result<()> {
        let dir = self.ensure_space_dir(&meta.space_id)?;
        self.write_sealed(&dir.join("space.json"), meta)
    }

    /// Load space metadata.
    pub fn load_meta(&self, space_id: &str) -> Result<SpaceMeta> {
        self.read_sealed(&self.space_dir(space_id).join("space.json"))
    }

    /// Persist a CRDT document snapshot (index or a note body), sealed at rest.
    pub fn save_doc_snapshot(&self, space_id: &str, doc_id: &str, snapshot: &[u8]) -> Result<()> {
        let dir = self.ensure_space_dir(space_id)?;
        let path = dir.join(format!("{}.ydoc", safe_doc_name(doc_id)));
        let (nonce, ct) = seal(&self.at_rest_key, AT_REST_EPOCH, snapshot)?;
        write_blob(&path, &nonce, &ct)
    }

    /// Load a CRDT document snapshot, or `None` if not present.
    pub fn load_doc_snapshot(&self, space_id: &str, doc_id: &str) -> Result<Option<Vec<u8>>> {
        let path = self.space_dir(space_id).join(format!("{}.ydoc", safe_doc_name(doc_id)));
        if !path.exists() {
            return Ok(None);
        }
        let (nonce, ct) = read_blob(&path)?;
        Ok(Some(open(&self.at_rest_key, AT_REST_EPOCH, &nonce, &ct)?))
    }

    /// Persist the per-writer drained high-water marks (sealed).
    pub fn save_applied(&self, space_id: &str, applied: &std::collections::HashMap<String, usize>) -> Result<()> {
        let dir = self.ensure_space_dir(space_id)?;
        self.write_sealed(&dir.join("applied.json"), applied)
    }

    /// Load drained high-water marks, defaulting to empty.
    pub fn load_applied(&self, space_id: &str) -> Result<std::collections::HashMap<String, usize>> {
        let path = self.space_dir(space_id).join("applied.json");
        if !path.exists() {
            return Ok(Default::default());
        }
        self.read_sealed(&path)
    }

    /// Cache a decrypted attachment by CID (plaintext, device-local only).
    pub fn cache_attachment(&self, space_id: &str, cid: &str, bytes: &[u8]) -> Result<PathBuf> {
        let dir = self.ensure_space_dir(space_id)?.join("attachments");
        std::fs::create_dir_all(&dir)?;
        let path = dir.join(cid);
        std::fs::write(&path, bytes)?;
        Ok(path)
    }

    /// Read a cached attachment, or `None`.
    pub fn cached_attachment(&self, space_id: &str, cid: &str) -> Result<Option<Vec<u8>>> {
        let path = self.space_dir(space_id).join("attachments").join(cid);
        if !path.exists() {
            return Ok(None);
        }
        Ok(Some(std::fs::read(&path)?))
    }

    fn write_sealed<T: Serialize>(&self, path: &Path, value: &T) -> Result<()> {
        let plaintext = serde_json::to_vec(value)?;
        let (nonce, ct) = seal(&self.at_rest_key, AT_REST_EPOCH, &plaintext)?;
        write_blob(path, &nonce, &ct)
    }

    fn read_sealed<T: DeserializeOwned>(&self, path: &Path) -> Result<T> {
        let (nonce, ct) = read_blob(path)?;
        let plaintext = open(&self.at_rest_key, AT_REST_EPOCH, &nonce, &ct)?;
        Ok(serde_json::from_slice(&plaintext)?)
    }
}

/// Sealed-blob file format: `nonce (24 bytes) || ciphertext`.
fn write_blob(path: &Path, nonce: &[u8; NONCE_LEN], ct: &[u8]) -> Result<()> {
    let mut buf = Vec::with_capacity(NONCE_LEN + ct.len());
    buf.extend_from_slice(nonce);
    buf.extend_from_slice(ct);
    std::fs::write(path, &buf).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn read_blob(path: &Path) -> Result<([u8; NONCE_LEN], Vec<u8>)> {
    let buf = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    if buf.len() < NONCE_LEN {
        anyhow::bail!("sealed blob {} too short", path.display());
    }
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&buf[..NONCE_LEN]);
    Ok((nonce, buf[NONCE_LEN..].to_vec()))
}

/// Make a filesystem-safe filename from a doc id (`note:<hex>` -> `note_<hex>`).
fn safe_doc_name(doc_id: &str) -> String {
    doc_id.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::model::SpaceMeta;

    fn tmp_store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path(), &[3u8; 32]).unwrap();
        (dir, store)
    }

    fn meta() -> SpaceMeta {
        SpaceMeta {
            space_id: "deadbeef".into(),
            name: "Work".into(),
            created_at: 100,
            key_epoch: 0,
            owner: "owner".into(),
            members: vec![],
        }
    }

    #[test]
    fn meta_roundtrips_through_at_rest_seal() {
        let (_d, store) = tmp_store();
        let m = meta();
        store.save_meta(&m).unwrap();
        let back = store.load_meta("deadbeef").unwrap();
        assert_eq!(back, m);
    }

    #[test]
    fn doc_snapshot_roundtrips() {
        let (_d, store) = tmp_store();
        store.save_doc_snapshot("deadbeef", "note:abc", b"snapshot-bytes").unwrap();
        let back = store.load_doc_snapshot("deadbeef", "note:abc").unwrap();
        assert_eq!(back.as_deref(), Some(&b"snapshot-bytes"[..]));
        assert!(store.load_doc_snapshot("deadbeef", "note:missing").unwrap().is_none());
    }

    #[test]
    fn list_space_ids_finds_saved_spaces() {
        let (_d, store) = tmp_store();
        store.save_meta(&meta()).unwrap();
        assert_eq!(store.list_space_ids().unwrap(), vec!["deadbeef".to_string()]);
    }

    #[test]
    fn at_rest_file_is_not_plaintext() {
        let (dir, store) = tmp_store();
        store.save_meta(&meta()).unwrap();
        let raw = std::fs::read(dir.path().join("ce-notes/deadbeef/space.json")).unwrap();
        // The display name must not appear in the sealed bytes.
        assert!(!raw.windows(4).any(|w| w == b"Work"));
    }

    #[test]
    fn applied_marks_roundtrip() {
        let (_d, store) = tmp_store();
        let mut m = std::collections::HashMap::new();
        m.insert("peer".to_string(), 7usize);
        store.save_applied("deadbeef", &m).unwrap();
        assert_eq!(store.load_applied("deadbeef").unwrap(), m);
        assert!(store.load_applied("unseen").unwrap().is_empty());
    }
}
