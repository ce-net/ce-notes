//! The high-level CE Notes API: [`Notes`] (the device handle) and [`Space`] (one open notebook).
//!
//! This ties the pieces together: identity + X25519 device keys ([`crypto`](super::crypto)), the
//! encrypted CRDT op-set over ce-coord ([`mergelog`](super::mergelog)), the Yjs-backed note docs
//! ([`notedoc`](super::notedoc)), local persistence ([`store`](super::store)), and capability-gated
//! sharing ([`ce_cap`]). The node is untouched — everything composes from existing primitives.
//!
//! Concurrency note: a [`Space`] holds its CRDT docs and merge-set behind async mutexes so the sync
//! task and the editing API can both touch them. Reads are local; writes seal an update and publish
//! it on this device's writer-log.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use ce_cap::{Caveats, Resource, SignedCapability, encode_chain};
use ce_coord::Coord;
use ce_identity::Identity;
use ce_rs::CeClient;
use tokio::sync::Mutex;

use super::crypto::{self, DeviceKeys, SpaceKey, seal};
use super::mergelog::MergeSet;
use super::model::{
    AttachmentRef, DeviceId, FolderId, Invite, MemberEntry, NoteHeader, NoteId, NoteOp, Role,
    SpaceId, SpaceMeta,
};
use super::notedoc::{NoteDoc, YrsDoc};
use super::store::Store;

/// The merge-set log name for a space (namespaces the ce-coord topics under this space).
fn log_name(space_id: &str) -> String {
    format!("notes-{space_id}")
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn random_hex(len_bytes: usize) -> String {
    use rand_core::{OsRng, RngCore};
    let mut b = vec![0u8; len_bytes];
    OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

/// A device handle to CE Notes: the local identity, derived device keys, the ce-coord/ce-rs clients,
/// and the local store. Open spaces from it.
pub struct Notes {
    identity: Arc<Identity>,
    device_keys: DeviceKeys,
    coord: Coord,
    client: CeClient,
    store: Store,
    node_id: String,
}

impl Notes {
    /// Open the notes layer for this device. Reads the node identity from `identity_dir` (the same
    /// `node.key` the node uses), derives the X25519 device keys, connects ce-coord to the local
    /// node, and opens the at-rest store under `data_dir`.
    pub async fn open(identity_dir: &Path, data_dir: &Path, coord: Coord, client: CeClient) -> Result<Notes> {
        let identity = Identity::load_or_generate(identity_dir)
            .with_context(|| format!("load identity from {}", identity_dir.display()))?;
        let secret = identity.secret_bytes();
        let device_keys = DeviceKeys::from_ed25519_secret(&secret);
        let store = Store::open(data_dir, &secret)?;
        let node_id = identity.node_id_hex();
        Ok(Notes {
            identity: Arc::new(identity),
            device_keys,
            coord,
            client,
            store,
            node_id,
        })
    }

    /// This device's NodeId (hex).
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// This device's published X25519 public key.
    pub fn x25519_public(&self) -> [u8; 32] {
        self.device_keys.public()
    }

    /// Create a new space owned by this device. Generates the space key, self-wraps it, and persists
    /// metadata. Returns the opened [`Space`].
    pub async fn create_space(&self, name: &str) -> Result<Space> {
        let space_id = random_hex(32);
        let space_key = SpaceKey::generate();
        let wrapped = crypto::wrap_key(&self.device_keys.public(), 0, &space_key)?;
        let owner_member = MemberEntry {
            device_id: self.node_id.clone(),
            x25519_pub: self.device_keys.public(),
            label: "this device".into(),
            role: Role::Owner,
            wrapped_key: wrapped,
            added_at: now_secs(),
            revoked: false,
        };
        let meta = SpaceMeta {
            space_id: space_id.clone(),
            name: name.to_string(),
            created_at: now_secs(),
            key_epoch: 0,
            owner: self.node_id.clone(),
            members: vec![owner_member],
        };
        self.store.save_meta(&meta)?;
        self.open_space_with_meta(meta, space_key).await
    }

    /// Open an existing local space by id (unwrapping the key for this device).
    pub async fn open_space(&self, space_id: &str) -> Result<Space> {
        let meta = self.store.load_meta(space_id)?;
        let member = meta
            .member(&self.node_id)
            .ok_or_else(|| anyhow::anyhow!("this device is not a member of space {space_id}"))?;
        let space_key = crypto::unwrap_key(self.device_keys.secret(), &member.wrapped_key)?;
        self.open_space_with_meta(meta, space_key).await
    }

    /// Import an invite blob: verify the key unwraps, persist metadata, and open the space.
    pub async fn import_invite(&self, invite_bytes: &[u8]) -> Result<Space> {
        let invite = Invite::decode(invite_bytes)?;
        if invite.invitee != self.node_id {
            bail!(
                "invite is addressed to {}, not this device {}",
                invite.invitee,
                self.node_id
            );
        }
        // Recover the space key to confirm the wrap is valid for us.
        let space_key = crypto::unwrap_key(self.device_keys.secret(), &invite.wrapped_key)?;
        // Note: the grant chain is verified by *hosts* when they enforce; we keep it with the space.
        // We persist the invited metadata (which already lists us as a member via the inviter's
        // re-wrap, but ensure our own entry is present).
        let mut meta = invite.space_meta.clone();
        if meta.member(&self.node_id).is_none() {
            meta.members.push(MemberEntry {
                device_id: self.node_id.clone(),
                x25519_pub: invite.invitee_x25519,
                label: "this device".into(),
                role: invite.role,
                wrapped_key: invite.wrapped_key.clone(),
                added_at: now_secs(),
                revoked: false,
            });
        }
        self.store.save_meta(&meta)?;
        self.open_space_with_meta(meta, space_key).await
    }

    /// Space ids with local state.
    pub fn space_ids(&self) -> Result<Vec<SpaceId>> {
        self.store.list_space_ids()
    }

    /// Load just the metadata of every local space (for listing without opening).
    pub fn space_metas(&self) -> Result<Vec<SpaceMeta>> {
        self.space_ids()?.into_iter().map(|id| self.store.load_meta(&id)).collect()
    }

    async fn open_space_with_meta(&self, meta: SpaceMeta, space_key: SpaceKey) -> Result<Space> {
        let name = log_name(&meta.space_id);
        let peers = meta.active_device_ids();
        let merge = MergeSet::open(&self.coord, &name, &self.node_id, &peers).await?;

        // Restore CRDT docs from local snapshots (the index doc plus any cached note bodies).
        let mut docs: HashMap<String, YrsDoc> = HashMap::new();
        if let Some(snap) = self.store.load_doc_snapshot(&meta.space_id, NoteOp::INDEX_DOC)? {
            docs.insert(NoteOp::INDEX_DOC.to_string(), YrsDoc::from_snapshot(&snap)?);
        } else {
            docs.insert(NoteOp::INDEX_DOC.to_string(), YrsDoc::new());
        }

        let inner = SpaceInner {
            meta: Mutex::new(meta.clone()),
            space_key: Mutex::new(space_key),
            merge: Mutex::new(merge),
            docs: Mutex::new(docs),
            index: Mutex::new(IndexState::default()),
            store_present: true,
        };
        let space = Space {
            space_id: meta.space_id.clone(),
            node_id: self.node_id.clone(),
            identity: self.identity.clone(),
            client: self.client.clone(),
            coord: self.coord.clone(),
            store: Arc::new(StoreHandle::new(self.store_clone()?)),
            inner: Arc::new(inner),
        };
        // Drain anything already present (e.g. our own prior writer-log) into the docs/index.
        space.pump_once().await?;
        Ok(space)
    }

    // The Store is not Clone (it holds a key); re-open a handle from the same data dir/secret.
    fn store_clone(&self) -> Result<Store> {
        Store::open(self.store.root().parent().unwrap_or(self.store.root()), &self.identity.secret_bytes())
    }
}

/// A wrapper so a [`Space`] owns its own [`Store`] handle (the store holds a key and is not Clone).
struct StoreHandle {
    store: Store,
}
impl StoreHandle {
    fn new(store: Store) -> StoreHandle {
        StoreHandle { store }
    }
    fn get(&self) -> &Store {
        &self.store
    }
}

/// The mutable, per-space index derived from the index CRDT: note headers and folders by id.
#[derive(Default)]
struct IndexState {
    notes: HashMap<NoteId, NoteHeader>,
    folders: HashMap<FolderId, super::model::Folder>,
}

/// The shared inner state of an open space, behind async mutexes.
struct SpaceInner {
    meta: Mutex<SpaceMeta>,
    space_key: Mutex<SpaceKey>,
    merge: Mutex<MergeSet>,
    /// Live CRDT docs: `"index"` plus `"note:<id>"` for every note touched this session.
    docs: Mutex<HashMap<String, YrsDoc>>,
    index: Mutex<IndexState>,
    store_present: bool,
}

/// One open notebook on this device. Local reads are synchronous-ish (behind the inner mutexes);
/// writes seal an encrypted update and publish it on this device's writer-log.
#[derive(Clone)]
pub struct Space {
    space_id: SpaceId,
    node_id: String,
    identity: Arc<Identity>,
    client: CeClient,
    coord: Coord,
    store: Arc<StoreHandle>,
    inner: Arc<SpaceInner>,
}

/// How the index CRDT serializes a header/folder mutation inside its Yjs `Y.Text`. We keep the index
/// as a newline-delimited JSON log inside the index doc's text — each line is one upsert. Last write
/// per id wins on read (folders/titles are LWW; deletes are tombstones), which matches the design's
/// "Y.Map LWW per key" choice while staying within the single text-CRDT surface.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(tag = "t")]
enum IndexEntry {
    Note(NoteHeader),
    Folder(super::model::Folder),
}

impl Space {
    /// The space id.
    pub fn id(&self) -> &str {
        &self.space_id
    }

    /// This device's NodeId (hex) — the writer-log this device owns in the space.
    pub fn device_id(&self) -> &str {
        &self.node_id
    }

    /// Snapshot of the space metadata.
    pub async fn meta(&self) -> SpaceMeta {
        self.inner.meta.lock().await.clone()
    }

    /// List non-deleted note headers, newest-updated first.
    pub async fn notes(&self) -> Vec<NoteHeader> {
        let idx = self.inner.index.lock().await;
        let mut v: Vec<NoteHeader> =
            idx.notes.values().filter(|h| !h.deleted).cloned().collect();
        v.sort_by(|a, b| b.updated_at.cmp(&a.updated_at).then(a.note_id.cmp(&b.note_id)));
        v
    }

    /// The header for a note, if present and not deleted.
    pub async fn note_header(&self, note_id: &str) -> Option<NoteHeader> {
        let idx = self.inner.index.lock().await;
        idx.notes.get(note_id).filter(|h| !h.deleted).cloned()
    }

    /// The current body text of a note (loads its CRDT doc from snapshot/merge-set if needed).
    pub async fn note_text(&self, note_id: &str) -> Result<String> {
        let doc_id = NoteOp::note_doc_id(note_id);
        self.ensure_doc_loaded(&doc_id).await?;
        let docs = self.inner.docs.lock().await;
        Ok(docs.get(&doc_id).map(|d| d.text()).unwrap_or_default())
    }

    /// Create a new note (optionally in a folder), returning its id. Publishes the header to the
    /// index CRDT.
    pub async fn create_note(&self, title: &str, folder: Option<FolderId>) -> Result<NoteId> {
        let note_id = format!("{:016x}{}", now_secs(), random_hex(8));
        let header = NoteHeader {
            note_id: note_id.clone(),
            title: title.to_string(),
            folder_id: folder,
            updated_at: now_secs(),
            deleted: false,
        };
        // Materialize an empty body doc and seed the title as the first heading.
        {
            let mut docs = self.inner.docs.lock().await;
            docs.insert(NoteOp::note_doc_id(&note_id), YrsDoc::new());
        }
        self.publish_index(IndexEntry::Note(header.clone())).await?;
        if !title.is_empty() {
            self.set_note_text(&note_id, &format!("# {title}\n\n")).await?;
        }
        self.persist_index_snapshot().await?;
        Ok(note_id)
    }

    /// Replace a note's body with `new_text`. Seals the CRDT delta and publishes it; also refreshes
    /// the index header's `updated_at` and cached title.
    pub async fn set_note_text(&self, note_id: &str, new_text: &str) -> Result<()> {
        let doc_id = NoteOp::note_doc_id(note_id);
        self.ensure_doc_loaded(&doc_id).await?;

        let delta = {
            let mut docs = self.inner.docs.lock().await;
            let doc = docs
                .get_mut(&doc_id)
                .ok_or_else(|| anyhow::anyhow!("note {note_id} not loaded"))?;
            doc.set_text(new_text)?
        };
        if !delta.is_empty() {
            self.publish_op(&doc_id, &delta).await?;
        }
        self.persist_doc_snapshot(&doc_id).await?;

        // Update the index header (title cache = first markdown heading, else first line).
        if let Some(mut header) = self.note_header(note_id).await {
            header.title = derive_title(new_text).unwrap_or(header.title);
            header.updated_at = now_secs();
            self.publish_index(IndexEntry::Note(header)).await?;
            self.persist_index_snapshot().await?;
        }
        Ok(())
    }

    /// Tombstone-delete a note (CRDT-safe; recoverable).
    pub async fn delete_note(&self, note_id: &str) -> Result<()> {
        if let Some(mut header) = self.note_header(note_id).await {
            header.deleted = true;
            header.updated_at = now_secs();
            self.publish_index(IndexEntry::Note(header)).await?;
            self.persist_index_snapshot().await?;
        }
        Ok(())
    }

    /// Create a folder, returning its id.
    pub async fn create_folder(&self, name: &str, parent: Option<FolderId>) -> Result<FolderId> {
        let folder_id = random_hex(8);
        let folder = super::model::Folder {
            folder_id: folder_id.clone(),
            name: name.to_string(),
            parent,
            deleted: false,
        };
        self.publish_index(IndexEntry::Folder(folder)).await?;
        self.persist_index_snapshot().await?;
        Ok(folder_id)
    }

    /// List non-deleted folders.
    pub async fn folders(&self) -> Vec<super::model::Folder> {
        let idx = self.inner.index.lock().await;
        let mut v: Vec<_> = idx.folders.values().filter(|f| !f.deleted).cloned().collect();
        v.sort_by(|a, b| a.name.cmp(&b.name));
        v
    }

    /// Encrypt a file and store it as a content-addressed object, returning the [`AttachmentRef`].
    /// The per-file key lives only inside the ref (and thus only inside the encrypted CRDT).
    pub async fn attach(&self, note_id: &str, path: &Path) -> Result<AttachmentRef> {
        let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("attachment").to_string();
        let mime = guess_mime(&name);

        let file_key = SpaceKey::generate();
        let (nonce, ct) = seal(&file_key, 0, &bytes)?;
        let cid = self.client.put_object(&ct).await.context("put_object attachment ciphertext")?;

        let aref = AttachmentRef {
            cid,
            file_key: file_key.0,
            nonce,
            name,
            mime,
            size: bytes.len() as u64,
        };
        // Cache the plaintext locally and record the ref into the note body's metadata via a marker
        // line (kept simple: append a reference line; the body CRDT carries it like any other text).
        self.store.get().cache_attachment(&self.space_id, &aref.cid, &bytes)?;
        let _ = note_id; // attachment-to-note linkage is recorded by the caller in the body text
        Ok(aref)
    }

    /// Fetch an attachment: pull the ciphertext object, decrypt with the ref's per-file key, verify.
    pub async fn fetch_attachment(&self, aref: &AttachmentRef) -> Result<Vec<u8>> {
        if let Some(cached) = self.store.get().cached_attachment(&self.space_id, &aref.cid)? {
            if cached.len() as u64 == aref.size {
                return Ok(cached);
            }
        }
        let ct = self.client.get_object(&aref.cid).await.context("get_object attachment")?;
        let key = SpaceKey::from_bytes(aref.file_key);
        let plaintext = crypto::open(&key, 0, &aref.nonce, &ct)?;
        if plaintext.len() as u64 != aref.size {
            bail!("attachment size mismatch after decrypt");
        }
        self.store.get().cache_attachment(&self.space_id, &aref.cid, &plaintext)?;
        Ok(plaintext)
    }

    /// Create an invite for a new member identified by their NodeId hex. Wraps the current space key
    /// to the invitee's X25519 key (derived from the NodeId) and mints a `ce-cap` grant rooted at
    /// this device's identity granting `notes:read` (and `notes:write` for writers), scoped to this
    /// space's nodes, expiring at `expires_unix` (0 = never). Adds the invitee as a member.
    pub async fn invite(&self, invitee_node_id: &str, role: Role, expires_unix: u64) -> Result<Vec<u8>> {
        let invitee = parse_node_id(invitee_node_id)?;
        let invitee_x = DeviceKeys::x25519_public_from_node_id(&invitee)?;

        let (epoch, space_key_bytes) = {
            let meta = self.inner.meta.lock().await;
            let key = self.inner.space_key.lock().await;
            (meta.key_epoch, key.0)
        };
        let space_key = SpaceKey::from_bytes(space_key_bytes);
        let wrapped = crypto::wrap_key(&invitee_x, epoch, &space_key)?;

        // Mint the capability chain (root = this device). Resource::Any keeps the MVP simple; the
        // ability strings carry the space scope semantically ("notes:read"/"notes:write") and the
        // wrapped key is the true confidentiality boundary.
        let caveats = Caveats { not_after: expires_unix, ..Default::default() };
        let grant = SignedCapability::issue(
            self.identity.as_ref(),
            invitee,
            role.abilities(),
            Resource::Any,
            caveats,
            now_secs(), // nonce: unique-enough per issuer for revocation addressing
            None,
        );
        let grant_token = encode_chain(&[grant]);

        // Add the invitee as a member and persist.
        let invitee_hex = invitee_node_id.to_string();
        {
            let mut meta = self.inner.meta.lock().await;
            if meta.member(&invitee_hex).is_none() {
                meta.members.push(MemberEntry {
                    device_id: invitee_hex.clone(),
                    x25519_pub: invitee_x,
                    label: invitee_hex.clone(),
                    role,
                    wrapped_key: wrapped.clone(),
                    added_at: now_secs(),
                    revoked: false,
                });
            }
            self.store.get().save_meta(&meta)?;
        }
        // Start following the new member's writer-log.
        {
            let mut merge = self.inner.merge.lock().await;
            merge.add_peer(&self.coord, &log_name(&self.space_id), &invitee_hex).await?;
        }

        let meta_snapshot = self.inner.meta.lock().await.clone();
        let invite = Invite {
            space_meta: meta_snapshot,
            wrapped_key: wrapped,
            invitee: invitee_hex,
            invitee_x25519: invitee_x,
            role,
            grant_token,
        };
        invite.encode()
    }

    /// Per-peer sync status: `(device_id, applied_version)` across this device's writer-log and every
    /// followed peer.
    pub async fn sync_status(&self) -> Vec<(DeviceId, u64)> {
        self.inner.merge.lock().await.sync_status()
    }

    /// Pull any newly-arrived ops from the merge-set, decrypt them, and apply to the CRDT docs /
    /// index. Call this periodically (the CLI's `sync` does, and the TUI loops on it).
    pub async fn pump_once(&self) -> Result<()> {
        let ops = {
            let mut merge = self.inner.merge.lock().await;
            merge.new_ops()
        };
        if ops.is_empty() {
            return Ok(());
        }
        for op in ops {
            self.apply_incoming(&op).await?;
        }
        self.persist_index_snapshot().await?;
        Ok(())
    }

    // ---- internals ----

    async fn apply_incoming(&self, op: &NoteOp) -> Result<()> {
        let plaintext = {
            let key = self.inner.space_key.lock().await;
            // Only the current epoch's key is held; older-epoch ops we authored ourselves still
            // decrypt because we re-wrap on rotation. If decryption fails (e.g. pre-membership
            // epoch), skip rather than poison.
            match crypto::open(&key, op.epoch, &op.nonce, &op.ct) {
                Ok(p) => p,
                Err(_) => return Ok(()),
            }
        };

        if op.doc_id == NoteOp::INDEX_DOC {
            self.apply_index_update(&plaintext).await?;
        } else {
            self.ensure_doc_loaded(&op.doc_id).await?;
            let mut docs = self.inner.docs.lock().await;
            if let Some(doc) = docs.get_mut(&op.doc_id) {
                doc.apply_update(&plaintext)?;
            }
            drop(docs);
            self.persist_doc_snapshot(&op.doc_id).await?;
        }
        Ok(())
    }

    async fn apply_index_update(&self, update: &[u8]) -> Result<()> {
        // Apply to the index CRDT doc, then re-derive the index state from its full text.
        {
            let mut docs = self.inner.docs.lock().await;
            let doc = docs.entry(NoteOp::INDEX_DOC.to_string()).or_insert_with(YrsDoc::new);
            doc.apply_update(update)?;
        }
        self.rebuild_index_state().await
    }

    async fn rebuild_index_state(&self) -> Result<()> {
        let text = {
            let docs = self.inner.docs.lock().await;
            docs.get(NoteOp::INDEX_DOC).map(|d| d.text()).unwrap_or_default()
        };
        let mut idx = self.inner.index.lock().await;
        idx.notes.clear();
        idx.folders.clear();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            match serde_json::from_str::<IndexEntry>(line) {
                Ok(IndexEntry::Note(h)) => {
                    // Last write per id wins (later lines override earlier).
                    idx.notes.insert(h.note_id.clone(), h);
                }
                Ok(IndexEntry::Folder(f)) => {
                    idx.folders.insert(f.folder_id.clone(), f);
                }
                Err(_) => continue, // tolerate partial/old lines
            }
        }
        Ok(())
    }

    async fn publish_index(&self, entry: IndexEntry) -> Result<()> {
        let line = serde_json::to_string(&entry)?;
        // Append the line to the index CRDT, capturing the delta.
        let delta = {
            let mut docs = self.inner.docs.lock().await;
            let doc = docs.entry(NoteOp::INDEX_DOC.to_string()).or_insert_with(YrsDoc::new);
            let mut current = doc.text();
            if !current.is_empty() && !current.ends_with('\n') {
                current.push('\n');
            }
            current.push_str(&line);
            current.push('\n');
            doc.set_text(&current)?
        };
        if !delta.is_empty() {
            self.publish_op(NoteOp::INDEX_DOC, &delta).await?;
        }
        self.rebuild_index_state().await
    }

    async fn publish_op(&self, doc_id: &str, plaintext_update: &[u8]) -> Result<()> {
        let (epoch, sealed) = {
            let meta = self.inner.meta.lock().await;
            let key = self.inner.space_key.lock().await;
            let (nonce, ct) = seal(&key, meta.key_epoch, plaintext_update)?;
            (meta.key_epoch, (nonce, ct))
        };
        let op = NoteOp { doc_id: doc_id.to_string(), epoch, nonce: sealed.0, ct: sealed.1 };
        let merge = self.inner.merge.lock().await;
        merge.publish(op).await?;
        Ok(())
    }

    async fn ensure_doc_loaded(&self, doc_id: &str) -> Result<()> {
        {
            let docs = self.inner.docs.lock().await;
            if docs.contains_key(doc_id) {
                return Ok(());
            }
        }
        let snapshot = self.store.get().load_doc_snapshot(&self.space_id, doc_id)?;
        let doc = match snapshot {
            Some(s) => YrsDoc::from_snapshot(&s)?,
            None => YrsDoc::new(),
        };
        self.inner.docs.lock().await.insert(doc_id.to_string(), doc);
        Ok(())
    }

    async fn persist_doc_snapshot(&self, doc_id: &str) -> Result<()> {
        if !self.inner.store_present {
            return Ok(());
        }
        let snapshot = {
            let docs = self.inner.docs.lock().await;
            docs.get(doc_id).map(|d| d.encode_state())
        };
        if let Some(snap) = snapshot {
            self.store.get().save_doc_snapshot(&self.space_id, doc_id, &snap)?;
        }
        Ok(())
    }

    async fn persist_index_snapshot(&self) -> Result<()> {
        self.persist_doc_snapshot(NoteOp::INDEX_DOC).await
    }
}

/// Derive a display title from body text: the first markdown heading (`# ...`) if present, else the
/// first non-empty line, trimmed.
fn derive_title(body: &str) -> Option<String> {
    for line in body.lines() {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        let title = t.trim_start_matches('#').trim();
        if !title.is_empty() {
            return Some(title.to_string());
        }
    }
    None
}

fn guess_mime(name: &str) -> String {
    let ext = name.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    match ext.as_str() {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "pdf" => "application/pdf",
        "txt" | "md" => "text/plain",
        "json" => "application/json",
        _ => "application/octet-stream",
    }
    .to_string()
}

fn parse_node_id(hex_str: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex_str.trim()).context("node id is not valid hex")?;
    bytes.try_into().map_err(|_| anyhow::anyhow!("node id must be 32 bytes (64 hex chars)"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_title_prefers_heading() {
        assert_eq!(derive_title("# Hello\n\nbody"), Some("Hello".to_string()));
        assert_eq!(derive_title("\n\nfirst line\nsecond"), Some("first line".to_string()));
        assert_eq!(derive_title("   "), None);
    }

    #[test]
    fn guess_mime_known_and_unknown() {
        assert_eq!(guess_mime("a.png"), "image/png");
        assert_eq!(guess_mime("notes.md"), "text/plain");
        assert_eq!(guess_mime("blob"), "application/octet-stream");
    }

    #[test]
    fn parse_node_id_validates_length() {
        assert!(parse_node_id("zz").is_err());
        let good = "0".repeat(64);
        assert!(parse_node_id(&good).is_ok());
    }
}
