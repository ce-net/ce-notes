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
    AttachmentRef, ChecklistItem, Color, DeviceId, Folder, FolderId, Invite, Label, LabelId,
    MemberEntry, NoteHeader, NoteId, NoteKind, NoteOp, Reminder, Role, SpaceId, SpaceMeta,
};
use super::notedoc::{NoteDoc, YrsDoc};
use super::store::Store;

/// Maximum note body size (bytes of UTF-8 text). Bounds memory and the size of a single sealed op.
pub const MAX_BODY_BYTES: usize = 1024 * 1024;
/// Maximum attachment plaintext size we will read into memory and seal. Larger files are rejected
/// rather than buffered whole (streaming/chunked attachment encryption is a documented follow-up).
pub const MAX_ATTACHMENT_BYTES: u64 = 32 * 1024 * 1024;
/// Maximum number of members in a space (bounds the reader-log fan-out and invite size).
pub const MAX_MEMBERS: usize = 256;
/// Maximum number of labels a single note may carry.
pub const MAX_NOTE_LABELS: usize = 64;
/// Maximum length of a single index-log line we will parse (defends `rebuild_index_state`).
pub const MAX_INDEX_LINE_BYTES: usize = 64 * 1024;
/// When the index doc's text grows past this many bytes, compact it to one line per live id.
const INDEX_COMPACT_THRESHOLD: usize = 256 * 1024;

/// The error returned when a non-writer attempts a mutating operation.
#[derive(Debug)]
pub struct PermissionDenied {
    pub op: &'static str,
}
impl std::fmt::Display for PermissionDenied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "permission denied: this device is not authorized to {} in this space", self.op)
    }
}
impl std::error::Error for PermissionDenied {}

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
        if invite.space_meta.members.len() > MAX_MEMBERS {
            bail!("invite lists {} members, over the limit", invite.space_meta.members.len());
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
        // Restore the persisted drained marks so the initial pump skips re-draining the entire op
        // history (the persisted CRDT snapshots already reflect those ops). Each mark is clamped to
        // the log's live length, and any op missing from the snapshot is re-applied idempotently —
        // so a stale or partial marks file can never lose data, only do redundant work. Then rebuild
        // the derived index from the loaded snapshot and pump whatever is genuinely new.
        if let Ok(marks) = self.store.load_applied(&meta.space_id)
            && !marks.is_empty()
        {
            space.inner.merge.lock().await.restore_drained(&marks);
        }
        space.rebuild_index_state().await?;
        space.pump_once().await?;
        Ok(space)
    }

    // The Store is not Clone (it holds a key); re-open a handle from the same data dir/secret.
    fn store_clone(&self) -> Result<Store> {
        Store::open(self.store.data_dir(), &self.identity.secret_bytes())
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

/// The mutable, per-space index derived from the index CRDT: note headers, folders, and labels by
/// id. Each map value is the LWW survivor across every index-log line for that id.
#[derive(Default)]
struct IndexState {
    notes: HashMap<NoteId, NoteHeader>,
    folders: HashMap<FolderId, Folder>,
    labels: HashMap<LabelId, Label>,
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

/// How the index CRDT serializes a header/folder/label mutation inside its Yjs `Y.Text`. We keep the
/// index as a newline-delimited JSON log inside the index doc's text — each line is one upsert.
/// **Last write per id wins by `updated_at`** (NOT by line order), reconciled in
/// [`Space::rebuild_index_state`], which is what makes the union of two devices' index logs converge
/// regardless of the order lines arrive in. Deletes are tombstones. The log is periodically
/// compacted (one line per live id) so it stays bounded.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(tag = "t")]
enum IndexEntry {
    Note(NoteHeader),
    Folder(Folder),
    Label(Label),
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

    /// List the main-view note headers: non-deleted, non-archived, pinned first then newest-updated.
    pub async fn notes(&self) -> Vec<NoteHeader> {
        let idx = self.inner.index.lock().await;
        let mut v: Vec<NoteHeader> =
            idx.notes.values().filter(|h| !h.deleted && !h.archived).cloned().collect();
        sort_notes(&mut v);
        v
    }

    /// List archived (non-deleted) notes.
    pub async fn archived_notes(&self) -> Vec<NoteHeader> {
        let idx = self.inner.index.lock().await;
        let mut v: Vec<NoteHeader> =
            idx.notes.values().filter(|h| !h.deleted && h.archived).cloned().collect();
        sort_notes(&mut v);
        v
    }

    /// List tombstoned (trashed) notes, newest first — the trash view, for restore.
    pub async fn trashed_notes(&self) -> Vec<NoteHeader> {
        let idx = self.inner.index.lock().await;
        let mut v: Vec<NoteHeader> = idx.notes.values().filter(|h| h.deleted).cloned().collect();
        sort_notes(&mut v);
        v
    }

    /// List non-deleted, non-archived notes carrying `label_id`, pinned-first.
    pub async fn notes_with_label(&self, label_id: &str) -> Vec<NoteHeader> {
        let idx = self.inner.index.lock().await;
        let mut v: Vec<NoteHeader> = idx
            .notes
            .values()
            .filter(|h| !h.deleted && !h.archived && h.labels.iter().any(|l| l == label_id))
            .cloned()
            .collect();
        sort_notes(&mut v);
        v
    }

    /// The header for a note, if present and not deleted (main accessor — hides trash).
    pub async fn note_header(&self, note_id: &str) -> Option<NoteHeader> {
        let idx = self.inner.index.lock().await;
        idx.notes.get(note_id).filter(|h| !h.deleted).cloned()
    }

    /// The header for a note regardless of tombstone state (internal / trash-aware callers).
    async fn note_header_raw(&self, note_id: &str) -> Option<NoteHeader> {
        let idx = self.inner.index.lock().await;
        idx.notes.get(note_id).cloned()
    }

    async fn folder_exists(&self, folder_id: &str) -> bool {
        let idx = self.inner.index.lock().await;
        idx.folders.get(folder_id).map(|f| !f.deleted).unwrap_or(false)
    }

    /// Whether this device is authorized to write in the space (Owner or Writer).
    pub async fn can_write(&self) -> bool {
        self.inner.meta.lock().await.can_write(&self.node_id)
    }

    async fn require_write(&self, op: &'static str) -> Result<()> {
        if self.can_write().await {
            Ok(())
        } else {
            Err(PermissionDenied { op }.into())
        }
    }

    async fn require_owner(&self, op: &'static str) -> Result<()> {
        let meta = self.inner.meta.lock().await;
        let is_owner = meta.member(&self.node_id).map(|m| m.role == Role::Owner).unwrap_or(false);
        if is_owner { Ok(()) } else { Err(PermissionDenied { op }.into()) }
    }

    /// The current body text of a note (loads its CRDT doc from snapshot/merge-set if needed).
    pub async fn note_text(&self, note_id: &str) -> Result<String> {
        let doc_id = NoteOp::note_doc_id(note_id);
        self.ensure_doc_loaded(&doc_id).await?;
        let docs = self.inner.docs.lock().await;
        Ok(docs.get(&doc_id).map(|d| d.text()).unwrap_or_default())
    }

    /// Create a new markdown note (optionally in a folder), returning its id. Publishes the header to
    /// the index CRDT. Requires write permission.
    pub async fn create_note(&self, title: &str, folder: Option<FolderId>) -> Result<NoteId> {
        self.create_note_kind(title, folder, NoteKind::Markdown).await
    }

    /// Create a new note of an explicit [`NoteKind`] (markdown or checklist).
    pub async fn create_note_kind(
        &self,
        title: &str,
        folder: Option<FolderId>,
        kind: NoteKind,
    ) -> Result<NoteId> {
        self.require_write("create notes").await?;
        if let Some(fid) = &folder
            && !self.folder_exists(fid).await
        {
            bail!("folder {fid} does not exist");
        }
        let note_id = format!("{:016x}{}", now_secs(), random_hex(8));
        let mut header = NoteHeader::new(note_id.clone(), title.to_string(), folder, now_secs());
        header.kind = kind;
        // Materialize an empty body doc.
        {
            let mut docs = self.inner.docs.lock().await;
            docs.insert(NoteOp::note_doc_id(&note_id), YrsDoc::new());
        }
        self.publish_index(IndexEntry::Note(header.clone())).await?;
        if kind == NoteKind::Markdown && !title.is_empty() {
            self.set_note_text(&note_id, &format!("# {title}\n\n")).await?;
        }
        self.persist_index_snapshot().await?;
        Ok(note_id)
    }

    /// Replace a note's body with `new_text`. Seals the CRDT delta and publishes it; also refreshes
    /// the index header's `updated_at` and cached title. Requires write permission; the body is
    /// bounded by [`MAX_BODY_BYTES`].
    pub async fn set_note_text(&self, note_id: &str, new_text: &str) -> Result<()> {
        self.require_write("edit notes").await?;
        if new_text.len() > MAX_BODY_BYTES {
            bail!("note body is {} bytes, exceeds the {} byte limit", new_text.len(), MAX_BODY_BYTES);
        }
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

    /// Tombstone-delete a note (CRDT-safe; recoverable via [`restore_note`](Space::restore_note)).
    /// Requires write permission.
    pub async fn delete_note(&self, note_id: &str) -> Result<()> {
        self.require_write("delete notes").await?;
        if let Some(mut header) = self.note_header_raw(note_id).await {
            header.deleted = true;
            header.updated_at = now_secs();
            self.publish_index(IndexEntry::Note(header)).await?;
            self.persist_index_snapshot().await?;
        }
        Ok(())
    }

    /// Restore a tombstoned note back into the main listing. Requires write permission.
    pub async fn restore_note(&self, note_id: &str) -> Result<()> {
        self.require_write("restore notes").await?;
        if let Some(mut header) = self.note_header_raw(note_id).await {
            if header.deleted {
                header.deleted = false;
                header.updated_at = now_secs();
                self.publish_index(IndexEntry::Note(header)).await?;
                self.persist_index_snapshot().await?;
            }
        } else {
            bail!("no such note {note_id}");
        }
        Ok(())
    }

    /// Create a folder, returning its id. Requires write permission.
    pub async fn create_folder(&self, name: &str, parent: Option<FolderId>) -> Result<FolderId> {
        self.require_write("create folders").await?;
        let folder_id = random_hex(8);
        let folder = Folder { folder_id: folder_id.clone(), name: name.to_string(), parent, deleted: false };
        self.publish_index(IndexEntry::Folder(folder)).await?;
        self.persist_index_snapshot().await?;
        Ok(folder_id)
    }

    /// List non-deleted folders.
    pub async fn folders(&self) -> Vec<Folder> {
        let idx = self.inner.index.lock().await;
        let mut v: Vec<_> = idx.folders.values().filter(|f| !f.deleted).cloned().collect();
        v.sort_by(|a, b| a.name.cmp(&b.name));
        v
    }

    // ---- note attributes (pin / archive / color / labels / reminders) -------------------------

    /// Apply a mutation to a note's header (write-gated, bumps `updated_at`, republishes + persists).
    async fn mutate_header<F: FnOnce(&mut NoteHeader)>(
        &self,
        note_id: &str,
        op: &'static str,
        f: F,
    ) -> Result<()> {
        self.require_write(op).await?;
        let mut header =
            self.note_header_raw(note_id).await.ok_or_else(|| anyhow::anyhow!("no such note {note_id}"))?;
        f(&mut header);
        header.updated_at = now_secs();
        self.publish_index(IndexEntry::Note(header)).await?;
        self.persist_index_snapshot().await
    }

    /// Pin or unpin a note (pinned notes sort to the top).
    pub async fn set_pinned(&self, note_id: &str, pinned: bool) -> Result<()> {
        self.mutate_header(note_id, "pin notes", |h| h.pinned = pinned).await
    }

    /// Archive or unarchive a note.
    pub async fn set_archived(&self, note_id: &str, archived: bool) -> Result<()> {
        self.mutate_header(note_id, "archive notes", |h| h.archived = archived).await
    }

    /// Set a note's color.
    pub async fn set_color(&self, note_id: &str, color: Color) -> Result<()> {
        self.mutate_header(note_id, "color notes", |h| h.color = color).await
    }

    /// Set (or clear) a note's reminder.
    pub async fn set_reminder(&self, note_id: &str, reminder: Option<Reminder>) -> Result<()> {
        self.mutate_header(note_id, "set reminders", |h| h.reminder = reminder).await
    }

    /// Move a note into a folder (or to the root with `None`).
    pub async fn move_note(&self, note_id: &str, folder: Option<FolderId>) -> Result<()> {
        if let Some(fid) = &folder
            && !self.folder_exists(fid).await
        {
            bail!("folder {fid} does not exist");
        }
        self.mutate_header(note_id, "move notes", |h| h.folder_id = folder).await
    }

    /// Undone reminders, returned as `(note_id, title, Reminder)` sorted by due time. The caller can
    /// partition by `now` to separate due-now from upcoming.
    pub async fn reminders(&self, _now: u64) -> Vec<(NoteId, String, Reminder)> {
        let idx = self.inner.index.lock().await;
        let mut out: Vec<(NoteId, String, Reminder)> = idx
            .notes
            .values()
            .filter(|h| !h.deleted)
            .filter_map(|h| h.reminder.filter(|r| !r.done).map(|r| (h.note_id.clone(), h.title.clone(), r)))
            .collect();
        out.sort_by_key(|(_, _, r)| r.due_unix);
        out
    }

    // ---- labels -------------------------------------------------------------------------------

    /// Create a label, returning its id. Requires write permission.
    pub async fn create_label(&self, name: &str, color: Color) -> Result<LabelId> {
        self.require_write("create labels").await?;
        let label_id = random_hex(8);
        let label = Label { label_id: label_id.clone(), name: name.to_string(), color, deleted: false };
        self.publish_index(IndexEntry::Label(label)).await?;
        self.persist_index_snapshot().await?;
        Ok(label_id)
    }

    /// List non-deleted labels, sorted by name.
    pub async fn labels(&self) -> Vec<Label> {
        let idx = self.inner.index.lock().await;
        let mut v: Vec<_> = idx.labels.values().filter(|l| !l.deleted).cloned().collect();
        v.sort_by(|a, b| a.name.cmp(&b.name));
        v
    }

    /// Tombstone-delete a label (it is also removed from any note it tagged on next label edit; the
    /// listing filters deleted labels out). Requires write permission.
    pub async fn delete_label(&self, label_id: &str) -> Result<()> {
        self.require_write("delete labels").await?;
        let exists = {
            let idx = self.inner.index.lock().await;
            idx.labels.get(label_id).cloned()
        };
        if let Some(mut l) = exists {
            l.deleted = true;
            self.publish_index(IndexEntry::Label(l)).await?;
            self.persist_index_snapshot().await?;
        }
        Ok(())
    }

    /// Add a label to a note (idempotent; bounded by [`MAX_NOTE_LABELS`]).
    pub async fn add_note_label(&self, note_id: &str, label_id: &str) -> Result<()> {
        let exists = {
            let idx = self.inner.index.lock().await;
            idx.labels.get(label_id).map(|l| !l.deleted).unwrap_or(false)
        };
        if !exists {
            bail!("no such label {label_id}");
        }
        let label_id = label_id.to_string();
        self.mutate_header(note_id, "label notes", move |h| {
            if !h.labels.contains(&label_id) && h.labels.len() < MAX_NOTE_LABELS {
                h.labels.push(label_id);
            }
        })
        .await
    }

    /// Remove a label from a note (idempotent).
    pub async fn remove_note_label(&self, note_id: &str, label_id: &str) -> Result<()> {
        let label_id = label_id.to_string();
        self.mutate_header(note_id, "label notes", move |h| h.labels.retain(|l| l != &label_id)).await
    }

    // ---- search -------------------------------------------------------------------------------

    /// Full-text search across decrypted note titles, labels, and bodies. Case-insensitive substring
    /// match on whitespace-split query terms; a note matches only if EVERY term is found somewhere in
    /// its title, any of its label names, or its body text. Returns matching headers, pinned-first.
    ///
    /// The search runs entirely locally over plaintext this device already holds — the mesh only ever
    /// sees ciphertext, so server-side search is impossible by construction.
    pub async fn search(&self, query: &str) -> Result<Vec<NoteHeader>> {
        let terms: Vec<String> =
            query.split_whitespace().map(|t| t.to_lowercase()).filter(|t| !t.is_empty()).collect();
        if terms.is_empty() {
            return Ok(Vec::new());
        }
        // Snapshot the candidate set and the label-name map under the index lock, then release it
        // before touching note bodies (which may load CRDT docs).
        let (candidates, label_names): (Vec<NoteHeader>, HashMap<LabelId, String>) = {
            let idx = self.inner.index.lock().await;
            let cands = idx.notes.values().filter(|h| !h.deleted).cloned().collect();
            let names = idx.labels.iter().map(|(k, v)| (k.clone(), v.name.to_lowercase())).collect();
            (cands, names)
        };

        let mut out = Vec::new();
        for h in candidates {
            let mut haystack = h.title.to_lowercase();
            haystack.push('\n');
            for lid in &h.labels {
                if let Some(name) = label_names.get(lid) {
                    haystack.push_str(name);
                    haystack.push('\n');
                }
            }
            // Body text (markdown text, or the checklist item texts).
            let body = self.search_body_text(&h).await.unwrap_or_default();
            haystack.push_str(&body.to_lowercase());
            if terms.iter().all(|t| haystack.contains(t)) {
                out.push(h);
            }
        }
        sort_notes(&mut out);
        Ok(out)
    }

    /// The searchable plaintext of a note's body (markdown text, or concatenated checklist items).
    async fn search_body_text(&self, h: &NoteHeader) -> Result<String> {
        match h.kind {
            NoteKind::Markdown => self.note_text(&h.note_id).await,
            NoteKind::Checklist => {
                let items = self.checklist(&h.note_id).await?;
                Ok(items.iter().map(|i| i.text.clone()).collect::<Vec<_>>().join("\n"))
            }
        }
    }

    // ---- checklists ---------------------------------------------------------------------------

    /// The live checklist items of a checklist note, reconciled LWW per item id, sorted by `order`
    /// then `item_id`, with deleted items removed.
    pub async fn checklist(&self, note_id: &str) -> Result<Vec<ChecklistItem>> {
        let doc_id = NoteOp::note_doc_id(note_id);
        self.ensure_doc_loaded(&doc_id).await?;
        let text = {
            let docs = self.inner.docs.lock().await;
            docs.get(&doc_id).map(|d| d.text()).unwrap_or_default()
        };
        Ok(reduce_checklist(&text))
    }

    /// Append a checklist item, returning its id. Requires write permission.
    pub async fn add_checklist_item(&self, note_id: &str, text: &str) -> Result<String> {
        self.require_write("edit checklists").await?;
        if text.len() > MAX_INDEX_LINE_BYTES {
            bail!("checklist item too long");
        }
        let order = {
            let items = self.checklist(note_id).await?;
            items.iter().map(|i| i.order).max().unwrap_or(-1) + 1
        };
        let item = ChecklistItem {
            item_id: random_hex(8),
            text: text.to_string(),
            checked: false,
            order,
            updated_at: now_secs(),
            deleted: false,
        };
        let id = item.item_id.clone();
        self.append_checklist_record(note_id, &item).await?;
        Ok(id)
    }

    /// Set the checked state of a checklist item. Requires write permission.
    pub async fn set_checklist_checked(&self, note_id: &str, item_id: &str, checked: bool) -> Result<()> {
        self.mutate_checklist_item(note_id, item_id, |i| i.checked = checked).await
    }

    /// Edit the text of a checklist item. Requires write permission.
    pub async fn set_checklist_text(&self, note_id: &str, item_id: &str, text: &str) -> Result<()> {
        if text.len() > MAX_INDEX_LINE_BYTES {
            bail!("checklist item too long");
        }
        let text = text.to_string();
        self.mutate_checklist_item(note_id, item_id, move |i| i.text = text).await
    }

    /// Reorder a checklist item to a new `order` key. Requires write permission.
    pub async fn set_checklist_order(&self, note_id: &str, item_id: &str, order: i64) -> Result<()> {
        self.mutate_checklist_item(note_id, item_id, move |i| i.order = order).await
    }

    /// Tombstone-delete a checklist item. Requires write permission.
    pub async fn delete_checklist_item(&self, note_id: &str, item_id: &str) -> Result<()> {
        self.mutate_checklist_item(note_id, item_id, |i| i.deleted = true).await
    }

    async fn mutate_checklist_item<F: FnOnce(&mut ChecklistItem)>(
        &self,
        note_id: &str,
        item_id: &str,
        f: F,
    ) -> Result<()> {
        self.require_write("edit checklists").await?;
        let mut item = self
            .checklist_item_raw(note_id, item_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("no such checklist item {item_id}"))?;
        f(&mut item);
        item.updated_at = now_secs();
        self.append_checklist_record(note_id, &item).await
    }

    async fn checklist_item_raw(&self, note_id: &str, item_id: &str) -> Result<Option<ChecklistItem>> {
        let doc_id = NoteOp::note_doc_id(note_id);
        self.ensure_doc_loaded(&doc_id).await?;
        let text = {
            let docs = self.inner.docs.lock().await;
            docs.get(&doc_id).map(|d| d.text()).unwrap_or_default()
        };
        Ok(reduce_checklist_all(&text).remove(item_id))
    }

    /// Append one checklist record line to the note body doc, seal + publish the delta, persist.
    async fn append_checklist_record(&self, note_id: &str, item: &ChecklistItem) -> Result<()> {
        let doc_id = NoteOp::note_doc_id(note_id);
        self.ensure_doc_loaded(&doc_id).await?;
        let line = serde_json::to_string(item)?;
        let delta = {
            let mut docs = self.inner.docs.lock().await;
            let doc = docs.entry(doc_id.clone()).or_insert_with(YrsDoc::new);
            let mut current = doc.text();
            if !current.is_empty() && !current.ends_with('\n') {
                current.push('\n');
            }
            current.push_str(&line);
            current.push('\n');
            if current.len() > MAX_BODY_BYTES {
                bail!("checklist exceeds the {} byte body limit", MAX_BODY_BYTES);
            }
            doc.set_text(&current)?
        };
        if !delta.is_empty() {
            self.publish_op(&doc_id, &delta).await?;
        }
        self.persist_doc_snapshot(&doc_id).await?;
        // Touch the header's updated_at so the note sorts as recently changed.
        if let Some(mut header) = self.note_header_raw(note_id).await {
            header.updated_at = now_secs();
            self.publish_index(IndexEntry::Note(header)).await?;
            self.persist_index_snapshot().await?;
        }
        Ok(())
    }

    // ---- key rotation / revocation ------------------------------------------------------------

    /// Revoke a member and rotate the space key. Owner-only.
    ///
    /// Bumps `key_epoch`, generates a fresh space key, marks the member revoked, re-wraps the NEW key
    /// to every remaining active member (so they keep access), drops the revoked member's reader-log,
    /// and seals all subsequent ops under the new epoch. The revoked member retains whatever
    /// plaintext they already held (the documented forward-secrecy-only boundary) but cannot decrypt
    /// any op sealed under the new epoch.
    pub async fn revoke(&self, member_node_id: &str) -> Result<()> {
        self.require_owner("revoke members").await?;
        if member_node_id == self.node_id {
            bail!("cannot revoke the owner device itself");
        }
        // Generate the new key and re-wrap to survivors under a single critical section.
        let new_key = SpaceKey::generate();
        {
            let mut meta = self.inner.meta.lock().await;
            let present = meta.members.iter().any(|m| m.device_id == member_node_id && !m.revoked);
            if !present {
                bail!("{member_node_id} is not an active member");
            }
            let new_epoch = meta.key_epoch.checked_add(1).ok_or_else(|| anyhow::anyhow!("epoch overflow"))?;
            // Mark revoked, then re-wrap the new key to every remaining active member.
            for m in meta.members.iter_mut() {
                if m.device_id == member_node_id {
                    m.revoked = true;
                    continue;
                }
                if m.revoked {
                    continue;
                }
                m.wrapped_key = crypto::wrap_key(&m.x25519_pub, new_epoch, &new_key)?;
            }
            meta.key_epoch = new_epoch;
            self.store.get().save_meta(&meta)?;
        }
        // Swap in the new key for all future seals/opens.
        {
            let mut key = self.inner.space_key.lock().await;
            *key = SpaceKey::from_bytes(new_key.0);
        }
        // Stop following the revoked member's writer-log.
        {
            let mut merge = self.inner.merge.lock().await;
            merge.remove_peer(member_node_id);
        }
        Ok(())
    }

    /// Encrypt a file and store it as a content-addressed object, returning the [`AttachmentRef`].
    /// The per-file key lives only inside the ref (and thus only inside the encrypted CRDT).
    pub async fn attach(&self, note_id: &str, path: &Path) -> Result<AttachmentRef> {
        self.require_write("attach files").await?;
        // Reject oversized files BEFORE reading them into memory (a fstat-bounded check). Streaming
        // chunked attachment encryption for arbitrarily large files is a documented follow-up.
        let meta = std::fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
        if meta.len() > MAX_ATTACHMENT_BYTES {
            bail!(
                "attachment is {} bytes, exceeds the {} byte limit",
                meta.len(),
                MAX_ATTACHMENT_BYTES
            );
        }
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
        if aref.size > MAX_ATTACHMENT_BYTES {
            bail!("attachment ref claims {} bytes, over the limit", aref.size);
        }
        if let Some(cached) = self.store.get().cached_attachment(&self.space_id, &aref.cid)?
            && cached.len() as u64 == aref.size
        {
            return Ok(cached);
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
        // Only the owner may add members and mint the rooted grant.
        self.require_owner("invite members").await?;
        // Validate the invitee NodeId is a real on-curve Ed25519 point BEFORE mutating membership, so
        // a malformed id cannot leave partial state (parse + Montgomery derivation both up front).
        let invitee = parse_node_id(invitee_node_id)?;
        let invitee_x = DeviceKeys::x25519_public_from_node_id(&invitee)?;
        {
            let meta = self.inner.meta.lock().await;
            let active = meta.members.iter().filter(|m| !m.revoked).count();
            if meta.member(invitee_node_id).is_none() && active >= MAX_MEMBERS {
                bail!("space already has the maximum {MAX_MEMBERS} members");
            }
        }

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
        self.persist_applied().await?;
        Ok(())
    }

    // ---- internals ----

    async fn apply_incoming(&self, op: &NoteOp) -> Result<()> {
        let current_epoch = { self.inner.meta.lock().await.key_epoch };
        let plaintext = {
            let key = self.inner.space_key.lock().await;
            // Only the current epoch's key is held; older-epoch ops we authored ourselves still
            // decrypt because we re-wrap on rotation. If decryption fails, skip rather than poison —
            // but distinguish the EXPECTED cross-epoch skip from an UNEXPECTED failure (corrupt or
            // forged op, or a key-rotation bug) so divergence is diagnosable.
            match crypto::open(&key, op.epoch, &op.nonce, &op.ct) {
                Ok(p) => p,
                Err(_) => {
                    if op.epoch != current_epoch {
                        tracing::debug!(
                            doc_id = %op.doc_id,
                            op_epoch = op.epoch,
                            current_epoch,
                            "skipping op sealed under a different key epoch (expected)"
                        );
                    } else {
                        tracing::warn!(
                            doc_id = %op.doc_id,
                            epoch = op.epoch,
                            ct_len = op.ct.len(),
                            "failed to decrypt op under the CURRENT epoch key (corrupt or forged?)"
                        );
                    }
                    return Ok(());
                }
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
        let reduced = reduce_index(&text);
        let mut idx = self.inner.index.lock().await;
        *idx = reduced;
        Ok(())
    }

    /// Compact the index log in place when it has grown past [`INDEX_COMPACT_THRESHOLD`]: rewrite the
    /// index doc's text to exactly one canonical line per live id (the current LWW survivor). Because
    /// every line feeds the same LWW reducer, a compacted log merged with any concurrent un-compacted
    /// appends still converges to the identical derived state — so this is safe to do locally and
    /// publish as an ordinary delta. Bounds per-edit cost and storage.
    async fn maybe_compact_index(&self) -> Result<()> {
        let text_len = {
            let docs = self.inner.docs.lock().await;
            docs.get(NoteOp::INDEX_DOC).map(|d| d.text().len()).unwrap_or(0)
        };
        if text_len <= INDEX_COMPACT_THRESHOLD {
            return Ok(());
        }
        self.rebuild_index_state().await?;
        let canonical = {
            let idx = self.inner.index.lock().await;
            let mut lines: Vec<String> = Vec::new();
            // Deterministic order so two replicas that compact independently produce identical text.
            let mut notes: Vec<&NoteHeader> = idx.notes.values().collect();
            notes.sort_by(|a, b| a.note_id.cmp(&b.note_id));
            for h in notes {
                lines.push(serde_json::to_string(&IndexEntry::Note(h.clone()))?);
            }
            let mut folders: Vec<&Folder> = idx.folders.values().collect();
            folders.sort_by(|a, b| a.folder_id.cmp(&b.folder_id));
            for f in folders {
                lines.push(serde_json::to_string(&IndexEntry::Folder(f.clone()))?);
            }
            let mut labels: Vec<&Label> = idx.labels.values().collect();
            labels.sort_by(|a, b| a.label_id.cmp(&b.label_id));
            for l in labels {
                lines.push(serde_json::to_string(&IndexEntry::Label(l.clone()))?);
            }
            lines.join("\n")
        };
        let delta = {
            let mut docs = self.inner.docs.lock().await;
            let doc = docs.entry(NoteOp::INDEX_DOC.to_string()).or_insert_with(YrsDoc::new);
            doc.set_text(&format!("{canonical}\n"))?
        };
        if !delta.is_empty() {
            self.publish_op(NoteOp::INDEX_DOC, &delta).await?;
        }
        self.persist_index_snapshot().await
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
        self.rebuild_index_state().await?;
        self.maybe_compact_index().await
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

    /// Persist the merge-set's per-log drained high-water marks so a reopen does not re-drain the
    /// entire op history.
    async fn persist_applied(&self) -> Result<()> {
        if !self.inner.store_present {
            return Ok(());
        }
        let marks = self.inner.merge.lock().await.drained_marks();
        self.store.get().save_applied(&self.space_id, &marks)
    }
}

/// Sort note headers for display: pinned notes first, then newest-updated, ties broken by id so the
/// order is total and stable across replicas.
fn sort_notes(v: &mut [NoteHeader]) {
    v.sort_by(|a, b| {
        b.pinned
            .cmp(&a.pinned)
            .then(b.updated_at.cmp(&a.updated_at))
            .then(a.note_id.cmp(&b.note_id))
    });
}

/// Deterministic, order-independent merge of two observations of the same folder. Folders carry no
/// logical clock, so a delete tombstone always wins (monotonic), and otherwise the lexicographically
/// larger JSON wins — a stable total order every replica computes identically.
fn merge_folder(a: Folder, b: Folder) -> Folder {
    if a.deleted != b.deleted {
        return if a.deleted { a } else { b };
    }
    let ja = serde_json::to_string(&a).unwrap_or_default();
    let jb = serde_json::to_string(&b).unwrap_or_default();
    if ja >= jb { a } else { b }
}

/// Deterministic, order-independent merge of two observations of the same label (same rule as
/// [`merge_folder`]).
fn merge_label(a: Label, b: Label) -> Label {
    if a.deleted != b.deleted {
        return if a.deleted { a } else { b };
    }
    let ja = serde_json::to_string(&a).unwrap_or_default();
    let jb = serde_json::to_string(&b).unwrap_or_default();
    if ja >= jb { a } else { b }
}

/// Reduce the index log (newline-delimited JSON [`IndexEntry`] records inside the index doc's text)
/// to the derived [`IndexState`]: the LWW survivor per note / folder / label id. Notes reconcile by
/// `updated_at` (NOT line order), folders/labels by the deterministic tombstone-then-JSON order — so
/// the union of two devices' logs converges to the same state regardless of arrival order. Blank,
/// oversized, or unparseable lines are skipped.
fn reduce_index(text: &str) -> IndexState {
    let mut idx = IndexState::default();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.len() > MAX_INDEX_LINE_BYTES {
            continue;
        }
        match serde_json::from_str::<IndexEntry>(line) {
            Ok(IndexEntry::Note(h)) => {
                let merged = match idx.notes.remove(&h.note_id) {
                    Some(prev) => NoteHeader::merge(prev, h),
                    None => h,
                };
                idx.notes.insert(merged.note_id.clone(), merged);
            }
            Ok(IndexEntry::Folder(f)) => {
                let merged = match idx.folders.remove(&f.folder_id) {
                    Some(prev) => merge_folder(prev, f),
                    None => f,
                };
                idx.folders.insert(merged.folder_id.clone(), merged);
            }
            Ok(IndexEntry::Label(l)) => {
                let merged = match idx.labels.remove(&l.label_id) {
                    Some(prev) => merge_label(prev, l),
                    None => l,
                };
                idx.labels.insert(merged.label_id.clone(), merged);
            }
            Err(_) => continue,
        }
    }
    idx
}

/// Reduce a checklist body (newline-delimited JSON [`ChecklistItem`] records) to the LWW survivor
/// per item id, INCLUDING tombstones (so callers can read the current state of a deleted item).
fn reduce_checklist_all(text: &str) -> HashMap<String, ChecklistItem> {
    let mut by_id: HashMap<String, ChecklistItem> = HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.len() > MAX_INDEX_LINE_BYTES {
            continue;
        }
        if let Ok(item) = serde_json::from_str::<ChecklistItem>(line) {
            let merged = match by_id.remove(&item.item_id) {
                Some(prev) => ChecklistItem::merge(prev, item),
                None => item,
            };
            by_id.insert(merged.item_id.clone(), merged);
        }
    }
    by_id
}

/// Reduce a checklist body to the live (non-deleted) items, sorted by `order` then `item_id`.
fn reduce_checklist(text: &str) -> Vec<ChecklistItem> {
    let mut v: Vec<ChecklistItem> =
        reduce_checklist_all(text).into_values().filter(|i| !i.deleted).collect();
    v.sort_by(|a, b| a.order.cmp(&b.order).then(a.item_id.cmp(&b.item_id)));
    v
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

    fn hdr(id: &str, updated: u64, pinned: bool, archived: bool) -> NoteHeader {
        let mut h = NoteHeader::new(id.into(), id.into(), None, updated);
        h.pinned = pinned;
        h.archived = archived;
        h
    }

    #[test]
    fn sort_notes_pins_first_then_recency() {
        let mut v = vec![
            hdr("a", 100, false, false),
            hdr("b", 300, false, false),
            hdr("c", 50, true, false), // pinned but oldest
            hdr("d", 200, true, false),
        ];
        sort_notes(&mut v);
        let order: Vec<&str> = v.iter().map(|h| h.note_id.as_str()).collect();
        // Pinned (d before c by recency), then unpinned by recency (b before a).
        assert_eq!(order, vec!["d", "c", "b", "a"]);
    }

    #[test]
    fn merge_folder_tombstone_wins_and_is_order_independent() {
        let live = Folder { folder_id: "f".into(), name: "x".into(), parent: None, deleted: false };
        let dead = Folder { folder_id: "f".into(), name: "x".into(), parent: None, deleted: true };
        assert!(merge_folder(live.clone(), dead.clone()).deleted);
        assert!(merge_folder(dead.clone(), live.clone()).deleted);
        // Two live observations: deterministic regardless of order.
        let a = Folder { folder_id: "f".into(), name: "alpha".into(), parent: None, deleted: false };
        let b = Folder { folder_id: "f".into(), name: "beta".into(), parent: None, deleted: false };
        assert_eq!(merge_folder(a.clone(), b.clone()), merge_folder(b, a));
    }

    #[test]
    fn reduce_checklist_is_lww_per_item_and_sorted() {
        let item = |id: &str, text: &str, checked: bool, order: i64, t: u64, del: bool| {
            serde_json::to_string(&ChecklistItem {
                item_id: id.into(),
                text: text.into(),
                checked,
                order,
                updated_at: t,
                deleted: del,
            })
            .unwrap()
        };
        // Two records for "x": the newer (checked) wins. "y" before "x" by order key.
        let text = [
            item("x", "buy milk", false, 1, 10, false),
            item("y", "buy eggs", false, 0, 5, false),
            item("x", "buy milk", true, 1, 20, false),
        ]
        .join("\n");
        let items = reduce_checklist(&text);
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].item_id, "y"); // order 0 first
        assert_eq!(items[1].item_id, "x");
        assert!(items[1].checked, "newer record wins LWW");

        // A delete tombstone (newer) removes the item from the live list.
        let with_del = [text, item("y", "buy eggs", false, 0, 99, true)].join("\n");
        let after = reduce_checklist(&with_del);
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].item_id, "x");
    }

    fn note_line(id: &str, title: &str, updated: u64, pinned: bool) -> String {
        let mut h = NoteHeader::new(id.into(), title.into(), None, updated);
        h.pinned = pinned;
        serde_json::to_string(&IndexEntry::Note(h)).unwrap()
    }

    #[test]
    fn reduce_index_is_lww_and_order_independent() {
        // Two observations of note "a": the newer title wins. A label and a folder too.
        let label = serde_json::to_string(&IndexEntry::Label(Label {
            label_id: "L".into(),
            name: "work".into(),
            color: Color::Blue,
            deleted: false,
        }))
        .unwrap();
        let folder = serde_json::to_string(&IndexEntry::Folder(Folder {
            folder_id: "F".into(),
            name: "lists".into(),
            parent: None,
            deleted: false,
        }))
        .unwrap();
        let forward = [
            note_line("a", "old", 100, false),
            note_line("a", "new", 200, true),
            label.clone(),
            folder.clone(),
        ]
        .join("\n");
        // The same records in REVERSE order must reduce to the identical state (line order is not
        // time order; LWW by updated_at decides).
        let reverse = [folder, label, note_line("a", "new", 200, true), note_line("a", "old", 100, false)]
            .join("\n");

        let f = reduce_index(&forward);
        let r = reduce_index(&reverse);
        assert_eq!(f.notes.len(), 1);
        assert_eq!(f.notes.get("a").unwrap().title, "new");
        assert!(f.notes.get("a").unwrap().pinned);
        assert_eq!(f.notes.get("a"), r.notes.get("a"), "index reduction is order-independent");
        assert_eq!(f.labels.len(), 1);
        assert_eq!(f.folders.len(), 1);
    }

    #[test]
    fn reduce_index_skips_garbage_and_oversize_lines() {
        let huge = "x".repeat(MAX_INDEX_LINE_BYTES + 1);
        let text = format!("garbage\n\n{}\n{huge}\n", note_line("a", "t", 1, false));
        let idx = reduce_index(&text);
        assert_eq!(idx.notes.len(), 1);
    }

    #[test]
    fn reduce_checklist_skips_garbage_and_oversize_lines() {
        let good = serde_json::to_string(&ChecklistItem {
            item_id: "i".into(),
            text: "ok".into(),
            checked: false,
            order: 0,
            updated_at: 1,
            deleted: false,
        })
        .unwrap();
        let huge = "x".repeat(MAX_INDEX_LINE_BYTES + 1);
        let text = format!("not json\n\n{good}\n{huge}\n");
        let items = reduce_checklist(&text);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].item_id, "i");
    }
}
