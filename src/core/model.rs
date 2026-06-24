//! The CE Notes data model — spaces, members, notes, folders, attachments, and the on-wire op.
//!
//! Everything here is serialized *inside* encrypted CRDT updates or inside the space metadata. The
//! mesh only ever sees [`NoteOp`] (opaque ciphertext) plus an authenticated sender NodeId.

use serde::{Deserialize, Serialize};

use super::crypto::{NONCE_LEN, WrappedKey};

/// A space (notebook / vault) id — 32 random bytes, hex. Stable across renames and moves; it is the
/// unit of sharing and the unit of encryption.
pub type SpaceId = String;
/// A note id — hex, monotonic-ish so listings sort by creation by default.
pub type NoteId = String;
/// A folder id — hex random.
pub type FolderId = String;
/// A label id — hex random.
pub type LabelId = String;
/// A device id — a CE NodeId hex (64 chars).
pub type DeviceId = String;

/// A note color, mirroring Google Keep's fixed palette. `Default` is the unset/white note.
///
/// Parsing is case-insensitive and accepts a few aliases (`grey`, `navy`, `white`/`none`):
/// ```
/// use ce_notes::core::model::Color;
/// assert_eq!(Color::parse("Blue"), Some(Color::Blue));
/// assert_eq!(Color::parse("grey"), Some(Color::Gray));
/// assert_eq!(Color::parse("navy"), Some(Color::DarkBlue));
/// assert_eq!(Color::Red.name(), "red");
/// assert_eq!(Color::parse("chartreuse"), None);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Color {
    #[default]
    Default,
    Red,
    Orange,
    Yellow,
    Green,
    Teal,
    Blue,
    DarkBlue,
    Purple,
    Pink,
    Brown,
    Gray,
}

impl Color {
    /// Parse a color name (case-insensitive). Returns `None` for an unknown name.
    pub fn parse(s: &str) -> Option<Color> {
        Some(match s.trim().to_ascii_lowercase().as_str() {
            "default" | "white" | "none" => Color::Default,
            "red" => Color::Red,
            "orange" => Color::Orange,
            "yellow" => Color::Yellow,
            "green" => Color::Green,
            "teal" => Color::Teal,
            "blue" => Color::Blue,
            "darkblue" | "dark-blue" | "navy" => Color::DarkBlue,
            "purple" => Color::Purple,
            "pink" => Color::Pink,
            "brown" => Color::Brown,
            "gray" | "grey" => Color::Gray,
            _ => return None,
        })
    }

    /// The lowercase canonical name.
    pub fn name(self) -> &'static str {
        match self {
            Color::Default => "default",
            Color::Red => "red",
            Color::Orange => "orange",
            Color::Yellow => "yellow",
            Color::Green => "green",
            Color::Teal => "teal",
            Color::Blue => "blue",
            Color::DarkBlue => "darkblue",
            Color::Purple => "purple",
            Color::Pink => "pink",
            Color::Brown => "brown",
            Color::Gray => "gray",
        }
    }
}

/// A user-defined label (Keep-style colored tag). Notes reference labels many-to-many by id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Label {
    pub label_id: LabelId,
    pub name: String,
    #[serde(default)]
    pub color: Color,
    #[serde(default)]
    pub deleted: bool,
}

/// A time-based reminder attached to a note: a unix-seconds due time and whether it has fired.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reminder {
    /// Unix seconds the reminder is due.
    pub due_unix: u64,
    /// Set once the reminder has been surfaced/acknowledged (so it is not re-shown).
    #[serde(default)]
    pub done: bool,
}

/// A member's role within a space. The owner may add/revoke members and rotate the key; writers may
/// edit; readers may only read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Role {
    Owner,
    Writer,
    Reader,
}

impl Role {
    /// May this role mutate notes? Owners and writers may; readers may not.
    pub fn can_write(self) -> bool {
        matches!(self, Role::Owner | Role::Writer)
    }

    /// The capability ability strings this role is granted when shared.
    pub fn abilities(self) -> Vec<String> {
        let mut a = vec!["notes:read".to_string()];
        if self.can_write() {
            a.push("notes:write".to_string());
        }
        a
    }
}

/// One device/person authorized on a space. Every authorized device appears here with the space key
/// wrapped to its X25519 public key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberEntry {
    /// The CE NodeId (hex) this member's key is wrapped to.
    pub device_id: DeviceId,
    /// The member's X25519 public key (carried explicitly so the derivation source is swappable).
    pub x25519_pub: [u8; 32],
    /// Human label, e.g. "my phone" or "alice@laptop".
    pub label: String,
    /// Role within the space.
    pub role: Role,
    /// The current-epoch space key sealed to this device.
    pub wrapped_key: WrappedKey,
    /// Unix seconds when added.
    pub added_at: u64,
    /// Whether this member has been revoked (kept as a tombstone, never hard-removed).
    pub revoked: bool,
}

/// Space metadata — the membership and key state. Stored locally (encrypted at rest) and embedded in
/// invites. Distinct from the note *content*, which lives in the encrypted CRDT logs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpaceMeta {
    pub space_id: SpaceId,
    /// Display name (user-editable).
    pub name: String,
    /// Unix seconds at creation.
    pub created_at: u64,
    /// Bumped on key rotation (revocation). The current epoch's key seals all *new* updates.
    pub key_epoch: u32,
    /// The owner's NodeId (hex) — the capability-chain root for this space.
    pub owner: DeviceId,
    /// Authorized devices/people.
    pub members: Vec<MemberEntry>,
}

impl SpaceMeta {
    /// The non-revoked member entry for `device_id`, if any.
    pub fn member(&self, device_id: &str) -> Option<&MemberEntry> {
        self.members.iter().find(|m| m.device_id == device_id && !m.revoked)
    }

    /// Every non-revoked member device id (the writers whose logs we read).
    pub fn active_device_ids(&self) -> Vec<DeviceId> {
        self.members
            .iter()
            .filter(|m| !m.revoked)
            .map(|m| m.device_id.clone())
            .collect()
    }

    /// Is `device_id` an active member authorized to write?
    pub fn can_write(&self, device_id: &str) -> bool {
        self.member(device_id).map(|m| m.role.can_write()).unwrap_or(false)
    }
}

/// What kind of body a note carries: a freeform markdown text, or a structured checklist.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum NoteKind {
    /// Freeform markdown body (a single `Y.Text`).
    #[default]
    Markdown,
    /// A structured checklist (a CRDT log of [`ChecklistItem`] records in the body doc).
    Checklist,
}

/// The cached index entry for a note. The authoritative title also lives as the first heading of the
/// note body; this is the index copy kept in the per-space index CRDT for fast listing.
///
/// Every mutable field is last-writer-wins, reconciled by [`NoteHeader::merge`] using `updated_at`
/// (ties broken by `note_id`), so the same set of header upserts converges on every replica.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoteHeader {
    pub note_id: NoteId,
    pub title: String,
    pub folder_id: Option<FolderId>,
    pub updated_at: u64,
    /// CRDT-safe delete: a tombstone, never a hard remove (so a concurrent edit + delete keeps the
    /// note recoverable).
    pub deleted: bool,
    /// Pinned notes sort above all others in the main list.
    #[serde(default)]
    pub pinned: bool,
    /// Archived notes are hidden from the main list (still searchable / restorable).
    #[serde(default)]
    pub archived: bool,
    /// Note color (Keep palette).
    #[serde(default)]
    pub color: Color,
    /// Labels applied to this note (many-to-many, by id).
    #[serde(default)]
    pub labels: Vec<LabelId>,
    /// Body kind: markdown or checklist.
    #[serde(default)]
    pub kind: NoteKind,
    /// Optional time-based reminder.
    #[serde(default)]
    pub reminder: Option<Reminder>,
}

impl NoteHeader {
    /// A fresh markdown note header.
    pub fn new(note_id: NoteId, title: String, folder_id: Option<FolderId>, now: u64) -> NoteHeader {
        NoteHeader {
            note_id,
            title,
            folder_id,
            updated_at: now,
            deleted: false,
            pinned: false,
            archived: false,
            color: Color::Default,
            labels: Vec::new(),
            kind: NoteKind::Markdown,
            reminder: None,
        }
    }

    /// LWW merge of two header observations for the same note: the newer `updated_at` wins; ties are
    /// broken deterministically by the serialized form so every replica picks the same survivor.
    pub fn merge(a: NoteHeader, b: NoteHeader) -> NoteHeader {
        match a.updated_at.cmp(&b.updated_at) {
            std::cmp::Ordering::Greater => a,
            std::cmp::Ordering::Less => b,
            std::cmp::Ordering::Equal => {
                // Deterministic tiebreak: pick the lexicographically larger JSON so all replicas
                // agree even when two edits share a second. (Stable, total, replica-independent.)
                let ja = serde_json::to_string(&a).unwrap_or_default();
                let jb = serde_json::to_string(&b).unwrap_or_default();
                if ja >= jb { a } else { b }
            }
        }
    }
}

/// One item of a checklist note. Stored as a CRDT log record inside the note's body doc; reconciled
/// last-writer-wins per `item_id` by `updated_at`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChecklistItem {
    pub item_id: String,
    pub text: String,
    pub checked: bool,
    /// Sort key (lower first). Lets items be reordered without renumbering siblings.
    pub order: i64,
    pub updated_at: u64,
    #[serde(default)]
    pub deleted: bool,
}

impl ChecklistItem {
    /// LWW merge for the same `item_id`.
    pub fn merge(a: ChecklistItem, b: ChecklistItem) -> ChecklistItem {
        match a.updated_at.cmp(&b.updated_at) {
            std::cmp::Ordering::Greater => a,
            std::cmp::Ordering::Less => b,
            std::cmp::Ordering::Equal => {
                let ja = serde_json::to_string(&a).unwrap_or_default();
                let jb = serde_json::to_string(&b).unwrap_or_default();
                if ja >= jb { a } else { b }
            }
        }
    }
}

/// A folder in the space's folder tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Folder {
    pub folder_id: FolderId,
    pub name: String,
    pub parent: Option<FolderId>,
    pub deleted: bool,
}

/// A reference to an encrypted attachment blob. The `file_key`/`nonce` live ONLY inside the
/// encrypted CRDT — the mesh stores only the ciphertext object, addressed by `cid`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachmentRef {
    /// CE object CID (manifest hash from `put_object`) of the *ciphertext*.
    pub cid: String,
    /// Per-file random key (XChaCha20-Poly1305). Stored only inside the encrypted CRDT.
    pub file_key: [u8; 32],
    /// AEAD nonce for the file ciphertext.
    pub nonce: [u8; NONCE_LEN],
    pub name: String,
    pub mime: String,
    /// Plaintext size in bytes.
    pub size: u64,
}

/// The op carried on the MergeLog. Opaque ciphertext to the mesh: only `doc_id`, `epoch`, `nonce`
/// and the sealed bytes travel. Every Yjs update (index or note body) becomes one of these.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoteOp {
    /// Which document this update targets: `"index"` or `"note:<NoteId>"`.
    pub doc_id: String,
    /// The space key epoch used to seal `ct`.
    pub epoch: u32,
    /// AEAD nonce.
    pub nonce: [u8; NONCE_LEN],
    /// `seal(space_key, epoch, yjs_update_bytes)`.
    pub ct: Vec<u8>,
}

impl NoteOp {
    /// The doc id of the per-space index document.
    pub const INDEX_DOC: &'static str = "index";

    /// The doc id for a note body.
    pub fn note_doc_id(note_id: &str) -> String {
        format!("note:{note_id}")
    }
}

/// An invite blob handed to a new member out-of-band (or via a directed mesh message). Carries
/// enough to join: the space metadata, the key wrapped to the invitee, and the capability grant
/// chain proving the owner authorized them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invite {
    /// Snapshot of space metadata at invite time.
    pub space_meta: SpaceMeta,
    /// The space key wrapped to the invitee's X25519 key.
    pub wrapped_key: WrappedKey,
    /// The invitee's NodeId (hex) the wrap and grant are addressed to.
    pub invitee: DeviceId,
    /// The invitee's X25519 public key (so members can re-wrap on rotation without re-deriving).
    pub invitee_x25519: [u8; 32],
    /// Role granted.
    pub role: Role,
    /// The `ce-cap` capability chain (hex token) rooted at the owner's key, granting `notes:*`.
    pub grant_token: String,
}

/// Maximum accepted size of an encoded [`Invite`] blob (defends `decode` against a hostile/oversized
/// input being deserialized into memory). An invite carries metadata for every existing member, so
/// this scales with membership while still bounding the worst case far below any real notebook.
pub const MAX_INVITE_BYTES: usize = 4 * 1024 * 1024;

impl Invite {
    /// Encode to bytes for transport / file handoff.
    pub fn encode(&self) -> anyhow::Result<Vec<u8>> {
        Ok(serde_json::to_vec(self)?)
    }

    /// Decode an invite blob, rejecting anything larger than [`MAX_INVITE_BYTES`] before parsing.
    pub fn decode(bytes: &[u8]) -> anyhow::Result<Invite> {
        if bytes.len() > MAX_INVITE_BYTES {
            anyhow::bail!(
                "invite blob is {} bytes, exceeds the {} byte limit",
                bytes.len(),
                MAX_INVITE_BYTES
            );
        }
        Ok(serde_json::from_slice(bytes)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_abilities_attenuate() {
        assert_eq!(Role::Reader.abilities(), vec!["notes:read".to_string()]);
        assert_eq!(
            Role::Writer.abilities(),
            vec!["notes:read".to_string(), "notes:write".to_string()]
        );
        assert!(Role::Owner.can_write());
        assert!(!Role::Reader.can_write());
    }

    #[test]
    fn note_doc_id_format() {
        assert_eq!(NoteOp::note_doc_id("abc"), "note:abc");
        assert_eq!(NoteOp::INDEX_DOC, "index");
    }

    fn meta_with(members: Vec<MemberEntry>) -> SpaceMeta {
        SpaceMeta {
            space_id: "s".into(),
            name: "n".into(),
            created_at: 0,
            key_epoch: 0,
            owner: "owner".into(),
            members,
        }
    }

    fn member(id: &str, role: Role, revoked: bool) -> MemberEntry {
        MemberEntry {
            device_id: id.into(),
            x25519_pub: [0u8; 32],
            label: id.into(),
            role,
            wrapped_key: WrappedKey {
                epoch: 0,
                ephemeral_pub: [0u8; 32],
                nonce: [0u8; NONCE_LEN],
                ct: vec![],
            },
            added_at: 0,
            revoked,
        }
    }

    #[test]
    fn active_members_exclude_revoked() {
        let meta = meta_with(vec![
            member("a", Role::Owner, false),
            member("b", Role::Writer, true),
            member("c", Role::Reader, false),
        ]);
        let ids = meta.active_device_ids();
        assert_eq!(ids, vec!["a".to_string(), "c".to_string()]);
        assert!(meta.can_write("a"));
        assert!(!meta.can_write("c"));
        assert!(!meta.can_write("b")); // revoked
        assert!(!meta.can_write("unknown"));
    }

    #[test]
    fn color_parse_roundtrip() {
        for c in [
            Color::Default,
            Color::Red,
            Color::DarkBlue,
            Color::Gray,
            Color::Teal,
        ] {
            assert_eq!(Color::parse(c.name()), Some(c));
        }
        assert_eq!(Color::parse("GREY"), Some(Color::Gray));
        assert_eq!(Color::parse("navy"), Some(Color::DarkBlue));
        assert_eq!(Color::parse("chartreuse"), None);
    }

    #[test]
    fn note_header_merge_is_lww_and_deterministic() {
        let mut older = NoteHeader::new("n1".into(), "old".into(), None, 100);
        let mut newer = NoteHeader::new("n1".into(), "new".into(), None, 200);
        newer.pinned = true;
        // Newer updated_at wins regardless of argument order.
        assert_eq!(NoteHeader::merge(older.clone(), newer.clone()).title, "new");
        assert_eq!(NoteHeader::merge(newer.clone(), older.clone()).title, "new");
        // Tie: deterministic and order-independent.
        older.updated_at = 200;
        let ab = NoteHeader::merge(older.clone(), newer.clone());
        let ba = NoteHeader::merge(newer, older);
        assert_eq!(ab, ba, "tiebreak must be order-independent");
    }

    #[test]
    fn checklist_item_merge_is_lww() {
        let a = ChecklistItem {
            item_id: "i".into(),
            text: "buy milk".into(),
            checked: false,
            order: 0,
            updated_at: 10,
            deleted: false,
        };
        let mut b = a.clone();
        b.checked = true;
        b.updated_at = 20;
        assert!(ChecklistItem::merge(a.clone(), b.clone()).checked);
        assert!(ChecklistItem::merge(b, a).checked);
    }

    #[test]
    fn invite_decode_rejects_oversize() {
        let huge = vec![b'x'; MAX_INVITE_BYTES + 1];
        assert!(Invite::decode(&huge).is_err());
    }

    #[test]
    fn note_header_new_defaults() {
        let h = NoteHeader::new("n".into(), "t".into(), None, 5);
        assert!(!h.pinned && !h.archived && !h.deleted);
        assert_eq!(h.color, Color::Default);
        assert_eq!(h.kind, NoteKind::Markdown);
        assert!(h.labels.is_empty());
        assert!(h.reminder.is_none());
    }
}
