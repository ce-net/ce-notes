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
/// A device id — a CE NodeId hex (64 chars).
pub type DeviceId = String;

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

/// The cached index entry for a note. The authoritative title also lives as the first heading of the
/// note body; this is the index copy kept in the per-space index CRDT for fast listing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoteHeader {
    pub note_id: NoteId,
    pub title: String,
    pub folder_id: Option<FolderId>,
    pub updated_at: u64,
    /// CRDT-safe delete: a tombstone, never a hard remove (so a concurrent edit + delete keeps the
    /// note recoverable).
    pub deleted: bool,
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

impl Invite {
    /// Encode to bytes for transport / file handoff.
    pub fn encode(&self) -> anyhow::Result<Vec<u8>> {
        Ok(serde_json::to_vec(self)?)
    }

    /// Decode an invite blob.
    pub fn decode(bytes: &[u8]) -> anyhow::Result<Invite> {
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
}
