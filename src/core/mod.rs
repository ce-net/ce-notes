//! `ce-notes::core` — the library: crypto envelope, data model, text-CRDT doc, multi-writer merge
//! log over ce-coord, local at-rest store, and the high-level [`Notes`]/[`Space`] API.
//!
//! No UI and no I/O beyond ce-rs / ce-coord / the local store. The CLI/TUI front-end lives in the
//! `ce-notes` binary and is a thin shell over this surface.

pub mod crypto;
pub mod mergelog;
pub mod model;
pub mod notedoc;
pub mod notes;
pub mod store;

pub use crypto::{DeviceKeys, SpaceKey, WrappedKey};
pub use mergelog::{MergeLog, MergeSet};
pub use model::{
    AttachmentRef, ChecklistItem, Color, DeviceId, Folder, FolderId, Invite, Label, LabelId,
    MemberEntry, NoteHeader, NoteId, NoteKind, NoteOp, Reminder, Role, SpaceId, SpaceMeta,
};
pub use notedoc::{NoteDoc, YrsDoc};
pub use notes::{Notes, Space};
pub use store::Store;
