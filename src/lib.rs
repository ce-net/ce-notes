//! # CE Notes — local-first, end-to-end-encrypted CRDT notes on the CE mesh
//!
//! CE Notes models a notebook ("space") as a content-addressed, E2E-encrypted set of CRDT documents.
//! Prose notes are Yjs-compatible text CRDTs whose binary updates ride ce-coord's replicated log as
//! opaque, app-encrypted bytes; attachments are encrypted and stored via the CE blob/object layer,
//! referenced by `{cid, key}` inside the CRDT. **CE never decrypts anything** — confidentiality is
//! pure app-layer envelope encryption (XChaCha20-Poly1305 content key per space, wrapped per device
//! via X25519 derived from each device's Ed25519 NodeId), while CE provides authenticated transport,
//! the blob layer, and capability gating for sharing.
//!
//! Layering: `CE Notes → ce-coord → ce-rs → local CE node → mesh`. The node stays primitives-only;
//! this crate is an app over existing primitives, no new node endpoints.
//!
//! The library surface is [`core`]; the `ce-notes` binary is a CLI/TUI shell over it.
//!
//! ```no_run
//! use ce_notes::core::Notes;
//! use ce_coord::Coord;
//! use ce_rs::CeClient;
//! # async fn demo(identity_dir: &std::path::Path, data_dir: &std::path::Path) -> anyhow::Result<()> {
//! let coord = Coord::connect().await?;
//! let client = CeClient::local();
//! let notes = Notes::open(identity_dir, data_dir, coord, client).await?;
//! let space = notes.create_space("Work").await?;
//! let id = space.create_note("Shopping list", None).await?;
//! space.set_note_text(&id, "# Shopping list\n\n- milk\n- bread\n").await?;
//! # Ok(()) }
//! ```

pub mod core;

pub use core::{
    AttachmentRef, DeviceKeys, Invite, MemberEntry, NoteDoc, NoteHeader, NoteOp, Notes, Role, Space,
    SpaceKey, SpaceMeta, Store, WrappedKey, YrsDoc,
};
