//! The text-CRDT document model behind a note body, kept behind the [`NoteDoc`] trait so the
//! concrete CRDT (yrs today, loro tomorrow) is swappable without touching the rest of the app.
//!
//! A note body is a single CRDT document with a `Y.Text` rooted at `"body"`. Edits produce binary
//! *update* deltas; those deltas are what we encrypt and ship over ce-coord. Because CRDT updates
//! are commutative and idempotent, applying the union of all members' updates (in any order, with
//! duplicates) converges every replica to the same text — which is exactly what lets us run a
//! per-device log and union them without a global order (see [`mergelog`](super::mergelog)).
//!
//! The trait surface is deliberately tiny: create, apply an update, encode the full state as an
//! update, read the text, and apply a plain-text replacement as a minimal diff. Everything the app
//! needs, nothing the CRDT-specific API leaks.

use anyhow::Result;

/// A convergent text document. Implementors are CRDTs: applying the same set of updates (any order,
/// any duplicates) yields identical [`text`](NoteDoc::text).
pub trait NoteDoc: Send {
    /// A fresh, empty document.
    fn new() -> Self
    where
        Self: Sized;

    /// Reconstruct a document from a previously [`encode_state`](NoteDoc::encode_state)d snapshot.
    fn from_snapshot(snapshot: &[u8]) -> Result<Self>
    where
        Self: Sized;

    /// Apply a binary CRDT update (as produced by [`encode_state`] or by `set_text`'s emitted
    /// delta). Idempotent and order-independent.
    fn apply_update(&mut self, update: &[u8]) -> Result<()>;

    /// Encode the document's full current state as a single update — a snapshot that, applied to a
    /// fresh doc, reproduces it. Used for persistence and for catch-up snapshots.
    fn encode_state(&self) -> Vec<u8>;

    /// The current plain text of the body.
    fn text(&self) -> String;

    /// Replace the entire body with `new_text`, returning the binary update delta that captures the
    /// change (to be encrypted and broadcast). The replacement is computed as a minimal
    /// common-prefix/suffix diff so unchanged regions keep their CRDT identity and concurrent edits
    /// elsewhere are preserved.
    fn set_text(&mut self, new_text: &str) -> Result<Vec<u8>>;
}

/// The yrs (Rust Yjs) implementation of [`NoteDoc`]. Yjs-binary-compatible, so the future web client
/// (CodeMirror + Yjs) speaks the same update format.
pub mod yrs_impl {
    use super::*;
    use yrs::updates::decoder::Decode;
    use yrs::{Doc, GetString, OffsetKind, Options, ReadTxn, Text, Transact, Update};

    const BODY: &str = "body";

    /// A note body backed by a yrs `Doc` with a `Y.Text` at `"body"`.
    pub struct YrsDoc {
        doc: Doc,
    }

    impl YrsDoc {
        fn text_ref(&self) -> yrs::TextRef {
            self.doc.get_or_insert_text(BODY)
        }

        /// Doc options pinned to **UTF-16** offset counting. yrs defaults to UTF-8 *byte* offsets,
        /// but `set_text`'s diff is computed in UTF-16 units, and UTF-16 is also what JS Yjs uses —
        /// so this both makes our index math correct AND keeps the wire format interoperable with a
        /// future CodeMirror+Yjs web client. A fixed `client_id` is NOT used (random per doc is
        /// required for CRDT correctness), only the offset kind is overridden.
        fn options() -> Options {
            Options { offset_kind: OffsetKind::Utf16, ..Options::default() }
        }
    }

    impl NoteDoc for YrsDoc {
        fn new() -> Self {
            let doc = Doc::with_options(YrsDoc::options());
            // Materialize the text type so the root exists from the start.
            let _ = doc.get_or_insert_text(BODY);
            YrsDoc { doc }
        }

        fn from_snapshot(snapshot: &[u8]) -> Result<Self> {
            let mut d = YrsDoc::new();
            d.apply_update(snapshot)?;
            Ok(d)
        }

        fn apply_update(&mut self, update: &[u8]) -> Result<()> {
            let update = Update::decode_v1(update)
                .map_err(|e| anyhow::anyhow!("decode yrs update: {e}"))?;
            let mut txn = self.doc.transact_mut();
            txn.apply_update(update)
                .map_err(|e| anyhow::anyhow!("apply yrs update: {e}"))?;
            Ok(())
        }

        fn encode_state(&self) -> Vec<u8> {
            let txn = self.doc.transact();
            txn.encode_state_as_update_v1(&yrs::StateVector::default())
        }

        fn text(&self) -> String {
            let text = self.text_ref();
            let txn = self.doc.transact();
            text.get_string(&txn)
        }

        fn set_text(&mut self, new_text: &str) -> Result<Vec<u8>> {
            let text = self.text_ref();
            // Capture the state vector before the edit so we can encode just the delta afterwards.
            let before = {
                let txn = self.doc.transact();
                txn.state_vector()
            };

            let current = self.text();
            // yrs `Text` indexes by UTF-16 code units, so the replacement span MUST be expressed in
            // UTF-16 units — not Unicode scalars — or any non-BMP character (emoji, astral CJK)
            // shifts every later offset and corrupts the delta. `diff` returns UTF-16 offsets.
            let Diff { prefix_u16, removed_u16, inserted } = diff(&current, new_text);

            {
                let mut txn = self.doc.transact_mut();
                if removed_u16 > 0 {
                    text.remove_range(&mut txn, prefix_u16, removed_u16);
                }
                if !inserted.is_empty() {
                    text.insert(&mut txn, prefix_u16, &inserted);
                }
            }

            let txn = self.doc.transact();
            Ok(txn.encode_diff_v1(&before))
        }
    }

    /// A minimal single-span replacement turning `old` into `new`, expressed in **UTF-16 code units**
    /// (yrs's native index space): a common-prefix length, a count of UTF-16 units to remove after
    /// it, and the substring to insert.
    pub(crate) struct Diff {
        pub prefix_u16: u32,
        pub removed_u16: u32,
        pub inserted: String,
    }

    /// Compute the minimal single-span replacement turning `old` into `new`, in UTF-16 units. We
    /// diff over `char`s (so we never split a code point) but accumulate the UTF-16 length of the
    /// common prefix / removed middle, because that is the index space yrs `Text` operates in.
    pub(crate) fn diff(old: &str, new: &str) -> Diff {
        let old_chars: Vec<char> = old.chars().collect();
        let new_chars: Vec<char> = new.chars().collect();

        let mut prefix = 0;
        while prefix < old_chars.len()
            && prefix < new_chars.len()
            && old_chars[prefix] == new_chars[prefix]
        {
            prefix += 1;
        }

        let mut suffix = 0;
        while suffix < old_chars.len() - prefix
            && suffix < new_chars.len() - prefix
            && old_chars[old_chars.len() - 1 - suffix] == new_chars[new_chars.len() - 1 - suffix]
        {
            suffix += 1;
        }

        // Convert the char-based spans into UTF-16 unit counts (each char is 1 or 2 UTF-16 units).
        let prefix_u16: u32 = old_chars[..prefix].iter().map(|c| c.len_utf16() as u32).sum();
        let removed_u16: u32 = old_chars[prefix..old_chars.len() - suffix]
            .iter()
            .map(|c| c.len_utf16() as u32)
            .sum();
        let inserted: String = new_chars[prefix..new_chars.len() - suffix].iter().collect();
        Diff { prefix_u16, removed_u16, inserted }
    }
}

pub use yrs_impl::YrsDoc;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_doc_is_empty() {
        let d = YrsDoc::new();
        assert_eq!(d.text(), "");
    }

    #[test]
    fn set_text_then_read() {
        let mut d = YrsDoc::new();
        d.set_text("Hello, world").unwrap();
        assert_eq!(d.text(), "Hello, world");
    }

    #[test]
    fn snapshot_roundtrip() {
        let mut d = YrsDoc::new();
        d.set_text("a snapshot test").unwrap();
        let snap = d.encode_state();
        let d2 = YrsDoc::from_snapshot(&snap).unwrap();
        assert_eq!(d2.text(), "a snapshot test");
    }

    #[test]
    fn updates_are_commutative() {
        // Two replicas make independent edits to a shared base, exchange deltas, and converge.
        let mut base = YrsDoc::new();
        let base_update = base.set_text("shared base").unwrap();

        let mut a = YrsDoc::from_snapshot(&base.encode_state()).unwrap();
        let mut b = YrsDoc::from_snapshot(&base.encode_state()).unwrap();

        let _ = base_update; // base state already applied via snapshot

        let a_delta = a.set_text("shared base + A").unwrap();
        let b_delta = b.set_text("B + shared base").unwrap();

        // Apply in opposite orders on the two replicas.
        a.apply_update(&b_delta).unwrap();
        b.apply_update(&a_delta).unwrap();

        // Convergence: identical final text regardless of apply order.
        assert_eq!(a.text(), b.text());
    }

    #[test]
    fn apply_update_is_idempotent() {
        let mut a = YrsDoc::new();
        let delta = a.set_text("idempotent").unwrap();
        let mut b = YrsDoc::new();
        b.apply_update(&delta).unwrap();
        // Applying the same update twice changes nothing.
        b.apply_update(&delta).unwrap();
        assert_eq!(b.text(), "idempotent");
    }

    #[test]
    fn non_bmp_edit_roundtrips_and_converges() {
        // Emoji and astral-plane chars are 2 UTF-16 units each. Editing text that contains them and
        // then merging concurrent edits must converge and round-trip exactly — this catches the
        // UTF-16-vs-char indexing bug.
        let mut origin = YrsDoc::new();
        origin.set_text("hello 😀 world 𝕏 end").unwrap();
        assert_eq!(origin.text(), "hello 😀 world 𝕏 end");
        let snap = origin.encode_state();

        let mut a = YrsDoc::from_snapshot(&snap).unwrap();
        let mut b = YrsDoc::from_snapshot(&snap).unwrap();

        // A edits before the emoji; B edits after the astral char. Both spans cross multi-unit chars.
        let a_delta = a.set_text("HELLO 😀 world 𝕏 end").unwrap();
        let b_delta = b.set_text("hello 😀 world 𝕏 END").unwrap();

        a.apply_update(&b_delta).unwrap();
        b.apply_update(&a_delta).unwrap();
        assert_eq!(a.text(), b.text(), "non-BMP edits must converge");
        assert!(a.text().contains("HELLO"));
        assert!(a.text().contains("END"));
        assert!(a.text().contains('😀'));
        assert!(a.text().contains('𝕏'));
    }

    #[test]
    fn insert_emoji_into_middle_is_exact() {
        // Inserting an emoji between existing chars must not shift surrounding text.
        let mut d = YrsDoc::new();
        d.set_text("abcdef").unwrap();
        d.set_text("abc😀def").unwrap();
        assert_eq!(d.text(), "abc😀def");
        d.set_text("abc😀d🎉ef").unwrap();
        assert_eq!(d.text(), "abc😀d🎉ef");
    }

    #[test]
    fn incremental_edits_preserve_concurrent_changes() {
        // Build "line one\nline two" on a single doc, encode full state, fork two replicas, edit
        // different lines concurrently, then merge: both edits survive.
        let mut origin = YrsDoc::new();
        origin.set_text("line one\nline two").unwrap();
        let snap = origin.encode_state();

        let mut a = YrsDoc::from_snapshot(&snap).unwrap();
        let mut b = YrsDoc::from_snapshot(&snap).unwrap();

        let a_delta = a.set_text("LINE ONE\nline two").unwrap();
        let b_delta = b.set_text("line one\nLINE TWO").unwrap();

        a.apply_update(&b_delta).unwrap();
        b.apply_update(&a_delta).unwrap();
        assert_eq!(a.text(), b.text());
        // Both edits are present after the merge.
        assert!(a.text().contains("LINE ONE"));
        assert!(a.text().contains("LINE TWO"));
    }
}
