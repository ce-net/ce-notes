//! The multi-writer "merge log": the one minimal addition the notes design needs on top of
//! ce-coord's single-writer [`Replicated`](ce_coord::Replicated).
//!
//! ce-coord gives an ordered, authenticated, gap-repaired, catch-up-capable log *per writer*. A
//! notes space needs **any** device to edit offline without a single-writer outage stalling edits.
//! The design's answer (§5–6): run **one writer-log per device** and take the **set union** across
//! all of them. Each per-writer stream still rides ce-coord's exactly-once/in-order machinery; the
//! union converges because the payloads ([`NoteOp`]) wrap a CRDT whose updates are commutative.
//!
//! [`MergeLog`] is the trivial [`StateMachine`] each per-writer log replicates: it just accumulates
//! the ops it receives, in order, with a high-water mark so a consumer can drain only what is new.
//! [`MergeSet`] wires N readers + 1 writer together and exposes "give me every op I haven't seen
//! yet across all writers" — the Space layer decrypts those and applies them to the CRDT docs.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use ce_coord::{Coord, Replicated, StateMachine, Version};

use super::model::NoteOp;

/// The per-writer state machine: an append-only list of the [`NoteOp`]s that writer has published.
/// Deterministic and order-preserving (ce-coord applies in version order), exactly what a CRDT
/// union needs.
#[derive(Default)]
pub struct MergeLog {
    ops: Vec<NoteOp>,
}

impl StateMachine for MergeLog {
    type Op = NoteOp;

    fn apply(&mut self, op: NoteOp) {
        self.ops.push(op);
    }
}

impl MergeLog {
    /// Number of ops applied so far (equals this writer's applied version).
    pub fn len(&self) -> usize {
        self.ops.len()
    }

    /// True if no ops have been applied.
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    /// The ops at index `from..` (i.e. versions `from+1..`). Cheap clone of the tail.
    pub fn ops_from(&self, from: usize) -> Vec<NoteOp> {
        if from >= self.ops.len() { Vec::new() } else { self.ops[from..].to_vec() }
    }
}

/// One device's view of a space's replicated op-set: its own writer-log plus a reader-log per peer
/// device. Drain [`new_ops`](MergeSet::new_ops) to get every op (from any writer) not yet consumed.
pub struct MergeSet {
    /// This device's writer-log — its outbound encrypted updates.
    writer: Replicated<MergeLog>,
    /// `device_id -> reader-log` for every *other* member device.
    readers: HashMap<String, Replicated<MergeLog>>,
    /// High-water mark per log (`self` plus each peer): how many of its ops we've already drained.
    drained: HashMap<String, usize>,
    /// This device's own id (the writer-log's key in `drained`).
    self_id: String,
}

impl MergeSet {
    /// Open the merge set for `name` on this device. `self_id` is this device's NodeId hex;
    /// `peer_ids` are the *other* member devices whose logs to follow.
    pub async fn open(
        coord: &Coord,
        name: &str,
        self_id: &str,
        peer_ids: &[String],
    ) -> Result<MergeSet> {
        let writer = Replicated::<MergeLog>::writer(coord.clone(), name).await?;
        let mut readers = HashMap::new();
        for peer in peer_ids {
            if peer == self_id {
                continue; // never follow our own writer-log as a reader
            }
            let r = Replicated::<MergeLog>::reader(coord.clone(), name, peer).await?;
            readers.insert(peer.clone(), r);
        }
        let mut drained = HashMap::new();
        drained.insert(self_id.to_string(), 0usize);
        for peer in readers.keys() {
            drained.insert(peer.clone(), 0usize);
        }
        Ok(MergeSet { writer, readers, drained, self_id: self_id.to_string() })
    }

    /// Add a peer reader-log after construction (e.g. a newly added member). Idempotent.
    pub async fn add_peer(&mut self, coord: &Coord, name: &str, peer_id: &str) -> Result<()> {
        if peer_id == self.self_id || self.readers.contains_key(peer_id) {
            return Ok(());
        }
        let r = Replicated::<MergeLog>::reader(coord.clone(), name, peer_id).await?;
        self.readers.insert(peer_id.to_string(), r);
        self.drained.entry(peer_id.to_string()).or_insert(0);
        Ok(())
    }

    /// Publish one op from this device. Returns the assigned [`Version`] in this device's writer-log.
    pub async fn publish(&self, op: NoteOp) -> Result<Version> {
        self.writer.propose(op).await
    }

    /// Drain every op (across this device's writer-log and all peer reader-logs) not yet returned by
    /// a previous call. The Space layer decrypts and applies these to its CRDT docs. Order across
    /// writers does not matter — the payloads are commutative CRDT updates.
    pub fn new_ops(&mut self) -> Vec<NoteOp> {
        let mut out = Vec::new();

        // Our own writer-log first (so local edits show even before any peer connects).
        let seen = self.drained.get(&self.self_id).copied().unwrap_or(0);
        let fresh = self.writer.read(|log| log.ops_from(seen));
        if !fresh.is_empty() {
            self.drained.insert(self.self_id.clone(), seen + fresh.len());
            out.extend(fresh);
        }

        // Then each peer's reader-log.
        for (peer, reader) in &self.readers {
            let seen = self.drained.get(peer).copied().unwrap_or(0);
            let fresh = reader.read(|log| log.ops_from(seen));
            if !fresh.is_empty() {
                self.drained.insert(peer.clone(), seen + fresh.len());
                out.extend(fresh);
            }
        }
        out
    }

    /// Per-writer applied versions, for a sync-status display: `(device_id, applied_version)`.
    pub fn sync_status(&self) -> Vec<(String, Version)> {
        let mut v = vec![(self.self_id.clone(), self.writer.version())];
        for (peer, reader) in &self.readers {
            v.push((peer.clone(), reader.version()));
        }
        v
    }

    /// A watch receiver that fires whenever this device's own writer-log advances.
    pub fn writer_watch(&self) -> tokio::sync::watch::Receiver<Version> {
        self.writer.version_watch()
    }

    /// Shared handle to every reader's version watch, keyed by device id (for a UI sync gutter).
    pub fn reader_watches(&self) -> HashMap<String, tokio::sync::watch::Receiver<Version>> {
        self.readers.iter().map(|(k, r)| (k.clone(), r.version_watch())).collect()
    }
}

/// A cheap clonable wrapper so the Space can share a [`MergeSet`] across tasks behind a lock.
pub type SharedMergeSet = Arc<tokio::sync::Mutex<MergeSet>>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::crypto::NONCE_LEN;

    fn op(doc: &str) -> NoteOp {
        NoteOp { doc_id: doc.into(), epoch: 0, nonce: [0u8; NONCE_LEN], ct: vec![1, 2, 3] }
    }

    #[test]
    fn mergelog_accumulates_in_order() {
        let mut log = MergeLog::default();
        assert!(log.is_empty());
        log.apply(op("a"));
        log.apply(op("b"));
        assert_eq!(log.len(), 2);
        let tail = log.ops_from(1);
        assert_eq!(tail.len(), 1);
        assert_eq!(tail[0].doc_id, "b");
    }

    #[test]
    fn ops_from_past_end_is_empty() {
        let mut log = MergeLog::default();
        log.apply(op("a"));
        assert!(log.ops_from(5).is_empty());
        assert!(log.ops_from(1).is_empty());
        assert_eq!(log.ops_from(0).len(), 1);
    }
}
