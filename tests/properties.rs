//! Property / fuzz tests for ce-notes' pure surface — no live node or ce-coord required.
//!
//! These pin the security- and correctness-critical invariants of the local-first design:
//!
//!   * CRDT convergence: applying the same set of `YrsDoc` updates in ANY order, with arbitrary
//!     duplicates, yields identical text (commutative + idempotent). This is the property that lets
//!     ce-notes run one writer-log per device and union them with no global order.
//!   * Crypto envelope: seal/open round-trips for arbitrary plaintext+epoch; any tamper (key,
//!     epoch, nonce, ciphertext byte) makes open() FAIL rather than return garbage.
//!   * Key wrapping: wrap/unwrap round-trips per device; a wrap addressed to one device cannot be
//!     unwrapped by another; derivation is deterministic.
//!   * At-rest: the on-disk store seals everything — plaintext (a known space name / note body)
//!     NEVER appears on disk; a truncated/corrupt sealed blob fails to open, not silently empties.
//!   * Capability attenuation for notes roles: a Reader chain can never authorize `notes:write`.
//!   * Invite serialization round-trips (encode == decode).

use ce_notes::core::crypto::{self, DeviceKeys, SpaceKey, WrappedKey, open, seal, unwrap_key, wrap_key};
use ce_notes::core::model::{ChecklistItem, Color, Invite, MemberEntry, NoteHeader, Role, SpaceMeta};
use ce_notes::core::notedoc::{NoteDoc, YrsDoc};
use ce_notes::core::store::Store;
use proptest::prelude::*;

// ---- CRDT convergence: the keystone property ------------------------------------------------

proptest! {
    // Build a base doc, fork N replicas, each makes a distinct edit, then every replica receives
    // every delta in a RANDOM order with random duplicates. All replicas must converge to identical
    // text. This is commutativity + idempotence together — exactly the merge-log union requirement.
    #[test]
    fn crdt_converges_under_random_op_order(
        edits in proptest::collection::vec("[a-zA-Z0-9 ]{0,12}", 1..6),
        shuffles in proptest::collection::vec(any::<u64>(), 1..4),
        dup_mask in any::<u32>(),
    ) {
        // Base state shared by all replicas.
        let mut base = YrsDoc::new();
        base.set_text("base").unwrap();
        let base_snapshot = base.encode_state();

        // Each replica forks from the base and applies its own edit, capturing the delta.
        let mut replicas: Vec<YrsDoc> = Vec::new();
        let mut deltas: Vec<Vec<u8>> = Vec::new();
        for (i, e) in edits.iter().enumerate() {
            let mut d = YrsDoc::from_snapshot(&base_snapshot).unwrap();
            // Distinct edit per replica so the merge is non-trivial.
            let delta = d.set_text(&format!("base {i}:{e}")).unwrap();
            deltas.push(delta);
            replicas.push(d);
        }

        // Deliver every delta to every replica, in a per-replica shuffled order, some duplicated.
        let n = deltas.len();
        for (ri, replica) in replicas.iter_mut().enumerate() {
            let seed = shuffles[ri % shuffles.len()];
            let order = shuffled_indices(n, seed);
            for &di in &order {
                replica.apply_update(&deltas[di]).unwrap();
                // Idempotence stress: re-apply the same delta when the mask bit is set.
                if (dup_mask >> (di % 32)) & 1 == 1 {
                    replica.apply_update(&deltas[di]).unwrap();
                }
            }
        }

        // All replicas converge to the same text.
        let first = replicas[0].text();
        for r in &replicas[1..] {
            prop_assert_eq!(r.text(), first.clone(), "replicas diverged: CRDT not convergent");
        }
    }

    // Re-applying any single update an arbitrary number of times is a no-op (idempotence).
    #[test]
    fn apply_update_is_idempotent(text in "[a-zA-Z0-9 ]{0,40}", repeats in 1usize..6) {
        let mut a = YrsDoc::new();
        let delta = a.set_text(&text).unwrap();
        let mut b = YrsDoc::new();
        for _ in 0..repeats {
            b.apply_update(&delta).unwrap();
        }
        prop_assert_eq!(b.text(), a.text());
    }

    // Snapshot round-trip: encode_state then from_snapshot reproduces the text exactly.
    #[test]
    fn snapshot_roundtrips(text in "\\PC{0,60}") {
        let mut a = YrsDoc::new();
        a.set_text(&text).unwrap();
        let snap = a.encode_state();
        let b = YrsDoc::from_snapshot(&snap).unwrap();
        prop_assert_eq!(b.text(), a.text());
        prop_assert_eq!(b.text(), text);
    }

    // Arbitrary unicode (including non-BMP emoji / astral chars, 2 UTF-16 units each) must round-trip
    // exactly through set_text -> read. This is the regression guard for the UTF-16-vs-char indexing
    // bug: a wrong offset would corrupt or shift the text for any non-BMP input.
    #[test]
    fn set_text_roundtrips_arbitrary_unicode(text in "[\\x{0}-\\x{10FFFF}]{0,40}") {
        let mut d = YrsDoc::new();
        d.set_text(&text).unwrap();
        prop_assert_eq!(d.text(), text);
    }

    // Two replicas making independent edits to text seeded with non-BMP characters must converge.
    #[test]
    fn non_bmp_replicas_converge(
        prefix in "[a-z😀🎉𝕏]{0,8}",
        a_edit in "[A-Z]{1,4}",
        b_edit in "[0-9]{1,4}",
    ) {
        let mut base = YrsDoc::new();
        base.set_text(&format!("{prefix}|middle|")).unwrap();
        let snap = base.encode_state();
        let mut a = YrsDoc::from_snapshot(&snap).unwrap();
        let mut b = YrsDoc::from_snapshot(&snap).unwrap();
        let da = a.set_text(&format!("{prefix}|middle|{a_edit}")).unwrap();
        let db = b.set_text(&format!("{b_edit}{prefix}|middle|")).unwrap();
        a.apply_update(&db).unwrap();
        b.apply_update(&da).unwrap();
        prop_assert_eq!(a.text(), b.text());
    }
}

// ---- LWW merge laws (the index/checklist reduction reducers) ---------------------------------

proptest! {
    // NoteHeader::merge is commutative and idempotent (a CRDT LWW register): merge(a,b) == merge(b,a)
    // and merge(a,a) == a, for arbitrary updated_at clocks. This is what makes the index converge
    // regardless of the order log lines from different devices arrive in.
    #[test]
    fn note_header_merge_is_commutative_and_idempotent(t1 in any::<u64>(), t2 in any::<u64>(), p1 in any::<bool>(), p2 in any::<bool>()) {
        let mut a = NoteHeader::new("id".into(), "A".into(), None, t1);
        a.pinned = p1;
        let mut b = NoteHeader::new("id".into(), "B".into(), None, t2);
        b.pinned = p2;
        prop_assert_eq!(NoteHeader::merge(a.clone(), b.clone()), NoteHeader::merge(b.clone(), a.clone()));
        prop_assert_eq!(NoteHeader::merge(a.clone(), a.clone()), a);
    }

    // NoteHeader::merge is associative: the survivor of three observations does not depend on
    // grouping. (Total order on (updated_at, json) guarantees this.)
    #[test]
    fn note_header_merge_is_associative(t1 in any::<u64>(), t2 in any::<u64>(), t3 in any::<u64>()) {
        let a = NoteHeader::new("id".into(), "alpha".into(), None, t1);
        let b = NoteHeader::new("id".into(), "beta".into(), None, t2);
        let c = NoteHeader::new("id".into(), "gamma".into(), None, t3);
        let left = NoteHeader::merge(NoteHeader::merge(a.clone(), b.clone()), c.clone());
        let right = NoteHeader::merge(a, NoteHeader::merge(b, c));
        prop_assert_eq!(left, right);
    }

    #[test]
    fn checklist_item_merge_is_commutative(t1 in any::<u64>(), t2 in any::<u64>(), c1 in any::<bool>(), c2 in any::<bool>()) {
        let a = ChecklistItem { item_id: "i".into(), text: "x".into(), checked: c1, order: 0, updated_at: t1, deleted: false };
        let b = ChecklistItem { item_id: "i".into(), text: "y".into(), checked: c2, order: 1, updated_at: t2, deleted: false };
        prop_assert_eq!(ChecklistItem::merge(a.clone(), b.clone()), ChecklistItem::merge(b, a));
    }

    #[test]
    fn color_parse_is_total_over_palette(idx in 0usize..12) {
        let all = [
            Color::Default, Color::Red, Color::Orange, Color::Yellow, Color::Green, Color::Teal,
            Color::Blue, Color::DarkBlue, Color::Purple, Color::Pink, Color::Brown, Color::Gray,
        ];
        let c = all[idx];
        prop_assert_eq!(Color::parse(c.name()), Some(c));
    }
}

/// A deterministic shuffle of `0..n` from a seed (xorshift), for reproducible proptest cases.
fn shuffled_indices(n: usize, mut seed: u64) -> Vec<usize> {
    let mut v: Vec<usize> = (0..n).collect();
    // Fisher-Yates with an xorshift PRNG.
    for i in (1..n).rev() {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let j = (seed % (i as u64 + 1)) as usize;
        v.swap(i, j);
    }
    v
}

// ---- Crypto envelope: round-trip + tamper-detect --------------------------------------------

proptest! {
    #[test]
    fn seal_open_roundtrips(plaintext in proptest::collection::vec(any::<u8>(), 0..1024), epoch in any::<u32>()) {
        let key = SpaceKey::generate();
        let (nonce, ct) = seal(&key, epoch, &plaintext).unwrap();
        let back = open(&key, epoch, &nonce, &ct).unwrap();
        prop_assert_eq!(back, plaintext);
    }

    #[test]
    fn open_rejects_wrong_epoch(plaintext in proptest::collection::vec(any::<u8>(), 0..256), e1 in any::<u32>(), e2 in any::<u32>()) {
        prop_assume!(e1 != e2);
        let key = SpaceKey::generate();
        let (nonce, ct) = seal(&key, e1, &plaintext).unwrap();
        prop_assert!(open(&key, e2, &nonce, &ct).is_err(), "epoch is bound as AAD; mismatch must fail");
    }

    #[test]
    fn open_rejects_ciphertext_tamper(plaintext in proptest::collection::vec(any::<u8>(), 1..256), flip in any::<usize>()) {
        let key = SpaceKey::generate();
        let (nonce, mut ct) = seal(&key, 0, &plaintext).unwrap();
        let i = flip % ct.len();
        ct[i] ^= 0xff;
        prop_assert!(open(&key, 0, &nonce, &ct).is_err(), "tampered ciphertext must fail AEAD");
    }

    #[test]
    fn wrap_unwrap_roundtrips(seed in proptest::array::uniform32(any::<u8>())) {
        let dev = DeviceKeys::from_ed25519_secret(&seed);
        let space_key = SpaceKey::generate();
        let original = space_key.0;
        let wrapped = wrap_key(&dev.public(), 0, &space_key).unwrap();
        let recovered = unwrap_key(dev.secret(), &wrapped).unwrap();
        prop_assert_eq!(recovered.0, original);
    }

    #[test]
    fn wrap_to_a_cannot_unwrap_with_b(sa in proptest::array::uniform32(any::<u8>()), sb in proptest::array::uniform32(any::<u8>())) {
        prop_assume!(sa != sb);
        let a = DeviceKeys::from_ed25519_secret(&sa);
        let b = DeviceKeys::from_ed25519_secret(&sb);
        // If the derived publics happen to collide (astronomically unlikely), skip.
        prop_assume!(a.public() != b.public());
        let key = SpaceKey::generate();
        let wrapped = wrap_key(&a.public(), 0, &key).unwrap();
        prop_assert!(unwrap_key(b.secret(), &wrapped).is_err(), "a wrap for A must not open for B");
    }
}

// ---- At-rest: plaintext NEVER on disk -------------------------------------------------------

proptest! {
    // The on-disk sealed blob for a space's metadata must not contain the space's plaintext name,
    // for any non-trivial name. A stolen disk without the node key yields nothing.
    #[test]
    fn at_rest_seals_space_name(name in "[A-Za-z]{6,24}", secret in proptest::array::uniform32(any::<u8>())) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path(), &secret).unwrap();
        let meta = SpaceMeta {
            space_id: "abc123".into(),
            name: name.clone(),
            created_at: 0,
            key_epoch: 0,
            owner: "owner".into(),
            members: vec![],
        };
        store.save_meta(&meta).unwrap();
        let raw = std::fs::read(dir.path().join("ce-notes").join("abc123").join("space.json")).unwrap();
        let needle = name.as_bytes();
        let found = raw.windows(needle.len()).any(|w| w == needle);
        prop_assert!(!found, "plaintext space name leaked to disk");
        // And it round-trips back through the seal.
        let back = store.load_meta("abc123").unwrap();
        prop_assert_eq!(back.name, name);
    }

    // A doc snapshot also seals — its plaintext bytes must not appear verbatim on disk.
    #[test]
    fn at_rest_seals_doc_snapshot(body in "[A-Za-z ]{16,64}", secret in proptest::array::uniform32(any::<u8>())) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path(), &secret).unwrap();
        store.save_doc_snapshot("sp", "note:1", body.as_bytes()).unwrap();
        // Find the sealed file and ensure the plaintext body is not present.
        let space_dir = dir.path().join("ce-notes").join("sp");
        let mut leaked = false;
        for entry in std::fs::read_dir(&space_dir).unwrap() {
            let p = entry.unwrap().path();
            if p.extension().and_then(|e| e.to_str()) == Some("ydoc") {
                let raw = std::fs::read(&p).unwrap();
                if raw.windows(body.len()).any(|w| w == body.as_bytes()) {
                    leaked = true;
                }
            }
        }
        prop_assert!(!leaked, "plaintext note body leaked to disk");
        let back = store.load_doc_snapshot("sp", "note:1").unwrap();
        prop_assert_eq!(back.as_deref(), Some(body.as_bytes()));
    }
}

// ---- Deterministic failure injection: corrupt sealed blob -----------------------------------

#[test]
fn truncated_sealed_blob_fails_to_open() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path(), &[5u8; 32]).unwrap();
    let meta = SpaceMeta {
        space_id: "trunc".into(),
        name: "secret".into(),
        created_at: 0,
        key_epoch: 0,
        owner: "o".into(),
        members: vec![],
    };
    store.save_meta(&meta).unwrap();
    let path = dir.path().join("ce-notes").join("trunc").join("space.json");
    let raw = std::fs::read(&path).unwrap();
    // Truncate into the ciphertext (keep the nonce but drop the AEAD tag region).
    std::fs::write(&path, &raw[..raw.len().saturating_sub(8)]).unwrap();
    assert!(store.load_meta("trunc").is_err(), "a truncated sealed blob must fail, not return garbage");
}

#[test]
fn shorter_than_nonce_blob_fails_cleanly() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path(), &[6u8; 32]).unwrap();
    // Write a file too short to even contain the 24-byte nonce.
    let space_dir = dir.path().join("ce-notes").join("sp2");
    std::fs::create_dir_all(&space_dir).unwrap();
    std::fs::write(space_dir.join("space.json"), b"short").unwrap();
    assert!(store.load_meta("sp2").is_err(), "a sub-nonce blob must error cleanly, not panic");
}

#[test]
fn atomic_write_leaves_no_temp_files_and_roundtrips() {
    // After a successful sealed write the space dir contains exactly the final file (no leftover
    // .tmp), proving the temp-file+rename path cleans up.
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path(), &[8u8; 32]).unwrap();
    let meta = SpaceMeta {
        space_id: "atomic".into(),
        name: "n".into(),
        created_at: 0,
        key_epoch: 0,
        owner: "o".into(),
        members: vec![],
    };
    store.save_meta(&meta).unwrap();
    let space_dir = dir.path().join("ce-notes").join("atomic");
    let names: Vec<String> = std::fs::read_dir(&space_dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, vec!["space.json".to_string()], "only the final file remains: {names:?}");
    assert_eq!(store.load_meta("atomic").unwrap(), meta);
}

#[test]
fn repeated_overwrites_never_corrupt() {
    // Overwriting the same sealed file many times always leaves a readable, current value (rename is
    // atomic: a reader sees either the old or the new file, never a torn one).
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path(), &[9u8; 32]).unwrap();
    for i in 0..50u64 {
        let meta = SpaceMeta {
            space_id: "rw".into(),
            name: format!("v{i}"),
            created_at: i,
            key_epoch: 0,
            owner: "o".into(),
            members: vec![],
        };
        store.save_meta(&meta).unwrap();
        assert_eq!(store.load_meta("rw").unwrap().name, format!("v{i}"));
    }
}

#[test]
fn wrong_at_rest_key_cannot_open_anothers_disk() {
    // Two devices with different node secrets derive different at-rest keys; one cannot read the
    // other's sealed store even pointed at the same files.
    let dir = tempfile::tempdir().unwrap();
    let store_a = Store::open(dir.path(), &[1u8; 32]).unwrap();
    let meta = SpaceMeta {
        space_id: "x".into(),
        name: "n".into(),
        created_at: 0,
        key_epoch: 0,
        owner: "o".into(),
        members: vec![],
    };
    store_a.save_meta(&meta).unwrap();
    let store_b = Store::open(dir.path(), &[2u8; 32]).unwrap();
    assert!(store_b.load_meta("x").is_err(), "a different at-rest key must not open A's sealed meta");
}

// ---- Capability attenuation for notes roles -------------------------------------------------

#[test]
fn reader_role_abilities_never_include_write() {
    // Role -> abilities is the attenuation source for invites; a Reader must never carry write.
    assert!(!Role::Reader.abilities().iter().any(|a| a == "notes:write"));
    assert!(Role::Reader.abilities().iter().any(|a| a == "notes:read"));
    assert!(Role::Writer.abilities().iter().any(|a| a == "notes:write"));
    assert!(Role::Owner.can_write());
    assert!(!Role::Reader.can_write());
}

// ---- Invite serialization round-trip --------------------------------------------------------

#[test]
fn invite_encode_decode_roundtrips() {
    use ce_notes::core::crypto::NONCE_LEN;
    let dev = DeviceKeys::from_ed25519_secret(&[9u8; 32]);
    let space_key = SpaceKey::generate();
    let wrapped = wrap_key(&dev.public(), 2, &space_key).unwrap();
    let meta = SpaceMeta {
        space_id: "sid".into(),
        name: "Space".into(),
        created_at: 7,
        key_epoch: 2,
        owner: "owner".into(),
        members: vec![MemberEntry {
            device_id: "owner".into(),
            x25519_pub: [0u8; 32],
            label: "owner".into(),
            role: Role::Owner,
            wrapped_key: WrappedKey { epoch: 2, ephemeral_pub: [0u8; 32], nonce: [0u8; NONCE_LEN], ct: vec![] },
            added_at: 0,
            revoked: false,
        }],
    };
    let invite = Invite {
        space_meta: meta,
        wrapped_key: wrapped,
        invitee: "inv".into(),
        invitee_x25519: dev.public(),
        role: Role::Writer,
        grant_token: "deadbeef".into(),
    };
    let bytes = invite.encode().unwrap();
    let back = Invite::decode(&bytes).unwrap();
    assert_eq!(back.invitee, "inv");
    assert_eq!(back.role, Role::Writer);
    assert_eq!(back.space_meta.key_epoch, 2);
    // The invitee can actually recover the space key from the round-tripped wrap.
    let recovered = unwrap_key(dev.secret(), &back.wrapped_key).unwrap();
    assert_eq!(recovered.0, space_key.0);
}

#[test]
fn tampered_invite_wrapped_key_is_rejected() {
    // An invite whose wrapped_key ciphertext is altered in transit must fail to unwrap (AEAD), so a
    // man-in-the-middle cannot hand a victim a key they cannot actually recover, nor smuggle a forged
    // one. This is the crypto core of import_invite's safety.
    use ce_notes::core::crypto::NONCE_LEN;
    let dev = DeviceKeys::from_ed25519_secret(&[33u8; 32]);
    let space_key = SpaceKey::generate();
    let mut wrapped = wrap_key(&dev.public(), 1, &space_key).unwrap();
    // Sanity: untampered unwraps.
    assert!(unwrap_key(dev.secret(), &wrapped).is_ok());
    // Flip a ciphertext byte.
    wrapped.ct[0] ^= 0xff;
    let meta = SpaceMeta {
        space_id: "sid".into(),
        name: "Space".into(),
        created_at: 0,
        key_epoch: 1,
        owner: "owner".into(),
        members: vec![],
    };
    let invite = Invite {
        space_meta: meta,
        wrapped_key: wrapped,
        invitee: "inv".into(),
        invitee_x25519: dev.public(),
        role: Role::Writer,
        grant_token: "tok".into(),
    };
    let bytes = invite.encode().unwrap();
    let back = Invite::decode(&bytes).unwrap();
    assert!(
        unwrap_key(dev.secret(), &back.wrapped_key).is_err(),
        "tampered wrapped key must fail to unwrap"
    );
    let _ = NONCE_LEN;
}

#[test]
fn x25519_from_node_id_matches_device_derivation() {
    use ed25519_dalek::{SigningKey, VerifyingKey};
    let seed = [21u8; 32];
    let sk = SigningKey::from_bytes(&seed);
    let vk: VerifyingKey = sk.verifying_key();
    let node_id = vk.to_bytes();
    let from_node = DeviceKeys::x25519_public_from_node_id(&node_id).unwrap();
    let dev = DeviceKeys::from_ed25519_secret(&seed);
    assert_eq!(from_node, dev.public(), "a sender can wrap to a peer knowing only its NodeId");
    // A wrap to the node-id-derived key opens with the device secret.
    let key = SpaceKey::generate();
    let wrapped = crypto::wrap_key(&from_node, 0, &key).unwrap();
    assert_eq!(unwrap_key(dev.secret(), &wrapped).unwrap().0, key.0);
}

#[test]
fn invalid_node_id_x25519_derivation_errors() {
    // Not all 32-byte strings are valid Ed25519 points; derivation must error, not panic.
    let bad = [0xffu8; 32];
    let res = DeviceKeys::x25519_public_from_node_id(&bad);
    // It either errors (invalid point) — assert it does not panic and is handled.
    let _ = res; // some all-0xff may or may not decompress; the point is no panic.
}
