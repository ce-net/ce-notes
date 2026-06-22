//! Live end-to-end test for ce-notes against a real ephemeral CE node + ce-coord.
//!
//! Exercises the FULL stack — `Notes` -> `Space` -> `MergeSet` -> ce-coord -> node mesh — that the
//! pure unit/property tests cannot reach:
//!
//!   1. open a device, create a space, create notes, set bodies;
//!   2. `pump_once` drains this device's own writer-log into the index + bodies (the self-sync path
//!      that ce-coord's per-writer log drives over the live node);
//!   3. titles/headers/folders derive correctly through the index CRDT;
//!   4. persistence: reopening the space from the at-rest store reproduces the notes (sealed on disk);
//!   5. an invite is minted (a real `ce-cap` chain) and imported by a SECOND device handle pointed at
//!      the same node, recovering the space key — the capability/key-handoff path end to end.
//!
//! Not `#[ignore]`d: runs whenever the release `ce` binary exists; SKIPS cleanly otherwise. No
//! Docker/GPU — notes are pure mesh + blob + coord.

use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::Duration;

use ce_coord::Coord;
use ce_identity::Identity;
use ce_notes::core::Notes;
use ce_rs::CeClient;

fn find_ce_binary() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("CE_BIN") {
        let p = PathBuf::from(p);
        if p.exists() {
            return Some(p);
        }
    }
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut dir = manifest.as_path();
    loop {
        for rel in [".cargo-shared/release/ce", "target/release/ce"] {
            let cand = dir.join(rel);
            if cand.exists() {
                return Some(cand);
            }
        }
        match dir.parent() {
            Some(p) => dir = p,
            None => break,
        }
    }
    None
}

struct Node {
    child: Child,
    data_dir: PathBuf,
    api: String,
    token: String,
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.data_dir);
    }
}

fn spawn_node(ce: &PathBuf, api_port: u16, p2p_port: u16) -> Node {
    let data_dir = std::env::temp_dir().join(format!(
        "ce-notes-live-{}-{}-{}",
        std::process::id(),
        api_port,
        rand_suffix()
    ));
    std::fs::create_dir_all(&data_dir).unwrap();
    let child = Command::new(ce)
        .arg("--data-dir")
        .arg(&data_dir)
        .arg("start")
        .arg("--no-mine")
        .arg("--api-port")
        .arg(api_port.to_string())
        .arg("--port")
        .arg(p2p_port.to_string())
        .arg("--ephemeral")
        .arg("--no-mdns")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn ce node");
    let token = {
        let path = data_dir.join("api.token");
        let mut t = String::new();
        for _ in 0..200 {
            if let Ok(s) = std::fs::read_to_string(&path) {
                if !s.trim().is_empty() {
                    t = s.trim().to_string();
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(!t.is_empty(), "node never wrote api.token");
        t
    };
    Node { child, data_dir, api: format!("http://127.0.0.1:{api_port}"), token }
}

fn rand_suffix() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.subsec_nanos() as u64).unwrap_or(0)
}

async fn wait_healthy(c: &CeClient) {
    for _ in 0..200 {
        if c.health().await.unwrap_or(false) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("node never healthy");
}

/// Build a client whose token is freshly read from disk (guards against a token rewrite right after
/// health), and wait until an authenticated write succeeds.
async fn auth_client(node: &Node) -> CeClient {
    for _ in 0..200 {
        let token = std::fs::read_to_string(node.data_dir.join("api.token"))
            .map(|t| t.trim().to_string())
            .unwrap_or_else(|_| node.token.clone());
        let c = CeClient::with_token(node.api.clone(), Some(token));
        if c.put_blob(b"auth-probe".to_vec()).await.is_ok() {
            return c;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("node never accepted an authenticated write");
}

#[tokio::test]
async fn notes_full_lifecycle_over_live_node() {
    let Some(ce) = find_ce_binary() else {
        eprintln!("SKIP: no release `ce` binary found (set CE_BIN or build it); skipping live test");
        return;
    };

    let node = spawn_node(&ce, 18970, 14970);
    wait_healthy(&CeClient::with_token(node.api.clone(), Some(node.token.clone()))).await;
    let client = auth_client(&node).await;

    // Device A: its own identity dir + data dir, both under a temp root we clean up.
    let work = std::env::temp_dir().join(format!("ce-notes-work-{}-{}", std::process::id(), rand_suffix()));
    let id_dir_a = work.join("idA");
    let data_dir_a = work.join("dataA");
    std::fs::create_dir_all(&id_dir_a).unwrap();
    std::fs::create_dir_all(&data_dir_a).unwrap();

    let coord_a = Coord::with_client(client.clone()).await.expect("coord A");
    let notes_a = Notes::open(&id_dir_a, &data_dir_a, coord_a, client.clone())
        .await
        .expect("open notes A");

    // --- Create a space + notes ---
    let space = notes_a.create_space("Work").await.expect("create space");
    let space_id = space.id().to_string();
    let n1 = space.create_note("Shopping", None).await.expect("create note");
    space
        .set_note_text(&n1, "# Shopping\n\n- milk\n- bread\n")
        .await
        .expect("set text");

    // Drain our own writer-log into the index/bodies.
    space.pump_once().await.expect("pump");

    // --- Headers + body derive correctly ---
    let headers = space.notes().await;
    assert_eq!(headers.len(), 1, "exactly one note listed");
    assert_eq!(headers[0].title, "Shopping", "title derived from first heading");
    let body = space.note_text(&n1).await.expect("body");
    assert!(body.contains("milk") && body.contains("bread"), "body persisted: {body:?}");

    // A folder + a second note.
    let folder = space.create_folder("Lists", None).await.expect("folder");
    let n2 = space.create_note("Ideas", Some(folder.clone())).await.expect("note 2");
    space.set_note_text(&n2, "# Ideas\n\nbuild ce-notes tests").await.expect("set 2");
    space.pump_once().await.expect("pump 2");
    assert_eq!(space.notes().await.len(), 2, "two notes after second create");
    assert_eq!(space.folders().await.len(), 1, "one folder");

    // Sync status reports this device's own writer-log advanced.
    let status = space.sync_status().await;
    assert!(status.iter().any(|(_, v)| *v > 0), "writer-log version advanced");

    // --- Delete is a tombstone (note disappears from listing, recoverable model) ---
    space.delete_note(&n2).await.expect("delete");
    space.pump_once().await.expect("pump 3");
    assert_eq!(space.notes().await.len(), 1, "deleted note no longer listed");

    // --- Persistence: reopen the space from the at-rest store (sealed on disk) ---
    drop(space);
    let reopened = notes_a.open_space(&space_id).await.expect("reopen space");
    reopened.pump_once().await.expect("pump reopened");
    let body_after = reopened.note_text(&n1).await.expect("body after reopen");
    assert!(
        body_after.contains("milk"),
        "note body survived reopen from sealed at-rest store: {body_after:?}"
    );

    // The on-disk space.json must be sealed — the plaintext space name must not appear.
    let space_json = data_dir_a.join("ce-notes").join(&space_id).join("space.json");
    if let Ok(raw) = std::fs::read(&space_json) {
        assert!(
            !raw.windows(4).any(|w| w == b"Work"),
            "space name must be sealed at rest, not plaintext on disk"
        );
    }

    // --- Invite: mint a real ce-cap grant for a second device and import it ---
    // Device B: a fresh identity = a fresh NodeId the owner invites.
    let id_dir_b = work.join("idB");
    let data_dir_b = work.join("dataB");
    std::fs::create_dir_all(&id_dir_b).unwrap();
    std::fs::create_dir_all(&data_dir_b).unwrap();
    // `Notes::open` loads the identity directly from `identity_dir` (not a nested `identity/` dir),
    // so generate B's key at the SAME path so the invited node id matches what B will load.
    let b_identity = Identity::load_or_generate(&id_dir_b).expect("B id");
    let b_node_id = b_identity.node_id_hex();

    let invite_bytes = reopened
        .invite(&b_node_id, ce_notes::core::Role::Writer, 0)
        .await
        .expect("mint invite");
    assert!(!invite_bytes.is_empty(), "invite encodes to bytes");

    // B opens its own Notes handle on the same node and imports the invite.
    let coord_b = Coord::with_client(client.clone()).await.expect("coord B");
    let notes_b = Notes::open(&id_dir_b, &data_dir_b, coord_b, client.clone())
        .await
        .expect("open notes B");
    assert_eq!(notes_b.node_id(), b_node_id, "B's loaded identity matches the invited node id");

    let space_b = notes_b.import_invite(&invite_bytes).await.expect("import invite");
    assert_eq!(space_b.id(), space_id, "B opened the same space via the invite");
    // B recovered the space key (import_invite unwraps it); B can read/derive the index once synced.
    // We don't assert cross-device convergence here (single-node, two coord pumps share one inbox
    // ring); the key-handoff + capability mint/import is the property under test and it succeeded.

    // An invite addressed to a DIFFERENT node id must be rejected by B.
    let wrong = reopened
        .invite(&"00".repeat(32), ce_notes::core::Role::Reader, 0)
        .await
        .expect("mint invite for stranger");
    let rejected = notes_b.import_invite(&wrong).await;
    assert!(rejected.is_err(), "B must reject an invite not addressed to it");

    // Cleanup the working dirs (the node is cleaned by Node::drop).
    let _ = std::fs::remove_dir_all(&work);
}
