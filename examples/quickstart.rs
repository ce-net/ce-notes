//! A runnable walkthrough of the CE Notes API end to end, against a local CE node.
//!
//! Prerequisites: a CE node running locally (`ce start`) whose HTTP API is reachable at the URL
//! below. This example never touches the node's internals — it composes only the public `ce_notes`
//! library surface over the ce-rs / ce-coord SDK.
//!
//! Run with:
//! ```bash
//! cargo run --example quickstart
//! # or point at a non-default node / dirs:
//! CE_NODE_URL=http://127.0.0.1:8844 cargo run --example quickstart
//! ```
//!
//! It creates a throwaway space under a temp data dir, exercises notes, labels, pin/archive, a
//! checklist, search, and prints the results — then leaves the temp dir for inspection.

use std::path::PathBuf;

use anyhow::{Context, Result};
use ce_coord::Coord;
use ce_notes::core::{Color, NoteKind, Notes};
use ce_rs::CeClient;

#[tokio::main]
async fn main() -> Result<()> {
    let node_url =
        std::env::var("CE_NODE_URL").unwrap_or_else(|_| "http://127.0.0.1:8844".to_string());

    // A throwaway identity + data dir so this example never disturbs your real notebooks.
    let root: PathBuf = std::env::temp_dir().join(format!("ce-notes-quickstart-{}", std::process::id()));
    let identity_dir = root.join("identity");
    let data_dir = root.join("data");
    std::fs::create_dir_all(&identity_dir)?;
    std::fs::create_dir_all(&data_dir)?;

    let client = CeClient::new(node_url.clone());
    let coord = Coord::with_client(CeClient::new(node_url.clone()))
        .await
        .with_context(|| format!("connect to CE node at {node_url} (is `ce start` running?)"))?;
    let notes = Notes::open(&identity_dir, &data_dir, coord, client).await?;
    println!("this device: {}", notes.node_id());

    // --- A space with a couple of notes ---
    let space = notes.create_space("Quickstart").await?;
    println!("created space {}", space.id());

    let shopping = space.create_note("Shopping", None).await?;
    space.set_note_text(&shopping, "# Shopping\n\n- milk\n- bread\n").await?;

    let ideas = space.create_note("Ideas", None).await?;
    space.set_note_text(&ideas, "# Ideas\n\nbuild a local-first notes app").await?;

    // --- Organize: a label, a color, a pin ---
    let errands = space.create_label("errands", Color::Yellow).await?;
    space.add_note_label(&shopping, &errands).await?;
    space.set_color(&shopping, Color::Red).await?;
    space.set_pinned(&ideas, true).await?;

    space.pump_once().await?;
    println!("\nnotes (pinned first):");
    for h in space.notes().await {
        let pin = if h.pinned { "*" } else { " " };
        println!("  {pin} {}  {}  [{}]", h.note_id, h.title, h.color.name());
    }

    // --- A checklist note ---
    let groceries = space.create_note_kind("Groceries", None, NoteKind::Checklist).await?;
    let eggs = space.add_checklist_item(&groceries, "eggs").await?;
    space.add_checklist_item(&groceries, "butter").await?;
    space.set_checklist_checked(&groceries, &eggs, true).await?;
    space.pump_once().await?;
    println!("\nchecklist:");
    for i in space.checklist(&groceries).await? {
        println!("  {} {}", if i.checked { "[x]" } else { "[ ]" }, i.text);
    }

    // --- Search across titles, labels, and bodies ---
    println!("\nsearch \"milk\":");
    for h in space.search("milk").await? {
        println!("  {}  {}", h.note_id, h.title);
    }

    println!("\ndone. temp data dir: {}", root.display());
    Ok(())
}
