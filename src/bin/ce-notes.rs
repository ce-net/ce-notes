//! `ce-notes` — the CLI/TUI front-end for CE Notes.
//!
//! A thin shell over `ce_notes::core`. Every command opens the notes layer (identity + at-rest
//! store + ce-coord over the local node), does its work, and pumps the merge-set so newly-arrived
//! ops from other devices are applied before reading.

use std::path::PathBuf;

use anyhow::{Context, Result};
use ce_coord::Coord;
use ce_notes::core::{Color, NoteKind, Notes, Reminder, Role, Space};
use ce_rs::CeClient;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "ce-notes",
    about = "Local-first, end-to-end-encrypted CRDT notes on the CE mesh",
    version
)]
struct Cli {
    /// CE node HTTP API base URL.
    #[arg(long, default_value = "http://127.0.0.1:8844", global = true)]
    node_url: String,

    /// Identity directory (defaults to the CE node's identity dir).
    #[arg(long, global = true)]
    identity_dir: Option<PathBuf>,

    /// Data directory for local notes state (defaults to the CE data dir).
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,

    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Manage spaces (notebooks).
    #[command(subcommand)]
    Space(SpaceCmd),
    /// Create a new note in a space.
    New {
        #[arg(long)]
        space: String,
        #[arg(long)]
        folder: Option<String>,
        /// Note title.
        title: String,
    },
    /// List notes in a space.
    Ls {
        #[arg(long)]
        space: String,
    },
    /// Print a note's body.
    Cat {
        #[arg(long)]
        space: String,
        note_id: String,
    },
    /// Edit a note in $EDITOR; the saved text replaces the body (merged via CRDT).
    Edit {
        #[arg(long)]
        space: String,
        note_id: String,
    },
    /// Set a note's body from a string or a file (non-interactive edit).
    Set {
        #[arg(long)]
        space: String,
        note_id: String,
        /// Read body from this file instead of the inline text argument.
        #[arg(long)]
        file: Option<PathBuf>,
        /// Inline body text (used when --file is not given).
        #[arg(default_value = "")]
        text: String,
    },
    /// Attach a file to a note (encrypted, content-addressed).
    Attach {
        #[arg(long)]
        space: String,
        note_id: String,
        path: PathBuf,
    },
    /// Delete a note (tombstone; recoverable).
    Rm {
        #[arg(long)]
        space: String,
        note_id: String,
    },
    /// Pin or unpin a note (pinned notes sort to the top).
    Pin {
        #[arg(long)]
        space: String,
        note_id: String,
        /// Unpin instead of pin.
        #[arg(long)]
        off: bool,
    },
    /// Archive or unarchive a note (archived notes are hidden from the main list).
    Archive {
        #[arg(long)]
        space: String,
        note_id: String,
        /// Unarchive instead of archive.
        #[arg(long)]
        off: bool,
    },
    /// Set a note's color (default|red|orange|yellow|green|teal|blue|darkblue|purple|pink|brown|gray).
    Color {
        #[arg(long)]
        space: String,
        note_id: String,
        color: String,
    },
    /// Set or clear a note's reminder (unix-seconds due time; `--clear` to remove).
    Remind {
        #[arg(long)]
        space: String,
        note_id: String,
        /// Due time in unix seconds.
        #[arg(long)]
        at: Option<u64>,
        /// Clear the reminder.
        #[arg(long)]
        clear: bool,
    },
    /// List due/upcoming reminders in a space.
    Reminders {
        #[arg(long)]
        space: String,
    },
    /// Full-text search note titles, labels, and bodies in a space.
    Search {
        #[arg(long)]
        space: String,
        query: String,
    },
    /// List archived notes.
    Archived {
        #[arg(long)]
        space: String,
    },
    /// List trashed notes (tombstoned), restorable with `restore`.
    Trash {
        #[arg(long)]
        space: String,
    },
    /// Restore a trashed note back into the main list.
    Restore {
        #[arg(long)]
        space: String,
        note_id: String,
    },
    /// Manage labels.
    #[command(subcommand)]
    Label(LabelCmd),
    /// Manage a checklist note.
    #[command(subcommand)]
    Check(CheckCmd),
    /// Revoke a member and rotate the space key (owner only).
    Revoke {
        #[arg(long)]
        space: String,
        /// Member NodeId (64 hex chars).
        member: String,
    },
    /// Create an invite for another device/person by NodeId.
    Invite {
        #[arg(long)]
        space: String,
        /// Invitee NodeId (64 hex chars).
        #[arg(long)]
        to: String,
        /// Role: reader or writer.
        #[arg(long, default_value = "writer")]
        role: String,
        /// Expiry in days (0 = never).
        #[arg(long, default_value_t = 90)]
        expires_days: u64,
        /// Write the invite blob to this file (otherwise printed as hex to stdout).
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Import an invite blob produced by `invite`.
    Import {
        /// Invite blob file (or `-` to read hex from stdin).
        blob: String,
    },
    /// Pull updates from peers and print per-peer sync status for a space.
    Sync {
        #[arg(long)]
        space: String,
    },
    /// Print this device's NodeId (hex) — what others invite.
    Whoami,
}

#[derive(Subcommand)]
enum SpaceCmd {
    /// Create a new space.
    New { name: String },
    /// List spaces with local state.
    Ls,
}

#[derive(Subcommand)]
enum LabelCmd {
    /// Create a label.
    New {
        #[arg(long)]
        space: String,
        name: String,
        /// Label color (see `color` command for the palette).
        #[arg(long, default_value = "default")]
        color: String,
    },
    /// List labels in a space.
    Ls {
        #[arg(long)]
        space: String,
    },
    /// Delete a label.
    Rm {
        #[arg(long)]
        space: String,
        label_id: String,
    },
    /// Add a label to a note.
    Add {
        #[arg(long)]
        space: String,
        note_id: String,
        label_id: String,
    },
    /// Remove a label from a note.
    Del {
        #[arg(long)]
        space: String,
        note_id: String,
        label_id: String,
    },
    /// List notes carrying a label.
    Notes {
        #[arg(long)]
        space: String,
        label_id: String,
    },
}

#[derive(Subcommand)]
enum CheckCmd {
    /// Create a new checklist note.
    New {
        #[arg(long)]
        space: String,
        title: String,
    },
    /// List a checklist note's items.
    Ls {
        #[arg(long)]
        space: String,
        note_id: String,
    },
    /// Add an item to a checklist note.
    Add {
        #[arg(long)]
        space: String,
        note_id: String,
        text: String,
    },
    /// Check an item.
    Check {
        #[arg(long)]
        space: String,
        note_id: String,
        item_id: String,
    },
    /// Uncheck an item.
    Uncheck {
        #[arg(long)]
        space: String,
        note_id: String,
        item_id: String,
    },
    /// Delete an item.
    Rm {
        #[arg(long)]
        space: String,
        note_id: String,
        item_id: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    if let Err(e) = run(cli).await {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
    Ok(())
}

/// Default CE data/identity directories (matching the node's `ce` ProjectDirs layout).
fn ce_data_dir() -> Result<PathBuf> {
    let dirs = dirs_next::data_dir().context("no data dir on this platform")?;
    Ok(dirs.join("ce"))
}

async fn open_notes(cli: &Cli) -> Result<Notes> {
    let data_dir = match &cli.data_dir {
        Some(d) => d.clone(),
        None => ce_data_dir()?,
    };
    let identity_dir = match &cli.identity_dir {
        Some(d) => d.clone(),
        None => data_dir.join("identity"),
    };
    let client = CeClient::new(cli.node_url.clone());
    let coord = Coord::with_client(CeClient::new(cli.node_url.clone()))
        .await
        .context("connect to CE node (is `ce start` running?)")?;
    Notes::open(&identity_dir, &data_dir, coord, client).await
}

async fn open_space(notes: &Notes, space_id: &str) -> Result<Space> {
    let space = notes.open_space(space_id).await?;
    // Apply anything peers have sent before reading.
    space.pump_once().await?;
    Ok(space)
}

fn parse_role(s: &str) -> Result<Role> {
    match s.to_ascii_lowercase().as_str() {
        "owner" => Ok(Role::Owner),
        "writer" | "write" | "rw" => Ok(Role::Writer),
        "reader" | "read" | "ro" => Ok(Role::Reader),
        other => anyhow::bail!("unknown role '{other}' (use reader|writer)"),
    }
}

async fn run(cli: Cli) -> Result<()> {
    match &cli.cmd {
        Command::Whoami => {
            let notes = open_notes(&cli).await?;
            println!("{}", notes.node_id());
        }
        Command::Space(SpaceCmd::New { name }) => {
            let notes = open_notes(&cli).await?;
            let space = notes.create_space(name).await?;
            println!("created space {} \"{}\"", space.id(), name);
        }
        Command::Space(SpaceCmd::Ls) => {
            let notes = open_notes(&cli).await?;
            let metas = notes.space_metas()?;
            if metas.is_empty() {
                println!("no spaces yet — create one with: ce-notes space new \"Name\"");
            }
            for m in metas {
                println!("{}  {}  ({} members)", m.space_id, m.name, m.members.len());
            }
        }
        Command::New { space, folder, title } => {
            let notes = open_notes(&cli).await?;
            let s = open_space(&notes, space).await?;
            let id = s.create_note(title, folder.clone()).await?;
            println!("{id}");
        }
        Command::Ls { space } => {
            let notes = open_notes(&cli).await?;
            let s = open_space(&notes, space).await?;
            let notes_list = s.notes().await;
            if notes_list.is_empty() {
                println!("(no notes)");
            }
            for h in notes_list {
                println!("{}  {}", h.note_id, h.title);
            }
        }
        Command::Cat { space, note_id } => {
            let notes = open_notes(&cli).await?;
            let s = open_space(&notes, space).await?;
            print!("{}", s.note_text(note_id).await?);
        }
        Command::Set { space, note_id, file, text } => {
            let notes = open_notes(&cli).await?;
            let s = open_space(&notes, space).await?;
            let body = match file {
                Some(p) => std::fs::read_to_string(p).with_context(|| format!("read {}", p.display()))?,
                None => text.clone(),
            };
            s.set_note_text(note_id, &body).await?;
            println!("saved {note_id}");
        }
        Command::Edit { space, note_id } => {
            let notes = open_notes(&cli).await?;
            let s = open_space(&notes, space).await?;
            let current = s.note_text(note_id).await?;
            let edited = edit_in_editor(&current)?;
            s.set_note_text(note_id, &edited).await?;
            println!("saved {note_id}");
        }
        Command::Attach { space, note_id, path } => {
            let notes = open_notes(&cli).await?;
            let s = open_space(&notes, space).await?;
            let aref = s.attach(note_id, path).await?;
            println!("attached {} ({} bytes) cid={}", aref.name, aref.size, aref.cid);
        }
        Command::Rm { space, note_id } => {
            let notes = open_notes(&cli).await?;
            let s = open_space(&notes, space).await?;
            s.delete_note(note_id).await?;
            println!("deleted {note_id} (recoverable)");
        }
        Command::Invite { space, to, role, expires_days, out } => {
            let notes = open_notes(&cli).await?;
            let s = open_space(&notes, space).await?;
            let role = parse_role(role)?;
            let expires = if *expires_days == 0 {
                0
            } else {
                now_secs() + expires_days * 86_400
            };
            let blob = s.invite(to, role, expires).await?;
            match out {
                Some(p) => {
                    std::fs::write(p, &blob).with_context(|| format!("write {}", p.display()))?;
                    println!("invite written to {}", p.display());
                }
                None => println!("{}", hex::encode(&blob)),
            }
        }
        Command::Import { blob } => {
            let notes = open_notes(&cli).await?;
            let bytes = if blob == "-" {
                use std::io::Read;
                let mut s = String::new();
                std::io::stdin().read_to_string(&mut s)?;
                hex::decode(s.trim()).context("stdin is not valid hex")?
            } else {
                let raw = std::fs::read(blob).with_context(|| format!("read {blob}"))?;
                // Accept either a raw blob file or a hex-encoded one.
                match std::str::from_utf8(&raw).ok().and_then(|s| hex::decode(s.trim()).ok()) {
                    Some(decoded) => decoded,
                    None => raw,
                }
            };
            let s = notes.import_invite(&bytes).await?;
            println!("imported space {} \"{}\"", s.id(), s.meta().await.name);
        }
        Command::Sync { space } => {
            let notes = open_notes(&cli).await?;
            let s = open_space(&notes, space).await?;
            s.pump_once().await?;
            println!("per-peer sync status (device : applied version):");
            for (dev, v) in s.sync_status().await {
                let tag = if dev == notes.node_id() { " (this device)" } else { "" };
                println!("  {dev} : {v}{tag}");
            }
        }
        Command::Pin { space, note_id, off } => {
            let s = open_space(&open_notes(&cli).await?, space).await?;
            s.set_pinned(note_id, !*off).await?;
            println!("{} {note_id}", if *off { "unpinned" } else { "pinned" });
        }
        Command::Archive { space, note_id, off } => {
            let s = open_space(&open_notes(&cli).await?, space).await?;
            s.set_archived(note_id, !*off).await?;
            println!("{} {note_id}", if *off { "unarchived" } else { "archived" });
        }
        Command::Color { space, note_id, color } => {
            let s = open_space(&open_notes(&cli).await?, space).await?;
            let c = Color::parse(color)
                .ok_or_else(|| anyhow::anyhow!("unknown color '{color}'"))?;
            s.set_color(note_id, c).await?;
            println!("colored {note_id} {}", c.name());
        }
        Command::Remind { space, note_id, at, clear } => {
            let s = open_space(&open_notes(&cli).await?, space).await?;
            let reminder = if *clear {
                None
            } else {
                let due = at.ok_or_else(|| anyhow::anyhow!("pass --at <unix-seconds> or --clear"))?;
                Some(Reminder { due_unix: due, done: false })
            };
            s.set_reminder(note_id, reminder).await?;
            println!("reminder {} for {note_id}", if *clear { "cleared" } else { "set" });
        }
        Command::Reminders { space } => {
            let s = open_space(&open_notes(&cli).await?, space).await?;
            let due = s.reminders(now_secs()).await;
            if due.is_empty() {
                println!("(no reminders)");
            }
            for (id, title, r) in due {
                println!("{}  {title}  (due {})", id, r.due_unix);
            }
        }
        Command::Search { space, query } => {
            let s = open_space(&open_notes(&cli).await?, space).await?;
            let hits = s.search(query).await?;
            if hits.is_empty() {
                println!("(no matches)");
            }
            for h in hits {
                println!("{}  {}", h.note_id, h.title);
            }
        }
        Command::Archived { space } => {
            let s = open_space(&open_notes(&cli).await?, space).await?;
            for h in s.archived_notes().await {
                println!("{}  {}", h.note_id, h.title);
            }
        }
        Command::Trash { space } => {
            let s = open_space(&open_notes(&cli).await?, space).await?;
            for h in s.trashed_notes().await {
                println!("{}  {}", h.note_id, h.title);
            }
        }
        Command::Restore { space, note_id } => {
            let s = open_space(&open_notes(&cli).await?, space).await?;
            s.restore_note(note_id).await?;
            println!("restored {note_id}");
        }
        Command::Revoke { space, member } => {
            let s = open_space(&open_notes(&cli).await?, space).await?;
            s.revoke(member).await?;
            println!("revoked {member} and rotated the space key");
        }
        Command::Label(lc) => run_label(&cli, lc).await?,
        Command::Check(cc) => run_check(&cli, cc).await?,
    }
    Ok(())
}

async fn run_label(cli: &Cli, lc: &LabelCmd) -> Result<()> {
    let notes = open_notes(cli).await?;
    match lc {
        LabelCmd::New { space, name, color } => {
            let s = open_space(&notes, space).await?;
            let c = Color::parse(color).ok_or_else(|| anyhow::anyhow!("unknown color '{color}'"))?;
            let id = s.create_label(name, c).await?;
            println!("{id}");
        }
        LabelCmd::Ls { space } => {
            let s = open_space(&notes, space).await?;
            let labels = s.labels().await;
            if labels.is_empty() {
                println!("(no labels)");
            }
            for l in labels {
                println!("{}  {}  ({})", l.label_id, l.name, l.color.name());
            }
        }
        LabelCmd::Rm { space, label_id } => {
            let s = open_space(&notes, space).await?;
            s.delete_label(label_id).await?;
            println!("deleted label {label_id}");
        }
        LabelCmd::Add { space, note_id, label_id } => {
            let s = open_space(&notes, space).await?;
            s.add_note_label(note_id, label_id).await?;
            println!("labeled {note_id} with {label_id}");
        }
        LabelCmd::Del { space, note_id, label_id } => {
            let s = open_space(&notes, space).await?;
            s.remove_note_label(note_id, label_id).await?;
            println!("unlabeled {note_id}");
        }
        LabelCmd::Notes { space, label_id } => {
            let s = open_space(&notes, space).await?;
            for h in s.notes_with_label(label_id).await {
                println!("{}  {}", h.note_id, h.title);
            }
        }
    }
    Ok(())
}

async fn run_check(cli: &Cli, cc: &CheckCmd) -> Result<()> {
    let notes = open_notes(cli).await?;
    match cc {
        CheckCmd::New { space, title } => {
            let s = open_space(&notes, space).await?;
            let id = s.create_note_kind(title, None, NoteKind::Checklist).await?;
            println!("{id}");
        }
        CheckCmd::Ls { space, note_id } => {
            let s = open_space(&notes, space).await?;
            let items = s.checklist(note_id).await?;
            if items.is_empty() {
                println!("(no items)");
            }
            for i in items {
                let mark = if i.checked { "[x]" } else { "[ ]" };
                println!("{} {mark} {}", i.item_id, i.text);
            }
        }
        CheckCmd::Add { space, note_id, text } => {
            let s = open_space(&notes, space).await?;
            let id = s.add_checklist_item(note_id, text).await?;
            println!("{id}");
        }
        CheckCmd::Check { space, note_id, item_id } => {
            let s = open_space(&notes, space).await?;
            s.set_checklist_checked(note_id, item_id, true).await?;
            println!("checked {item_id}");
        }
        CheckCmd::Uncheck { space, note_id, item_id } => {
            let s = open_space(&notes, space).await?;
            s.set_checklist_checked(note_id, item_id, false).await?;
            println!("unchecked {item_id}");
        }
        CheckCmd::Rm { space, note_id, item_id } => {
            let s = open_space(&notes, space).await?;
            s.delete_checklist_item(note_id, item_id).await?;
            println!("removed {item_id}");
        }
    }
    Ok(())
}

fn now_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// The platform default editor, used when `$EDITOR` (and `$VISUAL`) are unset. On Windows there is
/// no `vi`, so fall back to `notepad`; elsewhere keep the POSIX `vi`.
#[cfg(windows)]
const DEFAULT_EDITOR: &str = "notepad";
#[cfg(not(windows))]
const DEFAULT_EDITOR: &str = "vi";

/// Open `$EDITOR` on a temp file seeded with `initial`, returning the saved contents.
fn edit_in_editor(initial: &str) -> Result<String> {
    let editor = std::env::var("VISUAL")
        .or_else(|_| std::env::var("EDITOR"))
        .unwrap_or_else(|_| DEFAULT_EDITOR.to_string());
    let mut path = std::env::temp_dir();
    path.push(format!("ce-notes-edit-{}.md", std::process::id()));
    std::fs::write(&path, initial)?;
    let status = std::process::Command::new(&editor)
        .arg(&path)
        .status()
        .with_context(|| format!("launch editor '{editor}'"))?;
    if !status.success() {
        anyhow::bail!("editor exited with failure; aborting edit");
    }
    let edited = std::fs::read_to_string(&path)?;
    let _ = std::fs::remove_file(&path);
    Ok(edited)
}
