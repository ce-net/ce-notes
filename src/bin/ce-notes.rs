//! `ce-notes` — the CLI/TUI front-end for CE Notes.
//!
//! A thin shell over `ce_notes::core`. Every command opens the notes layer (identity + at-rest
//! store + ce-coord over the local node), does its work, and pumps the merge-set so newly-arrived
//! ops from other devices are applied before reading.

use std::path::PathBuf;

use anyhow::{Context, Result};
use ce_coord::Coord;
use ce_notes::core::{Notes, Role, Space};
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
