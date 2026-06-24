# CE Notes

Local-first, end-to-end-encrypted, CRDT notes on the CE mesh — Anytype/Obsidian-class notes with
**no proprietary server**. Your notes live on your own devices, sync peer-to-peer over CE's libp2p
mesh, and the mesh (relays included) only ever sees ciphertext plus an authenticated sender NodeId.

CE Notes is an **application** built on CE primitives, layered:

```
CE Notes  →  ce-coord  →  ce-rs  →  local CE node  →  libp2p mesh
```

The node is untouched — there are no notes-specific endpoints. Everything composes from existing
primitives: mesh pub/sub + request/reply (via ce-coord), the content-addressed blob/object layer,
the local node identity key, and the `ce-cap` capability verifier for sharing.

## What it does

- **Multi-device sync, offline-first.** Every device is a CE NodeId with a full local replica. Edits
  made offline merge on reconnect with zero conflict UI.
- **End-to-end encryption.** One XChaCha20-Poly1305 content key per space (notebook), wrapped per
  device via X25519 (derived from each device's Ed25519 NodeId). CRDT updates are sealed before they
  hit the mesh. CE never decrypts anything.
- **Concurrent editing via a text CRDT.** Note bodies are Yjs-compatible (`yrs`) documents; updates
  are commutative, so the union across every device's log converges — no lost edits. The doc is
  pinned to UTF-16 offset counting, so emoji and astral-plane characters edit correctly and the wire
  format stays interoperable with a future CodeMirror+Yjs web client.
- **Keep-class organization.** Notes carry **pin**, **archive**, **color** (a 12-hue palette),
  many-to-many **labels**, **reminders** (time-based), and **folders**. The main list is pinned-first
  then newest; archived notes are hidden but searchable; deleted notes are a recoverable **trash**.
- **Checklists.** A note can be a structured checklist — a CRDT log of `{id, text, checked, order}`
  items with add / check / edit / reorder / delete, reconciled last-writer-wins per item, distinct
  from the freeform markdown body.
- **Full-text search.** `search <space> <query>` matches all whitespace-split terms across decrypted
  titles, label names, and bodies (markdown text or checklist items). Search runs entirely locally
  over plaintext this device holds — server-side search is impossible by construction (the mesh only
  ever sees ciphertext).
- **Attachments.** Files are encrypted with a per-file key and stored as content-addressed objects
  (`put_object`), referenced by `{cid, key}` inside the encrypted CRDT. Bounded at 32 MiB (streaming
  chunked encryption for larger files is a documented follow-up).
- **Sharing by capability, with revocation.** Share a notebook by minting a `ce-cap` grant and
  wrapping the space key to the invitee's device key — no device allowlists, trust is the signed
  capability chain plus the wrapped key. **Roles are enforced app-side** (a Reader cannot author or
  publish write-ops locally). **Revoke** rotates the space key: it bumps the epoch, generates a fresh
  key, re-wraps it to every remaining member, and seals all future ops under the new epoch.

## Architecture

A **space** (notebook / vault) is the unit of sharing and the unit of encryption. It holds notes,
folders, and attachment refs. Each device runs, per space:

- a **writer-log** (ce-coord `Replicated<MergeLog>`) — its own outbound encrypted updates;
- a **reader-log** for every other member device.

The union of these per-writer logs is the space's op-set. Because the payloads ([`NoteOp`]) wrap
commutative CRDT updates, order across writers does not matter — this sidesteps ce-coord's
single-writer limitation for the edit path entirely. The minimal addition is `MergeLog` / `MergeSet`
(in `core::mergelog`), prototyped here and proposable upstream to ce-coord.

**The index** (note headers, folders, labels) is itself a CRDT: a newline-delimited JSON log inside a
single index `Y.Text`, reduced to derived state by **last-writer-wins per id** — notes by their
`updated_at` clock, folders/labels by a deterministic tombstone-then-JSON total order. Two devices'
logs therefore converge to the same index regardless of the order lines arrive in. The log
auto-compacts to one canonical line per live id once it grows past a threshold; because every line
feeds the same LWW reducer, a compacted log merged with concurrent un-compacted appends still
converges identically.

**Checklists** use the same pattern at the note level: the body `Y.Text` of a checklist note holds a
log of `{item_id, text, checked, order}` records, reduced LWW per `item_id`, with tombstone deletes.

```
NoteDoc (yrs Y.Text)  --update bytes-->  seal(space_key)  -->  NoteOp{doc_id, epoch, nonce, ct}
       ^ local, offline                    ^ XChaCha20-Poly1305      |
                                                                     v
                                       ce-coord writer-log  -->  pub/sub topic notes-<space>
```

### Crate layout

`ce-notes` is one crate exposing both a library and a binary:

- `ce_notes::core` — the library:
  - `crypto` — XChaCha20-Poly1305 envelope, X25519-from-Ed25519 derivation, key wrap/unwrap.
  - `model` — `SpaceMeta`, `MemberEntry`, `Role`, `NoteHeader`, `Folder`, `AttachmentRef`, `NoteOp`,
    `Invite`.
  - `notedoc` — the `NoteDoc` trait + the `yrs`-backed `YrsDoc` (CRDT is swappable behind the trait).
  - `mergelog` — `MergeLog` state machine + `MergeSet` (N readers + 1 writer over ce-coord).
  - `store` — local, at-rest-encrypted persistence (sealed under a device-local key).
  - `notes` — the high-level `Notes` (device handle) and `Space` (open notebook) API.
- the `ce-notes` binary — the CLI.

## CLI

```
ce-notes whoami                                   # this device's NodeId (what others invite)
ce-notes space new "Work"                         # create a notebook
ce-notes space ls                                 # list notebooks
ce-notes new   --space <id> "Note title"          # create a note
ce-notes ls    --space <id>                        # list notes (pinned first, archived hidden)
ce-notes cat   --space <id> <note_id>              # print a note body
ce-notes edit  --space <id> <note_id>              # edit in $EDITOR
ce-notes set   --space <id> <note_id> --file body.md   # non-interactive body set
ce-notes attach --space <id> <note_id> ./diagram.png   # encrypted attachment (<= 32 MiB)
ce-notes rm    --space <id> <note_id>              # tombstone delete (recoverable)

# organization
ce-notes pin     --space <id> <note_id> [--off]    # pin / unpin
ce-notes archive --space <id> <note_id> [--off]    # archive / unarchive
ce-notes color   --space <id> <note_id> red        # set color (palette below)
ce-notes remind  --space <id> <note_id> --at <unix> # set a reminder (or --clear)
ce-notes reminders --space <id>                    # list due/upcoming reminders
ce-notes search  --space <id> "milk work"          # full-text search title/labels/body
ce-notes archived --space <id>                     # list archived notes
ce-notes trash   --space <id>                      # list trashed notes
ce-notes restore --space <id> <note_id>            # restore a trashed note

# labels
ce-notes label new   --space <id> "work" --color blue
ce-notes label ls    --space <id>
ce-notes label add   --space <id> <note_id> <label_id>
ce-notes label del   --space <id> <note_id> <label_id>
ce-notes label notes --space <id> <label_id>       # notes carrying a label
ce-notes label rm    --space <id> <label_id>

# checklists
ce-notes check new     --space <id> "Groceries"
ce-notes check add     --space <id> <note_id> "eggs"
ce-notes check ls      --space <id> <note_id>
ce-notes check check   --space <id> <note_id> <item_id>
ce-notes check uncheck --space <id> <note_id> <item_id>
ce-notes check rm      --space <id> <note_id> <item_id>

# sharing
ce-notes invite --space <id> --to <node_id> --role writer --out invite.bin
ce-notes import invite.bin                          # join a shared notebook
ce-notes revoke --space <id> <member_node_id>       # revoke a member + rotate the key (owner only)
ce-notes sync  --space <id>                          # pull peers + per-peer sync status
```

Color palette: `default red orange yellow green teal blue darkblue purple pink brown gray`.

Global flags: `--node-url`, `--identity-dir`, `--data-dir` (all default to the CE node's layout).

## Encryption details

- **Space content key**: 32-byte XChaCha20-Poly1305, generated by the owner at space creation. Each
  CRDT update is sealed with a fresh 24-byte random nonce; the key epoch is bound in as AEAD
  associated data.
- **Key wrapping**: X25519 sealed box. An ephemeral X25519 keypair does ECDH against the member's
  long-term X25519 public key; the shared secret is hashed (domain-separated, binding both public
  keys) into an AEAD key that seals the space key. Only the member's secret recovers it.
- **Identity → X25519**: a device's Ed25519 node secret yields its X25519 secret (the Ed25519 signing
  scalar) and public key (Montgomery form of the Ed25519 public point). A sender can wrap to a peer
  knowing only its NodeId via the Edwards→Montgomery birational map.
- **At rest**: local `space.json` / `*.ydoc` / `applied.json` are sealed under a device-local key
  derived from the node identity secret — a stolen disk without the key file yields nothing.

**Revocation tradeoff (documented):** rotating the space key gives a forward-secrecy boundary only —
old ciphertext stays decryptable to anyone who already held the old key. This is the honest
local-first tradeoff.

## Sharing

1. `ce-notes invite --space <id> --to <node_id> --role writer` mints a `ce-cap` grant rooted at this
   device, wraps the current space key to the invitee's X25519 key, adds the invitee as a member, and
   emits an invite blob (`{ space_meta, wrapped_key, grant_token }`).
2. The invitee runs `ce-notes import <blob>`: it unwraps the key, persists the metadata, and starts
   reader-logs for every member device.

## Robustness & limits

- **Atomic at-rest persistence.** Every sealed file (`space.json`, `*.ydoc`, `applied.json`) is
  written to a temp file in the same directory, fsync'd, then renamed over the target — a crash or
  disk-full mid-write can never truncate or corrupt an existing file.
- **Bounded index, O(1) edits.** The per-space index is a newline-delimited LWW log inside a single
  CRDT text. Reconciliation is **last-writer-wins by `updated_at`** (not line order), so two devices'
  logs converge regardless of arrival order; the log auto-**compacts** (one canonical line per live
  id) once it passes a size threshold, keeping per-edit cost and storage bounded.
- **Resume without re-draining history.** The per-writer drained high-water marks are persisted
  (`applied.json`) and restored on reopen (clamped to the live log length), so a restart applies only
  genuinely-new ops instead of replaying the whole history. Re-application is idempotent, so a stale
  or partial marks file can only cost redundant work, never lose data.
- **DoS / size guards.** Note bodies ≤ 1 MiB, attachments ≤ 32 MiB (rejected by `fstat` *before*
  reading into memory), ≤ 256 members per space, ≤ 64 labels per note, invite blobs ≤ 4 MiB (checked
  before deserialization), and oversized index/checklist log lines are skipped on parse.
- **Diagnosable divergence.** A failed op decrypt is no longer silently swallowed — an
  expected cross-epoch skip logs at `debug`, an *unexpected* current-epoch failure (corrupt or forged
  op) logs at `warn` with the doc id and epoch.

## Status

What is **real and tested**: the crypto envelope and key wrapping, X25519-from-Ed25519 derivation,
the `NoteDoc` CRDT (commutativity + idempotence, including non-BMP/emoji text), the LWW index
reduction + compaction, at-rest atomic sealed persistence + resume marks, pin/archive/color/labels/
reminders/folders/trash, structured checklists, local full-text search, reader-role enforcement, and
key-rotation-on-revoke. The pure logic is covered by unit + property tests; the full mesh stack
(`Notes → Space → MergeSet → ce-coord → node`) is exercised by `tests/live_node.rs` against an
ephemeral real node whenever a release `ce` binary is present (it skips cleanly otherwise).

Deferred / out of scope (honest follow-ups, not faked):

- **Streaming attachment encryption** for files larger than 32 MiB (today the whole file is buffered
  and sealed in one pass; the cap prevents unbounded memory).
- **Forward secrecy of past content on revoke.** Rotation cuts off *future* content only — anyone who
  already held the old key can still read old ciphertext. This is the documented local-first tradeoff.
- **Location-based reminders and reminder notification delivery** (the model + listing of due/upcoming
  time-based reminders is implemented; wiring a notifier is a later integration).
- **Inline images / rich text / MIME bodies** (bodies are markdown text; attachments are referenced,
  not embedded).
- **TUI / web / mobile clients** — the CLI covers every operation; the UTF-16 wire format is chosen so
  a CodeMirror+Yjs web client can interoperate later.
- **SSE push** — still on the ce-coord poll; the SSE wrapper is a future ce-rs change.
- **Two-device live sync over two physical nodes** — `scripts/two-device-demo.sh` /
  `scripts/two-device-demo.ps1` drive it end to end against two running `ce` nodes.

## Build & test

```bash
cargo build
cargo test
```

The library, unit, and property tests need no infrastructure. `tests/live_node.rs` auto-runs against
an ephemeral node when a release `ce` binary is found (or `CE_BIN` is set), and skips otherwise. The
two-device demo needs a running CE node on each device. See `examples/quickstart.rs` for a runnable
walkthrough of the API.
