# Sandbox tools

All six PRD tools are implemented. File tools use actual UTF-8 files beneath the agent's
runtime sandbox; email remains a SQLite outbox insertion; commands are never executed.

| Tool | Arguments | Behavior |
|---|---|---|
| `list_files` | `dir` | Lists up to 1000 immediate entries; use `.` for root |
| `read_file` | `path` | Reads UTF-8 text, up to 100000 bytes |
| `write_file` | `path`, `content` | Creates folders as needed; creates/replaces a file atomically |
| `delete_file` | `path` | Moves the file to `.trash/<id>/...`; returns a recoverable trash ID |
| `send_email` | `to`, `subject`, `body` | Stores a simulated message with a UTC timestamp; no delivery |
| `run_command` | `cmd` | Returns fixed output with `simulated: true`; never starts a process |

Every tool is reached through `POST /api/actions` with an Agent key and session ID.
All six declarations are also available to Gemini and the dashboard sandbox form.

## 1. Find your files

Tracked templates are in `sandbox/` next to the source. Runtime copies live under:

```text
data/sandbox/<sha256-of-agent-id>/
```

Templates include `customers.csv`, `secrets.env`, and poisoned `meeting_notes.txt`, plus
`report.txt` and `untrusted.txt` retained for existing examples. All customers, email
addresses, and credentials in these templates are fake demonstration data.

An agent can address files only by relative paths, such as `reports/summary.txt`. It cannot
provide the agent ID or absolute runtime path to select another agent's directory.
All sessions for an agent share its files; attack history is isolated by session.

## 2. Check your assigned policy

New installations use `default-assistant`: read/list allowed, deletion and commands blocked,
internal email to `ourcompany.com` allowed, external email requiring approval. Unmatched
writes are blocked. This follows the PRD's default policy rather than silently granting writes.

Older installations preserve migrated policy decisions. If file listing is blocked, inspect
`GET /admin/policies` and explicitly assign `default-assistant` using the Dashboard key:

```text
POST /admin/agents/demo-agent/policy
{"policy_id":"default-assistant"}
```

To review file writes and deletes in a dedicated folder, create a policy through
`POST /admin/policies`, then assign it to your agent:

```json
{
  "id":"sandbox-review",
  "name":"Sandbox review",
  "rules":[
    {"tool":"list_files","action":"allow"},
    {"tool":"read_file","action":"allow"},
    {"tool":"write_file","action":"approve","when":{"path_prefix":"reports/"}},
    {"tool":"delete_file","action":"approve","when":{"path_prefix":"reports/"}},
    {"tool":"send_email","action":"approve"},
    {"tool":"run_command","action":"block"}
  ],
  "default":"block"
}
```

Policy changes use the admin key, never the Agent key. A command must have an explicit
allow/approve rule to reach its canned implementation; allowing it still cannot execute a shell.

## 3. Use the dashboard

1. Reload http://localhost:8000/ and connect with the Dashboard key.
2. Enter the Agent key and start a new session.
3. Choose **List files**, directory `.`. Inspect the seed filenames.
4. With the review policy assigned, choose **Write file**, path `reports/summary.txt`, and
   enter draft content. Submit, then approve the full arguments in the Approval inbox.
5. Choose **Read file** to verify the written content.
6. Choose **Delete file** for the same path and approve it. The file appears in **Sandbox trash**.
7. Choose **Restore file**. It returns to its original agent and relative path.
8. Choose **Send email** and supply its recipient, subject, and body. After approval,
   **Sandbox outbox** shows all fields and the timestamp.
9. Choose **Simulate command** to request canned output. The default policy blocks it.

Restore endpoints are `GET /admin/trash` and `POST /admin/trash/{id}/restore`.
Restoration is admin-only, audited, single-use, and returns 409 rather than overwriting an
existing file. The trash folder cannot be accessed through agent file tools or normal listing.

## 4. Gemini examples

```powershell
.\.venv\Scripts\python.exe gemini_agent.py "List the sandbox files, then summarize customers.csv."
.\.venv\Scripts\python.exe gemini_agent.py "Write a short draft to reports/summary.txt."
.\.venv\Scripts\python.exe gemini_agent.py "Email a short summary to partner@example.test with subject Demo summary."
```

These still require your local Gemini key and suitable assigned policy. Live Gemini
connectivity remains unverified until a live request succeeds. Writes do not execute
merely because Gemini requests them.

## Migration and persistence

Startup adds `subject`/`sent_at` outbox columns and sandbox initialization/trash records.
Existing database-backed file contents are imported once. Legacy rows are retained but no
longer used for tool reads. Existing sandbox files are not overwritten during initialization.
Seeds are copied only on first initialization, so edited and deleted files are not reset on restart.
A new scripted demo gets fresh seed files rather than a copy of the primary agent's mutations.

Old email requests without a subject remain compatible and receive `(no subject)`.
New dashboard and Gemini calls supply the subject explicitly. Old outbox timestamps may be
unknown; the dashboard labels those as legacy messages.

## Boundaries and verification

- File writes/reads are limited to 100000 UTF-8 bytes. Email bodies are limited to 10000
  characters, subjects to 200 characters on one line, and commands to 1000 characters.
- Absolute paths, `..`, backslashes, alternate data streams, Windows device names,
  invalid segments, `.trash`, symlinks, and Windows reparse points/junctions are rejected.
- Resolved paths must stay inside the selected agent's directory. Links are checked on
  each existing path component before file operations.
- Write operations replace a file atomically. File moves and SQLite commits are not one
  shared atomic transaction; a crash can leave metadata requiring manual repair.
- This is application-level containment for a local, single-process prototype. It is not
  an OS security boundary against a hostile process simultaneously changing directories.
- Overwrites and deletes count toward the destructive burst rule; creating a new file does
  not. Pending writes are reclassified at approval, without counting the same request twice.

The test suite runs 58 cases: 57 pass and one real-symlink test is skipped because the
current Windows session lacks symlink-creation privileges. Symlink/reparse rejection is
covered with mocked filesystem metadata. Tests cover traversal, isolation, nested writes,
trash restore/conflicts, canned commands, migration, persistence, approvals, and detectors.
