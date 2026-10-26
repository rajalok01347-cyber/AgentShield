# LLM record and replay

The cache applies only to Gemini model responses. AgentShield continues to execute policy
checks, detectors, sandbox tools, human approvals, and audit writes on every run.

## Modes

Set `LLM_MODE` or pass `--llm-mode` (the command-line flag takes precedence).

| Mode | Gemini | Cache behavior |
|---|---|---|
| `live` | Called every turn | Never reads or writes cache entries |
| `record` | Called every turn | Saves each successful validated model response, replacing an entry for the same key |
| `replay` | Never called | Loads only matching entries; a miss or invalid recording stops with an error |

Replay requires the AgentShield Agent key, but does not ask for a Gemini key. It still
connects to the local AgentShield gateway. It is offline with respect to Google, not
with respect to your running local gateway.

The runner explicitly prints:

> Agent responses are replayed; security decisions are live.

## Step 1: start AgentShield

Open a terminal in the project folder and start the backend as described in README.md:

```powershell
.\.venv\Scripts\python.exe -u -m uvicorn app:app --host 127.0.0.1 --port 8000
```

Keep it running. Open http://localhost:8000/ and connect the dashboard with its Dashboard key.

## Step 2: record a simple Gemini task

In a second terminal, in the same project folder:

```powershell
$env:LLM_MODE = "record"
.\.venv\Scripts\python.exe gemini_agent.py "Read report.txt."
```

Enter the Gemini API key and AgentShield Agent key at the hidden prompts, or use the
existing environment variables. Never paste credentials into source files or chat.

Each model turn prints `LLM recorded: <key prefix>`. Confirm that Gemini actually requested
the file read in the dashboard. The live model may choose its own calls; caching does not
force it to follow any particular action script.

## Step 3: replay the same task

```powershell
$env:LLM_MODE = "replay"
.\.venv\Scripts\python.exe gemini_agent.py "Read report.txt."
```

Use the same model name, exact task text, tool definitions, and initial sandbox state.
Only the Agent key is needed. The terminal prints `LLM replay: <key prefix>`.
Refresh the dashboard: this is a fresh session, request, and audit entry, even though
Gemini's response was loaded from the cache. Repeat the command to rehearse again.

## Step 4: record and replay approval

```powershell
$env:LLM_MODE = "record"
.\.venv\Scripts\python.exe gemini_agent.py "Email a short greeting to partner@example.test with subject Demo greeting."
```

Refresh the dashboard and approve or reject the pending email. Allow the model to finish
its response so the follow-up turn is recorded too. Then repeat in replay mode:

```powershell
$env:LLM_MODE = "replay"
.\.venv\Scripts\python.exe gemini_agent.py "Email a short greeting to partner@example.test with subject Demo greeting."
```

Human review happens again. Approval is never replayed automatically. To reach the recorded
follow-up answer, make the same approval decision. A different decision creates a different
model request, which needs its own recording.

## Step 5: switch back to live

```powershell
$env:LLM_MODE = "live"
.\.venv\Scripts\python.exe gemini_agent.py "Read report.txt."
```

Or use a flag for a single invocation:

```powershell
.\.venv\Scripts\python.exe gemini_agent.py --llm-mode replay "Read report.txt."
```

## Cache location and format

Default: `data/shield.db`, the same local SQLite database as AgentShield. If
`AGENTSHIELD_DATA` is set for the runner, its database is used. The runner and backend
should use the intended configuration consistently.

Override with `LLM_CACHE_PATH` or `--cache-db`:

```powershell
.\.venv\Scripts\python.exe gemini_agent.py --llm-mode record --cache-db data/rehearsal.db "Read report.txt."
```

The `llm_cache` table is created when record or replay opens the cache. Each row has
`key`, `request_json`, `response_json`, `created_at`, and `response_hash`.
The key is SHA-256 of canonical JSON containing the model, message history, tool definitions,
system instruction, generation settings, function-calling mode, and cache format version.
Object-key order does not matter; message, rule-result, and tool-array order still matter.

`response_json` stores validated model content, including function-call IDs, every returned
part, and thought signatures. Provider billing/usage counters are not needed for replay.
The response hash detects accidental corruption; this is not a signed or tamper-proof archive.
Only successful responses are recorded. Provider errors, rate limits, incomplete content,
and malformed content are not saved. API authentication headers are never part of the key
or recording. Tasks and tool outputs are intentionally saved, so recordings can contain
sensitive text if you use real data. Keep this demo restricted to fake data.

Default recordings and SQLite files/sidecars are ignored by Git. Do not commit custom
recording files under other names or upload them without reviewing their contents.

## Why fresh IDs do not break replay

Operational request/session IDs stay in the runner and dashboard rather than being sent
back to Gemini. Email row IDs/timestamps and deletion trash IDs are also omitted from the
model-facing result. This behavior is the same in live, record, and replay modes.
Tool-call IDs from Gemini itself are preserved exactly.

Meaningful results remain unchanged: file contents, recipients, subjects, bodies, policy
reasons, decisions, detector rules, and overwrite flags. A file's literal content is never
edited just because it contains a field name such as `id` or `sent_at`.

## Recording different security branches

Record every branch needed for a demonstration. Use a separate cache file for each variant,
for example `--cache-db data/approved.db` and `--cache-db data/rejected.db`. Use separate
ON/OFF cache files when the full agent shield-toggle integration is completed.

Record mode always calls Gemini and replaces matching entries. Real Gemini responses can
have new function-call IDs or thought signatures even for the same first task. Re-recording
another branch into the same file can therefore replace the common first response and make
older follow-up entries unreachable. A single cache can retain multiple decision branches
when their common model responses match exactly; the tests demonstrate that case with
simulated responses. Separate files avoid that requirement for real recordings. The existing dashboard ON/OFF comparison
is still a scripted tool demo; the CLI agent has no shield bypass or admin credential.

Sandbox changes matter. For example, replaying a write against an existing file returns
`overwritten: true`, while the original creation returned `false`. Deleting a missing file,
changing a policy, taking a different approval decision, or changing tool definitions can
cause a cache miss. Restore the intended test state or record that branch; do not hide
changed results or silently fall back to Google.

A cache miss at a later turn does not undo earlier live actions. Inspect the dashboard and
outbox before retrying a run that already submitted actions. Do not treat replay as a dry run.

## Verification and remaining work

The suite has 70 cases: 69 pass and the existing host-dependent symlink case is skipped.
Cache tests cover persistence, canonical keys, live bypass, record replacement, strict
replay misses, corrupt entries, provider failures, metadata normalization, repeated replay,
fresh gateway decisions, separate decision branches, and fresh human approvals/outbox entries.
Tests use simulated provider responses and the real gateway. They do not claim successful
live Gemini connectivity or real Google recordings; a local Gemini key is still required.

Full six-step PRD demo integration, remaining API-contract alignment, and final security
documentation/rehearsal remain separate milestones.
