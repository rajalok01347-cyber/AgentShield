# Security notes

AgentShield is a local teaching demo. It uses fake files, simulated commands and a local outbox instead of real email. It is not designed to run on a network or the internet.

## Threat model

The agent (Gemini) is treated as untrusted: it can make mistakes, be tricked by hidden instructions in a file (prompt injection), or be asked outright to leak data. AgentShield limits what that agent can do with its tools and makes every decision visible to the person running the demo.

Out of scope: an attacker who already controls the laptop, the Python process, or the `data/` folder.

## Local access model

- On first start the backend creates a Dashboard key and an Agent key and saves them in `data/keys.json` (ignored by Git). Deleting `data/` creates new keys and also deletes the Gemini replay cache.
- The dashboard page receives the Dashboard key in its HTML so it connects without a login. This is only acceptable because:
  - `start.ps1` binds Uvicorn to `127.0.0.1`, and
  - `TrustedHostMiddleware` rejects any Host header other than `localhost` or `127.0.0.1`.
  Do not change the host, forward the port, or put the app behind a proxy.
- The Agent key stays inside the backend for dashboard-started runs and is never sent to the browser. Agent keys are stored in the database as SHA-256 hashes.
- The Gemini API key lives only in `.env` (ignored by Git) and is sent only to Google, only in `live` and `record` modes.

## Protections

| Layer | What it stops |
|---|---|
| **Task check** (before Gemini) | Tasks that plainly ask to send a sensitive-looking file (`secrets.env`, credentials, passwords, API keys) to an outside email address. Gemini is never called. |
| **Policy** (every tool call) | Ordered rules allow, block, or hold an action for approval. Anything unmatched is blocked. |
| **Attack detector** (every tool call) | Blocks outside email after the session read untrusted or suspicious content; blocks outgoing email containing secret-like text; blocks bursts of deletes/overwrites. Can override an `allow`. |
| **Human approval** | Risky actions wait for the presenter. Approving runs the policy and detector checks again before the action executes. |
| **Sandbox** | File tools only reach the agent's own copy in `data/sandbox/<id>/`. Path tricks (`..`, absolute paths, backslashes), symlinks, Windows junctions and device names are rejected. Deletes go to a recoverable trash. Commands never run. Email only goes to a local table. |
| **Audit log** | Every decision, shield change, policy change, approval, task check and reset is added to a SHA-256 hash chain and checked against a local checkpoint. Task checks log a hash of the task, not its text. |
| **Shield switch** | Turns the task check, policy and detector off for live demo runs. It starts ON after every restart, and every change is logged. Only the Dashboard key can change it. |
| **Record/replay** | Only Gemini's replies are cached. Every security decision runs live. Replay never falls back to calling Gemini. |

## Known limits

- **The detector is a set of simple rules.** It can block harmless content (for example, a document that discusses "sending passwords to someone@…") and miss attacks that are reworded, encoded, split across steps, or use a format it doesn't recognise. The task check only catches requests that name a sensitive file, a send action and an outside address together.
- **Untrusted files are listed by name** (`meeting_notes.txt`, `untrusted.txt`) in `agentshield/sandbox.py`. Other files are only flagged if their content matches an injection phrase.
- **Shield OFF bypasses every check** for live runs. It still uses the fake sandbox.
- **The audit checkpoint is stored locally.** Someone who can edit both `data/shield.db` and `data/checkpoint.json` can rewrite history. A crash between a database write and the checkpoint write can also make verification fail.
- **Reset clears the previous audit chain** and starts a new one with a `demo_reset` event. It is a presentation convenience, not an audit-retention feature.
- **Single process, single user.** One SQLite file and an in-memory shield setting; not built for several workers or several users.
- **Fake data only.** Never put real secrets, real documents or production data into `sandbox/` or a task.
