# Attack detector rules

This milestone implements the four rules in PRD section 5.3 for the currently available
sandbox tools. These are explainable heuristics, not a general prompt-injection classifier.

| Rule ID | Trigger | Effect |
|---|---|---|
| `injection_phrases` | Tool output contains `ignore [all] previous/prior instructions`, `you are now`, or `send ... to` | Marks this session tainted; writes a detector flag to the audit chain |
| `untrusted_content` | A tool result is explicitly marked untrusted | Marks this session tainted; writes a flag |
| `taint_exfiltration` | A tainted session requests email to a domain outside its policy's explicit internal-domain allowlist | Blocks the action |
| `destructive_burst` | More than N destructive submissions occur in M seconds within one session | Blocks the action before the tool executes |
| `secret_in_outbound` | Outbound arguments contain `API_KEY=`, `password:`, or an `sk-` token with at least eight following token characters | Blocks, including email to allowlisted internal recipients |

## Matching and ordering

Text is normalized with Unicode NFKC and collapsed whitespace before scanning. Phrase
and secret matching are case-insensitive. `send ... to` permits up to 200 characters
between the words. Matching a phrase flags the session but does not block the file read.

After policy evaluation, the detector can override any policy result with a block.
For outbound calls, secret detection takes priority over taint detection. The returned
`detector_rule` identifies the rule responsible for a block. Policy-only blocks have no
rule ID. Matched secret values are never copied into rule reasons; the prototype's request
arguments and audit arguments still retain their original submitted values. Use fake data.

Explicit internal domains come from `allow` email rules with `to_domain_in`. A broad
unconditional email allowance does not exempt tainted outbound data from detection.
Session taint persists in SQLite until a new session is started; it does not affect another session.

## Burst settings

Defaults: allow up to 3 destructive submissions in a rolling 10-second window; the fourth
is blocked. The policy may still block any of the first three independently.

Optional environment variables, set before starting the backend:

```powershell
$env:AGENTSHIELD_BURST_LIMIT = "3"
$env:AGENTSHIELD_BURST_WINDOW = "10"
```

Deletes and `write_file` calls that overwrite an existing file are destructive. New file creation is not. Pending writes are checked again at approval and counted once by request ID. `http_post` is recognized as outbound internally
but is not exposed as an API tool in this milestone. `http_post` remains unimplemented.

The current submission is counted. Policy-blocked and failed sandbox-tool attempts count.
Validation/authentication failures and unknown tools do not. Approval polling and human
approval do not add submissions. The window includes both endpoints and ignores future-dated
rows. Counts are persisted in an indexed SQLite table and isolated by session ID.
Old requests from before this migration are not reconstructed as timed attempts.

## Approval and demo behavior

Approving a request reruns the policy, taint, secret, and burst checks. For example, a pending
email becomes blocked if the same session reads an injection before approval. Approved tool
results are scanned too, so a file requiring approval can still taint its session when read.
If a recheck blocks execution, the dashboard reports that block rather than a successful send.

The admin-only shield-OFF scripted demo bypasses blocking decisions. It still records
attempts and flags to preserve visibility; each demo uses a fresh session and fake tools.
The Gemini agent has no bypass endpoint or admin key.

## Inspect in the dashboard

1. Refresh the page to load the latest dashboard code, then connect with the Dashboard key.
2. Enter the Agent key. Choose **New session**.
3. Read `untrusted.txt`. Inspect `session_flag` in the result and the `detector_flag` audit event.
4. Try sending ordinary text to `demo@external.example`. The rule is `taint_exfiltration`.
5. Start a new session. Submit an email containing `API_KEY=fake-demo-only`. The rule is
   `secret_in_outbound`, without sending any simulated message.
6. Start another new session. Request deletion of `report.txt` four times quickly. The
   default policy blocks the initial calls; the fourth shows `destructive_burst` instead.
7. Expand action details for the rule ID; choose **Verify integrity** to check the audit chain.

The feed shows rule IDs and reasons. The session label shows **Tainted** after suspicious
output. The policy panel reports the configured burst threshold.

## Verification and limits

The suite covers clean and suspicious content, arbitrary filenames, exact allowlisted domains,
Unicode/whitespace variants, secret blocks, burst boundaries/expiry/session isolation,
policy overrides, approval rechecks, and failed tool attempts.

These rules can have false positives (for example, a document discussing prompt injection)
and false negatives (for example, obfuscated instructions, encoded secrets, unfamiliar
credential formats, or exfiltration channels outside the exposed tools). The burst guard is
per-session and uses the local wall clock; it is not an account-wide rate limiter. This remains
a single-process local prototype. The full sandbox is now implemented; record/replay remains a later milestone.
