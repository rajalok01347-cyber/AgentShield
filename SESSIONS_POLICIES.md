# Sessions and policy engine: first PRD alignment milestone

## What changed

- Tool calls require a `session_id` belonging to the authenticated agent.
- A session stores `id`, `agent_id`, `tainted`, and `started_at` in SQLite.
- The Gemini runner creates a fresh session for every task.
- The dashboard creates a session on the first submitted action and provides **New session**.
- Requests and new audit events include session IDs. New action audit events include arguments.
- Policies live in a separate table; each agent has a `policy_id` assignment.
- Rules are evaluated in order. The first matching rule wins. No match means block.
- Human approval rechecks the current policy and session taint before execution.

## Session API

1. `POST /api/sessions` (alias `/v1/sessions`) creates a session. Supply the Agent key.
2. `GET /api/sessions/{id}` returns that agent's session only.
3. `POST /api/actions` requires this body:

```json
{"session_id":"RETURNED_SESSION_ID","tool":"read_file","args":{"path":"report.txt"}}
```

Use `Authorization: Bearer <Agent key>` or the existing `x-api-key` header.
A missing session gives 422; unknown sessions and another agent's sessions give 404.
The session is not a credential; knowing its ID does not grant access.
Session files remain scoped to the agent, not copied into a separate filesystem per session.
The existing taint rule now acts within one session only.

## Policy API

Use the Dashboard key as `x-admin-key`. Agent credentials cannot manage policies.

- `GET /admin/policies`: list actual JSON policies and agent assignments.
- `POST /admin/policies`: create or update a validated policy by ID.
- `POST /admin/agents/{agent_id}/policy`: assign an existing policy using
  `{"policy_id":"default-assistant"}`.

Example policy body:

```json
{
  "id": "review-assistant",
  "name": "Review assistant",
  "rules": [
    {"tool":"read_file","action":"allow","when":{"path_prefix":"reports/"}},
    {"tool":"delete_file","action":"block","reason":"Deletion is not permitted"},
    {"tool":"send_email","action":"allow","when":{"to_domain_in":["ourcompany.com"],"max_size":1000}},
    {"tool":"send_email","action":"approve","reason":"External or large email needs approval"}
  ],
  "default":"block"
}
```

Policy updates and assignment changes are audit events. Invalid policies return 422
without changing the stored policy. Updates apply to existing sessions as well as new ones.
The dashboard displays policies and their assigned agents; editing uses the API explorer.

### Condition semantics

All specified conditions on a rule must match:

- `to_domain_in`: exact, case-insensitive recipient domain. Subdomains do not match
  automatically. Wildcards, URLs, and empty allowlists are rejected.
- `path_prefix`: relative folder boundary. `reports/` matches `reports/q1.txt` but
  not `reports-evil/q1.txt`. Absolute paths, backslashes, and traversal fail the condition.
- `max_size`: the sum of character lengths of all string argument values must be
  strictly less than the limit. This counts recipient/path values as well as the body.

Unknown conditions, invalid action names, non-positive size limits, and non-block defaults
are rejected. Rules for future tools can be stored, but all six tools are now exposed. See [SANDBOX_TOOLS.md](SANDBOX_TOOLS.md) for the current tool milestone.

New installations use `policies/default.json`. The source definition is in `policy.py`;
the JSON file is a reviewable copy, not automatically reloaded. An internal email to
`ourcompany.com` is allowed; other email requires approval; deletion is blocked.

## Migration

Startup adds tables and columns without deleting requests, files, outbox messages, or audit history.
Legacy tool mappings become ordered policies named `migrated-<agent-id>`. These preserve the
previous decisions; they do not silently adopt the new internal-domain allowance.
Legacy requests are grouped under `legacy-<agent-id>` sessions. Existing audit hashes are
preserved, so old audit events will not gain session fields retroactively.
Old scripted-demo identities get records with unissued random key hashes so their pending
requests can still be reviewed. These identities have no issued API credential.

To adopt the PRD default for an existing agent, explicitly assign `default-assistant` through
the admin assignment endpoint. Restarting does not overwrite edited policies or assignments.

## Verification and remaining work

58 test cases cover the existing app, Gemini contract, policies, session isolation, approval-time
rechecks, and migration across repeated startups. The live browser check demonstrated that
an external email is blocked in a tainted session and pending in a fresh session.

This milestone does not finish the PRD. The full `/v1` API contract, record/replay cache, timeout expiry behavior, and final security docs/demo
rehearsals are still pending. Live Gemini connectivity still requires the user's local key.

The detector milestone is now implemented; see [DETECTOR_RULES.md](DETECTOR_RULES.md).
