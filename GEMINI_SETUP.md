# Connect Gemini to AgentShield

This runner uses Gemini's `generateContent` function-calling API. Gemini proposes
calls; the runner submits them to AgentShield. It never imports or executes sandbox tools.

```text
Your task → Gemini → tool call → AgentShield → allow / block / human review
                ↑                                ↓
                └──────── tool outcome ──────────┘
```

## 1. Get your Gemini API key

Create or view a key in [Google AI Studio](https://aistudio.google.com/apikey).
Model access, pricing, and quota depend on your Google project; this integration does
not guarantee free usage. Use the model available to your project.

Do not paste the key into chat, the dashboard, or a tracked source file.

## 2. Start AgentShield

Open PowerShell in the AgentShield project folder. Install dependencies if needed:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -u -m uvicorn app:app --host 127.0.0.1 --port 8000
```

Keep this terminal running. It prints a Dashboard key and an Agent key.
If the backend is already running from the latest code, use its existing keys.
The startup seeds `demo-agent`, whose default policy allows reading, blocks deletion,
and requires human approval for email. The Gemini runner uses this identity.

## 3. Connect the dashboard

Open [AgentShield](http://localhost:8000/) and enter the **Dashboard key**.
The Gemini key does not belong in this page. The agent runner never gets the Dashboard key.

## 4. Start the Gemini agent in a second terminal

Open another PowerShell terminal in the same project folder:

```powershell
.\.venv\Scripts\python.exe gemini_agent.py "Read report.txt and email a short summary to manager@acme.example."
```

The runner prompts for:

1. **Gemini API key** — hidden while you enter it.
2. **AgentShield Agent key** — the Agent key printed by the backend, also hidden.

If `GEMINI_API_KEY` and `AGENTSHIELD_AGENT_KEY` are already environment variables,
the runner uses them instead of prompting. They are not printed, placed in URLs,
or saved by this runner. `.env` files are ignored by Git but are not automatically loaded.

The default model is `gemini-flash-latest`. Override it when your project requires another:

```powershell
.\.venv\Scripts\python.exe gemini_agent.py --model YOUR_MODEL_ID "Read report.txt."
```

Your task, sandbox tool results, and subsequent conversation are sent to Google Gemini.
Only fake sandbox data is provided by this project. Do not put real confidential data in the task.

## 5. Approve the email

When Gemini asks to send an email:

1. The terminal reports `send_email: pending` and a request ID.
2. In the dashboard, choose **Refresh**.
3. Inspect the pending recipient and message.
4. Choose **Approve & execute** or **Reject**.
5. The runner polls its own request and sends the final outcome back to Gemini.
6. Refresh the dashboard to see the resulting action and sandbox outbox message.

Only AgentShield executes an approved request. The runner does not submit it again.
The email is simulated; no real message is delivered.

## 6. Try a blocked action

```powershell
.\.venv\Scripts\python.exe gemini_agent.py "Delete report.txt."
```

If Gemini requests deletion, the gateway blocks it and returns that decision to Gemini.
The LLM may decline or choose not to call a tool; model decisions are nondeterministic.
The dashboard's scripted ON/OFF demo remains the deterministic attack demonstration.

## 7. Run the tests

```powershell
.\.venv\Scripts\python.exe -m unittest discover -p "test_*.py" -v
```

43 tests cover the backend and offline Gemini integration. Gemini responses are mocked;
the gateway, authentication, approval state, and sandbox operations use the real application.
Tests check ID/signature preservation, multiple calls, approval/rejection, timeout,
agent-scoped status, limits, and sanitized API errors.

## Operational limits

- The runner allows 12 model turns and 24 tool calls per task; it has no shield-OFF mode.
- It waits up to five minutes for approval. Configure `--approval-timeout 600` for ten minutes.
- On timeout or interruption, pending requests remain on the dashboard. The run stops;
  it does not save conversation history or support resuming that conversation.
- No automatic retries are made for tool submissions or Gemini API errors. After a
  connection failure, inspect the dashboard before rerunning to avoid duplicate requests.
- A 429 response means Gemini rate limits or quota need attention. A 404 can mean
  the configured model is unavailable. Raw provider error bodies are not printed.
- Approval status is read using `GET /api/actions/{rid}` with the Agent key. Requests
  belonging to another identity return 404. `GET /api/agent` checks the Agent key first.
- The prototype still starts with one seeded agent identity. Each CLI task creates a new
  session, so suspicious-document history is isolated between runs. Multi-agent provisioning comes later.
- Live Gemini connectivity is unverified until a valid local key is supplied and a live task succeeds.

## Official references

- [Gemini function calling](https://ai.google.dev/gemini-api/docs/generate-content/function-calling)
- [Gemini API keys](https://ai.google.dev/gemini-api/docs/api-key)
