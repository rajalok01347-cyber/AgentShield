# AgentShield

A security gateway between AI agents and their tools.

## Planned behavior

- Identify agents using API keys and database policies.
- Allow safe actions, block prohibited actions, and hold risky actions for human approval.
- Detect suspicious sequences associated with prompt injection.
- Record actions in a hash-linked audit log.
- Demonstrate shield OFF versus ON using sandbox tools only.

## Project status

Early prototype. `app.py` contains initial FastAPI and SQLite gateway code.
The dashboard, automated tests, and LLM integration are not yet complete.
The application has not yet been run or verified. Do not deploy this prototype.

## Planned stack

Python, FastAPI, SQLite (Postgres later), and a web dashboard.

## Files

- `app.py`: initial gateway prototype and sandbox tool logic
- `requirements.txt`: Python dependencies
- `.gitignore`: excludes secrets, local data, and environments

## Development setup

Requires Python 3.10 or newer. From this directory in PowerShell:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Once the dashboard is implemented, the intended launch command is:

```powershell
.\.venv\Scripts\python.exe -m uvicorn app:app --reload --host 127.0.0.1
```

Keep API keys out of Git. All demo emails and file operations are simulated.
