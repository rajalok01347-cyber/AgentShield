import hashlib, hmac, json, os, secrets, sqlite3, threading
from pathlib import Path
from datetime import datetime, timezone
from typing import Literal
from fastapi import FastAPI, Header, HTTPException, Depends
from fastapi.responses import FileResponse
import re
from contextlib import contextmanager
from sandbox import execute, seed_agent, validate_path, restore, MAX_FILE_BYTES, safe_path
from pydantic import BaseModel, Field, ConfigDict, model_validator
from policy import Policy, DEFAULT_POLICY, evaluate
from detector import inspect_action, inspect_result, record_attempt, BURST_LIMIT, BURST_WINDOW
ROOT = Path(__file__).parent
DATA = Path(os.getenv('AGENTSHIELD_DATA', str(ROOT / 'data')))
DATA.mkdir(parents=True, exist_ok=True)
LOCK = threading.RLock()
ADMIN = os.getenv('AGENTSHIELD_ADMIN_KEY') or secrets.token_urlsafe(24)
AGENT = os.getenv('AGENTSHIELD_AGENT_KEY') or secrets.token_urlsafe(24)
if not os.getenv('AGENTSHIELD_ADMIN_KEY'):
    print('Dashboard key:', ADMIN)
if not os.getenv('AGENTSHIELD_AGENT_KEY'):
    print('Agent key:', AGENT)
app = FastAPI(title='AgentShield')

@contextmanager
def db():
    c = sqlite3.connect(DATA / 'shield.db')
    c.row_factory = sqlite3.Row
    try:
        with c:
            yield c
    finally:
        c.close()
with db() as c:
    c.executescript('CREATE TABLE IF NOT EXISTS agents(id TEXT PRIMARY KEY,key_hash TEXT,policy TEXT); CREATE TABLE IF NOT EXISTS requests(id TEXT PRIMARY KEY,agent TEXT,tool TEXT,args TEXT,status TEXT,reason TEXT,result TEXT); CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY,payload TEXT,prev TEXT,hash TEXT); CREATE TABLE IF NOT EXISTS files(agent TEXT,name TEXT,body TEXT,PRIMARY KEY(agent,name));')
    c.execute('CREATE TABLE IF NOT EXISTS outbox(id INTEGER PRIMARY KEY,agent TEXT,recipient TEXT,body TEXT)')
    for column, definition in [('subject', "TEXT NOT NULL DEFAULT ''"), ('sent_at', 'TEXT')]:
        if column not in [r['name'] for r in c.execute('PRAGMA table_info(outbox)')]:
            c.execute(f'ALTER TABLE outbox ADD COLUMN {column} {definition}')
    c.executescript('CREATE TABLE IF NOT EXISTS sandbox_agents(agent TEXT PRIMARY KEY); CREATE TABLE IF NOT EXISTS trash(id TEXT PRIMARY KEY,agent TEXT,path TEXT,stored_path TEXT,deleted_at TEXT,status TEXT);')
    c.executescript('CREATE TABLE IF NOT EXISTS policies(id TEXT PRIMARY KEY,name TEXT,rules_json TEXT); CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY,agent_id TEXT NOT NULL,tainted INTEGER NOT NULL DEFAULT 0,started_at TEXT NOT NULL);')
    if 'policy_id' not in [r['name'] for r in c.execute('PRAGMA table_info(agents)')]:
        c.execute('ALTER TABLE agents ADD COLUMN policy_id TEXT')
    if 'session_id' not in [r['name'] for r in c.execute('PRAGMA table_info(requests)')]:
        c.execute('ALTER TABLE requests ADD COLUMN session_id TEXT')
    c.execute('CREATE TABLE IF NOT EXISTS destructive_attempts(id INTEGER PRIMARY KEY,session_id TEXT NOT NULL,tool TEXT NOT NULL,created_at REAL NOT NULL)')
    if 'request_id' not in [r['name'] for r in c.execute('PRAGMA table_info(destructive_attempts)')]:
        c.execute('ALTER TABLE destructive_attempts ADD COLUMN request_id TEXT')
    c.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_attempt_request ON destructive_attempts(request_id) WHERE request_id IS NOT NULL')
    c.execute('CREATE INDEX IF NOT EXISTS idx_attempt_session_time ON destructive_attempts(session_id,created_at)')
    if 'detector_rule' not in [r['name'] for r in c.execute('PRAGMA table_info(requests)')]:
        c.execute('ALTER TABLE requests ADD COLUMN detector_rule TEXT')
    c.execute('INSERT OR IGNORE INTO policies VALUES(?,?,?)', ('default-assistant', DEFAULT_POLICY.name, DEFAULT_POLICY.model_dump_json()))
    for old in c.execute('SELECT * FROM agents WHERE policy_id IS NULL').fetchall():
        old_policy = json.loads(old['policy'])
        migrated = Policy(name='Migrated ' + old['id'], rules=[{'tool': tool, 'action': 'approve' if mode == 'approval' else mode} for tool, mode in old_policy.items()])
        pid = 'migrated-' + old['id']
        c.execute('INSERT OR IGNORE INTO policies VALUES(?,?,?)', (pid, migrated.name, migrated.model_dump_json()))
        c.execute('UPDATE agents SET policy_id=? WHERE id=?', (pid, old['id']))
    c.execute('INSERT OR IGNORE INTO agents(id,key_hash,policy,policy_id) VALUES(?,?,?,?)', ('demo-agent', hashlib.sha256(AGENT.encode()).hexdigest(), '{}', 'default-assistant'))
    c.execute('UPDATE agents SET key_hash=? WHERE id=?', (hashlib.sha256(AGENT.encode()).hexdigest(), 'demo-agent'))
    for old in c.execute('SELECT DISTINCT agent FROM requests WHERE session_id IS NULL').fetchall():
        sid = 'legacy-' + old['agent']
        c.execute('INSERT OR IGNORE INTO sessions VALUES(?,?,0,?)', (sid, old['agent'], datetime.now(timezone.utc).isoformat()))
        c.execute('UPDATE requests SET session_id=? WHERE agent=? AND session_id IS NULL', (sid, old['agent']))
        reads = c.execute("SELECT args FROM requests WHERE session_id=? AND tool='read_file' AND status='executed'", (sid,)).fetchall()
        if any((json.loads(r['args']).get('path') == 'untrusted.txt' for r in reads)):
            c.execute('UPDATE sessions SET tainted=1 WHERE id=?', (sid,))
    for orphan in c.execute('SELECT DISTINCT r.agent FROM requests r LEFT JOIN agents a ON a.id=r.agent WHERE a.id IS NULL').fetchall():
        c.execute('INSERT INTO agents(id,key_hash,policy,policy_id) VALUES(?,?,?,?)', (orphan['agent'], secrets.token_hex(32), '{}', 'default-assistant'))
    for row in c.execute('SELECT id FROM agents').fetchall():
        seed_agent(c, row['id'])

def admin(x_admin_key: str=Header(default='')):
    if not hmac.compare_digest(x_admin_key, ADMIN):
        raise HTTPException(401, 'Admin key required')

def agent(x_api_key: str=Header(default=''), authorization: str=Header(default='')):
    if authorization:
        if not authorization.startswith('Bearer '):
            raise HTTPException(401, 'Use Bearer authentication')
        x_api_key = authorization[7:]
    with db() as c:
        r = c.execute('SELECT * FROM agents WHERE key_hash=?', (hashlib.sha256(x_api_key.encode()).hexdigest(),)).fetchone()
    if not r:
        raise HTTPException(401, 'Invalid agent key')
    return dict(r)

def digest(payload, prev):
    return hashlib.sha256((prev + payload).encode()).hexdigest()

def log(c, kind, **details):
    r = c.execute('SELECT seq,hash FROM events ORDER BY seq DESC LIMIT 1').fetchone()
    seq = r['seq'] + 1 if r else 1
    prev = r['hash'] if r else '0' * 64
    payload = json.dumps({'time': datetime.now(timezone.utc).isoformat(), 'kind': kind, **details}, sort_keys=True, separators=(',', ':'))
    c.execute('INSERT INTO events VALUES(?,?,?,?)', (seq, payload, prev, digest(payload, prev)))

def checkpoint(c):
    r = c.execute('SELECT seq,hash FROM events ORDER BY seq DESC LIMIT 1').fetchone()
    (DATA / 'checkpoint.json').write_text(json.dumps(dict(r) if r else {'seq': 0, 'hash': '0' * 64}))

class Action(BaseModel):
    session_id: str | None = Field(default=None, min_length=1, max_length=100)
    tool: Literal['list_files', 'read_file', 'write_file', 'delete_file', 'send_email', 'run_command']
    args: dict[str, str] = Field(default_factory=dict)
    model_config = ConfigDict(extra='forbid')

    @model_validator(mode='after')
    def validate_args(self):
        if self.tool == 'send_email' and set(self.args) == {'to', 'body'}:
            self.args['subject'] = '(no subject)'
        expected = {'list_files': {'dir'}, 'read_file': {'path'}, 'write_file': {'path', 'content'}, 'delete_file': {'path'}, 'send_email': {'to', 'subject', 'body'}, 'run_command': {'cmd'}}[self.tool]
        if set(self.args) != expected:
            raise ValueError('Expected arguments: ' + ', '.join(sorted(expected)))
        if self.tool == 'send_email':
            if not re.fullmatch('[A-Za-z0-9._+%-]+@[A-Za-z0-9-]+(?:\\.[A-Za-z0-9-]+)+', self.args['to']):
                raise ValueError('A single valid email address is required')
            if not self.args['body'].strip() or len(self.args['body']) > 10000:
                raise ValueError('Email body must contain 1-10000 characters')
            if not self.args['subject'].strip() or len(self.args['subject']) > 200 or any((c in self.args['subject'] for c in '\r\n')):
                raise ValueError('Email subject must contain 1-200 characters on one line')
        elif self.tool == 'run_command':
            if not self.args['cmd'].strip() or len(self.args['cmd']) > 1000:
                raise ValueError('Simulated command must contain 1-1000 characters')
        elif self.tool == 'list_files':
            self.args['dir'] = validate_path(self.args['dir'], directory=True)
        else:
            self.args['path'] = validate_path(self.args['path'])
            if self.tool == 'write_file' and len(self.args['content'].encode('utf-8')) > MAX_FILE_BYTES:
                raise ValueError('Sandbox files are limited to 100000 UTF-8 bytes')
        return self

def create_session(c, who):
    sid = secrets.token_hex(16)
    c.execute('INSERT INTO sessions VALUES(?,?,0,?)', (sid, who, datetime.now(timezone.utc).isoformat()))
    return sid

def session_for(c, sid, who):
    row = c.execute('SELECT * FROM sessions WHERE id=? AND agent_id=?', (sid, who)).fetchone()
    if row is None:
        raise HTTPException(404, 'Session not found')
    return row

def load_policy(c, who):
    row = c.execute('SELECT p.rules_json FROM policies p JOIN agents a ON a.policy_id=p.id WHERE a.id=?', (who,)).fetchone()
    if row is None:
        raise HTTPException(403, 'Agent has no valid assigned policy')
    return Policy.model_validate_json(row['rules_json'])

def decide(c, policy, session, action, destructive=None):
    mode, reason = evaluate(policy, action.tool, action.args)
    finding = inspect_action(c, policy, session, action, destructive=destructive)
    if finding:
        return ('block', finding.reason, finding.rule)
    return (mode, reason, None)

def observe_result(c, who, sid, rid, result):
    finding = inspect_result(result)
    if finding:
        c.execute('UPDATE sessions SET tainted=1 WHERE id=?', (sid,))
        log(c, 'detector_flag', request_id=rid, agent=who, session_id=sid, detector_rule=finding.rule, reason=finding.reason)
    return finding.rule if finding else None

def submit(who, a, shield=True, policy_override=None):
    if not a.session_id:
        raise HTTPException(422, 'session_id is required; create a session first')
    with LOCK, db() as c:
        session = session_for(c, a.session_id, who)
        policy = policy_override or load_policy(c, who)
        rid = secrets.token_hex(8)
        destructive = a.tool == 'delete_file' or (a.tool == 'write_file' and safe_path(who, a.args['path']).is_file())
        record_attempt(c, a.session_id, a.tool, request_id=rid, destructive=destructive)
        mode, reason, detector_rule = decide(c, policy, session, a, destructive=destructive) if shield else ('allow', 'Shield OFF: sandbox only', None)
        status = {'allow': 'executed', 'block': 'blocked', 'approve': 'pending'}[mode]
        log(c, 'action', request_id=rid, agent=who, session_id=a.session_id, tool=a.tool, args=a.args, status='allowed' if mode == 'allow' else status, decision=mode, reason=reason, detector_rule=detector_rule)
        error = None
        try:
            result = execute(c, who, a) if mode == 'allow' else None
        except HTTPException as exc:
            error = exc
            status = 'error'
            result = {'error': exc.detail}
            log(c, 'tool_error', request_id=rid, agent=who, session_id=a.session_id, tool=a.tool, status=status, http_status=exc.status_code)
        flag = observe_result(c, who, a.session_id, rid, result) if result else None
        c.execute('INSERT INTO requests(id,agent,tool,args,status,reason,result,session_id,detector_rule) VALUES(?,?,?,?,?,?,?,?,?)', (rid, who, a.tool, json.dumps(a.args), status, reason, json.dumps(result), a.session_id, detector_rule))
        c.commit()
        checkpoint(c)
    if error:
        raise error
    return {'id': rid, 'session_id': a.session_id, 'status': status, 'reason': reason, 'result': result, 'detector_rule': detector_rule, 'session_flag': flag}

@app.get('/')
def index():
    return FileResponse(ROOT / 'index.html', headers={'Cache-Control': 'no-store'})

@app.get('/health')
def health():
    return {'status': 'ok'}

@app.get('/api/outbox', dependencies=[Depends(admin)])
def outbox():
    with db() as c:
        return {'messages': [dict(r) for r in c.execute('SELECT * FROM outbox ORDER BY id DESC')]}

@app.post('/api/actions')
def actions(a: Action, identity=Depends(agent)):
    return submit(identity['id'], a)

@app.get('/api/agent')
def agent_info(identity=Depends(agent)):
    with db() as c:
        policy = load_policy(c, identity['id'])
    return {'id': identity['id'], 'policy': policy.model_dump()}

@app.get('/api/actions/{rid}')
def action_status(rid: str, identity=Depends(agent)):
    with db() as c:
        row = c.execute('SELECT * FROM requests WHERE id=? AND agent=?', (rid, identity['id'])).fetchone()
    if row is None:
        raise HTTPException(404, 'Request not found')
    return {'id': row['id'], 'session_id': row['session_id'], 'status': row['status'], 'reason': row['reason'], 'result': json.loads(row['result']), 'detector_rule': row['detector_rule']}

@app.get('/api/state', dependencies=[Depends(admin)])
def state():
    with db() as c:
        return {'detector': {'burst_limit': BURST_LIMIT, 'burst_window': BURST_WINDOW}, 'requests': [dict(r) for r in c.execute('SELECT * FROM requests ORDER BY rowid DESC')], 'events': [dict(r) for r in c.execute('SELECT * FROM events ORDER BY seq DESC')], 'agents': [{'id': r['id'], 'policy_id': r['policy_id']} for r in c.execute('SELECT * FROM agents')], 'sessions': [dict(r) for r in c.execute('SELECT * FROM sessions ORDER BY started_at DESC')], 'policies': [{'id': r['id'], **json.loads(r['rules_json'])} for r in c.execute('SELECT * FROM policies')]}

@app.post('/api/approvals/{rid}/{decision}', dependencies=[Depends(admin)])
def approve(rid: str, decision: Literal['approve', 'reject']):
    with LOCK, db() as c:
        r = c.execute('SELECT * FROM requests WHERE id=?', (rid,)).fetchone()
        if not r:
            raise HTTPException(404, 'Request not found')
        if r['status'] != 'pending':
            raise HTTPException(409, 'Request already resolved')
        action = Action(session_id=r['session_id'], tool=r['tool'], args=json.loads(r['args']))
        error = None
        result = None
        detector_rule = None
        reason = 'Rejected by human'
        status = 'rejected'
        if decision == 'approve':
            try:
                destructive = action.tool == 'delete_file' or (action.tool == 'write_file' and safe_path(r['agent'], action.args['path']).is_file())
                record_attempt(c, r['session_id'], action.tool, request_id=rid, destructive=destructive)
                mode, reason, detector_rule = decide(c, load_policy(c, r['agent']), session_for(c, r['session_id'], r['agent']), action, destructive=destructive)
                status = 'blocked' if mode == 'block' else 'executed'
                result = execute(c, r['agent'], action) if status == 'executed' else None
                if result:
                    observe_result(c, r['agent'], r['session_id'], rid, result)
            except HTTPException as exc:
                error = exc
                status = 'error'
                reason = 'Sandbox approval failed: ' + str(exc.detail)
                result = {'error': exc.detail}
        c.execute('UPDATE requests SET status=?,reason=?,result=?,detector_rule=? WHERE id=?', (status, reason, json.dumps(result), detector_rule, rid))
        log(c, 'human_decision', request_id=rid, session_id=r['session_id'], decision=decision, status=status, reason=reason, detector_rule=detector_rule)
        c.commit()
        checkpoint(c)
    if error:
        raise error
    return {'status': status, 'result': result, 'reason': reason, 'detector_rule': detector_rule}

@app.get('/api/verify', dependencies=[Depends(admin)])
def verify():
    with LOCK, db() as c:
        prev = '0' * 64
        seq = 0
        for r in c.execute('SELECT * FROM events ORDER BY seq'):
            if r['seq'] != seq + 1 or r['prev'] != prev or digest(r['payload'], prev) != r['hash']:
                return {'valid': False, 'reason': f"Chain broken at entry {r['seq']}"}
            prev = r['hash']
            seq = r['seq']
        anchor = json.loads((DATA / 'checkpoint.json').read_text()) if (DATA / 'checkpoint.json').exists() else {'seq': 0, 'hash': '0' * 64}
        return {'valid': anchor == {'seq': seq, 'hash': prev}, 'entries': seq, 'reason': 'Chain and local checkpoint compared'}

class Demo(BaseModel):
    shield: bool = True

@app.post('/api/demo', dependencies=[Depends(admin)])
def demo(options: Demo):
    who = 'demo-' + secrets.token_hex(4)
    with db() as c:
        seed_agent(c, who)
        c.execute('INSERT INTO agents(id,key_hash,policy,policy_id) VALUES(?,?,?,?)', (who, secrets.token_hex(32), '{}', 'default-assistant'))
        sid = create_session(c, who)
    policy = DEFAULT_POLICY
    steps = [Action(tool='read_file', args={'path': 'report.txt'}), Action(tool='delete_file', args={'path': 'report.txt'}), Action(tool='send_email', args={'to': 'manager@acme.example', 'body': 'Quarterly summary'}), Action(tool='read_file', args={'path': 'untrusted.txt'}), Action(tool='send_email', args={'to': 'thief@unknown.example', 'body': 'Internal revenue forecast: $420,000.'})]
    return {'session_id': sid, 'steps': [submit(who, a.model_copy(update={'session_id': sid}), options.shield, policy) for a in steps]}

@app.post('/api/demo/tamper', dependencies=[Depends(admin)])
def tamper():
    with LOCK, db() as c:
        if not c.execute('SELECT 1 FROM events').fetchone():
            raise HTTPException(409, 'Run a demo first')
        c.execute('UPDATE events SET payload=? WHERE seq=(SELECT MIN(seq) FROM events)', ('{"kind":"tampered"}',))
    return {'message': 'Demo entry changed. Verify the chain.'}

@app.post('/api/sessions')
@app.post('/v1/sessions')
def new_session(identity=Depends(agent)):
    with LOCK, db() as c:
        sid = create_session(c, identity['id'])
    return {'id': sid, 'agent_id': identity['id'], 'tainted': False}

@app.get('/api/sessions/{sid}')
def get_session(sid: str, identity=Depends(agent)):
    with db() as c:
        return dict(session_for(c, sid, identity['id']))

class PolicyRecord(Policy):
    id: str = Field(pattern='^[A-Za-z0-9_-]{1,100}$')

@app.get('/admin/policies', dependencies=[Depends(admin)])
def list_policies():
    with db() as c:
        return {'policies': [{'id': r['id'], **json.loads(r['rules_json'])} for r in c.execute('SELECT * FROM policies')], 'agents': [{'id': r['id'], 'policy_id': r['policy_id']} for r in c.execute('SELECT * FROM agents')]}

@app.post('/admin/policies', dependencies=[Depends(admin)])
def save_policy(record: PolicyRecord):
    policy = Policy.model_validate(record.model_dump(exclude={'id'}))
    with LOCK, db() as c:
        c.execute('INSERT INTO policies VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,rules_json=excluded.rules_json', (record.id, policy.name, policy.model_dump_json()))
        log(c, 'policy_updated', policy_id=record.id, policy=policy.model_dump())
        c.commit()
        checkpoint(c)
    return record.model_dump()

class Assignment(BaseModel):
    model_config = ConfigDict(extra='forbid')
    policy_id: str

@app.post('/admin/agents/{agent_id}/policy', dependencies=[Depends(admin)])
def assign_policy(agent_id: str, body: Assignment):
    with LOCK, db() as c:
        if not c.execute('SELECT 1 FROM policies WHERE id=?', (body.policy_id,)).fetchone():
            raise HTTPException(404, 'Policy not found')
        if not c.execute('SELECT 1 FROM agents WHERE id=?', (agent_id,)).fetchone():
            raise HTTPException(404, 'Agent not found')
        c.execute('UPDATE agents SET policy_id=? WHERE id=?', (body.policy_id, agent_id))
        log(c, 'policy_assigned', agent=agent_id, policy_id=body.policy_id)
        c.commit()
        checkpoint(c)
    return {'agent_id': agent_id, 'policy_id': body.policy_id}

@app.get('/admin/trash', dependencies=[Depends(admin)])
def list_trash():
    with db() as c:
        return {'files': [dict(r) for r in c.execute('SELECT id,agent,path,deleted_at,status FROM trash ORDER BY deleted_at DESC')]}

@app.post('/admin/trash/{trash_id}/restore', dependencies=[Depends(admin)])
def restore_file(trash_id: str):
    with LOCK, db() as c:
        result = restore(c, trash_id)
        log(c, 'sandbox_restore', **result)
        c.commit()
        checkpoint(c)
    return result
