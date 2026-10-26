"""Small, deterministic session attack rules. Findings never include matched secrets."""
import os
import re
import time
import unicodedata
from dataclasses import dataclass
from policy import email_domain, outbound_domains

BURST_LIMIT = int(os.getenv('AGENTSHIELD_BURST_LIMIT', '3'))
BURST_WINDOW = float(os.getenv('AGENTSHIELD_BURST_WINDOW', '10'))
if not 1 <= BURST_LIMIT <= 10000 or not 0 < BURST_WINDOW <= 3600:
    raise ValueError('Burst limit must be 1-10000 and window must be >0 and <=3600 seconds')
DESTRUCTIVE_TOOLS = {'delete_file', 'write_file', 'overwrite_file'}
OUTBOUND_TOOLS = {'send_email', 'http_post'}
INJECTION = [
    re.compile(r'\bignore\s+(?:all\s+)?(?:previous|prior)\s+instructions\b', re.I),
    re.compile(r'\byou\s+are\s+now\b', re.I),
    re.compile(r'\bsend\b.{1,200}?\bto\b', re.I),
]
SECRETS = [
    re.compile(r'\bAPI_KEY\s*=', re.I),
    re.compile(r'\bpassword\s*:', re.I),
    re.compile(r'\bsk-[a-z0-9_-]{8,}\b', re.I),
]


@dataclass(frozen=True)
class Finding:
    rule: str
    reason: str


def strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from strings(item)


def normalized(value):
    return ' '.join(unicodedata.normalize('NFKC', value).split())


def inspect_result(result):
    if any(pattern.search(normalized(text)) for text in strings(result) for pattern in INJECTION):
        return Finding('injection_phrases', 'Injection phrases: suspicious instructions found in tool output')
    if isinstance(result, dict) and result.get('untrusted'):
        return Finding('untrusted_content', 'Untrusted content: tool result marked this session tainted')
    return None


def record_attempt(connection, session_id, tool, now=None):
    if tool in DESTRUCTIVE_TOOLS:
        connection.execute('INSERT INTO destructive_attempts(session_id,tool,created_at) VALUES(?,?,?)',
                           (session_id, tool, time.time() if now is None else now))


def inspect_action(connection, policy, session, action, now=None):
    if action.tool in OUTBOUND_TOOLS:
        if any(pattern.search(normalized(text)) for text in strings(action.args) for pattern in SECRETS):
            return Finding('secret_in_outbound', 'Secret in outbound data: credential-like content detected')
        if session['tainted'] and email_domain(action.args.get('to')) not in outbound_domains(policy):
            return Finding('taint_exfiltration', 'Taint → exfiltration: untrusted content read, external recipient')
    if action.tool in DESTRUCTIVE_TOOLS:
        current = time.time() if now is None else now
        count = connection.execute('SELECT COUNT(*) FROM destructive_attempts WHERE session_id=? AND created_at>=? AND created_at<=?',
                                   (session['id'], current-BURST_WINDOW, current)).fetchone()[0]
        if count > BURST_LIMIT:
            return Finding('destructive_burst', f'Destructive burst: more than {BURST_LIMIT} calls in {BURST_WINDOW:g} seconds')
    return None
