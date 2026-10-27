"""SQLite cache for model content only. Never caches gateway decisions."""
import hashlib
import json
import sqlite3
from contextlib import closing, contextmanager
from datetime import datetime, timezone
from pathlib import Path


class CacheError(Exception):
    pass


def canonical(value):
    try:
        return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False)
    except (TypeError,ValueError):
        raise CacheError('Model cache input must be valid JSON.') from None


def request_key(request):
    return hashlib.sha256(canonical(request).encode('utf-8')).hexdigest()


@contextmanager
def connection(path):
    try:
        with closing(sqlite3.connect(path)) as c, c:
            yield c
    except sqlite3.Error:
        raise CacheError('Cache storage is unavailable or incompatible. Check its path, permissions, and schema.') from None


class LLMCache:
    def __init__(self,path):
        self.path=Path(path)
        self.path.parent.mkdir(parents=True,exist_ok=True)
        with connection(self.path) as c:
            c.execute('CREATE TABLE IF NOT EXISTS llm_cache(key TEXT PRIMARY KEY,request_json TEXT NOT NULL,response_json TEXT NOT NULL,created_at TEXT NOT NULL,response_hash TEXT NOT NULL)')

    def get(self,request):
        key=request_key(request)
        with connection(self.path) as c:
            row=c.execute('SELECT request_json,response_json,response_hash FROM llm_cache WHERE key=?',(key,)).fetchone()
        if row is None:
            raise CacheError('Replay cache miss: '+key+'. Record this exact task and conversation first; no Gemini call was made.')
        if row[0]!=canonical(request) or hashlib.sha256(row[1].encode('utf-8')).hexdigest()!=row[2]:
            raise CacheError('Cached response failed integrity checks: '+key)
        try:
            content=json.loads(row[1])
        except ValueError:
            raise CacheError('Cached response is not valid JSON: '+key) from None
        validate_content(content)
        return content

    def put(self,request,content):
        validate_content(content)
        response=canonical(content)
        with connection(self.path) as c:
            c.execute('INSERT INTO llm_cache VALUES(?,?,?,?,?) ON CONFLICT(key) DO UPDATE SET request_json=excluded.request_json,response_json=excluded.response_json,created_at=excluded.created_at,response_hash=excluded.response_hash',
                      (request_key(request),canonical(request),response,datetime.now(timezone.utc).isoformat(),hashlib.sha256(response.encode('utf-8')).hexdigest()))


def validate_content(content):
    if not isinstance(content,dict) or content.get('role')!='model' or not isinstance(content.get('parts'),list) or not content['parts']:
        raise CacheError('Model content is malformed; no cache entry was used or saved.')
    for part in content['parts']:
        if not isinstance(part,dict):
            raise CacheError('Malformed model part.')
        if 'functionCall' in part:
            call=part['functionCall']
            if not isinstance(call,dict) or not isinstance(call.get('name'),str) or not isinstance(call.get('args',{}),dict):
                raise CacheError('Malformed cached function call.')
        elif not isinstance(part.get('text'),str):
            raise CacheError('Unsupported model content part.')


class CachedModel:
    def __init__(self,provider,cache,mode,model,system,tools,generation=None,report=print):
        if mode not in ('live','record','replay'):
            raise CacheError('LLM_MODE must be live, record, or replay')
        self.provider,self.cache,self.mode=provider,cache,mode
        self.model,self.system,self.tools=model,system,tools
        self.generation=generation or {'maxOutputTokens':2048}
        self.report=report

    def generate(self,contents):
        request={'model':self.model,'messages':contents,'system':self.system,'tool_definitions':self.tools,
                 'generation':self.generation,'function_calling_mode':'AUTO','cache_format':1}
        if self.mode=='replay':
            content=self.cache.get(request)
            self.report('LLM replay: '+request_key(request)[:12])
            return content
        content=self.provider.generate(contents)
        if self.mode=='record':
            self.cache.put(request,content)
            self.report('LLM recorded: '+request_key(request)[:12])
        return content
