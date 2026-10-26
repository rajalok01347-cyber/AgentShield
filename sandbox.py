"""Filesystem sandbox tools. Never sends email or executes a command."""
import hashlib
import os
import re
import secrets
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from fastapi import HTTPException

ROOT = Path(os.getenv('AGENTSHIELD_DATA', str(Path(__file__).parent/'data'))) / 'sandbox'
SEEDS = Path(__file__).parent/'sandbox'
MAX_FILE_BYTES = 100_000


def validate_path(value, directory=False):
    if directory and value in ('', '.'):
        return ''
    if not isinstance(value, str) or not value or len(value)>300 or '\\' in value:
        raise ValueError('Use a relative sandbox path with forward slashes')
    parts=value.split('/')
    for part in parts:
        if not re.fullmatch(r'[A-Za-z0-9_-][A-Za-z0-9_.-]{0,99}',part) or part.endswith('.'):
            raise ValueError('Invalid sandbox path or traversal attempt')
        if re.fullmatch(r'(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?',part,re.I):
            raise ValueError('Windows device names are not sandbox paths')
    return '/'.join(parts)


def no_links(path):
    try:
        info=path.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISLNK(info.st_mode) or getattr(info,'st_file_attributes',0) & getattr(stat,'FILE_ATTRIBUTE_REPARSE_POINT',0x400):
        raise HTTPException(403,'Links and junctions are not permitted in the sandbox')


def agent_root(agent_id):
    no_links(ROOT)
    ROOT.mkdir(parents=True,exist_ok=True)
    root=ROOT/hashlib.sha256(agent_id.encode()).hexdigest()
    no_links(root)
    root.mkdir(exist_ok=True)
    return root


def safe_path(agent_id, relative, directory=False, internal=False):
    if not internal:
        relative=validate_path(relative,directory)
    root=agent_root(agent_id)
    candidate=root/relative
    current=root
    parts=Path(relative).parts
    for index,part in enumerate(parts):
        current=current/part
        no_links(current)
        if index<len(parts)-1 and current.exists() and not current.is_dir():
            raise HTTPException(409,'A file occupies a parent directory')
    if not candidate.resolve().is_relative_to(root.resolve()):
        raise HTTPException(403,'Path leaves the agent sandbox')
    return candidate


def put_file(agent_id,path,content):
    """Write UTF-8 atomically within the agent directory; also used for fixtures."""
    data=content.encode('utf-8')
    if len(data)>MAX_FILE_BYTES:
        raise HTTPException(413,'Sandbox files are limited to 100000 UTF-8 bytes')
    target=safe_path(agent_id,path)
    target.parent.mkdir(parents=True,exist_ok=True)
    if target.exists() and not target.is_file():
        raise HTTPException(409,'A directory already occupies this path')
    temporary=None
    try:
        with tempfile.NamedTemporaryFile(dir=target.parent,delete=False) as stream:
            temporary=Path(stream.name)
            stream.write(data)
        os.replace(temporary,target)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return target


def seed_agent(connection,agent_id):
    if connection.execute('SELECT 1 FROM sandbox_agents WHERE agent=?',(agent_id,)).fetchone():
        return
    root=agent_root(agent_id)
    # Import legacy content once, without overwriting any existing sandbox file.
    for row in connection.execute('SELECT name,body FROM files WHERE agent=?',(agent_id,)).fetchall():
        try:
            path=validate_path(row['name'])
        except ValueError:
            continue
        if not safe_path(agent_id,path).exists():
            put_file(agent_id,path,row['body'])
    for source in sorted(SEEDS.iterdir()):
        if source.is_file() and not source.is_symlink() and not (root/source.name).exists():
            put_file(agent_id,source.name,source.read_text(encoding='utf-8-sig'))
    connection.execute('INSERT INTO sandbox_agents VALUES(?)',(agent_id,))


def execute(connection,agent_id,action):
    seed_agent(connection,agent_id)
    args=action.args
    if action.tool=='run_command':
        return {'simulated':True,'stdout':'Sandbox command completed (simulated). No command was executed.','exit_code':0}
    if action.tool=='list_files':
        directory=safe_path(agent_id,args['dir'],directory=True)
        if not directory.is_dir():
            raise HTTPException(404,'Sandbox directory not found')
        entries=[]
        for item in sorted(directory.iterdir()):
            if item.name=='.trash':
                continue
            no_links(item)
            entries.append({'name':item.name,'type':'directory' if item.is_dir() else 'file',
                            'path':item.relative_to(agent_root(agent_id)).as_posix()})
            if len(entries)==1000:
                break
        return {'dir':args['dir'] or '.', 'entries':entries,'limit':1000}
    if action.tool=='write_file':
        target=safe_path(agent_id,args['path'])
        overwritten=target.exists()
        put_file(agent_id,args['path'],args['content'])
        return {'written':args['path'],'bytes':len(args['content'].encode('utf-8')),'overwritten':overwritten}
    if action.tool in ('read_file','delete_file'):
        target=safe_path(agent_id,args['path'])
        if not target.is_file():
            raise HTTPException(404,'Sandbox file not found')
        if action.tool=='read_file':
            if target.stat().st_size>MAX_FILE_BYTES:
                raise HTTPException(413,'Sandbox file is too large')
            try:
                content=target.read_text(encoding='utf-8')
            except UnicodeDecodeError:
                raise HTTPException(422,'Sandbox file is not UTF-8 text') from None
            return {'content':content,'untrusted':args['path'] in ('untrusted.txt','meeting_notes.txt')}
        trash_id=secrets.token_hex(16)
        stored=f'.trash/{trash_id}/{args["path"]}'
        destination=safe_path(agent_id,stored,internal=True)
        destination.parent.mkdir(parents=True,exist_ok=True)
        os.replace(target,destination)
        connection.execute('INSERT INTO trash(id,agent,path,stored_path,deleted_at,status) VALUES(?,?,?,?,?,?)',
                           (trash_id,agent_id,args['path'],stored,datetime.now(timezone.utc).isoformat(),'trashed'))
        return {'deleted':args['path'],'trash_id':trash_id,'recoverable':True}
    if action.tool=='send_email':
        sent_at=datetime.now(timezone.utc).isoformat()
        cursor=connection.execute('INSERT INTO outbox(agent,recipient,subject,body,sent_at) VALUES(?,?,?,?,?)',
                                  (agent_id,args['to'],args['subject'],args['body'],sent_at))
        return {'delivery':'sandbox outbox only','message_id':cursor.lastrowid,
                'to':args['to'],'subject':args['subject'],'body':args['body'],'sent_at':sent_at}
    raise HTTPException(422,'Unknown sandbox tool')


def restore(connection,trash_id):
    row=connection.execute('SELECT * FROM trash WHERE id=?',(trash_id,)).fetchone()
    if row is None:
        raise HTTPException(404,'Trash entry not found')
    if row['status']!='trashed':
        raise HTTPException(409,'File already restored')
    source=safe_path(row['agent'],row['stored_path'],internal=True)
    target=safe_path(row['agent'],row['path'])
    if target.exists():
        raise HTTPException(409,'Restore would overwrite an existing sandbox file')
    if not source.is_file():
        raise HTTPException(404,'Trashed file not found')
    target.parent.mkdir(parents=True,exist_ok=True)
    os.replace(source,target)
    connection.execute("UPDATE trash SET status='restored' WHERE id=?",(trash_id,))
    return {'restored':row['path'],'agent':row['agent'],'trash_id':trash_id}
