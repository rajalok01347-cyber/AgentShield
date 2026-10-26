"""Database-only tools: no host file access and no email delivery."""
from fastapi import HTTPException


def execute(connection, agent_id, action):
    if action.tool in ('read_file', 'delete_file'):
        name = action.args['path']
        row = connection.execute(
            'SELECT body FROM files WHERE agent=? AND name=?', (agent_id, name)
        ).fetchone()
        if row is None:
            raise HTTPException(404, 'Sandbox file not found')
        if action.tool == 'read_file':
            return {'content': row['body'], 'untrusted': name == 'untrusted.txt'}
        connection.execute(
            'DELETE FROM files WHERE agent=? AND name=?', (agent_id, name)
        )
        return {'deleted': name}
    cursor = connection.execute(
        'INSERT INTO outbox(agent,recipient,body) VALUES(?,?,?)',
        (agent_id, action.args['to'], action.args['body']),
    )
    return {'delivery': 'sandbox outbox only', 'message_id': cursor.lastrowid,
            'to': action.args['to'], 'body': action.args['body']}
