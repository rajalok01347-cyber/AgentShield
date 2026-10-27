"""Small .env loader for local development; process environment always takes precedence."""
import os
import re
from pathlib import Path

_KEY = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')


def load_env(path=None):
    env_path = Path(path) if path else Path(__file__).resolve().parent.parent / '.env'
    if not env_path.is_file():
        return
    for raw_line in env_path.read_text(encoding='utf-8').splitlines():
        line = raw_line.strip()
        if not line or line.startswith('#'):
            continue
        if line.startswith('export '):
            line = line[7:].lstrip()
        name, separator, value = line.partition('=')
        name, value = name.strip(), value.strip()
        if not separator or not _KEY.fullmatch(name):
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
            value = value[1:-1]
        os.environ.setdefault(name, value)
