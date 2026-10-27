"""Validated, ordered policies. Every condition must match; first matching rule wins."""
import re
from pathlib import PurePosixPath
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, StrictInt, field_validator


class Conditions(BaseModel):
    model_config = ConfigDict(extra='forbid')
    to_domain_in: list[str] | None = None
    path_prefix: str | None = None
    max_size: StrictInt | None = Field(default=None, gt=0)

    @field_validator('to_domain_in')
    @classmethod
    def domains(cls, values):
        if values is None:
            return values
        if not values:
            raise ValueError('Domain allowlist cannot be empty')
        normalized = [v.lower() for v in values]
        if any(not re.fullmatch(r'[a-z0-9-]+(?:\.[a-z0-9-]+)+', v) for v in normalized):
            raise ValueError('Use exact domain names, without URLs or wildcards')
        return normalized

    @field_validator('path_prefix')
    @classmethod
    def prefix(cls, value):
        if value is not None and (not value or '\\' in value or value.startswith('/') or '..' in value.split('/')):
            raise ValueError('Use a relative sandbox path prefix without traversal')
        return value


class Rule(BaseModel):
    model_config = ConfigDict(extra='forbid')
    tool: str = Field(min_length=1, max_length=100)
    action: Literal['allow', 'block', 'approve']
    reason: str | None = Field(default=None, max_length=1000)
    when: Conditions = Field(default_factory=Conditions)


class Policy(BaseModel):
    model_config = ConfigDict(extra='forbid')
    name: str = Field(min_length=1, max_length=100)
    rules: list[Rule] = Field(max_length=100)
    default: Literal['block'] = 'block'


def email_domain(value):
    if not isinstance(value, str) or not re.fullmatch(r'[^\s@,;<>]+@[^\s@,;<>]+', value):
        return None
    return value.rsplit('@', 1)[1].lower()


def matches(conditions, args):
    if conditions.to_domain_in is not None and email_domain(args.get('to')) not in conditions.to_domain_in:
        return False
    if conditions.path_prefix is not None:
        path = args.get('path', '')
        if not path or path.startswith('/') or '\\' in path or '..' in path.split('/'):
            return False
        prefix = conditions.path_prefix.rstrip('/')
        normalized = str(PurePosixPath(path))
        if normalized != prefix and not normalized.startswith(prefix + '/'):
            return False
    if conditions.max_size is not None:
        if any(not isinstance(value, str) for value in args.values()):
            return False
        if sum(len(value) for value in args.values()) >= conditions.max_size:
            return False
    return True


def evaluate(policy, tool, args):
    for index, rule in enumerate(policy.rules):
        if rule.tool == tool and matches(rule.when, args):
            return rule.action, rule.reason or f'Policy rule {index + 1}: {rule.action}'
    return 'block', 'No policy rule matched; default block'


def outbound_domains(policy):
    return {domain for rule in policy.rules if rule.tool == 'send_email' and rule.action == 'allow'
            for domain in (rule.when.to_domain_in or [])}


DEFAULT_POLICY = Policy(name='default-assistant', rules=[
    Rule(tool='read_file', action='allow'),
    Rule(tool='list_files', action='allow'),
    Rule(tool='delete_file', action='block', reason='Deletion is not permitted'),
    Rule(tool='send_email', action='allow', when=Conditions(to_domain_in=['ourcompany.com'])),
    Rule(tool='send_email', action='approve', reason='External email needs approval'),
    Rule(tool='run_command', action='block'),
])
