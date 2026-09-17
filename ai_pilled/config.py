"""Strict project configuration; commands are argument lists, never shell strings."""
from dataclasses import dataclass, field
from .json_data import loads
import os
import re
import stat
from pathlib import Path


class ConfigError(ValueError):
    pass


@dataclass
class Config:
    commands: dict[str, list[str]] = field(default_factory=dict)
    protected_branches: list[str] = field(default_factory=lambda: ['main', 'master'])
    timeout: int = 120
    require_tests: bool = True
    aggressiveness: str = 'normal'
    review_on_commit: bool = False
    codex_executable: str = 'codex'
    audit_dependencies_on_change: bool = False
    review_checks_on_commit: bool = False
    python_requirements: list[str] = field(default_factory=list)
    python_audit_executable: str = 'pip-audit'


def load(repo):
    path = Path(repo) / '.ai-pilled.json'
    if path.is_symlink():
        raise ConfigError('Configuration must not be a symlink')
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    except FileNotFoundError:
        return Config()
    except OSError as exc:
        raise ConfigError('Cannot open .ai-pilled.json') from exc
    try:
        with os.fdopen(fd, 'rb') as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ConfigError('Configuration must be a regular file')
            content = stream.read(64_001)
        if len(content) > 64_000:
            raise ConfigError('Configuration exceeds the 64 KB size limit')
        return parse_config(content)
    except ConfigError:
        raise
    except (ValueError, OSError) as exc:
        raise ConfigError('Cannot read valid JSON from .ai-pilled.json') from exc


def parse_config(content):
    """Apply one strict schema to filesystem and staged policy bytes."""
    try:
        data = loads(content)
    except ValueError as exc:
        raise ConfigError('Cannot read valid JSON from .ai-pilled.json') from exc
    allowed = {'version', 'commands', 'protected_branches', 'timeout',
               'require_tests', 'aggressiveness', 'review_on_commit', 'codex_executable', 'audit_dependencies_on_change', 'review_checks_on_commit', 'python_requirements', 'python_audit_executable'}
    if not isinstance(data, dict) or set(data) - allowed:
        raise ConfigError('Configuration must be an object with supported keys')
    if type(data.get('version', 1)) is not int or data.get('version', 1) != 1:
        raise ConfigError('Configuration version must be 1')
    commands = data.get('commands', {})
    if not isinstance(commands, dict):
        raise ConfigError('commands must map check names to argument lists')
    for name, args in commands.items():
        if name not in {'test', 'lint', 'typecheck', 'deadcode', 'coverage', 'dependency', 'benchmark', 'simplify', 'repair'}:
            raise ConfigError('Unknown command check name')
        if not isinstance(args, list) or not args or any(
                not isinstance(a, str) or '\0' in a for a in args) or not args[0]:
            raise ConfigError('Each command must be a nonempty argument list')
    branches = data.get('protected_branches', ['main', 'master'])
    if not isinstance(branches, list) or any(not isinstance(b, str) or not b for b in branches):
        raise ConfigError('protected_branches must be a list of nonempty branch names')
    timeout = data.get('timeout', 120)
    if type(timeout) is not int or not 1 <= timeout <= 3600:
        raise ConfigError('timeout must be an integer between 1 and 3600 seconds')
    require_tests = data.get('require_tests', True)
    if type(require_tests) is not bool:
        raise ConfigError('require_tests must be boolean')
    aggressiveness = data.get('aggressiveness', 'normal')
    if aggressiveness not in ('lazy', 'normal', 'strict'):
        raise ConfigError('aggressiveness must be lazy, normal, or strict')
    review_on_commit = data.get('review_on_commit', False)
    if type(review_on_commit) is not bool:
        raise ConfigError('review_on_commit must be boolean')
    executable = data.get('codex_executable', 'codex')
    if not isinstance(executable, str) or not executable or '\0' in executable:
        raise ConfigError('codex_executable must be a nonempty executable path or command name')
    dependency_changes = data.get('audit_dependencies_on_change', False)
    if type(dependency_changes) is not bool:
        raise ConfigError('audit_dependencies_on_change must be boolean')
    review_checks = data.get('review_checks_on_commit', False)
    if type(review_checks) is not bool:
        raise ConfigError('review_checks_on_commit must be boolean')
    python_files = data.get('python_requirements', [])
    if (not isinstance(python_files, list) or len(python_files) > 32
            or any(not isinstance(p, str) or not p or len(p) > 1000 or '\0' in p
                   or Path(p).is_absolute() or '..' in Path(p).parts for p in python_files)
            or len(set(python_files)) != len(python_files)):
        raise ConfigError('python_requirements must list at most 32 unique repository-relative paths')
    python_executable = data.get('python_audit_executable', 'pip-audit')
    if not isinstance(python_executable, str) or not python_executable or '\0' in python_executable:
        raise ConfigError('python_audit_executable must be a nonempty executable path or command name')
    return Config(commands, branches, timeout, require_tests, aggressiveness,
                  review_on_commit, executable, dependency_changes, review_checks, python_files, python_executable)


def load_staged(repo):
    """Load only the resolved regular policy blob selected by Git's index."""
    from .runtime import CommandError, run
    try:
        records = list(filter(None, run(['git', 'ls-files', '--stage', '-z', '--', '.ai-pilled.json'],
                                        repo, limit=2048).split(b'\0')))
        if not records:
            return Config()
        if len(records) != 1:
            raise ConfigError('Staged configuration must be a resolved regular file')
        metadata, path = records[0].split(b'\t', 1)
        mode, oid, stage = metadata.split()
        if (path != b'.ai-pilled.json' or mode not in (b'100644', b'100755') or stage != b'0'
                or re.fullmatch(rb'[0-9a-f]{40}(?:[0-9a-f]{24})?', oid) is None):
            raise ConfigError('Staged configuration must be a resolved regular file')
        return parse_config(run(['git', 'cat-file', 'blob', oid.decode('ascii')], repo, limit=64_000))
    except ConfigError:
        raise
    except (CommandError, ValueError, OSError) as exc:
        raise ConfigError('Cannot read complete staged configuration') from exc
