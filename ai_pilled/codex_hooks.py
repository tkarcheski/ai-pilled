"""Merge command hooks into project-local Codex configuration; preserve unrelated hooks."""
from contextlib import contextmanager
import fcntl
import json
from .json_data import loads
import os
from pathlib import Path
import shlex
import stat
import sys

from .runtime import CommandError, Report, run
from .state import atomic_text, directory


def groups(repo):
    source = Path(__file__).resolve().parent.parent
    command = (f'PYTHONDONTWRITEBYTECODE=1 PYTHONPATH={shlex.quote(str(source))} '
               f'{shlex.quote(sys.executable)} -m ai_pilled '
               f'--repo {shlex.quote(str(repo))} lifecycle')
    return {event: [{'matcher': matcher, 'hooks': [
        {'type': 'command', 'command': command, 'timeout': timeout,
         'statusMessage': f'ai-pilled: {label}'}]}]
        for event, matcher, timeout, label in (
            ('SessionStart', 'startup|resume|clear|compact', 30, 'repository state'),
            ('PostToolUse', '*', 60, 'checks and tool summary'),
            ('Stop', '', 180, 'test results'))}


def read_object(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise CommandError('Codex configuration must be a regular file')
            content = stream.read(1_000_001)
        if len(content) > 1_000_000:
            raise CommandError('Codex configuration exceeds the 1 MB size limit')
        data = loads(content)
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as exc:
        raise CommandError('Cannot read valid regular JSON configuration') from exc
    if not isinstance(data, dict):
        raise CommandError('Configuration must be a JSON object')
    return data


def render_object(data):
    chunks = []
    size = 1  # Final newline.
    for chunk in json.JSONEncoder(indent=2).iterencode(data):
        size += len(chunk)  # The encoder escapes non-ASCII characters by default.
        if size > 1_000_000:
            raise CommandError('Updated Codex configuration exceeds the 1 MB size limit')
        chunks.append(chunk)
    return ''.join(chunks) + '\n'


@contextmanager
def locked(repo):
    root = Path(run(['git', 'rev-parse', '--show-toplevel'], repo).decode().strip())
    state = directory(root)
    if (root / '.codex').is_symlink():
        raise CommandError('Refusing symlink Codex configuration directory')
    fd = os.open(state / 'codex-install.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    with os.fdopen(fd, 'rb') as lock:
        if not stat.S_ISREG(os.fstat(lock.fileno()).st_mode):
            raise CommandError('Codex installation lock must be a regular file')
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield root, state


def validate_hooks(data):
    hooks = data.get('hooks', {})
    if not isinstance(hooks, dict) or any(not isinstance(v, list) for v in hooks.values()):
        raise CommandError('Expected Codex hook event arrays')
    return hooks


def read_installation(path, root):
    if not path.exists() and not path.is_symlink():
        return None
    data = read_object(path)
    current = groups(root)
    legacy = groups(root)
    legacy['PostToolUse'][0]['matcher'] = 'Bash|apply_patch|Write|Edit'
    legacy['PostToolUse'][0]['hooks'][0]['statusMessage'] = 'ai-pilled: credential scan'
    if set(data) != {'groups'} or data['groups'] not in (current, legacy):
        raise CommandError('Installation metadata differs from this runtime; use the original runtime or reconcile manually')
    return data


def install(repo):
    with locked(repo) as (root, state):
        path = root / '.codex' / 'hooks.json'
        manifest_path = state / 'codex-installation.json'
        data = read_object(path)
        hooks = validate_hooks(data)
        desired = groups(root)
        previous = read_installation(manifest_path, root)
        if previous:
            if previous['groups'] != desired:
                raise CommandError('Owned hook definitions changed; uninstall and reinstall to review the new definitions')
            if any(hooks.get(event, []).count(group) != 1
                   for event, entries in desired.items() for group in entries):
                raise CommandError('Installed Codex hooks were edited; preserve and reconcile manually')
        else:
            if any(group in hooks.get(event, []) for event, entries in desired.items() for group in entries):
                raise CommandError('Matching unmanaged Codex hooks already exist')
            for event, entries in desired.items():
                hooks.setdefault(event, []).extend(entries)
            data['hooks'] = hooks
            rendered = render_object(data)
            manifest = render_object({'groups': desired})
            # A manifest written first lets a later invocation detect an interrupted install.
            atomic_text(manifest_path, manifest)
            atomic_text(path, rendered)
    result = Report('install-codex-hooks')
    # Installation is complete, activation remains explicitly separate.
    result.findings = []
    return result


def uninstall(repo):
    with locked(repo) as (root, state):
        path = root / '.codex' / 'hooks.json'
        manifest_path = state / 'codex-installation.json'
        previous = read_installation(manifest_path, root)
        if not previous:
            return Report('uninstall-codex-hooks')
        data = read_object(path)
        hooks = validate_hooks(data)
        for event, entries in previous.get('groups', {}).items():
            for group in entries:
                if hooks.get(event, []).count(group) != 1:
                    raise CommandError('Installed Codex hooks were edited; preserve and reconcile manually')
        for event, entries in previous['groups'].items():
            for group in entries:
                hooks[event].remove(group)
            if not hooks[event]:
                del hooks[event]
        data['hooks'] = hooks
        atomic_text(path, render_object(data))
        manifest_path.unlink()
    return Report('uninstall-codex-hooks')
