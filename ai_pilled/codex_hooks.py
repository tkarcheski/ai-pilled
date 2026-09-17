"""Merge command hooks into project-local Codex configuration; preserve unrelated hooks."""
from contextlib import contextmanager
import fcntl
from .locking import acquire_lock
import hashlib
import json
from .json_data import loads
import os
from pathlib import Path
import shlex
import stat
import sys

from .runtime import CommandError, Report, run, git_path
from .state import atomic_text, directory
from .file_io import directory_beneath, read_snapshot as read_file_snapshot


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


def read_snapshot(path, root):
    try:
        content, identity = read_file_snapshot(path, 1_000_000, root=root)
        if content is None:
            return {}, None
        data = loads(content)
    except (OSError, ValueError) as exc:
        raise CommandError('Cannot read valid regular JSON configuration') from exc
    if not isinstance(data, dict):
        raise CommandError('Configuration must be a JSON object')
    return data, (*identity, hashlib.sha256(content).hexdigest())


def require_unchanged(path, snapshot, root):
    if read_snapshot(path, root)[1] != snapshot:
        raise CommandError('Codex configuration changed concurrently; retry after reconciling edits')


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
    root = git_path(run(['git', 'rev-parse', '--show-toplevel'], repo))
    state = directory(root)
    if (root / '.codex').is_symlink():
        raise CommandError('Refusing symlink Codex configuration directory')
    with directory_beneath(root, state.relative_to(root)) as parent:
        fd = os.open('codex-install.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK,
                     0o600, dir_fd=parent)
    with os.fdopen(fd, 'rb') as lock:
        if not stat.S_ISREG(os.fstat(lock.fileno()).st_mode):
            raise CommandError('Codex installation lock must be a regular file')
        acquire_lock(lock, fcntl.LOCK_EX)
        yield root, state


def validate_hooks(data):
    hooks = data.get('hooks', {})
    if not isinstance(hooks, dict) or any(not isinstance(v, list) for v in hooks.values()):
        raise CommandError('Expected Codex hook event arrays')
    return hooks


def read_installation(path, root):
    data, snapshot = read_snapshot(path, root)
    if snapshot is None:
        return None, None
    current = groups(root)
    legacy = groups(root)
    legacy['PostToolUse'][0]['matcher'] = 'Bash|apply_patch|Write|Edit'
    legacy['PostToolUse'][0]['hooks'][0]['statusMessage'] = 'ai-pilled: credential scan'
    if set(data) != {'groups'} or data['groups'] not in (current, legacy):
        raise CommandError('Installation metadata differs from this runtime; use the original runtime or reconcile manually')
    return data, snapshot


def install(repo):
    with locked(repo) as (root, state):
        path = root / '.codex' / 'hooks.json'
        manifest_path = state / 'codex-installation.json'
        data, config_snapshot = read_snapshot(path, root)
        hooks = validate_hooks(data)
        desired = groups(root)
        previous, manifest_snapshot = read_installation(manifest_path, root)
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
            # Never replace ownership metadata created by a concurrent writer.
            owned_identity = atomic_text(manifest_path, manifest, exclusive=True, root=root)
            _, owned_snapshot = read_snapshot(manifest_path, root)
            if (owned_snapshot is None or owned_snapshot[:2] != owned_identity
                    or owned_snapshot[-1] != hashlib.sha256(manifest.encode()).hexdigest()):
                raise CommandError('Codex installation metadata changed concurrently')
            publishing = False

            def guard():
                nonlocal publishing
                require_unchanged(path, config_snapshot, root)
                require_unchanged(manifest_path, owned_snapshot, root)
                publishing = True

            try:
                atomic_text(path, rendered, before_publish=guard, root=root)
            except (OSError, CommandError):
                # Keep recovery metadata if publication may have succeeded.
                try:
                    if not publishing or read_snapshot(path, root)[1] == config_snapshot:
                        require_unchanged(manifest_path, owned_snapshot, root)
                        manifest_path.unlink()
                except (OSError, CommandError):
                    pass
                raise
            require_unchanged(manifest_path, owned_snapshot, root)
    result = Report('install-codex-hooks')
    # Installation is complete, activation remains explicitly separate.
    result.findings = []
    return result


def uninstall(repo):
    with locked(repo) as (root, state):
        path = root / '.codex' / 'hooks.json'
        manifest_path = state / 'codex-installation.json'
        previous, manifest_snapshot = read_installation(manifest_path, root)
        if not previous:
            return Report('uninstall-codex-hooks')
        data, config_snapshot = read_snapshot(path, root)
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
        def guard():
            require_unchanged(path, config_snapshot, root)
            require_unchanged(manifest_path, manifest_snapshot, root)

        atomic_text(path, render_object(data), before_publish=guard, root=root)
        require_unchanged(manifest_path, manifest_snapshot, root)
        manifest_path.unlink()
    return Report('uninstall-codex-hooks')
