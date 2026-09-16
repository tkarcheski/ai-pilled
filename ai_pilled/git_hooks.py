"""Git gates and reversible hook installation."""
from contextlib import contextmanager
import fcntl
from .locking import acquire_lock
import hashlib
import json
from .json_data import loads
import os
from pathlib import Path
import re
import shlex
import sys
import stat

from .runtime import CommandError, CommandFailed, Report, run, git_path
from .config import load
from .file_io import read_regular
from .commit_messages import check_subject
from .security import scan, scan_text
from .state import directory as state_directory


def commit_message(path):
    report = Report('commit-message')
    raw = read_regular(Path(path), 64_000)
    text = raw.decode('utf-8', errors='replace')
    scan_text(report, '(commit message)', text)
    lines = text.splitlines()
    subject = next((line for line in lines if line and not line.startswith('#')), '')
    check_subject(report, subject)
    return report


def git_value(repo, key, scope='--local'):
    # Git returns 1 when a key is absent; all other failures remain blocking.
    arguments = ['git', 'config', *([scope] if scope else []), '--get', key]
    try:
        output = run(arguments, repo, timeout=10, limit=16_000)
    except CommandFailed as exc:
        if exc.exit_code == 1:
            return None
        raise CommandError('Cannot read Git configuration') from exc
    if not output.endswith(b'\n'):
        raise CommandError('Incomplete Git configuration value')
    try:
        return output[:-1].decode('utf-8')
    except UnicodeError as exc:
        raise CommandError('Git configuration value must be valid UTF-8') from exc


def hook_config_scope(repo):
    common = git_path(run(['git', 'rev-parse', '--git-common-dir'], repo))
    gitdir = git_path(run(['git', 'rev-parse', '--git-dir'], repo))
    if (repo / common).resolve() == (repo / gitdir).resolve():
        return '--local'
    if git_value(repo, 'extensions.worktreeConfig') != 'true':
        if git_value(repo, 'core.worktree') is not None or git_value(repo, 'core.bare') == 'true':
            raise CommandError('Configure Git worktreeConfig manually for this repository layout')
        run(['git', 'config', '--local', 'extensions.worktreeConfig', 'true'], repo)
    return '--worktree'


def hook_contents(repo):
    source = str(Path(__file__).resolve().parent.parent)
    return {event: ('#!/bin/sh\n# Managed by ai-pilled.\n'
                   f'PYTHONDONTWRITEBYTECODE=1 PYTHONPATH={shlex.quote(source)} '
                   f'exec {shlex.quote(sys.executable)} -m ai_pilled '
                   f'--repo {shlex.quote(str(repo))} hook {event} "$@"\n')
            for event in ('pre-commit', 'commit-msg', 'pre-push')}


@contextmanager
def locked(repo):
    root = git_path(run(['git', 'rev-parse', '--show-toplevel'], repo))
    state = state_directory(root)
    fd = os.open(state / 'git-install.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    with os.fdopen(fd, 'r+') as lock:
        if not stat.S_ISREG(os.fstat(lock.fileno()).st_mode):
            raise CommandError('Git installation lock must be a regular file')
        acquire_lock(lock, fcntl.LOCK_EX)
        yield root


def verify_hook(path, content):
    if read_regular(path, 64_000) != content.encode():
        raise CommandError('Existing hook differs from generated content; preserve and reconcile manually')
    if not os.access(path, os.X_OK):
        raise CommandError('Installed hook is no longer executable; reconcile manually')


def create_owned_file(path, content, mode, created):
    """Claim a new file exclusively; never follow or truncate a racing replacement."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
        metadata = os.fstat(stream.fileno())
        created.append((path, metadata.st_dev, metadata.st_ino))
        stream.write(content)
        stream.flush()
        os.fchmod(stream.fileno(), mode)


def install(repo):
    with locked(repo) as root:
        return _install(root)


def _install(repo):
    directory = repo / '.ai-pilled' / 'hooks'
    manifest = repo / '.ai-pilled' / 'installation.json'
    if (repo / '.ai-pilled').is_symlink() or directory.is_symlink() or manifest.is_symlink():
        raise CommandError('Refusing symlink installation paths')
    scope = hook_config_scope(repo)
    previous = git_value(repo, 'core.hooksPath', scope)
    # Effective user/global settings count too: do not replace another hook manager.
    effective = git_value(repo, 'core.hooksPath', scope=None)
    if effective not in (None, str(directory)):
        raise CommandError('Existing core.hooksPath detected; compose hooks manually')
    if not manifest.exists():
        default_hooks = git_path(run(['git', 'rev-parse', '--git-path', 'hooks'], repo))
        if not default_hooks.is_absolute():
            default_hooks = repo / default_hooks
        if default_hooks.exists() and any(p.is_file() and os.access(p, os.X_OK)
                                         and not p.name.endswith('.sample')
                                         for p in default_hooks.iterdir()):
            raise CommandError('Existing executable Git hooks detected; compose hooks manually')
        if directory.exists():
            raise CommandError('Unmanaged .ai-pilled/hooks directory already exists')
    installed = read_manifest(manifest, directory) if manifest.exists() else None
    contents = hook_contents(repo)
    hashes = {}
    missing = set()
    for event, content in contents.items():
        path = directory / event
        if path.is_symlink():
            raise CommandError('Refusing to replace a symlink hook')
        try:
            verify_hook(path, content)
        except FileNotFoundError:
            missing.add(event)
        hashes[event] = hashlib.sha256(content.encode()).hexdigest()
    if installed:
        if installed['scope'] != scope or installed['hashes'] != hashes:
            raise CommandError('Installation manifest differs from generated hooks; reconcile manually')
        previous = installed['previous']
    # Validate every owned file before creating or rewriting any of them.
    directory.mkdir(parents=True, exist_ok=True)
    created: list[tuple[Path, int, int]] = []
    activation_started = False
    try:
        for event, content in contents.items():
            path = directory / event
            if event in missing:
                create_owned_file(path, content, 0o755, created)
        if not installed:
            create_owned_file(manifest, json.dumps({'previous': previous, 'scope': scope,
                              'hooks_path': str(directory), 'hashes': hashes}, indent=2), 0o600, created)
        for event, content in contents.items():
            verify_hook(directory / event, content)
        activation_started = True
        run(['git', 'config', scope, 'core.hooksPath', str(directory)], repo)
    except BaseException:
        if activation_started:
            try:
                active = git_value(repo, 'core.hooksPath', scope=None) == str(directory)
            except (CommandError, OSError):
                active = True  # An unknown outcome cannot authorize deleting potentially active hooks.
            if active:
                raise
        for path, device, inode in reversed(created):
            try:
                metadata = path.lstat()
                if (metadata.st_dev, metadata.st_ino) == (device, inode):
                    path.unlink()
            except FileNotFoundError:
                pass
        if not installed:
            if not any(directory.iterdir()):
                directory.rmdir()
        raise
    return Report('install-git-hooks')


def read_manifest(manifest, expected):
    try:
        data = loads(read_regular(manifest, 64_000))
    except (ValueError, OSError) as exc:
        raise CommandError('Cannot read installation manifest') from exc
    if (not isinstance(data, dict) or set(data) != {'previous', 'scope', 'hooks_path', 'hashes'}
            or data.get('hooks_path') != str(expected)
            or data.get('scope') not in ('--local', '--worktree') or expected.is_symlink()
            or (data.get('previous') is not None and not isinstance(data['previous'], str))):
        raise CommandError('Invalid installation manifest')
    hashes = data.get('hashes')
    if (not isinstance(hashes, dict) or set(hashes) != {'pre-commit', 'commit-msg', 'pre-push'}
            or any(not isinstance(h, str) or not re.fullmatch('[0-9a-f]{64}', h) for h in hashes.values())):
        raise CommandError('Invalid installation hook checksums')
    expected_hashes = {name: hashlib.sha256(content.encode()).hexdigest()
                       for name, content in hook_contents(expected.parent.parent).items()}
    if hashes != expected_hashes or data['previous'] not in (None, str(expected)):
        raise CommandError('Manifest does not match owned hooks; preserve and reconcile manually')
    return data


def uninstall(repo):
    with locked(repo) as root:
        return _uninstall(root)


def _uninstall(repo):
    manifest = repo / '.ai-pilled' / 'installation.json'
    if not manifest.exists():
        return Report('uninstall-git-hooks')
    if (repo / '.ai-pilled').is_symlink() or manifest.is_symlink():
        raise CommandError('Refusing symlink installation paths')
    expected = repo / '.ai-pilled' / 'hooks'
    data = read_manifest(manifest, expected)
    for name, checksum in data.get('hashes', {}).items():
        if name not in ('pre-commit', 'commit-msg', 'pre-push'):
            raise CommandError('Invalid installed hook name')
        path = expected / name
        if path.is_symlink() or (path.exists() and hashlib.sha256(read_regular(path, 64_000)).hexdigest() != checksum):
            raise CommandError('Installed hook changed; preserve and reconcile manually')
    if git_value(repo, 'core.hooksPath', data['scope']) != data['hooks_path']:
        raise CommandError('hooksPath changed since installation; preserve it and reconcile manually')
    if data['previous'] is None:
        run(['git', 'config', data['scope'], '--unset', 'core.hooksPath'], repo)
    else:
        run(['git', 'config', data['scope'], 'core.hooksPath', data['previous']], repo)
    manifest.unlink()
    directory = Path(data['hooks_path'])
    for name in ('pre-commit', 'commit-msg', 'pre-push'):
        path = directory / name
        if path.exists():
            path.unlink()
    if directory.exists() and not any(directory.iterdir()):
        directory.rmdir()
    return Report('uninstall-git-hooks')


def dispatch(repo, event, arguments):
    if event == 'pre-push':
        from .pre_push import pre_push
        if arguments and len(arguments) != 2:
            raise CommandError('Expected the Git pre-push remote name and destination')
        return pre_push(repo, sys.stdin.read(), destination=arguments[1] if arguments else None)
    if event == 'pre-commit':
        if load(repo).review_checks_on_commit:
            from .staged_review import review_checks
            return review_checks(repo)
        return scan(repo, patterns=load(repo).aggressiveness == 'strict')
    if event == 'commit-msg' and len(arguments) == 1:
        report = commit_message(arguments[0])
        if report.status != 'pass':
            return report
        config = load(repo)
        if config.review_on_commit:
            from .codex_review import review
            return review(repo, config.codex_executable,
                          read_regular(Path(arguments[0]), 64_000).decode(errors='replace'))
        return report
    raise CommandError('Invalid Git hook arguments')
