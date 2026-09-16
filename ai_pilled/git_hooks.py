"""Git gates and reversible hook installation."""
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import sys

from .runtime import CommandError, Report, run
from .security import scan


def commit_message(path):
    report = Report('commit-message')
    lines = Path(path).read_text().splitlines()
    subject = next((line for line in lines if line and not line.startswith('#')), '')
    if not re.fullmatch(r'(feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)'
                        r'(\([^()\r\n]+\))?!?: \S.*', subject):
        report.add('conventional-commit', 'Use type(scope): subject, for example fix: handle empty input.')
    if len(subject) > 72:
        report.add('subject-length', 'Keep the commit subject at 72 characters or fewer.')
    return report


def git_value(repo, key, scope='--local'):
    # Git returns 1 when a key is absent; other failures are not absence.
    import subprocess
    result = subprocess.run(['git', 'config', scope, '--get', key], cwd=repo,
                            capture_output=True, timeout=10)
    if result.returncode == 1:
        return None
    if result.returncode:
        raise CommandError('Cannot read Git configuration')
    return result.stdout.decode().rstrip('\n')


def hook_config_scope(repo):
    common = Path(run(['git', 'rev-parse', '--git-common-dir'], repo).decode().strip())
    gitdir = Path(run(['git', 'rev-parse', '--git-dir'], repo).decode().strip())
    if (repo / common).resolve() == (repo / gitdir).resolve():
        return '--local'
    if git_value(repo, 'extensions.worktreeConfig') != 'true':
        if git_value(repo, 'core.worktree') is not None or git_value(repo, 'core.bare') == 'true':
            raise CommandError('Configure Git worktreeConfig manually for this repository layout')
        run(['git', 'config', '--local', 'extensions.worktreeConfig', 'true'], repo)
    return '--worktree'


def install(repo):
    repo = Path(run(['git', 'rev-parse', '--show-toplevel'], repo).decode().strip())
    directory = repo / '.ai-pilled' / 'hooks'
    manifest = repo / '.ai-pilled' / 'installation.json'
    if (repo / '.ai-pilled').is_symlink() or directory.is_symlink() or manifest.is_symlink():
        raise CommandError('Refusing symlink installation paths')
    scope = hook_config_scope(repo)
    previous = git_value(repo, 'core.hooksPath', scope)
    # Effective user/global settings count too: do not replace another hook manager.
    import subprocess
    result = subprocess.run(['git', 'config', '--get', 'core.hooksPath'],
                            cwd=repo, capture_output=True, timeout=10)
    if result.returncode not in (0, 1):
        raise CommandError('Cannot read effective hooks path')
    effective = result.stdout.decode().rstrip('\n') if result.returncode == 0 else None
    if effective not in (None, str(directory)):
        raise CommandError('Existing core.hooksPath detected; compose hooks manually')
    if not manifest.exists():
        default_hooks = Path(run(['git', 'rev-parse', '--git-path', 'hooks'], repo).decode().strip())
        if not default_hooks.is_absolute():
            default_hooks = repo / default_hooks
        if default_hooks.exists() and any(p.is_file() and os.access(p, os.X_OK)
                                         and not p.name.endswith('.sample')
                                         for p in default_hooks.iterdir()):
            raise CommandError('Existing executable Git hooks detected; compose hooks manually')
        if directory.exists():
            raise CommandError('Unmanaged .ai-pilled/hooks directory already exists')
    installed = read_manifest(manifest, directory) if manifest.exists() else None
    source = str(Path(__file__).resolve().parent.parent)
    contents = {}
    hashes = {}
    for event in ('pre-commit', 'commit-msg', 'pre-push'):
        content = ('#!/bin/sh\n# Managed by ai-pilled.\n'
                   f'PYTHONDONTWRITEBYTECODE=1 PYTHONPATH={shlex.quote(source)} '
                   f'exec {shlex.quote(sys.executable)} -m ai_pilled '
                   f'--repo {shlex.quote(str(repo))} hook {event} "$@"\n')
        path = directory / event
        if path.is_symlink():
            raise CommandError('Refusing to replace a symlink hook')
        if path.exists() and (not path.is_file() or path.read_text() != content):
            raise CommandError('Existing hook differs from generated content; preserve and reconcile manually')
        if path.exists() and not os.access(path, os.X_OK):
            raise CommandError('Installed hook is no longer executable; reconcile manually')
        contents[event] = content
        hashes[event] = hashlib.sha256(content.encode()).hexdigest()
    if installed:
        if installed['scope'] != scope or installed['hashes'] != hashes:
            raise CommandError('Installation manifest differs from generated hooks; reconcile manually')
        previous = installed['previous']
    # Validate every owned file before creating or rewriting any of them.
    directory.mkdir(parents=True, exist_ok=True)
    created = []
    try:
        for event, content in contents.items():
            path = directory / event
            if not path.exists():
                created.append(path)
                path.write_text(content)
                path.chmod(0o755)
        if not installed:
            manifest.write_text(json.dumps({'previous': previous, 'scope': scope,
                                            'hooks_path': str(directory), 'hashes': hashes}, indent=2))
        run(['git', 'config', scope, 'core.hooksPath', str(directory)], repo)
    except BaseException:
        for path in created:
            path.unlink(missing_ok=True)
        if not installed:
            manifest.unlink(missing_ok=True)
            if not any(directory.iterdir()):
                directory.rmdir()
        raise
    return Report('install-git-hooks')


def read_manifest(manifest, expected):
    try:
        data = json.loads(manifest.read_text())
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
    return data


def uninstall(repo):
    repo = Path(run(['git', 'rev-parse', '--show-toplevel'], repo).decode().strip())
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
        if path.is_symlink() or (path.exists() and hashlib.sha256(path.read_bytes()).hexdigest() != checksum):
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
        return pre_push(repo, sys.stdin.read())
    if event == 'pre-commit':
        return scan(repo)
    if event == 'commit-msg' and len(arguments) == 1:
        return commit_message(arguments[0])
    raise CommandError('Invalid Git hook arguments')
