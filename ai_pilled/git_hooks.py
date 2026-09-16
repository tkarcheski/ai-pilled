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
    directory.mkdir(parents=True, exist_ok=True)
    source = str(Path(__file__).resolve().parent.parent)
    hashes = {}
    for event in ('pre-commit', 'commit-msg'):
        content = ('#!/bin/sh\n# Managed by ai-pilled.\n'
                   f'PYTHONDONTWRITEBYTECODE=1 PYTHONPATH={shlex.quote(source)} '
                   f'exec {shlex.quote(sys.executable)} -m ai_pilled '
                   f'--repo {shlex.quote(str(repo))} hook {event} "$@"\n')
        path = directory / event
        if path.is_symlink():
            raise CommandError('Refusing to replace a symlink hook')
        if path.exists() and path.read_text() != content:
            raise CommandError('Existing hook differs from generated content; preserve and reconcile manually')
        path.write_text(content)
        hashes[event] = hashlib.sha256(content.encode()).hexdigest()
        path.chmod(0o755)
    if not manifest.exists():
        manifest.write_text(json.dumps({'previous': previous, 'scope': scope,
                                       'hooks_path': str(directory), 'hashes': hashes}, indent=2))
    run(['git', 'config', scope, 'core.hooksPath', str(directory)], repo)
    return Report('install-git-hooks')


def uninstall(repo):
    repo = Path(run(['git', 'rev-parse', '--show-toplevel'], repo).decode().strip())
    manifest = repo / '.ai-pilled' / 'installation.json'
    if not manifest.exists():
        return Report('uninstall-git-hooks')
    if (repo / '.ai-pilled').is_symlink() or manifest.is_symlink():
        raise CommandError('Refusing symlink installation paths')
    data = json.loads(manifest.read_text())
    expected = repo / '.ai-pilled' / 'hooks'
    if data.get('hooks_path') != str(expected) or data.get('scope') not in ('--local', '--worktree') or expected.is_symlink():
        raise CommandError('Invalid installation manifest')
    if data.get('previous') is not None and not isinstance(data['previous'], str):
        raise CommandError('Invalid previous hooks path')
    for name, checksum in data.get('hashes', {}).items():
        if name not in ('pre-commit', 'commit-msg'):
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
    # Keep generated files for inspection; next install can reuse only our known files.
    directory = Path(data['hooks_path'])
    for name in ('pre-commit', 'commit-msg'):
        path = directory / name
        if path.exists() and not path.is_symlink() and '# Managed by ai-pilled.' in path.read_text():
            path.unlink()
    if directory.exists() and not any(directory.iterdir()):
        directory.rmdir()
    return Report('uninstall-git-hooks')


def dispatch(repo, event, arguments):
    if event == 'pre-commit':
        return scan(repo)
    if event == 'commit-msg' and len(arguments) == 1:
        return commit_message(arguments[0])
    raise CommandError('Invalid Git hook arguments')
