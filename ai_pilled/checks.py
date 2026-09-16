"""Configured checks preserve failure, missing-tool, and timeout states."""
import os
from pathlib import Path

from .config import load
from .runtime import CommandError, CommandUnavailable, Report, run


def command_check(repo, name, executable_root=None):
    config = load(repo)
    report = Report(name)
    argv = config.commands.get(name)
    if argv is None:
        report.add('not-configured', f'Configure commands.{name} in .ai-pilled.json.',
                   severity='warning')
        return report
    argv = [resolve_executable(repo, argv[0], executable_root), *argv[1:]]
    try:
        # Git hooks export routing variables. A test creating another repo must
        # not inherit the parent repository's Git directory, index, or config.
        env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
        run(argv, repo, timeout=config.timeout, env=env)
    except CommandUnavailable as exc:
        report.add('command-unavailable', str(exc), severity='warning')
    except CommandError as exc:
        report.add('command-failed', str(exc))
    return report


def resolve_executable(repo, executable, executable_root=None):
    if executable_root is not None and not Path(executable).is_absolute() and '/' in executable:
        original = Path(executable_root) / executable
        if (not (Path(repo) / executable).exists() and original.is_file()
                and not run(['git', 'ls-files', '--', executable], executable_root)):
            if not run(['git', 'check-ignore', '--', executable], executable_root, acceptable_codes=(0, 1)):
                return executable
            head = run(['git', 'rev-parse', '--verify', '--quiet', 'HEAD'], executable_root, acceptable_codes=(0, 1))
            if head and run(['git', 'ls-tree', '--name-only', 'HEAD', '--', executable], executable_root):
                return executable
            return str(original.absolute())
    return executable
