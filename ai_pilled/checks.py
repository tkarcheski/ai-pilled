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
    argv = list(argv)
    if executable_root is not None and not Path(argv[0]).is_absolute() and '/' in argv[0]:
        executable = Path(executable_root) / argv[0]
        if (not (Path(repo) / argv[0]).exists() and executable.is_file()
                and not run(['git', 'ls-files', '--', argv[0]], executable_root)):
            argv[0] = str(executable.absolute())
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
