"""Configured checks preserve failure, missing-tool, and timeout states."""
import os

from .config import load
from .runtime import CommandError, Report, run


def command_check(repo, name):
    config = load(repo)
    report = Report(name)
    argv = config.commands.get(name)
    if argv is None:
        report.add('not-configured', f'Configure commands.{name} in .ai-pilled.json.',
                   severity='warning')
        return report
    try:
        # Git hooks export routing variables. A test creating another repo must
        # not inherit the parent repository's Git directory, index, or config.
        env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
        run(argv, repo, timeout=config.timeout, env=env)
    except CommandError as exc:
        report.add('command-failed', str(exc))
    return report
