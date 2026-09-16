"""Configured checks preserve failure, missing-tool, and timeout states."""
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
        run(argv, repo, timeout=config.timeout)
    except CommandError as exc:
        report.add('command-failed', str(exc))
    return report
