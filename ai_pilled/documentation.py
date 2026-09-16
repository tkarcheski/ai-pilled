"""Update one generated README block while preserving handwritten content."""
import argparse
import hashlib

from .config import ConfigError, load
from .metrics import local_path
from .runtime import CommandError, Report
from .state import atomic_text

START = '<!-- ai-pilled:commands:start -->'
END = '<!-- ai-pilled:commands:end -->'


def replace_block(original, block):
    if START not in original and END not in original:
        return original.rstrip() + ('\n\n' if original.strip() else '') + block + '\n'
    if original.count(START) != 1 or original.count(END) != 1:
        raise CommandError('README must contain either no markers or exactly one complete generated block')
    start, end = original.index(START), original.index(END)
    if end < start:
        raise CommandError('README generated markers are in the wrong order')
    return original[:start] + block + original[end + len(END):]


def update_readme(repo, name='README.md', check=False):
    report = Report('readme-reference')
    try:
        from .__main__ import build_parser
        config = load(repo)
        parser = build_parser()
        # Fixed width avoids generated churn from terminal size.
        def formatter(prog):
            return argparse.HelpFormatter(prog, width=88)
        parser.formatter_class = formatter
        help_text = parser.format_help().rstrip()
        configured = ', '.join(sorted(config.commands)) or 'none'
        block = '\n'.join((START, '## ai-pilled command reference', '',
                           'Generated from the installed CLI and project check configuration.', '',
                           f'Quality profile: **{config.aggressiveness}**. Configured commands: {configured}.',
                           'Configuration is not proof that checks passed; use quality to run them.', '',
                           '~~~text', help_text, '~~~', END))
        path = local_path(repo, name)
        if path.exists() and (not path.is_file() or path.stat().st_size > 2_000_000):
            raise CommandError('README must be a bounded regular file')
        original = path.read_text() if path.exists() else ''
        rendered = replace_block(original, block)
        report.snapshot = hashlib.sha256(rendered.encode()).hexdigest()
        changed = rendered != original
        report.metrics = {'changed': int(changed)}
        if check and changed:
            report.add('readme-outdated', 'Regenerate the ai-pilled command reference.', path=name)
        elif changed:
            mode = path.stat().st_mode & 0o777 if path.exists() else 0o644
            atomic_text(path, rendered, mode)
    except (CommandError, ConfigError, OSError, UnicodeError) as exc:
        report.add('readme-update-unavailable', str(exc) if isinstance(exc, (CommandError, ConfigError))
                   else 'Cannot read or update README', severity='warning')
    return report
