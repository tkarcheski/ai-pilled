"""Run comprehensive checks against the index, without borrowing unstaged source."""
import os
from pathlib import Path
import tempfile

from .codex_review import materialize_index, review
from .config import ConfigError
from .pipeline import PipelineReport, combine, quality
from .runtime import CommandError, isolated_git, run, git_path
from .security import scan
from .state import record


def review_checks(repo, model=False, executable=None):
    root = git_path(run(['git', 'rev-parse', '--show-toplevel'], repo))
    report = PipelineReport('staged-review')
    before = scan(root, patterns=True)
    report.snapshot = before.snapshot
    combine(report, before)
    try:
        if before.status == 'pass':
            with tempfile.TemporaryDirectory(prefix='ai-pilled-staged-checks-') as temporary:
                snapshot = Path(temporary) / 'snapshot'
                snapshot.mkdir()
                materialize_index(root, snapshot)
                if scan(root, patterns=True).snapshot != before.snapshot:
                    raise CommandError('Index changed while preparing staged checks; rerun')
                env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
                run(['git', 'init', '-q', '-b', 'staged-review'], snapshot, env=env)
                (snapshot / '.git/info/exclude').write_text('.ai-pilled/\n')
                run(['git', 'add', '--force', '--all'], snapshot, env=env)
                with isolated_git():
                    result = quality(snapshot, executable_root=root, comprehensive=True)
                combine(report, result)
            after = scan(root, patterns=True)
            if after.status != 'pass':
                combine(report, after)
            if after.snapshot != before.snapshot:
                raise CommandError('Index changed during staged checks; rerun')
            if model and report.status == 'pass':
                result = review(root, executable)
                combine(report, result)
                if result.snapshot != before.snapshot or scan(root).snapshot != before.snapshot:
                    raise CommandError('Index changed between checks and model review; rerun')
    except (CommandError, ConfigError, OSError, ValueError) as exc:
        report.add('staged-checks-unavailable', str(exc) if isinstance(exc, (CommandError, ConfigError))
                   else 'Cannot prepare staged check evidence', severity='warning')
    report.metrics = {'checks_run': len(report.checks),
                      'checks_passed': sum(c['status'] == 'pass' for c in report.checks)}
    record(root, report, 'staged-review')
    return report
