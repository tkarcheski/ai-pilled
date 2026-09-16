"""Quality profiles and local PR-readiness checks with current-snapshot evidence."""
from dataclasses import dataclass, field
import fnmatch
from pathlib import Path

from .checks import command_check
from .config import ConfigError, load
from .dependencies import audit
from .runtime import CommandError, Report, run
from .security import scan
from .state import record

QUALITY_CHECKS = ('lint', 'typecheck', 'deadcode', 'coverage', 'dependency')


@dataclass
class PipelineReport(Report):
    checks: list[dict] = field(default_factory=list)


def combine(report, result):
    report.checks.append(result.to_dict())
    if result.status == 'fail' or result.status == 'incomplete' and report.status == 'pass':
        report.status = result.status
    for finding in result.findings:
        report.add(f'{result.check}:{finding.rule}', finding.message,
                   path=finding.path, line=finding.line, severity=finding.severity)


def quality(repo, ready=False, executable_root=None):
    report = PipelineReport('pr-readiness' if ready else 'quality')
    root = Path(run(['git', 'rev-parse', '--show-toplevel'], repo).decode().strip())
    config = load(root)
    try:
        head = run(['git', 'rev-parse', '--verify', 'HEAD'], root).decode().strip()
    except CommandError:
        head = None
    if ready:
        try:
            branch = run(['git', 'symbolic-ref', '--short', 'HEAD'], root).decode().strip()
        except CommandError:
            branch = None
        if not branch:
            report.add('detached-head', 'Check out the proposal branch before validating readiness.')
        elif any(fnmatch.fnmatchcase(branch, pattern) for pattern in config.protected_branches):
            report.add('protected-branch', 'Create a proposal branch before validating readiness.')
        if head is None:
            report.add('missing-commit', 'Commit the proposal before validating readiness.')
        if run(['git', 'status', '--porcelain', '--untracked-files=normal'], root):
            report.add('dirty-worktree', 'Readiness requires a clean committed proposal.')
        if report.status != 'pass':
            record(root, report, 'ready')
            return report
    index_before = run(['git', 'ls-files', '--stage', '-z'], root)
    before = scan(root, 'worktree', patterns=config.aggressiveness == 'strict')
    report.snapshot = before.snapshot
    combine(report, before)
    record(root, before, 'quality:security')
    # Do not invoke project commands or registry tools after a credential failure.
    if before.status == 'pass':
        names = []
        if config.require_tests or 'test' in config.commands or config.aggressiveness == 'strict':
            names.append('test')
        if config.aggressiveness != 'lazy':
            names += [name for name in QUALITY_CHECKS if name in config.commands]
        if config.aggressiveness == 'strict':
            for name in ('lint', 'typecheck', 'deadcode', 'coverage'):
                if name not in names:
                    names.append(name)
        try:
            for name in names:
                result = command_check(root, name, executable_root=executable_root)
                combine(report, result)
                record(root, result, 'quality:' + name)
            if config.aggressiveness != 'lazy' and 'dependency' not in names and any(
                    (root / name).exists() for name in ('package-lock.json', 'npm-shrinkwrap.json')):
                combine(report, audit(root))
            after = scan(root, 'worktree', patterns=config.aggressiveness == 'strict')
            record(root, after, 'quality:security-final')
            if after.status != 'pass':
                combine(report, after)
            try:
                current_head = run(['git', 'rev-parse', '--verify', 'HEAD'], root).decode().strip()
            except CommandError:
                current_head = None
            index_after = run(['git', 'ls-files', '--stage', '-z'], root)
            if after.snapshot != before.snapshot or current_head != head or index_after != index_before:
                report.add('snapshot-changed', 'Checks changed source files, permissions, index, or HEAD; review and rerun.',
                           severity='warning')
            if ready and run(['git', 'status', '--porcelain', '--untracked-files=normal'], root):
                report.add('proposal-changed', 'The proposal is no longer clean after running checks.')
        except (CommandError, ConfigError) as exc:
            report.add('pipeline-unavailable', str(exc), severity='warning')
    report.metrics = {'checks_run': len(report.checks),
                      'checks_passed': sum(c['status'] == 'pass' for c in report.checks)}
    record(root, report, 'ready' if ready else 'quality')
    return report
