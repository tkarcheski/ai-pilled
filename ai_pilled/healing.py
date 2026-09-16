"""Verify a single-commit reversal before offering an explicit local revert."""
from dataclasses import dataclass, field
import os
from pathlib import Path
import tempfile

from .checks import command_check
from .config import ConfigError, load
from .pipeline import quality
from .refactor import export_patch
from .runtime import CommandError, Report, run
from .security import scan
from .state import directory


@dataclass
class HealingReport(Report):
    action: str = 'not-applied'
    patch: str = ''
    commit: str = ''
    checks: list[dict] = field(default_factory=list)


def unchanged(root, head, branch):
    if run(['git', 'symbolic-ref', '--quiet', 'HEAD'], root) != branch or run(['git', 'rev-parse', 'HEAD'], root).decode().strip() != head or run(
            ['git', 'status', '--porcelain', '--untracked-files=normal'], root):
        raise CommandError('Checkout changed; no automatic revert is permitted')


def heal(repo, expected_head, apply=False):
    report = HealingReport('self-healing')
    try:
        root = Path(run(['git', 'rev-parse', '--show-toplevel'], repo).decode().strip())
        config = load(root)
        head = run(['git', 'rev-parse', '--verify', 'HEAD'], root).decode().strip()
        if expected_head != head:
            raise CommandError('Expected HEAD must exactly match the current commit SHA')
        report.snapshot = head
        branch = run(['git', 'symbolic-ref', '--quiet', 'HEAD'], root)
        unchanged(root, head, branch)
        if 'test' not in config.commands:
            raise CommandError('Configure commands.test before attempting self-healing')
        parents = run(['git', 'rev-list', '--parents', '-n', '1', head], root).split()
        if len(parents) != 2:
            raise CommandError('Self-healing requires a non-merge commit with one parent')
        security = scan(root, 'worktree', patterns=config.aggressiveness == 'strict')
        if security.status != 'pass':
            report.status, report.findings = security.status, security.findings
            return report
        policy = (root / '.ai-pilled.json').read_bytes()
        baseline = command_check(root, 'test')
        report.checks.append(baseline.to_dict())
        unchanged(root, head, branch)
        if baseline.status == 'pass':
            report.action = 'unnecessary'
            return report
        if baseline.status != 'fail':
            raise CommandError('Current test failure must be established before proposing a revert')
        run(['git', 'check-ignore', '-q', '--', '.ai-pilled/'], root)
        state = directory(root)
        env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
        with tempfile.TemporaryDirectory(prefix='heal-work-', dir=state) as temporary:
            clone = Path(temporary) / 'checkout'
            run(['git', 'clone', '--quiet', '--no-local', '--no-checkout', '--', str(root), str(clone)],
                root, timeout=config.timeout, env=env)
            run(['git', 'remote', 'remove', 'origin'], clone, env=env)
            run(['git', 'checkout', '--quiet', '--detach', head], clone, env=env)
            run(['git', 'revert', '--no-commit', head], clone, env=env)
            if (clone / '.ai-pilled.json').is_symlink() or (clone / '.ai-pilled.json').read_bytes() != policy:
                raise CommandError('Revert would change the quality policy; review it manually')
            candidate = quality(clone, executable_root=root)
            report.checks.append(candidate.to_dict())
            if candidate.status != 'pass':
                report.status, report.findings = candidate.status, candidate.findings
                return report
            unchanged(root, head, branch)
            patch = run(['git', 'diff', '--binary', '--no-ext-diff', '--no-textconv', head, '--'], clone, env=env)
            if not patch:
                raise CommandError('The tested reversal has no changes')
            tree = run(['git', 'write-tree'], clone, env=env).strip()
            report.patch = str(export_patch(state, patch, 'heal'))
            report.action = 'preview'
            if apply:
                unchanged(root, head, branch)
                # Use ordinary Git behavior and hooks; never reset, force, or push.
                try:
                    run(['git', 'revert', '--no-commit', head], root, timeout=config.timeout, env=env)
                    run(['git', 'commit', '-m', 'fix: revert failing commit ' + head[:12],
                         '-m', 'This reverts commit ' + head + '.'], root, timeout=config.timeout, env=env)
                except CommandError as exc:
                    report.action = 'inspect-checkout'
                    raise CommandError('Git revert did not complete; inspect checkout and hook output before continuing') from exc
                report.commit = run(['git', 'rev-parse', 'HEAD'], root).decode().strip()
                actual_parent = run(['git', 'rev-parse', 'HEAD^'], root).decode().strip()
                actual_tree = run(['git', 'rev-parse', 'HEAD^{tree}'], root).strip()
                if run(['git', 'symbolic-ref', '--quiet', 'HEAD'], root) != branch or actual_parent != head or actual_tree != tree or run(['git', 'status', '--porcelain'], root):
                    report.action = 'inspect-checkout'
                    raise CommandError('Revert differs from the verified result; inspect checkout before continuing')
                report.action = 'applied'
    except (CommandError, ConfigError, OSError) as exc:
        report.add('healing-unavailable', str(exc) if isinstance(exc, (CommandError, ConfigError))
                   else 'Cannot prepare a verified revert', severity='warning')
    return report
