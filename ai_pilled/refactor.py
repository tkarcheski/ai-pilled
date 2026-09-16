"""Run explicitly configured refactor steps in a disposable local clone."""
from dataclasses import dataclass, field
import os
import uuid

from .checks import command_check, require_visible_index
from .config import ConfigError, load
from .file_io import read_beneath, read_regular, temporary_directory_beneath
from .pipeline import quality
from .runtime import CommandError, Report, isolated_git, run, git_path
from .security import scan
from .state import atomic_bytes_beneath, directory


@dataclass
class RefactorReport(Report):
    steps: list[dict] = field(default_factory=list)
    patch: str = ''


def export_patch(state, patch, prefix):
    output = state / (prefix + '-' + uuid.uuid4().hex + '.patch')
    relative = output.relative_to(state.parent)
    atomic_bytes_beneath(state.parent, relative, patch, exclusive=True)
    if read_beneath(state.parent, relative, len(patch)) != patch:
        raise CommandError('Exported patch changed during publication; inspect before retrying')
    return output


def refactor(repo):
    report = RefactorReport('refactor')
    try:
        root = git_path(run(['git', 'rev-parse', '--show-toplevel'], repo))
        config = load(root)
        policy = read_regular(root / '.ai-pilled.json', 64_000)
        if any(name not in config.commands for name in ('simplify', 'repair', 'test')):
            raise CommandError('Configure commands.simplify, commands.repair, and commands.test first')
        require_visible_index(root)
        if run(['git', 'status', '--porcelain', '--untracked-files=normal'], root):
            raise CommandError('Refactoring requires a clean committed source checkout')
        base = run(['git', 'rev-parse', '--verify', 'HEAD'], root).decode().strip()
        report.snapshot = base
        security = scan(root, 'worktree', patterns=config.aggressiveness == 'strict')
        if security.status != 'pass':
            report.status = security.status
            report.findings = security.findings
            return report
        state = directory(root)
        try:
            run(['git', 'check-ignore', '-q', '--', '.ai-pilled/'], root)
        except CommandError as exc:
            raise CommandError('Ignore .ai-pilled/ before running disposable refactor work') from exc
        env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
        with temporary_directory_beneath(root, '.ai-pilled', prefix='refactor-work-') as temporary:
            clone = temporary / 'checkout'
            run(['git', 'clone', '--quiet', '--no-local', '--no-checkout', '--', str(root), str(clone)],
                root, timeout=config.timeout, env=env)
            run(['git', 'remote', 'remove', 'origin'], clone, env=env)
            run(['git', 'checkout', '--quiet', '--detach', base], clone, env=env)
            for name in ('simplify', 'repair'):
                result = command_check(clone, name, executable_root=root)
                report.steps.append(result.to_dict())
                if result.status != 'pass':
                    report.status = result.status
                    report.findings = result.findings
                    return report
                if run(['git', 'rev-parse', 'HEAD'], clone, env=env).decode().strip() != base:
                    raise CommandError('Refactor commands must not create commits or change HEAD')
                if read_regular(clone / '.ai-pilled.json', 64_000) != policy:
                    raise CommandError('Refactor commands must not change the quality configuration')
                with isolated_git():
                    require_visible_index(clone)
                    security = scan(clone, 'worktree', patterns=config.aggressiveness == 'strict')
                if security.status != 'pass':
                    report.status = security.status
                    report.findings = security.findings
                    return report
            with isolated_git():
                verified = quality(clone, executable_root=root)
            report.steps.append(verified.to_dict())
            if verified.status != 'pass':
                report.status = verified.status
                report.findings = verified.findings
                return report
            with isolated_git():
                require_visible_index(clone)
            require_visible_index(root)
            if run(['git', 'rev-parse', 'HEAD'], root).decode().strip() != base or run(
                    ['git', 'status', '--porcelain', '--untracked-files=normal'], root):
                raise CommandError('Original checkout changed during refactoring; no patch exported')
            new_paths = run(['git', 'ls-files', '--others', '--exclude-standard', '-z'], clone, env=env)
            names = [p.decode('utf-8', errors='surrogateescape') for p in new_paths.split(b'\0') if p]
            for start in range(0, len(names), 100):
                run(['git', 'add', '--intent-to-add', '--', *names[start:start + 100]], clone, env=env)
            patch = run(['git', 'diff', '--binary', '--no-ext-diff', '--no-textconv', base, '--'],
                        clone, env=env)
            if not patch:
                report.metrics = {'patch_bytes': 0}
                return report
            report.patch = str(export_patch(state, patch, 'refactor'))
            report.metrics = {'patch_bytes': len(patch)}
    except (CommandError, ConfigError, OSError) as exc:
        report.add('refactor-unavailable', str(exc) if isinstance(exc, (CommandError, ConfigError))
                   else 'Cannot complete disposable refactor work', severity='warning')
    return report
