import argparse
import json
from pathlib import Path
import sys

from . import codex_hooks
from .dependencies import audit
from .dependency_health import health, licenses
from .codex_review import review
from .lifecycle import handle, read_payload
from .checks import command_check
from .git_hooks import dispatch, install, uninstall
from .config import ConfigError
from .runtime import CommandError
from .security import scan
from .reporting import dashboard, summarize
from .state import record
from .metrics import bundle, coverage
from .performance import benchmark
from .pipeline import quality
from .releases import prepare_release, release_plan
from .documentation import update_readme
from .refactor import refactor
from .notifications import notify


def build_parser():
    parser = argparse.ArgumentParser(prog='ai-pilled')
    parser.add_argument('--repo', type=Path, default=Path.cwd())
    commands = parser.add_subparsers(dest='command', required=True)
    security = commands.add_parser('scan', help='Scan the Git index or working tree for credentials')
    security.add_argument('--scope', choices=['staged', 'worktree'], default='staged')
    security.add_argument('--patterns', action='store_true', help='Also inspect Python AST security patterns')
    check = commands.add_parser('check', help='Run a configured quality command')
    check.add_argument('name', choices=['test', 'lint', 'typecheck', 'deadcode', 'coverage', 'dependency'])
    review_parser = commands.add_parser('review', help='Review the staged snapshot with Codex')
    review_parser.add_argument('--codex', help='Codex executable path or command name')
    dependency = commands.add_parser('dependency-audit', help='Audit npm lockfile vulnerabilities')
    dependency.add_argument('--npm', default='npm', help='npm executable path or command name')
    coverage_parser = commands.add_parser('coverage', help='Check line coverage from coverage.py JSON')
    coverage_parser.add_argument('--report', required=True)
    coverage_parser.add_argument('--minimum', type=float, required=True)
    bundle_parser = commands.add_parser('bundle', help='Check built artifacts against a byte budget')
    bundle_parser.add_argument('--path', required=True)
    bundle_parser.add_argument('--maximum', type=int, required=True)
    performance = commands.add_parser('benchmark', help='Compare median process time against a local baseline')
    performance.add_argument('--runs', type=int, default=3)
    performance.add_argument('--maximum-regression', type=float, default=20)
    performance.add_argument('--save-baseline', action='store_true')
    health_parser = commands.add_parser('dependency-health', help='Check installed npm tree and available versions')
    health_parser.add_argument('--npm', default='npm')
    license_parser = commands.add_parser('licenses', help='Match lockfile licenses against an explicit allowlist')
    license_parser.add_argument('--allow', action='append', default=[])
    release = commands.add_parser('release-plan', help='Generate changelog and semantic-version proposal')
    release.add_argument('--current', required=True)
    release.add_argument('--since')
    prepare = commands.add_parser('prepare-release', help='Validate readiness and write VERSION/CHANGELOG.md')
    prepare.add_argument('--current', required=True)
    prepare.add_argument('--since')
    readme = commands.add_parser('update-readme', help='Refresh a generated README command reference')
    readme.add_argument('--path', default='README.md')
    readme.add_argument('--check', action='store_true')
    commands.add_parser('refactor', help='Run configured refactor steps in a disposable clone and export a patch')
    commands.add_parser('quality', help='Run the configured quality profile')
    commands.add_parser('ready', help='Validate a clean proposal branch and its quality checks')
    notification = commands.add_parser('notify', help='Preview or explicitly send a historical check digest')
    notification.add_argument('provider', choices=['slack', 'linear', 'github', 'email'])
    notification.add_argument('--send', action='store_true')
    notification.add_argument('--github-repo')
    notification.add_argument('--issue', type=int)
    notification.add_argument('--team')
    notification.add_argument('--sender')
    notification.add_argument('--recipient')
    commands.add_parser('summary', help='Summarize recorded checks and next steps')
    commands.add_parser('dashboard', help='Build an offline check-history dashboard')
    commands.add_parser('lifecycle')
    commands.add_parser('install-codex-hooks')
    commands.add_parser('uninstall-codex-hooks')
    commands.add_parser('install-git-hooks')
    commands.add_parser('uninstall-git-hooks')
    hook = commands.add_parser('hook')
    hook.add_argument('event', choices=['pre-commit', 'commit-msg', 'pre-push'])
    hook.add_argument('arguments', nargs='*')
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        if args.command == 'summary':
            print(json.dumps(summarize(args.repo), indent=2))
            return 0
        if args.command == 'dashboard':
            print(json.dumps({'dashboard': str(dashboard(args.repo).resolve())}))
            return 0
        if args.command == 'lifecycle':
            print(json.dumps(handle(args.repo, read_payload(sys.stdin))))
            return 0
        if args.command == 'review':
            report = review(args.repo, args.codex)
        elif args.command == 'update-readme':
            report = update_readme(args.repo, args.path, args.check)
        elif args.command == 'notify':
            report = notify(args.repo, args.provider, send=args.send, github_repo=args.github_repo,
                            issue=args.issue, team=args.team, sender=args.sender, recipient=args.recipient)
        elif args.command == 'refactor':
            report = refactor(args.repo)
        elif args.command == 'prepare-release':
            report = prepare_release(args.repo, args.current, args.since)
        elif args.command == 'release-plan':
            report = release_plan(args.repo, args.current, args.since)
        elif args.command == 'dependency-health':
            report = health(args.repo, args.npm)
        elif args.command == 'licenses':
            report = licenses(args.repo, args.allow)
        elif args.command in ('quality', 'ready'):
            report = quality(args.repo, ready=args.command == 'ready')
        elif args.command == 'benchmark':
            report = benchmark(args.repo, args.runs, args.maximum_regression, args.save_baseline)
        elif args.command == 'coverage':
            report = coverage(args.repo, args.report, args.minimum)
        elif args.command == 'bundle':
            report = bundle(args.repo, args.path, args.maximum)
        elif args.command == 'dependency-audit':
            report = audit(args.repo, args.npm)
        elif args.command == 'install-codex-hooks':
            report = codex_hooks.install(args.repo)
        elif args.command == 'uninstall-codex-hooks':
            report = codex_hooks.uninstall(args.repo)
        elif args.command == 'scan':
            report = scan(args.repo, args.scope, args.patterns)
        elif args.command == 'check':
            report = command_check(args.repo, args.name)
        elif args.command == 'install-git-hooks':
            report = install(args.repo)
        elif args.command == 'uninstall-git-hooks':
            report = uninstall(args.repo)
        else:
            report = dispatch(args.repo, args.event, args.arguments)
        if args.command in ('scan', 'check', 'hook'):
            record(args.repo, report, args.command)
    except (CommandError, ConfigError, OSError) as exc:
        print(json.dumps({'check': args.command, 'status': 'error', 'message': str(exc)}))
        return 2
    print(json.dumps(report.to_dict(), indent=2))
    return {'pass': 0, 'fail': 1, 'incomplete': 2}[report.status]


if __name__ == '__main__':
    sys.exit(main())
