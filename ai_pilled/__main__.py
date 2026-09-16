import argparse
import json
from pathlib import Path
import sys

from . import codex_hooks
from .dependencies import audit
from .codex_review import review
from .lifecycle import handle, read_payload
from .checks import command_check
from .git_hooks import dispatch, install, uninstall
from .config import ConfigError
from .runtime import CommandError
from .security import scan


def main(argv=None):
    parser = argparse.ArgumentParser(prog='ai-pilled')
    parser.add_argument('--repo', type=Path, default=Path.cwd())
    commands = parser.add_subparsers(dest='command', required=True)
    security = commands.add_parser('scan', help='Scan the Git index or working tree for credentials')
    security.add_argument('--scope', choices=['staged', 'worktree'], default='staged')
    check = commands.add_parser('check', help='Run a configured quality command')
    check.add_argument('name', choices=['test', 'lint', 'typecheck', 'deadcode', 'coverage', 'dependency'])
    review_parser = commands.add_parser('review', help='Review the staged snapshot with Codex')
    review_parser.add_argument('--codex', default='codex', help='Codex executable path or command name')
    dependency = commands.add_parser('dependency-audit', help='Audit npm lockfile vulnerabilities')
    dependency.add_argument('--npm', default='npm', help='npm executable path or command name')
    commands.add_parser('lifecycle')
    commands.add_parser('install-codex-hooks')
    commands.add_parser('uninstall-codex-hooks')
    commands.add_parser('install-git-hooks')
    commands.add_parser('uninstall-git-hooks')
    hook = commands.add_parser('hook')
    hook.add_argument('event', choices=['pre-commit', 'commit-msg', 'pre-push'])
    hook.add_argument('arguments', nargs='*')
    args = parser.parse_args(argv)
    try:
        if args.command == 'lifecycle':
            print(json.dumps(handle(args.repo, read_payload(sys.stdin))))
            return 0
        if args.command == 'review':
            report = review(args.repo, args.codex)
        elif args.command == 'dependency-audit':
            report = audit(args.repo, args.npm)
        elif args.command == 'install-codex-hooks':
            report = codex_hooks.install(args.repo)
        elif args.command == 'uninstall-codex-hooks':
            report = codex_hooks.uninstall(args.repo)
        elif args.command == 'scan':
            report = scan(args.repo, args.scope)
        elif args.command == 'check':
            report = command_check(args.repo, args.name)
        elif args.command == 'install-git-hooks':
            report = install(args.repo)
        elif args.command == 'uninstall-git-hooks':
            report = uninstall(args.repo)
        else:
            report = dispatch(args.repo, args.event, args.arguments)
    except (CommandError, ConfigError, OSError) as exc:
        print(json.dumps({'check': args.command, 'status': 'error', 'message': str(exc)}))
        return 2
    print(json.dumps(report.to_dict(), indent=2))
    return {'pass': 0, 'fail': 1, 'incomplete': 2}[report.status]


if __name__ == '__main__':
    sys.exit(main())
