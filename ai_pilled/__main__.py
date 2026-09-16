import argparse
import json
from pathlib import Path
import sys

from .checks import command_check
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
    args = parser.parse_args(argv)
    try:
        report = scan(args.repo, args.scope) if args.command == 'scan' else command_check(args.repo, args.name)
    except (CommandError, ConfigError, OSError) as exc:
        print(json.dumps({'check': args.command, 'status': 'error', 'message': str(exc)}))
        return 2
    print(json.dumps(report.to_dict(), indent=2))
    return {'pass': 0, 'fail': 1, 'incomplete': 2}[report.status]


if __name__ == '__main__':
    sys.exit(main())
