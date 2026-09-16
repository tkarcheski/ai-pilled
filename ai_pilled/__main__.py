import argparse
import json
from pathlib import Path
import sys

from .runtime import CommandError
from .security import scan


def main(argv=None):
    parser = argparse.ArgumentParser(prog='ai-pilled')
    parser.add_argument('--repo', type=Path, default=Path.cwd())
    commands = parser.add_subparsers(dest='command', required=True)
    security = commands.add_parser('scan', help='Scan the Git index or working tree for credentials')
    security.add_argument('--scope', choices=['staged', 'worktree'], default='staged')
    args = parser.parse_args(argv)
    try:
        report = scan(args.repo, args.scope)
    except (CommandError, OSError) as exc:
        print(json.dumps({'check': 'security', 'status': 'error', 'message': str(exc)}))
        return 2
    print(json.dumps(report.to_dict(), indent=2))
    return {'pass': 0, 'fail': 1, 'incomplete': 2}[report.status]


if __name__ == '__main__':
    sys.exit(main())
