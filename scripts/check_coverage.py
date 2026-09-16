"""Regenerate this repository's coverage evidence before enforcing its budget."""
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ai_pilled.metrics import coverage  # noqa: E402
from ai_pilled.state import directory  # noqa: E402


def main():
    directory(ROOT)
    env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
    env['COVERAGE_FILE'] = str(ROOT / '.ai-pilled' / 'coverage-data')
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    commands = [
        [sys.executable, '-m', 'coverage', 'run', '--source=ai_pilled',
         '-m', 'unittest', 'discover', '-s', 'tests', '-q'],
        [sys.executable, '-m', 'coverage', 'json', '-o', '.ai-pilled/coverage.json'],
    ]
    for command in commands:
        # Commands above use this interpreter and fixed coverage/test arguments, without a shell.
        result = subprocess.run(command, cwd=ROOT, env=env, check=False)  # noqa: S603
        if result.returncode:
            return result.returncode
    report = coverage(ROOT, '.ai-pilled/coverage.json', 80)
    print(f'Fresh line coverage: {report.metrics.get("line_percent", "unavailable")}; {report.status}')
    return {'pass': 0, 'fail': 1, 'incomplete': 2}[report.status]


if __name__ == '__main__':
    sys.exit(main())
