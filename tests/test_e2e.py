"""Real CLI, Git hooks, and local remotes; external registry responses are fixtures."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from ai_pilled.credentials import redact

ROOT = Path(__file__).resolve().parents[1]


class EndToEndTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='ai-pilled-e2e-')
        self.addCleanup(temporary.cleanup)
        self.repo = Path(temporary.name) / 'checkout'
        self.repo.mkdir()
        self.remote = Path(temporary.name) / 'remote.git'
        self.env = {k: v for k, v in os.environ.items()
                    if k in ('PATH', 'HOME', 'LANG', 'LC_ALL', 'SYSTEMROOT')}
        self.env.update(PYTHONPATH=str(ROOT), PYTHONDONTWRITEBYTECODE='1',
                        GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull)
        self.execute(['git', 'init', '-q', '-b', 'feature'])
        self.execute(['git', 'init', '--bare', '-q', str(self.remote)])
        self.git('config', 'user.name', 'E2E fixture')
        self.git('config', 'user.email', 'e2e@example.invalid')
        self.git('remote', 'add', 'origin', str(self.remote))
        self.config = {'aggressiveness': 'strict', 'review_checks_on_commit': True,
                       'commands': {name: [sys.executable, '-c', 'pass']
                                    for name in ('lint', 'typecheck', 'deadcode', 'coverage')}}
        self.config['commands']['test'] = [sys.executable, 'verify.py']
        (self.repo / '.ai-pilled.json').write_text(json.dumps(self.config))
        (self.repo / '.gitignore').write_text('.ai-pilled/\n')
        (self.repo / 'value.txt').write_text('correct\n')
        (self.repo / 'verify.py').write_text('from pathlib import Path\n'
            'assert Path("value.txt").read_text() == "correct\\n"\n'
            'assert not Path(".ai-pilled/fail-test").exists()\n')
        self.git('add', '.ai-pilled.json', '.gitignore', 'value.txt', 'verify.py')
        self.assertEqual(self.cli('install-git-hooks')['status'], 'pass')

    def execute(self, argv, *, codes=(0,), input_data=None):
        result = subprocess.run(argv, cwd=self.repo, env=self.env, timeout=40,
                                input=input_data, capture_output=True)
        self.assertIn(result.returncode, codes, redact(result.stderr.decode(errors='replace')))
        return result.stdout + result.stderr if argv[0] == 'git' else result.stdout

    def git(self, *args, codes=(0,)):
        return self.execute(['git', *args], codes=codes)

    def cli(self, *args, codes=(0,), input_data=None):
        return json.loads(self.execute([sys.executable, '-m', 'ai_pilled', *args],
                                      codes=codes, input_data=input_data))

    def test_commit_push_lifecycle_and_reporting(self):
        session = self.cli('lifecycle', input_data=b'{"hook_event_name":"SessionStart"}')
        self.assertIn('feature', session['hookSpecificOutput']['additionalContext'])
        self.git('commit', '-m', 'feat: working fixture')
        self.git('push', 'origin', 'HEAD:refs/heads/feature')
        local = self.git('rev-parse', 'HEAD').strip()
        self.assertEqual(self.git('ls-remote', 'origin', 'refs/heads/feature').split()[0], local)
        output = self.cli('lifecycle', input_data=json.dumps({'hook_event_name': 'PostToolUse',
            'tool_name': 'exec_command', 'tool_response': {'exit_code': 0}}).encode())
        self.assertNotIn('decision', output)
        self.assertIn('"blocker": "proceed"', output['hookSpecificOutput']['additionalContext'])
        self.assertEqual(self.cli('summary')['blocker'], 'proceed')
        dashboard = Path(self.cli('dashboard')['dashboard'])
        self.assertTrue(dashboard.is_relative_to(self.repo))
        self.assertIn('Content-Security-Policy', dashboard.read_text())

    def test_bad_message_secret_and_partial_staging_block_commits(self):
        self.git('commit', '-m', 'feat: working fixture')
        head = self.git('rev-parse', 'HEAD')
        (self.repo / 'note.txt').write_text('safe note\n')
        self.git('add', 'note.txt')
        self.git('commit', '-m', 'bad subject', codes=(1,))
        self.assertEqual(self.git('rev-parse', 'HEAD'), head)
        for secret, rule in (('ghp_' + 'A' * 36, b'github-token'),
                             ('pypi-' + 'A' * 85, b'pypi-token'),
                             ('aws_secret_access_key: |-\n  ' + 'aB3/+' * 8, b'aws-secret-key'),
                             (json.dumps('ghp_' + 'A' * 36).replace('g', '\\u0067', 1), b'github-token')):
            (self.repo / 'note.txt').write_text(secret)
            self.git('add', 'note.txt')
            output = self.git('commit', '-m', 'feat: rejected credential', codes=(1,))
            self.assertFalse(secret.encode() in output, 'Hook output must redact credentials')
            self.assertIn(rule, output)
            self.assertEqual(self.git('rev-parse', 'HEAD'), head)
        (self.repo / 'note.txt').write_text('safe note\n')
        (self.repo / 'transport.py').write_text('import requests as http\nhttp.session().get(url, verify=False)\n'
                                              'def unrelated():\n import json as http\n return http.dumps({})\n')
        self.git('add', 'note.txt', 'transport.py')
        (self.repo / 'transport.py').write_text('import requests\nrequests.get(url)\n')
        output = self.git('commit', '-m', 'feat: rejected TLS bypass', codes=(1,))
        self.assertIn(b'tls-verification-disabled', output)
        self.assertEqual(self.git('rev-parse', 'HEAD'), head)
        self.git('add', 'transport.py')
        for source, fixed, rule in (
                ('import urllib3\nurllib3.PoolManager(cert_reqs="CERT_NONE")\n',
                 'import urllib3\nurllib3.PoolManager(cert_reqs="CERT_REQUIRED")\n', b'tls-verification-disabled'),
                ('import subprocess\nsubprocess.getoutput(command)\n',
                 'import subprocess\nsubprocess.run(["echo", value], check=True)\n', b'shell-execution'),
                ('import ssl\nssl._create_default_https_context = ssl._create_unverified_context\n',
                 'import ssl\nssl._create_default_https_context = ssl.create_default_context\n', b'unverified-tls-context'),
                ('import tarfile\ntarfile.open(path).extractall(filter="fully_trusted")\n',
                 'import tarfile\ntarfile.open(path).extractall(filter="data")\n', b'unsafe-archive-extraction'),
                ('import pickle\npickle.Unpickler(stream).load()\n',
                 'import json\njson.load(stream)\n', b'unsafe-deserialization'),
                ('import yaml\nyaml.unsafe_load(data)\n',
                 'import yaml\nfrom yaml.loader import SafeLoader\nyaml.load(data, Loader=SafeLoader)\n', b'unsafe-yaml'),
                ("value = 'ghp_' '" + 'A' * 36 + "'\n",
                 'value = "ordinary"\n', b'github-token'),
                ('import os\nprint(os.environ.copy().get("TOKEN"))\n',
                 'import os\nprint(os.environ.copy().get("HOME"))\n', b'environment-secret-log'),
                ('from os import getenv\nprint(getenv("API_KEY"))\n',
                 'from os import getenv\nprint(getenv("HOME"))\n', b'environment-secret-log')):
            (self.repo / 'example.py').write_text(source)
            self.git('add', 'example.py')
            (self.repo / 'example.py').write_text(fixed)
            output = self.git('commit', '-m', 'feat: rejected unsafe API', codes=(1,))
            self.assertIn(rule, output)
            self.assertEqual(self.git('rev-parse', 'HEAD'), head)
            self.git('add', 'example.py')
        (self.repo / 'value.txt').write_text('broken\n')
        self.git('add', 'note.txt', 'value.txt')
        (self.repo / 'value.txt').write_text('correct\n')
        output = self.git('commit', '-m', 'feat: rejected partial staging', codes=(1,))
        self.assertIn(b'command-failed', output)
        self.assertEqual(self.git('rev-parse', 'HEAD'), head)

    def test_protected_destination_and_failing_tests_leave_remote_unchanged(self):
        self.git('commit', '-m', 'feat: initial fixture')
        self.git('push', 'origin', 'HEAD:refs/heads/feature')
        initial = self.git('ls-remote', 'origin')
        (self.repo / 'note.txt').write_text('new proposal\n')
        self.git('add', 'note.txt')
        self.git('commit', '-m', 'feat: proposal before hidden edit')
        self.git('update-index', '--assume-unchanged', 'value.txt')
        (self.repo / 'value.txt').write_text('hidden change\n')
        output = self.git('push', 'origin', 'HEAD:refs/heads/feature', codes=(1,))
        self.assertIn(b'hidden-worktree', output)
        self.assertEqual(self.git('ls-remote', 'origin'), initial)
        self.git('update-index', '--no-assume-unchanged', 'value.txt')
        (self.repo / 'value.txt').write_text('correct\n')
        self.git('push', 'origin', 'HEAD:refs/heads/main', codes=(1,))
        self.assertEqual(self.git('ls-remote', 'origin'), initial)
        (self.repo / 'note.txt').write_text('next commit\n')
        self.git('add', 'note.txt')
        self.git('commit', '-m', 'feat: next fixture')
        (self.repo / '.ai-pilled/fail-test').touch()
        output = self.git('push', 'origin', 'HEAD:refs/heads/feature', codes=(1,))
        self.assertIn(b'command-failed', output)
        self.assertEqual(self.git('ls-remote', 'origin'), initial)

    def test_python_audit_and_lifecycle_preserve_provider_failure(self):
        (self.repo / 'requirements.txt').write_text('example==1.0\n')
        provider = self.repo / '.ai-pilled/fixture-pip-audit'
        self.config.update(audit_dependencies_on_change=True,
                           python_requirements=['requirements.txt'], python_audit_executable=str(provider))
        (self.repo / '.ai-pilled.json').write_text(json.dumps(self.config))
        data = {'dependencies': [{'name': 'example', 'version': '1.0', 'vulns': [
            {'id': 'PYSEC-2026-1', 'fix_versions': ['2.0']}]}]}
        provider.write_text(f'#!{sys.executable}\nimport json\nprint({json.dumps(data)!r})\nraise SystemExit(1)\n')
        provider.chmod(0o755)
        self.assertEqual(self.cli('python-audit', '--pip-audit', str(provider), codes=(1,))['status'], 'fail')
        payload = json.dumps({'hook_event_name': 'PostToolUse', 'tool_name': 'exec_command',
                              'tool_response': {'exit_code': 0}}).encode()
        result = self.cli('lifecycle', input_data=payload)
        self.assertEqual(result['decision'], 'block')
        self.assertIn('"python_dependency_result_reused": true', result['hookSpecificOutput']['additionalContext'])
        provider.write_text(f'#!{sys.executable}\nraise SystemExit(2)\n')
        self.assertEqual(self.cli('python-audit', '--pip-audit', str(provider), codes=(2,))['status'], 'incomplete')
        result = self.cli('lifecycle', input_data=payload)
        self.assertEqual(result['decision'], 'block')
        self.assertIn('"python_dependency_result_reused": false', result['hookSpecificOutput']['additionalContext'])

    def test_audit_planning_previews_and_artifact_budgets(self):
        self.git('commit', '-m', 'feat: audited fixture')
        head = self.git('rev-parse', 'HEAD')
        audit = self.cli('full-audit')
        self.assertEqual(audit['status'], 'pass')
        self.assertEqual(audit['metrics']['model_reviews_run'], 0)
        self.assertEqual({check['check'] for check in audit['checks'][0]['checks']},
                         {'security', 'test', 'lint', 'typecheck', 'deadcode', 'coverage'})
        plan = self.cli('release-plan', '--current', '1.0.0')
        self.assertEqual(plan['next_version'], '1.1.0')
        self.assertFalse((self.repo / 'VERSION').exists())
        for arguments in (['slack'], ['github', '--github-repo', 'fixture/example', '--issue', '1'],
                          ['linear', '--team', '00000000-0000-0000-0000-000000000001'],
                          ['email', '--sender', 'sender@example.invalid', '--recipient', 'to@example.invalid']):
            with self.subTest(provider=arguments[0]):
                result = self.cli('notify', *arguments)
                self.assertEqual(result['status'], 'pass')
                self.assertEqual(result['delivery'], 'preview')
        self.assertEqual(self.git('rev-parse', 'HEAD'), head)
        self.assertEqual(self.git('tag', '--list'), b'')
        self.assertEqual(self.git('status', '--porcelain'), b'')
        self.assertEqual(self.git('ls-remote', 'origin'), b'')
        coverage = self.repo / '.ai-pilled/coverage-input.json'
        coverage.write_text(json.dumps({'totals': {'covered_lines': 9, 'num_statements': 10}}))
        self.assertEqual(self.cli('coverage', '--report', '.ai-pilled/coverage-input.json',
                                  '--minimum', '80')['metrics']['line_percent'], 90)
        self.assertEqual(self.cli('coverage', '--report', '.ai-pilled/coverage-input.json',
                                  '--minimum', '95', codes=(1,))['status'], 'fail')
        (self.repo / '.ai-pilled/artifact.bin').write_bytes(b'abc')
        self.assertEqual(self.cli('bundle', '--path', '.ai-pilled/artifact.bin', '--maximum', '3')['status'], 'pass')
        self.assertEqual(self.cli('bundle', '--path', '.ai-pilled/artifact.bin', '--maximum', '2', codes=(1,))['status'], 'fail')
        self.assertTrue({'coverage-budget', 'bundle-budget'} <= set(self.cli('summary')['unresolved']))

    def test_entrypoints_and_dynamic_options_block_then_allow_corrected_push(self):
        self.git('commit', '-m', 'feat: establish security fixture')
        original_head = self.git('rev-parse', 'HEAD')
        header = '#!/usr/bin/env python3\n'
        secret = 'ghp_' + 'A' * 36
        cases = (
            ('entrypoint', header + 'token = ' + repr('ghp_') + ' ' + repr('A' * 36),
             header + 'print("safe")', b'github-token'),
            ('shell-tool', header + 'import subprocess\nsubprocess.run(command, shell=enabled)',
             header + 'import subprocess\nsubprocess.run(["echo", "safe"], check=True)', b'shell-option-unresolved'),
            ('transport.py', 'import httpx\nhttpx.Client(verify=context)',
             'import httpx\nhttpx.Client(verify=True)', b'tls-option-unresolved'),
            ('shell-vector.py', 'import subprocess\nsubprocess.run(["sh", "-c", command])',
             'import subprocess\nsubprocess.run(["echo", value], check=True)', b'shell-execution'),
            ('runtime.py', '__import__("pickle").loads(data)',
             'import json\njson.loads(data)', b'unsafe-deserialization'),
            ('window.pyw', 'import pickle\npickle.loads(data)',
             'import json\njson.loads(data)', b'unsafe-deserialization'),
        )
        for name, unsafe, corrected, rule in cases:
            with self.subTest(name=name):
                (self.repo / name).write_text(unsafe)
                self.git('add', name)
                (self.repo / name).write_text(corrected)
                output = self.git('commit', '-m', 'feat: reject unsafe staged entrypoint', codes=(1,))
                self.assertIn(rule, output)
                self.assertNotIn(secret.encode(), output)
                self.assertEqual(self.git('rev-parse', 'HEAD'), original_head)
                self.git('add', name)
        self.git('commit', '-m', 'fix: resolve entrypoint security findings')
        corrected_head = self.git('rev-parse', 'HEAD').strip()
        self.assertNotEqual(corrected_head, original_head.strip())
        self.git('push', 'origin', 'HEAD:refs/heads/feature')
        self.assertEqual(self.git('ls-remote', 'origin', 'refs/heads/feature').split()[0], corrected_head)
