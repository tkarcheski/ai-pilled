import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from ai_pilled.dependencies import audit
from ai_pilled.runtime import CommandError, run


def response(vulnerable=False):
    counts = dict(info=0, low=0, moderate=0, high=int(vulnerable), critical=0, total=int(vulnerable))
    return {'auditReportVersion': 2, 'metadata': {'vulnerabilities': counts},
            'vulnerabilities': {'example': {'severity': 'high', 'fixAvailable': True}} if vulnerable else {}}


class DependencyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        (self.repo / 'package.json').write_text('{"name":"fixture","version":"1.0.0"}')
        (self.repo / 'package-lock.json').write_text('{"lockfileVersion":3,"packages":{}}')
        self.fake = self.repo / 'npm-fake'
        self.provider(response())

    def provider(self, payload, code=0, extra=''):
        self.fake.write_text(f'#!{sys.executable}\nimport sys,os\nfrom pathlib import Path\n'
                            'assert sys.argv[1] == "audit"\n'
                            'assert "--ignore-scripts" in sys.argv\n'
                            'assert "--package-lock-only" in sys.argv\n'
                            'assert not any(k.startswith("GIT_") for k in os.environ)\n'
                            f'{extra}\nprint({json.dumps(payload)!r})\nsys.exit({code})\n')
        self.fake.chmod(0o755)

    def test_clean_structured_audit(self):
        with patch.dict(os.environ, {'GIT_DIR': '/invalid'}):
            result = audit(self.repo, str(self.fake))
        self.assertEqual(result.status, 'pass')
        self.assertTrue(result.snapshot)

    def test_vulnerability_exit_one_is_parsed(self):
        self.provider(response(True), 1)
        result = audit(self.repo, str(self.fake))
        self.assertEqual(result.status, 'fail')
        self.assertEqual(result.findings[0].path, 'example')
        self.assertIn('high', result.findings[0].message)

    def test_registry_error_does_not_leak_response(self):
        self.provider({'error': {'summary': 'private registry credential'}}, 1)
        result = audit(self.repo, str(self.fake))
        self.assertEqual(result.status, 'incomplete')
        self.assertNotIn('private registry credential', json.dumps(result.to_dict()))

    def test_unknown_schema_and_inconsistent_counts_are_incomplete(self):
        malformed = response()
        malformed['metadata']['vulnerabilities']['total'] = 3
        for value in ({}, malformed, {'auditReportVersion': 1}, response() | {'vulnerabilities': []}):
            with self.subTest(value=value):
                self.provider(value)
                self.assertEqual(audit(self.repo, str(self.fake)).status, 'incomplete')

    def test_missing_lock_does_not_start_provider(self):
        (self.repo / 'package-lock.json').unlink()
        result = audit(self.repo, 'not-installed')
        self.assertEqual(result.status, 'incomplete')
        self.assertIn('requires', result.findings[0].message)

    def test_missing_tool_is_incomplete(self):
        self.assertEqual(audit(self.repo, 'not-installed-ai-pilled-npm').status, 'incomplete')

    def test_changed_lock_invalidates_audit(self):
        self.provider(response(), extra='Path("package-lock.json").write_text("{}")')
        result = audit(self.repo, str(self.fake))
        self.assertEqual(result.status, 'incomplete')
        self.assertIn('changed', result.findings[0].message)

    def test_symlink_lock_is_not_followed(self):
        path = self.repo / 'package-lock.json'
        path.unlink()
        path.symlink_to('/etc/passwd')
        self.assertEqual(audit(self.repo, str(self.fake)).status, 'incomplete')

    def test_accepted_exit_codes_are_opt_in(self):
        argv = [sys.executable, '-c', 'print("report"); raise SystemExit(1)']
        with self.assertRaises(CommandError):
            run(argv, self.repo)
        self.assertEqual(run(argv, self.repo, acceptable_codes=(0, 1)), b'report\n')
        with self.assertRaises(CommandError):
            run([sys.executable, '-c', 'raise SystemExit(2)'], self.repo, acceptable_codes=(0, 1))
