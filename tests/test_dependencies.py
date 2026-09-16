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

    def test_exit_status_must_match_audit_level_evidence(self):
        for payload, code in ((response(), 1), (response(True), 0)):
            with self.subTest(code=code):
                self.provider(payload, code)
                result = audit(self.repo, str(self.fake))
                self.assertEqual(result.status, 'incomplete')
                self.assertIn('contradicts', result.findings[0].message)

    def test_info_only_vulnerability_can_exit_zero_at_low_threshold(self):
        payload = response(True)
        payload['metadata']['vulnerabilities'].update(high=0, info=1)
        payload['vulnerabilities']['example']['severity'] = 'info'
        self.provider(payload, 0)
        result = audit(self.repo, str(self.fake))
        self.assertEqual(result.status, 'fail')
        self.assertEqual(result.findings[0].rule, 'dependency-vulnerability')
        self.assertIn('info vulnerability', result.findings[0].message)

    def test_legacy_audit_cache_is_refreshed(self):
        from ai_pilled.dependencies import audit_changed
        original = audit(self.repo, str(self.fake))
        path = self.repo / '.ai-pilled/events.jsonl'
        entry = json.loads(path.read_text())
        entry['report']['metrics'].pop('evidence_version')
        path.write_text(json.dumps(entry) + '\n')
        with patch('ai_pilled.dependencies.audit', return_value=original) as provider:
            result, reused = audit_changed(self.repo)
        self.assertFalse(reused)
        self.assertEqual(result.status, 'pass')
        provider.assert_called_once_with(self.repo, timeout=30)

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

    def test_unchanged_dependency_result_is_reused_and_change_invalidates_it(self):
        from ai_pilled.dependencies import audit_changed
        original = audit(self.repo, str(self.fake))
        self.assertEqual(original.status, 'pass')
        with patch('ai_pilled.dependencies.audit') as provider:
            cached, reused = audit_changed(self.repo)
            self.assertTrue(reused)
            self.assertEqual(cached.status, 'pass')
            provider.assert_not_called()
            (self.repo / 'package-lock.json').write_text('{"lockfileVersion":3,"packages":{"changed":{}}}')
            provider.return_value = original
            self.assertFalse(audit_changed(self.repo)[1])
            provider.assert_called_once_with(self.repo, timeout=30)

    def test_incomplete_results_are_retried_but_known_failures_remain_blocking(self):
        from ai_pilled.dependencies import audit_changed
        from ai_pilled.runtime import Report
        self.provider(response(True), 1)
        self.assertEqual(audit(self.repo, str(self.fake)).status, 'fail')
        self.assertEqual(audit_changed(self.repo)[0].status, 'fail')
        self.provider({'error': {}}, 1)
        audit(self.repo, str(self.fake))
        with patch('ai_pilled.dependencies.audit', return_value=Report('retry')) as provider:
            self.assertFalse(audit_changed(self.repo)[1])
            provider.assert_called_once()

    def test_expired_audit_is_not_reused(self):
        from ai_pilled.dependencies import audit_changed
        from ai_pilled.runtime import Report
        audit(self.repo, str(self.fake))
        history_path = self.repo / '.ai-pilled' / 'events.jsonl'
        data = json.loads(history_path.read_text())
        data['at'] = '2000-01-01T00:00:00+00:00'
        history_path.write_text(json.dumps(data) + '\n')
        with patch('ai_pilled.dependencies.audit', return_value=Report('fresh')) as provider:
            self.assertFalse(audit_changed(self.repo)[1])
            provider.assert_called_once()
