import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ai_pilled.python_dependencies import audit_python
from ai_pilled.runtime import CommandUnavailable


class PythonDependencyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.repo = Path(temporary.name)
        self.path = self.repo / 'requirements.txt'
        self.path.write_text('Example_Package==1.2.3\n')
        self.row = {'name': 'example-package', 'version': '1.2.3', 'vulns': []}

    def response(self, rows=None):
        return json.dumps({'dependencies': [self.row] if rows is None else rows, 'fixes': []}).encode()

    def test_complete_report_passes_without_resolution_or_installation(self):
        def provider(argv, repo, **kwargs):
            self.assertIn('--no-deps', argv)
            self.assertIn('--disable-pip', argv)
            self.assertNotIn('--fix', argv)
            selected = Path(argv[argv.index('--requirement') + 1])
            self.assertNotEqual(selected, self.path)
            self.assertEqual(selected.read_text(), 'example-package==1.2.3\n')
            self.assertNotIn('PIP_AUDIT_OUTPUT', kwargs['env'])
            self.assertNotIn('GIT_DIR', kwargs['env'])
            return self.response()
        with patch.dict(os.environ, {'GIT_DIR': '/not-this-project', 'PIP_AUDIT_OUTPUT': 'unwanted'}):
            with patch('ai_pilled.python_dependencies.run', side_effect=provider):
                result = audit_python(self.repo)
        self.assertEqual(result.status, 'pass')
        self.assertEqual(result.metrics['packages_audited'], 1)

    def test_vulnerability_blocks_and_reports_fixed_versions(self):
        self.row['vulns'] = [{'id': 'PYSEC-2026-1', 'fix_versions': ['1.2.4']}]
        with patch('ai_pilled.python_dependencies.run', return_value=self.response()):
            result = audit_python(self.repo)
        self.assertEqual(result.status, 'fail')
        self.assertIn('1.2.4', result.findings[0].message)
        self.assertEqual(result.findings[0].path, 'example-package')

    def test_missing_extra_duplicate_and_skipped_packages_never_pass(self):
        bad = [[], [self.row, self.row],
               [dict(self.row, name='unrequested')], [dict(self.row, version='2.0')],
               [dict(self.row, skip_reason='not on index')],
               [dict(self.row, vulns=[{'id': 'CVE-2026-1', 'fix_versions': None}])]]
        for rows in bad:
            with self.subTest(rows=rows), patch('ai_pilled.python_dependencies.run', return_value=self.response(rows)):
                self.assertEqual(audit_python(self.repo).status, 'incomplete')

    def test_unsupported_input_never_invokes_provider(self):
        for source in ('example>=1', '-r other.txt', '--index-url https://example.invalid',
                       'package @ https://example.invalid/a.whl', 'example==1; python_version>"3"',
                       'example[extra]==1', 'example==1.*'):
            self.path.write_text(source)
            with self.subTest(source=source), patch('ai_pilled.python_dependencies.run') as provider:
                self.assertEqual(audit_python(self.repo).status, 'incomplete')
                provider.assert_not_called()

    def test_conflicting_pins_across_files_are_rejected(self):
        (self.repo / 'dev.txt').write_text('example-package==2.0\n')
        with patch('ai_pilled.python_dependencies.run') as provider:
            result = audit_python(self.repo, ['requirements.txt', 'dev.txt'])
        self.assertEqual(result.status, 'incomplete')
        provider.assert_not_called()

    def test_changed_requirements_invalidate_completed_audit(self):
        def provider(*args, **kwargs):
            self.path.write_text('other==1.0\n')
            return self.response()
        with patch('ai_pilled.python_dependencies.run', side_effect=provider):
            result = audit_python(self.repo)
        self.assertEqual(result.status, 'incomplete')
        self.assertIn('changed', result.findings[0].message)

    def test_unavailable_tool_and_malformed_json_are_incomplete(self):
        with patch('ai_pilled.python_dependencies.run', side_effect=CommandUnavailable('Tool unavailable')):
            self.assertEqual(audit_python(self.repo).status, 'incomplete')
        for value in (b'not json', b'{}', b'null'):
            with patch('ai_pilled.python_dependencies.run', return_value=value):
                self.assertEqual(audit_python(self.repo).status, 'incomplete')

    def test_empty_file_is_explicit_zero_package_audit(self):
        self.path.write_text('# No runtime dependencies\n')
        with patch('ai_pilled.python_dependencies.run') as provider:
            result = audit_python(self.repo)
        self.assertEqual(result.status, 'pass')
        self.assertEqual(result.metrics['packages_audited'], 0)
        provider.assert_not_called()

    def test_symlink_and_oversized_inputs_are_rejected(self):
        self.path.unlink()
        self.path.symlink_to(self.repo / 'missing')
        self.assertEqual(audit_python(self.repo).status, 'incomplete')
        self.path.unlink()
        self.path.write_text('#' * 2_000_001)
        self.assertEqual(audit_python(self.repo).status, 'incomplete')
        self.assertEqual(audit_python(self.repo, ['../outside']).status, 'incomplete')

    def test_legacy_list_report_is_supported(self):
        with patch('ai_pilled.python_dependencies.run', return_value=json.dumps([self.row]).encode()):
            self.assertEqual(audit_python(self.repo).status, 'pass')

    def test_credentials_are_blocked_before_provider_invocation(self):
        token = 'ghp_' + 'A' * 36
        self.path.write_text(token + '==1.0')
        with patch('ai_pilled.python_dependencies.run') as provider:
            result = audit_python(self.repo)
        self.assertEqual(result.status, 'incomplete')
        self.assertNotIn(token, json.dumps(result.to_dict()))
        provider.assert_not_called()
