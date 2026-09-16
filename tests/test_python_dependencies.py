import json
import os
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ai_pilled.python_dependencies import audit_python
from ai_pilled.runtime import CommandUnavailable, CompletedCommand


class PythonDependencyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.repo = Path(temporary.name)
        self.path = self.repo / 'requirements.txt'
        self.path.write_text('Example_Package==1.2.3\n')
        self.row = {'name': 'example-package', 'version': '1.2.3', 'vulns': []}

    def response(self, rows=None):
        dependencies = [self.row] if rows is None else rows
        code = 1 if any(row.get('vulns') for row in dependencies) else 0
        return CompletedCommand(json.dumps({'dependencies': dependencies, 'fixes': []}).encode(), code)

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
            with patch('ai_pilled.python_dependencies.run_completed', side_effect=provider):
                result = audit_python(self.repo)
        self.assertEqual(result.status, 'pass')
        self.assertEqual(result.metrics['packages_audited'], 1)

    def test_hash_export_audits_only_sanitized_pins(self):
        self.path.write_text('Example_Package==1.2.3 \\\n'
                             '    --hash=sha256:' + 'a' * 64 + ' \\\n'
                             '    --hash=sha256:' + 'B' * 64 + ' # wheel variants\n')
        def provider(argv, repo, **kwargs):
            selected = Path(argv[argv.index('--requirement') + 1])
            self.assertEqual(selected.read_text(), 'example-package==1.2.3\n')
            return self.response()
        with patch('ai_pilled.python_dependencies.run_completed', side_effect=provider):
            result = audit_python(self.repo)
        self.assertEqual(result.status, 'pass')
        self.assertEqual(result.metrics['packages_audited'], 1)

    def test_malformed_hashes_and_continuations_do_not_contact_provider(self):
        for source in ('Example_Package==1.2.3 --hash=sha256:abc',
                       'Example_Package==1.2.3 --hash=md5:' + 'a' * 32,
                       'Example_Package==1.2.3 --hash=sha256:' + 'g' * 64,
                       'Example_Package==1.2.3 --index-url=https://example.invalid',
                       'Example_Package==1.2.3#not-a-comment',
                       'Example_Package==1.2.3 \\', '\\',
                       'Example_Package==1.2.3 \\\\\n--hash=sha256:' + 'a' * 64,
                       '# ' + 'x' * 64_000):
            self.path.write_text(source)
            with self.subTest(source=source[:80]), patch('ai_pilled.python_dependencies.run_completed') as provider:
                self.assertEqual(audit_python(self.repo).status, 'incomplete')
                provider.assert_not_called()

    def test_joined_credential_is_blocked_before_provider(self):
        token = 'ghp_' + 'A' * 36
        self.path.write_text(token[:20] + '\\\n' + token[20:] + '==1.0\n')
        with patch('ai_pilled.python_dependencies.run_completed') as provider:
            result = audit_python(self.repo)
        self.assertEqual(result.status, 'incomplete')
        self.assertNotIn(token, json.dumps(result.to_dict()))
        self.assertIn('credentials', result.findings[0].message)
        provider.assert_not_called()

    def test_comments_follow_pip_join_order(self):
        from ai_pilled.python_dependencies import requirements
        self.path.write_text('# standalone comment \\\nExample_Package==1.2.3\n'
                             'ignored==2 # inline continuation \\\nnot-another-package==3\n')
        self.assertEqual(requirements(self.repo, ['requirements.txt'])[1],
                         {'example-package': '1.2.3', 'ignored': '2'})

    def test_hash_change_invalidates_audit_evidence(self):
        self.path.write_text('Example_Package==1.2.3 --hash=sha256:' + 'a' * 64)
        def provider(*args, **kwargs):
            self.path.write_text('Example_Package==1.2.3 --hash=sha256:' + 'b' * 64)
            return self.response()
        with patch('ai_pilled.python_dependencies.run_completed', side_effect=provider):
            result = audit_python(self.repo)
        self.assertEqual(result.status, 'incomplete')
        self.assertIn('changed', result.findings[0].message)

    def test_real_provider_exit_status_must_match_its_evidence(self):
        tool = self.repo / 'provider'
        for code, vulnerabilities in ((1, []), (0, [{'id': 'PYSEC-2026-1', 'fix_versions': []}])):
            with self.subTest(code=code):
                row = dict(self.row, vulns=vulnerabilities)
                data = json.dumps({'dependencies': [row]})
                tool.write_text(f'#!{sys.executable}\nprint({data!r})\nraise SystemExit({code})\n')
                tool.chmod(0o755)
                result = audit_python(self.repo, executable=str(tool))
                self.assertEqual(result.status, 'incomplete')
                self.assertIn('contradicts', result.findings[0].message)

    def test_legacy_cached_evidence_is_refreshed(self):
        from ai_pilled.python_dependencies import audit_python_changed
        self.configure_automation()
        with patch('ai_pilled.python_dependencies.run_completed', return_value=self.response()):
            audit_python(self.repo)
        path = self.repo / '.ai-pilled/events.jsonl'
        entry = json.loads(path.read_text())
        for metrics in ({}, [], {'evidence_version': True}, {'evidence_version': 1}):
            with self.subTest(metrics=metrics):
                entry['report']['metrics'] = metrics
                path.write_text(json.dumps(entry) + '\n')
                with patch('ai_pilled.python_dependencies.run_completed', return_value=self.response()) as provider:
                    result, reused = audit_python_changed(self.repo)
                self.assertFalse(reused)
                self.assertEqual(result.status, 'pass')
                provider.assert_called_once()

    def test_duplicate_vulnerability_keys_are_incomplete(self):
        raw = json.dumps({'dependencies': [self.row]})
        raw = raw.replace('"vulns": []', '"vulns":[{"id":"hidden","fix_versions":[]}],"vulns":[]')
        with patch('ai_pilled.python_dependencies.run_completed', return_value=CompletedCommand(raw.encode(), 0)):
            self.assertEqual(audit_python(self.repo).status, 'incomplete')

    def test_vulnerability_blocks_and_reports_fixed_versions(self):
        self.row['vulns'] = [{'id': 'PYSEC-2026-1', 'fix_versions': ['1.2.4']}]
        with patch('ai_pilled.python_dependencies.run_completed', return_value=self.response()):
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
            with self.subTest(rows=rows), patch('ai_pilled.python_dependencies.run_completed', return_value=self.response(rows)):
                self.assertEqual(audit_python(self.repo).status, 'incomplete')

    def test_unsupported_input_never_invokes_provider(self):
        for source in ('example>=1', '-r other.txt', '--index-url https://example.invalid',
                       'package @ https://example.invalid/a.whl', 'example==1; python_version>"3"',
                       'example[extra]==1', 'example==1.*'):
            self.path.write_text(source)
            with self.subTest(source=source), patch('ai_pilled.python_dependencies.run_completed') as provider:
                self.assertEqual(audit_python(self.repo).status, 'incomplete')
                provider.assert_not_called()

    def test_conflicting_pins_across_files_are_rejected(self):
        (self.repo / 'dev.txt').write_text('example-package==2.0\n')
        with patch('ai_pilled.python_dependencies.run_completed') as provider:
            result = audit_python(self.repo, ['requirements.txt', 'dev.txt'])
        self.assertEqual(result.status, 'incomplete')
        provider.assert_not_called()

    def test_changed_requirements_invalidate_completed_audit(self):
        def provider(*args, **kwargs):
            self.path.write_text('other==1.0\n')
            return self.response()
        with patch('ai_pilled.python_dependencies.run_completed', side_effect=provider):
            result = audit_python(self.repo)
        self.assertEqual(result.status, 'incomplete')
        self.assertIn('changed', result.findings[0].message)

    def test_unavailable_tool_and_malformed_json_are_incomplete(self):
        with patch('ai_pilled.python_dependencies.run_completed', side_effect=CommandUnavailable('Tool unavailable')):
            self.assertEqual(audit_python(self.repo).status, 'incomplete')
        for value in (b'not json', b'{}', b'null'):
            with patch('ai_pilled.python_dependencies.run_completed', return_value=CompletedCommand(value, 0)):
                self.assertEqual(audit_python(self.repo).status, 'incomplete')

    def test_empty_file_is_explicit_zero_package_audit(self):
        self.path.write_text('# No runtime dependencies\n')
        with patch('ai_pilled.python_dependencies.run_completed') as provider:
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
        with patch('ai_pilled.python_dependencies.run_completed', return_value=CompletedCommand(json.dumps([self.row]).encode(), 0)):
            self.assertEqual(audit_python(self.repo).status, 'pass')

    def test_credentials_are_blocked_before_provider_invocation(self):
        token = 'ghp_' + 'A' * 36
        self.path.write_text(token + '==1.0')
        with patch('ai_pilled.python_dependencies.run_completed') as provider:
            result = audit_python(self.repo)
        self.assertEqual(result.status, 'incomplete')
        self.assertNotIn(token, json.dumps(result.to_dict()))
        provider.assert_not_called()

    def configure_automation(self):
        (self.repo / '.ai-pilled.json').write_text(json.dumps({
            'python_requirements': ['requirements.txt'], 'python_audit_executable': 'selected-pip-audit'}))

    def test_automation_reuses_complete_result_but_not_changed_inputs(self):
        from ai_pilled.python_dependencies import audit_python_changed
        self.configure_automation()
        with patch('ai_pilled.python_dependencies.run_completed', return_value=self.response()):
            audit_python(self.repo)
        with patch('ai_pilled.python_dependencies.audit_python') as provider:
            result, reused = audit_python_changed(self.repo)
            self.assertTrue(reused)
            self.assertEqual(result.status, 'pass')
            self.assertEqual(result.metrics['packages_audited'], 1)
            provider.assert_not_called()
            self.path.write_text('example-package==2.0\n')
            self.assertFalse(audit_python_changed(self.repo)[1])
            provider.assert_called_once_with(self.repo, ['requirements.txt'], 'selected-pip-audit', timeout=30)

    def test_automation_retains_failures_retries_incomplete_and_expired(self):
        from ai_pilled.python_dependencies import audit_python_changed
        self.configure_automation()
        self.row['vulns'] = [{'id': 'PYSEC-2026-1', 'fix_versions': []}]
        with patch('ai_pilled.python_dependencies.run_completed', return_value=self.response()):
            audit_python(self.repo)
        self.assertEqual(audit_python_changed(self.repo)[0].status, 'fail')
        with patch('ai_pilled.python_dependencies.run_completed', side_effect=CommandUnavailable('offline')):
            audit_python(self.repo)
        with patch('ai_pilled.python_dependencies.audit_python') as provider:
            self.assertFalse(audit_python_changed(self.repo)[1])
            provider.assert_called_once()
        with patch('ai_pilled.python_dependencies.run_completed', return_value=self.response()):
            audit_python(self.repo)
        path = self.repo / '.ai-pilled/events.jsonl'
        entries = [json.loads(line) for line in path.read_text().splitlines()]
        for entry in entries:
            entry['at'] = '2000-01-01T00:00:00+00:00'
        path.write_text(''.join(json.dumps(entry) + '\n' for entry in entries))
        with patch('ai_pilled.python_dependencies.audit_python') as provider:
            self.assertFalse(audit_python_changed(self.repo)[1])
            provider.assert_called_once()
