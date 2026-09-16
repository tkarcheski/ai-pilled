import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ai_pilled.python_health import health_python, licenses_python
from ai_pilled.runtime import CommandFailed, CommandUnavailable


class PythonHealthTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.repo = Path(temporary.name)
        self.data = {'version': '1', 'environment': {'python_version': '3.14'}, 'installed': [
            {'metadata': {'name': 'example', 'version': '1.0', 'license_expression': 'MIT'}}]}

    def inspect(self):
        return json.dumps(self.data).encode()

    def test_health_uses_isolated_python_and_no_network_by_default(self):
        def provider(argv, repo, **kwargs):
            self.assertEqual(argv[:4], ['selected-python', '-I', '-m', 'pip'])
            self.assertIn(argv[4], ('inspect', 'check'))
            return self.inspect() if argv[4] == 'inspect' else b'No broken requirements found.'
        with patch('ai_pilled.python_health.run', side_effect=provider):
            result = health_python(self.repo, 'selected-python')
        self.assertEqual(result.status, 'pass')
        self.assertEqual(result.metrics['outdated_checked'], 0)

    def test_conflicts_fail_but_unavailable_check_is_incomplete(self):
        for error, status in ((CommandFailed('python', 1), 'fail'),
                              (CommandFailed('python', 2), 'incomplete'),
                              (CommandUnavailable('timeout'), 'incomplete')):
            def provider(repo, executable, arguments, failure=error):
                if arguments == ['check']:
                    raise failure
                return self.inspect()
            with self.subTest(error=str(error)), patch('ai_pilled.python_health.pip_command', side_effect=provider):
                self.assertEqual(health_python(self.repo, 'python').status, status)

    def test_outdated_evidence_is_informational_and_bound_to_installed_versions(self):
        rows = {'name': 'example', 'installed_version': '1.0', 'latest': '2.0', 'versions': ['2.0', '1.0']}
        with patch('ai_pilled.python_health.pip_command', side_effect=[self.inspect(), b'', json.dumps(rows).encode(), self.inspect()]):
            result = health_python(self.repo, 'python', outdated=True)
        self.assertEqual(result.status, 'pass')
        self.assertEqual(result.findings[0].severity, 'info')
        rows['installed_version'] = 'unmatched'
        with patch('ai_pilled.python_health.pip_command', side_effect=[self.inspect(), b'', json.dumps(rows).encode()]):
            self.assertEqual(health_python(self.repo, 'python', outdated=True).status, 'incomplete')

    def test_changed_environment_invalidates_health_and_license_checks(self):
        original = self.inspect()
        self.data['installed'][0]['metadata']['version'] = '2.0'
        with patch('ai_pilled.python_health.pip_command', side_effect=[original, b'', self.inspect()]):
            self.assertEqual(health_python(self.repo, 'python').status, 'incomplete')
        with patch('ai_pilled.python_health.pip_command', side_effect=[original, self.inspect()]):
            self.assertEqual(licenses_python(self.repo, 'python', ['MIT']).status, 'incomplete')

    def test_exact_license_policy_preserves_unknown_evidence(self):
        for license_value, allowed, status in (('MIT', ['MIT'], 'pass'), ('GPL-3.0-only', ['MIT'], 'fail'),
                                               (None, ['MIT'], 'incomplete'), ('UNKNOWN', ['MIT'], 'incomplete')):
            self.data['installed'][0]['metadata']['license_expression'] = license_value
            with self.subTest(license=license_value), patch('ai_pilled.python_health.pip_command', return_value=self.inspect()):
                self.assertEqual(licenses_python(self.repo, 'python', allowed).status, status)
        with patch('ai_pilled.python_health.pip_command') as provider:
            self.assertEqual(licenses_python(self.repo, 'python', []).status, 'incomplete')
            provider.assert_not_called()

    def test_malformed_or_duplicate_installed_evidence_never_passes(self):
        for data in ({}, {'version': '2', 'installed': [], 'environment': {}},
                     dict(self.data, installed=self.data['installed'] * 2),
                     dict(self.data, installed=[{'metadata': {'name': 'missing-version'}}])):
            with self.subTest(data=data), patch('ai_pilled.python_health.pip_command', return_value=json.dumps(data).encode()):
                self.assertEqual(health_python(self.repo, 'python').status, 'incomplete')

    def test_failed_index_lookup_cannot_claim_up_to_date(self):
        with patch('ai_pilled.python_health.pip_command', side_effect=[self.inspect(), b'', CommandFailed('python', 1)]):
            result = health_python(self.repo, 'python', outdated=True)
        self.assertEqual(result.status, 'incomplete')

    def test_unpublished_installed_version_requires_manual_comparison(self):
        data = {'name': 'example', 'installed_version': '1.0', 'latest': '2.0', 'versions': ['2.0']}
        with patch('ai_pilled.python_health.pip_command', side_effect=[self.inspect(), b'', json.dumps(data).encode(), self.inspect()]):
            result = health_python(self.repo, 'python', outdated=True)
        self.assertEqual(result.status, 'incomplete')
        self.assertEqual(result.findings[0].rule, 'python-version-unavailable')

    def test_real_environment_ignores_repository_pip_module_and_checks_license(self):
        import venv
        environment = self.repo / 'environment'
        # Preserve the library location of relocatable Python builds inside a venv.
        venv.EnvBuilder(with_pip=True, symlinks=True).create(environment)
        (self.repo / 'pip.py').write_text('from pathlib import Path\nPath("shadow-executed").touch()\nraise RuntimeError("shadowed")\n')
        executable = str(environment / 'bin' / 'python')
        result = health_python(self.repo, executable)
        self.assertEqual(result.status, 'pass', result.to_dict())
        self.assertFalse((self.repo / 'shadow-executed').exists())
        result = licenses_python(self.repo, executable, ['MIT'])
        # Python 3.10 ensurepip also bundles setuptools with unknown metadata.
        self.assertIn(result.status, ('pass', 'incomplete'), result.to_dict())
        self.assertTrue(all(f.path == 'setuptools' and f.rule == 'python-license-unknown'
                            for f in result.findings), result.to_dict())
