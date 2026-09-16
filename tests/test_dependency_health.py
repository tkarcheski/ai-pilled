import json
from pathlib import Path
import sys
import tempfile
import unittest

from ai_pilled.dependency_health import health, licenses


class DependencyHealthTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        (self.repo / 'package.json').write_text('{"name":"fixture"}')
        self.lock({'node_modules/example': {'version': '1.0.0', 'license': 'MIT'}})
        self.fake = self.repo / 'fake-npm'

    def lock(self, packages):
        (self.repo / 'package-lock.json').write_text(json.dumps({'lockfileVersion': 3, 'packages': packages}))

    def provider(self, tree, outdated):
        self.fake.write_text(f'#!{sys.executable}\nimport sys,json\n'
                            f'data = {tree!r} if sys.argv[1] == "ls" else {outdated!r}\n'
                            'print(json.dumps(data))\nraise SystemExit(1 if data.get("problems") or sys.argv[1] == "outdated" and data else 0)\n')
        self.fake.chmod(0o755)

    def test_outdated_versions_are_informational_not_claimed_vulnerabilities(self):
        self.provider({'name': 'fixture', 'dependencies': {}},
                      {'example': {'current': '1.0.0', 'wanted': '1.1.0', 'latest': '2.0.0'}})
        result = health(self.repo, str(self.fake))
        self.assertEqual(result.status, 'pass')
        self.assertEqual(result.findings[0].severity, 'info')
        self.assertIn('latest tag 2.0.0', result.findings[0].message)

    def test_version_conflicts_block_and_raw_diagnostics_are_not_stored(self):
        self.provider({'name': 'fixture', 'problems': ['private diagnostic'],
                       'error': {'code': 'ELSPROBLEMS'}}, {})
        result = health(self.repo, str(self.fake))
        self.assertEqual(result.status, 'fail')
        self.assertNotIn('private diagnostic', json.dumps(result.to_dict()))

    def test_unknown_tree_or_registry_error_is_incomplete(self):
        for tree, outdated in (({}, {}), ({'error': {'code': 'EFAIL'}}, {}),
                               ({'name': 'fixture'}, {'error': {'message': 'private'}})):
            self.provider(tree, outdated)
            self.assertEqual(health(self.repo, str(self.fake)).status, 'incomplete')

    def test_missing_current_version_is_not_clean(self):
        self.provider({'name': 'fixture'}, {'example': {'wanted': '1.0.0', 'latest': '2.0.0'}})
        self.assertEqual(health(self.repo, str(self.fake)).status, 'incomplete')

    def test_allowlist_is_required_and_exact(self):
        self.assertEqual(licenses(self.repo, []).status, 'incomplete')
        self.assertEqual(licenses(self.repo, ['MIT']).status, 'pass')
        self.assertEqual(licenses(self.repo, ['Apache-2.0']).status, 'fail')

    def test_license_expressions_are_not_silently_reinterpreted(self):
        self.lock({'node_modules/example': {'license': '(MIT OR Apache-2.0)'}})
        self.assertEqual(licenses(self.repo, ['MIT']).status, 'fail')
        self.assertEqual(licenses(self.repo, ['(MIT OR Apache-2.0)']).status, 'pass')

    def test_missing_license_and_workspace_links_are_incomplete(self):
        for package in ({'version': '1'}, {'link': True, 'license': 'MIT'}):
            self.lock({'node_modules/example': package})
            self.assertEqual(licenses(self.repo, ['MIT']).status, 'incomplete')
