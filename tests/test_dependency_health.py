import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

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

    def provider(self, tree, outdated, tree_code=None, outdated_code=None):
        tree_code = int(bool(tree.get("problems"))) if tree_code is None else tree_code
        outdated_code = int(bool(outdated)) if outdated_code is None else outdated_code
        self.fake.write_text(f'#!{sys.executable}\nimport sys,json\n'
                            f'data = {tree!r} if sys.argv[1] == "ls" else {outdated!r}\n'
                            f'print(json.dumps(data))\nraise SystemExit({tree_code} if sys.argv[1] == "ls" else {outdated_code})\n')
        self.fake.chmod(0o755)

    def test_outdated_versions_are_informational_not_claimed_vulnerabilities(self):
        self.provider({'name': 'fixture', 'dependencies': {}},
                      {'example': {'current': '1.0.0', 'wanted': '1.1.0', 'latest': '2.0.0'}})
        result = health(self.repo, str(self.fake))
        self.assertEqual(result.status, 'pass')
        self.assertEqual(result.findings[0].severity, 'info')
        self.assertIn('latest tag 2.0.0', result.findings[0].message)

    def test_process_status_must_agree_with_health_evidence(self):
        clean = {'name': 'fixture', 'dependencies': {}}
        update = {'example': {'current': '1.0.0', 'wanted': '1.1.0', 'latest': '1.1.0'}}
        cases = ((clean, {}, 1, 0), (clean, {}, 0, 1),
                 ({'name': 'fixture', 'problems': ['invalid entry']}, {}, 0, 0),
                 (clean, update, 0, 0))
        for tree, outdated, tree_code, outdated_code in cases:
            with self.subTest(tree_code=tree_code, outdated_code=outdated_code):
                self.provider(tree, outdated, tree_code, outdated_code)
                result = health(self.repo, str(self.fake))
                self.assertEqual(result.status, 'incomplete')
                self.assertIn('contradicts', result.findings[0].message)

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


    def test_lockfile_replaced_by_invalid_root_is_incomplete(self):
        from ai_pilled.dependencies import snapshot
        def replace_after_snapshot(repo):
            fingerprint = snapshot(repo)
            (repo / 'package-lock.json').write_text('[]')
            return fingerprint
        with patch('ai_pilled.dependency_health.snapshot', side_effect=replace_after_snapshot):
            result = licenses(self.repo, ['MIT'])
        self.assertEqual(result.status, 'incomplete')
        self.assertEqual(result.findings[0].rule, 'license-check-unavailable')

    def test_replaced_lockfile_symlink_is_not_read(self):
        from ai_pilled.runtime import run
        import os
        # A pipe proves the second read neither follows the link nor waits for data.
        pipe = self.repo / 'pipe'
        os.mkfifo(pipe)
        code = ('from pathlib import Path; import sys; from unittest.mock import patch\n'
                'from ai_pilled.dependencies import snapshot\n'
                'from ai_pilled.dependency_health import licenses\n'
                'repo=Path(sys.argv[1])\n'
                'def replace(root):\n'
                '    value=snapshot(root); path=root/"package-lock.json"\n'
                '    path.unlink(); path.symlink_to(root/"pipe"); return value\n'
                'with patch("ai_pilled.dependency_health.snapshot", side_effect=replace):\n'
                '    assert licenses(repo,["MIT"]).status == "incomplete"\n')
        run([sys.executable, '-c', code, str(self.repo)],
            Path(__file__).resolve().parents[1], timeout=5)
