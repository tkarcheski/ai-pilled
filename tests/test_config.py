import os
from unittest.mock import patch
import json
from pathlib import Path
import sys
import tempfile
import unittest

from ai_pilled.checks import command_check
from ai_pilled.config import ConfigError, load


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)

    def configure(self, data):
        (self.repo / '.ai-pilled.json').write_text(json.dumps(data))

    def test_defaults_protect_primary_branches_and_require_tests(self):
        config = load(self.repo)
        self.assertEqual(config.protected_branches, ['main', 'master'])
        self.assertTrue(config.require_tests)

    def test_missing_tests_are_incomplete(self):
        self.assertEqual(command_check(self.repo, 'test').status, 'incomplete')

    def test_success_and_failure_are_distinct(self):
        for code, status in [(0, 'pass'), (1, 'fail')]:
            self.configure({'commands': {'test': [sys.executable, '-c', f'raise SystemExit({code})']}})
            self.assertEqual(command_check(self.repo, 'test').status, status)

    def test_command_is_not_interpreted_as_shell(self):
        self.configure({'commands': {'test': [sys.executable, '-c',
                        'import sys; assert sys.argv[1] == "$(touch hacked)"',
                        '$(touch hacked)']}})
        self.assertEqual(command_check(self.repo, 'test').status, 'pass')
        self.assertFalse((self.repo / 'hacked').exists())

    def test_unknown_executable_fails(self):
        self.configure({'commands': {'test': ['ai-pilled-nonexistent-executable']}})
        self.assertEqual(command_check(self.repo, 'test').status, 'fail')

    def test_invalid_configs_rejected(self):
        for value in [[], {'typo': True}, {'version': True}, {'timeout': True},
                      {'commands': {'test': 'npm test'}},
                      {'commands': {'test': []}}, {'commands': {'nonsense': ['true']}},
                      {'require_tests': 'false'}, {'protected_branches': 'main'},
                      {'aggressiveness': 'reckless'}]:
            with self.subTest(value=value):
                self.configure(value)
                with self.assertRaises(ConfigError):
                    load(self.repo)

    def test_parent_git_environment_is_not_passed_to_checks(self):
        self.configure({'commands': {'test': [sys.executable, '-c',
                       'import os; assert not any(k.startswith("GIT_") for k in os.environ)']}})
        with patch.dict(os.environ, {'GIT_DIR': '/not-the-test-repo', 'GIT_CONFIG_COUNT': '1',
                                     'GIT_CONFIG_KEY_0': 'core.bare', 'GIT_CONFIG_VALUE_0': 'true'}):
            self.assertEqual(command_check(self.repo, 'test').status, 'pass')
