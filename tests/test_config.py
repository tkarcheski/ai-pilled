import os
from unittest.mock import patch
import json
from pathlib import Path
import sys
import tempfile
import unittest

from ai_pilled.checks import command_check
from ai_pilled.config import ConfigError, load, load_staged
from ai_pilled.runtime import run


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)

    def configure(self, data):
        (self.repo / '.ai-pilled.json').write_text(json.dumps(data))

    def test_staged_configuration_ignores_unstaged_deleted_and_untracked_policy(self):
        run(['git', 'init', '-q'], self.repo)
        self.configure({'timeout': 7})
        self.assertEqual(load_staged(self.repo).timeout, 120)
        run(['git', 'add', '.ai-pilled.json'], self.repo)
        self.configure({'timeout': 31})
        self.assertEqual(load_staged(self.repo).timeout, 7)
        policy = self.repo / '.ai-pilled.json'
        policy.unlink()
        self.assertEqual(load_staged(self.repo).timeout, 7)
        policy.symlink_to('not-present')
        self.assertEqual(load_staged(self.repo).timeout, 7)
        run(['git', 'add', '.ai-pilled.json'], self.repo)
        with self.assertRaisesRegex(ConfigError, 'resolved regular file'):
            load_staged(self.repo)

    def test_staged_configuration_rejects_malformed_and_oversized_blobs(self):
        run(['git', 'init', '-q'], self.repo)
        for content in ('{"require_tests":false,"require_tests":true}', '[]', 'broken', ' ' * 64_001):
            with self.subTest(size=len(content)):
                (self.repo / '.ai-pilled.json').write_text(content)
                run(['git', 'add', '.ai-pilled.json'], self.repo)
                self.configure({})
                with self.assertRaises(ConfigError):
                    load_staged(self.repo)

    def test_conflicted_staged_policy_cannot_choose_a_side(self):
        run(['git', 'init', '-q'], self.repo)
        oid = run(['git', 'hash-object', '-w', '--stdin'], self.repo, input_data=b'{}').strip()
        rows = b''.join(b'100644 ' + oid + b' ' + str(stage).encode() + b'\t.ai-pilled.json\n'
                        for stage in (1, 2, 3))
        run(['git', 'update-index', '--index-info'], self.repo, input_data=rows)
        with self.assertRaisesRegex(ConfigError, 'resolved regular file'):
            load_staged(self.repo)

    def test_changed_configuration_after_read_is_not_used_or_defaulted(self):
        from contextlib import contextmanager
        policy = self.repo / '.ai-pilled.json'
        original = os.fdopen
        for change in ('replace', 'delete', 'mode', 'symlink'):
            with self.subTest(change=change):
                if policy.is_symlink():
                    policy.unlink()
                self.configure({'timeout': 7})
                replacement = self.repo / 'replacement'
                replacement.write_text('{"timeout":31}')
                @contextmanager
                def changed(fd, *args, change=change, replacement=replacement, **kwargs):
                    with original(fd, *args, **kwargs) as stream:
                        yield stream
                    if change == 'replace':
                        replacement.replace(policy)
                    elif change == 'delete':
                        policy.unlink()
                    elif change == 'mode':
                        policy.chmod(0o700)
                    else:
                        policy.unlink()
                        policy.symlink_to(replacement)
                with patch('ai_pilled.file_io.os.fdopen', side_effect=changed):
                    with self.assertRaises(ConfigError):
                        load(self.repo)

    def test_replaced_policy_cannot_authorize_quality_with_stale_settings(self):
        from contextlib import contextmanager
        from ai_pilled.pipeline import quality
        run(['git', 'init', '-q'], self.repo)
        (self.repo / '.gitignore').write_text('.ai-pilled/\n')
        self.configure({'aggressiveness': 'lazy', 'require_tests': False})
        run(['git', 'add', '.gitignore', '.ai-pilled.json'], self.repo)
        replacement = self.repo / 'replacement'
        replacement.write_text('{"aggressiveness":"strict","require_tests":true}')
        original = os.fdopen
        swapped = False
        @contextmanager
        def changed(fd, *args, **kwargs):
            nonlocal swapped
            with original(fd, *args, **kwargs) as stream:
                yield stream
            if not swapped:
                swapped = True
                replacement.replace(self.repo / '.ai-pilled.json')
        with patch('ai_pilled.file_io.os.fdopen', side_effect=changed), \
                patch('ai_pilled.pipeline.command_check') as commands:
            with self.assertRaises(ConfigError):
                quality(self.repo)
        commands.assert_not_called()
        self.assertTrue(swapped)

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

    def test_unknown_executable_is_incomplete(self):
        self.configure({'commands': {'test': ['ai-pilled-nonexistent-executable']}})
        self.assertEqual(command_check(self.repo, 'test').status, 'incomplete')

    def test_duplicate_safety_settings_are_rejected(self):
        (self.repo / '.ai-pilled.json').write_text('{"require_tests":true,"require_tests":false}')
        with self.assertRaises(ConfigError):
            load(self.repo)

    def test_invalid_configs_rejected(self):
        for value in [[], {'typo': True}, {'version': True}, {'timeout': True},
                      {'commands': {'test': 'npm test'}},
                      {'commands': {'test': []}}, {'commands': {'nonsense': ['true']}},
                      {'require_tests': 'false'}, {'protected_branches': 'main'},
                      {'aggressiveness': 'reckless'}, {'review_on_commit': 'true'}, {'codex_executable': []}, {'audit_dependencies_on_change': 'yes'}, {'review_checks_on_commit': 'yes'}]:
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

    def test_timeout_and_output_limit_do_not_claim_test_failure(self):
        for program in ('import time; time.sleep(5)', 'print("x" * 2_000_001)'):
            self.configure({'timeout': 1, 'commands': {'test': [sys.executable, '-c', program]}})
            result = command_check(self.repo, 'test')
            self.assertEqual(result.status, 'incomplete')
            self.assertEqual(result.findings[0].rule, 'command-unavailable')

    def test_signal_termination_does_not_claim_test_failure(self):
        self.configure({'commands': {'test': [sys.executable, '-c',
                        'import os,signal; os.kill(os.getpid(), signal.SIGTERM)']}})
        self.assertEqual(command_check(self.repo, 'test').status, 'incomplete')


    def test_symlink_configuration_is_not_silently_defaulted_or_followed(self):
        path = self.repo / '.ai-pilled.json'
        target = self.repo / 'outside.json'
        path.symlink_to(target)
        with self.assertRaises(ConfigError):
            load(self.repo)
        target.write_text('{"require_tests": false}')
        with self.assertRaises(ConfigError):
            load(self.repo)

    def test_configuration_size_is_bounded(self):
        (self.repo / '.ai-pilled.json').write_text(' ' * 64_000 + '{}')
        with self.assertRaises(ConfigError):
            load(self.repo)

    def test_named_pipe_configuration_is_rejected_without_waiting(self):
        os.mkfifo(self.repo / '.ai-pilled.json')
        code = ('import sys; from ai_pilled.config import load,ConfigError\n'
                'try: load(sys.argv[1])\n'
                'except ConfigError: print("rejected")\n'
                'else: raise SystemExit(1)')
        output = run([sys.executable, '-c', code, str(self.repo)],
                     Path(__file__).resolve().parents[1], timeout=5)
        self.assertEqual(output.strip(), b'rejected')


    def test_excessively_nested_configuration_is_a_config_error(self):
        (self.repo / '.ai-pilled.json').write_text('[' * 1500 + '0' + ']' * 1500)
        with self.assertRaises(ConfigError):
            load(self.repo)

    def test_python_audit_configuration_rejects_unsafe_or_ambiguous_paths(self):
        for value in ('requirements.txt', ['../outside'], ['/outside'], ['a', 'a'],
                      ['a'] * 33, [None], ['a\0b']):
            self.configure({'python_requirements': value})
            with self.subTest(value=value), self.assertRaises(ConfigError):
                load(self.repo)
        self.configure({'python_audit_executable': []})
        with self.assertRaises(ConfigError):
            load(self.repo)
