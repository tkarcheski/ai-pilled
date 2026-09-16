import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from ai_pilled.refactor import refactor


class RefactorTests(unittest.TestCase):
    def setUp(self):
        clean = patch.dict(os.environ, {k: v for k, v in os.environ.items()
                                       if not k.startswith('GIT_')}, clear=True)
        clean.start()
        self.addCleanup(clean.stop)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        self.git('init', '-q', '-b', 'feature')
        self.git('config', 'user.name', 'Test')
        self.git('config', 'user.email', 'test@example.invalid')
        (self.repo / '.gitignore').write_text('.ai-pilled/\n')
        (self.repo / 'code.py').write_text('value = 1\n')

    def git(self, *args):
        return subprocess.run(['git', *args], cwd=self.repo, check=True, capture_output=True).stdout

    def configure(self, simplify=None, repair=None):
        data = {'aggressiveness': 'lazy', 'commands': {
            'simplify': simplify or [sys.executable, '-c',
                'from pathlib import Path; Path("code.py").write_text("value = 2\\n")'],
            'repair': repair or [sys.executable, '-c', 'pass'],
            'test': [sys.executable, '-c',
                     'from pathlib import Path; assert Path("code.py").read_text() == "value = 2\\n"']}}
        (self.repo / '.ai-pilled.json').write_text(json.dumps(data))
        self.git('add', '.gitignore', 'code.py', '.ai-pilled.json')
        self.git('commit', '-qm', 'test: source fixture')

    def test_returns_applicable_patch_without_changing_source_index_or_head(self):
        self.configure()
        before = self.git('rev-parse', 'HEAD')
        result = refactor(self.repo)
        self.assertEqual(result.status, 'pass', result.to_dict())
        self.assertTrue(result.patch)
        self.assertEqual((self.repo / 'code.py').read_text(), 'value = 1\n')
        self.assertEqual(self.git('rev-parse', 'HEAD'), before)
        self.assertEqual(self.git('status', '--porcelain'), b'')
        self.assertEqual(self.git('diff', '--cached'), b'')
        self.git('apply', '--check', result.patch)
        self.git('apply', result.patch)
        self.assertEqual((self.repo / 'code.py').read_text(), 'value = 2\n')
        self.assertFalse(list((self.repo / '.ai-pilled').glob('refactor-work-*')))

    def test_hidden_source_changes_are_preserved_without_running_steps(self):
        self.configure()
        head = self.git('rev-parse', 'HEAD')
        self.git('update-index', '--skip-worktree', 'code.py')
        (self.repo / 'code.py').write_text('value = 3\n')
        with patch('ai_pilled.refactor.command_check') as command:
            result = refactor(self.repo)
        self.assertEqual(result.status, 'incomplete')
        self.assertFalse(result.patch)
        command.assert_not_called()
        self.assertEqual(self.git('rev-parse', 'HEAD'), head)
        self.assertEqual((self.repo / 'code.py').read_text(), 'value = 3\n')

    def test_repair_cannot_hide_candidate_changes_from_export(self):
        for flag in ('--assume-unchanged', '--skip-worktree'):
            with self.subTest(flag=flag):
                self.configure(repair=['git', 'update-index', flag, 'code.py'])
                head = self.git('rev-parse', 'HEAD')
                result = refactor(self.repo)
                self.assertEqual(result.status, 'incomplete')
                self.assertIn('index flags', result.findings[0].message)
                self.assertFalse(result.patch)
                self.assertEqual(self.git('rev-parse', 'HEAD'), head)
                self.assertEqual(self.git('status', '--porcelain'), b'')
                self.assertEqual((self.repo / 'code.py').read_text(), 'value = 1\n')
                self.assertFalse(list((self.repo / '.ai-pilled').glob('refactor-work-*')))

    def test_quality_cannot_hide_candidate_changes_before_patch_export(self):
        self.configure()
        config_path = self.repo / '.ai-pilled.json'
        config = json.loads(config_path.read_text())
        config['commands']['test'] = ['git', 'update-index', '--assume-unchanged', 'code.py']
        config_path.write_text(json.dumps(config))
        self.git('add', '.ai-pilled.json')
        self.git('commit', '-qm', 'test: candidate index mutation')
        head = self.git('rev-parse', 'HEAD')
        result = refactor(self.repo)
        self.assertEqual(result.status, 'incomplete')
        self.assertEqual([step['status'] for step in result.steps], ['pass', 'pass', 'pass'])
        self.assertIn('index flags', result.findings[0].message)
        self.assertFalse(result.patch)
        self.assertEqual(self.git('rev-parse', 'HEAD'), head)
        self.assertEqual(self.git('status', '--porcelain'), b'')
        self.assertFalse(list((self.repo / '.ai-pilled').glob('refactor-work-*')))

    def test_failed_repair_exports_nothing(self):
        self.configure(repair=[sys.executable, '-c', 'raise SystemExit(1)'])
        result = refactor(self.repo)
        self.assertEqual(result.status, 'fail')
        self.assertFalse(result.patch)
        self.assertEqual((self.repo / 'code.py').read_text(), 'value = 1\n')

    def test_generated_credential_never_enters_exported_patch(self):
        self.configure(simplify=[sys.executable, '-c',
            'from pathlib import Path; Path("credential").write_text("ghp_" + "A" * 36)'])
        result = refactor(self.repo)
        self.assertEqual(result.status, 'fail')
        self.assertFalse(result.patch)
        self.assertNotIn('ghp_' + 'A' * 36, str(result.to_dict()))

    def test_missing_steps_and_dirty_source_are_incomplete(self):
        self.assertEqual(refactor(self.repo).status, 'incomplete')
        self.configure()
        (self.repo / 'code.py').write_text('uncommitted')
        self.assertEqual(refactor(self.repo).status, 'incomplete')

    def test_commands_cannot_hide_edits_in_a_new_commit(self):
        self.configure(simplify=['git', '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid',
                                  '-c', 'commit.gpgsign=false', 'commit', '--allow-empty', '-qm', 'test: new head'])
        result = refactor(self.repo)
        self.assertEqual(result.status, 'incomplete')
        self.assertIn('must not create commits', result.findings[0].message)
        self.assertFalse(result.patch)

    def test_changed_quality_policy_exports_nothing(self):
        self.configure(simplify=[sys.executable, '-c',
            'from pathlib import Path; Path(".ai-pilled.json").write_text("{}")'])
        result = refactor(self.repo)
        self.assertEqual(result.status, 'incomplete')
        self.assertIn('quality configuration', result.findings[0].message)
        self.assertFalse(result.patch)

    def test_generated_nonregular_and_oversized_policy_never_blocks_or_exports(self):
        for replacement in ('os.mkfifo(p)', 'p.symlink_to("code.py")',
                            'p.write_bytes(b"x" * 64_001)'):
            with self.subTest(replacement=replacement):
                code = ('import os; from pathlib import Path; '
                        'p=Path(".ai-pilled.json"); p.unlink(); ' + replacement)
                self.configure(simplify=[sys.executable, '-c', code])
                before = self.git('rev-parse', 'HEAD')
                policy = (self.repo / '.ai-pilled.json').read_bytes()
                env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1]),
                           PYTHONDONTWRITEBYTECODE='1')
                process = subprocess.run([sys.executable, '-m', 'ai_pilled', '--repo',
                                          str(self.repo), 'refactor'], env=env,
                                         capture_output=True, timeout=5, check=False)
                self.assertEqual(process.returncode, 2)
                result = json.loads(process.stdout)
                self.assertEqual(result['status'], 'incomplete')
                self.assertFalse(result['patch'])
                self.assertEqual(result['steps'][0]['status'], 'pass')
                self.assertEqual(self.git('rev-parse', 'HEAD'), before)
                self.assertEqual(self.git('status', '--porcelain'), b'')
                self.assertEqual((self.repo / '.ai-pilled.json').read_bytes(), policy)
                self.assertFalse(list((self.repo / '.ai-pilled').glob('refactor-work-*')))

    def test_new_files_are_included_in_patch(self):
        self.configure(repair=[sys.executable, '-c',
            'from pathlib import Path; Path("new.py").write_text("new = True")'])
        result = refactor(self.repo)
        self.assertEqual(result.status, 'pass', result.to_dict())
        self.git('apply', result.patch)
        self.assertEqual((self.repo / 'new.py').read_text(), 'new = True')

    def test_source_virtualenv_interpreter_keeps_its_identity(self):
        import venv
        tool = self.repo / '.ai-pilled' / 'tools'
        venv.EnvBuilder(with_pip=False, symlinks=True).create(tool)
        self.configure(repair=['.ai-pilled/tools/bin/python', '-c',
                              'import sys; assert sys.prefix != sys.base_prefix'])
        result = refactor(self.repo)
        self.assertEqual(result.status, 'pass', result.to_dict())

    def test_inherited_git_routing_cannot_hide_generated_credentials(self):
        self.configure(repair=[sys.executable, '-c',
            'from pathlib import Path; Path("credential").write_text("ghp_" + "A" * 36)'])
        config = json.loads((self.repo / '.ai-pilled.json').read_text())
        config['commands']['test'] = [sys.executable, '-c', 'pass']
        (self.repo / '.ai-pilled.json').write_text(json.dumps(config))
        self.git('add', '.ai-pilled.json')
        self.git('commit', '-qm', 'test: routing fixture')
        before = self.git('rev-parse', 'HEAD')
        with patch.dict(os.environ, {'GIT_DIR': str(self.repo / '.git'),
                                     'GIT_WORK_TREE': str(self.repo),
                                     'GIT_INDEX_FILE': str(self.repo / '.git/index')}):
            result = refactor(self.repo)
        self.assertEqual(result.status, 'fail', result.to_dict())
        self.assertFalse(result.patch)
        self.assertTrue(any(f.rule == 'github-token' for f in result.findings))
        self.assertEqual(self.git('rev-parse', 'HEAD'), before)
        self.assertEqual(self.git('status', '--porcelain'), b'')

    def test_inherited_git_routing_checks_refactored_source(self):
        self.configure()
        with patch.dict(os.environ, {'GIT_DIR': str(self.repo / '.git'),
                                     'GIT_WORK_TREE': str(self.repo)}):
            result = refactor(self.repo)
        self.assertEqual(result.status, 'pass', result.to_dict())
        self.assertTrue(result.patch)
        self.assertEqual((self.repo / 'code.py').read_text(), 'value = 1\n')

    def test_patch_export_preserves_binary_bytes_private_mode_and_exclusive_names(self):
        from ai_pilled.refactor import export_patch
        state = self.repo / '.ai-pilled'
        state.mkdir()
        payload = b'\xff\x00binary fixture\n'
        output = export_patch(state, payload, 'fixture')
        self.assertEqual(output.read_bytes(), payload)
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        with patch('ai_pilled.refactor.uuid.uuid4') as identifier:
            identifier.return_value.hex = 'fixed'
            target = state / 'fixture-fixed.patch'
            target.write_bytes(b'preserve')
            with self.assertRaises(FileExistsError):
                export_patch(state, payload, 'fixture')
        self.assertEqual(target.read_bytes(), b'preserve')
        self.assertEqual(list(state.glob('.ai-pilled-*.tmp')), [])

    def test_patch_parent_swaps_never_export_outside_or_return_stale_path(self):
        from ai_pilled.refactor import export_patch
        from ai_pilled.runtime import CommandError
        original_open, original_link = os.open, os.link
        for moment in ('open', 'publish'):
            with self.subTest(moment=moment):
                root = self.repo / moment
                state = root / '.ai-pilled'
                state.mkdir(parents=True)
                outside = root / 'outside'
                outside.mkdir()
                (outside / 'marker').write_text('preserve')

                def swap(state=state, root=root, outside=outside):
                    state.rename(root / 'original')
                    state.symlink_to(outside, target_is_directory=True)

                def before_open(path, *args, selected=state, **kwargs):
                    if (path == '.ai-pilled' and 'dir_fd' in kwargs
                            or isinstance(path, Path) and path.parent == selected and path.suffix == '.patch'):
                        swap()
                    return original_open(path, *args, **kwargs)

                def before_publish(*args, **kwargs):
                    swap()
                    return original_link(*args, **kwargs)

                target, replacement = (('ai_pilled.state.os.open', before_open) if moment == 'open'
                                       else ('ai_pilled.state.os.link', before_publish))
                with patch(target, side_effect=replacement):
                    with self.assertRaises((CommandError, OSError)):
                        export_patch(state, b'fixture', 'fixture')
                self.assertEqual(sorted(path.name for path in outside.iterdir()), ['marker'])
                self.assertEqual((outside / 'marker').read_text(), 'preserve')
                self.assertEqual(list((root / 'original').glob('.ai-pilled-*.tmp')), [])

    def test_failed_patch_write_leaves_no_partial_artifact(self):
        from contextlib import contextmanager
        from ai_pilled.refactor import export_patch
        state = self.repo / '.ai-pilled'
        state.mkdir()
        original_fdopen = os.fdopen

        class BrokenWriter:
            def __init__(self, stream):
                self.stream = stream

            def write(self, content):
                self.stream.write(content[:3])
                raise OSError('fixture write failure')

        @contextmanager
        def failed_write(*args, **kwargs):
            with original_fdopen(*args, **kwargs) as stream:
                yield BrokenWriter(stream)

        with patch('ai_pilled.state.os.fdopen', side_effect=failed_write):
            with self.assertRaisesRegex(OSError, 'fixture write failure'):
                export_patch(state, b'fixture patch', 'fixture')
        self.assertEqual(list(state.iterdir()), [])
