import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ai_pilled.documentation import END, START, update_readme


class DocumentationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        self.path = self.repo / 'README.md'

    def test_updates_only_generated_block_and_is_idempotent(self):
        prefix, suffix = '# Handwritten title\n\n', '\n\nUser instructions stay here.\n'
        self.path.write_text(prefix + START + '\nold\n' + END + suffix)
        self.path.chmod(0o640)
        self.assertEqual(update_readme(self.repo).status, 'pass')
        content = self.path.read_text()
        self.assertTrue(content.startswith(prefix))
        self.assertTrue(content.endswith(suffix))
        self.assertIn('release-plan', content)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o640)
        self.assertEqual(update_readme(self.repo).metrics['changed'], 0)

    def test_check_detects_drift_without_writing(self):
        self.path.write_text('# Existing documentation\n')
        before = self.path.read_bytes()
        self.assertEqual(update_readme(self.repo, check=True).status, 'fail')
        self.assertEqual(self.path.read_bytes(), before)
        update_readme(self.repo)
        self.assertEqual(update_readme(self.repo, check=True).status, 'pass')

    def test_config_changes_are_documented_without_exposing_arguments(self):
        (self.repo / '.ai-pilled.json').write_text(json.dumps({
            'aggressiveness': 'strict', 'commands': {'test': ['tool', 'private-argument']}}))
        update_readme(self.repo)
        text = self.path.read_text()
        self.assertIn('**strict**', text)
        self.assertIn('Configured commands: test.', text)
        self.assertNotIn('private-argument', text)

    def test_incomplete_or_duplicate_markers_preserve_file(self):
        for text in (START, END, END + START, START + END + START + END):
            self.path.write_text(text)
            self.assertEqual(update_readme(self.repo).status, 'incomplete')
            self.assertEqual(self.path.read_text(), text)

    def test_symlink_and_outside_paths_are_rejected(self):
        target = self.repo / 'untouched'
        target.write_text('keep')
        self.path.symlink_to(target)
        self.assertEqual(update_readme(self.repo).status, 'incomplete')
        self.assertEqual(target.read_text(), 'keep')
        self.assertEqual(update_readme(self.repo, '../outside.md').status, 'incomplete')

    def test_replaced_path_cannot_copy_external_text_into_readme(self):
        from ai_pilled.metrics import local_path
        self.path.write_text('# Original\n')
        target = self.repo / 'untouched'
        target.write_text('private unrelated content')
        def replaced(*args):
            path = local_path(*args)
            path.unlink()
            path.symlink_to(target)
            return path
        with patch('ai_pilled.documentation.local_path', side_effect=replaced):
            result = update_readme(self.repo)
        self.assertEqual(result.status, 'incomplete')
        self.assertTrue(self.path.is_symlink())
        self.assertEqual(target.read_text(), 'private unrelated content')

    def test_concurrent_prose_edit_is_preserved_and_can_be_retried(self):
        from ai_pilled.state import atomic_text
        self.path.write_text('# Original prose\n')

        def concurrent(path, text, mode, **options):
            path.write_text('# Concurrent user edit\n')
            return atomic_text(path, text, mode, **options)

        with patch('ai_pilled.documentation.atomic_text', side_effect=concurrent):
            result = update_readme(self.repo)
        self.assertEqual(result.status, 'incomplete')
        self.assertIn('concurrently', result.findings[0].message)
        self.assertEqual(self.path.read_text(), '# Concurrent user edit\n')
        self.assertEqual(update_readme(self.repo).status, 'pass')
        self.assertTrue(self.path.read_text().startswith('# Concurrent user edit\n'))

    def test_concurrent_creation_and_deletion_are_preserved(self):
        from ai_pilled.state import atomic_text
        for initially_present in (False, True):
            with self.subTest(initially_present=initially_present):
                self.path.unlink(missing_ok=True)
                if initially_present:
                    self.path.write_text('# Original\n')

                def concurrent(path, text, mode, *, present=initially_present, **options):
                    if present:
                        path.unlink()
                    else:
                        path.write_text('')
                    return atomic_text(path, text, mode, **options)

                with patch('ai_pilled.documentation.atomic_text', side_effect=concurrent):
                    result = update_readme(self.repo)
                self.assertEqual(result.status, 'incomplete')
                self.assertEqual(self.path.exists(), not initially_present)
                if not initially_present:
                    self.assertEqual(self.path.read_text(), '')

    def test_concurrent_symlink_replacement_preserves_target(self):
        from ai_pilled.state import atomic_text
        self.path.write_text('# Original\n')
        target = self.repo / 'user.md'
        target.write_text('# Private unrelated prose\n')

        def concurrent(path, text, mode, **options):
            path.unlink()
            path.symlink_to(target)
            return atomic_text(path, text, mode, **options)

        with patch('ai_pilled.documentation.atomic_text', side_effect=concurrent):
            result = update_readme(self.repo)
        self.assertEqual(result.status, 'incomplete')
        self.assertTrue(self.path.is_symlink())
        self.assertEqual(target.read_text(), '# Private unrelated prose\n')

    def test_concurrent_permission_change_is_preserved(self):
        from ai_pilled.state import atomic_text
        self.path.write_text('# Original\n')
        self.path.chmod(0o644)

        def concurrent(path, text, mode, **options):
            path.chmod(0o600)
            return atomic_text(path, text, mode, **options)

        with patch('ai_pilled.documentation.atomic_text', side_effect=concurrent):
            result = update_readme(self.repo)
        self.assertEqual(result.status, 'incomplete')
        self.assertEqual(self.path.read_text(), '# Original\n')
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_file_changed_during_snapshot_read_is_preserved(self):
        from contextlib import contextmanager
        from ai_pilled.file_io import open_regular
        self.path.write_text('# Original\n')

        class ChangingReader:
            def __init__(self, stream, path):
                self.stream, self.path = stream, path

            def fileno(self):
                return self.stream.fileno()

            def read(self, maximum):
                content = self.stream.read(maximum)
                self.path.write_text('# Edited during read\n')
                return content

        @contextmanager
        def changing(path):
            with open_regular(path) as stream:
                yield ChangingReader(stream, path)

        with patch('ai_pilled.file_io.open_regular', side_effect=changing):
            result = update_readme(self.repo)
        self.assertEqual(result.status, 'incomplete')
        self.assertIn('changed while reading', result.findings[0].message)
        self.assertEqual(self.path.read_text(), '# Edited during read\n')
