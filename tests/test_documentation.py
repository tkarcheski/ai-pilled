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
