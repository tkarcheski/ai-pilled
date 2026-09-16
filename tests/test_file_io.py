import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from ai_pilled.file_io import temporary_directory_beneath


class TemporaryWorkspaceTests(unittest.TestCase):
    def test_replaced_parent_cannot_redirect_creation_children_or_cleanup(self):
        with tempfile.TemporaryDirectory() as fixture:
            root = Path(fixture)
            state = root / '.ai-pilled'
            state.mkdir()
            original = root / 'original'
            outside = root / 'outside'
            outside.mkdir()
            sentinel = outside / 'keep'
            sentinel.write_bytes(b'unchanged')
            real_temporary = tempfile.TemporaryDirectory

            def replace_parent(*args, **kwargs):
                state.rename(original)
                state.symlink_to(outside, target_is_directory=True)
                return real_temporary(*args, **kwargs)

            with patch('ai_pilled.file_io.tempfile.TemporaryDirectory', side_effect=replace_parent):
                with temporary_directory_beneath(root, '.ai-pilled', prefix='fixture-') as work:
                    self.assertTrue(work.resolve().is_relative_to(original))
                    self.assertEqual(work.stat().st_mode & 0o777, 0o700)
                    subprocess.run([sys.executable, '-c',
                                    'from pathlib import Path; import sys; '
                                    '(Path(sys.argv[1]) / "child").write_bytes(b"fixture")',
                                    str(work)], check=True, capture_output=True, timeout=3)
                    self.assertEqual((work / 'child').read_bytes(), b'fixture')
                    # Cleanup must not follow an identically named outside directory.
                    decoy = outside / work.name
                    decoy.mkdir()
                    (decoy / 'keep').write_bytes(b'decoy')
            self.assertEqual(list(original.iterdir()), [])
            self.assertEqual(sentinel.read_bytes(), b'unchanged')
            self.assertEqual((decoy / 'keep').read_bytes(), b'decoy')

    def test_symlink_parent_is_rejected_before_temporary_creation(self):
        with tempfile.TemporaryDirectory() as fixture:
            root = Path(fixture)
            outside = root / 'outside'
            outside.mkdir()
            (root / '.ai-pilled').symlink_to(outside, target_is_directory=True)
            with patch('ai_pilled.file_io.tempfile.TemporaryDirectory') as creation:
                with self.assertRaises(OSError):
                    with temporary_directory_beneath(root, '.ai-pilled', prefix='fixture-'):
                        self.fail('Invalid parent was accepted')
            creation.assert_not_called()
            self.assertEqual(list(outside.iterdir()), [])

    def test_exception_cleans_workspace_and_closes_parent(self):
        with tempfile.TemporaryDirectory() as fixture:
            root = Path(fixture)
            (root / '.ai-pilled').mkdir()
            with self.assertRaisesRegex(RuntimeError, 'fixture failure'):
                with temporary_directory_beneath(root, '.ai-pilled', prefix='fixture-') as work:
                    descriptor = int(work.parent.name)
                    (work / 'partial').write_bytes(b'fixture')
                    raise RuntimeError('fixture failure')
            with self.assertRaises(OSError):
                os.fstat(descriptor)
            self.assertEqual(list((root / '.ai-pilled').iterdir()), [])
