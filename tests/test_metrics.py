import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ai_pilled.metrics import bundle, coverage


class MetricsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)

    def coverage_file(self, covered, total, percent=100):
        (self.repo / 'coverage.json').write_text(json.dumps({
            'totals': {'covered_lines': covered, 'num_statements': total,
                       'percent_covered': percent}}))

    def test_coverage_uses_counts_not_rounded_percentage(self):
        self.coverage_file(79, 100)
        result = coverage(self.repo, 'coverage.json', 80)
        self.assertEqual(result.status, 'fail')
        self.assertEqual(result.metrics['line_percent'], 79)
        self.coverage_file(80, 100)
        self.assertEqual(coverage(self.repo, 'coverage.json', 80).status, 'pass')

    def test_missing_empty_and_invalid_coverage_do_not_pass(self):
        self.assertEqual(coverage(self.repo, 'coverage.json', 80).status, 'incomplete')
        for covered, total in ((0, 0), (2, 1), (-1, 5), (True, 1)):
            self.coverage_file(covered, total)
            self.assertEqual(coverage(self.repo, 'coverage.json', 80).status, 'incomplete')
        self.coverage_file(1, 1)
        self.assertEqual(coverage(self.repo, 'coverage.json', float('nan')).status, 'incomplete')

    def test_bundle_counts_nested_files_at_exact_boundary(self):
        (self.repo / 'dist' / 'nested').mkdir(parents=True)
        (self.repo / 'dist' / 'app.js').write_bytes(b'a' * 70)
        (self.repo / 'dist' / 'nested' / 'app.css').write_bytes(b'b' * 30)
        result = bundle(self.repo, 'dist', 100)
        self.assertEqual(result.status, 'pass')
        self.assertEqual(result.metrics, {'bytes': 100, 'files': 2, 'maximum_bytes': 100})
        self.assertEqual(bundle(self.repo, 'dist', 99).status, 'fail')

    def test_bundle_snapshot_changes_for_equal_size_edits(self):
        (self.repo / 'app.js').write_bytes(b'a')
        before = bundle(self.repo, 'app.js', 10)
        (self.repo / 'app.js').write_bytes(b'b')
        after = bundle(self.repo, 'app.js', 10)
        self.assertNotEqual(before.snapshot, after.snapshot)

    def test_missing_empty_or_external_artifacts_never_pass(self):
        (self.repo / 'dist').mkdir()
        for path in ('dist', 'missing', '../outside', '/etc/passwd'):
            self.assertEqual(bundle(self.repo, path, 100).status, 'incomplete')

    def test_symlink_parent_and_directory_contents_are_rejected(self):
        (self.repo / 'dist').mkdir()
        (self.repo / 'dist' / 'external').symlink_to('/etc')
        self.assertEqual(bundle(self.repo, 'dist', 100).status, 'incomplete')
        self.assertEqual(coverage(self.repo, 'dist/external/passwd', 80).status, 'incomplete')

    def test_replaced_coverage_path_cannot_follow_external_evidence(self):
        from ai_pilled.metrics import local_path
        self.coverage_file(0, 10)
        with tempfile.TemporaryDirectory() as other:
            outside = Path(other) / 'outside.json'
            outside.write_text(json.dumps({'totals': {'covered_lines': 10, 'num_statements': 10}}))
            def replaced(*args):
                path = local_path(*args)
                path.unlink()
                path.symlink_to(outside)
                return path
            with patch('ai_pilled.metrics.local_path', side_effect=replaced):
                result = coverage(self.repo, 'coverage.json', 90)
            self.assertEqual(result.status, 'incomplete')
            self.assertEqual(result.metrics, {})
            self.assertTrue((self.repo / 'coverage.json').is_symlink())

    def test_special_and_oversized_evidence_remains_incomplete(self):
        path = self.repo / 'coverage.json'
        os.mkfifo(path)
        self.assertEqual(coverage(self.repo, path.name, 90).status, 'incomplete')
        self.assertEqual(bundle(self.repo, path.name, 100).status, 'incomplete')
        self.assertTrue(path.is_fifo())
        path.unlink()
        path.write_bytes(b' ' * 2_000_001)
        self.assertEqual(coverage(self.repo, path.name, 90).status, 'incomplete')

    def test_unreadable_subdirectory_cannot_be_omitted_from_budget(self):
        dist = self.repo / 'dist'
        hidden = dist / 'private'
        hidden.mkdir(parents=True)
        (dist / 'visible.txt').write_bytes(b'x')
        (hidden / 'large.bin').write_bytes(b'x' * 100)
        original = os.scandir

        def denied(path):
            if Path(path) == hidden:
                raise PermissionError('private directory')
            return original(path)

        with patch('ai_pilled.metrics.os.scandir', side_effect=denied):
            result = bundle(self.repo, 'dist', 10)
        self.assertEqual(result.status, 'incomplete')
        self.assertEqual(result.metrics, {})
        self.assertEqual((hidden / 'large.bin').read_bytes(), b'x' * 100)

    def test_directory_iteration_failure_cannot_publish_partial_metrics(self):
        from contextlib import contextmanager
        dist = self.repo / 'dist'
        dist.mkdir()
        (dist / 'a.txt').write_bytes(b'a')
        (dist / 'b.txt').write_bytes(b'b')
        original = os.scandir

        def interrupted(children):
            yield next(children)
            raise OSError('interrupted directory read')

        @contextmanager
        def partial(path):
            with original(path) as children:
                yield interrupted(children)

        with patch('ai_pilled.metrics.os.scandir', side_effect=partial):
            result = bundle(self.repo, 'dist', 100)
        self.assertEqual(result.status, 'incomplete')
        self.assertEqual(result.metrics, {})

    def test_bundle_entry_limit_counts_files_and_empty_directories(self):
        dist = self.repo / 'dist'
        dist.mkdir()
        (dist / 'a').write_bytes(b'a')
        (dist / 'b').write_bytes(b'b')
        with patch('ai_pilled.metrics.MAX_ARTIFACT_ENTRIES', 3):
            self.assertEqual(bundle(self.repo, 'dist', 2).status, 'pass')
            (dist / 'empty').mkdir()
            result = bundle(self.repo, 'dist', 2)
        self.assertEqual(result.status, 'incomplete')
        self.assertIn('traversal limit', result.findings[0].message)
        self.assertEqual(result.metrics, {})

    def test_bundle_preserves_non_utf8_filename_bytes(self):
        dist = self.repo / 'dist'
        dist.mkdir()
        artifact = dist / os.fsdecode(b'asset-\xff.bin')
        artifact.write_bytes(b'abc')
        result = bundle(self.repo, 'dist', 3)
        self.assertEqual(result.status, 'pass')
        self.assertEqual(result.metrics, {'bytes': 3, 'files': 1, 'maximum_bytes': 3})
        artifact.rename(dist / os.fsdecode(b'asset-\xfe.bin'))
        self.assertNotEqual(bundle(self.repo, 'dist', 3).snapshot, result.snapshot)
