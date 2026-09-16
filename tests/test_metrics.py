import json
from pathlib import Path
import tempfile
import unittest

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
