import json
import unittest

from ai_pilled.pipeline import PipelineReport, combine
from ai_pilled.runtime import MAX_FINDINGS, Report
from ai_pilled.security import scan_bytes


class ReportBoundTests(unittest.TestCase):
    def test_repeated_credentials_have_bounded_output_and_remain_blocking(self):
        token = 'ghp_' + 'Z' * 36
        result = Report('security')
        scan_bytes(result, 'many.txt', ((token + '\n') * 5000).encode())
        serialized = json.dumps(result.to_dict())
        self.assertEqual(result.status, 'fail')
        self.assertLess(len(serialized), 50_000)
        self.assertNotIn(token, serialized)
        self.assertEqual(result.findings[-1].rule, 'findings-truncated')

    def test_late_error_survives_an_already_full_informational_report(self):
        result = Report('check')
        for _ in range(MAX_FINDINGS + 10):
            result.add('notice', 'Informational', severity='info')
        self.assertEqual(result.status, 'incomplete')
        result.add('critical', 'Important late failure')
        self.assertEqual(result.status, 'fail')
        self.assertEqual(result.findings[-1].severity, 'error')
        self.assertTrue(any(f.rule == 'critical' for f in result.findings))
        combined = PipelineReport('quality')
        combine(combined, result)
        self.assertEqual(combined.status, 'fail')
        self.assertTrue(any(f.severity == 'error' for f in combined.findings))
        self.assertLessEqual(len(combined.findings), MAX_FINDINGS + 1)

    def test_subcheck_status_is_preserved_even_without_visible_findings(self):
        combined = PipelineReport('quality')
        combine(combined, Report('test', status='fail'))
        combine(combined, Report('other', status='incomplete'))
        self.assertEqual(combined.status, 'fail')

    def test_small_informational_report_still_passes(self):
        result = Report('check')
        result.add('notice', 'Informational', severity='info')
        self.assertEqual(result.status, 'pass')
        self.assertEqual(len(result.findings), 1)
