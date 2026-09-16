import json
from pathlib import Path
import tempfile
import unittest

from ai_pilled.pipeline import PipelineReport
from ai_pilled.runtime import CommandError, Report
from ai_pilled.state import record
from ai_pilled.suggestions import latest_checks, suggest


class SuggestionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.repo = Path(temporary.name)
        self.config = {'aggressiveness': 'strict', 'review_checks_on_commit': True,
                       'commands': {name: ['unexecuted-command'] for name in
                                    ('test', 'lint', 'typecheck', 'deadcode', 'coverage', 'benchmark', 'simplify', 'repair')}}
        self.configure()

    def configure(self):
        (self.repo / '.ai-pilled.json').write_text(json.dumps(self.config))

    def test_complete_configuration_still_requires_current_evidence(self):
        before = (self.repo / '.ai-pilled.json').read_bytes()
        result = suggest(self.repo)
        self.assertEqual(result['suggestions'][0]['id'], 'verify-current-index')
        self.assertIn('no checks', result['evidence'])
        self.assertFalse((self.repo / '.ai-pilled').exists())
        self.assertEqual((self.repo / '.ai-pilled.json').read_bytes(), before)

    def test_failures_prioritize_concrete_checks_before_feature_gaps(self):
        self.config['commands'].pop('typecheck')
        self.configure()
        failed = Report('test')
        failed.add('failed', 'A test failed')
        record(self.repo, failed, 'test')
        result = suggest(self.repo)
        self.assertEqual(result['suggestions'][0]['id'], 'recheck-test')
        self.assertEqual(result['suggestions'][0]['command'], ['python', '-m', 'ai_pilled', '--repo', str(self.repo.resolve()), 'check', 'test'])
        self.assertEqual(result['suggestions'][1]['id'], 'configure-typecheck')
        self.assertIn('may be stale', result['suggestions'][0]['reason'])

    def test_new_aggregate_child_success_supersedes_old_failure(self):
        failed = Report('test', status='fail')
        record(self.repo, failed, 'test')
        newer = PipelineReport('staged-review', checks=[PipelineReport('quality',
                               checks=[Report('test').to_dict()]).to_dict()])
        record(self.repo, newer, 'review')
        self.assertEqual(suggest(self.repo)['suggestions'][0]['id'], 'verify-current-index')

    def test_python_scope_and_optional_feature_configuration_are_suggested(self):
        (self.repo / 'requirements.txt').write_text('example==1.0\n')
        self.config.update(review_checks_on_commit=False, require_tests=False,
                           protected_branches=[], aggressiveness='normal')
        self.config['commands'].pop('benchmark')
        self.config['commands'].pop('repair')
        self.configure()
        ids = {item['id'] for item in suggest(self.repo, 20)['suggestions']}
        self.assertTrue({'configure-python-audit', 'enable-staged-review', 'require-push-tests',
                         'protect-destinations', 'strict-quality-profile',
                         'configure-performance-baseline', 'configure-disposable-refactor'} <= ids)
        self.assertGreater(suggest(self.repo, 1)['omitted'], 0)

    def test_python_rerun_uses_selected_scope_without_shell_execution(self):
        self.config['python_requirements'] = ['requirements-dev.txt']
        self.config['python_audit_executable'] = '$(touch should-not-exist)'
        self.configure()
        record(self.repo, Report('python-dependency-vulnerabilities', status='incomplete'), 'audit')
        item = suggest(self.repo)['suggestions'][0]
        self.assertIn('requirements-dev.txt', item['command'])
        self.assertIn('$(touch should-not-exist)', item['command'])
        self.assertFalse((self.repo / 'should-not-exist').exists())

    def test_unknown_failed_checks_do_not_suggest_replaying_external_actions(self):
        record(self.repo, Report('release-publication', status='fail'), 'release')
        item = suggest(self.repo)['suggestions'][0]
        self.assertEqual(item['command'], ['python', '-m', 'ai_pilled', '--repo', str(self.repo.resolve()), 'summary'])
        self.assertIn('do not replay external actions', item['next'])

    def test_invalid_limits_and_nested_evidence_are_rejected(self):
        for limit in (0, 21, True):
            with self.assertRaises(CommandError):
                suggest(self.repo, limit)
        for report in ({'check': 'quality', 'status': 'pass', 'checks': 'not-a-list'},
                       {'check': 'quality', 'status': 'pass', 'checks': [{}]},
                       {'check': 'unsafe; command', 'status': 'fail'}):
            with self.assertRaises(CommandError):
                latest_checks([{'report': report}])

    def test_output_redacts_sensitive_config_values(self):
        token = 'ghp_' + 'Z' * 36
        self.config.update(python_requirements=['requirements.txt'], python_audit_executable=token)
        self.configure()
        record(self.repo, Report('python-dependency-vulnerabilities', status='fail'), 'audit')
        self.assertFalse(token in json.dumps(suggest(self.repo)))

    def test_commands_bind_selected_repository_even_from_another_directory(self):
        selected = self.repo / 'project with spaces'
        selected.mkdir()
        (selected / '.ai-pilled.json').write_text(json.dumps(self.config))
        item = suggest(selected)['suggestions'][0]
        self.assertEqual(item['command'][3:5], ['--repo', str(selected.resolve())])
        self.assertEqual(item['command'][5:], ['review-checks'])

    def test_performance_followup_preserves_budget_without_replacing_baseline(self):
        record(self.repo, Report('performance-regression', status='fail',
                                metrics={'runs': 5, 'maximum_regression_percent': 12.5}), 'benchmark')
        baseline = self.repo / '.ai-pilled/benchmark.json'
        baseline.write_text('unchanged evidence')
        item = suggest(self.repo)['suggestions'][0]
        self.assertEqual(item['command'][5:], ['benchmark', '--runs', '5', '--maximum-regression', '12.5'])
        self.assertNotIn('--save-baseline', item['command'])
        self.assertEqual(baseline.read_text(), 'unchanged evidence')
        self.config['commands'].pop('benchmark')
        self.configure()
        self.assertEqual(suggest(self.repo)['suggestions'][0]['command'][-1], 'summary')

    def test_invalid_performance_evidence_requires_inspection(self):
        for metrics in ({}, {'runs': True, 'maximum_regression_percent': 20},
                        {'runs': 11, 'maximum_regression_percent': 20},
                        {'runs': 3, 'maximum_regression_percent': -1},
                        {'runs': 3, 'maximum_regression_percent': 10 ** 400},
                        {'runs': 3, 'maximum_regression_percent': 'unsafe argument'}):
            with self.subTest(metrics=metrics):
                record(self.repo, Report('performance-regression', status='fail', metrics=metrics), 'benchmark')
                self.assertEqual(suggest(self.repo)['suggestions'][0]['command'][-1], 'summary')
