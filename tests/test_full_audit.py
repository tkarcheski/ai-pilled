import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from ai_pilled.full_audit import full_audit
from ai_pilled.runtime import CommandError


class FullAuditTests(unittest.TestCase):
    def setUp(self):
        clean = patch.dict(os.environ, {k: v for k, v in os.environ.items()
                                       if not k.startswith('GIT_')}, clear=True)
        clean.start()
        self.addCleanup(clean.stop)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.repo = Path(temporary.name)
        self.git('init', '-q', '-b', 'feature')
        self.git('config', 'user.name', 'Test')
        self.git('config', 'user.email', 'test@example.invalid')
        (self.repo / '.gitignore').write_text('.ai-pilled/\n')
        (self.repo / 'code.py').write_text('value = 1\n')
        (self.repo / '.ai-pilled.json').write_text(json.dumps({'aggressiveness': 'lazy',
            'commands': {name: [sys.executable, '-c', 'pass']
                         for name in ('test', 'lint', 'typecheck', 'deadcode', 'coverage')}}))
        self.git('add', '.gitignore', 'code.py', '.ai-pilled.json')
        self.git('commit', '-qm', 'test: audit fixture')

    def git(self, *args):
        return subprocess.run(['git', *args], cwd=self.repo, check=True, capture_output=True).stdout

    def test_default_runs_quality_without_model(self):
        with patch('ai_pilled.full_audit.invoke_review') as model:
            result = full_audit(self.repo)
        self.assertEqual(result.status, 'pass', result.to_dict())
        self.assertEqual(result.metrics['model_reviews_run'], 0)
        model.assert_not_called()

    def test_lazy_profile_cannot_skip_comprehensive_gates(self):
        config = self.repo / '.ai-pilled.json'
        data = json.loads(config.read_text())
        data['commands'].pop('lint')
        config.write_text(json.dumps(data))
        with patch('ai_pilled.full_audit.invoke_review') as model:
            result = full_audit(self.repo, model_reviews=True)
        self.assertEqual(result.status, 'incomplete')
        self.assertTrue(any(f.rule.endswith('not-configured') for f in result.findings))
        model.assert_not_called()

    def test_commit_between_quality_and_review_invalidates_prior_checks(self):
        from ai_pilled.pipeline import quality
        for empty in (False, True):
            with self.subTest(empty=empty):
                def changed(repo, empty_commit=empty, **kwargs):
                    result = quality(repo, **kwargs)
                    if not empty_commit:
                        (self.repo / 'code.py').write_text('value = 2\n')
                        self.git('add', 'code.py')
                    self.git('commit', '--allow-empty', '-qm', 'fix: replacement after checks')
                    return result
                with patch('ai_pilled.full_audit.quality', side_effect=changed), \
                        patch('ai_pilled.full_audit.invoke_review') as model:
                    result = full_audit(self.repo, model_reviews=True)
                self.assertEqual(result.status, 'incomplete')
                self.assertIn('HEAD changed', result.findings[-1].message)
                model.assert_not_called()

    def test_hidden_worktree_changes_cannot_use_different_reviewed_source(self):
        for flag, clear in (('--assume-unchanged', '--no-assume-unchanged'),
                            ('--skip-worktree', '--no-skip-worktree')):
            with self.subTest(flag=flag):
                self.git('update-index', flag, 'code.py')
                (self.repo / 'code.py').write_text('value = 2\n')
                self.assertEqual(self.git('status', '--porcelain'), b'')
                with patch('ai_pilled.full_audit.invoke_review') as model:
                    result = full_audit(self.repo, model_reviews=True)
                self.assertEqual(result.status, 'incomplete')
                model.assert_not_called()
                self.git('update-index', clear, 'code.py')
                (self.repo / 'code.py').write_text('value = 1\n')

    def test_hidden_change_during_review_invalidates_completed_result(self):
        def model(*_):
            self.git('update-index', '--assume-unchanged', 'code.py')
            (self.repo / 'code.py').write_text('value = 3\n')
            return []
        with patch('ai_pilled.full_audit.invoke_review', side_effect=model):
            result = full_audit(self.repo, model_reviews=True, workers=1)
        self.assertEqual(result.status, 'incomplete')
        self.assertEqual(result.findings[-1].rule, 'snapshot-changed')

    def test_three_perspectives_run_concurrently_in_distinct_snapshots(self):
        barrier = threading.Barrier(3)
        paths = []
        def model(snapshot, prompt, executable, timeout):
            paths.append(snapshot)
            self.assertEqual((snapshot / 'code.py').read_text(), 'value = 1\n')
            self.assertFalse((snapshot / '.git').exists())
            self.assertIn(b'untrusted', prompt)
            barrier.wait(timeout=3)
            return []
        with patch('ai_pilled.full_audit.invoke_review', side_effect=model):
            result = full_audit(self.repo, model_reviews=True)
        self.assertEqual(result.status, 'pass', result.to_dict())
        self.assertEqual(result.metrics['model_reviews_run'], 3)
        self.assertEqual(len(set(paths)), 3)
        self.assertTrue(all(not path.exists() for path in paths))
        self.assertEqual(self.git('status', '--porcelain'), b'')

    def test_findings_and_unavailable_workers_are_preserved(self):
        def model(snapshot, *_):
            if snapshot.name == 'security':
                raise CommandError('Provider unavailable')
            return [('code.py', 1, 'Concrete defect')] if snapshot.name == 'correctness' else []
        with patch('ai_pilled.full_audit.invoke_review', side_effect=model):
            result = full_audit(self.repo, model_reviews=True, workers=1)
        self.assertEqual(result.status, 'fail')
        self.assertEqual([check['status'] for check in result.checks], ['pass', 'fail', 'incomplete', 'pass'])

    def test_model_cannot_cite_missing_source(self):
        with patch('ai_pilled.full_audit.invoke_review', return_value=[('missing.py', 1, 'Defect')]):
            result = full_audit(self.repo, model_reviews=True)
        self.assertEqual(result.status, 'incomplete')
        self.assertIn('outside the supplied source', result.findings[0].message)

    def test_dirty_source_blocks_inference(self):
        (self.repo / 'code.py').write_text('value = 2\n')
        with patch('ai_pilled.full_audit.invoke_review') as model:
            result = full_audit(self.repo, model_reviews=True)
        self.assertEqual(result.status, 'incomplete')
        model.assert_not_called()

    def test_failed_checks_block_inference(self):
        config = self.repo / '.ai-pilled.json'
        config.write_text(json.dumps({'commands': {'test': [sys.executable, '-c', 'raise SystemExit(1)']}}))
        with patch('ai_pilled.full_audit.invoke_review') as model:
            result = full_audit(self.repo, model_reviews=True)
        self.assertEqual(result.status, 'fail')
        model.assert_not_called()

    def test_source_change_invalidates_model_result(self):
        def model(*_):
            (self.repo / 'code.py').write_text('value = 3\n')
            return []
        with patch('ai_pilled.full_audit.invoke_review', side_effect=model):
            result = full_audit(self.repo, model_reviews=True, workers=1)
        self.assertEqual(result.status, 'incomplete')
        self.assertEqual(result.findings[-1].rule, 'snapshot-changed')
