from concurrent.futures import ThreadPoolExecutor
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from ai_pilled.lifecycle import handle, read_payload
from ai_pilled.runtime import CommandError, Report
from ai_pilled.state import history, record


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        environment = patch.dict(os.environ, {k: v for k, v in os.environ.items()
                                              if not k.startswith('GIT_')}, clear=True)
        environment.start()
        self.addCleanup(environment.stop)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        subprocess.run(['git', 'init', '-q', str(self.repo)], check=True)
        (self.repo / '.gitignore').write_text('.ai-pilled/\n')
        (self.repo / '.ai-pilled.json').write_text(json.dumps({
            'commands': {'test': [sys.executable, '-c', 'raise SystemExit(0)']}}))

    def test_session_start_loads_unborn_repository(self):
        output = handle(self.repo, {'hook_event_name': 'SessionStart'})
        self.assertEqual(output['hookSpecificOutput']['hookEventName'], 'SessionStart')
        self.assertIn('changed_paths', output['hookSpecificOutput']['additionalContext'])

    def test_post_tool_secret_feedback_does_not_echo_credential(self):
        token = 'ghp_' + 'A' * 36
        (self.repo / 'secret').write_text(token)
        output = handle(self.repo, {'hook_event_name': 'PostToolUse',
                                   'tool_response': 'do not store this raw output'})
        self.assertEqual(output['decision'], 'block')
        self.assertNotIn(token, json.dumps(output))
        stored = json.dumps(history(self.repo))
        self.assertNotIn(token, stored)
        self.assertNotIn('do not store', stored)

    def test_stop_checks_tests(self):
        self.assertEqual(handle(self.repo, {'hook_event_name': 'Stop'}),
                         {'systemMessage': 'ai-pilled tests: pass.'})

    def test_stop_does_not_loop_on_missing_test_configuration(self):
        (self.repo / '.ai-pilled.json').unlink()
        self.assertEqual(handle(self.repo, {'hook_event_name': 'Stop'})['decision'], 'block')
        again = handle(self.repo, {'hook_event_name': 'Stop', 'stop_hook_active': True})
        self.assertNotIn('decision', again)

    def test_concurrent_records_remain_valid(self):
        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(lambda i: record(self.repo, Report(str(i)), 'test'), range(30)))
        entries = history(self.repo)
        self.assertEqual(len(entries), 30)
        self.assertEqual(len({e['id'] for e in entries}), 30)

    def test_invalid_or_oversize_payload_rejected(self):
        for payload in ['{', ' ' * 1_000_001]:
            with self.assertRaises(CommandError):
                read_payload(io.StringIO(payload))

    def test_unsupported_event_fails(self):
        with self.assertRaises(CommandError):
            handle(self.repo, {'hook_event_name': 'PostToolBatch'})
