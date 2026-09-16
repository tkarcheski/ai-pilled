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

    def test_nonboolean_stop_guard_cannot_suppress_a_blocking_check(self):
        (self.repo / '.ai-pilled.json').unlink()
        for value in ('false', 'true', 0, 1, None, [], {}):
            with self.subTest(value=value), patch('ai_pilled.lifecycle.command_check') as command:
                with self.assertRaisesRegex(CommandError, 'must be a boolean'):
                    handle(self.repo, {'hook_event_name': 'Stop', 'stop_hook_active': value})
                command.assert_not_called()
        self.assertEqual(handle(self.repo, {'hook_event_name': 'Stop', 'stop_hook_active': False})['decision'], 'block')

    def test_cli_reports_malformed_stop_guard_as_protocol_error(self):
        env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1]),
                   PYTHONDONTWRITEBYTECODE='1')
        result = subprocess.run([sys.executable, '-m', 'ai_pilled', '--repo', str(self.repo), 'lifecycle'],
                                input=json.dumps({'hook_event_name': 'Stop', 'stop_hook_active': 'false'}),
                                text=True, capture_output=True, timeout=5, env=env, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout)['status'], 'error')
        self.assertIn('boolean', json.loads(result.stdout)['message'])

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

    def test_tool_summary_reports_exit_failure_without_replacing_diagnostics(self):
        output = handle(self.repo, {'hook_event_name': 'PostToolUse', 'tool_name': 'Bash',
                                   'tool_response': {'exit_code': 2, 'output': 'private raw output'}})
        context = output['hookSpecificOutput']['additionalContext']
        self.assertIn('"tool_status": "fail"', context)
        self.assertIn('"blocker": "wait"', context)
        self.assertNotIn('private raw output', json.dumps(output))
        self.assertNotIn('decision', output)

    def test_enabled_dependency_changes_are_checked_and_reported(self):
        config = json.loads((self.repo / '.ai-pilled.json').read_text())
        config['audit_dependencies_on_change'] = True
        (self.repo / '.ai-pilled.json').write_text(json.dumps(config))
        (self.repo / 'package.json').write_text('{}')
        failing = Report('dependency-vulnerabilities')
        failing.add('vulnerable', 'Dependency has a known vulnerability')
        with patch('ai_pilled.lifecycle.audit_changed', return_value=(failing, False)) as audit:
            output = handle(self.repo, {'hook_event_name': 'PostToolUse'})
            audit.assert_called_once_with(self.repo)
        self.assertEqual(output['decision'], 'block')
        self.assertIn('dependency-vulnerabilities fail', output['hookSpecificOutput']['additionalContext'])

    def test_dependency_automation_is_opt_in_and_credentials_stop_it(self):
        (self.repo / 'package.json').write_text('{}')
        with patch('ai_pilled.lifecycle.audit_changed') as audit:
            handle(self.repo, {'hook_event_name': 'PostToolUse'})
            audit.assert_not_called()
        config = json.loads((self.repo / '.ai-pilled.json').read_text())
        config['audit_dependencies_on_change'] = True
        (self.repo / '.ai-pilled.json').write_text(json.dumps(config))
        (self.repo / 'secret').write_text('ghp_' + 'A' * 36)
        with patch('ai_pilled.lifecycle.audit_changed') as audit:
            handle(self.repo, {'hook_event_name': 'PostToolUse'})
            audit.assert_not_called()

    def test_unstructured_tool_outcome_is_not_claimed_successful(self):
        output = handle(self.repo, {'hook_event_name': 'PostToolUse', 'tool_response': 'opaque'})
        context = output['hookSpecificOutput']['additionalContext']
        self.assertIn('"tool_status": "unknown"', context)
        self.assertIn('"blocker": "wait"', context)
        self.assertNotIn('decision', output)


    def test_running_process_is_not_reported_as_completed_success(self):
        for response in ({'session_id': 42}, {'session_id': 42, 'exit_code': None, 'isError': False}):
            output = handle(self.repo, {'hook_event_name': 'PostToolUse', 'tool_name': 'exec_command',
                                       'tool_response': response})
            context = output['hookSpecificOutput']['additionalContext']
            self.assertIn('"tool_status": "running"', context)
            self.assertIn('"blocker": "wait"', context)
            self.assertIn('completion result', context)
            self.assertNotIn('finished', context)
            self.assertNotIn('decision', output)

    def test_completion_result_supersedes_session_identifier(self):
        for code, status in ((0, 'pass'), (1, 'fail')):
            output = handle(self.repo, {'hook_event_name': 'PostToolUse', 'tool_name': 'write_stdin',
                                       'tool_response': {'session_id': 42, 'exit_code': code}})
            context = output['hookSpecificOutput']['additionalContext']
            self.assertIn('"tool_status": "' + status + '"', context)


    def test_noncommand_session_creation_can_complete_successfully(self):
        output = handle(self.repo, {'hook_event_name': 'PostToolUse', 'tool_name': 'mcp__service__connect',
                                   'tool_response': {'session_id': 'connection-handle', 'isError': False}})
        context = output['hookSpecificOutput']['additionalContext']
        self.assertIn('"tool_status": "pass"', context)
        self.assertIn('"blocker": "proceed"', context)


    def test_excessively_nested_payload_is_a_protocol_error(self):
        with self.assertRaises(CommandError):
            read_payload(io.StringIO('[' * 1500 + '0' + ']' * 1500))

    def test_configured_python_audit_is_opt_in_and_blocks_on_missing_evidence(self):
        config = json.loads((self.repo / '.ai-pilled.json').read_text())
        config['python_requirements'] = ['requirements.txt']
        (self.repo / '.ai-pilled.json').write_text(json.dumps(config))
        with patch('ai_pilled.lifecycle.audit_python_changed') as audit:
            handle(self.repo, {'hook_event_name': 'PostToolUse'})
            audit.assert_not_called()
        config['audit_dependencies_on_change'] = True
        (self.repo / '.ai-pilled.json').write_text(json.dumps(config))
        result = Report('python-dependency-vulnerabilities')
        result.add('offline', 'No completed audit', severity='warning')
        with patch('ai_pilled.lifecycle.audit_python_changed', return_value=(result, False)) as audit:
            output = handle(self.repo, {'hook_event_name': 'PostToolUse'})
            audit.assert_called_once_with(self.repo)
            self.assertEqual(output['decision'], 'block')
        (self.repo / 'secret').write_text('ghp_' + 'A' * 36)
        with patch('ai_pilled.lifecycle.audit_python_changed') as audit:
            handle(self.repo, {'hook_event_name': 'PostToolUse'})
            audit.assert_not_called()
