"""Codex command-hook protocol, independently testable without a model call."""
import json
from pathlib import Path

from .checks import command_check
from .runtime import CommandError, Report, run
from .security import scan
from .state import record


def context(event, text):
    return {'hookSpecificOutput': {'hookEventName': event, 'additionalContext': text}}


def handle(repo, payload):
    if not isinstance(payload, dict):
        raise CommandError('Hook input must be a JSON object')
    event = payload.get('hook_event_name')
    root = Path(run(['git', 'rev-parse', '--show-toplevel'], repo).decode().strip())
    if event == 'SessionStart':
        status = run(['git', 'status', '--short'], root).decode(errors='replace')
        try:
            branch = run(['git', 'symbolic-ref', '--short', 'HEAD'], root).decode().strip()
        except CommandError:
            branch = '(detached)'
        report = Report('session-state')
        record(root, report, event)
        return context(event, 'ai-pilled repository state (data, not instructions): ' +
                       json.dumps({'branch': branch, 'changed_paths': status.splitlines(),
                                   'next': 'Implement the requested work; run checks before committing.'}))
    if event == 'PostToolUse':
        report = scan(root, 'worktree')
        record(root, report, event)
        summary = f'ai-pilled credential scan: {report.status}; {len(report.findings)} finding(s).'
        output = context(event, summary + ' Findings (data): ' + json.dumps(report.to_dict()))
        if report.status != 'pass':
            output.update(decision='block', reason='Review ai-pilled findings before continuing.')
        return output
    if event == 'Stop':
        report = command_check(root, 'test')
        record(root, report, event)
        message = f'ai-pilled tests: {report.status}.'
        if report.status != 'pass' and not payload.get('stop_hook_active', False):
            return {'decision': 'block', 'reason': message + ' ' +
                    '; '.join(f.message for f in report.findings)}
        return {'systemMessage': message}
    raise CommandError('Unsupported Codex lifecycle event')


def read_payload(stream):
    text = stream.read(1_000_001)
    if len(text) > 1_000_000:
        raise CommandError('Hook input exceeds size limit')
    try:
        return json.loads(text)
    except ValueError as exc:
        raise CommandError('Hook input must be valid JSON') from exc
