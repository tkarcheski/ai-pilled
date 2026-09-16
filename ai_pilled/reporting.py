"""Summaries and an offline dashboard of recorded check evidence."""
from collections import Counter
import html
import json
import os

from .runtime import CommandError
from .credentials import redact_data
from .state import directory, history

STATUSES = ('pass', 'fail', 'incomplete')


def entries(repo):
    try:
        records = history(repo)
    except (ValueError, OSError) as exc:
        raise CommandError('Cannot read valid local check history') from exc
    for entry in records:
        report = entry.get('report') if isinstance(entry, dict) else None
        if (not isinstance(report, dict) or report.get('status') not in STATUSES
                or not isinstance(report.get('check'), str)
                or not isinstance(report.get('findings'), list)
                or not isinstance(entry.get('at'), str)):
            raise CommandError('Local history contains an invalid check record')
    return redact_data(records)


def summarize(repo):
    records = entries(repo)
    latest = {}
    for entry in records:
        latest[entry['report']['check']] = entry
    blocked = [e['report']['check'] for e in latest.values() if e['report']['status'] != 'pass']
    counts = dict(Counter(e['report']['status'] for e in latest.values()))
    if not records:
        sentence = 'No check results have been recorded.'
        next_step = 'Run the configured checks to gather evidence.'
    elif blocked:
        sentence = f'{len(latest)} latest recorded checks include {len(blocked)} unresolved result(s).'
        next_step = 'Resolve failed or incomplete checks, then rerun them on the current files.'
    else:
        sentence = f'All {len(latest)} latest recorded checks passed.'
        next_step = 'Revalidate the current files before committing or pushing.'
    return {'summary': sentence, 'blocker': 'wait' if blocked or not records else 'proceed',
            'next': next_step, 'counts': counts, 'unresolved': blocked,
            'last_recorded_at': records[-1]['at'] if records else None,
            'evidence': 'Historical results only; this command does not validate current files.',
            'latest': [e for e in latest.values()]}


def dashboard(repo):
    summary = summarize(repo)
    recent = entries(repo)[-100:]
    def escape(value):
        return html.escape(str(value), quote=True)
    cards = ''.join(f'<div class="card {status}"><strong>{summary["counts"].get(status, 0)}</strong>'
                    f'<span>{status}</span></div>' for status in STATUSES)
    rows = []
    for entry in reversed(recent):
        report = entry['report']
        details = json.dumps(report['findings'], ensure_ascii=True)
        metrics = json.dumps(report.get('metrics', {}), ensure_ascii=True)
        rows.append('<tr>' + ''.join(f'<td>{escape(value)}</td>' for value in (
            entry['at'], report['check'], report['status'], metrics, details)) + '</tr>')
    content = '''<!doctype html>
<html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>ai-pilled — check history</title>
<style>
body{font:16px system-ui,sans-serif;background:#101720;color:#e8eef7;max-width:1100px;margin:auto;padding:32px}
h1{font-size:32px;margin-bottom:8px}p{line-height:1.5}.muted{color:#b6c2d3}
.cards{display:flex;gap:16px;flex-wrap:wrap;margin:24px 0}.card{border:1px solid #607083;border-radius:12px;padding:20px;min-width:140px}
.card strong{display:block;font-size:36px}.pass{border-color:#6bd6a0}.fail{border-color:#ff8989}.incomplete{border-color:#f0cb68}
.table{overflow-x:auto}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:12px;border-bottom:1px solid #405166;vertical-align:top}td:last-child{max-width:450px;overflow-wrap:anywhere}th{color:#b6c2d3}
</style>
<h1>ai-pilled check history</h1><p class="muted">Local evidence. No network requests or scripts.</p>
''' + f'<p>{escape(summary["summary"])}</p><p>{escape(summary["evidence"])}</p>' + (
        f'<div class="cards">{cards}</div><p><strong>Next:</strong> {escape(summary["next"])}</p>'
        '<h2>Recent results</h2><p class="muted">Latest 100 recorded runs. Cards count the latest result per check.</p>'
        '<div class="table"><table><thead><tr><th>Recorded</th><th>Check</th><th>Result</th><th>Measurements</th><th>Findings</th>'
        '</tr></thead><tbody>' + ''.join(rows) + '</tbody></table></div></html>')
    path = directory(repo) / 'dashboard.html'
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        stream.write(content)
    return path
