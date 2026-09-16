"""Foreground daily refactor scheduling with persisted, serialized attempts."""
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
import fcntl
import hashlib
import json
from .json_data import loads
import os
from pathlib import Path
import re
import stat
import time
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .refactor import refactor
from .runtime import CommandError, Report, run
from .state import atomic_json, directory, record


@dataclass
class ScheduledReport(Report):
    action: str = 'not-run'
    scheduled_time: str = ''
    timezone: str = ''
    next_date: str = ''
    result: dict = field(default_factory=dict)


def read_attempt(path, at, zone):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, 'rb') as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise CommandError('Schedule record must be a regular file')
        content = stream.read(16_001)
    if len(content) > 16_000:
        raise CommandError('Schedule record exceeds size limit')
    data = loads(content)
    if (not isinstance(data, dict) or set(data) != {'version', 'date', 'at', 'timezone', 'status', 'patch'}
            or type(data['version']) is not int or data['version'] != 1
            or data['at'] != at or data['timezone'] != zone
            or data['status'] not in ('running', 'pass', 'fail', 'incomplete')
            or not isinstance(data['date'], str) or not isinstance(data['patch'], str)):
        raise CommandError('Invalid schedule record; inspect it before retrying')
    date.fromisoformat(data['date'])
    return data


def nightly_refactor(repo, at='03:00', timezone_name='UTC', retry=False, now=None):
    report = ScheduledReport('nightly-refactor', scheduled_time=at, timezone=timezone_name)
    try:
        if not re.fullmatch(r'(?:[01][0-9]|2[0-3]):[0-5][0-9]', at):
            raise CommandError('Scheduled time must use HH:MM in 24-hour format')
        zone = ZoneInfo(timezone_name)
        current = now or datetime.now(timezone.utc)
        if current.tzinfo is None or current.utcoffset() is None:
            raise CommandError('Scheduling requires an aware clock')
        local = current.astimezone(zone)
        today = local.date()
        report.next_date = today.isoformat()
        root = Path(run(['git', 'rev-parse', '--show-toplevel'], repo).decode().strip())
        run(['git', 'check-ignore', '-q', '--', '.ai-pilled/'], root)
        state = directory(root)
        key = hashlib.sha256((timezone_name + '\0' + at).encode()).hexdigest()[:20]
        path = state / ('nightly-' + key + '.json')
        fd = os.open(state / 'nightly-refactor.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        with os.fdopen(fd, 'rb') as lock:
            if not stat.S_ISREG(os.fstat(lock.fileno()).st_mode):
                raise CommandError('Schedule lock must be a regular file')
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                report.action = 'busy'
                report.add('schedule-busy', 'Another scheduled refactor is running.', severity='warning')
                return report
            previous = read_attempt(path, at, timezone_name)
            hour, minute = map(int, at.split(':'))
            if (local.hour, local.minute) < (hour, minute):
                report.action = 'waiting'
                return report
            if previous and date.fromisoformat(previous['date']) >= today and not retry:
                report.action = 'already-attempted'
                report.next_date = (date.fromisoformat(previous['date']) + timedelta(days=1)).isoformat()
                report.result = {'status': previous['status'], 'patch': previous['patch']}
                if previous['status'] != 'pass':
                    report.add('previous-attempt-unresolved',
                               'Inspect the previous attempt before explicitly retrying; automatic retries are disabled.',
                               severity='warning')
                return report
            attempt = {'version': 1, 'date': today.isoformat(), 'at': at,
                       'timezone': timezone_name, 'status': 'running', 'patch': ''}
            # Reserve the day before work. A crash cannot silently repeat a model-backed command.
            atomic_json(path, attempt)
            result = refactor(root)
            report.action = 'ran'
            report.result = result.to_dict()
            report.status, report.findings = result.status, result.findings
            report.next_date = (today + timedelta(days=1)).isoformat()
            attempt.update(status=result.status, patch=result.patch)
            atomic_json(path, attempt)
            record(root, result, 'nightly-refactor')
    except (CommandError, OSError, ValueError, ZoneInfoNotFoundError) as exc:
        report.add('schedule-unavailable', str(exc) if isinstance(exc, CommandError)
                   else 'Cannot validate the timezone or schedule state; inspect before retrying', severity='warning')
    return report


def watch(repo, at='03:00', timezone_name='UTC'):
    """Run only in the foreground; no daemon, timer, or startup configuration is installed."""
    previous = None
    try:
        while True:
            report = nightly_refactor(repo, at, timezone_name)
            rendered = json.dumps(report.to_dict(), sort_keys=True)
            if rendered != previous:
                print(rendered, flush=True)
                previous = rendered
            if report.action in ('not-run', 'busy'):
                return 2
            time.sleep(60)
    except KeyboardInterrupt:
        return 130
