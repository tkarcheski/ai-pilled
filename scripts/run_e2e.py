"""Run the same end-to-end workflows locally and in CI; retain bounded evidence."""
import io
import json
from pathlib import Path
import sys
import time
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ai_pilled.credentials import redact  # noqa: E402
from ai_pilled.runtime import Report  # noqa: E402
from ai_pilled.state import atomic_text, directory, record  # noqa: E402


def test_ids(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from test_ids(item)
        else:
            yield item.id()


def main():
    suite = unittest.defaultTestLoader.discover(str(ROOT / 'tests'), pattern='test_e2e.py')
    names = list(test_ids(suite))
    started = time.monotonic()
    stream = io.StringIO()
    result = unittest.TextTestRunner(stream=stream, verbosity=0).run(suite)
    report = Report('end-to-end')
    report.metrics = {'tests_run': result.testsRun, 'failures': len(result.failures),
                      'errors': len(result.errors), 'skipped': len(result.skipped),
                      'seconds': round(time.monotonic() - started, 3)}
    failures = result.failures + result.errors
    for test, _ in failures:
        report.add('e2e-failed', 'Rerun this test locally for diagnostic details.', path=test.id())
    if not result.testsRun or result.skipped:
        report.add('e2e-incomplete', 'All end-to-end scenarios must run without skips.', severity='warning')
    state = directory(ROOT)
    record(ROOT, report, 'end-to-end')
    atomic_text(state / 'e2e.json', json.dumps(report.to_dict(), indent=2) + '\n')
    xml = ET.Element('testsuite', name='ai-pilled-e2e', tests=str(result.testsRun),
                     failures=str(len(result.failures)), errors=str(len(result.errors)),
                     skipped=str(len(result.skipped)), time=str(report.metrics['seconds']))
    # Only named outcomes are exported; raw process transcripts never enter artifacts.
    failed = {test.id() for test, _ in result.failures}
    errored = {test.id() for test, _ in result.errors}
    skipped = {test.id() for test, _ in result.skipped}
    for name in names:
        case = ET.SubElement(xml, 'testcase', name=name, classname='EndToEndTests')
        if name in failed:
            ET.SubElement(case, 'failure', message='Scenario failed')
        elif name in errored:
            ET.SubElement(case, 'error', message='Scenario raised an error')
        elif name in skipped:
            ET.SubElement(case, 'skipped')
    atomic_text(state / 'e2e.xml', ET.tostring(xml, encoding='unicode') + '\n')
    print(json.dumps(report.to_dict(), indent=2))
    if not result.wasSuccessful():
        print(redact(stream.getvalue())[-12000:], file=sys.stderr)
    return {'pass': 0, 'fail': 1, 'incomplete': 2}[report.status]


if __name__ == '__main__':
    sys.exit(main())
