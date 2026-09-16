"""Validate bounded cached audit evidence before it can suppress a fresh query."""
from .runtime import Finding, MAX_FINDINGS, Report


def cached_audit(data, check, rule, version, packages=None):
    metrics = data.get('metrics')
    if (data.get('check') != check or not isinstance(metrics, dict)
            or type(metrics.get('evidence_version')) is not int
            or metrics['evidence_version'] != version):
        raise ValueError('Invalid cached audit identity or evidence version')
    count = metrics.get('vulnerabilities')
    if type(count) is not int or count < 0 or data.get('status') != ('fail' if count else 'pass'):
        raise ValueError('Cached audit status contradicts its vulnerability count')
    if packages is not None and (type(metrics.get('packages_audited')) is not int
                                 or metrics['packages_audited'] != len(packages)):
        raise ValueError('Cached audit does not cover the selected packages')
    rows = data.get('findings')
    if not isinstance(rows, list) or len(rows) != min(count, MAX_FINDINGS) + int(count > MAX_FINDINGS):
        raise ValueError('Cached audit findings do not match its vulnerability count')
    findings = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict) or set(row) != {'rule', 'severity', 'message', 'path', 'line'}:
            raise ValueError('Invalid cached audit finding')
        finding = Finding(**row)
        truncated = index == MAX_FINDINGS
        if (finding.rule != ('findings-truncated' if truncated else rule)
                or finding.severity != 'error' or not isinstance(finding.message, str) or not finding.message
                or not isinstance(finding.path, str) or (truncated and finding.path != '')
                or (not truncated and not finding.path)
                or type(finding.line) is not int or finding.line != 0
                or packages is not None and not truncated and finding.path not in packages):
            raise ValueError('Invalid cached audit finding evidence')
        findings.append(finding)
    return Report(check, status=data['status'], findings=findings, snapshot=data['snapshot'], metrics=metrics)
