"""Shared commit subject conventions for local commits and outgoing history."""
import re


def check_subject(report, subject):
    if not re.fullmatch(r'(feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)'
                        r'(\([^()\r\n]+\))?!?: \S.*', subject):
        report.add('conventional-commit', 'Use type(scope): subject, for example fix: handle empty input.',
                   path='(commit message)', line=1)
    if len(subject) > 72:
        report.add('subject-length', 'Keep the commit subject at 72 characters or fewer.',
                   path='(commit message)', line=1)
