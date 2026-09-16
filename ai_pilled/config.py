"""Strict project configuration; commands are argument lists, never shell strings."""
from dataclasses import dataclass, field
import json
from pathlib import Path


class ConfigError(ValueError):
    pass


@dataclass
class Config:
    commands: dict[str, list[str]] = field(default_factory=dict)
    protected_branches: list[str] = field(default_factory=lambda: ['main', 'master'])
    timeout: int = 120
    require_tests: bool = True
    aggressiveness: str = 'normal'
    review_on_commit: bool = False
    codex_executable: str = 'codex'


def load(repo):
    path = Path(repo) / '.ai-pilled.json'
    if not path.exists():
        return Config()
    try:
        data = json.loads(path.read_text())
    except (ValueError, OSError) as exc:
        raise ConfigError('Cannot read valid JSON from .ai-pilled.json') from exc
    allowed = {'version', 'commands', 'protected_branches', 'timeout',
               'require_tests', 'aggressiveness', 'review_on_commit', 'codex_executable'}
    if not isinstance(data, dict) or set(data) - allowed:
        raise ConfigError('Configuration must be an object with supported keys')
    if type(data.get('version', 1)) is not int or data.get('version', 1) != 1:
        raise ConfigError('Configuration version must be 1')
    commands = data.get('commands', {})
    if not isinstance(commands, dict):
        raise ConfigError('commands must map check names to argument lists')
    for name, args in commands.items():
        if name not in {'test', 'lint', 'typecheck', 'deadcode', 'coverage', 'dependency', 'benchmark'}:
            raise ConfigError('Unknown command check name')
        if not isinstance(args, list) or not args or any(
                not isinstance(a, str) or '\0' in a for a in args) or not args[0]:
            raise ConfigError('Each command must be a nonempty argument list')
    branches = data.get('protected_branches', ['main', 'master'])
    if not isinstance(branches, list) or any(not isinstance(b, str) or not b for b in branches):
        raise ConfigError('protected_branches must be a list of nonempty branch names')
    timeout = data.get('timeout', 120)
    if type(timeout) is not int or not 1 <= timeout <= 3600:
        raise ConfigError('timeout must be an integer between 1 and 3600 seconds')
    require_tests = data.get('require_tests', True)
    if type(require_tests) is not bool:
        raise ConfigError('require_tests must be boolean')
    aggressiveness = data.get('aggressiveness', 'normal')
    if aggressiveness not in ('lazy', 'normal', 'strict'):
        raise ConfigError('aggressiveness must be lazy, normal, or strict')
    review_on_commit = data.get('review_on_commit', False)
    if type(review_on_commit) is not bool:
        raise ConfigError('review_on_commit must be boolean')
    executable = data.get('codex_executable', 'codex')
    if not isinstance(executable, str) or not executable or '\0' in executable:
        raise ConfigError('codex_executable must be a nonempty executable path or command name')
    return Config(commands, branches, timeout, require_tests, aggressiveness, review_on_commit, executable)
