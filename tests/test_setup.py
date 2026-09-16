import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parent.parent


class SetupTests(unittest.TestCase):
    def setUp(self):
        clean = patch.dict(os.environ, {k: v for k, v in os.environ.items()
                                       if not k.startswith('GIT_') and k != 'LLM_PROVIDER'}, clear=True)
        clean.start()
        self.addCleanup(clean.stop)
        self.temp = tempfile.TemporaryDirectory(prefix='ai setup ')
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        subprocess.run(['git', 'init', '-q', str(self.repo)], check=True)

    def test_setup_works_from_arbitrary_directory(self):
        result = subprocess.run(['bash', str(SOURCE / 'scripts/setup.sh'), str(self.repo)],
                                cwd=self.repo, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.repo / '.ai-pilled/hooks/pre-push').is_file())
        hooks = json.loads((self.repo / '.codex/hooks.json').read_text())
        self.assertIn('PostToolUse', hooks['hooks'])
        again = subprocess.run(['bash', str(SOURCE / 'scripts/setup.sh'), str(self.repo)],
                               cwd=self.repo, capture_output=True, text=True)
        self.assertEqual(again.returncode, 0, again.stderr)

    def test_unsupported_provider_does_not_mutate_target(self):
        for provider in ['claude', 'generic']:
            result = subprocess.run(['bash', str(SOURCE / f'scripts/configure-{provider}.sh')],
                                    cwd=self.repo, capture_output=True)
            self.assertEqual(result.returncode, 2)
            self.assertFalse((self.repo / '.ai-pilled').exists())

    def test_help_does_not_install(self):
        result = subprocess.run(['bash', str(SOURCE / 'scripts/setup.sh'), '--help'],
                                cwd=self.repo, capture_output=True)
        self.assertEqual(result.returncode, 0)
        self.assertFalse((self.repo / '.ai-pilled').exists())
