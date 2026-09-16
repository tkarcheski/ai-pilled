import unittest

from ai_pilled.python_security import inspect_python
from ai_pilled.runtime import Report


class PythonPatternTests(unittest.TestCase):
    def inspect(self, code):
        report = Report('patterns')
        inspect_python(report, 'example.py', code.encode())
        return report

    def test_import_aliases_and_call_locations(self):
        report = self.inspect('import pickle as p\nvalue = p.loads(data)\n')
        self.assertEqual(report.status, 'fail')
        self.assertEqual((report.findings[0].rule, report.findings[0].line), ('unsafe-deserialization', 2))

    def test_explicit_tls_bypasses_and_import_aliases_are_blocked(self):
        for source in ('import requests\nrequests.get(url, verify=False)',
                       'import requests as http\nhttp.post(url, verify=False)',
                       'from requests.api import request as send\nsend("GET", url, verify=False)',
                       'from httpx import Client as HTTP\nHTTP(verify=False)',
                       'import httpx\nhttpx.AsyncClient(verify=False)',
                       'import httpx\nhttpx.stream("GET", url, verify=False)'):
            with self.subTest(source=source):
                result = self.inspect(source)
                self.assertEqual(result.status, 'fail')
                self.assertEqual((result.findings[0].rule, result.findings[0].line),
                                 ('tls-verification-disabled', 2))

    def test_verified_tls_and_unrelated_flags_remain_allowed(self):
        for source in ('import requests\nrequests.get(url)',
                       'import requests\nrequests.get(url, verify=True)',
                       'import requests\nrequests.get(url, verify="trusted-ca.pem")',
                       'import httpx\nhttpx.Client(verify=context)',
                       'import ssl\nssl.create_default_context()',
                       'custom_operation(verify=False)',
                       '# requests.get(url, verify=False)\nexample = "httpx.Client(verify=False)"'):
            with self.subTest(source=source):
                self.assertEqual(self.inspect(source).status, 'pass')

    def test_unverified_ssl_context_factory_requires_review(self):
        result = self.inspect('from ssl import _create_unverified_context as context\ncontext()')
        self.assertEqual(result.status, 'fail')
        self.assertEqual(result.findings[0].rule, 'unverified-tls-context')

    def test_safe_yaml_is_distinguished_from_unsafe_load(self):
        for source in ('import yaml\nyaml.safe_load(data)',
                       'from yaml import load, SafeLoader\nload(data, Loader=SafeLoader)',
                       'import yaml\nyaml.load(data, yaml.CSafeLoader)'):
            self.assertEqual(self.inspect(source).status, 'pass')
        self.assertEqual(self.inspect('import yaml\nyaml.load(data)').status, 'fail')

    def test_shell_boolean_and_argument_arrays(self):
        self.assertEqual(self.inspect('import subprocess as s\ns.run(["echo", value])').status, 'pass')
        result = self.inspect('import subprocess as s\ns.run(value, shell=True)')
        self.assertEqual(result.findings[0].rule, 'shell-execution')

    def test_whole_environment_dump_without_flagging_single_nonsecret_lookup(self):
        self.assertEqual(self.inspect('import os\nprint(os.environ.get("HOME"))').status, 'pass')
        for expression in ('os.environ', 'dict(os.environ)', 'os.environ.copy()'):
            result = self.inspect('import os\nlogger.info("%s", ' + expression + ')')
            self.assertEqual(result.findings[0].rule, 'environment-dump')

    def test_comments_and_strings_are_not_executable_patterns(self):
        self.assertEqual(self.inspect('# eval(data)\ntext = "pickle.loads(data)"').status, 'pass')

    def test_weak_hashes_are_review_notices_and_explicit_nonsecurity_use_is_allowed(self):
        result = self.inspect('import hashlib\nhashlib.md5(data)')
        self.assertEqual(result.status, 'pass')
        self.assertEqual(result.findings[0].severity, 'info')
        self.assertFalse(self.inspect('import hashlib\nhashlib.md5(data, usedforsecurity=False)').findings)

    def test_dynamic_code_and_unparseable_files_do_not_pass_strict_inspection(self):
        self.assertEqual(self.inspect('eval(data)').status, 'fail')
        self.assertEqual(self.inspect('def broken(').status, 'incomplete')
        self.assertEqual(self.inspect('# café\nvalue = 1').status, 'pass')

    def test_formatted_and_nested_environment_dumps_are_blocked(self):
        for expression in ('f"environment: {os.environ}"',
                           '"environment: %s" % os.environ',
                           '{"env": dict(os.environ)}', '[os.environ.copy()]'):
            result = self.inspect('import os\nlogger.info(' + expression + ')')
            self.assertEqual(result.status, 'fail', expression)
            self.assertEqual(result.findings[0].rule, 'environment-dump')
        self.assertEqual(self.inspect("import os\nprint(f\"home: {os.environ.get('HOME')}\")").status, 'pass')

    def test_deep_expression_is_inspected_without_recursive_traversal(self):
        for expression, status in (('os.environ', 'fail'), ('"ordinary"', 'pass')):
            code = 'import os\nprint(' + expression + ' + ""' * 1200 + ')'
            with self.subTest(expression=expression):
                result = self.inspect(code)
                self.assertEqual(result.status, status)
                if status == 'fail':
                    self.assertEqual(result.findings[0].rule, 'environment-dump')
