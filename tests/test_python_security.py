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

    def test_unrelated_nested_import_cannot_hide_outer_tls_call(self):
        result = self.inspect('import requests as http\nhttp.get(url, verify=False)\n'
                              'def unrelated():\n import json as http\n return http.dumps({})\n')
        self.assertEqual([(f.rule, f.line) for f in result.findings], [('tls-verification-disabled', 2)])

    def test_sibling_function_aliases_are_inspected_independently(self):
        result = self.inspect('def unsafe(data):\n import pickle as parser\n return parser.loads(data)\n'
                              'def safe(data):\n import json as parser\n return parser.loads(data)\n')
        self.assertEqual([(f.rule, f.line) for f in result.findings], [('unsafe-deserialization', 3)])

    def test_relative_imports_are_not_mistaken_for_public_packages(self):
        for source in ('from . import pickle\npickle.loads(data)',
                       'from .vendor import requests\nrequests.get(url, verify=False)'):
            self.assertEqual(self.inspect(source).status, 'pass')

    def test_methods_inherit_outer_imports_instead_of_class_aliases(self):
        result = self.inspect('import pickle as parser\nclass Example:\n import json as parser\n'
                              ' value = parser.loads(data)\n def unsafe(self, data):\n  return parser.loads(data)')
        self.assertEqual([(f.rule, f.line) for f in result.findings], [('unsafe-deserialization', 6)])

    def test_defaults_and_nested_closures_keep_their_import_scope(self):
        result = self.inspect('import pickle as parser\ndef outer(value=parser.loads(data)):\n'
                              ' import json as parser\n def inner():\n  return parser.loads(data)\n')
        self.assertEqual([(f.rule, f.line) for f in result.findings], [('unsafe-deserialization', 2)])
        result = self.inspect('def outer():\n import pickle as parser\n'
                              ' return lambda data: parser.loads(data)')
        self.assertEqual(result.findings[0].rule, 'unsafe-deserialization')

    def test_parameters_shadow_imports_and_conflicting_imports_are_incomplete(self):
        self.assertEqual(self.inspect('import pickle as parser\n'
                                      'def local(parser):\n return parser.loads(data)').status, 'pass')
        result = self.inspect('import pickle as parser\nimport json as parser\nparser.loads(data)')
        self.assertEqual(result.status, 'incomplete')
        self.assertEqual(result.findings[0].rule, 'python-import-ambiguous')

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

    def test_implicit_shell_entry_points_are_blocked_through_aliases(self):
        for source in ('import subprocess\nsubprocess.getoutput(command)',
                       'from subprocess import getstatusoutput as output\noutput(command)',
                       'import os as system\nsystem.popen(command)',
                       'import asyncio\nasyncio.create_subprocess_shell(command)',
                       'from asyncio.subprocess import create_subprocess_shell as launch\nlaunch(command)'):
            with self.subTest(source=source):
                result = self.inspect(source)
                self.assertEqual([(f.rule, f.line) for f in result.findings], [('shell-execution', 2)])

    def test_literal_truthy_shell_flags_cannot_hide_shell_execution(self):
        for value in ('True', '1', '"enabled"'):
            result = self.inspect('import subprocess\nsubprocess.run(command, shell=' + value + ')')
            self.assertEqual(result.status, 'fail')
        for source in ('import subprocess\nsubprocess.run(["echo", value], shell=False)',
                       'import subprocess\nsubprocess.run(["echo", value], shell=0)',
                       'import asyncio\nasyncio.create_subprocess_exec("echo", value)',
                       'custom.getoutput(command)'):
            self.assertEqual(self.inspect(source).status, 'pass')

    def test_unsafe_yaml_variants_and_missing_safe_multi_document_loader_are_blocked(self):
        for source in ('import yaml\nyaml.unsafe_load(data)',
                       'from yaml import unsafe_load_all as load\nload(data)',
                       'import yaml\nyaml.load_all(data)',
                       'from yaml import load_all, UnsafeLoader\nload_all(data, Loader=UnsafeLoader)'):
            with self.subTest(source=source):
                result = self.inspect(source)
                self.assertEqual([(f.rule, f.line) for f in result.findings], [('unsafe-yaml', 2)])

    def test_safe_yaml_multi_document_and_unrelated_loaders_are_allowed(self):
        for source in ('import yaml\nyaml.safe_load_all(data)',
                       'from yaml import load_all, SafeLoader\nload_all(data, Loader=SafeLoader)',
                       'import yaml\nyaml.load_all(data, yaml.CSafeLoader)',
                       'from . import yaml\nyaml.unsafe_load(data)',
                       'custom.unsafe_load(data)',
                       '# yaml.unsafe_load(data)\nexample = "subprocess.getoutput(command)"'):
            with self.subTest(source=source):
                self.assertEqual(self.inspect(source).status, 'pass')

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
