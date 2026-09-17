import unittest

from ai_pilled.python_security import inspect_python
from ai_pilled.runtime import Report


class PythonPatternTests(unittest.TestCase):
    def inspect(self, code):
        report = Report('patterns')
        inspect_python(report, 'example.py', code.encode())
        return report

    def test_explicit_unfiltered_tar_extraction_requires_review(self):
        for call in ('tarfile.TarFile.extract', 'tarfile.TarFile.extractall',
                     'tarfile.open(path).extract', 'tarfile.open(path).extractall',
                     'tarfile.TarFile(path).extractall', 'tarfile.TarFile.open(path).extractall'):
            for setting in ('"fully_trusted"', 'tarfile.fully_trusted_filter'):
                with self.subTest(call=call, setting=setting):
                    result = self.inspect('import tarfile\n' + call + '(filter=' + setting + ')')
                    self.assertEqual([(f.rule, f.line) for f in result.findings], [('unsafe-archive-extraction', 2)])
        for source in (
                'from tarfile import TarFile as T\nT.extractall(archive, **{"filter": "fully_trusted"})',
                'from tarfile import open as load, fully_trusted_filter as trust\nload(path).extractall(filter=trust)',
                '__import__("tarfile").open(path).extractall(filter="fully_trusted")',
                'import tarfile\ngetattr(tarfile.TarFile, "extract")(archive, member, filter="fully_trusted")'):
            self.assertEqual(self.inspect(source).status, 'fail')

    def test_tar_filter_defaults_unknown_values_and_expansions_are_incomplete(self):
        for arguments in ('', 'filter=None', 'filter=custom', 'filter="INVALID"',
                          'filter=lambda member, path: member', '**settings',
                          '**{"filter": selected}', 'filter=b"data"'):
            with self.subTest(arguments=arguments):
                result = self.inspect('import tarfile\ntarfile.open(path).extractall(' + arguments + ')')
                self.assertEqual(result.status, 'incomplete')
                self.assertIn('archive-filter-unresolved', [f.rule for f in result.findings])
        result = self.inspect('import tarfile\ntarfile.open(path).extractall(filter="data", **settings)')
        self.assertEqual([f.rule for f in result.findings], ['python-keywords-unresolved'])

    def test_named_restricted_tar_filters_and_unrelated_calls_remain_allowed(self):
        for setting in ('"data"', '"tar"', 'tarfile.data_filter', 'tarfile.tar_filter'):
            self.assertEqual(self.inspect('import tarfile\ntarfile.open(path).extractall(filter=' + setting + ')').status, 'pass')
        for source in (
                'from tarfile import data_filter as restricted, TarFile as T\nT.extract(archive, member, filter=restricted)',
                'import tarfile\ntarfile.open(path).extractall(**{"filter": "fully_trusted", "filter": "data"})',
                'import tarfile\ntarfile.open(path).add(path, filter=callback)',
                'import tarfile\ntarfile.open(path).extractfile(member)',
                'from . import tarfile\ntarfile.open(path).extractall()',
                'import tarfile\ndef local(tarfile):\n tarfile.open(path).extractall()',
                'custom.extractall(filter="fully_trusted")'):
            self.assertEqual(self.inspect(source).status, 'pass')

    def test_conflicting_tar_filter_imports_cannot_certify_extraction(self):
        result = self.inspect('from tarfile import data_filter as policy\n'
                              'from tarfile import fully_trusted_filter as policy\n'
                              'import tarfile\ntarfile.open(path).extractall(filter=policy)')
        self.assertEqual(result.status, 'incomplete')
        self.assertIn('python-import-ambiguous', [f.rule for f in result.findings])

    def test_urllib3_disabled_hostname_matching_requires_review(self):
        calls = ('urllib3.PoolManager', 'urllib3.poolmanager.PoolManager',
                 'urllib3.ProxyManager', 'urllib3.proxy_from_url',
                 'urllib3.HTTPSConnectionPool', 'urllib3.connectionpool.HTTPSConnectionPool',
                 'urllib3.connection.HTTPSConnection')
        for call in calls:
            with self.subTest(call=call):
                result = self.inspect('import urllib3\n' + call + '(assert_hostname=False)')
                self.assertEqual([(f.rule, f.line) for f in result.findings], [('tls-hostname-review', 2)])
                self.assertEqual(result.status, 'incomplete')
        for source in (
                'from urllib3 import PoolManager as P\nP(**{"assert_hostname": False})',
                'import urllib3\ngetattr(urllib3, "PoolManager")(assert_hostname=False)',
                '__import__("urllib3").PoolManager(assert_hostname=False)',
                'import urllib3\nurllib3.PoolManager(assert_hostname=False, assert_fingerprint="pin")'):
            self.assertEqual(self.inspect(source).status, 'incomplete')

    def test_urllib3_proxy_hostname_policy_and_unknown_values(self):
        for call in ('urllib3.ProxyManager', 'urllib3.proxy_from_url',
                     'urllib3.poolmanager.ProxyManager', 'urllib3.poolmanager.proxy_from_url'):
            result = self.inspect('import urllib3\n' + call + '(proxy_assert_hostname=False)')
            self.assertEqual(result.findings[0].rule, 'tls-hostname-review')
        for value in ('selected', 'True', '0', '[]', '""', 'b"host"'):
            result = self.inspect('import urllib3\nurllib3.PoolManager(assert_hostname=' + value + ')')
            self.assertEqual(result.status, 'incomplete')
            self.assertEqual(result.findings[0].rule, 'tls-hostname-unresolved')

    def test_urllib3_hostname_defaults_and_unrelated_calls_remain_allowed(self):
        for arguments in ('', 'assert_hostname=None', 'assert_hostname="host.example"',
                          '**{"assert_hostname": False, "assert_hostname": None}'):
            self.assertEqual(self.inspect('import urllib3\nurllib3.PoolManager(' + arguments + ')').status, 'pass')
        for source in ('custom.PoolManager(assert_hostname=False)',
                       'from . import urllib3\nurllib3.PoolManager(assert_hostname=False)',
                       'import urllib3\ndef f(urllib3):\n urllib3.PoolManager(assert_hostname=False)',
                       'import urllib3\nurllib3.HTTPConnectionPool(assert_hostname=False)'):
            self.assertEqual(self.inspect(source).status, 'pass')

    def test_urllib3_disabled_certificate_requirements(self):
        calls = ('urllib3.PoolManager', 'urllib3.ProxyManager', 'urllib3.proxy_from_url',
                 'urllib3.poolmanager.PoolManager', 'urllib3.HTTPSConnectionPool',
                 'urllib3.connectionpool.HTTPSConnectionPool', 'urllib3.connection.HTTPSConnection',
                 'urllib3.util.create_urllib3_context', 'urllib3.util.ssl_.ssl_wrap_socket')
        for call in calls:
            for value in ('0', 'False', '"NONE"', '"CERT_NONE"', 'ssl.CERT_NONE', 'ssl.VerifyMode.CERT_NONE'):
                with self.subTest(call=call, value=value):
                    result = self.inspect('import urllib3\nimport ssl\n' + call + '(cert_reqs=' + value + ')')
                    self.assertEqual([(f.rule, f.line) for f in result.findings], [('tls-verification-disabled', 3)])
        for code in ('from urllib3 import PoolManager as P\nfrom ssl import CERT_NONE as off\nP(cert_reqs=off)',
                     'import urllib3\nurllib3.PoolManager(**{"cert_reqs": "CERT_NONE"})',
                     'import urllib3\nurllib3.HTTPSConnectionPool(*["host",None,None,1,False,None,None,None,None,None,None,0])',
                     'import urllib3\nurllib3.util.create_urllib3_context(None, 0)',
                     'import urllib3\nurllib3.util.ssl_wrap_socket(sock, None, None, 0)',
                     '__import__("urllib3").PoolManager(cert_reqs="NONE")'):
            self.assertEqual(self.inspect(code).status, 'fail')

    def test_urllib3_defaults_and_verified_modes_remain_allowed(self):
        for args in ('', 'cert_reqs=None', 'cert_reqs=1', 'cert_reqs=2', 'cert_reqs=True',
                     'cert_reqs="REQUIRED"', 'cert_reqs="CERT_REQUIRED"', 'cert_reqs="OPTIONAL"',
                     'cert_reqs=ssl.CERT_REQUIRED', 'cert_reqs=ssl.VerifyMode.CERT_REQUIRED',
                     '**{"cert_reqs": "NONE", "cert_reqs": "REQUIRED"}'):
            with self.subTest(args=args):
                self.assertEqual(self.inspect('import urllib3\nimport ssl\nurllib3.PoolManager(' + args + ')').status, 'pass')
        self.assertEqual(self.inspect('from . import urllib3\nurllib3.PoolManager(cert_reqs=0)').status, 'pass')
        self.assertEqual(self.inspect('import urllib3\ndef local(urllib3):\n urllib3.PoolManager(cert_reqs=0)').status, 'pass')

    def test_urllib3_unknown_certificate_settings_are_incomplete(self):
        for call, args in (('PoolManager', 'cert_reqs=mode'), ('PoolManager', '**settings'),
                           ('PoolManager', 'cert_reqs="INVALID"'), ('PoolManager', 'cert_reqs=[]'),
                           ('HTTPSConnectionPool', '*arguments'), ('util.create_urllib3_context', '*arguments')):
            with self.subTest(call=call, args=args):
                self.assertEqual(self.inspect('import urllib3\nurllib3.' + call + '(' + args + ')').status, 'incomplete')

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

    def test_comprehensions_skip_class_imports_for_body_filters_and_later_iterables(self):
        for expression in ('[parser.loads(data) for data in inputs]',
                           '{parser.loads(data) for data in inputs}',
                           '{data: parser.loads(data) for data in inputs}',
                           '(parser.loads(data) for data in inputs)',
                           '[data for data in inputs if parser.loads(data)]',
                           '[value for data in inputs for value in parser.loads(data)]'):
            with self.subTest(expression=expression):
                result = self.inspect('import pickle as parser\nclass Example:\n import json as parser\n values = ' + expression)
                self.assertEqual([(f.rule, f.line) for f in result.findings], [('unsafe-deserialization', 4)])

    def test_comprehension_first_iterable_uses_containing_class_scope(self):
        result = self.inspect('import pickle as parser\nclass Example:\n import json as parser\n'
                              ' values = [value for value in parser.loads(data)]')
        self.assertEqual(result.status, 'pass')
        result = self.inspect('import json as parser\nclass Example:\n import pickle as parser\n'
                              ' values = [value for value in parser.loads(data)]')
        self.assertEqual([(f.rule, f.line) for f in result.findings], [('unsafe-deserialization', 4)])

    def test_comprehension_targets_shadow_imports_without_leaking_bindings(self):
        for target, values in (('parser', 'handlers'), ('(parser, value)', 'pairs')):
            result = self.inspect('import pickle as parser\nvalues = [parser.loads(data) for ' + target +
                                  ' in ' + values + ']\nparser.loads(data)')
            self.assertEqual([(f.rule, f.line) for f in result.findings], [('unsafe-deserialization', 3)])

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

    def test_requests_falsey_literal_verification_bypasses_are_blocked(self):
        for value in ('0', '0.0', '""', 'b""'):
            with self.subTest(value=value):
                result = self.inspect('from requests import get as fetch\nfetch(url, verify=' + value + ')')
                self.assertEqual([(f.rule, f.line) for f in result.findings], [('tls-verification-disabled', 2)])
        for value in ('None', 'True', '"trusted-ca.pem"'):
            with self.subTest(value=value):
                self.assertEqual(self.inspect('import requests\nrequests.get(url, verify=' + value + ')').status, 'pass')

    def test_verified_tls_and_unrelated_flags_remain_allowed(self):
        for source in ('import requests\nrequests.get(url)',
                       'import requests\nrequests.get(url, verify=True)',
                       'import requests\nrequests.get(url, verify="trusted-ca.pem")',
                       'import ssl\nssl.create_default_context()',
                       'custom_operation(verify=False)',
                       '# requests.get(url, verify=False)\nexample = "httpx.Client(verify=False)"'):
            with self.subTest(source=source):
                self.assertEqual(self.inspect(source).status, 'pass')

    def test_stdlib_unverified_factory_alias_requires_review(self):
        for source in ('import ssl\nssl._create_stdlib_context()',
                       'from ssl import _create_stdlib_context as context\ncontext()',
                       '__import__("ssl")._create_stdlib_context()'):
            result = self.inspect(source)
            self.assertEqual([f.rule for f in result.findings], ['unverified-tls-context'])

    def test_process_wide_https_factory_overrides_require_review(self):
        for source in (
                'import ssl\nssl._create_default_https_context = ssl._create_unverified_context',
                'import ssl as tls\ntls._create_default_https_context: object = tls._create_stdlib_context',
                'import ssl\nfrom ssl import _create_unverified_context as insecure\nssl._create_default_https_context = insecure',
                'import ssl\nsetattr(ssl, "_create_default_https_context", ssl._create_unverified_context)',
                'import builtins, ssl\nbuiltins.setattr(*[ssl, "_create_default_https_context", ssl._create_stdlib_context])',
                'import ssl\nssl._create_default_https_context = getattr(ssl, "_create_unverified_context")'):
            with self.subTest(source=source):
                result = self.inspect(source)
                self.assertEqual([(f.rule, f.line) for f in result.findings],
                                 [('unverified-tls-context', len(source.splitlines()))])

    def test_unknown_https_overrides_cannot_certify_verification(self):
        for source in ('import ssl\nssl._create_default_https_context = custom_factory',
                       'import ssl\nsetattr(ssl, "_create_default_https_context", custom_factory)',
                       'import ssl\nssl._create_default_https_context = None'):
            result = self.inspect(source)
            self.assertEqual(result.status, 'incomplete')
            self.assertEqual([f.rule for f in result.findings], ['tls-default-unresolved'])

    def test_verified_https_restoration_and_unrelated_assignments_remain_allowed(self):
        for source in ('import ssl\nssl._create_default_https_context = ssl.create_default_context',
                       'import ssl\nssl._create_default_https_context = ssl._create_default_https_context',
                       'import ssl\nsetattr(ssl, "_create_default_https_context", ssl.create_default_context)',
                       'import ssl\nssl._create_default_https_context: object',
                       'from ssl import _create_default_https_context, _create_unverified_context\n'
                       '_create_default_https_context = _create_unverified_context',
                       'import ssl\ncustom._create_default_https_context = ssl._create_unverified_context',
                       'import ssl\ndef local(ssl):\n ssl._create_default_https_context = custom_factory'):
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

    def test_environment_dumps_through_serialization_and_literal_formatting(self):
        for expression in ('"environment: {}".format(os.environ)',
                           '"{env}".format(env=os.environ.copy())',
                           '"{env}".format_map({"env": os.environ})',
                           'json.dumps(obj=os.environ.copy())',
                           'str(object=os.environ)', 'tuple(os.environ.values())',
                           'os.environ.values()', 'list(os.environ.items())'):
            with self.subTest(expression=expression):
                result = self.inspect('import os, json\nlogger.info(' + expression + ')')
                self.assertEqual([(f.rule, f.line) for f in result.findings], [('environment-dump', 2)])

    def test_safe_formatted_lookups_and_unrelated_values_remain_allowed(self):
        for expression in ('"home: {}".format(os.environ.get("HOME"))',
                           '"{home}".format_map({"home": os.environ.get("HOME")})',
                           'json.dumps(obj={"home": os.environ.get("HOME")})',
                           'custom.values()', 'str(object="ordinary")'):
            with self.subTest(expression=expression):
                self.assertEqual(self.inspect('import os, json\nprint(' + expression + ')').status, 'pass')

    def test_deep_expression_is_inspected_without_recursive_traversal(self):
        for expression, status in (('os.environ', 'fail'), ('"ordinary"', 'pass')):
            code = 'import os\nprint(' + expression + ' + ""' * 1200 + ')'
            with self.subTest(expression=expression):
                result = self.inspect(code)
                self.assertEqual(result.status, status)
                if status == 'fail':
                    self.assertEqual(result.findings[0].rule, 'environment-dump')

    def test_credential_named_environment_lookups_are_not_loggable(self):
        expressions = ('os.environ["OPENAI_API_KEY"]', 'os.environ.get("DB_PASSWORD")',
                       'os.getenv("GITHUB_TOKEN")', 'os.getenv(key="AWS_ACCESS_KEY_ID")',
                       'os.environb[b"AWS_SECRET_ACCESS_KEY"]', 'os.getenvb(b"SIGNING_PRIVATE_KEY")',
                       'os.environb.get(b"CLIENT_SECRET")', 'os.getenv("SECRET")',
                       'json.dumps({"value": os.getenv("API_KEY")})',
                       "f\"credential: {os.environ.get('API_KEY')}\"")
        for expression in expressions:
            with self.subTest(expression=expression):
                result = self.inspect('import os, json\nlogger.info(' + expression + ')')
                self.assertEqual([(f.rule, f.line) for f in result.findings], [('environment-secret-log', 2)])

    def test_environment_lookup_aliases_and_keyword_log_arguments(self):
        for source in ('from os import getenv as lookup\nprint(lookup("API_KEY"))',
                       'from os import environ as env\nlogger.info(extra={"secret": env["TOKEN"]})',
                       'from os import getenvb as lookup\nprint(lookup(key=b"PASSWORD"))'):
            with self.subTest(source=source):
                self.assertEqual(self.inspect(source).findings[0].rule, 'environment-secret-log')

    def test_environment_mapping_lookup_methods_expose_named_credentials(self):
        for mapping, key in (('os.environ', '"TOKEN"'), ('os.environb', 'b"TOKEN"')):
            for method in ('pop', 'setdefault', '__getitem__'):
                arguments = key + (', "fallback"' if method == 'setdefault' else '')
                for source in (mapping + '.' + method + '(' + arguments + ')',
                               mapping + '.copy().' + method + '(' + arguments + ')'):
                    with self.subTest(source=source):
                        result = self.inspect('import os\nprint(' + source + ')')
                        self.assertEqual([(f.rule, f.line) for f in result.findings], [('environment-secret-log', 2)])
        for source in ('from os import environ as env\nlogger.info(env.pop("API_KEY"))',
                       'import os\nprint(getattr(os.environ, "pop")("TOKEN"))',
                       'import os\nprint(os.environ.__getitem__(**{"key": "PASSWORD"}))'):
            self.assertEqual(self.inspect(source).status, 'fail')

    def test_immediate_environment_copies_keep_mapping_provenance(self):
        for expression in ('os.environ.copy().values()', 'os.environb.copy().items()',
                           'os.environ.copy().copy()'):
            result = self.inspect('import os\nprint(' + expression + ')')
            self.assertEqual(result.findings[0].rule, 'environment-dump')
        for expression in ('os.environ.copy().get("TOKEN")', 'os.environ.copy()["API_KEY"]',
                           'os.environb.copy()[b"PASSWORD"]'):
            result = self.inspect('import os\nprint(' + expression + ')')
            self.assertEqual(result.findings[0].rule, 'environment-secret-log')

    def test_mapping_lookup_fallbacks_are_inspected(self):
        for expression in ('os.environ.pop("HOME", os.getenv("TOKEN"))',
                           'os.environ.pop(key="HOME", default=os.environb)',
                           'os.environ.setdefault("HOME", os.getenv("TOKEN"))',
                           'os.environ.setdefault(key="HOME", value=os.environ)',
                           'os.environ.copy().setdefault("HOME", os.getenv("TOKEN"))'):
            self.assertEqual(self.inspect('import os\nprint(' + expression + ')').status, 'fail')

    def test_mapping_metadata_and_ordinary_lookup_results_remain_allowed(self):
        for expression in ('os.environ.pop("HOME")', 'os.environ.setdefault("HOME", "fallback")',
                           'os.environ.__getitem__("HOME")', 'os.environ.copy()["HOME"]',
                           'os.environ.copy().get("PATH")', 'os.environ.copy().keys()',
                           'len(os.environ.copy())', 'os.environ.__contains__("TOKEN")',
                           'custom.pop("TOKEN")'):
            self.assertEqual(self.inspect('import os\nprint(' + expression + ')').status, 'pass')
        self.assertEqual(self.inspect('import os\nuse(os.environ.pop("TOKEN"))').status, 'pass')

    def test_starred_and_byte_environment_dumps(self):
        for expression in ('*os.environ.values()', 'os.environb', 'os.environb.copy()',
                           '*os.environb.items()', 'dict(os.environb)', '[*os.environ.values()]'):
            with self.subTest(expression=expression):
                self.assertEqual(self.inspect('import os\nprint(' + expression + ')').findings[0].rule,
                                 'environment-dump')

    def test_safe_environment_metadata_and_unrelated_lookups(self):
        for name in ('HOME', 'PATH', 'PASSWORD_MIN_LENGTH', 'TOKEN_COUNT', 'PRIVATE_KEY_PATH', 'CLIENT_ID'):
            with self.subTest(name=name):
                self.assertEqual(self.inspect('import os\nprint(os.getenv(' + repr(name) + '))').status, 'pass')
        for source in ('from . import os\nprint(os.getenv("API_KEY"))',
                       'print(custom.getenv("API_KEY"))', 'import os\nuse(os.getenv("API_KEY"))',
                       'import os\nprint(os.environb.get(b"HOME"))'):
            with self.subTest(source=source):
                self.assertEqual(self.inspect(source).status, 'pass')

    def test_qualified_builtin_print_and_aliases_cannot_hide_environment_leaks(self):
        for source in ('import builtins, os\nbuiltins.print(os.environ)',
                       'from builtins import print as emit\nimport os\nemit(os.getenv("TOKEN"))'):
            with self.subTest(source=source):
                self.assertEqual(self.inspect(source).status, 'fail')

    def test_environment_fallbacks_and_conditional_results_are_inspected(self):
        expressions = ('os.getenv("HOME", os.getenv("TOKEN"))',
                       'os.getenv(key="HOME", default=os.environb)',
                       'os.environ.get("HOME", os.environ)',
                       'os.getenv("API_KEY") if enabled else "ordinary"',
                       '"ordinary" if enabled else os.environ',
                       'os.getenv("HOME") or os.getenv("API_KEY")',
                       '(secret := os.getenv("API_KEY"))')
        for expression in expressions:
            with self.subTest(expression=expression):
                self.assertEqual(self.inspect('import os\nprint(' + expression + ')').status, 'fail')

    def test_condition_only_secret_access_does_not_log_its_value(self):
        for expression in ('"configured" if os.getenv("API_KEY") else "absent"',
                           'bool(os.getenv("API_KEY"))',
                           'os.getenv("HOME", "unknown")'):
            with self.subTest(expression=expression):
                self.assertEqual(self.inspect('import os\nprint(' + expression + ')').status, 'pass')

    def test_direct_unpickler_methods_are_unsafe_deserialization(self):
        for source in ('import pickle\npickle.Unpickler(stream).load()',
                       'from pickle import Unpickler as Parser\nParser(stream).load()',
                       'import _pickle as parser\nparser.Unpickler(stream).load()',
                       'import dill\ndill.Unpickler(stream).load()',
                       'import pickle\npickle.Unpickler.load(instance)',
                       'import _pickle\n_pickle.loads(data)'):
            with self.subTest(source=source):
                self.assertEqual([(f.rule, f.line) for f in self.inspect(source).findings],
                                 [('unsafe-deserialization', 2)])

    def test_unrelated_loaders_and_constructor_only_are_not_unpickling(self):
        for source in ('import pickle\npickle.Unpickler(stream)',
                       'custom.Unpickler(stream).load()',
                       'from . import pickle\npickle.Unpickler(stream).load()',
                       'import pickle\nclass Restricted(pickle.Unpickler):\n pass\nRestricted(stream).load()',
                       'from pickle import Unpickler\ndef inspect(Unpickler):\n return Unpickler(stream).load()'):
            with self.subTest(source=source):
                self.assertEqual(self.inspect(source).status, 'pass')

    def test_direct_requests_sessions_preserve_tls_inspection(self):
        for call in ('requests.Session().get(url, verify=False)',
                     'requests.sessions.Session().request("GET", url, verify=0)',
                     'requests.Session().post(url, verify="")'):
            with self.subTest(call=call):
                self.assertEqual(self.inspect('import requests\n' + call).findings[0].rule,
                                 'tls-verification-disabled')
        source = 'from requests.sessions import Session as Client\nClient().get(url, verify=False)'
        self.assertEqual(self.inspect(source).findings[0].rule, 'tls-verification-disabled')

    def test_direct_session_safe_settings_and_unrelated_constructors(self):
        for source in ('import requests\nrequests.Session().get(url, verify=None)',
                       'import requests\nrequests.Session().get(url, verify=True)',
                       'import requests\nrequests.Session().get(url, verify="ca.pem")',
                       'custom.Session().get(url, verify=False)',
                       'from . import requests\nrequests.Session().get(url, verify=False)'):
            with self.subTest(source=source):
                self.assertEqual(self.inspect(source).status, 'pass')

    def test_safe_yaml_loader_import_paths_are_recognized(self):
        for source in ('from yaml.loader import SafeLoader as Loader\nimport yaml\nyaml.load(data, Loader=Loader)',
                       'from yaml.cyaml import CSafeLoader\nfrom yaml import load_all\nload_all(data, CSafeLoader)',
                       'import yaml.loader\nimport yaml\nyaml.load_all(data, Loader=yaml.loader.SafeLoader)'):
            with self.subTest(source=source):
                self.assertEqual(self.inspect(source).status, 'pass')

    def test_unsafe_or_unrelated_yaml_loader_imports_still_require_review(self):
        for source in ('from yaml.loader import UnsafeLoader as SafeLoader\nimport yaml\nyaml.load(data, Loader=SafeLoader)',
                       'from yaml.cyaml import CLoader\nimport yaml\nyaml.load(data, Loader=CLoader)',
                       'from .yaml.loader import SafeLoader\nimport yaml\nyaml.load(data, Loader=SafeLoader)'):
            with self.subTest(source=source):
                self.assertEqual(self.inspect(source).findings[0].rule, 'unsafe-yaml')

    def test_keyword_hash_algorithm_retains_review_and_nonsecurity_opt_out(self):
        for algorithm in ('md5', 'SHA1'):
            source = 'from hashlib import new as create\ncreate(name=' + repr(algorithm) + ')'
            with self.subTest(algorithm=algorithm):
                result = self.inspect(source)
                self.assertEqual([(f.rule, f.severity) for f in result.findings], [('weak-hash-review', 'info')])
                self.assertEqual(result.status, 'pass')
                self.assertFalse(self.inspect(source[:-1] + ', usedforsecurity=False)').findings)
        self.assertFalse(self.inspect('import hashlib\nhashlib.new(name="sha256")').findings)

    def test_requests_session_factory_retains_tls_checks(self):
        for prefix, constructor in (('import requests', 'requests.session'),
                                    ('import requests.sessions', 'requests.sessions.session'),
                                    ('from requests import session as connect', 'connect')):
            with self.subTest(constructor=constructor):
                self.assertEqual(self.inspect(prefix + '\n' + constructor + '().get(url, verify=False)').findings[0].rule,
                                 'tls-verification-disabled')
                self.assertEqual(self.inspect(prefix + '\n' + constructor + '().get(url, verify=True)').status, 'pass')

    def test_yaml_fallback_imports_require_every_alternative_to_be_safe(self):
        template = ('import yaml\ntry:\n from yaml import CSafeLoader as Loader\n'
                    'except ImportError:\n from yaml import {fallback} as Loader\n'
                    'yaml.load(data, Loader=Loader)')
        self.assertFalse(self.inspect(template.format(fallback='SafeLoader')).findings)
        result = self.inspect(template.format(fallback='Loader'))
        self.assertEqual(result.status, 'fail')
        self.assertIn('unsafe-yaml', [finding.rule for finding in result.findings])

    def test_logger_factories_and_parameters_cannot_hide_environment_leaks(self):
        for source in ('import logging, os\nlogging.getLogger(__name__).info(os.environ)',
                       'import logging, os\nlogging.getLogger().warning(os.getenv("TOKEN"))',
                       'import os\ndef emit(logger):\n logger.info(os.getenv("API_KEY"))',
                       'import logging, os\nlogging.LoggerAdapter(logger, {}).debug(os.environb)'):
            with self.subTest(source=source):
                self.assertEqual(self.inspect(source).status, 'fail')
        safe = 'import logging, os\nlogging.getLogger().info(os.getenv("HOME"))'
        self.assertEqual(self.inspect(safe).status, 'pass')

    def test_literal_keyword_mappings_cannot_hide_security_flags(self):
        cases = (
            ('import requests as http\nhttp.get(url, **{"verify": False})', 'tls-verification-disabled'),
            ('import requests\nrequests.Session().get(url, **{"verify": 0})', 'tls-verification-disabled'),
            ('import httpx\nhttpx.Client(**{"verify": False})', 'tls-verification-disabled'),
            ('import subprocess as sp\nsp.run(command, **{"shell": True})', 'shell-execution'),
            ('import yaml\nyaml.load(data, **{"Loader": yaml.UnsafeLoader})', 'unsafe-yaml'),
            ('import hashlib\nhashlib.new(**{"name": "md5"})', 'weak-hash-review'))
        for source, rule in cases:
            with self.subTest(rule=rule):
                self.assertEqual([f.rule for f in self.inspect(source).findings], [rule])

    def test_literal_keyword_mappings_respect_dictionary_override_order(self):
        for mapping in ('{"verify": True, "verify": False}',
                        '{**{"verify": True}, **{"verify": False}}',
                        '{**{**{"verify": False}}}',
                        '{"verify": True, **{"verify": False}, "timeout": 5}'):
            with self.subTest(mapping=mapping):
                result = self.inspect('import requests\nrequests.get(url, **' + mapping + ')')
                self.assertEqual([f.rule for f in result.findings], ['tls-verification-disabled'])
        for mapping in ('{"verify": False, "verify": True}',
                        '{**{"verify": False}, **{"verify": True}}'):
            with self.subTest(mapping=mapping):
                self.assertFalse(self.inspect('import requests\nrequests.get(url, **' + mapping + ')').findings)

    def test_safe_expanded_settings_and_unrelated_calls_remain_allowed(self):
        for source in ('import yaml\nyaml.load(data, **{"Loader": yaml.SafeLoader})',
                       'import subprocess\nsubprocess.run(args, **{"shell": False})',
                       'import hashlib\nhashlib.new(**{"name": "md5", "usedforsecurity": False})',
                       'import requests\nrequests.get(url, **{})',
                       'custom.get(url, **options)',
                       'from . import requests\nrequests.get(url, **options)'):
            with self.subTest(source=source):
                self.assertFalse(self.inspect(source).findings)

    def test_unresolved_expanded_security_settings_report_incomplete_evidence(self):
        for source in ('import requests\nrequests.get(url, **options)',
                       'import requests\nrequests.get(url, **{key: value})',
                       'import requests\nrequests.get(url, **{"verify": True, **options})',
                       'import subprocess\nsubprocess.Popen(command, **options)',
                       'import hashlib\nhashlib.new(**options)',
                       'import yaml\nyaml.load(data, **{"Loader": yaml.SafeLoader, **options})'):
            with self.subTest(source=source):
                result = self.inspect(source)
                self.assertEqual(result.status, 'incomplete')
                self.assertEqual([f.rule for f in result.findings], ['python-keywords-unresolved'])

    def test_expanded_environment_lookup_keywords_keep_leak_checks(self):
        for expression in ('os.getenv(**{"key": "TOKEN"})',
                           'os.getenv(**{"key": "HOME", "default": os.environ})',
                           'os.getenv(**{**{"key": "HOME"}, "key": "API_KEY"})'):
            with self.subTest(expression=expression):
                self.assertEqual(self.inspect('import os\nprint(' + expression + ')').status, 'fail')
        self.assertFalse(self.inspect('import os\nprint(os.getenv(**{"key": "HOME"}))').findings)

    def test_literal_getattr_retains_security_call_and_environment_checks(self):
        cases = (
            ('import pickle\ngetattr(pickle, "loads")(data)', 'unsafe-deserialization'),
            ('import requests\ngetattr(requests, "get")(url, verify=False)', 'tls-verification-disabled'),
            ('import subprocess\ngetattr(subprocess, "run")(command, shell=True)', 'shell-execution'),
            ('import os\nprint(getattr(os, "environ"))', 'environment-dump'),
            ('import os\nprint(getattr(os, "getenv")("TOKEN"))', 'environment-secret-log'),
            ('import yaml\ngetattr(yaml, "load")(data)', 'unsafe-yaml'),
            ('import hashlib\ngetattr(hashlib, "md5")(data)', 'weak-hash-review'))
        for source, rule in cases:
            with self.subTest(rule=rule):
                result = self.inspect(source)
                self.assertEqual([(f.rule, f.line) for f in result.findings], [(rule, 2)])

    def test_getattr_aliases_nested_attributes_and_safe_calls(self):
        source = ('from builtins import getattr as lookup\nimport requests\n'
                  'lookup(lookup(requests, "api"), "get")(url, verify=False)')
        self.assertEqual([f.rule for f in self.inspect(source).findings], ['tls-verification-disabled'])
        for source in ('import json\ngetattr(json, "loads")(data)',
                       'import requests\ngetattr(requests, "get")(url, verify=True)',
                       'import yaml\nyaml.load(data, Loader=getattr(yaml, "SafeLoader"))',
                       'import pickle\ndef f(getattr):\n return getattr(pickle, "loads")(data)',
                       'from .builtins import getattr\nimport pickle\ngetattr(pickle, "loads")(data)'):
            with self.subTest(source=source):
                self.assertFalse(self.inspect(source).findings)

    def test_wildcard_imports_never_produce_complete_review_evidence(self):
        for source in ('from pickle import *\nloads(data)',
                       'from os import *\nprint(getenv("TOKEN"))',
                       'from math import *\nvalue = sqrt(4)',
                       'from .helpers import *'):
            with self.subTest(source=source):
                result = self.inspect(source)
                self.assertEqual(result.status, 'incomplete')
                self.assertEqual([(f.rule, f.line) for f in result.findings], [('python-wildcard-import', 1)])
        result = self.inspect('from helpers import *\nimport pickle\npickle.loads(data)')
        self.assertEqual(result.status, 'fail')
        self.assertEqual({f.rule for f in result.findings}, {'python-wildcard-import', 'unsafe-deserialization'})

    def test_eager_comprehensions_expose_secret_result_values(self):
        for expression in ('[os.getenv("TOKEN") for _ in items]',
                           '{os.getenv("API_KEY") for _ in items}',
                           '{name: os.getenv("PASSWORD") for name in names}',
                           '{os.getenv("PRIVATE_KEY"): name for name in names}',
                           '[{"value": os.environ.copy()} for _ in items]'):
            with self.subTest(expression=expression):
                result = self.inspect('import os\nprint(' + expression + ')')
                self.assertEqual(result.status, 'fail')
                self.assertIn(result.findings[0].rule, ('environment-secret-log', 'environment-dump'))

    def test_comprehension_controls_and_shadowed_names_are_not_result_values(self):
        for expression in ('[0 for _ in os.environ.values()]',
                           '[0 for _ in items if os.getenv("TOKEN")]',
                           '[os.getenv("HOME") for _ in items]',
                           '[os.getenv("TOKEN") for os in custom_providers]',
                           '{name: os.getenv("HOME") for name in names}'):
            with self.subTest(expression=expression):
                self.assertFalse(self.inspect('import os\nprint(' + expression + ')').findings)

    def test_materialized_generators_and_joined_values_keep_leak_checks(self):
        generator = '(os.getenv("TOKEN") for _ in items)'
        for expression in ('list(' + generator + ')', 'tuple(' + generator + ')',
                           'set(' + generator + ')', '" ".join(' + generator + ')',
                           'str.join(" ", ' + generator + ')',
                           'dict((name, os.getenv("TOKEN")) for name in names)',
                           '" ".join([os.getenv("TOKEN") for _ in items])'):
            with self.subTest(expression=expression):
                self.assertEqual(self.inspect('import os\nprint(' + expression + ')').status, 'fail')
        self.assertEqual(self.inspect('import os\nprint(*' + generator + ')').status, 'fail')
        source = 'from builtins import list as consume\nimport os\nprint(consume(' + generator + '))'
        self.assertEqual(self.inspect(source).status, 'fail')

    def test_generator_objects_and_safe_joined_values_do_not_claim_secret_disclosure(self):
        generator = '(os.getenv("TOKEN") for _ in items)'
        for expression in (generator, 'str(' + generator + ')', 'repr(' + generator + ')',
                           '"{}".format(' + generator + ')', '{"iterator": ' + generator + '}',
                           '" ".join(os.getenv("HOME") for _ in items)'):
            with self.subTest(expression=expression):
                self.assertFalse(self.inspect('import os\nprint(' + expression + ')').findings)

    def test_standard_output_and_error_streams_expose_environment_values(self):
        for expression in ('sys.stdout.write(str(os.environ))',
                           'sys.stderr.writelines([os.getenv("TOKEN")])',
                           'sys.__stdout__.write(os.getenv("API_KEY"))',
                           'sys.__stderr__.buffer.write(os.environb[b"PASSWORD"])',
                           'sys.stdout.buffer.writelines([os.getenvb(b"TOKEN")])',
                           'sys.displayhook(os.getenv("TOKEN"))',
                           'getattr(sys.stdout, "write")(os.getenv("TOKEN"))'):
            with self.subTest(expression=expression):
                result = self.inspect('import sys, os\n' + expression)
                self.assertEqual(result.status, 'fail')
                self.assertIn(result.findings[0].rule, ('environment-dump', 'environment-secret-log'))
        source = 'from sys import stderr as output\nimport os\noutput.write(os.getenv("TOKEN"))'
        self.assertEqual(self.inspect(source).status, 'fail')

    def test_writelines_consumes_generator_values_but_write_does_not(self):
        generator = '(os.getenv("TOKEN") for _ in items)'
        self.assertEqual(self.inspect('import sys, os\nsys.stderr.writelines(' + generator + ')').status, 'fail')
        self.assertFalse(self.inspect('import sys, os\nsys.stderr.write(' + generator + ')').findings)
        self.assertFalse(self.inspect('import sys, os\nsys.displayhook(' + generator + ')').findings)

    def test_warning_and_fatal_logging_aliases_keep_environment_checks(self):
        for source in ('import warnings, os\nwarnings.warn(os.getenv("TOKEN"))',
                       'import warnings, os\nwarnings.warn_explicit(os.getenv("TOKEN"), UserWarning, "file.py", 1)',
                       'from warnings import warn as notice\nimport os\nnotice(os.getenv("TOKEN"))',
                       'import logging, os\nlogging.fatal(os.getenv("API_KEY"))',
                       'import logging, os\nlogging.getLogger().warn(os.environ)',
                       'import os\ndef emit(logger):\n logger.fatal(os.getenv("TOKEN"))'):
            with self.subTest(source=source):
                self.assertEqual(self.inspect(source).status, 'fail')

    def test_standard_stream_checks_respect_safe_keys_and_binding_scope(self):
        for source in ('import sys, os\nsys.stdout.write(os.getenv("HOME"))',
                       'import sys, os\ndef emit(sys):\n sys.stdout.write(os.getenv("TOKEN"))',
                       'from . import sys\nimport os\nsys.stdout.write(os.getenv("TOKEN"))',
                       'import os\ncustom.write(os.getenv("TOKEN"))',
                       'import warnings, os\nwarnings.filterwarnings("ignore", message=os.getenv("TOKEN"))',
                       'import sys, os\nsys.stdout.writelines("public" for _ in items if os.getenv("TOKEN"))'):
            with self.subTest(source=source):
                self.assertFalse(self.inspect(source).findings)

    def test_insecure_temporary_names_and_aliases_require_review(self):
        for source in ('import tempfile\ntempfile.mktemp()',
                       'from tempfile import mktemp as name\nname(suffix=".txt")',
                       'import tempfile as files\ngetattr(files, "mktemp")()'):
            with self.subTest(source=source):
                result = self.inspect(source)
                self.assertEqual([(f.rule, f.line) for f in result.findings], [('insecure-temporary-name', 2)])
        for source in ('import tempfile\ntempfile.mkstemp()',
                       'import tempfile\ntempfile.NamedTemporaryFile(delete=False)',
                       'from . import tempfile\ntempfile.mktemp()',
                       'import tempfile\ndef custom(tempfile): return tempfile.mktemp()'):
            self.assertEqual(self.inspect(source).status, 'pass')

    def test_jwt_signature_bypass_calls_and_aliases(self):
        for source in ('import jwt\njwt.decode(token, options={"verify_signature": False})',
                       'from jwt import decode_complete as decode\ndecode(token, options={"verify_signature": False})',
                       'import jwt.api_jws as jwt\njwt.decode(token, key, algorithms, {"verify_signature": False})',
                       'import jwt\ngetattr(jwt, "decode")(token, **{"options": {**{"verify_signature": False}}})'):
            with self.subTest(source=source):
                result = self.inspect(source)
                self.assertEqual([(f.rule, f.line) for f in result.findings], [('jwt-signature-disabled', 2)])
        for value in ('0', 'None', '""'):
            result = self.inspect('import jwt\njwt.decode(token, options={"verify_signature": ' + value + '})')
            self.assertEqual(result.findings[0].rule, 'jwt-signature-disabled')

    def test_jwt_verified_defaults_literal_overrides_and_unrelated_apis_are_allowed(self):
        for source in ('import jwt\njwt.decode(token, key, algorithms=["RS256"])',
                       'import jwt\njwt.decode(token, options=None)',
                       'import jwt\njwt.decode(token, options={})',
                       'import jwt\njwt.decode(token, options={"verify_signature": False, **{"verify_signature": True}})',
                       'from .vendor import jwt\njwt.decode(token, options={"verify_signature": False})',
                       'import jwt\ndef local(jwt): return jwt.decode(token, options={"verify_signature": False})',
                       'import jwt\njwt.encode(claims, key)'):
            with self.subTest(source=source):
                self.assertEqual(self.inspect(source).status, 'pass')

    def test_jwt_dynamic_options_produce_incomplete_evidence(self):
        for options in ('settings', '{**settings}', '{key: False}', '{"verify_signature": enabled}'):
            with self.subTest(options=options):
                result = self.inspect('import jwt\njwt.decode(token, options=' + options + ')')
                self.assertEqual(result.status, 'incomplete')
                self.assertEqual(result.findings[0].rule, 'jwt-options-unresolved')
        result = self.inspect('import jwt\njwt.decode(token, **settings)')
        self.assertEqual(result.status, 'incomplete')
        self.assertEqual(result.findings[0].rule, 'python-keywords-unresolved')
        result = self.inspect('import jwt\njwt.decode(token, options={"verify_signature": False, **settings})')
        self.assertEqual(result.status, 'fail')
        self.assertEqual({f.rule for f in result.findings}, {'jwt-options-unresolved', 'jwt-signature-disabled'})

    def test_positional_shell_flags_and_literal_argument_expansion(self):
        prefix = 'command, -1, None, None, None, None, None, True, '
        for method in ('Popen', 'run', 'call', 'check_call', 'check_output'):
            for arguments in (prefix + 'True', '*(' + prefix + 'True,)',
                              '*[command, *[-1, None, None, None, None, None, True, True]]'):
                with self.subTest(method=method, arguments=arguments):
                    result = self.inspect('import subprocess as process\nprocess.' + method + '(' + arguments + ')')
                    self.assertEqual([(f.rule, f.line) for f in result.findings], [('shell-execution', 2)])
            for value in ('False', '0', 'None'):
                result = self.inspect('import subprocess\nsubprocess.' + method + '(' + prefix + value + ')')
                self.assertEqual(result.status, 'pass')

    def test_unresolved_positional_security_options_are_incomplete(self):
        for source in ('import subprocess\nsubprocess.Popen(*arguments)',
                       'from subprocess import run as execute\nexecute(command, *arguments)',
                       'import jwt\njwt.decode(token, *arguments)',
                       'import jwt\njwt.decode(*[token, *arguments])'):
            with self.subTest(source=source):
                result = self.inspect(source)
                self.assertEqual(result.status, 'incomplete')
                self.assertEqual(result.findings[0].rule, 'python-arguments-unresolved')
        result = self.inspect('import subprocess\nsubprocess.run(*arguments, shell=True)')
        self.assertEqual(result.status, 'fail')
        self.assertEqual({f.rule for f in result.findings}, {'python-arguments-unresolved', 'shell-execution'})

    def test_literal_positional_jwt_yaml_and_hash_options_are_inspected(self):
        cases = (
            ('import jwt\njwt.decode(*(token, key, algorithms, {"verify_signature": False}))',
             'jwt-signature-disabled'),
            ('import yaml\nyaml.load(*[data, yaml.UnsafeLoader])', 'unsafe-yaml'),
            ('import hashlib\nhashlib.new(*["md5", data])', 'weak-hash-review'))
        for source, rule in cases:
            with self.subTest(source=source):
                result = self.inspect(source)
                self.assertEqual(result.findings[0].rule, rule)
        for source in ('import jwt\njwt.decode(*[token, key, algorithms, {"verify_signature": True}])',
                       'import yaml\nyaml.load(*[data, yaml.SafeLoader])',
                       'import subprocess\nsubprocess.run(*[["echo", value]], shell=False)'):
            self.assertEqual(self.inspect(source).status, 'pass')

    def test_literal_expanded_environment_lookup_keys_are_not_loggable(self):
        for expression in ('os.getenv(*["TOKEN"])', 'os.environ.get(*("API_KEY",))',
                           'os.getenvb(*[b"PASSWORD"])',
                           'str(*[os.getenv(*["TOKEN"])])'):
            with self.subTest(expression=expression):
                result = self.inspect('import os\nprint(' + expression + ')')
                self.assertEqual(result.findings[0].rule, 'environment-secret-log')
        self.assertEqual(self.inspect('import os\nprint(os.getenv(*["HOME"]))').status, 'pass')

    def test_scientific_pickle_loaders_and_aliases_require_review(self):
        for source in ('import joblib\njoblib.load(path)',
                       'from joblib import load as restore\nrestore(path)',
                       'import pandas as pd\npd.read_pickle(path)',
                       'from pandas import read_pickle as restore\nrestore(path)'):
            with self.subTest(source=source):
                result = self.inspect(source)
                self.assertEqual([(f.rule, f.line) for f in result.findings], [('unsafe-deserialization', 2)])

    def test_numpy_pickle_enabled_by_keyword_positional_or_expansion(self):
        for expression in ('np.load(path, allow_pickle=True)',
                           'np.load(path, None, True)',
                           'np.load(*[path, None, True])',
                           'np.load(path, **{"allow_pickle": 1})',
                           'getattr(np, "load")(path, allow_pickle="enabled")'):
            with self.subTest(expression=expression):
                result = self.inspect('import numpy as np\n' + expression)
                self.assertEqual(result.findings[0].rule, 'unsafe-deserialization')
        result = self.inspect('from numpy import load as read\nread(path, allow_pickle=True)')
        self.assertEqual(result.status, 'fail')

    def test_explicit_torch_unrestricted_loading_is_reviewed(self):
        for source in ('import torch\ntorch.load(path, weights_only=False)',
                       'from torch import load as restore\nrestore(path, weights_only=False)',
                       'from torch.serialization import load\nload(path, **{"weights_only": False})',
                       'import torch\ntorch.load(path, weights_only=0)',
                       'import torch\ntorch.load(path, weights_only="")'):
            with self.subTest(source=source):
                result = self.inspect(source)
                self.assertEqual([(f.rule, f.line) for f in result.findings], [('unsafe-deserialization', 2)])

    def test_scientific_loader_defaults_restricted_options_and_unrelated_apis(self):
        for source in ('import numpy as np\nnp.load(path)',
                       'import numpy as np\nnp.load(path, allow_pickle=False)',
                       'import numpy as np\nnp.load(path, None, None)',
                       'import numpy as np\nnp.load(path, **{"allow_pickle": True, "allow_pickle": False})',
                       'import torch\ntorch.load(path, weights_only=True)',
                       'import torch\ntorch.load(path)',
                       'import torch\ntorch.load(path, weights_only=None)',
                       'import pandas as pd\npd.read_csv(path)',
                       'from . import joblib\njoblib.load(path)',
                       'import joblib\ndef local(joblib): return joblib.load(path)'):
            with self.subTest(source=source):
                self.assertEqual(self.inspect(source).status, 'pass')

    def test_scientific_dynamic_pickle_settings_are_incomplete(self):
        for source, rule in (
                ('import numpy as np\nnp.load(path, allow_pickle=enabled)', 'pickle-option-unresolved'),
                ('import numpy as np\nnp.load(path, None, enabled)', 'pickle-option-unresolved'),
                ('import numpy as np\nnp.load(*arguments)', 'python-arguments-unresolved'),
                ('import numpy as np\nnp.load(path, **settings)', 'python-keywords-unresolved'),
                ('import torch\ntorch.load(path, weights_only=restricted)', 'pickle-option-unresolved'),
                ('import torch\ntorch.load(path, **settings)', 'python-keywords-unresolved')):
            with self.subTest(source=source):
                result = self.inspect(source)
                self.assertEqual(result.status, 'incomplete')
                self.assertEqual(result.findings[0].rule, rule)

    def test_dynamic_shell_settings_cannot_silently_pass(self):
        for method in ('run', 'Popen', 'call', 'check_call', 'check_output'):
            for arguments in ('command, shell=enabled', 'command, **{"shell": enabled}',
                              'command, -1, None, None, None, None, None, True, enabled',
                              '*[command, -1, None, None, None, None, None, True, enabled]'):
                with self.subTest(method=method, arguments=arguments):
                    result = self.inspect('import subprocess as process\nprocess.' + method + '(' + arguments + ')')
                    self.assertEqual(result.status, 'incomplete')
                    self.assertEqual([(f.rule, f.line) for f in result.findings], [('shell-option-unresolved', 2)])
        for setting in ('[]', '[True]', 'get_setting()', 'not enabled', 'True if enabled else False'):
            result = self.inspect('from subprocess import run as execute\nexecute(command, shell=' + setting + ')')
            self.assertEqual(result.status, 'incomplete')
        self.assertEqual(self.inspect('custom.run(command, shell=enabled)').status, 'pass')

    def test_dynamic_tls_flags_and_contexts_require_review(self):
        for source in ('import requests\nrequests.get(url, verify=enabled)',
                       'from requests import get as fetch\nfetch(url, verify=ca_path)',
                       'import requests\nrequests.Session().get(url, **{"verify": enabled})',
                       'import httpx\nhttpx.Client(verify=context)',
                       'import httpx\nhttpx.stream("GET", url, verify=create_context())',
                       'import requests\ngetattr(requests, "get")(url, verify=not disabled)'):
            with self.subTest(source=source):
                result = self.inspect(source)
                self.assertEqual(result.status, 'incomplete')
                self.assertEqual([(f.rule, f.line) for f in result.findings], [('tls-option-unresolved', 2)])
        self.assertEqual(self.inspect('custom.get(url, verify=enabled)').status, 'pass')

    def test_unknown_options_do_not_hide_known_unsafe_settings(self):
        result = self.inspect('import subprocess\nsubprocess.run(*arguments, shell=enabled)')
        self.assertEqual(result.status, 'incomplete')
        self.assertEqual({f.rule for f in result.findings}, {'python-arguments-unresolved', 'shell-option-unresolved'})
        result = self.inspect('import requests\nrequests.get(url, **settings, verify=False)')
        self.assertEqual(result.status, 'fail')
        self.assertEqual({f.rule for f in result.findings}, {'python-keywords-unresolved', 'tls-verification-disabled'})

    def test_python_shebang_scripts_receive_pattern_review(self):
        for header in ('#!/usr/bin/python', '#! /usr/bin/python3.14 -I',
                       '#!/usr/bin/env python3', '#!/usr/bin/env -S python3 -I',
                       "#!/usr/bin/env -S 'python3 -I'", '#!/opt/venv/bin/pypy3.10'):
            with self.subTest(header=header):
                report = Report('patterns')
                inspect_python(report, 'bin/entrypoint', (header + '\nimport subprocess\nsubprocess.run(cmd, shell=True)').encode())
                self.assertEqual([(f.rule, f.line) for f in report.findings], [('shell-execution', 3)])

    def test_python_windows_and_stub_extensions_receive_review(self):
        for path in ('app.pyw', 'types.pyi'):
            report = Report('patterns')
            inspect_python(report, path, b'import pickle\npickle.loads(data)')
            self.assertEqual(report.findings[0].rule, 'unsafe-deserialization')

    def test_other_interpreters_and_shebang_mentions_are_not_python(self):
        for source in ('#!/bin/sh\necho python3', '#!/usr/bin/env notpython3\neval(data)',
                       '#!/usr/bin/python3-config\neval(data)',
                       '# docs\n#!/usr/bin/env python3\neval(data)', 'eval(data)'):
            report = Report('patterns')
            inspect_python(report, 'notes', source.encode())
            self.assertEqual(report.status, 'pass')

    def test_literal_runtime_imports_cannot_hide_known_unsafe_calls(self):
        for source, rule in (
                ('__import__("pickle").loads(data)', 'unsafe-deserialization'),
                ('import builtins\nbuiltins.__import__("subprocess").run(command, shell=True)', 'shell-execution'),
                ('from builtins import __import__ as load\nload("requests").get(url, verify=False)', 'tls-verification-disabled'),
                ('import importlib as loader\nloader.import_module("pickle").loads(data)', 'unsafe-deserialization'),
                ('from importlib import import_module as load\nload(name="subprocess").getoutput(command)', 'shell-execution'),
                ('import importlib\nimportlib.__import__("pickle").loads(data)', 'unsafe-deserialization'),
                ('getattr(__import__("pickle"), "loads")(data)', 'unsafe-deserialization'),
                ('print(__import__("os").getenv("TOKEN"))', 'environment-secret-log')):
            with self.subTest(source=source):
                result = self.inspect(source)
                self.assertEqual(result.status, 'fail')
                self.assertEqual([f.rule for f in result.findings], [rule])

    def test_runtime_imports_distinguish_top_level_and_full_module_results(self):
        for expression in ('__import__("requests.api").get(url, verify=False)',
                           '__import__("requests.api", fromlist=["get"]).get(url, verify=False)',
                           '__import__("requests.api", {}, {}, ("get",), 0).get(url, verify=False)',
                           '__import__("requests.api", fromlist=[]).get(url, verify=False)',
                           'importlib.import_module("requests.api").get(url, verify=False)'):
            result = self.inspect('import importlib\n' + expression)
            self.assertEqual([f.rule for f in result.findings], ['tls-verification-disabled'])
        for expression in ('__import__("vendor.pickle").loads(data)',
                           '__import__("vendor.pickle", fromlist=["loads"]).loads(data)',
                           'importlib.import_module("vendor.pickle").loads(data)'):
            self.assertEqual(self.inspect('import importlib\n' + expression).status, 'pass')

    def test_literal_runtime_import_argument_expansions_are_inspected(self):
        for expression in ('__import__(*["pickle"]).loads(data)',
                           '__import__(**{"name": "pickle"}).loads(data)',
                           'importlib.import_module(*("pickle",)).loads(data)',
                           '__import__("requests.api", **{"fromlist": ["get"], "level": 0}).get(url, verify=False)'):
            result = self.inspect('import importlib\n' + expression)
            self.assertEqual(result.status, 'fail')
            self.assertNotIn('python-import-unresolved', [f.rule for f in result.findings])

    def test_dynamic_relative_and_unknown_runtime_import_options_are_incomplete(self):
        for expression in ('__import__(module).loads(data)', '__import__("pick" + "le").loads(data)',
                           '__import__("pickle", fromlist=names).loads(data)',
                           '__import__("pickle", level=1).loads(data)',
                           '__import__("pickle", level=level).loads(data)',
                           '__import__("pickle", **options).loads(data)',
                           '__import__(*arguments).loads(data)',
                           'importlib.import_module(".pickle", "vendor").loads(data)',
                           'importlib.import_module(module).loads(data)',
                           '__import__("pickle", fromlist=[*names]).loads(data)'):
            with self.subTest(expression=expression):
                result = self.inspect('import importlib\n' + expression)
                self.assertEqual(result.status, 'incomplete')
                self.assertEqual([f.rule for f in result.findings], ['python-import-unresolved'])

    def test_safe_runtime_imports_shadowed_names_and_relative_helpers_are_allowed(self):
        for source in ('__import__("json").loads(data)',
                       'import importlib\nimportlib.import_module("json").loads(data)',
                       'def local(__import__): return __import__("pickle").loads(data)',
                       'from .vendor import importlib\nimportlib.import_module("pickle").loads(data)',
                       '__import__("yaml").load(data, Loader=__import__("yaml").SafeLoader)'):
            with self.subTest(source=source):
                self.assertEqual(self.inspect(source).status, 'pass')

    def test_import_result_identity_matches_documented_fromlist_semantics(self):
        import ast
        from ai_pilled.python_security import literal_import
        cases = (
            ('__import__("urllib.parse")', '__import__', 'urllib'),
            ('__import__("urllib.parse", fromlist=[])', '__import__', 'urllib'),
            ('__import__("urllib.parse", fromlist=None)', '__import__', 'urllib'),
            ('__import__("urllib.parse", fromlist=["urlparse"])', '__import__', 'urllib.parse'),
            ('__import__("urllib.parse", {}, {}, ("urlparse",), 0)', '__import__', 'urllib.parse'),
            ('loader("urllib.parse")', 'importlib.import_module', 'urllib.parse'),
        )
        for source, function, expected in cases:
            with self.subTest(source=source):
                self.assertEqual(literal_import(ast.parse(source, mode='eval').body, function), expected)

    def test_explicit_shell_command_vectors_require_review(self):
        for expression in ('subprocess.run(["sh", "-c", command])',
                           'subprocess.Popen(["/bin/bash", "-lc", command])',
                           'subprocess.check_output(args=("dash", "-c", command))',
                           'subprocess.call(["zsh", "-c", command], shell=False)',
                           'subprocess.run([b"/bin/sh", b"-c", command])',
                           'subprocess.run(["bash", "--norc", "-O", "extglob", "-c", command])',
                           'subprocess.run(["bash", "--rcfile", config, "-c", command])',
                           'subprocess.run(["sh", *["-c", command]])',
                           '__import__("subprocess").run(["sh", "-c", command])'):
            with self.subTest(expression=expression):
                result = self.inspect('import subprocess\n' + expression)
                self.assertEqual([f.rule for f in result.findings], ['shell-execution'])
        result = self.inspect('from subprocess import run as execute\nexecute(["sh", "-c", command])')
        self.assertEqual(result.status, 'fail')

    def test_async_shell_commands_and_executable_overrides_are_reviewed(self):
        for source in ('import asyncio\nasyncio.create_subprocess_exec("sh", "-c", command)',
                       'from asyncio.subprocess import create_subprocess_exec as execute\nexecute("bash", "-lc", command)',
                       'import subprocess\nsubprocess.run(["display", "-c", command], executable="/bin/sh")',
                       'import subprocess\nsubprocess.Popen(["display", "-c", command], -1, "/bin/bash")',
                       'import asyncio\nasyncio.create_subprocess_exec("display", "-c", command, executable="sh")'):
            result = self.inspect(source)
            self.assertEqual([f.rule for f in result.findings], ['shell-execution'])

    def test_shell_script_separator_and_non_shell_vectors_are_allowed(self):
        for expression in ('subprocess.run(["sh", "--", script, "-c", command])',
                           'subprocess.run(["bash", "script.sh", "-c", command])',
                           'subprocess.run(["bash", "--version"])',
                           'subprocess.run(["bash", "-o", "errexit", "script.sh", "-c", command])',
                           'subprocess.run(["python", "-c", code])',
                           'subprocess.run(["echo", "sh", "-c", command])',
                           'subprocess.run(["display", "-c", command], executable="python")',
                           'subprocess.run(command)',
                           'custom.run(["sh", "-c", command])'):
            with self.subTest(expression=expression):
                self.assertEqual(self.inspect('import subprocess\n' + expression).status, 'pass')

    def test_known_shell_with_unknown_options_produces_incomplete_evidence(self):
        for expression in ('subprocess.run(["sh", flags, command])',
                           'subprocess.run(["sh", *arguments])',
                           'subprocess.run(["bash", "--unknown-option", command])',
                           'subprocess.run(["bash", "-O", *arguments])',
                           'subprocess.run(["bash", "-o"])',
                           'subprocess.run(["sh", "-c", command], executable=selected)'):
            result = self.inspect('import subprocess\n' + expression)
            self.assertEqual(result.status, 'incomplete')
            self.assertEqual([f.rule for f in result.findings], ['shell-command-unresolved'])
        result = self.inspect('import asyncio\nasyncio.create_subprocess_exec(*arguments)')
        self.assertEqual(result.status, 'incomplete')
        self.assertEqual([f.rule for f in result.findings], ['python-arguments-unresolved'])
