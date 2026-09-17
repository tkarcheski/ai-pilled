"""Conservative Python AST patterns; these are review signals, not exploit proofs."""
import ast
import re
import warnings


IMPORT_CALLS = {'__import__', 'builtins.__import__', 'importlib.__import__', 'importlib.import_module'}


TLS_VERIFY_CALLS = {
    module + '.' + method
    for module in ('requests', 'requests.api', 'httpx')
    for method in ('request', 'get', 'post', 'put', 'patch', 'delete', 'head', 'options')
} | {'httpx.Client', 'httpx.AsyncClient', 'httpx.stream'}
# Positional cert_reqs locations exclude self; None denotes keyword-only forwarding.
CERT_REQUIREMENT_CALLS = {
    **{prefix + name: None for prefix in ('urllib3.', 'urllib3.poolmanager.')
       for name in ('PoolManager', 'ProxyManager', 'proxy_from_url')},
    'urllib3.HTTPSConnectionPool': 11,
    'urllib3.connectionpool.HTTPSConnectionPool': 11,
    'urllib3.connection.HTTPSConnection': None,
    **{prefix + 'create_urllib3_context': 1 for prefix in ('urllib3.util.', 'urllib3.util.ssl_.')},
    **{prefix + 'ssl_wrap_socket': 3 for prefix in ('urllib3.util.', 'urllib3.util.ssl_.')},
}
# Explicit keywords only: positional hostname locations vary across urllib3 releases.
HOSTNAME_OPTIONS = {
    name: ('assert_hostname', 'proxy_assert_hostname')
    if name.endswith(('ProxyManager', 'proxy_from_url')) else ('assert_hostname',)
    for name in CERT_REQUIREMENT_CALLS if not name.startswith('urllib3.util.')
}
CERT_MODES = {'ssl.CERT_NONE': 0, 'ssl.CERT_OPTIONAL': 1, 'ssl.CERT_REQUIRED': 2,
              'ssl.VerifyMode.CERT_NONE': 0, 'ssl.VerifyMode.CERT_OPTIONAL': 1,
              'ssl.VerifyMode.CERT_REQUIRED': 2}


UNVERIFIED_TLS_FACTORIES = {'ssl._create_unverified_context', 'ssl._create_stdlib_context'}


IMPLICIT_SHELL_CALLS = {'os.system', 'os.popen', 'subprocess.getoutput',
                        'subprocess.getstatusoutput', 'asyncio.create_subprocess_shell',
                        'asyncio.subprocess.create_subprocess_shell'}

STANDARD_OUTPUT_CALLS = {
    'sys.' + stream + layer + '.' + method
    for stream in ('stdout', 'stderr', '__stdout__', '__stderr__')
    for layer in ('', '.buffer')
    for method in ('write', 'writelines')
} | {'sys.displayhook', 'warnings.warn_explicit'}

JWT_DECODE_CALLS = {module + '.' + method
                    for module in ('jwt', 'jwt.api_jwt', 'jwt.api_jws')
                    for method in ('decode', 'decode_complete')}

SHELL_KEYWORD_CALLS = {'subprocess.run', 'subprocess.Popen', 'subprocess.call',
                       'subprocess.check_call', 'subprocess.check_output'}
PICKLE_OPTION_CALLS: dict[str, tuple[str, int | None, bool]] = {
    'numpy.load': ('allow_pickle', 2, True),
    'torch.load': ('weights_only', None, False),
    'torch.serialization.load': ('weights_only', None, False),
}
TAR_EXTRACT_CALLS = {'tarfile.TarFile.extract', 'tarfile.TarFile.extractall'}
TAR_CONSTRUCTORS = {'tarfile.open', 'tarfile.TarFile', 'tarfile.TarFile.open'}
TAR_FILTERS = {'tarfile.data_filter': 'data', 'tarfile.tar_filter': 'tar',
               'tarfile.fully_trusted_filter': 'fully_trusted'}
ASYNC_EXEC_CALLS = {'asyncio.create_subprocess_exec', 'asyncio.subprocess.create_subprocess_exec'}
SHELL_PROGRAMS = {'sh', 'bash', 'dash', 'ksh', 'zsh'}
POSITIONAL_SECURITY_CALLS = SHELL_KEYWORD_CALLS | ASYNC_EXEC_CALLS | JWT_DECODE_CALLS | {'numpy.load'} | {
    name for name, position in CERT_REQUIREMENT_CALLS.items() if position is not None}
KEYWORD_SECURITY_CALLS = TLS_VERIFY_CALLS | set(CERT_REQUIREMENT_CALLS) | POSITIONAL_SECURITY_CALLS | set(PICKLE_OPTION_CALLS) | TAR_EXTRACT_CALLS | {
    'yaml.load', 'yaml.load_all', 'hashlib.new', 'hashlib.md5', 'hashlib.sha1'}

ENVIRONMENT_MAPPINGS = ('os.environ', 'os.environb')
ENVIRONMENT_COPIES = {name + '.copy' for name in ENVIRONMENT_MAPPINGS}
ENVIRONMENT_DUMPS = {name + '.' + method for name in ENVIRONMENT_MAPPINGS
                     for method in ('copy', 'items', 'values')}
ENVIRONMENT_LOOKUPS = {name + '.' + method for name in ENVIRONMENT_MAPPINGS
                       for method in ('get', 'pop', 'setdefault', '__getitem__')} | {'os.getenv', 'os.getenvb'}

SAFE_YAML_LOADERS = {'yaml.SafeLoader', 'yaml.CSafeLoader',
                     'yaml.loader.SafeLoader', 'yaml.cyaml.CSafeLoader'}


PYTHON_SHEBANG = re.compile(
    rb"(?:^|[ \t/\"'])(?:python|pypy)(?:[23](?:\.[0-9]+)?)?(?=[ \t\r\"']|$)")


def is_python_source(path, content):
    """Recognize source extensions and Python-identifying interpreter lines."""
    if path.endswith(('.py', '.pyw', '.pyi')):
        return True
    if not content.startswith(b'#!'):
        return False
    return PYTHON_SHEBANG.search(content.split(b'\n', 1)[0][2:]) is not None


def parse_python(content, path):
    # Compiler warnings can print the original source line, including credentials.
    # Syntax failures still propagate to the caller's incomplete-evidence handling.
    with warnings.catch_warnings():
        warnings.simplefilter('ignore')
        return ast.parse(content, filename=path)


def import_scopes(tree):
    """Index import bindings by lexical block without recursive AST traversal.

    This resolves imports, not general assignment or runtime object data flow.
    Conflicting imports remain ambiguous rather than silently overwriting evidence.
    """
    scopes = {}
    bindings: list[dict[str, set[str]]] = [{}]
    parents: list[int | None] = [None]
    kinds = ['module']
    pending = [(tree, 0)]
    while pending:
        node, scope = pending.pop()
        scopes[node] = scope
        comprehension = isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp))
        if comprehension or isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            parent = scope
            while kinds[parent] == 'class':
                enclosing = parents[parent]
                if enclosing is None:
                    break
                parent = enclosing
            child = len(bindings)
            local: dict[str, set[str]] = {}
            if comprehension:
                for generator in node.generators:
                    for bound_node in ast.walk(generator.target):
                        if isinstance(bound_node, ast.Name):
                            local[bound_node.id] = {''}
            elif not isinstance(node, ast.ClassDef):
                arguments = node.args
                for argument in [*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs,
                                 *([arguments.vararg] if arguments.vararg else []),
                                 *([arguments.kwarg] if arguments.kwarg else [])]:
                    local[argument.arg] = {''}
            bindings.append(local)
            parents.append(parent)
            kinds.append('class' if isinstance(node, ast.ClassDef) else 'function')
            if comprehension:
                # Only the leftmost iterable runs in the containing (possibly class) scope.
                for item in ast.iter_child_nodes(node):
                    if isinstance(item, ast.comprehension):
                        scopes[item] = child
                        pending.append((item.target, child))
                        pending.append((item.iter, scope if item is node.generators[0] else child))
                        pending.extend((condition, child) for condition in item.ifs)
                    else:
                        pending.append((item, child))
                continue
            # Defaults, decorators, and bases are evaluated in the containing scope.
            for field, value in ast.iter_fields(node):
                selected = child if field == 'body' else scope
                for item in value if isinstance(value, list) else [value]:
                    if isinstance(item, ast.AST):
                        pending.append((item, selected))
            continue
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                if isinstance(node, ast.Import):
                    name = alias.asname or alias.name.split('.')[0]
                    target = alias.name if alias.asname else alias.name.split('.')[0]
                else:
                    name = alias.asname or alias.name
                    prefix = '.' * node.level + (node.module + '.' if node.module else '')
                    target = prefix + alias.name
                bindings[scope].setdefault(name, set()).add(target)
        pending.extend((child, scope) for child in ast.iter_child_nodes(node))
    return scopes, bindings, parents


def expand_arguments(arguments):
    """Expand only literal starred lists/tuples; never evaluate argument expressions."""
    if not any(isinstance(argument, ast.Starred) for argument in arguments):
        return arguments
    result = []
    pending = list(reversed(arguments))
    while pending:
        argument = pending.pop()
        if isinstance(argument, ast.Starred) and isinstance(argument.value, (ast.List, ast.Tuple)):
            pending.extend(reversed(argument.value.elts))
        else:
            result.append(argument)
    return result


def call_arguments(node):
    return expand_arguments(node.args)


def literal_text(node):
    if not isinstance(node, ast.Constant):
        return None
    if isinstance(node.value, bytes):
        return node.value.decode('latin-1')
    return node.value if isinstance(node.value, str) else None


def direct_shell_command(name, arguments, keywords):
    """Inspect literal POSIX shell argument vectors, keeping unknown flags incomplete."""
    options = {keyword.arg: keyword.value for keyword in keywords}
    if name in SHELL_KEYWORD_CALLS:
        selected = options.get('args', arguments[0] if arguments else None)
        if isinstance(selected, (ast.List, ast.Tuple)):
            values = expand_arguments(selected.elts)
        elif literal_text(selected) is not None:
            values = [selected]
        else:
            return False
        executable = options.get('executable', arguments[2] if len(arguments) > 2 else None)
    elif name in ASYNC_EXEC_CALLS:
        values = arguments
        executable = options.get('executable')
    else:
        return False
    if not values:
        return False
    program = literal_text(values[0])
    if executable is not None and not (isinstance(executable, ast.Constant) and executable.value is None):
        replacement = literal_text(executable)
        if replacement is None:
            return None if program and program.rsplit('/', 1)[-1] in SHELL_PROGRAMS else False
        program = replacement
    if program is None or program.rsplit('/', 1)[-1] not in SHELL_PROGRAMS:
        return False
    # A standalone noninteractive -n parses stdin without executing commands.
    if len(values) == 2 and literal_text(values[1]) == '-n':
        return False
    supplied_input = options.get('input') if name in ('subprocess.run', 'subprocess.check_output') else None
    input_script = supplied_input is not None and not (
        isinstance(supplied_input, ast.Constant) and supplied_input.value is None)
    stdin_mode = False
    index = 1
    while index < len(values):
        flag = literal_text(values[index])
        if flag is None:
            return None
        if flag in ('--help', '--version'):
            return False
        if flag in ('-', '--'):
            return input_script and (stdin_mode or index + 1 == len(values))
        if not flag.startswith(('-', '+')):
            return input_script and stdin_mode
        if flag in ('--rcfile', '--init-file', '-o', '-O', '+o', '+O'):
            if index + 1 >= len(values) or isinstance(values[index + 1], ast.Starred):
                return None
            index += 2
            continue
        if flag.startswith('--'):
            if flag not in ('--noprofile', '--norc', '--posix', '--login', '--restricted', '--verbose', '--debugger'):
                return None
        elif flag.startswith('++'):
            return None
        elif 'c' in flag[1:]:
            return True if flag.startswith('-') else None
        else:
            if 's' in flag[1:]:
                stdin_mode = flag.startswith('-')
            if flag.endswith(('o', 'O')):
                if index + 1 >= len(values) or isinstance(values[index + 1], ast.Starred):
                    return None
                index += 2
                continue
        index += 1
    return input_script


def mapping_keywords(value):
    """Expand one literal mapping; preserve unknown entries and last-key wins."""
    if not isinstance(value, ast.Dict):
        return [ast.keyword(arg=None, value=value)]
    values = {}
    unknown = []
    pending = list(reversed(list(zip(value.keys, value.values, strict=True))))
    while pending:
        key, item = pending.pop()
        if key is None and isinstance(item, ast.Dict):
            pending.extend(reversed(list(zip(item.keys, item.values, strict=True))))
        elif isinstance(key, ast.Constant) and isinstance(key.value, str):
            values[key.value] = item
        else:
            unknown.append(ast.keyword(arg=None, value=item))
    return [*(ast.keyword(arg=key, value=item) for key, item in values.items()), *unknown]


def call_keywords(node):
    """Expand literal mappings without evaluating source; preserve unknown entries."""
    result = []
    for keyword in node.keywords:
        if keyword.arg is not None:
            result.append(keyword)
        else:
            result.extend(mapping_keywords(keyword.value))
    return result


def literal_import(node, function):
    """Resolve literal absolute import results without loading any source modules."""
    arguments, keywords = call_arguments(node), call_keywords(node)
    if (any(isinstance(argument, ast.Starred) for argument in arguments)
            or any(keyword.arg is None for keyword in keywords)):
        return None
    options = {keyword.arg: keyword.value for keyword in keywords}
    module = options.get('name', arguments[0] if arguments else None)
    if (not isinstance(module, ast.Constant) or not isinstance(module.value, str)
            or not all(part.isidentifier() for part in module.value.split('.'))):
        return None
    if function == 'importlib.import_module':
        return module.value
    level = options.get('level', arguments[4] if len(arguments) > 4 else None)
    if level is not None and not (isinstance(level, ast.Constant)
            and isinstance(level.value, int) and level.value == 0):
        return None
    fromlist = options.get('fromlist', arguments[3] if len(arguments) > 3 else None)
    if fromlist is None:
        full_name = False
    elif isinstance(fromlist, ast.Constant):
        full_name = bool(fromlist.value)
    elif isinstance(fromlist, (ast.List, ast.Tuple)) and not any(
            isinstance(item, ast.Starred) for item in fromlist.elts):
        full_name = bool(fromlist.elts)
    else:
        return None
    return module.value if full_name else module.value.split('.')[0]


def inspect_python(report, path, content, *, tree=None):
    if not is_python_source(path, content):
        return
    try:
        if tree is None:
            tree = parse_python(content, path)
    except (SyntaxError, ValueError, RecursionError):
        report.add('python-unparsed', 'Python syntax could not be inspected by this interpreter.',
                   path=path, severity='warning')
        return
    scopes, bindings, parents = import_scopes(tree)
    ambiguous = set()

    def qualified(node, accepted=(), *, resolve_calls=True):
        attributes = []
        while True:
            if isinstance(node, ast.Attribute):
                attributes.append(node.attr)
                node = node.value
            elif (resolve_calls and isinstance(node, ast.Call) and len(node.args) in (2, 3) and not node.keywords
                  and isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str)
                  and qualified(node.func, resolve_calls=False) in ('getattr', 'builtins.getattr')):
                attributes.append(node.args[1].value)
                node = node.args[0]
            elif resolve_calls and isinstance(node, ast.Call):
                importer = qualified(node.func, resolve_calls=False)
                if importer in IMPORT_CALLS:
                    module = literal_import(node, importer)
                    return '.'.join([module, *reversed(attributes)]) if module else ''
                break
            else:
                break
        if not isinstance(node, ast.Name):
            return ''
        base = node.id
        scope = scopes[node]
        while scope is not None:
            if base in bindings[scope]:
                candidates = bindings[scope][base]
                if len(candidates) != 1:
                    alternatives = {'.'.join([candidate, *reversed(attributes)]) if candidate else ''
                                    for candidate in candidates}
                    if accepted and all(target in accepted for target in alternatives):
                        return min(alternatives)
                    key = (scope, base)
                    if key not in ambiguous:
                        ambiguous.add(key)
                        report.add('python-import-ambiguous',
                                   'Conflicting imports prevent reliable call inspection; use distinct aliases.',
                                   path=path, line=node.lineno, severity='warning')
                    return ''
                base = next(iter(candidates))
                break
            scope = parents[scope]
        return '.'.join([base, *reversed(attributes)]) if base else ''

    def credential_key(node):
        if not isinstance(node, ast.Constant):
            return False
        value = node.value
        if isinstance(value, bytes):
            value = value.decode('ascii', errors='replace')
        if not isinstance(value, str):
            return False
        value = value.upper()
        return value in ('AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY') or any(
            value == suffix or value.endswith('_' + suffix)
            for suffix in ('TOKEN', 'SECRET', 'PASSWORD', 'API_KEY', 'PRIVATE_KEY'))

    def environment_mapping(node):
        name = qualified(node)
        if name in ENVIRONMENT_MAPPINGS:
            return name
        if isinstance(node, ast.Call):
            constructor = qualified(node.func)
            if constructor in ENVIRONMENT_COPIES:
                return constructor.rsplit('.', 1)[0]
        return ''

    def environment_dump(node):
        pending = [node]
        while pending:
            value = pending.pop()
            if isinstance(value, ast.JoinedStr):
                pending.extend(value.values)
            elif isinstance(value, ast.FormattedValue):
                pending.append(value.value)
            elif isinstance(value, ast.Starred):
                pending.append(value.value.elt if isinstance(value.value, ast.GeneratorExp) else value.value)
            elif isinstance(value, ast.IfExp):
                pending.extend((value.body, value.orelse))
            elif isinstance(value, ast.BoolOp):
                pending.extend(value.values)
            elif isinstance(value, ast.NamedExpr):
                pending.append(value.value)
            elif isinstance(value, ast.BinOp):
                pending.extend((value.left, value.right))
            elif isinstance(value, (ast.ListComp, ast.SetComp)):
                pending.append(value.elt)
            elif isinstance(value, ast.DictComp):
                pending.extend((value.key, value.value))
            elif isinstance(value, (ast.List, ast.Tuple, ast.Set)):
                pending.extend(value.elts)
            elif isinstance(value, ast.Dict):
                pending.extend(value.keys)
                pending.extend(value.values)
            elif environment_mapping(value):
                return 'environment-dump'
            elif (isinstance(value, ast.Subscript)
                  and environment_mapping(value.value)
                  and credential_key(value.slice)):
                return 'environment-secret-log'
            elif isinstance(value, ast.Call):
                function = qualified(value.func)
                if isinstance(value.func, ast.Attribute):
                    mapping = environment_mapping(value.func.value)
                    if mapping:
                        function = mapping + '.' + value.func.attr
                arguments = call_arguments(value)
                if function.startswith('builtins.'):
                    function = function[len('builtins.'):]
                if function in ENVIRONMENT_DUMPS:
                    return 'environment-dump'
                if function in ENVIRONMENT_LOOKUPS:
                    lookup_keywords = call_keywords(value)
                    key = arguments[0] if arguments else next(
                        (keyword.value for keyword in lookup_keywords if keyword.arg == 'key'), None)
                    if credential_key(key):
                        return 'environment-secret-log'
                    pending.extend(arguments[1:])
                    fallback = 'value' if function.endswith('.setdefault') else 'default'
                    pending.extend(keyword.value for keyword in lookup_keywords if keyword.arg == fallback)
                literal_method = (value.func.attr if isinstance(value.func, ast.Attribute)
                                  and isinstance(value.func.value, ast.Constant)
                                  and isinstance(value.func.value.value, str) else '')
                if (function in ('dict', 'str', 'repr', 'list', 'tuple', 'set', 'json.dumps', 'str.join')
                        or literal_method in ('format', 'format_map', 'join')):
                    consumes = (function in ('dict', 'list', 'tuple', 'set', 'str.join')
                                or literal_method == 'join')
                    pending.extend(arg.elt if consumes and isinstance(arg, ast.GeneratorExp) else arg
                                   for arg in arguments)
                    pending.extend(keyword.value for keyword in value.keywords)
        return None

    def https_factory_override(factory, line):
        selected = qualified(factory)
        if selected in UNVERIFIED_TLS_FACTORIES:
            report.add('unverified-tls-context',
                       'The process-wide HTTPS default uses an unverified factory; restore verified defaults.',
                       path=path, line=line)
        elif selected not in ('ssl.create_default_context', 'ssl._create_default_https_context'):
            report.add('tls-default-unresolved',
                       'The replacement HTTPS default factory cannot be inspected; verify its certificate and hostname policy.',
                       path=path, line=line, severity='warning')

    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and any(alias.name == '*' for alias in node.names):
            report.add('python-wildcard-import',
                       'Wildcard imports prevent reliable binding inspection; use explicit imports.',
                       path=path, line=node.lineno, severity='warning')
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(isinstance(target, ast.Attribute) and target.attr == '_create_default_https_context'
                   and qualified(target) == 'ssl._create_default_https_context' for target in targets):
                https_factory_override(node.value, node.lineno)
        if not isinstance(node, ast.Call):
            continue
        name = qualified(node.func)
        if name in IMPORT_CALLS and literal_import(node, name) is None:
            report.add('python-import-unresolved',
                       'Runtime import target cannot be inspected; use an explicit absolute module and import options.',
                       path=path, line=node.lineno, severity='warning')
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Call):
            constructor = qualified(node.func.value.func)
            if constructor in ('requests.Session', 'requests.sessions.Session',
                               'requests.session', 'requests.sessions.session'):
                name = 'requests.' + node.func.attr
            elif constructor in TAR_CONSTRUCTORS and node.func.attr in ('extract', 'extractall'):
                name = 'tarfile.TarFile.' + node.func.attr
            elif constructor in ('pickle.Unpickler', '_pickle.Unpickler', 'dill.Unpickler') and node.func.attr == 'load':
                name = 'pickle.load'
        keywords = call_keywords(node)
        arguments = call_arguments(node)
        if (name in ('setattr', 'builtins.setattr') and len(arguments) == 3 and not node.keywords
                and qualified(arguments[0]) == 'ssl' and isinstance(arguments[1], ast.Constant)
                and arguments[1].value == '_create_default_https_context'):
            https_factory_override(arguments[2], node.lineno)
        unknown_arguments = any(isinstance(argument, ast.Starred) for argument in arguments)
        if name in POSITIONAL_SECURITY_CALLS and unknown_arguments:
            report.add('python-arguments-unresolved',
                       'Expanded positional settings cannot be fully inspected; make security options explicit.',
                       path=path, line=node.lineno, severity='warning')
        if name in KEYWORD_SECURITY_CALLS and any(keyword.arg is None for keyword in keywords):
            report.add('python-keywords-unresolved',
                       'Expanded keyword settings cannot be fully inspected; make security options explicit.',
                       path=path, line=node.lineno, severity='warning')
        if name in SHELL_KEYWORD_CALLS:
            shell_settings = [keyword.value for keyword in keywords if keyword.arg == 'shell']
            if not unknown_arguments and len(arguments) > 8:
                shell_settings.append(arguments[8])
            if any(not isinstance(setting, ast.Constant) for setting in shell_settings):
                report.add('shell-option-unresolved',
                           'Shell execution settings cannot be inspected; make the shell option explicit.',
                           path=path, line=node.lineno, severity='warning')
        if name in TLS_VERIFY_CALLS and any(keyword.arg == 'verify'
                and not isinstance(keyword.value, ast.Constant) for keyword in keywords):
            report.add('tls-option-unresolved',
                       'TLS verification settings cannot be inspected; review the supplied flag or context.',
                       path=path, line=node.lineno, severity='warning')
        if name in CERT_REQUIREMENT_CALLS:
            position = CERT_REQUIREMENT_CALLS[name]
            setting = next((keyword.value for keyword in keywords if keyword.arg == 'cert_reqs'),
                           arguments[position] if position is not None and not unknown_arguments
                           and len(arguments) > position else None)
            if setting is not None:
                mode = CERT_MODES.get(qualified(setting, set(CERT_MODES)))
                if isinstance(setting, ast.Constant):
                    value = setting.value
                    if value is None:
                        mode = 2  # urllib3 resolves an unspecified mode to CERT_REQUIRED.
                    elif isinstance(value, (int, bool)) and value in (0, 1, 2):
                        mode = int(value)
                    elif isinstance(value, str):
                        mode = {'NONE': 0, 'CERT_NONE': 0, 'OPTIONAL': 1,
                                'CERT_OPTIONAL': 1, 'REQUIRED': 2, 'CERT_REQUIRED': 2}.get(value)
                if mode == 0:
                    report.add('tls-verification-disabled',
                               'Certificate requirements disable TLS verification; use CERT_REQUIRED.',
                               path=path, line=node.lineno)
                elif mode is None:
                    report.add('tls-option-unresolved',
                               'Certificate requirements cannot be inspected; make verification explicit.',
                               path=path, line=node.lineno, severity='warning')
        if name in HOSTNAME_OPTIONS:
            for keyword in keywords:
                if keyword.arg not in HOSTNAME_OPTIONS[name]:
                    continue
                setting = keyword.value
                if isinstance(setting, ast.Constant) and setting.value is False:
                    report.add('tls-hostname-review',
                               'Hostname matching is disabled; review the intended peer identity or fingerprint-pinning policy.',
                               path=path, line=node.lineno, severity='warning')
                elif not (isinstance(setting, ast.Constant) and (setting.value is None
                          or isinstance(setting.value, str) and bool(setting.value))):
                    report.add('tls-hostname-unresolved',
                               'Hostname verification settings cannot be inspected; make the peer identity policy explicit.',
                               path=path, line=node.lineno, severity='warning')
        direct_shell = direct_shell_command(name, arguments, keywords)
        if direct_shell is None:
            report.add('shell-command-unresolved',
                       'Shell invocation cannot be inspected; make program/options explicit and separate script arguments with --.',
                       path=path, line=node.lineno, severity='warning')
        if name == 'hashlib.new':
            algorithm = arguments[0] if arguments else next(
                (keyword.value for keyword in keywords if keyword.arg == 'name'), None)
            if (isinstance(algorithm, ast.Constant) and isinstance(algorithm.value, str)
                    and algorithm.value.lower() in ('md5', 'sha1')):
                name = 'hashlib.' + algorithm.value.lower()
        log_method = node.func.attr if isinstance(node.func, ast.Attribute) else name.rsplit('.', 1)[-1]
        rule = message = None
        severity = 'error'
        if name in ('eval', 'exec', 'builtins.eval', 'builtins.exec'):
            rule, message = 'dynamic-code', 'Dynamic code execution requires review; use a constrained parser.'
        elif name == 'tempfile.mktemp':
            rule, message = 'insecure-temporary-name', (
                'Temporary names can be claimed before use; create the file atomically with mkstemp or NamedTemporaryFile.')
        elif name in TAR_EXTRACT_CALLS:
            setting = next((keyword.value for keyword in keywords if keyword.arg == 'filter'), None)
            selected_filter = (setting.value if isinstance(setting, ast.Constant) and isinstance(setting.value, str)
                               else TAR_FILTERS.get(qualified(setting)))
            if selected_filter == 'fully_trusted':
                rule, message = 'unsafe-archive-extraction', (
                    'Fully trusted tar extraction bypasses filtering; verify archive trust or use the data filter.')
            elif selected_filter not in ('data', 'tar'):
                rule, message, severity = 'archive-filter-unresolved', (
                    'Tar extraction filter is unknown or depends on runtime/instance defaults; make the policy explicit.'), 'warning'
        elif name in JWT_DECODE_CALLS:
            options = next((keyword.value for keyword in keywords if keyword.arg == 'options'),
                           arguments[3] if len(arguments) > 3 and not unknown_arguments else None)
            if options is not None and not (isinstance(options, ast.Constant) and options.value is None):
                settings = mapping_keywords(options)
                if any(setting.arg is None or setting.arg == 'verify_signature'
                       and not isinstance(setting.value, ast.Constant) for setting in settings):
                    report.add('jwt-options-unresolved',
                               'JWT signature settings cannot be fully inspected; make verification explicit.',
                               path=path, line=node.lineno, severity='warning')
                if any(setting.arg == 'verify_signature' and isinstance(setting.value, ast.Constant)
                       and not setting.value.value for setting in settings):
                    rule, message = 'jwt-signature-disabled', (
                        'JWT signature verification is disabled; do not trust these claims for authorization.')
        elif name in ('pickle.load', 'pickle.loads', '_pickle.load', '_pickle.loads', 'dill.load', 'dill.loads',
                      'pickle.Unpickler.load', '_pickle.Unpickler.load', 'dill.Unpickler.load',
                      'joblib.load', 'pandas.read_pickle'):
            rule, message = 'unsafe-deserialization', 'Object deserialization can execute code; do not accept untrusted input.'
        elif name in PICKLE_OPTION_CALLS:
            option, position, unsafe_truthiness = PICKLE_OPTION_CALLS[name]
            positional = (arguments[position] if position is not None and len(arguments) > position
                          and not unknown_arguments else None)
            setting = next((keyword.value for keyword in keywords if keyword.arg == option), positional)
            if setting is not None:
                if not isinstance(setting, ast.Constant):
                    report.add('pickle-option-unresolved',
                               'Pickle loading settings cannot be fully inspected; make the option explicit.',
                               path=path, line=node.lineno, severity='warning')
                elif setting.value is not None and bool(setting.value) == unsafe_truthiness:
                    rule, message = 'unsafe-deserialization', (
                        'Pickle-enabled loading can execute code; do not accept untrusted artifacts.')
        elif name in TLS_VERIFY_CALLS and any(
                k.arg == 'verify' and isinstance(k.value, ast.Constant)
                and (k.value.value is False or name.startswith('requests.')
                     and k.value.value is not None and not k.value.value)
                for k in keywords):
            rule, message = 'tls-verification-disabled', (
                'TLS certificate verification is disabled; use verified defaults or a trusted CA bundle.')
        elif name in UNVERIFIED_TLS_FACTORIES:
            rule, message = 'unverified-tls-context', (
                'Unverified SSL context factory requires review; prefer ssl.create_default_context.')
        elif name in ('yaml.unsafe_load', 'yaml.unsafe_load_all'):
            rule, message = 'unsafe-yaml', 'Use safe_load or safe_load_all for untrusted YAML.'
        elif name in ('yaml.load', 'yaml.load_all'):
            loader = next((k.value for k in keywords if k.arg == 'Loader'), None)
            if loader is None and len(arguments) > 1 and not unknown_arguments:
                loader = arguments[1]
            if qualified(loader, SAFE_YAML_LOADERS) not in SAFE_YAML_LOADERS:
                rule, message = 'unsafe-yaml', 'Use safe_load or an explicit SafeLoader for untrusted YAML.'
        elif direct_shell or name in IMPLICIT_SHELL_CALLS or (name in SHELL_KEYWORD_CALLS and (
                any(k.arg == 'shell' and isinstance(k.value, ast.Constant)
                    and bool(k.value.value) for k in keywords)
                or not unknown_arguments and len(arguments) > 8 and isinstance(arguments[8], ast.Constant)
                and bool(arguments[8].value))):
            rule, message = 'shell-execution', 'Shell command execution requires review; call the target program directly with an argument array.'
        elif (name in ('print', 'builtins.print') or name in STANDARD_OUTPUT_CALLS or log_method in
              ('debug', 'info', 'warning', 'warn', 'error', 'critical', 'fatal', 'exception', 'log')):
            if name in STANDARD_OUTPUT_CALLS and name.endswith('.writelines'):
                arguments = [arg.elt if isinstance(arg, ast.GeneratorExp) else arg for arg in arguments]
            rule = next((found for arg in [*arguments, *(keyword.value for keyword in keywords)]
                         if (found := environment_dump(arg))), None)
            if rule == 'environment-dump':
                message = 'Do not log the complete environment; it can contain credentials.'
            elif rule:
                message = 'Do not log credential-named environment values; redact them before logging.'
        elif name in ('hashlib.md5', 'hashlib.sha1'):
            if not any(k.arg == 'usedforsecurity' and isinstance(k.value, ast.Constant)
                       and k.value.value is False for k in keywords):
                rule, message = 'weak-hash-review', 'Confirm this weak hash is not used for security-sensitive decisions.'
                severity = 'info'
        if rule:
            report.add(rule, message, path=path, line=node.lineno, severity=severity)
