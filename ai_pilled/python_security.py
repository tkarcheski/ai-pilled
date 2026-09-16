"""Conservative Python AST patterns; these are review signals, not exploit proofs."""
import ast
import warnings


TLS_VERIFY_CALLS = {
    module + '.' + method
    for module in ('requests', 'requests.api', 'httpx')
    for method in ('request', 'get', 'post', 'put', 'patch', 'delete', 'head', 'options')
} | {'httpx.Client', 'httpx.AsyncClient', 'httpx.stream'}
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
POSITIONAL_SECURITY_CALLS = SHELL_KEYWORD_CALLS | JWT_DECODE_CALLS
KEYWORD_SECURITY_CALLS = TLS_VERIFY_CALLS | POSITIONAL_SECURITY_CALLS | {
    'yaml.load', 'yaml.load_all', 'hashlib.new', 'hashlib.md5', 'hashlib.sha1'}

SAFE_YAML_LOADERS = {'yaml.SafeLoader', 'yaml.CSafeLoader',
                     'yaml.loader.SafeLoader', 'yaml.cyaml.CSafeLoader'}


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


def call_arguments(node):
    """Expand only literal starred lists/tuples; never evaluate argument expressions."""
    if not any(isinstance(argument, ast.Starred) for argument in node.args):
        return node.args
    result = []
    pending = list(reversed(node.args))
    while pending:
        argument = pending.pop()
        if isinstance(argument, ast.Starred) and isinstance(argument.value, (ast.List, ast.Tuple)):
            pending.extend(reversed(argument.value.elts))
        else:
            result.append(argument)
    return result


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


def inspect_python(report, path, content, *, tree=None):
    if not path.endswith('.py'):
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

    def qualified(node, accepted=(), *, resolve_getattr=True):
        attributes = []
        while True:
            if isinstance(node, ast.Attribute):
                attributes.append(node.attr)
                node = node.value
            elif (resolve_getattr and isinstance(node, ast.Call) and len(node.args) in (2, 3) and not node.keywords
                  and isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str)
                  and qualified(node.func, resolve_getattr=False) in ('getattr', 'builtins.getattr')):
                attributes.append(node.args[1].value)
                node = node.args[0]
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
            elif qualified(value) in ('os.environ', 'os.environb'):
                return 'environment-dump'
            elif (isinstance(value, ast.Subscript)
                  and qualified(value.value) in ('os.environ', 'os.environb')
                  and credential_key(value.slice)):
                return 'environment-secret-log'
            elif isinstance(value, ast.Call):
                function = qualified(value.func)
                arguments = call_arguments(value)
                if function.startswith('builtins.'):
                    function = function[len('builtins.'):]
                if function in tuple(prefix + '.' + method for prefix in ('os.environ', 'os.environb')
                                     for method in ('copy', 'items', 'values')):
                    return 'environment-dump'
                if function in ('os.getenv', 'os.getenvb', 'os.environ.get', 'os.environb.get'):
                    lookup_keywords = call_keywords(value)
                    key = arguments[0] if arguments else next(
                        (keyword.value for keyword in lookup_keywords if keyword.arg == 'key'), None)
                    if credential_key(key):
                        return 'environment-secret-log'
                    pending.extend(arguments[1:])
                    pending.extend(keyword.value for keyword in lookup_keywords if keyword.arg == 'default')
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

    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and any(alias.name == '*' for alias in node.names):
            report.add('python-wildcard-import',
                       'Wildcard imports prevent reliable binding inspection; use explicit imports.',
                       path=path, line=node.lineno, severity='warning')
        if not isinstance(node, ast.Call):
            continue
        name = qualified(node.func)
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Call):
            constructor = qualified(node.func.value.func)
            if constructor in ('requests.Session', 'requests.sessions.Session',
                               'requests.session', 'requests.sessions.session'):
                name = 'requests.' + node.func.attr
            elif constructor in ('pickle.Unpickler', '_pickle.Unpickler', 'dill.Unpickler') and node.func.attr == 'load':
                name = 'pickle.load'
        keywords = call_keywords(node)
        arguments = call_arguments(node)
        unknown_arguments = any(isinstance(argument, ast.Starred) for argument in arguments)
        if name in POSITIONAL_SECURITY_CALLS and unknown_arguments:
            report.add('python-arguments-unresolved',
                       'Expanded positional settings cannot be fully inspected; make security options explicit.',
                       path=path, line=node.lineno, severity='warning')
        if name in KEYWORD_SECURITY_CALLS and any(keyword.arg is None for keyword in keywords):
            report.add('python-keywords-unresolved',
                       'Expanded keyword settings cannot be fully inspected; make security options explicit.',
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
                      'pickle.Unpickler.load', '_pickle.Unpickler.load', 'dill.Unpickler.load'):
            rule, message = 'unsafe-deserialization', 'Object deserialization can execute code; do not accept untrusted input.'
        elif name in TLS_VERIFY_CALLS and any(
                k.arg == 'verify' and isinstance(k.value, ast.Constant)
                and (k.value.value is False or name.startswith('requests.')
                     and k.value.value is not None and not k.value.value)
                for k in keywords):
            rule, message = 'tls-verification-disabled', (
                'TLS certificate verification is disabled; use verified defaults or a trusted CA bundle.')
        elif name == 'ssl._create_unverified_context':
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
        elif name in IMPLICIT_SHELL_CALLS or (name in SHELL_KEYWORD_CALLS and (
                any(k.arg == 'shell' and isinstance(k.value, ast.Constant)
                    and bool(k.value.value) for k in keywords)
                or not unknown_arguments and len(arguments) > 8 and isinstance(arguments[8], ast.Constant)
                and bool(arguments[8].value))):
            rule, message = 'shell-execution', 'Shell execution requires review; prefer argument arrays without shell=True.'
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
