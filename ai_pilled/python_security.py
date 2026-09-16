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


def inspect_python(report, path, content):
    if not path.endswith('.py'):
        return
    try:
        tree = parse_python(content, path)
    except (SyntaxError, ValueError, RecursionError):
        report.add('python-unparsed', 'Python syntax could not be inspected by this interpreter.',
                   path=path, severity='warning')
        return
    scopes, bindings, parents = import_scopes(tree)
    ambiguous = set()

    def qualified(node):
        attributes = []
        while isinstance(node, ast.Attribute):
            attributes.append(node.attr)
            node = node.value
        if not isinstance(node, ast.Name):
            return ''
        base = node.id
        scope = scopes[node]
        while scope is not None:
            if base in bindings[scope]:
                candidates = bindings[scope][base]
                if len(candidates) != 1:
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
            elif isinstance(value, (ast.FormattedValue, ast.Starred)):
                pending.append(value.value)
            elif isinstance(value, ast.IfExp):
                pending.extend((value.body, value.orelse))
            elif isinstance(value, ast.BoolOp):
                pending.extend(value.values)
            elif isinstance(value, ast.NamedExpr):
                pending.append(value.value)
            elif isinstance(value, ast.BinOp):
                pending.extend((value.left, value.right))
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
                if function in tuple(prefix + '.' + method for prefix in ('os.environ', 'os.environb')
                                     for method in ('copy', 'items', 'values')):
                    return 'environment-dump'
                if function in ('os.getenv', 'os.getenvb', 'os.environ.get', 'os.environb.get'):
                    key = value.args[0] if value.args else next(
                        (keyword.value for keyword in value.keywords if keyword.arg == 'key'), None)
                    if credential_key(key):
                        return 'environment-secret-log'
                    pending.extend(value.args[1:])
                    pending.extend(keyword.value for keyword in value.keywords if keyword.arg == 'default')
                literal_format = (isinstance(value.func, ast.Attribute)
                                  and isinstance(value.func.value, ast.Constant)
                                  and isinstance(value.func.value.value, str)
                                  and value.func.attr in ('format', 'format_map'))
                if function in ('dict', 'str', 'repr', 'list', 'tuple', 'set', 'json.dumps') or literal_format:
                    pending.extend(value.args)
                    pending.extend(keyword.value for keyword in value.keywords)
        return None

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = qualified(node.func)
        rule = message = None
        severity = 'error'
        if name in ('eval', 'exec', 'builtins.eval', 'builtins.exec'):
            rule, message = 'dynamic-code', 'Dynamic code execution requires review; use a constrained parser.'
        elif name in ('pickle.load', 'pickle.loads', 'dill.load', 'dill.loads'):
            rule, message = 'unsafe-deserialization', 'Object deserialization can execute code; do not accept untrusted input.'
        elif name in TLS_VERIFY_CALLS and any(
                k.arg == 'verify' and isinstance(k.value, ast.Constant)
                and (k.value.value is False or name.startswith('requests.')
                     and k.value.value is not None and not k.value.value)
                for k in node.keywords):
            rule, message = 'tls-verification-disabled', (
                'TLS certificate verification is disabled; use verified defaults or a trusted CA bundle.')
        elif name == 'ssl._create_unverified_context':
            rule, message = 'unverified-tls-context', (
                'Unverified SSL context factory requires review; prefer ssl.create_default_context.')
        elif name in ('yaml.unsafe_load', 'yaml.unsafe_load_all'):
            rule, message = 'unsafe-yaml', 'Use safe_load or safe_load_all for untrusted YAML.'
        elif name in ('yaml.load', 'yaml.load_all'):
            loader = next((k.value for k in node.keywords if k.arg == 'Loader'), None)
            if loader is None and len(node.args) > 1:
                loader = node.args[1]
            if qualified(loader) not in ('yaml.SafeLoader', 'yaml.CSafeLoader'):
                rule, message = 'unsafe-yaml', 'Use safe_load or an explicit SafeLoader for untrusted YAML.'
        elif name in IMPLICIT_SHELL_CALLS or (name in ('subprocess.run', 'subprocess.Popen', 'subprocess.call',
                                             'subprocess.check_call', 'subprocess.check_output') and
                                     any(k.arg == 'shell' and isinstance(k.value, ast.Constant)
                                         and bool(k.value.value) for k in node.keywords)):
            rule, message = 'shell-execution', 'Shell execution requires review; prefer argument arrays without shell=True.'
        elif (name in ('print', 'builtins.print') or name.rsplit('.', 1)[-1] in
              ('debug', 'info', 'warning', 'error', 'critical', 'exception', 'log')):
            rule = next((found for arg in [*node.args, *(keyword.value for keyword in node.keywords)]
                         if (found := environment_dump(arg))), None)
            if rule == 'environment-dump':
                message = 'Do not log the complete environment; it can contain credentials.'
            elif rule:
                message = 'Do not log credential-named environment values; redact them before logging.'
        elif name in ('hashlib.md5', 'hashlib.sha1') or (
                name == 'hashlib.new' and node.args and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str) and node.args[0].value.lower() in ('md5', 'sha1')):
            if not any(k.arg == 'usedforsecurity' and isinstance(k.value, ast.Constant)
                       and k.value.value is False for k in node.keywords):
                rule, message = 'weak-hash-review', 'Confirm this weak hash is not used for security-sensitive decisions.'
                severity = 'info'
        if rule:
            report.add(rule, message, path=path, line=node.lineno, severity=severity)
