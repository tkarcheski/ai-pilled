"""Conservative Python AST patterns; these are review signals, not exploit proofs."""
import ast


TLS_VERIFY_CALLS = {
    module + '.' + method
    for module in ('requests', 'requests.api', 'httpx')
    for method in ('request', 'get', 'post', 'put', 'patch', 'delete', 'head', 'options')
} | {'httpx.Client', 'httpx.AsyncClient', 'httpx.stream'}


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
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            parent = scope
            while kinds[parent] == 'class':
                enclosing = parents[parent]
                if enclosing is None:
                    break
                parent = enclosing
            child = len(bindings)
            local: dict[str, set[str]] = {}
            if not isinstance(node, ast.ClassDef):
                arguments = node.args
                for argument in [*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs,
                                 *([arguments.vararg] if arguments.vararg else []),
                                 *([arguments.kwarg] if arguments.kwarg else [])]:
                    local[argument.arg] = {''}
            bindings.append(local)
            parents.append(parent)
            kinds.append('class' if isinstance(node, ast.ClassDef) else 'function')
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
        tree = ast.parse(content, filename=path)
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

    def environment_dump(node):
        pending = [node]
        while pending:
            value = pending.pop()
            if isinstance(value, ast.JoinedStr):
                pending.extend(value.values)
            elif isinstance(value, ast.FormattedValue):
                pending.append(value.value)
            elif isinstance(value, ast.BinOp):
                pending.extend((value.left, value.right))
            elif isinstance(value, (ast.List, ast.Tuple, ast.Set)):
                pending.extend(value.elts)
            elif isinstance(value, ast.Dict):
                pending.extend(value.keys)
                pending.extend(value.values)
            elif qualified(value) == 'os.environ':
                return True
            elif isinstance(value, ast.Call):
                function = qualified(value.func)
                if function in ('os.environ.copy', 'os.environ.items'):
                    return True
                if function in ('dict', 'str', 'repr', 'list', 'json.dumps'):
                    pending.extend(value.args)
        return False

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
                k.arg == 'verify' and isinstance(k.value, ast.Constant) and k.value.value is False
                for k in node.keywords):
            rule, message = 'tls-verification-disabled', (
                'TLS certificate verification is disabled; use verified defaults or a trusted CA bundle.')
        elif name == 'ssl._create_unverified_context':
            rule, message = 'unverified-tls-context', (
                'Unverified SSL context factory requires review; prefer ssl.create_default_context.')
        elif name == 'yaml.load':
            loader = next((k.value for k in node.keywords if k.arg == 'Loader'), None)
            if loader is None and len(node.args) > 1:
                loader = node.args[1]
            if qualified(loader) not in ('yaml.SafeLoader', 'yaml.CSafeLoader'):
                rule, message = 'unsafe-yaml', 'Use safe_load or an explicit SafeLoader for untrusted YAML.'
        elif name == 'os.system' or (name in ('subprocess.run', 'subprocess.Popen', 'subprocess.call',
                                             'subprocess.check_call', 'subprocess.check_output') and
                                     any(k.arg == 'shell' and isinstance(k.value, ast.Constant)
                                         and k.value.value is True for k in node.keywords)):
            rule, message = 'shell-execution', 'Shell execution requires review; prefer argument arrays without shell=True.'
        elif (name == 'print' or name.rsplit('.', 1)[-1] in
              ('debug', 'info', 'warning', 'error', 'critical', 'exception', 'log')):
            if any(environment_dump(arg) for arg in node.args) or any(
                    environment_dump(keyword.value) for keyword in node.keywords):
                rule, message = 'environment-dump', 'Do not log the complete environment; it can contain credentials.'
        elif name in ('hashlib.md5', 'hashlib.sha1') or (
                name == 'hashlib.new' and node.args and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str) and node.args[0].value.lower() in ('md5', 'sha1')):
            if not any(k.arg == 'usedforsecurity' and isinstance(k.value, ast.Constant)
                       and k.value.value is False for k in node.keywords):
                rule, message = 'weak-hash-review', 'Confirm this weak hash is not used for security-sensitive decisions.'
                severity = 'info'
        if rule:
            report.add(rule, message, path=path, line=node.lineno, severity=severity)
