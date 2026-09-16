"""Conservative Python AST patterns; these are review signals, not exploit proofs."""
import ast


TLS_VERIFY_CALLS = {
    module + '.' + method
    for module in ('requests', 'requests.api', 'httpx')
    for method in ('request', 'get', 'post', 'put', 'patch', 'delete', 'head', 'options')
} | {'httpx.Client', 'httpx.AsyncClient', 'httpx.stream'}


def inspect_python(report, path, content):
    if not path.endswith('.py'):
        return
    try:
        tree = ast.parse(content, filename=path)
    except (SyntaxError, ValueError, RecursionError):
        report.add('python-unparsed', 'Python syntax could not be inspected by this interpreter.',
                   path=path, severity='warning')
        return
    aliases = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                aliases[alias.asname or alias.name.split('.')[0]] = (
                    alias.name if alias.asname else alias.name.split('.')[0])
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                aliases[alias.asname or alias.name] = node.module + '.' + alias.name

    def qualified(node):
        attributes = []
        while isinstance(node, ast.Attribute):
            attributes.append(node.attr)
            node = node.value
        base = aliases.get(node.id, node.id) if isinstance(node, ast.Name) else ''
        return '.'.join([base, *reversed(attributes)])

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
