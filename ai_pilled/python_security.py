"""Conservative Python AST patterns; these are review signals, not exploit proofs."""
import ast


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
        name = qualified(node)
        if name == 'os.environ':
            return True
        if isinstance(node, ast.Call):
            function = qualified(node.func)
            if function in ('os.environ.copy', 'os.environ.items'):
                return True
            if function in ('dict', 'str', 'repr', 'list', 'json.dumps'):
                return any(environment_dump(arg) for arg in node.args)
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
