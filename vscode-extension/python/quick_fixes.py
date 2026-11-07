"""Plan edits to Python source without importing or executing the scanned file."""

import ast
import io
import json
import re
import sys
import tokenize


DEBUG_RULE = "code-debug-mode"
SHELL_RULE = "code-subprocess-shell"
SUBPROCESS_METHODS = {"Popen", "run", "call", "check_call", "check_output"}
LITERAL_ARG = re.compile(r"[A-Za-z0-9_./:@+\-=]+")


def debug_import(tree, source, assignment):
    """Return whether to add an import, or None if the os binding is unclear."""
    imports = [
        node for node in tree.body
        if isinstance(node, ast.Import)
        and len(node.names) == 1
        and node.names[0].name == "os"
        and node.names[0].asname is None
        and node.lineno < assignment.lineno
    ]
    # Only allow references to os when a plain import already precedes DEBUG.
    # Other uses may introduce a binding we cannot safely reuse.
    allowed = {(node.lineno, node.col_offset + len("import ")) for node in imports}
    if imports:
        lines = source.split("\n")
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and node.id == "os" and isinstance(node.ctx, ast.Load):
                prefix = lines[node.lineno - 1].encode("utf-8")[:node.col_offset]
                allowed.add((node.lineno, len(prefix.decode("utf-8"))))
    for token in tokenize.generate_tokens(io.StringIO(source).readline):
        if token.type == tokenize.NAME and token.string == "os" and token.start not in allowed:
            return None
    return not imports


def debug_fix(tree, source, line):
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and node.lineno == line
            and node.col_offset == 0
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == "DEBUG"
            and isinstance(node.value, ast.Constant)
            and node.value.value is True
        ):
            add_import = debug_import(tree, source, node)
            if add_import is not None:
                return node.value, 'os.getenv("DEBUG", "False").lower() == "true"', add_import
    return None


def shell_fix(tree, line):
    matches = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and node.lineno == line
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "subprocess"
            and node.func.attr in SUBPROCESS_METHODS
            and len(node.args) == 1
            and isinstance(node.args[0], (ast.List, ast.Tuple))
            and node.args[0].elts
            and all(
                isinstance(arg, ast.Constant)
                and isinstance(arg.value, str)
                and LITERAL_ARG.fullmatch(arg.value)
                for arg in node.args[0].elts
            )
            and len(node.keywords) == 1
            and node.keywords[0].arg == "shell"
            and isinstance(node.keywords[0].value, ast.Constant)
            and node.keywords[0].value.value is True
        ):
            matches.append(node.keywords[0].value)
    if len(matches) == 1:
        return matches[0], "False", False
    return None


def plan_fixes(source, requests):
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return []
    lines = source.split("\n")

    def position(line, byte_column):
        prefix = lines[line - 1].encode("utf-8")[:byte_column].decode("utf-8")
        return [line - 1, len(prefix.encode("utf-16-le")) // 2]

    fixes = []
    for index, request in enumerate(requests):
        rule, line = request
        if rule == DEBUG_RULE:
            plan = debug_fix(tree, source, line)
        elif rule == SHELL_RULE:
            plan = shell_fix(tree, line)
        else:
            continue
        if plan is not None:
            node, replacement, add_import = plan
            fixes.append({
                "index": index,
                "start": position(node.lineno, node.col_offset),
                "end": position(node.end_lineno, node.end_col_offset),
                "replacement": replacement,
                "importLine": line - 1 if add_import else None,
            })
    return fixes


if __name__ == "__main__":
    request = json.load(sys.stdin)
    json.dump(plan_fixes(request["source"], request["diagnostics"]), sys.stdout)
