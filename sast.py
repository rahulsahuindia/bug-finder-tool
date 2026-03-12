import os
import tree_sitter_python as tspython
import tree_sitter_javascript as tsjs
from tree_sitter import Language, Parser

# Load languages
PY_LANGUAGE = Language(tspython.language())
JS_LANGUAGE = Language(tsjs.language())

# Dangerous patterns
DANGEROUS_PATTERNS = {
    'python': ['eval', 'exec', '__import__', 'subprocess', 'os.system', 'pickle.loads'],
    'javascript': ['eval', 'Function', 'setTimeout', 'setInterval', 'document.write']
}

def run_sast(repo_path):
    issues = []
    for root, dirs, files in os.walk(repo_path):
        for file in files:
            if file.endswith('.py'):
                issues.extend(scan_file(os.path.join(root, file), 'python'))
            elif file.endswith('.js'):
                issues.extend(scan_file(os.path.join(root, file), 'javascript'))
    return issues

def scan_file(filepath, language):
    issues = []
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        code = f.read()
    parser = Parser()
    if language == 'python':
        parser.set_language(PY_LANGUAGE)
    elif language == 'javascript':
        parser.set_language(JS_LANGUAGE)
    else:
        return issues

    tree = parser.parse(bytes(code, "utf8"))
    # Simple text-based search for dangerous functions (for demo)
    for pattern in DANGEROUS_PATTERNS[language]:
        if pattern in code:
            issues.append({
                'file': filepath,
                'pattern': pattern,
                'severity': 'high',
                'description': f'Dangerous function {pattern} used.'
            })
    return issues

