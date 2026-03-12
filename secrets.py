import os
import re

SECRET_PATTERNS = {
    'AWS Access Key': r'AKIA[0-9A-Z]{16}',
    'GitHub Token': r'ghp_[a-zA-Z0-9]{36}',
    'Slack Token': r'xox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}',
    'Private Key': r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
    'API Key': r'api[_-]?key[=:]\s*[a-zA-Z0-9]{20,}',
}

def find_secrets(repo_path):
    secrets = []
    for root, dirs, files in os.walk(repo_path):
        for file in files:
            if file.startswith('.git'):  # skip .git
                continue
            filepath = os.path.join(root, file)
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    for name, pattern in SECRET_PATTERNS.items():
                        matches = re.findall(pattern, content)
                        if matches:
                            secrets.append({
                                'file': filepath,
                                'type': name,
                                'matches': matches[:5]  # limit output
                            })
            except:
                continue
    return secrets
