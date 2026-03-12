import os
import json
import requests
import re

def scan_dependencies(repo_path):
    vulns = []
    # Scan for requirements.txt (Python)
    req_file = os.path.join(repo_path, 'requirements.txt')
    if os.path.exists(req_file):
        with open(req_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    match = re.match(r'([a-zA-Z0-9_-]+)([=<>!~]=?)?(.+)?', line)
                    if match:
                        pkg = match.group(1)
                        version = match.group(3) if match.group(3) else 'unknown'
                        vulns.extend(check_osv(pkg, version, 'PyPI'))
    # Similar for package.json (Node.js)
    pkg_file = os.path.join(repo_path, 'package.json')
    if os.path.exists(pkg_file):
        with open(pkg_file, 'r') as f:
            data = json.load(f)
            deps = data.get('dependencies', {})
            for pkg, version in deps.items():
                version = version.replace('^', '').replace('~', '')
                vulns.extend(check_osv(pkg, version, 'npm'))
    return vulns

def check_osv(package, version, ecosystem):
    url = "https://api.osv.dev/v1/query"
    payload = {
        "package": {"name": package, "ecosystem": ecosystem},
        "version": version
    }
    try:
        response = requests.post(url, json=payload)
        if response.status_code == 200:
            data = response.json()
            return data.get('vulns', [])
    except:
        pass
    return []
