import subprocess
import json

def scan_iac(repo_path):
    # Run checkov on the repo
    result = subprocess.run(['checkov', '-d', repo_path, '-o', 'json'], capture_output=True, text=True)
    if result.returncode == 0:
        data = json.loads(result.stdout)
        findings = []
        for check in data.get('results', {}).get('failed_checks', []):
            findings.append({
                "file": check['file'],
                "rule": check['check_name'],
                "message": check['check_name'],
                "severity": check.get('severity', 'medium'),
                "line": check['file_line_range'][0]
            })
        return findings
    return []
