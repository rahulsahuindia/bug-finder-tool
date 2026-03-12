import yaml
import re

class RulesEngine:
    def __init__(self, rules_file):
        with open(rules_file) as f:
            self.rules = yaml.safe_load(f)

    def scan(self, filepath, code):
        findings = []
        for rule in self.rules:
            if re.search(rule['pattern'], code):
                findings.append({
                    "rule": rule['id'],
                    "message": rule['message'],
                    "severity": rule['severity'],
                    "file": filepath
                })
        return findings
