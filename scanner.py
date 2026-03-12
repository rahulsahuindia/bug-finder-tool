import os
import json
from .sast import run_sast
from .depscan import scan_dependencies
from .secrets import find_secrets
from .reporter import generate_report

class BugFinder:
    def __init__(self, repo_path):
        self.repo_path = repo_path
        self.results = {
            'sast': [],
            'dependencies': [],
            'secrets': []
        }

    def scan(self):
        print(f"Scanning repository: {self.repo_path}")
        self.results['sast'] = run_sast(self.repo_path)
        self.results['dependencies'] = scan_dependencies(self.repo_path)
        self.results['secrets'] = find_secrets(self.repo_path)
        return self.results

    def report(self, format='json'):
        return generate_report(self.results, format)
