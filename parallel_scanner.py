import concurrent.futures
import os

def scan_file_parallel(filepath):
    # Run all detectors on one file
    from ml_detector import MLVulnDetector
    from taint_tracker import analyze_taint
    from rules_engine import RulesEngine

    ml = MLVulnDetector()
    rules = RulesEngine("rules/custom_rules.yaml")

    with open(filepath) as f:
        code = f.read()
    findings = []
    findings.extend(ml.scan_file(filepath))
    findings.extend(rules.scan(filepath, code))
    # taint tracking could be integrated
    return findings

def scan_repo_parallel(repo_path):
    all_findings = []
    files = [os.path.join(root, f) for root, dirs, files in os.walk(repo_path) 
             for f in files if f.endswith(('.py', '.js'))]
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        future_to_file = {executor.submit(scan_file_parallel, file): file for file in files}
        for future in concurrent.futures.as_completed(future_to_file):
            all_findings.extend(future.result())
    return all_findings
