import argparse
from parallel_scanner import scan_repo_parallel
from iac_scanner import scan_iac
from depscan import scan_dependencies
from github_integration import create_check_run

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--repo-path', required=True)
    parser.add_argument('--github-repo', help='owner/repo name')
    parser.add_argument('--commit-sha', help='commit SHA for check run')
    parser.add_argument('--github-token', help='GitHub token')
    args = parser.parse_args()

    findings = []
    # Parallel code scan
    findings.extend(scan_repo_parallel(args.repo_path))
    # IaC scan
    findings.extend(scan_iac(args.repo_path))
    # Dependency scan
    findings.extend(scan_dependencies(args.repo_path))

    # If GitHub integration requested
    if args.github_repo and args.commit_sha and args.github_token:
        create_check_run(args.github_repo, args.commit_sha, findings)
    else:
        print(json.dumps(findings, indent=2))

if __name__ == '__main__':
    main()
