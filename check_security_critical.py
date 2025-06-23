#!/usr/bin/env python3
"""
Script to check for critical security issues and fail if found
"""

import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Tuple

# Configuration: Set to True if you want medium-risk issues to be treated as critical
FAIL_ON_MEDIUM_RISK = os.getenv('FAIL_ON_MEDIUM_RISK', 'false').lower() == 'true'
FAIL_ON_ANY_VULNERABILITY = os.getenv('FAIL_ON_ANY_VULNERABILITY', 'false').lower() == 'true'


def check_pytest_results(pytest_file: str) -> Tuple[bool, List[str]]:
    """Check pytest results for failures"""
    issues = []
    critical = False

    if not Path(pytest_file).exists():
        return False, []

    try:
        with open(pytest_file, 'r') as f:
            data = json.load(f)

        summary = data.get('summary', {})
        failed = summary.get('failed', 0)

        if failed > 0:
            critical = True
            issues.append(f"{failed} API fuzzing tests failed")

    except (json.JSONDecodeError, KeyError) as e:
        print(f"Warning: Could not parse pytest results: {e}")

    return critical, issues


def check_pip_audit_results(pip_audit_file: str) -> Tuple[bool, List[str]]:
    """Check pip-audit results for critical/high severity vulnerabilities"""
    issues = []
    critical = False

    if not Path(pip_audit_file).exists():
        return False, []

    try:
        with open(pip_audit_file, 'r') as f:
            content = f.read().strip()

        if not content:
            return False, []

        data = json.loads(content)

        if not data or (isinstance(data, list) and len(data) == 0):
            return False, []

        vulnerabilities = data if isinstance(data, list) else [data]

        high_severity_vulns = []
        all_vulns = []

        for vuln in vulnerabilities:
            severity = (vuln.get('severity', '') or '').lower()
            all_vulns.append(vuln)

            if severity in ['high', 'critical']:
                high_severity_vulns.append(vuln)

        if high_severity_vulns:
            critical = True
            issues.append(f"{len(high_severity_vulns)} critical/high severity dependency vulnerabilities found")
        elif all_vulns:
            if FAIL_ON_ANY_VULNERABILITY:
                critical = True
                issues.append(f"{len(all_vulns)} dependency vulnerabilities found (treating as critical)")
            else:
                issues.append(f"{len(all_vulns)} dependency vulnerabilities found (not critical)")

    except (json.JSONDecodeError, KeyError, TypeError) as e:
        print(f"Warning: Could not parse pip-audit results: {e}")

    return critical, issues


def check_bandit_results(bandit_file: str) -> Tuple[bool, List[str]]:
    """Check bandit results for critical/high severity code security issues"""
    issues = []
    critical = False

    if not Path(bandit_file).exists():
        return False, []

    try:
        with open(bandit_file, 'r') as f:
            content = f.read().strip()

        if not content:
            return False, []

        data = json.loads(content)

        if not data or not isinstance(data, dict):
            return False, []

        results = data.get('results', [])
        if not results:
            return False, []

        high_severity_issues = []
        all_issues = results

        for issue in results:
            severity = (issue.get('issue_severity', '') or '').lower()

            if severity in ['high', 'critical']:
                high_severity_issues.append(issue)

        if high_severity_issues:
            critical = True
            issues.append(f"{len(high_severity_issues)} critical/high severity code security issues found")
        elif all_issues:
            if FAIL_ON_ANY_VULNERABILITY:
                critical = True
                issues.append(f"{len(all_issues)} code security issues found (treating as critical)")
            else:
                issues.append(f"{len(all_issues)} code security issues found (not critical)")

    except (json.JSONDecodeError, KeyError, TypeError) as e:
        print(f"Warning: Could not parse bandit results: {e}")

    return critical, issues


def check_zap_results(zap_file: str) -> Tuple[bool, List[str]]:
    """Check ZAP DAST results for critical/high severity security issues"""
    issues = []
    critical = False

    if not Path(zap_file).exists():
        return False, []

    try:
        with open(zap_file, 'r') as f:
            content = f.read().strip()

        if not content:
            return False, []

        data = json.loads(content)

        if not data or not isinstance(data, dict):
            return False, []

        # ZAP baseline JSON structure varies, but typically has 'alerts' or 'site' arrays
        alerts = []

        if 'alerts' in data:
            alerts = data['alerts']
        elif 'site' in data and isinstance(data['site'], list):
            for site in data['site']:
                alerts.extend(site.get('alerts', []))
        elif isinstance(data, list):
            alerts = data

        if not alerts:
            return False, []

        high_risk_alerts = [alert for alert in alerts if alert.get('risk', '').lower() == 'high']
        medium_risk_alerts = [alert for alert in alerts if alert.get('risk', '').lower() == 'medium']

        if high_risk_alerts:
            critical = True
            issues.append(f"{len(high_risk_alerts)} high-risk DAST security issues found")
        elif medium_risk_alerts:
            if FAIL_ON_MEDIUM_RISK:
                critical = True
                issues.append(f"{len(medium_risk_alerts)} medium-risk DAST security issues found (treating as critical)")
            else:
                issues.append(f"{len(medium_risk_alerts)} medium-risk DAST security issues found (not critical)")

        if len(alerts) > len(high_risk_alerts) + len(medium_risk_alerts):
            other_alerts = len(alerts) - len(high_risk_alerts) - len(medium_risk_alerts)
            issues.append(f"{other_alerts} other DAST security issues found")

    except (json.JSONDecodeError, KeyError, TypeError) as e:
        print(f"Warning: Could not parse ZAP results: {e}")

    return critical, issues


def check_all_security_issues(pytest_file: str, pip_audit_file: str, bandit_file: str, zap_file: str) -> Dict:
    """Check all security tools for critical issues"""

    # Check each tool
    pytest_critical, pytest_issues = check_pytest_results(pytest_file)
    pip_audit_critical, pip_audit_issues = check_pip_audit_results(pip_audit_file)
    bandit_critical, bandit_issues = check_bandit_results(bandit_file)
    zap_critical, zap_issues = check_zap_results(zap_file)

    # Combine results
    all_critical = pytest_critical or pip_audit_critical or bandit_critical or zap_critical
    all_issues = pytest_issues + pip_audit_issues + bandit_issues + zap_issues

    # Determine overall state and description
    if not all_critical and not all_issues:
        state = 'success'
        description = 'All API fuzzing tests passed and no security issues found'
    elif all_critical:
        state = 'failure'
        critical_issues = [issue for issue in all_issues if 'critical' in issue.lower() or 'high' in issue.lower() or 'failed' in issue.lower()]
        if len(critical_issues) == 1:
            description = critical_issues[0]
        else:
            description = f"Critical security issues found: {'; '.join(critical_issues)}"
    else:
        state = 'failure'
        description = f"Security issues found: {'; '.join(all_issues)}"

    return {
        'critical': all_critical,
        'state': state,
        'description': description,
        'issues': all_issues,
        'details': {
            'pytest': {'critical': pytest_critical, 'issues': pytest_issues},
            'pip_audit': {'critical': pip_audit_critical, 'issues': pip_audit_issues},
            'bandit': {'critical': bandit_critical, 'issues': bandit_issues},
            'zap': {'critical': zap_critical, 'issues': zap_issues}
        }
    }


def main():
    """Main function to check security issues"""

    if len(sys.argv) < 2:
        print("Usage: python check_security_critical.py <action> [pytest_results.json] [pip_audit_results.json] [bandit_results.json] [zap_results.json]")
        print("Actions:")
        print("  check - Check for critical issues and exit with code 1 if found")
        print("  status - Output status information as JSON")
        print("\nEnvironment variables:")
        print("  FAIL_ON_MEDIUM_RISK=true - Treat medium-risk DAST issues as critical")
        print("  FAIL_ON_ANY_VULNERABILITY=true - Treat any vulnerability as critical")
        sys.exit(1)

    action = sys.argv[1]
    pytest_file = sys.argv[2] if len(sys.argv) > 2 else "reports/pytest-results.json"
    pip_audit_file = sys.argv[3] if len(sys.argv) > 3 else "reports/pip-audit-report.json"
    bandit_file = sys.argv[4] if len(sys.argv) > 4 else "reports/bandit-report.json"
    zap_file = sys.argv[5] if len(sys.argv) > 5 else "reports/zap-report.json"

    # Check all security issues
    results = check_all_security_issues(pytest_file, pip_audit_file, bandit_file, zap_file)

    if action == "check":
        # Print summary
        print(f"Security Check Results:")
        print(f"Status: {results['state']}")
        print(f"Description: {results['description']}")

        if results['issues']:
            print("\nDetailed Issues:")
            for issue in results['issues']:
                print(f"  - {issue}")

        # Exit with code 1 if critical issues found
        if results['critical']:
            print(f"\n❌ Critical security issues found - failing the check")
            sys.exit(1)
        else:
            print(f"\n✅ No critical security issues found")
            sys.exit(0)

    elif action == "status":
        # Output JSON for consumption by GitHub Actions
        print(json.dumps(results, indent=2))

    else:
        print(f"Unknown action: {action}")
        sys.exit(1)


if __name__ == "__main__":
    main()
