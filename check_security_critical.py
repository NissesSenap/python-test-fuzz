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

        # Count by severity
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'unknown': 0}

        for vuln in vulnerabilities:
            severity = (vuln.get('severity', '') or '').lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
            else:
                severity_counts['unknown'] += 1

        total_vulns = sum(severity_counts.values())
        high_critical_vulns = severity_counts['critical'] + severity_counts['high']

        if total_vulns == 0:
            return False, []

        # Build detailed breakdown
        breakdown_parts = []
        for severity in ['critical', 'high', 'medium', 'low']:
            if severity_counts[severity] > 0:
                breakdown_parts.append(f"{severity_counts[severity]} {severity}")
        if severity_counts['unknown'] > 0:
            breakdown_parts.append(f"{severity_counts['unknown']} unknown")

        if high_critical_vulns > 0:
            critical = True
            issues.append(f"Dependency vulnerabilities: {', '.join(breakdown_parts)} (critical due to high/critical severity)")
        elif total_vulns > 0:
            if FAIL_ON_ANY_VULNERABILITY:
                critical = True
                issues.append(f"Dependency vulnerabilities: {', '.join(breakdown_parts)} (treating as critical)")
            else:
                issues.append(f"Dependency vulnerabilities: {', '.join(breakdown_parts)} (not critical)")

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

        # Count by severity
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'unknown': 0}

        for issue in results:
            severity = (issue.get('issue_severity', '') or '').lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
            else:
                severity_counts['unknown'] += 1

        total_issues = sum(severity_counts.values())
        high_critical_issues = severity_counts['critical'] + severity_counts['high']

        if total_issues == 0:
            return False, []

        # Build detailed breakdown
        breakdown_parts = []
        for severity in ['critical', 'high', 'medium', 'low']:
            if severity_counts[severity] > 0:
                breakdown_parts.append(f"{severity_counts[severity]} {severity}")
        if severity_counts['unknown'] > 0:
            breakdown_parts.append(f"{severity_counts['unknown']} unknown")

        if high_critical_issues > 0:
            critical = True
            issues.append(f"Code security issues: {', '.join(breakdown_parts)} (critical due to high/critical severity)")
        elif total_issues > 0:
            if FAIL_ON_ANY_VULNERABILITY:
                critical = True
                issues.append(f"Code security issues: {', '.join(breakdown_parts)} (treating as critical)")
            else:
                issues.append(f"Code security issues: {', '.join(breakdown_parts)} (not critical)")

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

        # Count by risk level (ZAP uses 'risk' instead of 'severity')
        risk_counts = {'high': 0, 'medium': 0, 'low': 0, 'informational': 0, 'unknown': 0}

        for alert in alerts:
            risk = (alert.get('risk', '') or '').lower()
            # ZAP sometimes uses 'info' instead of 'informational'
            if risk == 'info':
                risk = 'informational'

            if risk in risk_counts:
                risk_counts[risk] += 1
            else:
                risk_counts['unknown'] += 1

        total_alerts = sum(risk_counts.values())
        high_risk_alerts = risk_counts['high']
        medium_risk_alerts = risk_counts['medium']

        if total_alerts == 0:
            return False, []

        # Build detailed breakdown
        breakdown_parts = []
        for risk in ['high', 'medium', 'low', 'informational']:
            if risk_counts[risk] > 0:
                breakdown_parts.append(f"{risk_counts[risk]} {risk}")
        if risk_counts['unknown'] > 0:
            breakdown_parts.append(f"{risk_counts['unknown']} unknown")

        if high_risk_alerts > 0:
            critical = True
            issues.append(f"DAST security issues: {', '.join(breakdown_parts)} (critical due to high-risk alerts)")
        elif medium_risk_alerts > 0:
            if FAIL_ON_MEDIUM_RISK:
                critical = True
                issues.append(f"DAST security issues: {', '.join(breakdown_parts)} (treating medium-risk as critical)")
            else:
                issues.append(f"DAST security issues: {', '.join(breakdown_parts)} (not critical)")
        elif total_alerts > 0:
            issues.append(f"DAST security issues: {', '.join(breakdown_parts)} (low risk)")

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
    if not all_issues:
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
        # There are issues but none are critical
        state = 'success'
        description = f"Security issues found but none are critical: {'; '.join(all_issues)}"

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
