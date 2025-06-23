#!/usr/bin/env python3
"""
Script to generate GitHub PR comments and summaries from test results
"""

import json
import os
import sys
from pathlib import Path
from datetime import datetime

def generate_job_summary(test_results, security_results):
    """Generate GitHub Actions job summary"""
    
    summary = """# 🧪 API Fuzzing Test Results

## Test Summary
"""
    
    if test_results.get('passed', 0) > 0:
        summary += f"✅ **{test_results['passed']} tests passed**\n"
    
    if test_results.get('failed', 0) > 0:
        summary += f"❌ **{test_results['failed']} tests failed**\n"
    
    if test_results.get('skipped', 0) > 0:
        summary += f"⏭️ **{test_results['skipped']} tests skipped**\n"
    
    summary += f"\n⏱️ **Total duration**: {test_results.get('duration', 'N/A')}\n\n"
    
    # Security scan results
    summary += "## 🔒 Security Scan Results\n\n"
    
    total_issues = security_results.get('total_issues', 0)
    if total_issues == 0:
        summary += "✅ **No security issues found across all tools**\n\n"
    else:
        summary += f"⚠️ **{total_issues} total security issues found**\n\n"
     # Dependency vulnerabilities (pip-audit)
    vulnerabilities = security_results.get('vulnerabilities', 0)
    summary += "### 🔍 Dependency Vulnerabilities (pip-audit)\n"
    if vulnerabilities == 0:
        summary += "✅ No dependency vulnerabilities found\n\n"
    else:
        pip_audit_breakdown = security_results.get('pip_audit_breakdown', {})
        summary += f"❌ **{vulnerabilities}** dependency vulnerabilities found:\n"
        if pip_audit_breakdown.get('high', 0) > 0:
            summary += f"  - 🔴 High: {pip_audit_breakdown['high']}\n"
        if pip_audit_breakdown.get('medium', 0) > 0:
            summary += f"  - 🟡 Medium: {pip_audit_breakdown['medium']}\n"
        if pip_audit_breakdown.get('low', 0) > 0:
            summary += f"  - 🟢 Low: {pip_audit_breakdown['low']}\n"
        summary += "\n"

    # Code security issues (bandit)
    code_issues = security_results.get('code_issues', 0)
    summary += "### 📝 Code Security Issues (bandit)\n"
    if code_issues == 0:
        summary += "✅ No code security issues found\n\n"
    else:
        bandit_breakdown = security_results.get('bandit_breakdown', {})
        summary += f"❌ **{code_issues}** code security issues found:\n"
        if bandit_breakdown.get('high', 0) > 0:
            summary += f"  - 🔴 High: {bandit_breakdown['high']}\n"
        if bandit_breakdown.get('medium', 0) > 0:
            summary += f"  - 🟡 Medium: {bandit_breakdown['medium']}\n"
        if bandit_breakdown.get('low', 0) > 0:
            summary += f"  - 🟢 Low: {bandit_breakdown['low']}\n"
        summary += "\n"

    # DAST security issues (ZAP)
    dast_issues = security_results.get('dast_issues', 0)
    summary += "### 🛡️ DAST Security Issues (ZAP)\n"
    if dast_issues == 0:
        summary += "✅ No DAST security issues found\n\n"
    else:
        zap_breakdown = security_results.get('zap_breakdown', {})
        summary += f"❌ **{dast_issues}** DAST security issues found:\n"
        if zap_breakdown.get('high', 0) > 0:
            summary += f"  - 🔴 High: {zap_breakdown['high']}\n"
        if zap_breakdown.get('medium', 0) > 0:
            summary += f"  - 🟡 Medium: {zap_breakdown['medium']}\n"
        if zap_breakdown.get('low', 0) > 0:
            summary += f"  - 🟢 Low: {zap_breakdown['low']}\n"
        if zap_breakdown.get('informational', 0) > 0:
            summary += f"  - ℹ️ Info: {zap_breakdown['informational']}\n"
        summary += "\n"
    
    # Overall severity breakdown
    if total_issues > 0:
        summary += "### 📊 Overall Severity Breakdown\n"
        if security_results.get('high', 0) > 0:
            summary += f"- 🔴 **High**: {security_results['high']}\n"
        if security_results.get('medium', 0) > 0:
            summary += f"- 🟡 **Medium**: {security_results['medium']}\n"
        if security_results.get('low', 0) > 0:
            summary += f"- 🟢 **Low**: {security_results['low']}\n"
        if security_results.get('informational', 0) > 0:
            summary += f"- ℹ️ **Info**: {security_results['informational']}\n"
        summary += "\n"
    
    return summary

def generate_pr_comment(test_results, security_results, pr_number):
    """Generate PR comment content"""
    
    # Determine overall status
    total_issues = security_results.get('total_issues', 0)
    if test_results.get('failed', 0) == 0 and total_issues == 0:
        status_emoji = "✅"
        status_text = "All checks passed!"
    elif test_results.get('failed', 0) > 0:
        status_emoji = "❌"
        status_text = "Some tests failed"
    else:
        status_emoji = "⚠️"
        status_text = "Security issues found"
    
    comment = f"""## {status_emoji} API Fuzzing Results

{status_text}

### 📊 Test Results
| Metric | Count |
|--------|-------|
| ✅ Passed | {test_results.get('passed', 0)} |
| ❌ Failed | {test_results.get('failed', 0)} |
| ⏭️ Skipped | {test_results.get('skipped', 0)} |
| ⏱️ Duration | {test_results.get('duration', 'N/A')} |

### 🔒 Security Scan Results
"""
    
    total_issues = security_results.get('total_issues', 0)
    if total_issues == 0:
        comment += "✅ No security issues detected across all tools\n\n"
    else:
        comment += f"⚠️ {total_issues} total security issues found\n\n"
        
        # Dependency vulnerabilities (pip-audit)
        vulnerabilities = security_results.get('vulnerabilities', 0)
        comment += "#### 🔍 Dependency Vulnerabilities (pip-audit)\n"
        if vulnerabilities == 0:
            comment += "✅ No dependency vulnerabilities\n\n"
        else:
            pip_audit_breakdown = security_results.get('pip_audit_breakdown', {})
            comment += f"❌ **{vulnerabilities}** dependency vulnerabilities found:\n"
            if pip_audit_breakdown.get('high', 0) > 0:
                comment += f"  - 🔴 High: {pip_audit_breakdown['high']}\n"
            if pip_audit_breakdown.get('medium', 0) > 0:
                comment += f"  - 🟡 Medium: {pip_audit_breakdown['medium']}\n"
            if pip_audit_breakdown.get('low', 0) > 0:
                comment += f"  - 🟢 Low: {pip_audit_breakdown['low']}\n"
            comment += "\n"
        
        # Code security issues (bandit)
        code_issues = security_results.get('code_issues', 0)
        comment += "#### 📝 Code Security Issues (bandit)\n"
        if code_issues == 0:
            comment += "✅ No code security issues\n\n"
        else:
            bandit_breakdown = security_results.get('bandit_breakdown', {})
            comment += f"❌ **{code_issues}** code security issues found:\n"
            if bandit_breakdown.get('high', 0) > 0:
                comment += f"  - 🔴 High: {bandit_breakdown['high']}\n"
            if bandit_breakdown.get('medium', 0) > 0:
                comment += f"  - 🟡 Medium: {bandit_breakdown['medium']}\n"
            if bandit_breakdown.get('low', 0) > 0:
                comment += f"  - 🟢 Low: {bandit_breakdown['low']}\n"
            comment += "\n"
        
        # DAST security issues (ZAP)
        dast_issues = security_results.get('dast_issues', 0)
        comment += "#### 🛡️ DAST Security Issues (ZAP)\n"
        if dast_issues == 0:
            comment += "✅ No DAST security issues\n\n"
        else:
            zap_breakdown = security_results.get('zap_breakdown', {})
            comment += f"❌ **{dast_issues}** DAST security issues found:\n"
            if zap_breakdown.get('high', 0) > 0:
                comment += f"  - 🔴 High: {zap_breakdown['high']}\n"
            if zap_breakdown.get('medium', 0) > 0:
                comment += f"  - 🟡 Medium: {zap_breakdown['medium']}\n"
            if zap_breakdown.get('low', 0) > 0:
                comment += f"  - 🟢 Low: {zap_breakdown['low']}\n"
            if zap_breakdown.get('informational', 0) > 0:
                comment += f"  - ℹ️ Info: {zap_breakdown['informational']}\n"
            comment += "\n"
        comment += "\n"
    
    comment += f"\n---\n*Generated at {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}*"
    
    return comment

def parse_pytest_results(pytest_output_file):
    """Parse pytest results from JSON output"""
    if not Path(pytest_output_file).exists():
        return {'passed': 0, 'failed': 0, 'skipped': 0, 'duration': 'N/A'}
    
    try:
        with open(pytest_output_file, 'r') as f:
            data = json.load(f)
        
        summary = data.get('summary', {})
        return {
            'passed': summary.get('passed', 0),
            'failed': summary.get('failed', 0),
            'skipped': summary.get('skipped', 0),
            'duration': f"{data.get('duration', 0):.2f}s"
        }
    except (json.JSONDecodeError, KeyError):
        return {'passed': 0, 'failed': 0, 'skipped': 0, 'duration': 'N/A'}

def parse_pip_audit_results(pip_audit_file):
    """Parse pip-audit results from JSON output"""
    if not Path(pip_audit_file).exists():
        return {'vulnerabilities': 0, 'high': 0, 'medium': 0, 'low': 0}
    
    try:
        with open(pip_audit_file, 'r') as f:
            content = f.read().strip()
            
        # Handle empty file
        if not content:
            return {'vulnerabilities': 0, 'high': 0, 'medium': 0, 'low': 0}
            
        data = json.loads(content)
        
        # Handle empty array or null
        if not data or (isinstance(data, list) and len(data) == 0):
            return {'vulnerabilities': 0, 'high': 0, 'medium': 0, 'low': 0}
        
        # pip-audit returns an array of vulnerability objects
        if isinstance(data, list):
            vulnerabilities = len(data)
            severity_counts = {'high': 0, 'medium': 0, 'low': 0}
            
            for vuln in data:
                # Handle different pip-audit output formats
                if isinstance(vuln, dict):
                    # Look for severity in various possible fields
                    severity = 'unknown'
                    
                    # Check common severity fields
                    if 'severity' in vuln:
                        severity = str(vuln['severity']).lower()
                    elif 'cvss' in vuln and vuln['cvss']:
                        # Estimate severity from CVSS score if available
                        try:
                            cvss_score = float(vuln['cvss'])
                            if cvss_score >= 7.0:
                                severity = 'high'
                            elif cvss_score >= 4.0:
                                severity = 'medium'
                            else:
                                severity = 'low'
                        except (ValueError, TypeError):
                            severity = 'medium'
                    
                    # Categorize severity
                    if severity in ['high', 'critical']:
                        severity_counts['high'] += 1
                    elif severity in ['medium', 'moderate']:
                        severity_counts['medium'] += 1
                    elif severity in ['low', 'minor']:
                        severity_counts['low'] += 1
                    else:
                        # Default to medium for unknown severity
                        severity_counts['medium'] += 1
                else:
                    # If vulnerability is not a dict (unexpected format), count as medium
                    severity_counts['medium'] += 1
            
            return {
                'vulnerabilities': vulnerabilities,
                **severity_counts
            }
        else:
            # Unexpected format
            return {'vulnerabilities': 0, 'high': 0, 'medium': 0, 'low': 0}
            
    except (json.JSONDecodeError, KeyError, TypeError) as e:
        print(f"Warning: Could not parse pip-audit results: {e}")
        return {'vulnerabilities': 0, 'high': 0, 'medium': 0, 'low': 0}

def parse_bandit_results(bandit_file):
    """Parse bandit results from JSON output"""
    if not Path(bandit_file).exists():
        return {'issues': 0, 'high': 0, 'medium': 0, 'low': 0}
    
    try:
        with open(bandit_file, 'r') as f:
            content = f.read().strip()
            
        # Handle empty file
        if not content:
            return {'issues': 0, 'high': 0, 'medium': 0, 'low': 0}
            
        data = json.loads(content)
        
        # Handle empty or invalid data
        if not data or not isinstance(data, dict):
            return {'issues': 0, 'high': 0, 'medium': 0, 'low': 0}
        
        # Bandit JSON structure: {"results": [...], "metrics": {...}}
        results = data.get('results', [])
        if not results:
            return {'issues': 0, 'high': 0, 'medium': 0, 'low': 0}
        
        issues = len(results)
        severity_counts = {'high': 0, 'medium': 0, 'low': 0}
        
        for issue in results:
            if isinstance(issue, dict):
                # Bandit uses 'issue_severity' field
                severity = issue.get('issue_severity', 'MEDIUM').upper()
                
                if severity in ['HIGH', 'CRITICAL']:
                    severity_counts['high'] += 1
                elif severity in ['MEDIUM', 'MODERATE']:
                    severity_counts['medium'] += 1
                elif severity in ['LOW', 'MINOR', 'INFO']:
                    severity_counts['low'] += 1
                else:
                    # Default to medium for unknown severity
                    severity_counts['medium'] += 1
            else:
                # If issue is not a dict (unexpected format), count as medium
                severity_counts['medium'] += 1
        
        return {
            'issues': issues,
            **severity_counts
        }
        
    except (json.JSONDecodeError, KeyError, TypeError) as e:
        print(f"Warning: Could not parse bandit results: {e}")
        return {'issues': 0, 'high': 0, 'medium': 0, 'low': 0}

def parse_zap_results(zap_file):
    """Parse ZAP baseline results from JSON output"""
    if not Path(zap_file).exists():
        return {'alerts': 0, 'high': 0, 'medium': 0, 'low': 0, 'informational': 0}
    
    try:
        with open(zap_file, 'r') as f:
            content = f.read().strip()
            
        # Handle empty file
        if not content:
            return {'alerts': 0, 'high': 0, 'medium': 0, 'low': 0, 'informational': 0}
            
        data = json.loads(content)
        
        # Handle empty or invalid data
        if not data or not isinstance(data, dict):
            return {'alerts': 0, 'high': 0, 'medium': 0, 'low': 0, 'informational': 0}
        
        # ZAP baseline JSON structure varies, but typically has 'alerts' or 'site' arrays
        alerts = []
        
        # Try different possible structures
        if 'alerts' in data:
            alerts = data['alerts']
        elif 'site' in data and isinstance(data['site'], list):
            # Extract alerts from site structure
            for site in data['site']:
                if 'alerts' in site:
                    alerts.extend(site['alerts'])
        elif isinstance(data, list):
            # Sometimes the root is an array of alerts
            alerts = data
        
        if not alerts:
            return {'alerts': 0, 'high': 0, 'medium': 0, 'low': 0, 'informational': 0}
        
        severity_counts = {'high': 0, 'medium': 0, 'low': 0, 'informational': 0}
        
        for alert in alerts:
            if isinstance(alert, dict):
                # ZAP uses 'risk' field for severity
                risk = alert.get('risk', '').upper()
                
                if risk in ['HIGH', 'CRITICAL']:
                    severity_counts['high'] += 1
                elif risk in ['MEDIUM', 'MODERATE']:
                    severity_counts['medium'] += 1
                elif risk in ['LOW', 'MINOR']:
                    severity_counts['low'] += 1
                elif risk in ['INFORMATIONAL', 'INFO']:
                    severity_counts['informational'] += 1
                else:
                    # Default to informational for unknown risk
                    severity_counts['informational'] += 1
            else:
                # If alert is not a dict (unexpected format), count as informational
                severity_counts['informational'] += 1
        
        return {
            'alerts': len(alerts),
            **severity_counts
        }
        
    except (json.JSONDecodeError, KeyError, TypeError) as e:
        print(f"Warning: Could not parse ZAP results: {e}")
        return {'alerts': 0, 'high': 0, 'medium': 0, 'low': 0, 'informational': 0}

def combine_security_results(pip_audit_results, bandit_results, zap_results=None):
    """Combine pip-audit, bandit, and ZAP results into unified security summary"""
    if zap_results is None:
        zap_results = {'alerts': 0, 'high': 0, 'medium': 0, 'low': 0, 'informational': 0}
    
    return {
        'total_issues': (pip_audit_results.get('vulnerabilities', 0) + 
                        bandit_results.get('issues', 0) + 
                        zap_results.get('alerts', 0)),
        'vulnerabilities': pip_audit_results.get('vulnerabilities', 0),
        'code_issues': bandit_results.get('issues', 0),
        'dast_issues': zap_results.get('alerts', 0),
        'high': (pip_audit_results.get('high', 0) + 
                bandit_results.get('high', 0) + 
                zap_results.get('high', 0)),
        'medium': (pip_audit_results.get('medium', 0) + 
                  bandit_results.get('medium', 0) + 
                  zap_results.get('medium', 0)),
        'low': (pip_audit_results.get('low', 0) + 
               bandit_results.get('low', 0) + 
               zap_results.get('low', 0)),
        'informational': zap_results.get('informational', 0),
        # Individual tool breakdowns
        'pip_audit_breakdown': {
            'high': pip_audit_results.get('high', 0),
            'medium': pip_audit_results.get('medium', 0),
            'low': pip_audit_results.get('low', 0)
        },
        'bandit_breakdown': {
            'high': bandit_results.get('high', 0),
            'medium': bandit_results.get('medium', 0),
            'low': bandit_results.get('low', 0)
        },
        'zap_breakdown': {
            'high': zap_results.get('high', 0),
            'medium': zap_results.get('medium', 0),
            'low': zap_results.get('low', 0),
            'informational': zap_results.get('informational', 0)
        }
    }

def main():
    """Main function to generate PR outputs"""
    
    # Parse command line arguments
    if len(sys.argv) < 2:
        print("Usage: python generate_pr_output.py <action> [pytest_results.json] [pip_audit_results.json] [bandit_results.json] [zap_results.json]")
        print("Actions: summary, comment")
        sys.exit(1)
    
    action = sys.argv[1]
    pytest_file = sys.argv[2] if len(sys.argv) > 2 else "reports/pytest-results.json"
    pip_audit_file = sys.argv[3] if len(sys.argv) > 3 else "reports/pip-audit-report.json"
    bandit_file = sys.argv[4] if len(sys.argv) > 4 else "reports/bandit-report.json"
    zap_file = sys.argv[5] if len(sys.argv) > 5 else "reports/zap-report.json"
    
    # Parse test results
    test_results = parse_pytest_results(pytest_file)
    pip_audit_results = parse_pip_audit_results(pip_audit_file)
    bandit_results = parse_bandit_results(bandit_file)
    zap_results = parse_zap_results(zap_file)
    
    # Combine security results
    security_results = combine_security_results(pip_audit_results, bandit_results, zap_results)
    
    if action == "summary":
        # Generate job summary
        summary = generate_job_summary(test_results, security_results)
        
        # Write to GitHub Actions step summary
        github_step_summary = os.getenv('GITHUB_STEP_SUMMARY')
        if github_step_summary:
            with open(github_step_summary, 'a') as f:
                f.write(summary)
        else:
            print(summary)
    
    elif action == "comment":
        # Generate PR comment
        pr_number = os.getenv('GITHUB_REF', '').split('/')[-2] if 'pull' in os.getenv('GITHUB_REF', '') else 'unknown'
        comment = generate_pr_comment(test_results, security_results, pr_number)
        
        # Write comment to file for GitHub Actions to use
        with open('pr-comment.md', 'w') as f:
            f.write(comment)
        
        print("PR comment generated: pr-comment.md")
    
    else:
        print(f"Unknown action: {action}")
        sys.exit(1)

if __name__ == "__main__":
    main()
