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
        summary += "✅ **No security issues found**\n\n"
    else:
        summary += f"⚠️ **{total_issues} security issues found**\n\n"
        
        # Break down by type
        vulnerabilities = security_results.get('vulnerabilities', 0)
        code_issues = security_results.get('code_issues', 0)
        dast_issues = security_results.get('dast_issues', 0)
        
        if vulnerabilities > 0:
            summary += f"- 🔍 **Dependencies**: {vulnerabilities} vulnerabilities\n"
        if code_issues > 0:
            summary += f"- 📝 **Code Issues**: {code_issues} security issues\n"
        if dast_issues > 0:
            summary += f"- 🛡️ **DAST Scan**: {dast_issues} security issues\n"
        
        summary += "\n**Severity Breakdown:**\n"
        if security_results.get('high', 0) > 0:
            summary += f"- 🔴 **High**: {security_results['high']}\n"
        if security_results.get('medium', 0) > 0:
            summary += f"- 🟡 **Medium**: {security_results['medium']}\n"
        if security_results.get('low', 0) > 0:
            summary += f"- 🟢 **Low**: {security_results['low']}\n"
        if security_results.get('info', 0) > 0:
            summary += f"- ℹ️ **Info**: {security_results['info']}\n"
    
    # Add recommendations
    if test_results.get('failed', 0) > 0 or security_results.get('total_issues', 0) > 0:
        summary += "\n## 🔧 Recommendations\n\n"
        
        if test_results.get('failed', 0) > 0:
            summary += "- Review failing tests and fix API issues\n"
            summary += "- Check server logs for detailed error information\n"
        
        if security_results.get('vulnerabilities', 0) > 0:
            summary += "- Update vulnerable dependencies using pip-audit recommendations\n"
        
        if security_results.get('code_issues', 0) > 0:
            summary += "- Review and fix code security issues identified by bandit\n"
            summary += "- Consider implementing secure coding practices\n"
        
        if security_results.get('dast_issues', 0) > 0:
            summary += "- Review and fix DAST security issues identified by ZAP\n"
            summary += "- Check API endpoints for security vulnerabilities\n"
            summary += "- Implement proper input validation and security headers\n"
        
        if security_results.get('total_issues', 0) > 0:
            summary += "- Review detailed security scan reports for specific remediation steps\n"
    
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

### 🔒 Security Scan
"""
    
    if total_issues == 0:
        comment += "✅ No security issues detected\n"
    else:
        comment += f"⚠️ {total_issues} security issues found:\n\n"
        
        # Break down by type
        vulnerabilities = security_results.get('vulnerabilities', 0)
        code_issues = security_results.get('code_issues', 0)
        dast_issues = security_results.get('dast_issues', 0)
        
        comment += "| Type | Count |\n|------|-------|\n"
        if vulnerabilities > 0:
            comment += f"| 🔍 Dependencies | {vulnerabilities} |\n"
        if code_issues > 0:
            comment += f"| 📝 Code Issues | {code_issues} |\n"
        if dast_issues > 0:
            comment += f"| 🛡️ DAST Scan | {dast_issues} |\n"
        
        comment += "\n**Severity Breakdown:**\n"
        comment += "| Severity | Count |\n|----------|-------|\n"
        if security_results.get('high', 0) > 0:
            comment += f"| 🔴 High | {security_results['high']} |\n"
        if security_results.get('medium', 0) > 0:
            comment += f"| 🟡 Medium | {security_results['medium']} |\n"
        if security_results.get('low', 0) > 0:
            comment += f"| 🟢 Low | {security_results['low']} |\n"
        if security_results.get('info', 0) > 0:
            comment += f"| ℹ️ Info | {security_results['info']} |\n"
    
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
    """Parse ZAP DAST results from JSON output"""
    if not Path(zap_file).exists():
        return {'dast_issues': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    
    try:
        with open(zap_file, 'r') as f:
            content = f.read().strip()
            
        # Handle empty file
        if not content:
            return {'dast_issues': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
            
        data = json.loads(content)
        
        # Handle empty or invalid data
        if not data or not isinstance(data, dict):
            return {'dast_issues': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        
        # ZAP JSON structure: {"alerts": [...], "scan_summary": {...}}
        alerts = data.get('alerts', [])
        if not alerts:
            return {'dast_issues': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        
        issues = len(alerts)
        severity_counts = {'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        
        for alert in alerts:
            if isinstance(alert, dict):
                # ZAP uses 'risk' field with values: High, Medium, Low, Informational
                risk = alert.get('risk', 'Medium').lower()
                
                if risk in ['high', 'critical']:
                    severity_counts['high'] += 1
                elif risk in ['medium', 'moderate']:
                    severity_counts['medium'] += 1
                elif risk in ['low', 'minor']:
                    severity_counts['low'] += 1
                elif risk in ['informational', 'info']:
                    severity_counts['info'] += 1
                else:
                    # Default to medium for unknown risk
                    severity_counts['medium'] += 1
            else:
                # If alert is not a dict (unexpected format), count as medium
                severity_counts['medium'] += 1
        
        return {
            'dast_issues': issues,
            **severity_counts
        }
        
    except (json.JSONDecodeError, KeyError, TypeError) as e:
        print(f"Warning: Could not parse ZAP results: {e}")
        return {'dast_issues': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}

def combine_security_results(pip_audit_results, bandit_results, zap_results=None):
    """Combine pip-audit, bandit, and ZAP results into unified security summary"""
    if zap_results is None:
        zap_results = {'dast_issues': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    
    return {
        'total_issues': pip_audit_results.get('vulnerabilities', 0) + bandit_results.get('issues', 0) + zap_results.get('dast_issues', 0),
        'vulnerabilities': pip_audit_results.get('vulnerabilities', 0),
        'code_issues': bandit_results.get('issues', 0),
        'dast_issues': zap_results.get('dast_issues', 0),
        'high': pip_audit_results.get('high', 0) + bandit_results.get('high', 0) + zap_results.get('high', 0),
        'medium': pip_audit_results.get('medium', 0) + bandit_results.get('medium', 0) + zap_results.get('medium', 0),
        'low': pip_audit_results.get('low', 0) + bandit_results.get('low', 0) + zap_results.get('low', 0),
        'info': zap_results.get('info', 0),
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
