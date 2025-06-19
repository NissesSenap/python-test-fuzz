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
    
    if security_results.get('vulnerabilities', 0) == 0:
        summary += "✅ **No vulnerabilities found**\n\n"
    else:
        summary += f"⚠️ **{security_results['vulnerabilities']} vulnerabilities found**\n\n"
        
        if security_results.get('high', 0) > 0:
            summary += f"- 🔴 **High**: {security_results['high']}\n"
        if security_results.get('medium', 0) > 0:
            summary += f"- 🟡 **Medium**: {security_results['medium']}\n"
        if security_results.get('low', 0) > 0:
            summary += f"- 🟢 **Low**: {security_results['low']}\n"
    
    # Add recommendations
    if test_results.get('failed', 0) > 0 or security_results.get('vulnerabilities', 0) > 0:
        summary += "\n## 🔧 Recommendations\n\n"
        
        if test_results.get('failed', 0) > 0:
            summary += "- Review failing tests and fix API issues\n"
            summary += "- Check server logs for detailed error information\n"
        
        if security_results.get('vulnerabilities', 0) > 0:
            summary += "- Update vulnerable dependencies\n"
            summary += "- Review security scan report for details\n"
    
    return summary

def generate_pr_comment(test_results, security_results, pr_number):
    """Generate PR comment content"""
    
    # Determine overall status
    if test_results.get('failed', 0) == 0 and security_results.get('vulnerabilities', 0) == 0:
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
    
    if security_results.get('vulnerabilities', 0) == 0:
        comment += "✅ No vulnerabilities detected\n"
    else:
        comment += f"⚠️ {security_results['vulnerabilities']} vulnerabilities found:\n\n"
        comment += "| Severity | Count |\n|----------|-------|\n"
        if security_results.get('high', 0) > 0:
            comment += f"| 🔴 High | {security_results['high']} |\n"
        if security_results.get('medium', 0) > 0:
            comment += f"| 🟡 Medium | {security_results['medium']} |\n"
        if security_results.get('low', 0) > 0:
            comment += f"| 🟢 Low | {security_results['low']} |\n"
    
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
            data = json.load(f)
        
        if not data:
            return {'vulnerabilities': 0, 'high': 0, 'medium': 0, 'low': 0}
        
        vulnerabilities = len(data)
        severity_counts = {'high': 0, 'medium': 0, 'low': 0}
        
        for vuln in data:
            # pip-audit doesn't always include severity, so we'll estimate based on CVSS if available
            severity = vuln.get('severity', 'unknown').lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
            else:
                # Default to medium if unknown
                severity_counts['medium'] += 1
        
        return {
            'vulnerabilities': vulnerabilities,
            **severity_counts
        }
    except (json.JSONDecodeError, KeyError):
        return {'vulnerabilities': 0, 'high': 0, 'medium': 0, 'low': 0}

def main():
    """Main function to generate PR outputs"""
    
    # Parse command line arguments
    if len(sys.argv) < 2:
        print("Usage: python generate_pr_output.py <action> [pytest_results.json] [pip_audit_results.json]")
        print("Actions: summary, comment")
        sys.exit(1)
    
    action = sys.argv[1]
    pytest_file = sys.argv[2] if len(sys.argv) > 2 else "reports/pytest-results.json"
    pip_audit_file = sys.argv[3] if len(sys.argv) > 3 else "reports/pip-audit-report.json"
    
    # Parse test results
    test_results = parse_pytest_results(pytest_file)
    security_results = parse_pip_audit_results(pip_audit_file)
    
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
