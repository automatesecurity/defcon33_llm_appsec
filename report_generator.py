import json
from datetime import datetime
import uuid

def generate_html_report(findings: dict, output_path: str = "sast_report.html"):
    """
    Generates a beautiful, self-contained HTML report from SAST findings.

    Args:
        findings (dict): The structured findings from the SAST analyzer.
        output_path (str): The path to save the HTML report.
    """
    report_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Aggregate all validated vulnerabilities
    all_vulnerabilities = []
    for category, files in findings.items():
        for file_path, file_data in files.items():
            if "validated_vulnerabilities" in file_data and file_data["validated_vulnerabilities"]:
                for vuln in file_data["validated_vulnerabilities"]:
                    vuln_data = vuln.copy()
                    vuln_data['category'] = category.replace('_', ' ').title()
                    vuln_data['id'] = str(uuid.uuid4()) # Unique ID for ARIA attributes
                    all_vulnerabilities.append(vuln_data)

    # Sort vulnerabilities by severity (Critical -> High -> Medium -> Low)
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    all_vulnerabilities.sort(key=lambda v: severity_order.get(v.get('severity', 'UNKNOWN'), 4))

    # Calculate summary statistics
    total_vulns = len(all_vulnerabilities)
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    category_counts = {}

    for vuln in all_vulnerabilities:
        severity = vuln.get('severity', 'UNKNOWN')
        if severity in severity_counts:
            severity_counts[severity] += 1
        
        category = vuln.get('category', 'Uncategorized')
        category_counts[category] = category_counts.get(category, 0) + 1

    html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SAST Security Analysis Report</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/tokyo-night-dark.min.css">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: #1a1b26; /* Tokyo Night Background */
            color: #c0caf5; /* Brighter foreground for better contrast */
            margin: 0;
            padding: 20px;
            font-size: 16px;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: #1f2335;
            border: 1px solid #414868;
            border-radius: 8px;
            padding: 24px;
        }}
        header {{
            border-bottom: 1px solid #414868;
            padding-bottom: 16px;
            margin-bottom: 24px;
        }}
        header h1 {{
            font-size: 32px;
            font-weight: 700;
            margin: 0;
            color: #c0caf5;
        }}
        header p {{
            margin: 4px 0 0;
            color: #7aa2f7; /* Brighter subtext */
            font-size: 18px;
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 20px;
            margin-bottom: 24px;
        }}
        .summary-card {{
            background-color: #24283b;
            border: 1px solid #414868;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
        }}
        .summary-card .count {{
            font-size: 42px;
            font-weight: 700;
            margin: 0;
        }}
        .summary-card .label {{
            font-size: 16px;
            color: #7aa2f7;
            margin: 4px 0 0;
            font-weight: 500;
        }}
        .severity-CRITICAL .count {{ color: #f7768e; }}
        .severity-HIGH .count {{ color: #ff9e64; }}
        .severity-MEDIUM .count {{ color: #e0af68; }}
        .severity-LOW .count {{ color: #9ece6a; }}

        .findings-section h2 {{
            font-size: 28px;
            font-weight: 700;
            border-bottom: 1px solid #414868;
            padding-bottom: 8px;
            margin-top: 32px;
            color: #c0caf5;
        }}
        .finding-card {{
            border: 1px solid #414868;
            border-radius: 8px;
            margin-bottom: 20px;
            overflow: hidden;
            background-color: #24283b;
        }}
        .finding-header {{
            background-color: #292e42;
            padding: 16px 20px;
            border-bottom: 1px solid #414868;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .finding-header h3 {{
            font-size: 20px;
            font-weight: 700;
            margin: 0;
            color: #c0caf5;
        }}
        .severity-badge {{
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 14px;
            font-weight: 700;
            text-transform: uppercase;
            color: #1a1b26;
        }}
        .severity-badge-CRITICAL {{ background-color: #f7768e; }}
        .severity-badge-HIGH {{ background-color: #ff9e64; }}
        .severity-badge-MEDIUM {{ background-color: #e0af68; }}
        .severity-badge-LOW {{ background-color: #9ece6a; }}
        .severity-badge-UNKNOWN {{ background-color: #565f89; color: #c0caf5; }}

        .finding-body {{
            padding: 20px;
        }}
        .finding-body p {{
            margin: 0 0 14px;
            font-size: 16px;
        }}
        .finding-body strong {{
            color: #7aa2f7;
            font-weight: 600;
        }}
        .file-path {{
            font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, Courier, monospace;
            font-size: 15px;
            background-color: #414868;
            color: #c0caf5;
            padding: 4px 8px;
            border-radius: 4px;
        }}
        pre {{
            margin: 0;
            border-radius: 6px;
            overflow: auto;
            background: #1a1b26;
        }}
        code.hljs {{
            padding: 16px;
            font-size: 15px;
            background: transparent;
        }}
    </style>
</head>
<body>
    <div class="container" role="main">
        <header>
            <h1>SAST Security Analysis Report</h1>
            <p>Generated on: {report_date}</p>
        </header>

        <section class="summary" role="region" aria-labelledby="summary-heading">
            <h2 id="summary-heading" class="visually-hidden">Vulnerability Summary</h2>
            <div class="summary-grid">
                <div class="summary-card">
                    <p class="count">{total_vulns}</p>
                    <p class="label">Total Vulnerabilities</p>
                </div>
                <div class="summary-card severity-CRITICAL">
                    <p class="count">{severity_counts['CRITICAL']}</p>
                    <p class="label">Critical</p>
                </div>
                <div class="summary-card severity-HIGH">
                    <p class="count">{severity_counts['HIGH']}</p>
                    <p class="label">High</p>
                </div>
                <div class="summary-card severity-MEDIUM">
                    <p class="count">{severity_counts['MEDIUM']}</p>
                    <p class="label">Medium</p>
                </div>
                <div class="summary-card severity-LOW">
                    <p class="count">{severity_counts['LOW']}</p>
                    <p class="label">Low</p>
                </div>
            </div>
        </section>

        <section class="findings-section" role="region" aria-labelledby="findings-heading">
            <h2 id="findings-heading">Detailed Findings</h2>
            {''.join([generate_finding_card(v) for v in all_vulnerabilities]) if all_vulnerabilities else '<p>No vulnerabilities found.</p>'}
        </section>
    </div>
    <script>hljs.highlightAll();</script>
    <style>.visually-hidden {{ position: absolute; width: 1px; height: 1px; margin: -1px; padding: 0; overflow: hidden; clip: rect(0, 0, 0, 0); border: 0; }}</style>
</body>
</html>
    """
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    print(f"Successfully generated HTML report at: {output_path}")

def generate_finding_card(vuln: dict) -> str:
    """Generates the HTML for a single vulnerability card."""
    vuln_id = vuln.get('id')
    severity = vuln.get('severity', 'UNKNOWN')
    description = vuln.get('description', 'No description provided.')
    category = vuln.get('category', 'Uncategorized')
    file_path = vuln.get('file_path', 'Unknown file')
    line_numbers = vuln.get('line_numbers', [])
    lines_str = f":{', '.join(map(str, line_numbers))}" if line_numbers else ""
    code_snippet = vuln.get('code_snippet', 'No code snippet available.')
    explanation = vuln.get('explanation', 'No explanation provided.')

    lang_map = {
        '.js': 'javascript', '.py': 'python', '.java': 'java', '.php': 'php',
        '.c': 'c', '.cpp': 'cpp', '.h': 'c', '.cs': 'csharp', '.go': 'go',
        '.rb': 'ruby', '.rs': 'rust', '.ts': 'typescript'
    }
    lang = next((lang_map[ext] for ext in lang_map if file_path.endswith(ext)), 'plaintext')

    return f"""
<article class="finding-card" role="article" aria-labelledby="finding-heading-{vuln_id}">
    <div class="finding-header">
        <h3 id="finding-heading-{vuln_id}">{description}</h3>
        <span class="severity-badge severity-badge-{severity}">{severity}</span>
    </div>
    <div class="finding-body">
        <p><strong>Category:</strong> {category}</p>
        <p><strong>File:</strong> <span class="file-path">{file_path}{lines_str}</span></p>
        <p><strong>Explanation:</strong> {explanation}</p>
        <strong>Code Snippet:</strong>
        <pre><code class="language-{lang}">{code_snippet}</code></pre>
    </div>
</article>
"""

def create_sample_report():
    """Creates a sample report with dummy data."""
    sample_findings = {
        "A03_injection": {
            "repo/vulnerabilities/sqli/index.php": {
                "validated_vulnerabilities": [
                    {
                        "file_path": "repo/vulnerabilities/sqli/index.php",
                        "validated": True,
                        "severity": "CRITICAL",
                        "description": "SQL Injection vulnerability",
                        "line_numbers": [90, 91],
                        "code_snippet": '''$query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
$result = mysqli_query($GLOBALS["___mysqli_ston"], $query) or die('<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : null)) . '</pre>' );''',
                        "explanation": "The user-provided 'id' parameter is directly concatenated into the SQL query, allowing an attacker to manipulate the query and execute arbitrary SQL commands."
                    }
                ]
            }
        },
        "A01_broken_access_control": {
            "repo/vulnerabilities/fi/include.php": {
                 "validated_vulnerabilities": [
                    {
                        "file_path": "repo/vulnerabilities/fi/include.php",
                        "validated": True,
                        "severity": "HIGH",
                        "description": "Path Traversal vulnerability",
                        "line_numbers": [23],
                        "code_snippet": "include( $_GET[ 'page' ] );",
                        "explanation": "The 'page' parameter is taken from the user input and used directly in an 'include' statement without proper sanitization. This can allow an attacker to include arbitrary files from the server's filesystem."
                    }
                ]
            }
        },
        "A02_cryptographic_failures": {
            "repo/vulnerabilities/exec/index.php": {
                "validated_vulnerabilities": [
                    {
                        "file_path": "repo/vulnerabilities/exec/index.php",
                        "validated": True,
                        "severity": "MEDIUM",
                        "description": "Use of Weak Hashing Algorithm",
                        "line_numbers": [],
                        "code_snippet": "$token = md5( uniqid( rand(), true ) );",
                        "explanation": "The code uses md5 to generate a token. MD5 is a weak hashing algorithm and is not suitable for security-sensitive applications like token generation."
                    }
                ]
            }
        }
    }
    generate_html_report(sample_findings, "./sample_sast_report.html")

if __name__ == '__main__':
    create_sample_report()
