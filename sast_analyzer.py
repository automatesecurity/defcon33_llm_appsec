import os
import json # not needed for now - maybe for future pipeline dashboard ingestion
import asyncio
import aiofiles
import time
import random
from typing import Dict, List, Any
from pathlib import Path
from langchain_aws import ChatBedrock
from langchain.agents import create_react_agent, AgentExecutor
from langchain.tools import Tool
from langchain import hub
from langchain_core.prompts import PromptTemplate
from botocore.exceptions import ClientError


class OWASPTop10Instructions:
    """OWASP Top 10 2021 instruction sets for SAST analysis."""
    
    @staticmethod
    def get_all_instructions() -> Dict[str, str]:
        return {
            "A01_broken_access_control": OWASPTop10Instructions.a01_broken_access_control(),
            "A02_cryptographic_failures": OWASPTop10Instructions.a02_cryptographic_failures(),
            "A03_injection": OWASPTop10Instructions.a03_injection(),
            "A04_insecure_design": OWASPTop10Instructions.a04_insecure_design(),
            "A05_security_misconfiguration": OWASPTop10Instructions.a05_security_misconfiguration(),
            "A06_vulnerable_components": OWASPTop10Instructions.a06_vulnerable_components(),
            "A07_identification_failures": OWASPTop10Instructions.a07_identification_failures(),
            "A08_software_integrity_failures": OWASPTop10Instructions.a08_software_integrity_failures(),
            "A09_security_logging_failures": OWASPTop10Instructions.a09_security_logging_failures(),
            "A10_server_side_request_forgery": OWASPTop10Instructions.a10_server_side_request_forgery()
        }
    
    @staticmethod
    def a01_broken_access_control() -> str:
        return """
You are analyzing code for A01: Broken Access Control vulnerabilities.

Focus on identifying:
1. Missing authorization checks before accessing resources
2. Bypass of access control checks through parameter manipulation
3. Privilege escalation vulnerabilities
4. CORS misconfigurations allowing unauthorized API access
5. Force browsing to authenticated pages as unauthenticated user
6. Accessing API with missing access controls for POST, PUT, DELETE
7. Elevation of privilege (acting as user without being logged in, or acting as admin when logged in as user)
8. Metadata manipulation (replaying or tampering with JWT tokens, cookies, or hidden fields)

Look for patterns like:
- Direct object references without authorization
- Missing role-based access controls
- Insecure direct object references (IDOR)
- Path traversal vulnerabilities
- Unvalidated redirects and forwards

Return findings with file paths, line numbers, and detailed explanations.
"""

    @staticmethod
    def a02_cryptographic_failures() -> str:
        return """
You are analyzing code for A02: Cryptographic Failures vulnerabilities.

Focus on identifying:
1. Transmission of sensitive data in clear text (HTTP, SMTP, FTP)
2. Use of old or weak cryptographic algorithms (MD5, SHA1, DES, RC4)
3. Default crypto keys in use, weak crypto keys generated/re-used
4. Missing crypto validation on user-agent certificates
5. Weak random number generation
6. Hardcoded passwords, API keys, or crypto keys
7. Improper certificate validation
8. Missing encryption of sensitive data at rest
9. Weak password hashing functions

Look for patterns like:
- HTTP instead of HTTPS
- Weak encryption algorithms or modes
- Hardcoded cryptographic keys or passwords
- Weak random number generators
- Missing salt in password hashing
- Insecure storage of sensitive data

Return findings with file paths, line numbers, and detailed explanations.
"""

    @staticmethod
    def a03_injection() -> str:
        return """
You are analyzing code for A03: Injection vulnerabilities.

Focus on identifying:
1. SQL injection through unsanitized user input
2. NoSQL injection vulnerabilities
3. OS command injection
4. LDAP injection
5. XPath injection
6. XML injection
7. Code injection (eval, exec functions)
8. Template injection
9. Log injection

Look for patterns like:
- Dynamic SQL queries with string concatenation
- Unsanitized user input in database queries
- Use of eval(), exec(), or similar dangerous functions
- System command execution with user input
- Template rendering with user-controlled data
- Logging user input without sanitization
- Missing input validation and parameterized queries

Return findings with file paths, line numbers, and detailed explanations.
"""

    @staticmethod
    def a04_insecure_design() -> str:
        return """
You are analyzing code for A04: Insecure Design vulnerabilities.

Focus on identifying:
1. Missing or ineffective control design flaws
2. Lack of business logic validation
3. Missing rate limiting or throttling
4. Trust boundaries not properly defined
5. Insufficient workflow validation
6. Missing security controls in design
7. Overprivileged access patterns
8. Insecure default configurations

Look for patterns like:
- Business logic that can be bypassed
- Missing rate limiting on sensitive operations
- Workflows that don't validate state transitions
- Privileged operations without proper checks
- Default configurations that are insecure
- Missing threat modeling considerations
- Architectural security flaws

Return findings with file paths, line numbers, and detailed explanations.
"""

    @staticmethod
    def a05_security_misconfiguration() -> str:
        return """
You are analyzing code for A05: Security Misconfiguration vulnerabilities.

Focus on identifying:
1. Missing security hardening configurations
2. Improperly configured permissions on cloud services
3. Unnecessary features enabled (ports, services, pages, accounts, privileges)
4. Default accounts and passwords unchanged
5. Error handling revealing stack traces or sensitive information
6. Security settings in frameworks/libraries not set to secure values
7. Missing security headers
8. Directory listings enabled

Look for patterns like:
- Debug mode enabled in production
- Verbose error messages exposing internals
- Missing security headers (HSTS, CSP, etc.)
- Default configurations not changed
- Unnecessary services or endpoints enabled
- Insufficient logging and monitoring
- Improper file permissions

Return findings with file paths, line numbers, and detailed explanations.
"""

    @staticmethod
    def a06_vulnerable_components() -> str:
        return """
You are analyzing code for A06: Vulnerable and Outdated Components vulnerabilities.

Focus on identifying:
1. Outdated or vulnerable third-party libraries
2. Components with known security vulnerabilities
3. Unsupported or end-of-life components
4. Components from untrusted sources
5. Missing security patches
6. Unused dependencies that increase attack surface

Look for patterns like:
- Old versions of frameworks and libraries
- Dependencies with known CVEs
- Packages from unofficial sources
- Unused or unnecessary dependencies
- Missing dependency scanning
- Lack of component inventory
- Auto-generated or copied code with vulnerabilities

Return findings with file paths, line numbers, and detailed explanations.
"""

    @staticmethod
    def a07_identification_failures() -> str:
        return """
You are analyzing code for A07: Identification and Authentication Failures vulnerabilities.

Focus on identifying:
1. Weak password requirements or policies
2. Missing multi-factor authentication for high-value accounts
3. Session management flaws
4. Credential stuffing vulnerabilities
5. Weak session generation and management
6. Missing account lockout or rate limiting
7. Passwords stored using weak hashing
8. Insecure password recovery mechanisms

Look for patterns like:
- Weak password validation
- Session tokens that are predictable
- Session fixation vulnerabilities
- Missing session timeout
- Credentials transmitted over insecure channels
- Brute force attack vulnerabilities
- Weak account recovery processes
- Session tokens in URLs

Return findings with file paths, line numbers, and detailed explanations.
"""

    @staticmethod
    def a08_software_integrity_failures() -> str:
        return """
You are analyzing code for A08: Software and Data Integrity Failures vulnerabilities.

Focus on identifying:
1. Insecure deserialization vulnerabilities
2. Missing integrity checks on critical data
3. Auto-update functionality without integrity verification
4. Untrusted sources for libraries or plugins
5. Insecure CI/CD pipelines
6. Missing code signing verification
7. Supply chain attack vectors

Look for patterns like:
- Deserialization of untrusted data
- Missing integrity checks on downloads
- Unsigned code or components
- Insecure plugin architectures
- CI/CD secrets exposure
- Missing supply chain security controls
- Tampering detection mechanisms absent
- Third-party content without validation

Return findings with file paths, line numbers, and detailed explanations.
"""

    @staticmethod
    def a09_security_logging_failures() -> str:
        return """
You are analyzing code for A09: Security Logging and Monitoring Failures vulnerabilities.

Focus on identifying:
1. Missing logging of security-relevant events
2. Insufficient log detail for forensics
3. Logs stored insecurely or without integrity protection
4. Missing real-time monitoring and alerting
5. Log injection vulnerabilities
6. Sensitive data in logs
7. Missing audit trails for critical operations
8. Inadequate incident response capabilities

Look for patterns like:
- Authentication failures not logged
- High-value transactions without audit trails
- Logs containing sensitive information
- Missing monitoring for suspicious patterns
- Log files with weak access controls
- Insufficient log retention policies
- Missing alerting on security events
- No centralized logging infrastructure

Return findings with file paths, line numbers, and detailed explanations.
"""

    @staticmethod
    def a10_server_side_request_forgery() -> str:
        return """
You are analyzing code for A10: Server-Side Request Forgery (SSRF) vulnerabilities.

Focus on identifying:
1. User-controlled URLs in server-side requests
2. Missing URL validation and sanitization
3. Access to internal/private network resources
4. Cloud metadata service access
5. File:// protocol access
6. Blind SSRF vulnerabilities
7. DNS rebinding attack vectors

Look for patterns like:
- HTTP requests with user-provided URLs
- Missing allowlist validation for URLs
- Requests to localhost or private IP ranges
- Cloud metadata endpoints accessible
- File protocol usage with user input
- DNS lookups with user-controlled data
- Missing network segmentation considerations
- URL parsing vulnerabilities

Return findings with file paths, line numbers, and detailed explanations.
"""


class SASTAnalyzer:
    def __init__(self, repo_path: str = "./repo", llm=None, max_concurrent_requests: int = 8):
        self.repo_path = repo_path
        self.llm = llm
        self.owasp_instructions = OWASPTop10Instructions.get_all_instructions()
        self.findings = {}
        self.max_concurrent_requests = max_concurrent_requests
        self.semaphore = asyncio.Semaphore(max_concurrent_requests)
        self.request_count = 0
        self.throttle_delay = 0.1  # Base delay between requests
        
    def get_source_files(self) -> List[str]:
        """Get list of source code files to analyze."""
        source_extensions = {
            '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.c', '.cpp', 
            '.h', '.hpp', '.cs', '.php', '.rb', '.go', '.rs', '.scala'
        }
        
        source_files = []
        for root, dirs, files in os.walk(self.repo_path):
            # Skip common non-source directories
            dirs[:] = [d for d in dirs if d not in {'.git', 'node_modules', '__pycache__', '.pytest_cache', 'venv', 'env'}]
            
            for file in files:
                if Path(file).suffix.lower() in source_extensions:
                    source_files.append(os.path.join(root, file))
        
        return source_files[:50]  # Limit to first 50 files for performance
    
    async def read_file_content(self, file_path: str) -> str:
        """Read and return file content safely using async I/O."""
        try:
            async with aiofiles.open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return await f.read()
        except Exception as e:
            return f"Error reading file: {str(e)}"
    
    def _extract_issues_from_analysis(self, analysis_result: str, file_path: str, category: str) -> List[str]:
        """Extract key issues from the analysis result for immediate reporting."""
        issues = []
        
        if not analysis_result or len(analysis_result.strip()) < 50:
            return issues
        
        # Look for common indicators of security issues
        issue_indicators = [
            "vulnerability", "vulnerable", "security risk", "exploit", "attack",
            "injection", "XSS", "SQL injection", "buffer overflow", "path traversal",
            "insecure", "weak", "missing validation", "hardcoded", "exposed",
            "critical", "high risk", "medium risk", "low risk"
        ]
        
        lines = analysis_result.split('\n')
        current_issue = []
        
        for line in lines:
            line = line.strip()
            if not line:
                if current_issue:
                    issues.append(' '.join(current_issue))
                    current_issue = []
                continue
            
            # Check if line contains issue indicators
            line_lower = line.lower()
            if any(indicator in line_lower for indicator in issue_indicators):
                # Look for lines that describe specific issues
                if any(word in line_lower for word in ["found", "detected", "identified", "line", "risk"]):
                    if len(line) < 200:  # Keep it concise
                        issues.append(line)
                elif current_issue and len(' '.join(current_issue + [line])) < 150:
                    current_issue.append(line)
                elif not current_issue:
                    current_issue.append(line)
            elif current_issue and len(' '.join(current_issue + [line])) < 150:
                current_issue.append(line)
            elif current_issue:
                issues.append(' '.join(current_issue))
                current_issue = []
        
        # Add any remaining issue
        if current_issue:
            issues.append(' '.join(current_issue))
        
        # Remove duplicates and filter out generic statements
        unique_issues = []
        seen = set()
        
        for issue in issues:
            issue_clean = issue.strip().rstrip('.').rstrip(',')
            if (issue_clean not in seen and 
                len(issue_clean) > 20 and 
                not issue_clean.lower().startswith('analyze') and
                not issue_clean.lower().startswith('focus on')):
                unique_issues.append(issue_clean)
                seen.add(issue_clean)
        
        return unique_issues[:5]  # Return top 5 issues
    
    async def _exponential_backoff_llm_call(self, prompt: str, max_retries: int = 3) -> str:
        """Make LLM call with exponential backoff for throttling."""
        for attempt in range(max_retries + 1):
            try:
                async with self.semaphore:
                    # Add small delay to prevent overwhelming the API
                    await asyncio.sleep(self.throttle_delay)
                    
                    self.request_count += 1
                    if self.request_count % 10 == 0:
                        print(f"    API requests made: {self.request_count}")
                    
                    response = self.llm.invoke(prompt)
                    
                    if hasattr(response, 'content'):
                        return response.content
                    else:
                        return str(response)
                        
            except ClientError as e:
                error_code = e.response['Error']['Code']
                if error_code in ['ThrottlingException', 'TooManyRequestsException'] and attempt < max_retries:
                    wait_time = (2 ** attempt) + random.uniform(0, 1)
                    print(f"    Throttling detected, waiting {wait_time:.1f}s (attempt {attempt + 1}/{max_retries + 1})")
                    await asyncio.sleep(wait_time)
                    continue
                else:
                    raise e
            except Exception as e:
                if attempt < max_retries:
                    wait_time = (2 ** attempt) + random.uniform(0, 1)
                    print(f"    Error in LLM call, retrying in {wait_time:.1f}s: {str(e)[:100]}")
                    await asyncio.sleep(wait_time)
                    continue
                else:
                    raise e
        
        raise Exception(f"Max retries ({max_retries}) exceeded for LLM call")
    
    async def _validate_and_enhance_issue(self, issue_description: str, file_path: str, content: str, category: str) -> Dict:
        """Validate an issue and enhance it with line numbers and code context."""
        if not self.llm or len(content.strip()) < 20:
            return None
        
        # Create a focused validation prompt
        validation_prompt = f"""
You are a security expert validating a potential vulnerability. 

TASK: Examine the following code and determine if the reported issue is a legitimate security vulnerability.

REPORTED ISSUE: {issue_description}
CATEGORY: {category}
FILE: {file_path}

CODE TO ANALYZE:
```
{content}
```

INSTRUCTIONS:
1. If this is a real security vulnerability, respond with: "CONFIRMED"
2. If this is a false positive or not a vulnerability, respond with: "FALSE_POSITIVE"
3. After your determination, provide:
   - Severity level (CRITICAL/HIGH/MEDIUM/LOW)
   - Exact description of the vulnerability (1-2 sentences)
   - Line number(s) where the vulnerability exists (if identifiable)
   - Code snippet showing the vulnerable code (1-3 lines max)
   - Brief explanation of why this is vulnerable

FORMAT YOUR RESPONSE AS:
STATUS: [CONFIRMED/FALSE_POSITIVE]
SEVERITY: [CRITICAL/HIGH/MEDIUM/LOW]
DESCRIPTION: [Brief description]
LINES: [comma-separated line numbers or "unknown"]
CODE: [vulnerable code snippet or "not found"]
EXPLANATION: [brief explanation]
"""
        
        try:
            # Use LLM to validate the issue with backoff
            validation_result = await self._exponential_backoff_llm_call(validation_prompt)
            
            # Parse the validation response
            return self._parse_validation_response(validation_result, file_path, content)
            
        except Exception as e:
            print(f"        ⚠️ Validation error: {str(e)}")
            return None
    
    def _parse_validation_response(self, response: str, file_path: str, content: str) -> Dict:
        """Parse the validation response and extract structured information."""
        lines = response.split('\n')
        result = {
            'file_path': file_path,
            'validated': False,
            'severity': 'UNKNOWN',
            'description': '',
            'line_numbers': [],
            'code_snippet': '',
            'explanation': ''
        }
        
        for line in lines:
            line = line.strip()
            if line.startswith('STATUS:'):
                status = line.split('STATUS:')[1].strip().upper()
                result['validated'] = (status == 'CONFIRMED')
            elif line.startswith('SEVERITY:'):
                result['severity'] = line.split('SEVERITY:')[1].strip().upper()
            elif line.startswith('DESCRIPTION:'):
                result['description'] = line.split('DESCRIPTION:')[1].strip()
            elif line.startswith('LINES:'):
                lines_text = line.split('LINES:')[1].strip()
                if lines_text != 'unknown' and lines_text != 'not found':
                    try:
                        # Parse line numbers (could be "1,2,3" or "1-3" or "1")
                        if ',' in lines_text:
                            result['line_numbers'] = [int(x.strip()) for x in lines_text.split(',') if x.strip().isdigit()]
                        elif '-' in lines_text:
                            parts = lines_text.split('-')
                            if len(parts) == 2 and parts[0].strip().isdigit() and parts[1].strip().isdigit():
                                start, end = int(parts[0].strip()), int(parts[1].strip())
                                result['line_numbers'] = list(range(start, min(end + 1, start + 5)))  # Limit range
                        elif lines_text.isdigit():
                            result['line_numbers'] = [int(lines_text)]
                    except ValueError:
                        pass
            elif line.startswith('CODE:'):
                code_text = line.split('CODE:')[1].strip()
                if code_text not in ['not found', 'unknown', '']:
                    result['code_snippet'] = code_text
            elif line.startswith('EXPLANATION:'):
                result['explanation'] = line.split('EXPLANATION:')[1].strip()
        
        # If we have line numbers but no code snippet, try to extract from source
        if result['line_numbers'] and not result['code_snippet']:
            result['code_snippet'] = self._extract_code_at_lines(content, result['line_numbers'])
        
        # Only return if confirmed as vulnerability
        if result['validated'] and result['description']:
            return result
        
        return None
    
    def _extract_code_at_lines(self, content: str, line_numbers: List[int]) -> str:
        """Extract code snippet at specified line numbers."""
        try:
            lines = content.split('\n')
            code_lines = []
            
            for line_num in sorted(line_numbers[:3]):  # Max 3 lines
                if 1 <= line_num <= len(lines):
                    code_lines.append(f"{line_num}: {lines[line_num - 1].strip()}")
            
            return '; '.join(code_lines)
        except Exception:
            return ""
    
    async def _analyze_single_file(self, file_path: str, category: str, instruction: str, file_index: int, total_files: int) -> tuple:
        """Analyze a single file for OWASP vulnerabilities."""
        print(f"    [{file_index}/{total_files}] Analyzing: {os.path.basename(file_path)}")
        
        try:
            content = await self.read_file_content(file_path)
            if len(content) > 50000:  # Limit content size
                content = content[:50000] + "\n... (truncated)"
            
            analysis_prompt = f"""
{instruction}

Analyze the following code file for vulnerabilities:

File: {file_path}
Content:
```
{content}
```

Provide specific findings with:
1. Vulnerability type
2. Line numbers (approximate if needed)
3. Code snippets showing the issue
4. Risk level (Critical/High/Medium/Low)
5. Remediation recommendations
"""
            
            # Use the LLM to analyze the file with backoff
            analysis_result = await self._exponential_backoff_llm_call(analysis_prompt)
            
            finding = {
                "category": category,
                "analysis": analysis_result,
                "timestamp": "now"  # Could use actual timestamp
            }
            
            # Check for and validate issues found in this file
            issues_found = self._extract_issues_from_analysis(analysis_result, file_path, category)
            validated_issues = []
            
            if issues_found:
                print(f"    {len(issues_found)} potential issue(s) found in {os.path.basename(file_path)}, validating...")
                
                # Validate issues concurrently but with limited concurrency per file
                validation_tasks = []
                for issue in issues_found:
                    validation_tasks.append(
                        self._validate_and_enhance_issue(issue, file_path, content, category)
                    )
                
                # Process validations with limited concurrency
                validation_results = await asyncio.gather(*validation_tasks, return_exceptions=True)
                
                for result in validation_results:
                    if not isinstance(result, Exception) and result:
                        validated_issues.append(result)
                
                if validated_issues:
                    print(f"    ⚠️  {len(validated_issues)} CONFIRMED vulnerability(ies) in {os.path.basename(file_path)}:")
                    for issue in validated_issues[:3]:  # Show first 3 validated issues
                        print(f"         * {issue['severity']}: {issue['description']}")
                        print(f"           File: {issue['file_path']}")
                        if issue.get('line_numbers'):
                            print(f"           Lines: {', '.join(map(str, issue['line_numbers']))}")
                        if issue.get('code_snippet'):
                            print(f"           Code: {issue['code_snippet'][:100]}...")
                    
                    if len(validated_issues) > 3:
                        print(f"        ... and {len(validated_issues) - 3} more confirmed vulnerability(ies)")
                    
                    finding['validated_vulnerabilities'] = validated_issues
                else:
                    print(f"    ✓ No vulnerabilities confirmed after validation in {os.path.basename(file_path)}")
            else:
                print(f"    ✓ No issues found in {os.path.basename(file_path)}")
            
            return file_path, finding
            
        except Exception as e:
            error_finding = {
                "category": category,
                "error": str(e)
            }
            print(f"    ✗ Error analyzing {os.path.basename(file_path)}: {str(e)}")
            return file_path, error_finding
    
    async def analyze_with_owasp_category(self, category: str, source_files: List[str]) -> Dict:
        """Analyze source files for a specific OWASP category using async processing."""
        if not self.llm:
            return {"error": "No LLM instance provided"}
        
        instruction = self.owasp_instructions.get(category, "")
        if not instruction:
            return {"error": f"Unknown OWASP category: {category}"}
        
        files_to_analyze = source_files[:10]  # Limit files per category
        
        print(f"  → Analyzing {len(files_to_analyze)} files for {category} (max {self.max_concurrent_requests} concurrent)")
        
        # Create tasks for concurrent file analysis
        tasks = []
        for i, file_path in enumerate(files_to_analyze, 1):
            task = self._analyze_single_file(file_path, category, instruction, i, len(files_to_analyze))
            tasks.append(task)
        
        # Process files concurrently with error handling
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Collect findings from results
        findings = {}
        for result in results:
            if isinstance(result, Exception):
                print(f"    ✗ Unexpected error in file analysis: {str(result)}")
                continue
            
            file_path, finding = result
            findings[file_path] = finding
        
        return findings
    
    async def run_full_analysis(self) -> Dict:
        """Run complete SAST analysis across all OWASP Top 10 categories using async processing."""
        if not self.llm:
            return {"error": "No LLM instance provided"}
        
        source_files = self.get_source_files()
        
        print(f"Starting async SAST analysis on {len(source_files)} source files...")
        print(f"Will analyze across {len(self.owasp_instructions)} OWASP Top 10 categories")
        print(f"Max concurrent requests: {self.max_concurrent_requests}")
        print()
        
        start_time = time.time()
        total_categories = len(self.owasp_instructions)
        
        # Process categories sequentially to avoid overwhelming the API
        # But within each category, process files concurrently
        all_findings = {}
        
        for i, (category, instruction) in enumerate(self.owasp_instructions.items(), 1):
            print(f"[{i}/{total_categories}] Analyzing for {category.replace('_', ' ').title()}...")
            category_start = time.time()
            
            category_findings = await self.analyze_with_owasp_category(category, source_files)
            all_findings[category] = category_findings
            
            category_time = time.time() - category_start
            
            # Show progress summary for this category
            files_analyzed = len([f for f in category_findings.values() if "analysis" in f])
            files_with_errors = len([f for f in category_findings.values() if "error" in f])
            
            # Count validated vulnerabilities in this category
            total_vulnerabilities = 0
            files_with_vulnerabilities = 0
            for file_path, finding in category_findings.items():
                if "validated_vulnerabilities" in finding and finding["validated_vulnerabilities"]:
                    files_with_vulnerabilities += 1
                    total_vulnerabilities += len(finding["validated_vulnerabilities"])
            
            if total_vulnerabilities > 0:
                print(f"  Category complete in {category_time:.1f}s: {files_analyzed} files analyzed, {total_vulnerabilities} CONFIRMED vulnerabilities in {files_with_vulnerabilities} files, {files_with_errors} errors")
            else:
                print(f"  Category complete in {category_time:.1f}s: {files_analyzed} files analyzed, no confirmed vulnerabilities, {files_with_errors} errors")
            print()
        
        total_time = time.time() - start_time
        print(f"SAST analysis complete in {total_time:.1f}s! (avg {total_time/total_categories:.1f}s per category)")
        print(f"Total API requests made: {self.request_count}")
        self.findings = all_findings
        return all_findings
    
    def get_findings_summary(self) -> str:
        """Get a summary of all findings."""
        if not self.findings:
            return "No analysis has been run yet."
        
        summary = "SAST Analysis Summary\n"
        summary += "=" * 50 + "\n\n"
        
        total_vulnerabilities = 0
        total_files_with_vulns = 0
        
        for category, findings in self.findings.items():
            category_name = category.replace('_', ' ').title()
            summary += f"Category: {category_name}\n"
            summary += f"   Files analyzed: {len(findings)}\n"
            
            # Count confirmed vulnerabilities
            category_vulns = 0
            files_with_vulns = 0
            vuln_details = []
            
            for file_path, result in findings.items():
                if "validated_vulnerabilities" in result and result["validated_vulnerabilities"]:
                    files_with_vulns += 1
                    file_vulns = len(result["validated_vulnerabilities"])
                    category_vulns += file_vulns
                    
                    for vuln in result["validated_vulnerabilities"]:
                        vuln_details.append({
                            'file': file_path,
                            'severity': vuln['severity'],
                            'description': vuln['description'],
                            'lines': vuln.get('line_numbers', [])
                        })
            
            if category_vulns > 0:
                summary += f"   CONFIRMED vulnerabilities: {category_vulns} in {files_with_vulns} files\n"
                
                # Show top vulnerabilities for this category
                for vuln in vuln_details[:2]:  # Show top 2
                    file_name = vuln['file'].split('/')[-1]
                    lines_str = f" (lines: {', '.join(map(str, vuln['lines']))})" if vuln['lines'] else ""
                    summary += f"      • {vuln['severity']}: {vuln['description']} in {file_name}{lines_str}\n"
                
                if len(vuln_details) > 2:
                    summary += f"      ... and {len(vuln_details) - 2} more\n"
                    
                total_vulnerabilities += category_vulns
                total_files_with_vulns += files_with_vulns
            else:
                summary += f"   No confirmed vulnerabilities\n"
            
            summary += "\n"
        
        # Overall summary
        summary += " OVERALL SUMMARY\n"
        summary += "=" * 20 + "\n"
        summary += f"Total confirmed vulnerabilities: {total_vulnerabilities}\n"
        summary += f"Files with vulnerabilities: {total_files_with_vulns}\n"
        summary += f"Categories analyzed: {len(self.findings)}\n"
        
        if total_vulnerabilities == 0:
            summary += "\n No confirmed security vulnerabilities found!"
        else:
            summary += f"\n⚠️  Action required: {total_vulnerabilities} security vulnerabilities need attention"
        
        return summary


def create_sast_agent_executor(repo_path: str = "./repo", llm=None):
    """Create a SAST agent executor with OWASP Top 10 analysis capabilities."""
    
    sast_analyzer = SASTAnalyzer(repo_path, llm)
    
    async def analyze_owasp_category(category: str) -> str:
        """Analyze repository for a specific OWASP category."""
        source_files = sast_analyzer.get_source_files()
        findings = await sast_analyzer.analyze_with_owasp_category(category, source_files)
        
        result = f"Analysis results for {category}:\n\n"
        for file_path, finding in findings.items():
            result += f"File: {file_path}\n"
            if "analysis" in finding:
                result += f"Analysis: {finding['analysis'][:1000]}...\n\n"
            elif "error" in finding:
                result += f"Error: {finding['error']}\n\n"
        
        return result
    
    async def run_full_sast_analysis(query: str) -> str:
        """Run complete SAST analysis across all OWASP Top 10 categories."""
        print("\nInitiating comprehensive async SAST analysis...")
        findings = await sast_analyzer.run_full_analysis()
        summary = sast_analyzer.get_findings_summary()
        print("\nGenerating analysis summary...")
        return summary
    
    def get_analysis_summary(query: str) -> str:
        """Get summary of previous analysis."""
        return sast_analyzer.get_findings_summary()
    
    # Create tools
    tools = [
        Tool(
            name="analyze_owasp_category",
            func=analyze_owasp_category,
            description="Analyze code for specific OWASP category. Use category names like 'A01_broken_access_control', 'A02_cryptographic_failures', etc."
        ),
        Tool(
            name="run_full_sast_analysis", 
            func=run_full_sast_analysis,
            description="Run complete SAST analysis across all OWASP Top 10 categories."
        ),
        Tool(
            name="get_analysis_summary",
            func=get_analysis_summary,
            description="Get summary of SAST analysis results."
        )
    ]
    
    # Create agent
    prompt = hub.pull("hwchase17/react")
    agent = create_react_agent(llm, tools, prompt)
    
    # Create executor
    agent_executor = AgentExecutor(
        agent=agent,
        tools=tools,
        verbose=True,
        handle_parsing_errors=True,
        max_iterations=5
    )
    
    return agent_executor, sast_analyzer