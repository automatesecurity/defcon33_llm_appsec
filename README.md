# DEF CON 33 AI For Application Security
## Automated Security Analysis Framework

This application is an AI-powered automated security analysis framework designed for DEF CON 33, specifically built to analyze web applications for security vulnerabilities using machine learning and static analysis. The framework provides comprehensive security assessment capabilities including OWASP Top 10 vulnerability detection, call graph analysis, and vector-based code search.

## 🔧 What This Application Does

This security analysis framework performs the following core functions:

### 1. **Automated Static Application Security Testing (SAST)**
- Analyzes source code across multiple languages (Python, JavaScript, PHP, Java, C/C++)
- Implements comprehensive OWASP Top 10 2021 vulnerability detection:
  - A01: Broken Access Control
  - A02: Cryptographic Failures
  - A03: Injection vulnerabilities
  - A04: Insecure Design
  - A05: Security Misconfiguration
  - A06: Vulnerable and Outdated Components
  - A07: Identification and Authentication Failures
  - A08: Software and Data Integrity Failures
  - A09: Security Logging and Monitoring Failures
  - A10: Server-Side Request Forgery (SSRF)

### 2. **Call Graph Analysis**
- Builds comprehensive function call graphs using Tree-sitter parsers
- Tracks function definitions and call relationships across the codebase
- Supports multiple programming languages with syntax-aware parsing
- Provides caller/callee relationship mapping for security impact analysis

### 3. **Vector Database Integration**
- Creates FAISS-based vector embeddings of source code
- Enables semantic code search and similarity analysis
- Uses AWS Bedrock Titan embeddings for high-quality code representations
- Supports efficient querying of large codebases

### 4. **Target Application Analysis**
The framework comes preconfigured to analyze **DVWA (Damn Vulnerable Web Application)**, a deliberately vulnerable PHP web application designed for security testing and education.

## 🚀 How It Works

### Architecture Overview

1. **Repository Cloning**: Automatically clones the target repository (DVWA)
2. **Vector Database Creation**: Builds a FAISS vector index of all source code files
3. **Call Graph Generation**: Parses source code to create function relationship maps
4. **SAST Analysis**: Runs parallel analysis across all OWASP Top 10 categories
5. **Vulnerability Validation**: Uses LLM-powered validation to confirm security issues
6. **Report Generation**: Produces detailed security assessment reports

### Analysis Workflow

```
Input Repository → Vector Indexing → Call Graph Analysis → SAST Scanning → Validation → Report
```

### Key Components

- **`agent.py`**: Main orchestration script with Bedrock LLM integration
- **`agent-2.py`**: Enhanced version with OpenAI integration and vector database support  
- **`sast_analyzer.py`**: Core SAST analysis engine with OWASP Top 10 implementation
- **`call_graph_analyzer.py`**: Function relationship analysis using Tree-sitter
- **`test_openai.py`**: OpenAI API integration testing utility

## 📋 Prerequisites

- Python 3.8+
- AWS credentials (for Bedrock services)
- OpenAI API key (for enhanced analysis)
- Git

## 🛠️ Installation & Setup

### 1. Environment Setup

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Environment Configuration

Create a `.env` file in the project root:

```env
# AWS Configuration (for Bedrock)
AWS_ACCESS_KEY_ID=your_aws_access_key
AWS_SECRET_ACCESS_KEY=your_aws_secret_key
AWS_DEFAULT_REGION=us-east-1

# OpenAI Configuration (optional, for enhanced analysis)
OPENAI_API_KEY=your_openai_api_key
```

### 3. Test Your Setup

```bash
# Test OpenAI integration
python test_openai.py

# Verify AWS Bedrock access
python -c "from langchain_aws import ChatBedrock; print('Bedrock access configured')"
```

## 🎯 Usage

### Basic Analysis (Bedrock)

```bash
python agent.py
```

### Enhanced Analysis (OpenAI + Vector DB)

```bash
python agent-2.py
```

### What Happens During Execution

1. **Repository Cloning**: Downloads DVWA to `./repo/` directory
2. **Vector Database Creation**: Builds FAISS index in `vector database/` folder
3. **Call Graph Generation**: Maps all function relationships
4. **SAST Analysis**: Performs security analysis across all OWASP categories
5. **Results**: Displays comprehensive security findings with severity levels

## 📊 Output & Results

The application generates detailed security reports including:

- **Vulnerability Summary**: Count and categorization of security issues
- **File-Level Analysis**: Specific vulnerabilities found in each source file
- **Line-Level Details**: Exact locations of security issues with code context
- **Severity Assessment**: Risk levels (Critical/High/Medium/Low) for each finding
- **Remediation Guidance**: Recommendations for fixing identified vulnerabilities

### Sample Output

```
SAST Analysis Summary
==================================================

Category: Broken Access Control
   Files analyzed: 15
   CONFIRMED vulnerabilities: 8 in 5 files
      • HIGH: Direct object reference without authorization in login.php (lines: 45, 67)
      • MEDIUM: Missing role validation in admin panel access

Category: Injection
   Files analyzed: 15  
   CONFIRMED vulnerabilities: 12 in 8 files
      • CRITICAL: SQL injection via user input in vulnerabilities/sqli/source/low.php
      • HIGH: Command injection in vulnerabilities/exec/source/low.php

OVERALL SUMMARY
====================
Total confirmed vulnerabilities: 47
Files with vulnerabilities: 23
Categories analyzed: 10
```

## 🔒 Security Considerations

This tool is designed for **defensive security analysis only**:

- ✅ Vulnerability detection and analysis
- ✅ Security assessment and reporting  
- ✅ Educational security research
- ❌ **NOT for creating malicious code**
- ❌ **NOT for offensive security operations**

## 🏗️ Technical Architecture

### Dependencies

- **LangChain**: LLM orchestration and agent framework
- **Tree-sitter**: Multi-language code parsing
- **FAISS**: Vector similarity search and indexing
- **AWS Bedrock**: Claude AI model access
- **OpenAI**: GPT model integration
- **AsyncIO**: Concurrent vulnerability analysis

### Supported Languages

- Python (.py)
- JavaScript/TypeScript (.js, .ts, .jsx, .tsx)
- PHP (.php)
- Java (.java)
- C/C++ (.c, .cpp, .h, .hpp)
- Shell scripts (.sh, .bash)
- Configuration files (.json, .yml, .env)

## 🎓 Educational Use

This framework is designed for security education and training:

- **Security Assessment Learning**: Understand how SAST tools work
- **Vulnerability Research**: Study real vulnerability patterns
- **AI Security Applications**: Learn about LLM-powered security analysis
- **DEF CON Training**: Hands-on application security analysis

## 📝 License

This project is part of the DEF CON 33 AI for Application Security exercise. Please refer to the individual component licenses for specific terms.

## 🤝 Contributing

This is an educational framework for DEF CON 33. Contributions should focus on:

- Enhanced vulnerability detection patterns
- Additional programming language support
- Improved analysis accuracy
- Educational documentation

## 🐛 Troubleshooting

### Common Issues

1. **AWS Credentials**: Ensure proper AWS configuration for Bedrock access
2. **OpenAI API**: Verify API key is valid and has sufficient credits
3. **Memory Issues**: Large repositories may require increased system memory
4. **Network Access**: Ensure connectivity for repository cloning and API calls

### Performance Tips

- Limit analysis to specific file types using the configuration
- Use concurrent analysis sparingly to avoid API rate limits
- Monitor vector database size for large repositories

## Support

There is none
