# 🔒 Swift Security Scanner

> **⚠️ [Read the Disclaimer](#disclaimer) before using this tool**

A CLI tool for detecting OWASP Mobile Top 10 (2024) vulnerabilities in iOS Swift codebases.

## Features

- ✅ Detects **hardcoded secrets, API keys, and credentials** (M1)
- ✅ Identifies **weak cryptography** (MD5, SHA1, DES, RC4) (M10)
- ✅ Finds **insecure HTTP connections** and disabled ATS (M5)
- ✅ Detects **insecure data storage** patterns (M9)
- ✅ Multiple output formats: **Console, JSON, HTML**
- ✅ Severity ratings: CRITICAL, HIGH, MEDIUM, LOW, INFO
- ✅ CWE mappings for each vulnerability
- ✅ OWASP Mobile Top 10 2024 compliance

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/swift-security-scanner.git
cd swift-security-scanner

# Install dependencies
pip install -r requirements.txt

# Install the tool
pip install -e .
```

## Quick Start

```bash
# Scan a single Swift file
swift-scan path/to/file.swift

# Scan entire directory recursively
swift-scan path/to/project/ -r

# Generate HTML report
swift-scan path/to/project/ -f html -o report.html

# Generate JSON report
swift-scan path/to/project/ -f json -o report.json

# Filter by severity
swift-scan path/to/project/ -s HIGH

# Verbose output
swift-scan path/to/project/ -v
```

## Usage

```
swift-scan [TARGET] [OPTIONS]

Arguments:
  TARGET  Path to Swift file or directory to scan

Options:
  -o, --output PATH       Output file for report
  -f, --format [console|json|html]  Output format (default: console)
  -s, --severity [CRITICAL|HIGH|MEDIUM|LOW|INFO]  Minimum severity
  -r, --recursive         Scan directories recursively (default: true)
  -v, --verbose          Verbose output
  --help                 Show this message and exit
```

## Detected Vulnerabilities

### M1: Improper Credential Usage
- Hardcoded passwords, secrets, tokens
- Hardcoded API keys (AWS, Google, Stripe, GitHub, etc.)
- Private keys in source code

### M5: Insecure Communication
- HTTP URLs (non-HTTPS)
- Disabled App Transport Security (ATS)
- Disabled SSL/TLS certificate validation
- Cleartext network protocols

### M9: Insecure Data Storage
- Sensitive data in UserDefaults
- Plaintext file storage
- Sensitive data in logs
- World-readable file permissions
- Missing Data Protection API usage

### M10: Insufficient Cryptography
- Weak hash algorithms (MD5, SHA1)
- Weak encryption (DES, 3DES, RC4, RC2)
- ECB mode usage
- Weak random number generators
- Small RSA key sizes

## Example Output

```
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║        Swift Security Scanner v1.0                        ║
║        OWASP Mobile Top 10 Vulnerability Detector         ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝

================================================================================
SCAN SUMMARY
================================================================================

Files Scanned:        4
Lines Scanned:        287
Total Findings:       15
Files with Issues:    4

Severity Breakdown:
  CRITICAL  : 5
  HIGH      : 7
  MEDIUM    : 3

================================================================================
CRITICAL SEVERITY FINDINGS (5)
================================================================================

[CRITICAL] SWIFT-SEC-002: Hardcoded API key
  File:        examples/vulnerable_app/HardcodedSecrets.swift:6
  OWASP:       M1: Improper Credential Usage
  CWE:         CWE-798
  Description: Hardcoded API key found in source code...
  Code:        let apiKey = "sk_live_51H3rT0pNjRx1234567890abcdefghijk"
  Fix:         Store API keys in iOS Keychain...
```

## Test with Example Vulnerabilities

Test the scanner with provided vulnerable Swift files:

```bash
# Scan example vulnerable code
swift-scan examples/vulnerable_app/ -f html -o report.html
```

The `examples/vulnerable_app/` directory contains intentionally vulnerable code demonstrating each vulnerability category.

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.9'
      - name: Install scanner
        run: |
          pip install -e .
      - name: Run security scan
        run: |
          swift-scan . -f json -o report.json -s HIGH
      - name: Upload report
        uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: report.json
```

## OWASP Mobile Top 10 2024 Coverage

| Category | Coverage | Rules |
|----------|----------|-------|
| M1: Improper Credential Usage | ✅ | 2 rules |
| M2: Inadequate Supply Chain Security | ⚠️ | Partial |
| M3: Insecure Authentication/Authorization | 🔄 | Planned |
| M4: Insufficient Input/Output Validation | 🔄 | Planned |
| M5: Insecure Communication | ✅ | 4 rules |
| M6: Inadequate Privacy Controls | 🔄 | Planned |
| M7: Insufficient Binary Protections | 🔄 | Planned |
| M8: Security Misconfiguration | ⚠️ | Partial |
| M9: Insecure Data Storage | ✅ | 4 rules |
| M10: Insufficient Cryptography | ✅ | 3 rules |

## Contributing

Contributions are welcome! To add new rules:

1. Create a new rule class in `scanner/rules/`
2. Inherit from `BaseRule`
3. Implement required methods
4. Add to `load_all_rules()` in `scanner.py`
5. Add tests

## License

MIT License - See LICENSE file for details

## Author

Anil - Cybersecurity Analyst

## Acknowledgments

- OWASP Mobile Security Project
- OWASP Mobile Top 10 2024
- iOS Security Best Practices

## Roadmap

- [ ] Add more M3, M4, M6, M7 detection rules
- [ ] Info.plist scanning for ATS misconfigurations
- [ ] SARIF output format for IDE integration
- [ ] Custom rule configuration via YAML
- [ ] Performance optimization for large codebases
- [ ] SwiftUI-specific security checks

---

## Disclaimer

**This tool is provided "as-is" without any warranties or guarantees.** While Swift Security Scanner helps identify potential security vulnerabilities in Swift code, it should not be considered a complete security solution.

**Important Notes:**
- This scanner detects **common patterns** but cannot catch all security issues
- **False positives** may occur - manual verification is required
- **False negatives** are possible - the tool may miss certain vulnerabilities
- This tool does **not replace** professional security audits, penetration testing, or code reviews
- The author is **not responsible** for any security breaches, data loss, or damages resulting from the use or misuse of this tool
- Users are responsible for ensuring their code meets all applicable security standards and regulations

**Recommendations:**
- Use this tool as **part of** a comprehensive security strategy
- Combine with manual code review by security professionals
- Conduct regular penetration testing on your applications
- Follow Apple's security best practices and OWASP guidelines
- Keep your dependencies and tooling up to date

By using this tool, you acknowledge that you understand these limitations and accept full responsibility for your application's security.

---

**Made with ❤️ for the iOS security community**