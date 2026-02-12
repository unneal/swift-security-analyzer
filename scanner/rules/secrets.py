import re
from typing import List
from .base import BaseRule, Finding, Severity, OWASPCategory


class HardcodedSecretsRule(BaseRule):
    """Detects hardcoded secrets, passwords, and tokens in Swift code"""
    
    def get_rule_id(self) -> str:
        return "SWIFT-SEC-001"
    
    def get_name(self) -> str:
        return "Hardcoded Secrets Detected"
    
    def get_description(self) -> str:
        return "Hardcoded credentials, passwords, or secrets found in source code"
    
    def get_severity(self) -> Severity:
        return Severity.CRITICAL
    
    def get_owasp_category(self) -> OWASPCategory:
        return OWASPCategory.M1_IMPROPER_CREDENTIAL_USAGE
    
    def check(self, file_path: str, content: str, lines: List[str]) -> List[Finding]:
        findings = []
        
        # Patterns for hardcoded secrets
        secret_patterns = [
            (r'password\s*=\s*["\']([^"\']{8,})["\']', "Hardcoded password", "CWE-798"),
            (r'secret\s*=\s*["\']([^"\']{8,})["\']', "Hardcoded secret", "CWE-798"),
            (r'token\s*=\s*["\']([^"\']{20,})["\']', "Hardcoded token", "CWE-798"),
            (r'private[_]?key\s*=\s*["\']([^"\']{20,})["\']', "Hardcoded private key", "CWE-798"),
            (r'auth[_]?token\s*=\s*["\']([^"\']{20,})["\']', "Hardcoded auth token", "CWE-798"),
            (r'access[_]?token\s*=\s*["\']([^"\']{20,})["\']', "Hardcoded access token", "CWE-798"),
        ]
        
        for i, line in enumerate(lines, start=1):
            # Skip comments
            if line.strip().startswith("//") or line.strip().startswith("/*"):
                continue
            
            for pattern, title, cwe in secret_patterns:
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for match in matches:
                    findings.append(
                        self.create_finding(
                            file_path=file_path,
                            line_number=i,
                            code_snippet=line.strip(),
                            title=title,
                            description=f"{title} found in source code. This is a critical security vulnerability.",
                            recommendation="Use iOS Keychain, environment variables, or secure configuration management instead of hardcoding credentials.",
                            cwe_id=cwe
                        )
                    )
        
        return findings


class HardcodedAPIKeyRule(BaseRule):
    """Detects hardcoded API keys and cloud credentials"""
    
    def get_rule_id(self) -> str:
        return "SWIFT-SEC-002"
    
    def get_name(self) -> str:
        return "Hardcoded API Key Detected"
    
    def get_description(self) -> str:
        return "Hardcoded API keys or cloud service credentials found in source code"
    
    def get_severity(self) -> Severity:
        return Severity.CRITICAL
    
    def get_owasp_category(self) -> OWASPCategory:
        return OWASPCategory.M1_IMPROPER_CREDENTIAL_USAGE
    
    def check(self, file_path: str, content: str, lines: List[str]) -> List[Finding]:
        findings = []
        
        # API key patterns
        api_patterns = [
            (r'api[_]?key\s*=\s*["\']([A-Za-z0-9_\-]{20,})["\']', "Hardcoded API key", "CWE-798"),
            (r'apiKey\s*=\s*["\']([A-Za-z0-9_\-]{20,})["\']', "Hardcoded API key", "CWE-798"),
            (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID", "CWE-798"),
            (r'AIza[0-9A-Za-z\-_]{35}', "Google API Key", "CWE-798"),
            (r'sk_live_[0-9a-zA-Z]{24,}', "Stripe Live Secret Key", "CWE-798"),
            (r'rk_live_[0-9a-zA-Z]{24,}', "Stripe Live Restricted Key", "CWE-798"),
            (r'sq0atp-[0-9A-Za-z\-_]{22}', "Square Access Token", "CWE-798"),
            (r'ghp_[0-9a-zA-Z]{36}', "GitHub Personal Access Token", "CWE-798"),
        ]
        
        for i, line in enumerate(lines, start=1):
            # Skip comments
            if line.strip().startswith("//") or line.strip().startswith("/*"):
                continue
            
            for pattern, title, cwe in api_patterns:
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for match in matches:
                    findings.append(
                        self.create_finding(
                            file_path=file_path,
                            line_number=i,
                            code_snippet=line.strip(),
                            title=title,
                            description=f"{title} found in source code. Exposed API keys can lead to unauthorized access and financial loss.",
                            recommendation="Store API keys in iOS Keychain, use environment variables, or implement secure key management service.",
                            cwe_id=cwe
                        )
                    )
        
        return findings