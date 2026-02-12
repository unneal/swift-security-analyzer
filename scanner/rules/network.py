import re
from typing import List
from .base import BaseRule, Finding, Severity, OWASPCategory


class InsecureHTTPRule(BaseRule):
    """Detects hardcoded HTTP (non-HTTPS) URLs"""
    
    def get_rule_id(self) -> str:
        return "SWIFT-NET-001"
    
    def get_name(self) -> str:
        return "Insecure HTTP Connection"
    
    def get_description(self) -> str:
        return "Hardcoded HTTP URL detected. All network communication should use HTTPS."
    
    def get_severity(self) -> Severity:
        return Severity.HIGH
    
    def get_owasp_category(self) -> OWASPCategory:
        return OWASPCategory.M5_INSECURE_COMMUNICATION
    
    def check(self, file_path: str, content: str, lines: List[str]) -> List[Finding]:
        findings = []
        
        # Pattern for HTTP URLs (not HTTPS)
        http_pattern = r'["\']http://[^"\']+["\']'
        
        # Localhost exceptions
        localhost_pattern = r'http://(localhost|127\.0\.0\.1|0\.0\.0\.0)'
        
        for i, line in enumerate(lines, start=1):
            # Skip comments
            if line.strip().startswith("//") or line.strip().startswith("/*"):
                continue
            
            matches = re.finditer(http_pattern, line, re.IGNORECASE)
            for match in matches:
                # Skip localhost URLs (common in development)
                if not re.search(localhost_pattern, match.group(), re.IGNORECASE):
                    findings.append(
                        self.create_finding(
                            file_path=file_path,
                            line_number=i,
                            code_snippet=line.strip(),
                            title="Insecure HTTP URL",
                            description="Hardcoded HTTP URL found. Unencrypted HTTP connections expose data to interception and man-in-the-middle attacks.",
                            recommendation="Use HTTPS instead of HTTP for all network communications. Configure App Transport Security (ATS) properly.",
                            cwe_id="CWE-319"
                        )
                    )
        
        return findings


class NSAllowsArbitraryLoadsRule(BaseRule):
    """Detects NSAllowsArbitraryLoads in App Transport Security settings"""
    
    def get_rule_id(self) -> str:
        return "SWIFT-NET-002"
    
    def get_name(self) -> str:
        return "App Transport Security Disabled"
    
    def get_description(self) -> str:
        return "NSAllowsArbitraryLoads is enabled, weakening App Transport Security"
    
    def get_severity(self) -> Severity:
        return Severity.HIGH
    
    def get_owasp_category(self) -> OWASPCategory:
        return OWASPCategory.M5_INSECURE_COMMUNICATION
    
    def check(self, file_path: str, content: str, lines: List[str]) -> List[Finding]:
        findings = []
        
        # This rule primarily applies to Info.plist files, but we check Swift for references
        ats_patterns = [
            (r'NSAllowsArbitraryLoads', "NSAllowsArbitraryLoads reference"),
            (r'NSAllowsArbitraryLoadsInWebContent', "NSAllowsArbitraryLoadsInWebContent reference"),
            (r'NSExceptionAllowsInsecureHTTPLoads', "NSExceptionAllowsInsecureHTTPLoads reference"),
        ]
        
        for i, line in enumerate(lines, start=1):
            # Skip comments
            if line.strip().startswith("//") or line.strip().startswith("/*"):
                continue
            
            for pattern, title in ats_patterns:
                if re.search(pattern, line):
                    findings.append(
                        self.create_finding(
                            file_path=file_path,
                            line_number=i,
                            code_snippet=line.strip(),
                            title=title,
                            description="App Transport Security exception detected. This weakens the security of network connections.",
                            recommendation="Remove ATS exceptions and ensure all endpoints use HTTPS with valid certificates. Only add specific exceptions when absolutely necessary.",
                            cwe_id="CWE-295"
                        )
                    )
        
        return findings


class InsecureCertificateValidationRule(BaseRule):
    """Detects disabled or improper SSL/TLS certificate validation"""
    
    def get_rule_id(self) -> str:
        return "SWIFT-NET-003"
    
    def get_name(self) -> str:
        return "Insecure Certificate Validation"
    
    def get_description(self) -> str:
        return "SSL/TLS certificate validation is disabled or improperly implemented"
    
    def get_severity(self) -> Severity:
        return Severity.CRITICAL
    
    def get_owasp_category(self) -> OWASPCategory:
        return OWASPCategory.M5_INSECURE_COMMUNICATION
    
    def check(self, file_path: str, content: str, lines: List[str]) -> List[Finding]:
        findings = []
        
        # Patterns for disabled cert validation
        cert_validation_patterns = [
            (r'URLSession.*\.serverTrustPolicy.*\.disableEvaluation', "Server trust evaluation disabled"),
            (r'challenge\.protectionSpace\.authenticationMethod.*NSURLAuthenticationMethodServerTrust.*return.*URLCredential', "Accepting all server trust challenges"),
            (r'\.validatesCertificateChain\s*=\s*false', "Certificate chain validation disabled"),
            (r'kCFStreamSSLValidatesCertificateChain.*kCFBooleanFalse', "Certificate validation disabled"),
            (r'\.allowsInvalidCertificates\s*=\s*true', "Invalid certificates allowed"),
        ]
        
        for i, line in enumerate(lines, start=1):
            # Skip comments
            if line.strip().startswith("//") or line.strip().startswith("/*"):
                continue
            
            for pattern, title in cert_validation_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(
                        self.create_finding(
                            file_path=file_path,
                            line_number=i,
                            code_snippet=line.strip(),
                            title=title,
                            description="SSL/TLS certificate validation is disabled. This enables man-in-the-middle attacks.",
                            recommendation="Enable proper certificate validation. Use certificate pinning for additional security.",
                            severity=Severity.CRITICAL,
                            cwe_id="CWE-295"
                        )
                    )
        
        return findings


class ClearTextTrafficRule(BaseRule):
    """Detects potential cleartext network traffic"""
    
    def get_rule_id(self) -> str:
        return "SWIFT-NET-004"
    
    def get_name(self) -> str:
        return "Cleartext Network Traffic"
    
    def get_description(self) -> str:
        return "Potential cleartext network communication detected"
    
    def get_severity(self) -> Severity:
        return Severity.MEDIUM
    
    def get_owasp_category(self) -> OWASPCategory:
        return OWASPCategory.M5_INSECURE_COMMUNICATION
    
    def check(self, file_path: str, content: str, lines: List[str]) -> List[Finding]:
        findings = []
        
        # Patterns for cleartext protocols
        cleartext_patterns = [
            (r'CFStreamCreatePairWithSocketToHost', "Raw socket connection"),
            (r'socket\s*\(\s*AF_INET', "Unencrypted socket"),
            (r'telnet://', "Telnet protocol"),
            (r'ftp://', "FTP protocol"),
        ]
        
        for i, line in enumerate(lines, start=1):
            # Skip comments
            if line.strip().startswith("//") or line.strip().startswith("/*"):
                continue
            
            for pattern, title in cleartext_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(
                        self.create_finding(
                            file_path=file_path,
                            line_number=i,
                            code_snippet=line.strip(),
                            title=title,
                            description="Potential cleartext network communication detected. Data may be transmitted without encryption.",
                            recommendation="Use secure protocols (HTTPS, FTPS, SSH) and ensure all data is encrypted in transit.",
                            cwe_id="CWE-319"
                        )
                    )
        
        return findings