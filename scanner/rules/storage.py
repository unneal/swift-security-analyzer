import re
from typing import List
from .base import BaseRule, Finding, Severity, OWASPCategory


class InsecureStorageRule(BaseRule):
    """Detects insecure data storage patterns in Swift code"""
    
    def get_rule_id(self) -> str:
        return "SWIFT-STORAGE-001"
    
    def get_name(self) -> str:
        return "Insecure Data Storage"
    
    def get_description(self) -> str:
        return "Sensitive data stored insecurely without encryption"
    
    def get_severity(self) -> Severity:
        return Severity.HIGH
    
    def get_owasp_category(self) -> OWASPCategory:
        return OWASPCategory.M9_INSECURE_DATA_STORAGE
    
    def check(self, file_path: str, content: str, lines: List[str]) -> List[Finding]:
        findings = []
        
        # Patterns for insecure storage
        storage_patterns = [
            (r'NSUserDefaults|UserDefaults', "UserDefaults storage"),
            (r'\.plist', "Plist file storage"),
            (r'FileManager.*write.*toString', "Plain text file write"),
            (r'NSKeyedArchiver', "NSKeyedArchiver usage"),
            (r'\.sqlite', "SQLite database"),
        ]
        
        # Sensitive data keywords
        sensitive_keywords = ['password', 'token', 'secret', 'key', 'credential', 'auth', 'pin', 'ssn', 'credit', 'card']
        
        for i, line in enumerate(lines, start=1):
            # Skip comments
            if line.strip().startswith("//") or line.strip().startswith("/*"):
                continue
            
            # Check if line contains sensitive keywords
            is_sensitive = any(keyword in line.lower() for keyword in sensitive_keywords)
            
            if is_sensitive:
                for pattern, title in storage_patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        findings.append(
                            self.create_finding(
                                file_path=file_path,
                                line_number=i,
                                code_snippet=line.strip(),
                                title=f"Sensitive data in {title}",
                                description=f"Sensitive data appears to be stored using {title}, which is not encrypted by default.",
                                recommendation="Use iOS Keychain for storing sensitive data like passwords, tokens, and keys. For larger data, use Data Protection API with appropriate file protection levels.",
                                cwe_id="CWE-311"
                            )
                        )
        
        return findings


class UserDefaultsSecretRule(BaseRule):
    """Detects sensitive data stored in UserDefaults"""
    
    def get_rule_id(self) -> str:
        return "SWIFT-STORAGE-002"
    
    def get_name(self) -> str:
        return "Sensitive Data in UserDefaults"
    
    def get_description(self) -> str:
        return "Sensitive information stored in UserDefaults without encryption"
    
    def get_severity(self) -> Severity:
        return Severity.HIGH
    
    def get_owasp_category(self) -> OWASPCategory:
        return OWASPCategory.M9_INSECURE_DATA_STORAGE
    
    def check(self, file_path: str, content: str, lines: List[str]) -> List[Finding]:
        findings = []
        
        # Pattern for UserDefaults with sensitive keys
        user_defaults_pattern = r'UserDefaults\.standard\.set\(.*,\s*forKey:\s*["\']([^"\']+)["\']'
        
        # Sensitive key patterns
        sensitive_key_patterns = ['password', 'token', 'secret', 'key', 'auth', 'credential', 'pin', 'api', 'private']
        
        for i, line in enumerate(lines, start=1):
            # Skip comments
            if line.strip().startswith("//") or line.strip().startswith("/*"):
                continue
            
            match = re.search(user_defaults_pattern, line, re.IGNORECASE)
            if match:
                key = match.group(1).lower()
                if any(sensitive in key for sensitive in sensitive_key_patterns):
                    findings.append(
                        self.create_finding(
                            file_path=file_path,
                            line_number=i,
                            code_snippet=line.strip(),
                            title="Sensitive data in UserDefaults",
                            description=f"Sensitive key '{match.group(1)}' stored in UserDefaults. UserDefaults is not encrypted and can be accessed from device backups.",
                            recommendation="Use iOS Keychain (Security framework) to store sensitive data securely.",
                            cwe_id="CWE-311"
                        )
                    )
        
        return findings


class LoggingSensitiveDataRule(BaseRule):
    """Detects sensitive data in logging statements"""
    
    def get_rule_id(self) -> str:
        return "SWIFT-STORAGE-003"
    
    def get_name(self) -> str:
        return "Sensitive Data in Logs"
    
    def get_description(self) -> str:
        return "Sensitive information may be logged and exposed"
    
    def get_severity(self) -> Severity:
        return Severity.MEDIUM
    
    def get_owasp_category(self) -> OWASPCategory:
        return OWASPCategory.M9_INSECURE_DATA_STORAGE
    
    def check(self, file_path: str, content: str, lines: List[str]) -> List[Finding]:
        findings = []
        
        # Logging patterns
        log_patterns = [
            r'print\(',
            r'NSLog\(',
            r'os_log\(',
            r'Logger\(',
            r'\.log\(',
        ]
        
        # Sensitive keywords
        sensitive_keywords = ['password', 'token', 'secret', 'key', 'credential', 'auth', 'pin', 'ssn', 'credit']
        
        for i, line in enumerate(lines, start=1):
            # Skip comments
            if line.strip().startswith("//") or line.strip().startswith("/*"):
                continue
            
            # Check if line is a log statement
            is_log = any(re.search(pattern, line, re.IGNORECASE) for pattern in log_patterns)
            
            if is_log:
                # Check if logging sensitive data
                if any(keyword in line.lower() for keyword in sensitive_keywords):
                    findings.append(
                        self.create_finding(
                            file_path=file_path,
                            line_number=i,
                            code_snippet=line.strip(),
                            title="Sensitive data in logs",
                            description="Sensitive data appears to be logged. Logs can be accessed through device backups and debugging.",
                            recommendation="Remove sensitive data from log statements. Use redacted logging or structured logging with proper sanitization.",
                            cwe_id="CWE-532"
                        )
                    )
        
        return findings


class WorldReadableFileRule(BaseRule):
    """Detects files created with world-readable permissions"""
    
    def get_rule_id(self) -> str:
        return "SWIFT-STORAGE-004"
    
    def get_name(self) -> str:
        return "World-Readable File Permissions"
    
    def get_description(self) -> str:
        return "File created with overly permissive access controls"
    
    def get_severity(self) -> Severity:
        return Severity.MEDIUM
    
    def get_owasp_category(self) -> OWASPCategory:
        return OWASPCategory.M9_INSECURE_DATA_STORAGE
    
    def check(self, file_path: str, content: str, lines: List[str]) -> List[Finding]:
        findings = []
        
        # Patterns for file permissions
        permission_patterns = [
            (r'FileProtectionType\.none', "No file protection"),
            (r'\.completeFileProtection.*false', "File protection disabled"),
            (r'NSFileProtectionNone', "No file protection"),
        ]
        
        for i, line in enumerate(lines, start=1):
            # Skip comments
            if line.strip().startswith("//") or line.strip().startswith("/*"):
                continue
            
            for pattern, title in permission_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(
                        self.create_finding(
                            file_path=file_path,
                            line_number=i,
                            code_snippet=line.strip(),
                            title=title,
                            description="File created without proper protection. Data may be accessible even when device is locked.",
                            recommendation="Use appropriate file protection levels: .complete, .completeUnlessOpen, or .completeUntilFirstUserAuthentication based on your needs.",
                            cwe_id="CWE-732"
                        )
                    )
        
        return findings