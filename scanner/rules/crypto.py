import re
from typing import List
from .base import BaseRule, Finding, Severity, OWASPCategory


class WeakCryptoHashRule(BaseRule):
    """Detects usage of weak cryptographic hash algorithms (MD5, SHA1)"""
    
    def get_rule_id(self) -> str:
        return "SWIFT-CRYPTO-001"
    
    def get_name(self) -> str:
        return "Weak Cryptographic Hash Algorithm"
    
    def get_description(self) -> str:
        return "Usage of weak or broken cryptographic hash algorithms detected (MD5, SHA1)"
    
    def get_severity(self) -> Severity:
        return Severity.HIGH
    
    def get_owasp_category(self) -> OWASPCategory:
        return OWASPCategory.M10_INSUFFICIENT_CRYPTOGRAPHY
    
    def check(self, file_path: str, content: str, lines: List[str]) -> List[Finding]:
        findings = []
        
        # Patterns for weak hash algorithms
        weak_hash_patterns = [
            (r'CC_MD5|Insecure\.MD5', "MD5 hash usage", "Use SHA-256 or SHA-3 instead", "CWE-327"),
            (r'CC_SHA1|Insecure\.SHA1', "SHA1 hash usage", "Use SHA-256 or SHA-3 instead", "CWE-327"),
            (r'\.md5\(', "MD5 hash method", "Use SHA-256 or SHA-3 instead", "CWE-327"),
            (r'\.sha1\(', "SHA1 hash method", "Use SHA-256 or SHA-3 instead", "CWE-327"),
            (r'kCCHmacAlgMD5', "HMAC-MD5 usage", "Use HMAC-SHA256 instead", "CWE-327"),
            (r'kCCHmacAlgSHA1', "HMAC-SHA1 usage", "Use HMAC-SHA256 instead", "CWE-327"),
        ]
        
        for i, line in enumerate(lines, start=1):
            # Skip comments
            if line.strip().startswith("//") or line.strip().startswith("/*"):
                continue
            
            for pattern, title, recommendation, cwe in weak_hash_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(
                        self.create_finding(
                            file_path=file_path,
                            line_number=i,
                            code_snippet=line.strip(),
                            title=title,
                            description=f"{title} detected. MD5 and SHA1 are cryptographically broken and should not be used for security purposes.",
                            recommendation=recommendation,
                            cwe_id=cwe
                        )
                    )
        
        return findings


class InsecureCryptoRule(BaseRule):
    """Detects insecure cryptographic implementations"""
    
    def get_rule_id(self) -> str:
        return "SWIFT-CRYPTO-002"
    
    def get_name(self) -> str:
        return "Insecure Cryptographic Implementation"
    
    def get_description(self) -> str:
        return "Insecure cryptographic algorithm or implementation detected"
    
    def get_severity(self) -> Severity:
        return Severity.HIGH
    
    def get_owasp_category(self) -> OWASPCategory:
        return OWASPCategory.M10_INSUFFICIENT_CRYPTOGRAPHY
    
    def check(self, file_path: str, content: str, lines: List[str]) -> List[Finding]:
        findings = []
        
        # Patterns for insecure crypto
        insecure_patterns = [
            (r'kCCAlgorithmDES|kCCAlgorithm3DES', "DES/3DES encryption", "Use AES-256 instead", "CWE-327"),
            (r'kCCAlgorithmRC4|kCCAlgorithmRC2', "RC4/RC2 encryption", "Use AES-256 instead", "CWE-327"),
            (r'kCCOptionECBMode', "ECB mode encryption", "Use CBC or GCM mode with proper IV", "CWE-327"),
            (r'SecKeyCreateRandomKey.*\.rsaEncryptionPKCS1', "RSA PKCS1 padding", "Use OAEP padding instead", "CWE-327"),
            (r'kSecAttrKeyTypeRSA.*1024', "RSA 1024-bit key", "Use at least RSA 2048-bit or ECDSA", "CWE-326"),
            (r'CCCrypt.*kCCOptionPKCS7Padding.*nil', "Missing initialization vector", "Always use a random IV for encryption", "CWE-329"),
        ]
        
        for i, line in enumerate(lines, start=1):
            # Skip comments
            if line.strip().startswith("//") or line.strip().startswith("/*"):
                continue
            
            for pattern, title, recommendation, cwe in insecure_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(
                        self.create_finding(
                            file_path=file_path,
                            line_number=i,
                            code_snippet=line.strip(),
                            title=title,
                            description=f"{title} detected. This cryptographic implementation is insecure.",
                            recommendation=recommendation,
                            cwe_id=cwe
                        )
                    )
        
        return findings


class WeakRandomRule(BaseRule):
    """Detects usage of weak random number generators"""
    
    def get_rule_id(self) -> str:
        return "SWIFT-CRYPTO-003"
    
    def get_name(self) -> str:
        return "Weak Random Number Generator"
    
    def get_description(self) -> str:
        return "Usage of weak or predictable random number generator"
    
    def get_severity(self) -> Severity:
        return Severity.MEDIUM
    
    def get_owasp_category(self) -> OWASPCategory:
        return OWASPCategory.M10_INSUFFICIENT_CRYPTOGRAPHY
    
    def check(self, file_path: str, content: str, lines: List[str]) -> List[Finding]:
        findings = []
        
        # Patterns for weak random
        weak_random_patterns = [
            (r'arc4random\(\)', "arc4random() usage", "Use SecRandomCopyBytes for cryptographic purposes", "CWE-338"),
            (r'random\(\)', "random() usage", "Use SecRandomCopyBytes for cryptographic purposes", "CWE-338"),
            (r'rand\(\)', "rand() usage", "Use SecRandomCopyBytes for cryptographic purposes", "CWE-338"),
            (r'drand48\(\)', "drand48() usage", "Use SecRandomCopyBytes for cryptographic purposes", "CWE-338"),
        ]
        
        for i, line in enumerate(lines, start=1):
            # Skip comments
            if line.strip().startswith("//") or line.strip().startswith("/*"):
                continue
            
            # Only flag if used in security context (heuristic check)
            security_keywords = ['token', 'key', 'password', 'secret', 'crypto', 'encrypt', 'auth']
            is_security_context = any(keyword in line.lower() for keyword in security_keywords)
            
            if is_security_context:
                for pattern, title, recommendation, cwe in weak_random_patterns:
                    if re.search(pattern, line):
                        findings.append(
                            self.create_finding(
                                file_path=file_path,
                                line_number=i,
                                code_snippet=line.strip(),
                                title=title,
                                description=f"{title} in security context. Standard random functions are not cryptographically secure.",
                                recommendation=recommendation,
                                cwe_id=cwe
                            )
                        )
        
        return findings