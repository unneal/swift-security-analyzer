from abc import ABC, abstractmethod
from typing import List, Dict, Any
from enum import Enum


class Severity(Enum):
    """Severity levels for security findings"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class OWASPCategory(Enum):
    """OWASP Mobile Top 10 categories"""
    M1_IMPROPER_PLATFORM_USAGE = "M1: Improper Platform Usage"
    M2_INSECURE_DATA_STORAGE = "M2: Insecure Data Storage"
    M3_INSECURE_COMMUNICATION = "M3: Insecure Communication"
    M4_INSECURE_AUTHENTICATION = "M4: Insecure Authentication"
    M5_INSUFFICIENT_CRYPTOGRAPHY = "M5: Insufficient Cryptography"
    M6_INSECURE_AUTHORIZATION = "M6: Insecure Authorization"
    M7_CLIENT_CODE_QUALITY = "M7: Client Code Quality"
    M8_CODE_TAMPERING = "M8: Code Tampering"
    M9_REVERSE_ENGINEERING = "M9: Reverse Engineering"
    M10_EXTRANEOUS_FUNCTIONALITY = "M10: Extraneous Functionality"


class Finding:
    """Represents a security finding"""
    
    def __init__(
        self,
        rule_id: str,
        title: str,
        description: str,
        severity: Severity,
        owasp_category: OWASPCategory,
        file_path: str,
        line_number: int,
        code_snippet: str,
        recommendation: str,
        cwe_id: str = None
    ):
        self.rule_id = rule_id
        self.title = title
        self.description = description
        self.severity = severity
        self.owasp_category = owasp_category
        self.file_path = file_path
        self.line_number = line_number
        self.code_snippet = code_snippet
        self.recommendation = recommendation
        self.cwe_id = cwe_id
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary"""
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "owasp_category": self.owasp_category.value,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "code_snippet": self.code_snippet,
            "recommendation": self.recommendation,
            "cwe_id": self.cwe_id
        }


class BaseRule(ABC):
    """Base class for all security rules"""
    
    def __init__(self):
        self.rule_id = self.get_rule_id()
        self.name = self.get_name()
        self.description = self.get_description()
        self.severity = self.get_severity()
        self.owasp_category = self.get_owasp_category()
    
    @abstractmethod
    def get_rule_id(self) -> str:
        """Return unique rule identifier"""
        pass
    
    @abstractmethod
    def get_name(self) -> str:
        """Return rule name"""
        pass
    
    @abstractmethod
    def get_description(self) -> str:
        """Return rule description"""
        pass
    
    @abstractmethod
    def get_severity(self) -> Severity:
        """Return default severity level"""
        pass
    
    @abstractmethod
    def get_owasp_category(self) -> OWASPCategory:
        """Return OWASP Mobile Top 10 category"""
        pass
    
    @abstractmethod
    def check(self, file_path: str, content: str, lines: List[str]) -> List[Finding]:
        """
        Check code for security issues
        
        Args:
            file_path: Path to the file being scanned
            content: Full file content as string
            lines: List of lines in the file
        
        Returns:
            List of Finding objects
        """
        pass
    
    def create_finding(
        self,
        file_path: str,
        line_number: int,
        code_snippet: str,
        title: str = None,
        description: str = None,
        recommendation: str = None,
        severity: Severity = None,
        cwe_id: str = None
    ) -> Finding:
        """Helper method to create a finding"""
        return Finding(
            rule_id=self.rule_id,
            title=title or self.name,
            description=description or self.description,
            severity=severity or self.severity,
            owasp_category=self.owasp_category,
            file_path=file_path,
            line_number=line_number,
            code_snippet=code_snippet,
            recommendation=recommendation or "Review and remediate this security issue",
            cwe_id=cwe_id
        )