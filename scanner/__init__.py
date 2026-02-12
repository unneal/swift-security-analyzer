"""
Swift Security Scanner
OWASP Mobile Top 10 (2024) Vulnerability Scanner for iOS Swift Code
"""

from .scanner import SwiftSecurityScanner, load_all_rules
from .rules.base import Finding, Severity, OWASPCategory

__version__ = "1.0.0"
__all__ = ["SwiftSecurityScanner", "load_all_rules", "Finding", "Severity", "OWASPCategory"]