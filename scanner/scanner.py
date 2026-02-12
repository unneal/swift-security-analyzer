import os
from typing import List, Dict, Any
from pathlib import Path

from .rules.base import BaseRule, Finding


class SwiftSecurityScanner:
    """Main scanner class that orchestrates security scanning"""
    
    def __init__(self, rules: List[BaseRule] = None):
        """
        Initialize scanner with rules
        
        Args:
            rules: List of rule objects to check. If None, all rules are loaded.
        """
        self.rules = rules or []
        self.findings = []
        self.stats = {
            "files_scanned": 0,
            "lines_scanned": 0,
            "findings_by_severity": {
                "CRITICAL": 0,
                "HIGH": 0,
                "MEDIUM": 0,
                "LOW": 0,
                "INFO": 0
            }
        }
    
    def add_rule(self, rule: BaseRule):
        """Add a rule to the scanner"""
        self.rules.append(rule)
    
    def scan_directory(self, directory: str, recursive: bool = True) -> List[Finding]:
        """
        Scan a directory for Swift files
        
        Args:
            directory: Path to directory to scan
            recursive: Whether to scan subdirectories
        
        Returns:
            List of all findings
        """
        directory_path = Path(directory)
        
        if not directory_path.exists():
            raise ValueError(f"Directory does not exist: {directory}")
        
        if not directory_path.is_dir():
            raise ValueError(f"Path is not a directory: {directory}")
        
        # Find all Swift files
        if recursive:
            swift_files = list(directory_path.rglob("*.swift"))
        else:
            swift_files = list(directory_path.glob("*.swift"))
        
        # Scan each file
        for swift_file in swift_files:
            self.scan_file(str(swift_file))
        
        return self.findings
    
    def scan_file(self, file_path: str) -> List[Finding]:
        """
        Scan a single Swift file
        
        Args:
            file_path: Path to Swift file
        
        Returns:
            List of findings for this file
        """
        file_path_obj = Path(file_path)
        
        if not file_path_obj.exists():
            raise ValueError(f"File does not exist: {file_path}")
        
        if file_path_obj.suffix != ".swift":
            raise ValueError(f"File is not a Swift file: {file_path}")
        
        # Read file content
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.splitlines()
        except Exception as e:
            print(f"Error reading file {file_path}: {e}")
            return []
        
        # Update stats
        self.stats["files_scanned"] += 1
        self.stats["lines_scanned"] += len(lines)
        
        # Run all rules on this file
        file_findings = []
        for rule in self.rules:
            try:
                findings = rule.check(file_path, content, lines)
                file_findings.extend(findings)
            except Exception as e:
                print(f"Error running rule {rule.rule_id} on {file_path}: {e}")
        
        # Update findings and stats
        for finding in file_findings:
            self.findings.append(finding)
            self.stats["findings_by_severity"][finding.severity.value] += 1
        
        return file_findings
    
    def get_findings(self) -> List[Finding]:
        """Get all findings"""
        return self.findings
    
    def get_findings_by_severity(self, severity: str) -> List[Finding]:
        """Get findings filtered by severity"""
        return [f for f in self.findings if f.severity.value == severity]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get scanning statistics"""
        return {
            **self.stats,
            "total_findings": len(self.findings),
            "unique_files_with_issues": len(set(f.file_path for f in self.findings))
        }
    
    def clear_findings(self):
        """Clear all findings and reset stats"""
        self.findings = []
        self.stats = {
            "files_scanned": 0,
            "lines_scanned": 0,
            "findings_by_severity": {
                "CRITICAL": 0,
                "HIGH": 0,
                "MEDIUM": 0,
                "LOW": 0,
                "INFO": 0
            }
        }


def load_all_rules() -> List[BaseRule]:
    """
    Load all available security rules
    
    Returns:
        List of instantiated rule objects
    """
    from .rules.secrets import HardcodedSecretsRule, HardcodedAPIKeyRule
    from .rules.crypto import WeakCryptoHashRule, InsecureCryptoRule
    from .rules.network import InsecureHTTPRule, NSAllowsArbitraryLoadsRule
    from .rules.storage import InsecureStorageRule, UserDefaultsSecretRule
    
    return [
        HardcodedSecretsRule(),
        HardcodedAPIKeyRule(),
        WeakCryptoHashRule(),
        InsecureCryptoRule(),
        InsecureHTTPRule(),
        NSAllowsArbitraryLoadsRule(),
        InsecureStorageRule(),
        UserDefaultsSecretRule(),
    ]