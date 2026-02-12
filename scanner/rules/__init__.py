"""Security rules for Swift code scanning"""

from .base import BaseRule, Finding, Severity, OWASPCategory
from .secrets import HardcodedSecretsRule, HardcodedAPIKeyRule
from .crypto import WeakCryptoHashRule, InsecureCryptoRule, WeakRandomRule
from .network import InsecureHTTPRule, NSAllowsArbitraryLoadsRule, InsecureCertificateValidationRule, ClearTextTrafficRule
from .storage import InsecureStorageRule, UserDefaultsSecretRule, LoggingSensitiveDataRule, WorldReadableFileRule

__all__ = [
    "BaseRule",
    "Finding",
    "Severity",
    "OWASPCategory",
    "HardcodedSecretsRule",
    "HardcodedAPIKeyRule",
    "WeakCryptoHashRule",
    "InsecureCryptoRule",
    "WeakRandomRule",
    "InsecureHTTPRule",
    "NSAllowsArbitraryLoadsRule",
    "InsecureCertificateValidationRule",
    "ClearTextTrafficRule",
    "InsecureStorageRule",
    "UserDefaultsSecretRule",
    "LoggingSensitiveDataRule",
    "WorldReadableFileRule",
]