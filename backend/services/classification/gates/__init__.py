"""Classification gates for vulnerability types."""
from .base import BaseGate, GateResult
from .sqli_gate import SQLiGate
from .code_injection_gate import CodeInjectionGate
from .command_injection_gate import CommandInjectionGate
from .xss_gate import XSSGate
from .path_traversal_gate import PathTraversalGate
from .xxe_gate import XXEGate
from .ssrf_gate import SSRFGate
from .deserialization_gate import DeserializationGate
from .hardcoded_secret_gate import HardcodedSecretGate
from .cswsh_gate import CSWSHGate
from .auth_bypass_gate import AuthBypassGate
from .open_redirect_gate import OpenRedirectGate

__all__ = [
    "BaseGate",
    "GateResult",
    "SQLiGate",
    "CodeInjectionGate",
    "CommandInjectionGate",
    "XSSGate",
    "PathTraversalGate",
    "XXEGate",
    "SSRFGate",
    "DeserializationGate",
    "HardcodedSecretGate",
    "CSWSHGate",
    "AuthBypassGate",
    "OpenRedirectGate",
]
