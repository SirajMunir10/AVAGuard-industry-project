"""
AVAGuard - Azure CIS Benchmark Compliance Checker
Phase 1: CLI Prototype

A tool for automated compliance validation against CIS Microsoft Azure 
Foundations Benchmark controls.
"""
__version__ = "1.0"
__author__ = "Ahmed Mujtaba"
__description__ = "Azure AD CIS Compliance Checker"

from avaguard.config import Config
from avaguard_core.auth import AzureAuthenticator
from avaguard_core.graph_api_client import GraphAPIClient

__all__ = ['Config', 'AzureAuthenticator', 'GraphAPIClient']