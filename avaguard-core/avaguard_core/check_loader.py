"""Dynamic Check Loader and Registry for AVAGuard."""

import importlib.util
import inspect
import logging
from pathlib import Path
from typing import Dict, List, Type, Optional, Any
from collections import defaultdict

from avaguard_core.checks.protocol import CheckProtocol
from .checks.base_check import BaseCheck

logger = logging.getLogger(__name__)

class CheckRegistry:
    """Registry for discovering, loading, and managing compliance checks."""
    
    def __init__(self):
        self.checks: Dict[str, Type[CheckProtocol]] = {}
        self.categories: Dict[str, List[Type[CheckProtocol]]] = defaultdict(list)
        
    def discover_checks(self, check_dirs: Optional[List[Path]] = None) -> int:
        """
        Scan directories for check classes that inherit from BaseCheck.
        
        Args:
            check_dirs: List of directory paths to scan. Defaults to the internal 'checks' folder.
            
        Returns:
            Number of checks successfully discovered and registered.
        """
        if not check_dirs:
            # Default to the 'checks' directory alongside this file
            check_dirs = [Path(__file__).parent / "checks"]
            
        count = 0
        for check_dir in check_dirs:
            if not check_dir.exists() or not check_dir.is_dir():
                logger.warning(f"Check directory not found: {check_dir}")
                continue
                
            logger.info(f"Scanning directory for checks: {check_dir}")
            
            # Find all Python files starting with 'check_'
            for file_path in check_dir.rglob("check_*.py"):
                module_name = file_path.stem
                
                try:
                    # Dynamically import the module
                    spec = importlib.util.spec_from_file_location(module_name, file_path)
                    if not spec or not spec.loader:
                        logger.warning(f"Could not load spec for {file_path}")
                        continue
                        
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    
                    # Inspect the module for classes matching the protocol
                    for name, obj in inspect.getmembers(module):
                        if (inspect.isclass(obj) and 
                            obj.__module__ == module_name and
                            obj.__name__ != 'CheckProtocol' and
                            obj.__name__ != 'BaseCheck' and
                            not obj.__name__.startswith('_') and
                            hasattr(obj, 'execute') and callable(getattr(obj, 'execute'))):
                            
                            try:
                                self._validate_check_class(obj)
                                self.register_check(obj)
                                count += 1
                            except TypeError as e:
                                logger.debug(f"Skipping {name}: {e}")
                            
                except Exception as e:
                    logger.error(f"Error loading check module {file_path}: {e}")
                    
        logger.info(f"Successfully discovered {count} checks.")
        return count
        
    def _validate_check_class(self, check_class: Any) -> None:
        """Validate that a check class satisfies CheckProtocol at runtime."""
        required_attrs = ['CHECK_ID', 'TITLE', 'DESCRIPTION', 'CIS_CONTROL_ID', 'CIS_SEVERITY']

        for attr in required_attrs:
            if not hasattr(check_class, attr):
                raise TypeError(
                    f"Check class '{check_class.__name__}' is missing required "
                    f"attribute '{attr}'. All checks must satisfy CheckProtocol."
                )

        if not hasattr(check_class, 'execute') or not callable(getattr(check_class, 'execute')):
            raise TypeError(
                f"Check class '{check_class.__name__}' must have a callable 'execute' method."
            )

    def register_check(self, check_class: Type[CheckProtocol]) -> None:
        """Register a specific check class."""
        self._validate_check_class(check_class)
        check_id = check_class.CHECK_ID
        if not check_id:
            logger.warning(f"Class {check_class.__name__} has no CHECK_ID. Skipping.")
            return
            
        if check_id in self.checks:
            logger.debug(f"Overwriting existing check {check_id}")
            
        self.checks[check_id] = check_class
        
        # Add to category index
        category = getattr(check_class, 'CATEGORY', 'Uncategorized')
        if check_class not in self.categories[category]:
            self.categories[category].append(check_class)
            
        logger.debug(f"Registered check: {check_id} - {check_class.__name__}")

    def get_checks_by_tier(self, tier: str = "all") -> Dict[str, Type[CheckProtocol]]:
        """
        Return checks filtered by license tier.
        
        Args:
            tier: 'free', 'premium', or 'all'
        """
        tier = tier.lower()
        if tier == "all":
            return self.checks.copy()
            
        filtered = {}
        for check_id, check_class in self.checks.items():
            is_premium = getattr(check_class, 'REQUIRES_PREMIUM', False)
            if tier == "premium" and is_premium:
                filtered[check_id] = check_class
            elif tier == "free" and not is_premium:
                filtered[check_id] = check_class
                
        return filtered
        
    def get_check(self, check_id: str) -> Optional[Type[CheckProtocol]]:
        """Retrieve a specific check by its ID."""
        return self.checks.get(check_id)
        
    def get_all_checks(self) -> Dict[str, Type[CheckProtocol]]:
        """Retrieve all registered checks."""
        return self.checks.copy()

# Provide a global instance for easy access if desired
default_registry = CheckRegistry()
