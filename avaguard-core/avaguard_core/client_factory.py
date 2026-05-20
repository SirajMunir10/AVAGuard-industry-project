"""Factory pattern for creating Graph API clients depending on environment."""

import os
import logging
from typing import Dict, Any, Optional

from .mock_graph_client import MockGraphAPIClient
from .graph_api_client import GraphAPIClient

logger = logging.getLogger(__name__)

class GraphClientFactory:
    """Creates the appropriate Graph API client based on the requested mode."""
    
    @staticmethod
    def create_client(mode: str = "mock", config: Optional[Dict[str, Any]] = None) -> Any:
        """
        Create a Graph API client.
        
        Args:
            mode: 'mock' or 'live'
            config: Dictionary containing configuration parameters:
                For 'mock':
                    - mock_data (optional): Path to the mock JSON dataset. 
                                          Defaults to enterprise_dataset.json
                For 'live':
                    - tenant_id (required): Azure AD tenant ID
                    - client_id (required): Application client ID
                    - client_secret (optional): Application secret for automation
                    - use_device_code (optional): Force interactive device code flow
        
        Returns:
            An instance of MockGraphAPIClient or GraphAPIClient
        """
        config = config or {}
        mode = mode.lower().strip()
        
        # Override with environment variable if present
        env_mode = os.environ.get("AVAGUARD_MODE")
        if env_mode in ["mock", "live"]:
            mode = env_mode
            
        if mode == "mock":
            mock_data_path = config.get('mock_data', 'enterprise_dataset.json')
            logger.info(f"Initializing Mock Graph API Client with dataset: {mock_data_path}")
            return MockGraphAPIClient(mock_data_file=mock_data_path)
            
        elif mode == "live":
            tenant_id = config.get('tenant_id') or os.environ.get('AZURE_TENANT_ID')
            client_id = config.get('client_id') or os.environ.get('AZURE_CLIENT_ID')
            client_secret = config.get('client_secret') or os.environ.get('AZURE_CLIENT_SECRET')
            use_device_code = config.get('use_device_code', False)
            
            if not tenant_id or not client_id:
                raise ValueError(
                    "Live mode requires 'tenant_id' and 'client_id' in config or "
                    "AZURE_TENANT_ID and AZURE_CLIENT_ID environment variables."
                )
                
            # If no secret is provided, we default to device code flow
            if not client_secret:
                use_device_code = True
                
            logger.info(
                f"Initializing Live Graph API Client for tenant {tenant_id}. "
                f"Auth flow: {'Device Code' if use_device_code else 'Client Credentials'}"
            )
                
            return GraphAPIClient(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret,
                use_device_code=use_device_code
            )
            
        else:
            raise ValueError(f"Invalid Graph API client mode: {mode}. Must be 'mock' or 'live'.")
