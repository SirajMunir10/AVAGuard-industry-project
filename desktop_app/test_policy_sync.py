import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'desktop_app'))
from web_client import WebPortalClient
from workers.enhanced_worker import EnhancedScanWorker

print("Testing WebPortalClient")
client = WebPortalClient("http://localhost:8000")
success = client.login("admin@example.com", "admin")  # Try to login
if success:
    print("Login successful")
    token = client._token.access_token
    
    # Try fetching policies directly
    succ, policies = client.get_active_policies()
    print("Policies fetch success:", succ)
    print("Policies:", policies)
    
    # Try EnhancedScanWorker
    print("Testing EnhancedScanWorker...")
    worker = EnhancedScanWorker(use_mock=True, portal_url="http://localhost:8000", access_token=token)
    checks = worker._select_checks()
    print("Worker selected checks:", len(checks))
else:
    print("Login failed")
