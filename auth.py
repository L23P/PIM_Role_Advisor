import os
import webbrowser
import sys
from msal import PublicClientApplication
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Get client and tenant IDs from environment variables
CLIENT_ID = os.getenv("AZURE_AD_CLIENT_ID")
TENANT_ID = os.getenv("AZURE_AD_TENANT_ID")

SCOPES = [
    'PrivilegedAccess.Read.AzureAD',
    'PrivilegedAccess.ReadWrite.AzureAD',
    'RoleManagement.Read.Directory',
    'RoleManagement.ReadWrite.Directory',
    'Directory.Read.All',
    'Directory.ReadWrite.All',
    'Group.Read.All',
    'Group.ReadWrite.All',
    'User.Read.All',
    'User.ReadWrite.All',
    'AuditLog.Read.All',
    'Policy.Read.All'
]

# Global token cache
_cached_token = None
_token_expires_at = None

def get_cached_token():
    """Get cached token if available and not expired"""
    global _cached_token, _token_expires_at
    
    if _cached_token and _token_expires_at:
        from datetime import datetime
        if datetime.now() < _token_expires_at:
            print("Using cached token")
            return _cached_token
    
    print("No valid cached token available")
    return None

def cache_token(token, expires_in=3600):
    """Cache the token with expiration"""
    global _cached_token, _token_expires_at
    from datetime import datetime, timedelta
    
    _cached_token = token
    _token_expires_at = datetime.now() + timedelta(seconds=expires_in - 300)  # 5 min buffer
    print(f"Token cached until {_token_expires_at}")

def get_token_interactive():
    """Get token interactively with caching"""
    print("=== STARTING AUTHENTICATION PROCESS ===")
    print(f"CLIENT_ID: {CLIENT_ID[:8] + '...' if CLIENT_ID else 'NOT SET'}")
    print(f"TENANT_ID: {TENANT_ID[:8] + '...' if TENANT_ID else 'NOT SET'}")
    print(f"SCOPES: {SCOPES}")
    
    if not CLIENT_ID or not TENANT_ID:
        raise Exception("AZURE_AD_CLIENT_ID and AZURE_AD_TENANT_ID must be set in environment variables")
    
    # Check cache first
    print("Step 1: Checking for cached token...")
    cached_token = get_cached_token()
    if cached_token:
        print("Step 1 COMPLETE: Using cached token")
        return cached_token
    
    print("Step 1 COMPLETE: No cached token found")
    print("Step 2: Creating MSAL PublicClientApplication...")
    
    try:
        # Create a public client application for interactive login
        app = PublicClientApplication(
            client_id=CLIENT_ID,
            authority=f"https://login.microsoftonline.com/{TENANT_ID}"        )
        print("Step 2 COMPLETE: MSAL app created successfully")
    except Exception as e:
        print(f"Step 2 FAILED: Error creating MSAL app: {str(e)}")
        raise
    
    # Try to get token from cache first
    print("Step 3: Checking MSAL token cache...")
    try:
        accounts = app.get_accounts()
        print(f"Step 3 INFO: Found {len(accounts)} cached account(s)")
    except Exception as e:
        print(f"Step 3 FAILED: Error getting accounts: {str(e)}")
        raise
    
    if accounts:
        print("Step 3a: Trying to get silent token from cached account...")
        # Use the first account
        result = app.acquire_token_silent(scopes=SCOPES, account=accounts[0])
        if result and "access_token" in result:
            print("Step 3 COMPLETE: Got token from MSAL cache.")
            token = result["access_token"]
            expires_in = int(result.get("expires_in", 3600))
            cache_token(token, expires_in)
            return token
        else:            print("Step 3 INFO: Silent token acquisition failed")
    
    # If no cached token, get a new one
    print("Step 4: Starting device code flow...")
    print("WARNING: This requires user interaction in the console!")
    try:
        print("Step 4a: About to call app.initiate_device_flow()...")
        print(f"Step 4a: Using scopes: {SCOPES}")
        
        # Use default device code flow which is more reliable and doesn't require redirect URIs
        # This will print a code to the console and instructions to authenticate
        flow = app.initiate_device_flow(scopes=SCOPES)
        
        print("Step 4b: Device flow initiated successfully!")
        print(f"Step 4b: Flow keys: {list(flow.keys()) if flow else 'None'}")
        
        if not flow or 'user_code' not in flow:
            raise Exception("Device flow initiation failed - no user code received")
        
        print("=== AUTHENTICATION CODE ===")
        print(flow['message'])
        print("=============================")
        print(f"User Code: {flow.get('user_code', 'NOT FOUND')}")
        print(f"Device Code: {flow.get('device_code', 'NOT FOUND')[:20]}...")
        print("Step 4c: Waiting for user authentication...")
        print("Step 4c: About to call app.acquire_token_by_device_flow() - this will block until user completes authentication")
        
        # Wait for the user to complete the authentication
        result = app.acquire_token_by_device_flow(flow)
        
        print("Step 4d: Device flow completed!")
        print(f"Step 4d: Result type: {type(result)}")
        print(f"Step 4d: Result keys: {list(result.keys()) if result else 'None'}")
        print("Authentication completed with status:", "Success" if result and "access_token" in result else "Failed")
        
        if "error" in result:
            print(f"Authentication error: {result.get('error')}")
            print(f"Error description: {result.get('error_description')}")
            raise Exception(f"Failed to authenticate: {result.get('error_description')}")
            
        token = result.get("access_token")
        if not token:
            print(f"Failed to get token: {result.get('error_description', 'Unknown error')}")
            raise Exception("No access token in the response")
            
        expires_in = int(result.get("expires_in", 3600))
        cache_token(token, expires_in)
        print("Authentication successful.")
        return token
    except Exception as e:
        print(f"Authentication error details: {str(e)}")
        raise Exception(f"Authentication failed: {str(e)}")
