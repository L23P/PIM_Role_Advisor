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

def get_token_interactive():
    print("Starting authentication process...")
    
    # Create a public client application for interactive login
    app = PublicClientApplication(
        client_id=CLIENT_ID,
        authority=f"https://login.microsoftonline.com/{TENANT_ID}"
    )
    
    # Try to get token from cache first
    accounts = app.get_accounts()
    if accounts:
        print(f"Found {len(accounts)} cached account(s). Trying to get silent token...")
        # Use the first account
        result = app.acquire_token_silent(scopes=SCOPES, account=accounts[0])
        if result and "access_token" in result:
            print("Got token from cache.")
            return result["access_token"]
      # If no cached token, get a new one
    print("No cached token found. Acquiring new token...")
    try:
        # Use default device code flow which is more reliable and doesn't require redirect URIs
        # This will print a code to the console and instructions to authenticate
        flow = app.initiate_device_flow(scopes=SCOPES)
        print("Please use the following code to authenticate:")
        print(flow['message'])
        print("\nWaiting for authentication...")
        
        # Wait for the user to complete the authentication
        result = app.acquire_token_by_device_flow(flow)
        
        print("Authentication result keys:", result.keys())
        print("Authentication completed with status:", "Success" if "access_token" in result else "Failed")
        
        if "error" in result:
            print(f"Authentication error: {result.get('error')}")
            print(f"Error description: {result.get('error_description')}")
            raise Exception(f"Failed to authenticate: {result.get('error_description')}")
            
        token = result.get("access_token")
        if not token:
            print(f"Failed to get token: {result.get('error_description', 'Unknown error')}")
            raise Exception("No access token in the response")
            
        print("Authentication successful.")
        return token
    except Exception as e:
        print(f"Authentication error details: {str(e)}")
        raise Exception(f"Authentication failed: {str(e)}")
        raise
