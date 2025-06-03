from msal import PublicClientApplication

CLIENT_ID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
SCOPES = [
    'PrivilegedAccess.Read.AzureAD',
    'RoleManagement.Read.Directory',
    'Directory.Read.All',
    'Group.Read.All'
]

def get_token_interactive():
    app = PublicClientApplication(CLIENT_ID)
    result = app.acquire_token_interactive(scopes=SCOPES)
    token = result.get("access_token")
    if not token:
        raise Exception("Failed to authenticate.")
    return token
