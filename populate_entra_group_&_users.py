import os
import asyncio
import aiohttp
import random
import string
import json
import traceback
from datetime import datetime
from dotenv import load_dotenv
from msal import PublicClientApplication

load_dotenv()

# Azure AD configuration
CLIENT_ID = os.getenv("AZURE_AD_CLIENT_ID")
TENANT_ID = os.getenv("AZURE_AD_TENANT_ID")

# Microsoft Graph API endpoints
GRAPH_BASE_URL = "https://graph.microsoft.com/v1.0"

# Log file for tracking created resources
LOG_FILE = "azure_test_resources.json"

# Global variables for planned assignments
planned_group_assignments = {}
planned_user_assignments = {}

# Required scopes for creating groups, users, and assigning roles
SCOPES = [
    'PrivilegedAccess.Read.AzureAD',
    'RoleManagement.Read.Directory',
    'RoleManagement.ReadWrite.Directory',
    'Directory.Read.All',
    'Directory.ReadWrite.All',
    'Group.Read.All',
    'Group.ReadWrite.All',
    'User.ReadWrite.All',
    'PrivilegedAccess.ReadWrite.AzureAD'
]

def print_table(headers, rows, title=None):
    """Print a formatted table"""
    if title:
        print(f"\n{title}")
        print("=" * len(title))
    
    if not rows:
        print("No data to display")
        return
    
    # Calculate column widths
    col_widths = [len(header) for header in headers]
    for row in rows:
        for i, cell in enumerate(row):
            if i < len(col_widths):
                col_widths[i] = max(col_widths[i], len(str(cell)))
    
    # Print header
    header_row = " | ".join(headers[i].ljust(col_widths[i]) for i in range(len(headers)))
    print(header_row)
    print("-" * len(header_row))
    
    # Print rows
    for row in rows:
        data_row = " | ".join(str(row[i]).ljust(col_widths[i]) for i in range(len(row)))
        print(data_row)

def get_token_interactive_admin():
    """Get authentication token with admin permissions for creating resources"""
    print("Starting authentication process...")
    print("IMPORTANT: You must authenticate with your Global Admin account!")
    
    # Create a public client application for interactive login
    app = PublicClientApplication(
        client_id=CLIENT_ID,
        authority=f"https://login.microsoftonline.com/{TENANT_ID}"
    )
    
    # Try to get token from cache first
    accounts = app.get_accounts()
    if accounts:
        print(f"Found {len(accounts)} cached account(s). Trying to get silent token...")
        result = app.acquire_token_silent(scopes=SCOPES, account=accounts[0])
        if result and "access_token" in result:
            print("Got token from cache.")
            return result["access_token"]
    
    # If no cached token, get a new one
    print("No cached token found. Acquiring new token...")
    try:
        # Use device code flow
        flow = app.initiate_device_flow(scopes=SCOPES)
        print("Please use the following code to authenticate:")
        print(flow['message'])
        print("\nWaiting for authentication...")
        print("CRITICAL: Use your Global Admin account with permissions to create users/groups and assign roles!")
        
        # Wait for the user to complete the authentication
        result = app.acquire_token_by_device_flow(flow)
        
        if "error" in result:
            print(f"Authentication error: {result.get('error')}")
            print(f"Error description: {result.get('error_description')}")
            raise Exception(f"Failed to authenticate: {result.get('error_description')}")
            
        token = result.get("access_token")
        if not token:
            print(f"Failed to get token: {result.get('error_description', 'Unknown error')}")
            raise Exception("No access token in the response")
            
        print("Authentication successful with admin permissions.")
        return token
    except Exception as e:
        print(f"Authentication error details: {str(e)}")
        raise Exception(f"Authentication failed: {str(e)}")

def load_log():
    """Load the log file with created resources"""
    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, 'r') as f:
                return json.load(f)
        except:
            pass
    return {"groups": [], "users": [], "created_at": None}

def save_log(log_data):
    """Save the log file with created resources"""
    with open(LOG_FILE, 'w') as f:
        json.dump(log_data, f, indent=2)

def generate_strong_password(length=16):
    """Generate a strong password with mixed case, numbers, and symbols"""
    characters = string.ascii_letters + string.digits + "!@#$%^&*"
    password = ''.join(random.choice(characters) for _ in range(length))
    return password

async def check_pim_licensing(token):
    """Check if the tenant has the required licensing for PIM by creating a test user and attempting eligible assignment"""
    print("Testing PIM licensing capability...")
    print("Creating temporary test user 'License-Check' to verify PIM eligibility...")
    
    try:
        headers = {"Authorization": f"Bearer {token}"}
        
        async with aiohttp.ClientSession(headers=headers) as session:
            # Get tenant domain first
            domain = await get_tenant_domain(session)
            
            # Create a test user
            test_user_data = {
                "accountEnabled": False,
                "displayName": "License-Check",
                "givenName": "License",
                "surname": "Check",
                "userPrincipalName": f"license.check.test@{domain}",
                "mailNickname": "license.check.test",
                "passwordProfile": {
                    "forceChangePasswordNextSignIn": True,
                    "password": generate_strong_password()
                }
            }
            
            # Create the test user
            response = await session.post(f"{GRAPH_BASE_URL}/users", json=test_user_data)
            if response.status != 201:
                print(f"⚠️  Failed to create test user for license check: {response.status}")
                print("ℹ️  Assuming PIM is not available")
                return False
            
            test_user = await response.json()
            test_user_id = test_user['id']
            print(f"✓ Created test user: {test_user['displayName']}")
            
            # Get Global Reader role ID
            roles_response = await session.get(f"{GRAPH_BASE_URL}/roleManagement/directory/roleDefinitions")
            if roles_response.status != 200:
                print("⚠️  Failed to fetch roles for license test")
                # Clean up test user
                await session.delete(f"{GRAPH_BASE_URL}/users/{test_user_id}")
                return False
            
            roles_data = await roles_response.json()
            global_reader_role = None
            for role in roles_data['value']:
                if role['displayName'] == 'Global Reader':
                    global_reader_role = role
                    break
            
            if not global_reader_role:
                print("⚠️  Global Reader role not found for license test")
                # Clean up test user
                await session.delete(f"{GRAPH_BASE_URL}/users/{test_user_id}")
                return False
            
            print(f"✓ Found Global Reader role: {global_reader_role['id']}")
            
            # Try to assign Global Reader as eligible
            print("Attempting to assign Global Reader role as ELIGIBLE to test PIM licensing...")
            
            assignment_data = {
                "action": "adminAssign",
                "principalId": test_user_id,
                "roleDefinitionId": global_reader_role['id'],
                "directoryScopeId": "/",
                "scheduleInfo": {
                    "startDateTime": datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "expiration": {
                        "type": "noExpiration"
                    }
                }
            }
            
            pim_url = f"https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleRequests"
            pim_response = await session.post(pim_url, json=assignment_data)
            
            # Clean up test user regardless of result
            print("Cleaning up test user...")
            delete_response = await session.delete(f"{GRAPH_BASE_URL}/users/{test_user_id}")
            if delete_response.status == 204:
                print("✓ Test user deleted successfully")
            
            # Check PIM assignment result
            if pim_response.status == 201:
                print("✓ Microsoft Entra ID P2 or Governance license detected")
                print("✓ PIM eligible role assignments are available")
                return True
            else:
                error_text = await pim_response.text()
                print(f"✗ PIM eligible assignment failed: {pim_response.status}")
                
                if "AadPremiumLicenseRequired" in error_text:
                    print("⚠️  Microsoft Entra ID P2 or Governance license NOT detected")
                    print("⚠️  PIM eligible role assignments are NOT available")
                    print("ℹ️  Only active role assignments will be created")
                    return False
                else:
                    print(f"⚠️  Unexpected error during PIM test: {error_text}")
                    print("ℹ️  Assuming PIM is not available - only active assignments will be created")
                    return False
                
    except Exception as e:
        print(f"⚠️  Error during PIM license check: {e}")
        print("ℹ️  Assuming PIM is not available - only active assignments will be created")
        return False

def generate_role_assignments(available_roles, has_pim_license=True):
    """Generate role assignments for a principal with licensing awareness"""
    # Randomly select 1-5 roles
    num_roles = random.randint(1, 5)
    selected_roles = random.sample(available_roles, min(num_roles, len(available_roles)))
    
    assignments = []
    for role in selected_roles:
        if has_pim_license:
            # Mix of eligible and active if PIM is available
            assignment_type = random.choice(['eligible', 'active'])
        else:
            # Only active assignments if no PIM license
            assignment_type = 'active'
        
        assignments.append({
            'role': role,
            'type': assignment_type
        })
    
    return assignments

def get_fixed_group_names():
    """Return a fixed list of 20 realistic department/function names"""
    return [
        "Finance-Operations",
        "IT-Security", 
        "Marketing-Digital",
        "Human-Resources",
        "Sales-Enterprise",
        "Legal-Compliance",
        "Engineering-DevOps",
        "Procurement-Vendor",
        "Analytics-Business",
        "Customer-Support",
        "Research-Development",
        "Quality-Assurance",
        "Operations-Management",
        "Product-Management",
        "Communications-PR",
        "Facilities-Management",
        "Training-Development",
        "Risk-Management",
        "Strategic-Planning",
        "Audit-Internal"
    ]

def get_fixed_user_names():
    """Return a fixed list of 20 realistic user names"""
    return [
        "John Smith",
        "Sarah Johnson",
        "Michael Davis",
        "Jennifer Wilson",
        "David Brown",
        "Lisa Anderson",
        "Robert Taylor",
        "Maria Garcia",
        "James Miller",
        "Amanda Thompson",
        "Christopher Lee",
        "Michelle White",
        "Daniel Harris",
        "Jessica Martin",
        "Matthew Clark",
        "Ashley Lewis",
        "Andrew Walker",
        "Stephanie Hall",
        "Joshua Young",
        "Nicole Allen"
    ]

async def get_entra_roles(token):
    """Get available Entra roles for assignment"""
    try:
        headers = {"Authorization": f"Bearer {token}"}
        
        async with aiohttp.ClientSession(headers=headers) as session:
            response = await session.get(f"{GRAPH_BASE_URL}/roleManagement/directory/roleDefinitions")
            if response.status == 200:
                data = await response.json()
                all_roles = data['value']
                
                # Filter out roles that cannot be assigned to regular users/groups
                excluded_role_names = [
                    'Restricted Guest User',
                    'Guest User',
                    'Guest Inviter',
                    'Directory Synchronization Accounts',
                    'Company Administrator',  # Legacy name for Global Administrator
                    'Device',
                    'Device Local Administrator',
                    'Device Users',
                    'Workplace Device Join',
                    'Azure AD Joined Device Local Administrator',
                    'Azure Information Protection Administrator'  # Often restricted
                ]
                
                # Filter out excluded roles and built-in system roles
                filtered_roles = []
                for role in all_roles:
                    role_name = role.get('displayName', '')
                    
                    # Skip if it's in the excluded list
                    if role_name in excluded_role_names:
                        continue
                    
                    # Skip if it contains certain keywords that indicate system/guest roles
                    if any(keyword in role_name.lower() for keyword in ['guest', 'device', 'company administrator']):
                        continue
                    
                    # Skip if it's a built-in system role that can't be assigned
                    if role.get('isBuiltIn', False) and role_name in ['Restricted Guest User', 'Guest User']:
                        continue
                    
                    filtered_roles.append(role)
                
                print(f"Filtered out {len(all_roles) - len(filtered_roles)} non-assignable roles")
                print(f"Available for assignment: {len(filtered_roles)} roles")
                
                return filtered_roles
            else:
                print(f"Error fetching roles: {response.status}")
                return []
    except Exception as e:
        print(f"Error getting Entra roles: {e}")
        return []

async def create_group(session, group_name, description):
    """Create a new Azure AD group with role assignment capability"""
    # Add TEST- prefix to group name
    display_name = f"TEST-{group_name}"
    mail_nickname = display_name.replace(" ", "").replace("-", "").lower()[:20]
    
    group_data = {
        "displayName": display_name,
        "description": description,
        "groupTypes": [],
        "mailEnabled": False,
        "mailNickname": mail_nickname,
        "securityEnabled": True,
        "isAssignableToRole": True  # Enable role assignment for the group
    }
    
    try:
        response = await session.post(f"{GRAPH_BASE_URL}/groups", json=group_data)
        if response.status == 201:
            group = await response.json()
            print(f"Created group: {display_name}")
            return group
        else:
            error_text = await response.text()
            print(f"Error creating group {display_name}: {response.status} - {error_text}")
            return None
    except Exception as e:
        print(f"Exception creating group {display_name}: {e}")
        return None

async def create_user(session, user_name, password, domain):
    """Create a new Azure AD user (disabled by default for testing)"""
    first_name, last_name = user_name.split(' ', 1) if ' ' in user_name else (user_name, "User")
    
    # Add TEST- prefix to display name
    display_name = f"TEST-{user_name}"
    
    # Create unique UPN with timestamp to avoid conflicts
    timestamp = datetime.now().strftime("%H%M%S")
    user_principal_name = f"test.{first_name.lower()}.{last_name.lower().replace(' ', '')}.{timestamp}@{domain}"
    mail_nickname = f"test.{first_name.lower()}.{last_name.lower().replace(' ', '')}.{timestamp}"
    
    user_data = {
        "accountEnabled": False,  # Disabled for testing safety
        "displayName": display_name,
        "givenName": f"TEST-{first_name}",
        "surname": last_name,
        "userPrincipalName": user_principal_name,
        "mailNickname": mail_nickname,
        "passwordProfile": {
            "forceChangePasswordNextSignIn": True,
            "password": password
        }
    }
    
    try:
        response = await session.post(f"{GRAPH_BASE_URL}/users", json=user_data)
        if response.status == 201:
            user = await response.json()
            print(f"Created user: {display_name} (disabled)")
            return user
        else:
            error_text = await response.text()
            print(f"Error creating user {display_name}: {response.status} - {error_text}")
            return None
    except Exception as e:
        print(f"Exception creating user {display_name}: {e}")
        return None

async def assign_role_to_principal(session, principal_id, role_id, role_name, principal_type, assignment_type, role_assignments):
    """Assign a role to a user or group (eligible or active but not activated)"""
    
    if assignment_type == 'active':
        # Create a permanent role assignment (active but not activated)
        assignment_data = {
            "principalId": principal_id,
            "roleDefinitionId": role_id,
            "directoryScopeId": "/"
        }
        
        try:
            response = await session.post(f"{GRAPH_BASE_URL}/roleManagement/directory/roleAssignments", json=assignment_data)
            if response.status == 201:
                print(f"✓ Assigned {role_name} (ACTIVE) to {principal_type}")
                role_assignments.append({
                    "principal": principal_type,
                    "role": role_name,
                    "type": "Active",
                    "status": "Success"
                })
                return True
            else:
                error_text = await response.text()
                
                # Check for specific error types
                if response.status == 400:
                    if "guest" in role_name.lower():
                        print(f"⚠️  Skipped {role_name} (ACTIVE) - Guest roles cannot be manually assigned")
                        role_assignments.append({
                            "principal": principal_type,
                            "role": role_name,
                            "type": "Active",
                            "status": "Skipped - Guest role"
                        })
                    else:
                        print(f"✗ Error assigning {role_name} (ACTIVE) to {principal_type}: {response.status}")
                        print(f"   Error details: {error_text}")
                        role_assignments.append({
                            "principal": principal_type,
                            "role": role_name,
                            "type": "Active",
                            "status": f"Error {response.status}"
                        })
                else:
                    print(f"✗ Error assigning {role_name} (ACTIVE) to {principal_type}: {response.status}")
                    role_assignments.append({
                        "principal": principal_type,
                        "role": role_name,
                        "type": "Active",
                        "status": f"Error {response.status}"
                    })
                return False
        except Exception as e:
            print(f"✗ Exception assigning {role_name} (ACTIVE) to {principal_type}: {e}")
            role_assignments.append({
                "principal": principal_type,
                "role": role_name,
                "type": "Active",
                "status": f"Exception: {str(e)[:30]}"
            })
            return False
    else:
        # Create an eligible assignment using the working method from your old script
        assignment_data = {
            "action": "adminAssign",
            "principalId": principal_id,
            "roleDefinitionId": role_id,
            "directoryScopeId": "/",
            "scheduleInfo": {
                "startDateTime": datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
                "expiration": {
                    "type": "noExpiration"
                }
            }
        }
        
        try:
            # Use the correct PIM API endpoint that works in your old script
            pim_url = f"https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleRequests"
            response = await session.post(pim_url, json=assignment_data)
            
            if response.status == 201:
                print(f"✓ Assigned {role_name} (ELIGIBLE) to {principal_type}")
                role_assignments.append({
                    "principal": principal_type,
                    "role": role_name,
                    "type": "Eligible",
                    "status": "Success"
                })
                return True
            else:
                error_text = await response.text()
                
                # Check for specific error types
                if response.status == 400:
                    if "guest" in role_name.lower():
                        print(f"⚠️  Skipped {role_name} (ELIGIBLE) - Guest roles cannot be manually assigned")
                        role_assignments.append({
                            "principal": principal_type,
                            "role": role_name,
                            "type": "Eligible",
                            "status": "Skipped - Guest role"
                        })
                    else:
                        print(f"✗ Error assigning {role_name} (ELIGIBLE) to {principal_type}: {response.status}")
                        print(f"   Error details: {error_text}")
                        role_assignments.append({
                            "principal": principal_type,
                            "role": role_name,
                            "type": "Eligible",
                            "status": f"Error {response.status}"
                        })
                else:
                    print(f"✗ Error assigning {role_name} (ELIGIBLE) to {principal_type}: {response.status}")
                    print(f"   Error details: {error_text}")
                    role_assignments.append({
                        "principal": principal_type,
                        "role": role_name,
                        "type": "Eligible",
                        "status": f"Error {response.status}"
                    })
                return False
        except Exception as e:
            print(f"✗ Exception assigning {role_name} (ELIGIBLE) to {principal_type}: {e}")
            role_assignments.append({
                "principal": principal_type,
                "role": role_name,
                "type": "Eligible",
                "status": f"Exception: {str(e)[:30]}"
            })
            return False

async def remove_user_role_assignments(session, user_id, user_name):
    """Remove all role assignments for a user before deletion"""
    try:
        print(f"    Checking role assignments for {user_name}...")
        
        # Check for active role assignments
        active_url = f"{GRAPH_BASE_URL}/roleManagement/directory/roleAssignments?$filter=principalId eq '{user_id}'"
        response = await session.get(active_url)
        
        if response.status == 200:
            data = await response.json()
            assignments = data.get('value', [])
            
            if assignments:
                print(f"    Found {len(assignments)} active role assignments to remove...")
                for assignment in assignments:
                    delete_url = f"{GRAPH_BASE_URL}/roleManagement/directory/roleAssignments/{assignment['id']}"
                    delete_response = await session.delete(delete_url)
                    
                    if delete_response.status == 204:
                        print(f"    ✓ Removed active role assignment: {assignment['id']}")
                    else:
                        error_text = await delete_response.text()
                        print(f"    ✗ Failed to remove active role assignment: {error_text}")
        
        # Check for eligible role assignments (PIM)
        eligible_url = f"{GRAPH_BASE_URL}/roleManagement/directory/roleEligibilitySchedules?$filter=principalId eq '{user_id}'"
        response = await session.get(eligible_url)
        
        if response.status == 200:
            data = await response.json()
            schedules = data.get('value', [])
            
            if schedules:
                print(f"    Found {len(schedules)} eligible role assignments to remove...")
                for schedule in schedules:
                    # Create a request to remove the eligible assignment
                    remove_request = {
                        "action": "adminRemove",
                        "principalId": user_id,
                        "roleDefinitionId": schedule['roleDefinitionId'],
                        "directoryScopeId": schedule.get('directoryScopeId', '/'),
                        "justification": "Removing assignment before user deletion"
                    }
                    
                    remove_url = f"{GRAPH_BASE_URL}/roleManagement/directory/roleEligibilityScheduleRequests"
                    remove_response = await session.post(remove_url, json=remove_request)
                    
                    if remove_response.status in [200, 201]:
                        print(f"    ✓ Requested removal of eligible role assignment")
                    else:
                        error_text = await remove_response.text()
                        print(f"    ✗ Failed to remove eligible role assignment: {error_text}")
        
        # Small delay to allow role removal to propagate
        await asyncio.sleep(2)
        return True
        
    except Exception as e:
        print(f"    ✗ Error removing role assignments: {e}")
        return False

async def check_user_dependencies(session, user_id, user_name):
    """Check what might be preventing user deletion"""
    print(f"    Checking dependencies for {user_name}...")
    dependencies = []
    
    try:
        # Check owned applications
        apps_url = f"{GRAPH_BASE_URL}/users/{user_id}/ownedObjects?$filter=@odata.type eq 'microsoft.graph.application'"
        response = await session.get(apps_url)
        if response.status == 200:
            data = await response.json()
            apps = data.get('value', [])
            if apps:
                dependencies.append(f"Owns {len(apps)} applications")
        
        # Check owned service principals  
        sp_url = f"{GRAPH_BASE_URL}/users/{user_id}/ownedObjects?$filter=@odata.type eq 'microsoft.graph.servicePrincipal'"
        response = await session.get(sp_url)
        if response.status == 200:
            data = await response.json()
            sps = data.get('value', [])
            if sps:
                dependencies.append(f"Owns {len(sps)} service principals")
        
        # Check group memberships
        groups_url = f"{GRAPH_BASE_URL}/users/{user_id}/memberOf"
        response = await session.get(groups_url)
        if response.status == 200:
            data = await response.json()
            groups = data.get('value', [])
            if groups:
                dependencies.append(f"Member of {len(groups)} groups")
        
        # Check directory role memberships
        roles_url = f"{GRAPH_BASE_URL}/roleManagement/directory/roleAssignments?$filter=principalId eq '{user_id}'"
        response = await session.get(roles_url)
        if response.status == 200:
            data = await response.json()
            roles = data.get('value', [])
            if roles:
                dependencies.append(f"Has {len(roles)} active role assignments")
        
        if dependencies:
            print(f"    Dependencies found: {', '.join(dependencies)}")
        else:
            print(f"    No blocking dependencies found")
            
        return dependencies
        
    except Exception as e:
        print(f"    Error checking dependencies: {e}")
        return []

async def delete_group(session, group_id, group_name):
    """Delete an Azure AD group"""
    try:
        response = await session.delete(f"{GRAPH_BASE_URL}/groups/{group_id}")
        if response.status == 204:
            print(f"✓ Deleted group: {group_name}")
            return True
        else:
            error_text = await response.text()
            print(f"✗ Failed to delete group {group_name}: {response.status} - {error_text}")
            return False
    except Exception as e:
        print(f"✗ Exception deleting group {group_name}: {e}")
        return False

async def delete_user(session, user_id, user_name):
    """Delete an Azure AD user with enhanced role assignment removal"""
    try:
        # First, try to remove role assignments
        print(f"  Preparing user {user_name} for deletion...")
        
        # Remove role assignments first
        await remove_user_role_assignments(session, user_id, user_name)
        
        # Check for other dependencies
        dependencies = await check_user_dependencies(session, user_id, user_name)
        
        if dependencies:
            print(f"  ⚠️  User {user_name} has dependencies that may prevent deletion")
        
        # Now attempt to delete the user
        response = await session.delete(f"{GRAPH_BASE_URL}/users/{user_id}")
        if response.status == 204:
            print(f"✓ Deleted user: {user_name}")
            return True
        else:
            error_text = await response.text()
            
            # Provide more specific error guidance
            if response.status == 403:
                if "Authorization_RequestDenied" in error_text:
                    print(f"✗ Failed to delete user {user_name}: Insufficient privileges")
                    print(f"  💡 Possible causes:")
                    print(f"     - User has active role assignments (tried to remove them)")
                    print(f"     - User owns applications or service principals")
                    print(f"     - Missing required permissions in app registration")
                    print(f"     - User is protected by conditional access policies")
                else:
                    print(f"✗ Failed to delete user {user_name}: 403 Forbidden")
            elif response.status == 400:
                print(f"✗ Failed to delete user {user_name}: Bad Request")
                print(f"  💡 Check if the user exists and the request format is correct")
            else:
                print(f"✗ Failed to delete user {user_name}: {response.status} - {error_text}")
            
            return False
    except Exception as e:
        print(f"✗ Exception deleting user {user_name}: {e}")
        return False

async def batch_delete_resources(session, resources, resource_type):
    """Delete resources in batches with rate limiting"""
    deleted_count = 0
    failed_count = 0
    failed_items = []
    
    print(f"\nDeleting {len(resources)} {resource_type}s...")
    
    for i, resource in enumerate(resources, 1):
        print(f"[{i}/{len(resources)}] Deleting {resource_type}: {resource['displayName']}")
        
        if resource_type == "group":
            success = await delete_group(session, resource['id'], resource['displayName'])
        else:  # user
            success = await delete_user(session, resource['id'], resource['displayName'])
        
        if success:
            deleted_count += 1
        else:
            failed_count += 1
            failed_items.append(resource)
        
        # Rate limiting
        await asyncio.sleep(0.5)
    
    return deleted_count, failed_count, failed_items

async def get_tenant_domain(session):
    """Get the tenant's primary domain for user creation"""
    try:
        response = await session.get(f"{GRAPH_BASE_URL}/organization")
        if response.status == 200:
            data = await response.json()
            if data['value']:
                # Get the first verified domain
                for domain in data['value'][0].get('verifiedDomains', []):
                    if domain.get('isDefault', False):
                        return domain['name']
                # Fallback to first verified domain
                for domain in data['value'][0].get('verifiedDomains', []):
                    return domain['name']
        return "yourdomain.onmicrosoft.com"  # Fallback
    except Exception as e:
        print(f"Error getting tenant domain: {e}")
        return "yourdomain.onmicrosoft.com"

def preview_resources(group_names, user_names, available_roles, has_pim_license=True):
    """Display a preview of the resources that will be created with their role assignments"""
    print("\n" + "="*100)
    print("PREVIEW: Resources to be created")
    print("="*100)
    
    # Display licensing status
    if has_pim_license:
        print("🔐 PIM License: Available - Creating mix of Active and Eligible assignments")
    else:
        print("⚠️  PIM License: Not Available - Creating Active assignments only")
    
    print("="*100)
    
    # Store assignments for consistency between preview and actual creation
    global planned_group_assignments, planned_user_assignments
    planned_group_assignments = {}
    planned_user_assignments = {}
    
    # Preview groups with role assignments
    group_rows = []
    for i, name in enumerate(group_names[:20], 1):
        role_assignments = generate_role_assignments(available_roles, has_pim_license)
        planned_group_assignments[name] = role_assignments
        
        # Create role summary with types
        role_summary = []
        for ra in role_assignments:
            role_summary.append(f"{ra['role']['displayName']} ({ra['type']})")
        
        roles_str = ", ".join(role_summary)
        if len(roles_str) > 80:
            roles_str = roles_str[:80] + "..."
            
        group_rows.append([
            str(i), 
            f"TEST-{name}", 
            str(len(role_assignments)), 
            roles_str
        ])
    
    print_table(
        ["#", "Group Name", "Roles", "Role Assignments (Type)"],
        group_rows,
        f"GROUPS TO CREATE ({len(group_names[:20])})"
    )
    
    # Preview users with role assignments
    user_rows = []
    for i, name in enumerate(user_names[:20], 1):
        role_assignments = generate_role_assignments(available_roles, has_pim_license)
        planned_user_assignments[name] = role_assignments
        
        # Create role summary with types
        role_summary = []
        for ra in role_assignments:
            role_summary.append(f"{ra['role']['displayName']} ({ra['type']})")
        
        roles_str = ", ".join(role_summary)
        if len(roles_str) > 80:
            roles_str = roles_str[:80] + "..."
            
        user_rows.append([
            str(i), 
            f"TEST-{name}", 
            str(len(role_assignments)), 
            roles_str
        ])
    
    print_table(
        ["#", "User Name", "Roles", "Role Assignments (Type)"],
        user_rows,
        f"USERS TO CREATE ({len(user_names[:20])})"
    )
    
    # Update footer messaging based on licensing
    if has_pim_license:
        print(f"\nEach resource will be assigned 1-5 random roles with mix of eligible and active assignments")
        print(f"Active assignments will be permanent but not activated")
        print(f"Eligible assignments require activation through PIM")
    else:
        print(f"\nEach resource will be assigned 1-5 random roles with ACTIVE assignments only")
        print(f"Active assignments will be permanent but not activated")
        print(f"No eligible assignments will be created (requires Microsoft Entra ID P2 or Governance license)")
    
    print(f"All users will be created in DISABLED state for security")
    print(f"Strong passwords will be generated for all users")

async def create_test_resources():
    """Create test groups and users with confirmation"""
    print("=== Azure AD Test Environment Setup ===")
    
    try:
        # Get authentication token with admin permissions
        token = get_token_interactive_admin()
        
        # Check PIM licensing first with actual test
        print("\n=== Checking PIM Licensing ===")
        has_pim_license = await check_pim_licensing(token)
        
        # Get available roles
        print("\nFetching available Entra roles...")
        available_roles = await get_entra_roles(token)
        if not available_roles:
            print("No roles available. Exiting.")
            return
        
        print(f"Found {len(available_roles)} available roles")
        
        # Global variables to store planned assignments
        global planned_group_assignments, planned_user_assignments
        
        while True:
            # Use fixed names instead of AI generation
            print("\nUsing predefined group and user names...")
            group_names = get_fixed_group_names()
            user_names = get_fixed_user_names()
            
            # Show preview (this sets planned assignments)
            preview_resources(group_names, user_names, available_roles, has_pim_license)
            
            # Get user confirmation
            print("\n" + "="*100)
            while True:
                choice = input("Do you want to proceed with creating these resources? (y/yes/n/no/r/regenerate): ").strip().lower()
                if choice in ['y', 'yes']:
                    print("Proceeding with resource creation...")
                    break
                elif choice in ['n', 'no']:
                    print("Creation cancelled.")
                    return
                elif choice in ['r', 'regenerate']:
                    print("Regenerating names and role assignments...")
                    break
                else:
                    print("Please enter 'y'/'yes' (proceed), 'n'/'no' (cancel), or 'r'/'regenerate' (regenerate)")
            
            if choice in ['y', 'yes']:
                break
            # If choice == 'r', continue to regenerate
        
        # Proceed with creation
        headers = {"Authorization": f"Bearer {token}"}
        log_data = load_log()
        all_role_assignments = []
        
        # Store licensing info in log
        log_data["pimLicenseAvailable"] = has_pim_license
        log_data["licenseCheckDate"] = datetime.now().isoformat()
        
        async with aiohttp.ClientSession(headers=headers) as session:
            # Get tenant domain for user creation
            domain = await get_tenant_domain(session)
            print(f"Using domain: {domain}")
            
            # Create groups
            print("\n=== Creating Groups ===")
            created_groups = []
            for i, group_name in enumerate(group_names[:20]):
                description = f"Test group for role assignment testing - {group_name} department"
                group = await create_group(session, group_name, description)
                if group:
                    created_groups.append(group)
                    
                    # Store planned role assignments in log
                    planned_roles = planned_group_assignments.get(group_name, [])
                    role_assignments_for_log = []
                    for ra in planned_roles:
                        role_assignments_for_log.append({
                            "roleId": ra['role']['id'],
                            "roleName": ra['role']['displayName'],
                            "assignmentType": ra['type']
                        })
                    
                    log_data["groups"].append({
                        "id": group["id"],
                        "displayName": group["displayName"],
                        "plannedRoleAssignments": role_assignments_for_log,
                        "created_at": datetime.now().isoformat()
                    })
                await asyncio.sleep(0.5)  # Rate limiting
            
            # Create users
            print("\n=== Creating Users ===")
            created_users = []
            for i, user_name in enumerate(user_names[:20]):
                password = generate_strong_password()
                print(f"Password for TEST-{user_name}: {password}")
                user = await create_user(session, user_name, password, domain)
                if user:
                    created_users.append(user)
                    
                    # Store planned role assignments in log
                    planned_roles = planned_user_assignments.get(user_name, [])
                    role_assignments_for_log = []
                    for ra in planned_roles:
                        role_assignments_for_log.append({
                            "roleId": ra['role']['id'],
                            "roleName": ra['role']['displayName'],
                            "assignmentType": ra['type']
                        })
                    
                    log_data["users"].append({
                        "id": user["id"],
                        "displayName": user["displayName"],
                        "userPrincipalName": user["userPrincipalName"],
                        "password": password,
                        "plannedRoleAssignments": role_assignments_for_log,
                        "created_at": datetime.now().isoformat()
                    })
                await asyncio.sleep(0.5)  # Rate limiting
            
            # Assign roles to groups
            print("\n=== Assigning Roles to Groups ===")
            for group in created_groups:
                group_name = group['displayName'].replace('TEST-', '')
                role_assignments = planned_group_assignments.get(group_name, [])
                print(f"\nAssigning {len(role_assignments)} roles to group: {group['displayName']}")
                for assignment in role_assignments:
                    await assign_role_to_principal(
                        session, 
                        group['id'], 
                        assignment['role']['id'], 
                        assignment['role']['displayName'],
                        f"Group: {group['displayName']}", 
                        assignment['type'],
                        all_role_assignments
                    )
                    await asyncio.sleep(0.3)  # Rate limiting
            
            # Assign users to groups
            print("\n=== Assigning Users to Groups ===")
            group_memberships = await assign_users_to_groups(session, created_groups, created_users)
            
            # Assign roles to users
            print("\n=== Assigning Roles to Users ===")
            for user in created_users:
                user_name = user['displayName'].replace('TEST-', '')
                role_assignments = planned_user_assignments.get(user_name, [])
                print(f"\nAssigning {len(role_assignments)} roles to user: {user['displayName']}")
                for assignment in role_assignments:
                    await assign_role_to_principal(
                        session, 
                        user['id'], 
                        assignment['role']['id'], 
                        assignment['role']['displayName'],
                        f"User: {user['displayName']}", 
                        assignment['type'],
                        all_role_assignments
                    )
                    await asyncio.sleep(0.3)  # Rate limiting
            
            # Update log with creation timestamp and actual assignments
            if not log_data["created_at"]:
                log_data["created_at"] = datetime.now().isoformat()
            
            # Add actual role assignment results to log
            log_data["roleAssignmentResults"] = all_role_assignments
            
            # Add group membership results to log
            log_data["groupMemberships"] = group_memberships
            
            # Save log
            save_log(log_data)
            
            # Display summary tables
            print("\n" + "="*120)
            print("SUMMARY TABLES")
            print("="*120)
            
            # Display licensing status in summary
            if has_pim_license:
                print("🔐 PIM License Status: Available (Eligible assignments created)")
            else:
                print("⚠️  PIM License Status: Not Available (Active assignments only)")
            print("="*120)
            
            # Groups table with role details
            group_rows = []
            for group in created_groups:
                group_roles = [ra for ra in all_role_assignments if ra['principal'] == f"Group: {group['displayName']}"]
                active_roles = [ra for ra in group_roles if ra['type'] == 'Active' and ra['status'] == 'Success']
                eligible_roles = [ra for ra in group_roles if ra['type'] == 'Eligible' and ra['status'] == 'Success']
                
                roles_summary = f"Active: {len(active_roles)}, Eligible: {len(eligible_roles)}"
                sample_roles = ", ".join([f"{ra['role']} ({ra['type']})" for ra in group_roles[:3] if ra['status'] == 'Success'])
                if len([ra for ra in group_roles if ra['status'] == 'Success']) > 3:
                    sample_roles += "..."
                    
                group_rows.append([
                    group['displayName'],
                    str(len([ra for ra in group_roles if ra['status'] == 'Success'])),
                    roles_summary,
                    sample_roles
                ])
            
            print_table(
                ["Group Name", "Total Roles", "Assignment Types", "Sample Roles"],
                group_rows,
                "CREATED GROUPS AND THEIR ROLE ASSIGNMENTS"
            )
            
            # Users table with role details
            user_rows = []
            for user in created_users:
                user_roles = [ra for ra in all_role_assignments if ra['principal'] == f"User: {user['displayName']}"]
                active_roles = [ra for ra in user_roles if ra['type'] == 'Active' and ra['status'] == 'Success']
                eligible_roles = [ra for ra in user_roles if ra['type'] == 'Eligible' and ra['status'] == 'Success']
                
                roles_summary = f"Active: {len(active_roles)}, Eligible: {len(eligible_roles)}"
                sample_roles = ", ".join([f"{ra['role']} ({ra['type']})" for ra in user_roles[:2] if ra['status'] == 'Success'])
                if len([ra for ra in user_roles if ra['status'] == 'Success']) > 2:
                    sample_roles += "..."
                    
                user_rows.append([
                    user['displayName'],
                    user['userPrincipalName'],
                    str(len([ra for ra in user_roles if ra['status'] == 'Success'])),
                    roles_summary,
                    sample_roles
                ])
            
            print_table(
                ["User Name", "UPN", "Total Roles", "Assignment Types", "Sample Roles"],
                user_rows,
                "CREATED USERS AND THEIR ROLE ASSIGNMENTS"
            )
            
            # Role assignment summary
            total_assignments = len(all_role_assignments)
            active_successful = len([ra for ra in all_role_assignments if ra['type'] == 'Active' and ra['status'] == 'Success'])
            active_failed = len([ra for ra in all_role_assignments if ra['type'] == 'Active' and ra['status'] != 'Success'])
            eligible_successful = len([ra for ra in all_role_assignments if ra['type'] == 'Eligible' and ra['status'] == 'Success'])
            eligible_failed = len([ra for ra in all_role_assignments if ra['type'] == 'Eligible' and ra['status'] != 'Success'])
            
            summary_rows = [
                ["Total Role Assignments", str(total_assignments)],
                ["Active Assignments (Successful)", str(active_successful)],
                ["Active Assignments (Failed)", str(active_failed)],
                ["Eligible Assignments (Successful)", str(eligible_successful)],
                ["Eligible Assignments (Failed)", str(eligible_failed)],
                ["Groups Created", str(len(created_groups))],
                ["Users Created", str(len(created_users))],
                ["PIM License Available", "Yes" if has_pim_license else "No"]
            ]
            
            print_table(
                ["Metric", "Count"],
                summary_rows,
                "ASSIGNMENT SUMMARY"
            )
            
            print("\n=== Setup Complete ===")
            print(f"Created {len(created_groups)} groups and {len(created_users)} users")
            print("All users are created in disabled state for security")
            print("All resources have TEST- prefix for easy identification")
            
            if has_pim_license:
                print("Each resource assigned 1-5 roles with mix of active and eligible assignments")
                print("Active roles are assigned but not activated - users need to sign in to use them")
                print("Eligible roles require activation through PIM")
            else:
                print("Each resource assigned 1-5 active roles only (no PIM license detected)")
                print("Active roles are assigned but not activated - users need to sign in to use them")
            
            if eligible_failed > 0:
                print(f"Note: {eligible_failed} eligible assignments failed - this may be due to PIM licensing requirements")
    
    except Exception as e:
        print(f"Error creating test resources: {e}")
        traceback.print_exc()

async def assign_users_to_groups(session, created_groups, created_users):
    """Assign users to groups with 0-10 members each, ensuring at least 2 empty groups"""
    print("\n=== Assigning Users to Groups ===")
    
    if not created_groups or not created_users:
        print("No groups or users to assign")
        return []
    
    group_memberships = []
    
    # Ensure at least 2 groups remain empty
    num_groups = len(created_groups)
    empty_group_indices = random.sample(range(num_groups), min(2, num_groups))
    
    print(f"Ensuring groups at indices {empty_group_indices} remain empty")
    
    for i, group in enumerate(created_groups):
        if i in empty_group_indices:
            print(f"Leaving group {group['displayName']} empty (by design)")
            group_memberships.append({
                "groupId": group["id"],
                "groupName": group["displayName"],
                "members": [],
                "memberCount": 0
            })
            continue
        
        # Randomly assign 1-10 users to this group
        max_members = min(10, len(created_users))
        num_members = random.randint(1, max_members)
        selected_users = random.sample(created_users, num_members)
        
        print(f"Assigning {num_members} users to group: {group['displayName']}")
        
        group_members = []
        successful_assignments = 0
        
        for user in selected_users:
            try:
                # Add user to group using Graph API
                member_data = {
                    "@odata.id": f"https://graph.microsoft.com/v1.0/users/{user['id']}"
                }
                
                response = await session.post(
                    f"{GRAPH_BASE_URL}/groups/{group['id']}/members/$ref",
                    json=member_data
                )
                
                if response.status == 204:
                    print(f"  ✓ Added {user['displayName']} to {group['displayName']}")
                    group_members.append({
                        "userId": user["id"],
                        "userName": user["displayName"],
                        "userPrincipalName": user["userPrincipalName"]
                    })
                    successful_assignments += 1
                else:
                    error_text = await response.text()
                    print(f"  ✗ Failed to add {user['displayName']} to {group['displayName']}: {response.status}")
                    if "already exists" in error_text.lower():
                        print(f"    (User already in group)")
                        # Still count as successful since user is in the group
                        group_members.append({
                            "userId": user["id"],
                            "userName": user["displayName"],
                            "userPrincipalName": user["userPrincipalName"]
                        })
                        successful_assignments += 1
                
            except Exception as e:
                print(f"  ✗ Exception adding {user['displayName']} to {group['displayName']}: {e}")
            
            # Rate limiting
            await asyncio.sleep(0.2)
        
        group_memberships.append({
            "groupId": group["id"],
            "groupName": group["displayName"],
            "members": group_members,
            "memberCount": successful_assignments
        })
        
        print(f"  Successfully assigned {successful_assignments}/{num_members} users to {group['displayName']}")
    
    return group_memberships


async def delete_test_resources():
    """Delete all created test resources with comprehensive verification"""
    print("=== Deleting Test Resources ===")
    
    # Load log data
    log_data = load_log()
    
    if not log_data.get("groups", []) and not log_data.get("users", []):
        print("No resources found in log to delete.")
        
        # Also check for any orphaned TEST- resources in Azure
        print("Checking for orphaned TEST- resources in Azure...")
        await check_and_delete_orphaned_test_resources()
        return
    
    print(f"Found {len(log_data.get('groups', []))} groups and {len(log_data.get('users', []))} users in log")
    
    try:
        # Get authentication token
        token = get_token_interactive_admin()
        headers = {"Authorization": f"Bearer {token}"}
        
        async with aiohttp.ClientSession(headers=headers) as session:
            total_deleted = 0
            total_failed = 0
            
            # Delete groups from log using enhanced batch method
            groups_to_delete = log_data.get("groups", [])
            if groups_to_delete:
                deleted, failed, failed_items = await batch_delete_resources(session, groups_to_delete, "group")
                total_deleted += deleted
                total_failed += failed
                
                # Remove successfully deleted groups from log
                remaining_groups = failed_items
            else:
                remaining_groups = []
            
            # Delete users from log using enhanced batch method
            users_to_delete = log_data.get("users", [])
            if users_to_delete:
                deleted, failed, failed_items = await batch_delete_resources(session, users_to_delete, "user")
                total_deleted += deleted
                total_failed += failed
                
                # Remove successfully deleted users from log
                remaining_users = failed_items
            else:
                remaining_users = []
            
            # Update log file
            updated_log = {
                "groups": remaining_groups,
                "users": remaining_users,
                "created_at": None if not remaining_groups and not remaining_users else log_data.get("created_at")
            }
            
            # Preserve other log data
            for key in ["pimLicenseAvailable", "licenseCheckDate", "roleAssignmentResults"]:
                if key in log_data:
                    updated_log[key] = log_data[key]
            
            save_log(updated_log)
            
            # Display enhanced deletion summary
            print("\n" + "="*80)
            print("DELETION SUMMARY")
            print("="*80)
            
            groups_deleted = len(groups_to_delete) - len(remaining_groups) if groups_to_delete else 0
            groups_failed = len(remaining_groups) if remaining_groups else 0
            users_deleted = len(users_to_delete) - len(remaining_users) if users_to_delete else 0
            users_failed = len(remaining_users) if remaining_users else 0
            
            summary_rows = [
                ["Groups Successfully Deleted", str(groups_deleted)],
                ["Groups Failed to Delete", str(groups_failed)],
                ["Users Successfully Deleted", str(users_deleted)],
                ["Users Failed to Delete", str(users_failed)],
                ["Total Items Processed", str(len(groups_to_delete) + len(users_to_delete))],
                ["Total Successful Deletions", str(groups_deleted + users_deleted)],
                ["Total Failed Deletions", str(groups_failed + users_failed)]
            ]
            
            print_table(["Metric", "Count"], summary_rows, "")
            
            # Show failed items if any
            if remaining_groups or remaining_users:
                print("\nFAILED DELETIONS:")
                for group in remaining_groups:
                    print(f"  • Group: {group['displayName']} ({group['id']})")
                for user in remaining_users:
                    print(f"  • User: {user['displayName']} ({user['id']})")
                print("\nNote: Failed items may still exist in Azure AD - check portal if needed")
            
            if groups_failed + users_failed == 0:
                print("\n✓ All logged resources deleted successfully - log file cleared")
            else:
                print(f"\n⚠️  {groups_failed + users_failed} resources failed to delete - log file updated with remaining items")
        
        print("\n=== Deletion Process Complete ===")
        
    except Exception as e:
        print(f"Error in deletion process: {e}")
        import traceback
        traceback.print_exc()

async def check_and_delete_orphaned_test_resources():
    """Check for and delete any TEST- resources not in the log file"""
    try:
        token = get_token_interactive_admin()
        headers = {"Authorization": f"Bearer {token}"}
        
        async with aiohttp.ClientSession(headers=headers) as session:
            orphaned_groups = []
            orphaned_users = []
            
            # Check for orphaned test groups
            print("Checking for orphaned TEST- groups...")
            groups_response = await session.get(f"{GRAPH_BASE_URL}/groups?$filter=startswith(displayName,'TEST-')")
            if groups_response.status == 200:
                groups_data = await groups_response.json()
                orphaned_groups = groups_data.get('value', [])
            
            # Check for orphaned test users
            print("Checking for orphaned TEST- users...")
            users_response = await session.get(f"{GRAPH_BASE_URL}/users?$filter=startswith(displayName,'TEST-')")
            if users_response.status == 200:
                users_data = await users_response.json()
                orphaned_users = users_data.get('value', [])
            
            if orphaned_groups or orphaned_users:
                print(f"\nFound {len(orphaned_groups)} orphaned groups and {len(orphaned_users)} orphaned users")
                
                # Show what was found
                if orphaned_groups:
                    group_rows = [[group['displayName'], group['id']] for group in orphaned_groups[:10]]
                    print_table(["Group Name", "ID"], group_rows, f"ORPHANED GROUPS (showing first 10 of {len(orphaned_groups)})")
                
                if orphaned_users:
                    user_rows = [[user['displayName'], user['userPrincipalName']] for user in orphaned_users[:10]]
                    print_table(["User Name", "UPN"], user_rows, f"ORPHANED USERS (showing first 10 of {len(orphaned_users)})")
                
                # Ask for confirmation
                while True:
                    cleanup_choice = input("\nDo you want to delete these orphaned TEST- resources? (y/yes/n/no): ").strip().lower()
                    if cleanup_choice in ['y', 'yes']:
                        print("Deleting orphaned resources...")
                        
                        # Delete orphaned groups
                        for group in orphaned_groups:
                            await delete_group(session, group["id"], group["displayName"])
                            await asyncio.sleep(0.3)
                        
                        # Delete orphaned users
                        for user in orphaned_users:
                            await delete_user(session, user["id"], user["displayName"])
                            await asyncio.sleep(0.3)
                        
                        print("✓ Orphaned resource cleanup complete")
                        break
                    elif cleanup_choice in ['n', 'no']:
                        print("Orphaned resource cleanup skipped")
                        break
                    else:
                        print("Please enter 'y'/'yes' or 'n'/'no'")
            else:
                print("✓ No orphaned TEST- resources found")
                
    except Exception as e:
        print(f"Error checking for orphaned resources: {e}")

async def verify_deletion_capability():
    """Test the deletion capability by creating and deleting a test resource"""
    print("=== Verifying Deletion Capability ===")
    print("Creating a test group to verify deletion works...")
    
    try:
        token = get_token_interactive_admin()
        headers = {"Authorization": f"Bearer {token}"}
        
        async with aiohttp.ClientSession(headers=headers) as session:
            # Create a test group
            test_group_data = {
                "displayName": "TEST-DELETION-VERIFY",
                "description": "Temporary group to verify deletion capability",
                "groupTypes": [],
                "mailEnabled": False,
                "mailNickname": "testdeletionverify",
                "securityEnabled": True,
                "isAssignableToRole": True
            }
            
            create_response = await session.post(f"{GRAPH_BASE_URL}/groups", json=test_group_data)
            if create_response.status == 201:
                test_group = await create_response.json()
                print(f"✓ Created test group: {test_group['displayName']}")
                
                # Wait a moment
                await asyncio.sleep(2)
                
                # Now try to delete it
                delete_response = await session.delete(f"{GRAPH_BASE_URL}/groups/{test_group['id']}")
                if delete_response.status == 204:
                    print("✓ Successfully deleted test group")
                    print("✓ Deletion capability verified - you can safely create and delete resources")
                    return True
                else:
                    error_text = await delete_response.text()
                    print(f"✗ Failed to delete test group: {delete_response.status} - {error_text}")
                    print("⚠️  There may be issues with deletion permissions")
                    return False
            else:
                error_text = await create_response.text()
                print(f"✗ Failed to create test group: {create_response.status} - {error_text}")
                print("⚠️  There may be issues with creation permissions")
                return False
                
    except Exception as e:
        print(f"✗ Error during deletion verification: {e}")
        return False

def show_current_resources():
    """Show currently logged resources"""
    log_data = load_log()
    
    print("\n=== Current Test Resources ===")
    if log_data.get("created_at"):
        print(f"Created at: {log_data['created_at']}")
    
    # Show PIM license status if available
    if "pimLicenseAvailable" in log_data:
        pim_status = "Available" if log_data["pimLicenseAvailable"] else "Not Available"
        print(f"PIM License Status: {pim_status}")
        if "licenseCheckDate" in log_data:
            print(f"License checked at: {log_data['licenseCheckDate']}")
    
    # Groups table
    group_rows = []
    for group in log_data.get("groups", []):
        role_count = len(group.get('plannedRoleAssignments', []))
        group_rows.append([
            group['displayName'],
            group['id'],
            str(role_count),
            group['created_at']
        ])
    
    print_table(
        ["Group Name", "ID", "Planned Roles", "Created At"],
        group_rows,
        f"GROUPS ({len(log_data.get('groups', []))})"
    )
    
    # Users table
    user_rows = []
    for user in log_data.get("users", []):
        role_count = len(user.get('plannedRoleAssignments', []))
        user_rows.append([
            user['displayName'],
            user['userPrincipalName'],
            str(role_count),
            user['created_at']
        ])
    
    print_table(
        ["User Name", "UPN", "Planned Roles", "Created At"],
        user_rows,
        f"USERS ({len(log_data.get('users', []))})"
    )
    
    # Show role assignment results if available
    if "roleAssignmentResults" in log_data:
        results = log_data["roleAssignmentResults"]
        successful = len([r for r in results if r.get('status') == 'Success'])
        failed = len([r for r in results if r.get('status') != 'Success'])
        
        print(f"\nRole Assignment Results: {successful} successful, {failed} failed")
    
    if not log_data.get("groups", []) and not log_data.get("users", []):
        print("No test resources found in log.")
        print("Use option 1 to create test resources.")

async def populate_existing_groups():
    """Populate existing groups with users from the log"""
    print("=== Populating Existing Groups with Users ===")
    
    # Load log data
    log_data = load_log()
    
    if not log_data.get("groups", []):
        print("No groups found in log. Please create groups first using option 1.")
        return
    
    if not log_data.get("users", []):
        print("No users found in log. Please create users first using option 1.")
        return
    
    groups = log_data.get("groups", [])
    users = log_data.get("users", [])
    
    print(f"Found {len(groups)} groups and {len(users)} users in log")
    
    # Check if groups already have memberships
    existing_memberships = log_data.get("groupMemberships", [])
    if existing_memberships:
        print(f"\nFound existing group memberships:")
        for membership in existing_memberships:
            print(f"  • {membership['groupName']}: {membership['memberCount']} members")
        
        while True:
            choice = input("\nDo you want to reassign users to groups? This will replace existing assignments (y/yes/n/no): ").strip().lower()
            if choice in ['n', 'no']:
                print("Group population cancelled.")
                return
            elif choice in ['y', 'yes']:
                print("Proceeding with reassignment...")
                break
            else:
                print("Please enter 'y'/'yes' or 'n'/'no'")
    
    try:
        # Get authentication token
        token = get_token_interactive_admin()
        headers = {"Authorization": f"Bearer {token}"}
        
        async with aiohttp.ClientSession(headers=headers) as session:
            # Convert log data to the format expected by assign_users_to_groups
            created_groups = []
            for group in groups:
                created_groups.append({
                    "id": group["id"],
                    "displayName": group["displayName"]
                })
            
            created_users = []
            for user in users:
                created_users.append({
                    "id": user["id"],
                    "displayName": user["displayName"],
                    "userPrincipalName": user["userPrincipalName"]
                })
            
            # Remove existing group memberships if any
            if existing_memberships:
                print("\n=== Removing Existing Group Memberships ===")
                for membership in existing_memberships:
                    group_id = membership["groupId"]
                    group_name = membership["groupName"]
                    members = membership.get("members", [])
                    
                    print(f"Removing {len(members)} members from {group_name}")
                    for member in members:
                        try:
                            # Remove user from group
                            response = await session.delete(
                                f"{GRAPH_BASE_URL}/groups/{group_id}/members/{member['userId']}/$ref"
                            )
                            if response.status == 204:
                                print(f"  ✓ Removed {member['userName']} from {group_name}")
                            else:
                                print(f"  ⚠️  Could not remove {member['userName']} from {group_name} (may not be a member)")
                        except Exception as e:
                            print(f"  ✗ Exception removing {member['userName']} from {group_name}: {e}")
                        
                        await asyncio.sleep(0.1)  # Rate limiting
            
            # Assign users to groups
            group_memberships = await assign_users_to_groups(session, created_groups, created_users)
            
            # Update log with new group memberships
            log_data["groupMemberships"] = group_memberships
            save_log(log_data)
            
            # Display summary
            print("\n" + "="*80)
            print("GROUP POPULATION SUMMARY")
            print("="*80)
            
            total_assignments = sum(membership["memberCount"] for membership in group_memberships)
            empty_groups = len([m for m in group_memberships if m["memberCount"] == 0])
            populated_groups = len([m for m in group_memberships if m["memberCount"] > 0])
            
            summary_rows = [
                ["Total Groups", str(len(group_memberships))],
                ["Empty Groups", str(empty_groups)], 
                ["Populated Groups", str(populated_groups)],
                ["Total User Assignments", str(total_assignments)],
                ["Average Members per Populated Group", f"{total_assignments/populated_groups:.1f}" if populated_groups > 0 else "0"]
            ]
            
            print_table(["Metric", "Count"], summary_rows, "")
            
            # Show detailed group memberships
            membership_rows = []
            for membership in group_memberships:
                member_names = [member["userName"] for member in membership["members"][:3]]
                member_display = ", ".join(member_names)
                if len(membership["members"]) > 3:
                    member_display += f" (and {len(membership['members']) - 3} more)"
                elif len(membership["members"]) == 0:
                    member_display = "(empty)"
                
                membership_rows.append([
                    membership["groupName"],
                    str(membership["memberCount"]),
                    member_display
                ])
            
            print_table(
                ["Group Name", "Members", "Sample Members"],
                membership_rows,
                "GROUP MEMBERSHIPS"
            )
            
            print("\n✓ Group population complete!")
            print(f"Successfully assigned users to {populated_groups} groups")
            print(f"Left {empty_groups} groups empty as required")
    
    except Exception as e:
        print(f"Error populating groups: {e}")
        traceback.print_exc()

def show_menu():
    """Display the main menu"""
    print("\n" + "="*50)
    print("Azure AD Test Environment Manager")
    print("="*50)
    print("1. Create users and groups")
    print("2. Delete created users and groups")
    print("3. Show current resources")
    print("4. Verify deletion capability")
    print("5. Populate groups with users")
    print("6. Exit")
    print("="*50)

async def main():
    """Main function with menu"""
    while True:
        show_menu()
        choice = input("Enter your choice (1-6): ").strip()
        
        if choice == "1":
            await create_test_resources()
        elif choice == "2":
            confirm = input("Are you sure you want to delete all test resources? (y/yes/n/no): ").strip().lower()
            if confirm in ['yes', 'y']:
                await delete_test_resources()
            else:
                print("Deletion cancelled.")
        elif choice == "3":
            show_current_resources()
        elif choice == "4":
            await verify_deletion_capability()
        elif choice == "5":
            await populate_existing_groups()
        elif choice == "6":
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please enter 1, 2, 3, 4, 5, or 6.")

# Entry point - this is what makes the script executable
if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\nScript interrupted by user. Exiting...")
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        import traceback
        traceback.print_exc()


