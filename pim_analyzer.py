"""
PIM Role Analyzer - Advanced analytical features for scanning Entra ID
and providing intelligent RBAC recommendations and groupings.
Enhanced with Azure OpenAI for intelligent recommendation generation.
"""

import asyncio
import aiohttp
import json
import os
import requests
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from typing import Dict, List, Any, Tuple, Optional
from dataclasses import dataclass, asdict
import logging
from dotenv import load_dotenv
from prompts import get_user_analysis_prompt, get_group_analysis_prompt, get_global_analysis_prompt, get_system_message

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Azure OpenAI configuration
AZURE_OPENAI_API_KEY = os.getenv('AZURE_OPENAI_API_KEY')
AZURE_OPENAI_ENDPOINT = os.getenv('AZURE_OPENAI_ENDPOINT')
AZURE_OPENAI_DEPLOYMENT = os.getenv('AZURE_OPENAI_DEPLOYMENT')
AZURE_OPENAI_API_VERSION = '2024-12-01-preview'

class AIRecommendationEngine:
    """Azure OpenAI-powered recommendation engine for PIM analysis"""
    
    def __init__(self):
        self.api_key = AZURE_OPENAI_API_KEY
        self.endpoint = AZURE_OPENAI_ENDPOINT
        self.deployment = AZURE_OPENAI_DEPLOYMENT
        self.api_version = AZURE_OPENAI_API_VERSION
        
        if not all([self.api_key, self.endpoint, self.deployment]):
            logger.warning("Azure OpenAI configuration incomplete - falling back to rule-based recommendations")
            self.enabled = False
        else:
            self.enabled = True
            self.uri = f"{self.endpoint}/openai/deployments/{self.deployment}/chat/completions?api-version={self.api_version}"
    def generate_user_recommendations(self, user_analysis: Dict, context: Optional[Dict] = None) -> List[str]:
        """Generate AI-powered recommendations for a specific user"""
        if not self.enabled:
            return self._fallback_user_recommendations(user_analysis)
        
        try:
            prompt = get_user_analysis_prompt(user_analysis, context)
            response = self._call_openai(prompt, "user_analysis")
            return self._parse_recommendations(response)
        except Exception as e:
            logger.error(f"AI recommendation generation failed: {e}")
            return self._fallback_user_recommendations(user_analysis)
    
    def generate_group_recommendations(self, group_analysis: Dict, context: Optional[Dict] = None) -> List[str]:
        """Generate AI-powered recommendations for a specific group"""
        if not self.enabled:
            return self._fallback_group_recommendations(group_analysis)
        
        try:
            prompt = get_group_analysis_prompt(group_analysis, context)
            response = self._call_openai(prompt, "group_analysis")
            return self._parse_recommendations(response)
        except Exception as e:
            logger.error(f"AI recommendation generation failed: {e}")
            return self._fallback_group_recommendations(group_analysis)
    
    def generate_global_recommendations(self, analysis_summary: Dict) -> List[str]:
        """Generate AI-powered global recommendations for the entire environment"""
        if not self.enabled:
            return self._fallback_global_recommendations(analysis_summary)
        
        try:
            prompt = get_global_analysis_prompt(analysis_summary)
            response = self._call_openai(prompt, "global_analysis")
            return self._parse_recommendations(response)
        except Exception as e:
            logger.error(f"AI recommendation generation failed: {e}")
            return self._fallback_global_recommendations(analysis_summary)
    def _call_openai(self, prompt: str, analysis_type: str) -> str:
        """Make a call to Azure OpenAI API"""
        headers = {
            'api-key': self.api_key,
            'Content-Type': 'application/json'
        }
        
        system_message = get_system_message()

        data = {
            'model': self.deployment,
            'temperature': 0.3,  # Lower temperature for more consistent security recommendations
            'max_tokens': 1500,
            'messages': [
                {"role": "system", "content": system_message},
                {"role": "user", "content": prompt}
            ]
        }
        
        response = requests.post(self.uri, headers=headers, json=data, timeout=30)
        response.raise_for_status()
        
        result = response.json()
        return result['choices'][0]['message']['content']
    
    def _build_user_prompt(self, user_analysis: Dict, context: Optional[Dict] = None) -> str:
        """Build a prompt for user-specific analysis"""
        user_name = user_analysis.get('user_name', 'Unknown')
        email = user_analysis.get('user_email', 'Unknown')
        department = user_analysis.get('department', 'Unknown')
        job_title = user_analysis.get('job_title', 'Unknown')
        active_roles = user_analysis.get('active_roles', [])
        eligible_roles = user_analysis.get('eligible_roles', [])
        last_signin = user_analysis.get('last_signin', 'Unknown')
        group_memberships = user_analysis.get('group_memberships', [])
        
        active_role_names = [role.get('role_name', 'Unknown') for role in active_roles]
        eligible_role_names = [role.get('role_name', 'Unknown') for role in eligible_roles]
        
        context_info = ""
        if context:
            total_users = context.get('total_users', 0)
            avg_roles_per_user = context.get('avg_roles_per_user', 0)
            context_info = f"\n\nEnvironment Context:\n- Total users in tenant: {total_users}\n- Average roles per user: {avg_roles_per_user:.1f}"
        
        return f"""Analyze this Entra ID user and provide specific security recommendations:

User Profile:
- Name: {user_name}
- Email: {email}
- Department: {department}
- Job Title: {job_title}
- Last Sign-in: {last_signin}

Current Permissions:
- Active Roles ({len(active_roles)}): {', '.join(active_role_names)}
- Eligible Roles ({len(eligible_roles)}): {', '.join(eligible_role_names)}
- Group Memberships ({len(group_memberships)}): {', '.join(group_memberships[:5])}{'...' if len(group_memberships) > 5 else ''}

{context_info}

Provide 2-4 specific, actionable recommendations for this user focusing on:
1. Role optimization (active vs eligible assignments)
2. Security risk mitigation
3. Compliance considerations
4. Access pattern analysis

Format as bullet points, each starting with a clear action verb."""
    
    def _build_group_prompt(self, group_analysis: Dict, context: Optional[Dict] = None) -> str:
        """Build a prompt for group-specific analysis"""
        group_name = group_analysis.get('group_name', 'Unknown')
        group_type = group_analysis.get('group_type', 'Unknown')
        members_count = group_analysis.get('members_count', 0)
        role_assignments = group_analysis.get('role_assignments', [])
        member_overlap = group_analysis.get('member_overlap', {})
        usage_score = group_analysis.get('usage_score', 0.0)
        
        role_names = [role.get('role_name', 'Unknown') for role in role_assignments]
        overlap_summary = ", ".join([f"{name} ({count})" for name, count in list(member_overlap.items())[:3]])
        
        return f"""Analyze this Entra ID group and provide specific optimization recommendations:

Group Profile:
- Name: {group_name}
- Type: {group_type}
- Members: {members_count}
- Usage Score: {usage_score:.2f}

Role Assignments ({len(role_assignments)}):
{', '.join(role_names)}

Member Overlap with Other Groups:
{overlap_summary}

Provide 2-3 specific recommendations for optimizing this group focusing on:
1. Group structure efficiency
2. Role assignment optimization
3. Member management
4. Security considerations

Format as bullet points, each starting with a clear action verb."""
    
    def _build_global_prompt(self, analysis_summary: Dict) -> str:
        """Build a prompt for global environment analysis"""
        total_users = analysis_summary.get('total_users', 0)
        total_groups = analysis_summary.get('total_groups', 0)
        total_roles = analysis_summary.get('total_roles', 0)
        total_assignments = analysis_summary.get('total_role_assignments', 0)
        high_risk_users = analysis_summary.get('high_risk_users', 0)
        medium_risk_users = analysis_summary.get('medium_risk_users', 0)
        
        return f"""Analyze this Entra ID environment and provide strategic RBAC recommendations:

Environment Overview:
- Total Users: {total_users}
- Total Groups: {total_groups}
- Total Roles: {total_roles}
- Total Role Assignments: {total_assignments}
- High Risk Users: {high_risk_users}
- Medium Risk Users: {medium_risk_users}

Risk Distribution:
- High Risk: {high_risk_users} users ({(high_risk_users/max(total_users,1)*100):.1f}%)
- Medium Risk: {medium_risk_users} users ({(medium_risk_users/max(total_users,1)*100):.1f}%)

Provide 4-6 strategic recommendations for this environment focusing on:
1. Overall security posture improvement
2. PIM implementation strategy
3. Governance and compliance
4. Risk reduction priorities
5. Operational efficiency

Format as bullet points, each starting with a clear action verb and including expected impact."""
    
    def _parse_recommendations(self, ai_response: str) -> List[str]:
        """Parse AI response into a list of recommendations"""
        lines = ai_response.strip().split('\n')
        recommendations = []
        
        for line in lines:
            line = line.strip()
            # Remove bullet points and numbering
            if line.startswith(('•', '-', '*', '1.', '2.', '3.', '4.', '5.', '6.')):
                line = line[2:].strip()
            elif line and line[0].isdigit() and '.' in line:
                line = line.split('.', 1)[1].strip()
            
            if line and len(line) > 10:  # Filter out very short lines
                recommendations.append(line)
        
        return recommendations[:6]  # Limit to 6 recommendations max
    
    def _fallback_user_recommendations(self, user_analysis: Dict) -> List[str]:
        """Fallback rule-based recommendations for users"""
        recommendations = []
        active_roles = user_analysis.get('active_roles', [])
        eligible_roles = user_analysis.get('eligible_roles', [])
        last_signin = user_analysis.get('last_signin')
        
        # High privilege role count
        if len(active_roles) > 3:
            recommendations.append(f"Consider converting {len(active_roles) - 2} active roles to eligible-only assignments")
        
        # No recent activity
        if not last_signin:
            recommendations.append("Verify account is still needed - no recent sign-in activity recorded")
        
        # Role imbalance
        if len(active_roles) > len(eligible_roles) and len(active_roles) > 2:
            recommendations.append("Review active role assignments - consider PIM eligible assignments for better security")
        
        return recommendations if recommendations else ["User permissions appear appropriately configured"]
    
    def _fallback_group_recommendations(self, group_analysis: Dict) -> List[str]:
        """Fallback rule-based recommendations for groups"""
        recommendations = []
        members_count = group_analysis.get('members_count', 0)
        role_assignments = group_analysis.get('role_assignments', [])
        member_overlap = group_analysis.get('member_overlap', {})
        
        # Empty groups
        if members_count == 0:
            recommendations.append("Consider removing unused group if not needed for future assignments")
        
        # High overlap
        if member_overlap:
            max_overlap = max(member_overlap.values())
            if max_overlap > members_count * 0.7:
                overlap_group = max(member_overlap, key=member_overlap.get)
                recommendations.append(f"Evaluate consolidation with '{overlap_group}' due to high member overlap")
        
        return recommendations if recommendations else ["Group structure appears optimized"]
    
    def _fallback_global_recommendations(self, analysis_summary: Dict) -> List[str]:
        """Fallback rule-based global recommendations"""
        recommendations = []
        high_risk_users = analysis_summary.get('high_risk_users', 0)
        total_users = analysis_summary.get('total_users', 1)
        
        if high_risk_users > total_users * 0.1:
            recommendations.append("Implement PIM for high-privilege roles to reduce standing access")
        
        recommendations.append("Regularly review and certify role assignments")
        recommendations.append("Enable conditional access policies for administrative roles")
        
        return recommendations

@dataclass
class RoleAssignment:
    """Represents a role assignment with metadata"""
    principal_id: str
    principal_name: str
    principal_type: str  # 'User', 'Group', 'ServicePrincipal'
    role_id: str
    role_name: str
    assignment_type: str  # 'active', 'eligible'
    scope: str
    created_date: Optional[str] = None
    last_used: Optional[str] = None

@dataclass
class UserAnalysis:
    """Analysis results for a user"""
    user_id: str
    user_name: str
    user_email: str
    department: Optional[str]
    job_title: Optional[str]
    active_roles: List[RoleAssignment]
    eligible_roles: List[RoleAssignment]
    group_memberships: List[str]
    last_signin: Optional[str]
    risk_level: str  # 'Low', 'Medium', 'High'
    recommendations: List[str]

@dataclass
class GroupAnalysis:
    """Analysis results for a group"""
    group_id: str
    group_name: str
    group_type: str
    members_count: int
    role_assignments: List[RoleAssignment]
    member_overlap: Dict[str, int]  # Overlap with other groups
    usage_score: float
    recommendations: List[str]

@dataclass
class AnalysisReport:
    """Complete analysis report"""
    timestamp: str
    tenant_id: str
    summary: Dict[str, Any]
    user_analyses: List[UserAnalysis]
    group_analyses: List[GroupAnalysis]
    orphaned_permissions: List[RoleAssignment]
    over_privileged_users: List[str]
    recommendations: List[str]

class PIMAnalyzer:
    """Advanced PIM analyzer for Entra ID environments"""
    def __init__(self, token: str):
        self.token = token
        self.headers = {"Authorization": f"Bearer {token}"}
        self.graph_base = "https://graph.microsoft.com"
        self.ai_engine = AIRecommendationEngine()
        
    async def scan_environment(self) -> AnalysisReport:
        """Perform a comprehensive scan of the Entra ID environment"""
        print("=== PIM ANALYZER: Starting comprehensive environment scan ===")
        logger.info("Starting comprehensive PIM environment scan...")
        
        async with aiohttp.ClientSession(headers=self.headers) as session:
            # Gather all necessary data
            print("PIM ANALYZER: Fetching users...")
            users = await self._get_all_users(session)
            print(f"PIM ANALYZER: Retrieved {len(users)} users")
            
            print("PIM ANALYZER: Fetching groups...")
            groups = await self._get_all_groups(session)
            print(f"PIM ANALYZER: Retrieved {len(groups)} groups")
            
            print("PIM ANALYZER: Fetching roles...")
            roles = await self._get_all_roles(session)
            print(f"PIM ANALYZER: Retrieved {len(roles)} roles")
            
            print("PIM ANALYZER: Fetching role assignments...")
            role_assignments = await self._get_all_role_assignments(session)
            print(f"PIM ANALYZER: Retrieved {len(role_assignments)} role assignments")
            
            print("PIM ANALYZER: Fetching PIM assignments...")
            pim_assignments = await self._get_pim_assignments(session)
            print(f"PIM ANALYZER: Retrieved {len(pim_assignments)} PIM assignments")
            
            logger.info(f"Retrieved {len(users)} users, {len(groups)} groups, {len(roles)} roles")
            
            # Create analysis context for AI
            print("PIM ANALYZER: Creating analysis context...")
            analysis_context = {
                'total_users': len(users),
                'total_groups': len(groups),
                'total_roles': len(roles),
                'total_assignments': len(role_assignments),
                'avg_roles_per_user': len(role_assignments) / max(len(users), 1)
            }
            
            # Analyze data
            print("PIM ANALYZER: Analyzing users...")
            user_analyses = await self._analyze_users(users, role_assignments, pim_assignments, groups, session, analysis_context)
            print(f"PIM ANALYZER: Completed user analysis for {len(user_analyses)} users")
            
            print("PIM ANALYZER: Analyzing groups...")
            group_analyses = await self._analyze_groups(groups, role_assignments, users)
            print(f"PIM ANALYZER: Completed group analysis for {len(group_analyses)} groups")
            
            # Identify issues
            print("PIM ANALYZER: Finding orphaned permissions...")
            orphaned_permissions = self._find_orphaned_permissions(role_assignments, users, groups)
            print(f"PIM ANALYZER: Found {len(orphaned_permissions)} orphaned permissions")
            
            print("PIM ANALYZER: Identifying over-privileged users...")
            over_privileged_users = self._identify_over_privileged_users(user_analyses)
            print(f"PIM ANALYZER: Found {len(over_privileged_users)} over-privileged users")
            
            # Generate recommendations
            print("PIM ANALYZER: Generating global recommendations...")
            recommendations = self._generate_global_recommendations(user_analyses, group_analyses, orphaned_permissions)
            print(f"PIM ANALYZER: Generated {len(recommendations)} recommendations")
            
            # Create summary
            print("PIM ANALYZER: Creating summary...")
            summary = self._create_summary(users, groups, roles, role_assignments, user_analyses, group_analyses)
            
            return AnalysisReport(
                timestamp=datetime.now().isoformat(),
                tenant_id="current",  # Could be retrieved from token
                summary=summary,
                user_analyses=user_analyses,
                group_analyses=group_analyses,
                orphaned_permissions=orphaned_permissions,
                over_privileged_users=over_privileged_users,
                recommendations=recommendations
            )
        
    async def _get_all_users(self, session: aiohttp.ClientSession) -> List[Dict]:
        """Retrieve all users with relevant properties"""
        users = []
        
        # Try different API endpoints in order of preference
        endpoints = [
            f"{self.graph_base}/v1.0/users?$select=id,displayName,mail,department,jobTitle,accountEnabled&$top=999",
            f"{self.graph_base}/beta/users?$select=id,displayName,mail,department,jobTitle,signInActivity,accountEnabled&$top=999",
            f"{self.graph_base}/v1.0/users?$select=id,displayName,mail,accountEnabled&$top=999"
        ]
        
        for endpoint in endpoints:
            try:
                url = endpoint
                while url:
                    async with session.get(url) as response:
                        if response.status == 200:
                            data = await response.json()
                            users.extend(data.get('value', []))
                            url = data.get('@odata.nextLink')
                        elif response.status == 403:
                            logger.warning(f"Insufficient permissions for {endpoint}")
                            break
                        else:
                            logger.error(f"Failed to retrieve users from {endpoint}: {response.status}")
                            break
                
                if users:  # If we got some users, use this endpoint
                    logger.info(f"Successfully retrieved {len(users)} users using {endpoint}")
                    break
                    
            except Exception as e:
                logger.error(f"Error retrieving users from {endpoint}: {e}")
                continue
        
        if not users:
            logger.warning("Could not retrieve users from any endpoint - analysis will be limited")
            
        return users
    
    async def _get_all_groups(self, session: aiohttp.ClientSession) -> List[Dict]:
        """Retrieve all groups with member information"""
        groups = []
        
        # Try different approaches for getting groups with members
        try:
            # First, get all groups
            url = f"{self.graph_base}/v1.0/groups?$select=id,displayName,groupTypes&$top=999"
            while url:
                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        batch_groups = data.get('value', [])
                        
                        # For each group, try to get members separately
                        for group in batch_groups:
                            try:
                                members_url = f"{self.graph_base}/v1.0/groups/{group['id']}/members?$select=id,displayName"
                                async with session.get(members_url) as members_response:
                                    if members_response.status == 200:
                                        members_data = await members_response.json()
                                        group['members'] = members_data.get('value', [])
                                    else:
                                        group['members'] = []
                            except Exception as e:
                                logger.debug(f"Could not get members for group {group.get('displayName', 'Unknown')}: {e}")
                                group['members'] = []
                        
                        groups.extend(batch_groups)
                        url = data.get('@odata.nextLink')
                    else:
                        logger.error(f"Failed to retrieve groups: {response.status}")
                        break
        except Exception as e:
            logger.error(f"Error retrieving groups: {e}")
            
        logger.info(f"Retrieved {len(groups)} groups")
        return groups
    
    async def _get_all_roles(self, session: aiohttp.ClientSession) -> List[Dict]:
        """Retrieve all role definitions"""
        try:
            url = f"{self.graph_base}/beta/roleManagement/directory/roleDefinitions"
            async with session.get(url) as response:                
                if response.status == 200:
                    data = await response.json()
                    return data.get('value', [])
                else:
                    logger.error(f"Failed to retrieve roles: {response.status}")
                    return []
        except Exception as e:
            logger.error(f"Error retrieving roles: {e}")
            return []
    
    async def _get_all_role_assignments(self, session: aiohttp.ClientSession) -> List[Dict]:
        """Retrieve all active role assignments"""
        assignments = []
        
        # Try different endpoints for role assignments (simplified to avoid 400 errors)
        endpoints = [
            f"{self.graph_base}/v1.0/roleManagement/directory/roleAssignments?$top=999",
            f"{self.graph_base}/beta/roleManagement/directory/roleAssignments?$top=999"
        ]
        
        for endpoint in endpoints:
            try:
                url = endpoint
                page_count = 0
                while url and page_count < 5:  # Limit pages to avoid long waits
                    async with session.get(url) as response:
                        if response.status == 200:
                            data = await response.json()
                            batch_assignments = data.get('value', [])
                            assignments.extend(batch_assignments)
                            url = data.get('@odata.nextLink')
                            page_count += 1
                        elif response.status == 403:
                            logger.warning(f"Insufficient permissions for {endpoint}")
                            break
                        elif response.status == 400:
                            logger.warning(f"Bad request for {endpoint} - trying simpler approach")
                            break
                        else:
                            logger.error(f"Failed to retrieve role assignments from {endpoint}: {response.status}")
                            break
                
                if assignments:
                    logger.info(f"Successfully retrieved {len(assignments)} role assignments using {endpoint}")
                  # Try to get expanded data for a subset of assignments
                    expanded_count = 0
                    for assignment in assignments[:50]:  # Only expand first 50 for performance
                        try:
                            if assignment.get('principalId') and not assignment.get('principal'):
                                principal_url = f"{self.graph_base}/v1.0/directoryObjects/{assignment['principalId']}"
                                async with session.get(principal_url) as principal_resp:
                                    if principal_resp.status == 200:
                                        assignment['principal'] = await principal_resp.json()
                                        expanded_count += 1
                            
                            if assignment.get('roleDefinitionId') and not assignment.get('roleDefinition'):
                                role_url = f"{self.graph_base}/v1.0/roleManagement/directory/roleDefinitions/{assignment['roleDefinitionId']}"
                                async with session.get(role_url) as role_resp:
                                    if role_resp.status == 200:
                                        assignment['roleDefinition'] = await role_resp.json()
                        except Exception as e:
                            logger.debug(f"Could not expand assignment data: {e}")
                    
                    if expanded_count > 0:
                        logger.info(f"Successfully expanded {expanded_count} role assignments")
                    break
                    
            except Exception as e:
                logger.error(f"Error retrieving role assignments from {endpoint}: {e}")
                continue
        
        if not assignments:
            logger.warning("Could not retrieve role assignments - analysis will focus on available data")
            
        return assignments
    
    async def _get_pim_assignments(self, session: aiohttp.ClientSession) -> List[Dict]:
        """Retrieve PIM eligible role assignments"""
        
        # Try different PIM endpoints
        endpoints = [
            f"{self.graph_base}/beta/privilegedAccess/aadRoles/roleAssignments?$expand=subject,roleDefinition",
            f"{self.graph_base}/beta/roleManagement/directory/roleEligibilitySchedules?$expand=principal,roleDefinition",
            f"{self.graph_base}/v1.0/roleManagement/directory/roleEligibilitySchedules"
        ]
        
        for endpoint in endpoints:
            try:
                async with session.get(endpoint) as response:
                    if response.status == 200:
                        data = await response.json()
                        assignments = data.get('value', [])
                        logger.info(f"Successfully retrieved {len(assignments)} PIM assignments using {endpoint}")
                        return assignments
                    elif response.status == 403:
                        logger.warning(f"Insufficient permissions for PIM endpoint {endpoint}")
                        continue
                    elif response.status == 400:
                        logger.warning(f"Bad request for PIM endpoint {endpoint} - may not be available")
                        continue
                    else:
                        logger.error(f"Failed to retrieve PIM assignments from {endpoint}: {response.status}")
                        continue
            except Exception as e:
                logger.error(f"Error retrieving PIM assignments from {endpoint}: {e}")
                continue
        
        logger.warning("Could not retrieve PIM assignments from any endpoint - PIM analysis will be limited")
        return []
    
    async def _analyze_users(self, users: List[Dict], role_assignments: List[Dict], 
                           pim_assignments: List[Dict], groups: List[Dict], 
                           session: aiohttp.ClientSession, context: Optional[Dict] = None) -> List[UserAnalysis]:
        """Analyze each user's permissions and generate recommendations"""
        user_analyses = []
        
        # Create lookups
        user_lookup = {user['id']: user for user in users}
        role_by_user = defaultdict(list)
        pim_by_user = defaultdict(list)
        
        # Group role assignments by user
        for assignment in role_assignments:
            if assignment.get('principal'):
                principal_id = assignment['principal']['id']
                role_by_user[principal_id].append(assignment)
        
        for assignment in pim_assignments:
            if assignment.get('subject'):
                subject_id = assignment['subject']['id']
                pim_by_user[subject_id].append(assignment)
        
        for user in users:
            if not user.get('accountEnabled', True):
                continue
                
            user_id = user['id']
            
            # Get user's role assignments
            active_roles = []
            for assignment in role_by_user.get(user_id, []):
                if assignment.get('roleDefinition'):
                    active_roles.append(RoleAssignment(
                        principal_id=user_id,
                        principal_name=user.get('displayName', 'Unknown'),
                        principal_type='User',
                        role_id=assignment['roleDefinition']['id'],
                        role_name=assignment['roleDefinition']['displayName'],
                        assignment_type='active',
                        scope=assignment.get('directoryScopeId', '/'),
                        created_date=assignment.get('createdDateTime')
                    ))
            
            # Get PIM eligible roles
            eligible_roles = []
            for assignment in pim_by_user.get(user_id, []):
                if assignment.get('roleDefinition'):
                    eligible_roles.append(RoleAssignment(
                        principal_id=user_id,
                        principal_name=user.get('displayName', 'Unknown'),
                        principal_type='User',
                        role_id=assignment['roleDefinition']['id'],
                        role_name=assignment['roleDefinition']['displayName'],
                        assignment_type='eligible',
                        scope='/',
                        created_date=assignment.get('startDateTime')
                    ))
            
            # Get group memberships
            group_memberships = []
            for group in groups:
                if group.get('members'):
                    for member in group['members']:
                        if member['id'] == user_id:
                            group_memberships.append(group['displayName'])
            
            # Analyze risk level and generate recommendations
            risk_level, recommendations = self._analyze_user_risk(user, active_roles, eligible_roles, group_memberships)
            
            user_analysis = UserAnalysis(
                user_id=user_id,
                user_name=user.get('displayName', 'Unknown'),
                user_email=user.get('mail', ''),
                department=user.get('department'),
                job_title=user.get('jobTitle'),
                active_roles=active_roles,
                eligible_roles=eligible_roles,
                group_memberships=group_memberships,
                last_signin=user.get('signInActivity', {}).get('lastSignInDateTime'),
                risk_level=risk_level,
                recommendations=recommendations
            )
            
            user_analyses.append(user_analysis)
            
        return user_analyses
    
    async def _analyze_groups(self, groups: List[Dict], role_assignments: List[Dict], 
                            users: List[Dict]) -> List[GroupAnalysis]:
        """Analyze groups and their role assignments"""
        group_analyses = []
        
        # Create lookups
        role_by_group = defaultdict(list)
        
        # Group role assignments by group
        for assignment in role_assignments:
            if assignment.get('principal') and assignment['principal'].get('@odata.type') == '#microsoft.graph.group':
                group_id = assignment['principal']['id']
                role_by_group[group_id].append(assignment)
        
        for group in groups:
            group_id = group['id']
            members_count = len(group.get('members', []))
            
            # Get group's role assignments
            group_role_assignments = []
            for assignment in role_by_group.get(group_id, []):
                if assignment.get('roleDefinition'):
                    group_role_assignments.append(RoleAssignment(
                        principal_id=group_id,
                        principal_name=group.get('displayName', 'Unknown'),
                        principal_type='Group',
                        role_id=assignment['roleDefinition']['id'],
                        role_name=assignment['roleDefinition']['displayName'],
                        assignment_type='active',
                        scope=assignment.get('directoryScopeId', '/'),
                        created_date=assignment.get('createdDateTime')
                    ))
            
            # Calculate member overlap with other groups
            member_overlap = self._calculate_group_overlap(group, groups)
            
            # Calculate usage score
            usage_score = self._calculate_group_usage_score(group, group_role_assignments, members_count)
            
            # Generate recommendations
            recommendations = self._generate_group_recommendations(group, group_role_assignments, members_count, member_overlap)
            
            group_analysis = GroupAnalysis(
                group_id=group_id,
                group_name=group.get('displayName', 'Unknown'),
                group_type='Security' if 'Unified' not in group.get('groupTypes', []) else 'Microsoft 365',
                members_count=members_count,
                role_assignments=group_role_assignments,
                member_overlap=member_overlap,
                usage_score=usage_score,
                recommendations=recommendations
            )
            
            group_analyses.append(group_analysis)
            
        return group_analyses
    
    def _analyze_user_risk(self, user: Dict, active_roles: List[RoleAssignment], 
                         eligible_roles: List[RoleAssignment], group_memberships: List[str]) -> Tuple[str, List[str]]:
        """Analyze user risk level and generate recommendations using AI"""
        
        # First calculate risk level using deterministic rules (for consistency)
        risk_factors = 0
        
        # High-privilege roles that increase risk
        high_privilege_roles = [
            'Global Administrator',
            'Privileged Role Administrator',
            'Security Administrator',
            'Exchange Administrator',
            'SharePoint Administrator'
        ]
        
        # Check for high-privilege active roles
        high_priv_active = [role for role in active_roles if role.role_name in high_privilege_roles]
        if high_priv_active:
            risk_factors += len(high_priv_active) * 2
        
        # Check for excessive role count
        total_roles = len(active_roles) + len(eligible_roles)
        if total_roles > 5:
            risk_factors += 1
        
        # Check for stale accounts (sign-in data)
        signin_activity = user.get('signInActivity', {})
        last_signin = signin_activity.get('lastSignInDateTime') if signin_activity else None
        
        if signin_activity and last_signin:
            try:
                signin_date = datetime.fromisoformat(last_signin.replace('Z', '+00:00'))
                days_since_signin = (datetime.now(signin_date.tzinfo) - signin_date).days
                if days_since_signin > 90:
                    risk_factors += 1
            except Exception:
                pass
        elif signin_activity and not last_signin:
            risk_factors += 1
        
        # Check for role/department mismatch
        if user.get('department') and user.get('jobTitle'):
            if self._detect_role_department_mismatch(user, active_roles + eligible_roles):
                risk_factors += 1
        
        # Determine risk level
        if risk_factors >= 4:
            risk_level = 'High'
        elif risk_factors >= 2:
            risk_level = 'Medium'
        else:
            risk_level = 'Low'
        
        # Generate AI-powered recommendations
        user_analysis_data = {
            'user_name': user.get('displayName', 'Unknown'),
            'user_email': user.get('mail', ''),
            'department': user.get('department'),
            'job_title': user.get('jobTitle'),
            'active_roles': [{'role_name': role.role_name} for role in active_roles],
            'eligible_roles': [{'role_name': role.role_name} for role in eligible_roles],
            'last_signin': last_signin,
            'group_memberships': group_memberships,
            'risk_level': risk_level,
            'high_privilege_active_count': len(high_priv_active),
            'total_roles': total_roles
        }
        
        try:
            recommendations = self.ai_engine.generate_user_recommendations(user_analysis_data)
        except Exception as e:
            logger.warning(f"AI recommendation generation failed for user {user.get('displayName')}: {e}")
            # Fallback to basic recommendations
            recommendations = []
            if high_priv_active:
                recommendations.append(f"Consider converting {len(high_priv_active)} high-privilege active role(s) to eligible-only")
            if total_roles > 5:
                recommendations.append(f"User has {total_roles} total roles - consider reviewing necessity")
            if not recommendations:
                recommendations.append("No immediate concerns identified")
        
        return risk_level, recommendations
    
    def _detect_role_department_mismatch(self, user: Dict, roles: List[RoleAssignment]) -> bool:
        """Detect potential mismatches between user's department/job and assigned roles"""
        department = user.get('department', '').lower()
        job_title = user.get('jobTitle', '').lower()
        
        # Simple heuristic - could be enhanced with ML
        it_keywords = ['it', 'technology', 'technical', 'engineer', 'developer', 'admin']
        hr_keywords = ['hr', 'human resources', 'people', 'talent']
        finance_keywords = ['finance', 'accounting', 'financial', 'controller']
        
        user_is_it = any(keyword in department or keyword in job_title for keyword in it_keywords)
        user_is_hr = any(keyword in department or keyword in job_title for keyword in hr_keywords)
        user_is_finance = any(keyword in department or keyword in job_title for keyword in finance_keywords)
        
        # Check for mismatched roles
        for role in roles:
            role_name_lower = role.role_name.lower()
            
            # Non-IT user with IT roles
            if not user_is_it and any(keyword in role_name_lower for keyword in ['admin', 'developer', 'technical']):
                return True
              # Non-HR user with HR roles
            if not user_is_hr and 'user' in role_name_lower and 'administrator' in role_name_lower:
                continue  # Skip general user admin roles
        
        return False
    
    def _calculate_group_overlap(self, group: Dict, all_groups: List[Dict]) -> Dict[str, int]:
        """Calculate member overlap between groups, excluding built-in groups like 'All Users'"""
        overlap = {}
        group_members = {member['id'] for member in group.get('members', [])}
        
        # Groups to exclude from overlap analysis (built-in Azure AD groups)
        excluded_groups = {
            'All Users',
            'All Guests', 
            'All Company',
            'All Members',
            'Domain Users',
            'Everyone'
        }
        
        for other_group in all_groups:
            if other_group['id'] == group['id']:
                continue
            
            # Skip built-in groups that naturally contain many users
            other_group_name = other_group.get('displayName', '')
            if other_group_name in excluded_groups:
                continue
                
            other_members = {member['id'] for member in other_group.get('members', [])}
            overlap_count = len(group_members.intersection(other_members))
            
            if overlap_count > 0:
                overlap[other_group['displayName']] = overlap_count
        
        return overlap
    
    def _calculate_group_usage_score(self, group: Dict, role_assignments: List[RoleAssignment], members_count: int) -> float:
        """Calculate a usage score for the group (0-1 scale)"""
        score = 0.0
        
        # Factor 1: Has role assignments (0.4 weight)
        if role_assignments:
            score += 0.4
        
        # Factor 2: Member count (0.3 weight) - normalize to 0-1 scale
        if members_count > 0:
            # Assume 1-50 members is good utilization
            member_score = min(members_count / 50.0, 1.0)
            score += 0.3 * member_score
        
        # Factor 3: Group naming convention (0.3 weight)
        group_name = group.get('displayName', '').lower()
        if any(keyword in group_name for keyword in ['pim', 'role', 'admin', 'security']):
            score += 0.3
        
        return min(score, 1.0)
    
    def _generate_group_recommendations(self, group: Dict, role_assignments: List[RoleAssignment], 
                                      members_count: int, member_overlap: Dict[str, int]) -> List[str]:
        """Generate AI-powered recommendations for group optimization"""
        
        # Prepare group analysis data for AI
        group_analysis_data = {
            'group_name': group.get('displayName', 'Unknown'),
            'group_type': 'Security' if 'Unified' not in group.get('groupTypes', []) else 'Microsoft 365',
            'members_count': members_count,
            'role_assignments': [{'role_name': role.role_name} for role in role_assignments],
            'member_overlap': member_overlap,
            'usage_score': self._calculate_group_usage_score(group, role_assignments, members_count)
        }
        
        try:
            recommendations = self.ai_engine.generate_group_recommendations(group_analysis_data)
        except Exception as e:
            logger.warning(f"AI recommendation generation failed for group {group.get('displayName')}: {e}")
            # Fallback to rule-based recommendations
            recommendations = []
            
            # Empty groups
            if members_count == 0:
                recommendations.append("Consider removing unused group if not needed for future assignments")
            
            # Groups without role assignments
            if not role_assignments and members_count > 0:
                recommendations.append("Group has members but no role assignments - verify purpose")
              # High member overlap
            if member_overlap:
                max_overlap = max(member_overlap.values())
                if max_overlap > members_count * 0.7:  # 70% overlap (adjusted from 80%)
                    overlap_group = max(member_overlap.keys(), key=lambda k: member_overlap[k])
                    recommendations.append(f"Evaluate consolidation with '{overlap_group}' due to high member overlap")
            
            # Large groups with privileged roles
            if members_count > 20 and role_assignments:
                high_priv_roles = [ra for ra in role_assignments if 'Administrator' in ra.role_name]
                if high_priv_roles:
                    recommendations.append(f"Large group ({members_count} members) with privileged roles - consider splitting")
            
            if not recommendations:
                recommendations.append("Group structure appears optimized")
        
        return recommendations
    
    def _find_orphaned_permissions(self, role_assignments: List[Dict], users: List[Dict], groups: List[Dict]) -> List[RoleAssignment]:
        """Find role assignments for non-existent principals"""
        orphaned = []
        
        user_ids = {user['id'] for user in users}
        group_ids = {group['id'] for group in groups}
        
        for assignment in role_assignments:
            if assignment.get('principal'):
                principal_id = assignment['principal']['id']
                principal_type = assignment['principal'].get('@odata.type', '').split('.')[-1]
                
                is_orphaned = False
                if principal_type == 'user' and principal_id not in user_ids:
                    is_orphaned = True
                elif principal_type == 'group' and principal_id not in group_ids:
                    is_orphaned = True
                
                if is_orphaned and assignment.get('roleDefinition'):
                    orphaned.append(RoleAssignment(
                        principal_id=principal_id,
                        principal_name=assignment['principal'].get('displayName', 'Unknown'),
                        principal_type=principal_type.title(),
                        role_id=assignment['roleDefinition']['id'],
                        role_name=assignment['roleDefinition']['displayName'],
                        assignment_type='active',
                        scope=assignment.get('directoryScopeId', '/'),
                        created_date=assignment.get('createdDateTime')
                    ))
        
        return orphaned
    
    def _identify_over_privileged_users(self, user_analyses: List[UserAnalysis]) -> List[str]:
        """Identify users with excessive privileges"""
        over_privileged = []
        
        for analysis in user_analyses:
            # Check for multiple high-privilege roles
            high_priv_active = len([role for role in analysis.active_roles 
                                  if 'Administrator' in role.role_name or 'Global' in role.role_name])
            
            if high_priv_active >= 2:
                over_privileged.append(analysis.user_name)
            
            # Check for users with many total roles
            total_roles = len(analysis.active_roles) + len(analysis.eligible_roles)
            if total_roles > 8:
                over_privileged.append(analysis.user_name)
        
        return list(set(over_privileged))  # Remove duplicates
    
    def _generate_global_recommendations(self, user_analyses: List[UserAnalysis], 
                                       group_analyses: List[GroupAnalysis], 
                                       orphaned_permissions: List[RoleAssignment]) -> List[str]:
        """Generate AI-powered global recommendations for the environment"""
        
        # Analyze overall statistics
        total_users = len(user_analyses)
        high_risk_users = len([ua for ua in user_analyses if ua.risk_level == 'High'])
        medium_risk_users = len([ua for ua in user_analyses if ua.risk_level == 'Medium'])
        users_with_active_roles = len([ua for ua in user_analyses if ua.active_roles])
        users_with_eligible_roles = len([ua for ua in user_analyses if ua.eligible_roles])
        
        # Prepare summary data for AI
        analysis_summary = {
            'total_users': total_users,
            'total_groups': len(group_analyses),
            'total_role_assignments': sum(len(ua.active_roles) + len(ua.eligible_roles) for ua in user_analyses),
            'high_risk_users': high_risk_users,
            'medium_risk_users': medium_risk_users,
            'low_risk_users': total_users - high_risk_users - medium_risk_users,
            'users_with_active_roles': users_with_active_roles,
            'users_with_eligible_roles': users_with_eligible_roles,
            'orphaned_permissions': len(orphaned_permissions),
            'empty_groups': len([ga for ga in group_analyses if ga.members_count == 0]),
            'pim_adoption_rate': (users_with_eligible_roles / max(users_with_active_roles, 1)) * 100
        }
        
        try:
            recommendations = self.ai_engine.generate_global_recommendations(analysis_summary)
        except Exception as e:
            logger.warning(f"AI global recommendation generation failed: {e}")
            # Fallback to rule-based recommendations
            recommendations = []
            
            # High-risk users
            if high_risk_users > 0:
                risk_percentage = (high_risk_users / total_users) * 100
                recommendations.append(f"Review {high_risk_users} high-risk users ({risk_percentage:.1f}% of total)")
            
            # Orphaned permissions
            if orphaned_permissions:
                recommendations.append(f"Clean up {len(orphaned_permissions)} orphaned role assignments")
            
            # PIM adoption
            if users_with_active_roles > 0:
                pim_adoption = (users_with_eligible_roles / users_with_active_roles) * 100
                if pim_adoption < 50:
                    recommendations.append(f"Consider increasing PIM adoption (currently {pim_adoption:.1f}%)")
            
            # Empty groups
            empty_groups = len([ga for ga in group_analyses if ga.members_count == 0])
            if empty_groups > 0:
                recommendations.append(f"Remove {empty_groups} empty groups")
            
            # Most common roles
            role_counter = Counter()
            for ua in user_analyses:
                for role in ua.active_roles + ua.eligible_roles:
                    role_counter[role.role_name] += 1
            
            most_common_roles = role_counter.most_common(3)
            if most_common_roles:
                recommendations.append(f"Most assigned roles: {', '.join([f'{role}({count})' for role, count in most_common_roles])}")
        
        return recommendations
    
    def _create_summary(self, users: List[Dict], groups: List[Dict], roles: List[Dict], 
                       role_assignments: List[Dict], user_analyses: List[UserAnalysis], 
                       group_analyses: List[GroupAnalysis]) -> Dict[str, Any]:
        """Create a summary of the analysis"""
        return {
            'total_users': len(users),
            'total_groups': len(groups),
            'total_roles': len(roles),
            'total_role_assignments': len(role_assignments),
            'high_risk_users': len([ua for ua in user_analyses if ua.risk_level == 'High']),
            'medium_risk_users': len([ua for ua in user_analyses if ua.risk_level == 'Medium']),
            'low_risk_users': len([ua for ua in user_analyses if ua.risk_level == 'Low']),
            'users_with_active_roles': len([ua for ua in user_analyses if ua.active_roles]),
            'users_with_eligible_roles': len([ua for ua in user_analyses if ua.eligible_roles]),
            'groups_with_roles': len([ga for ga in group_analyses if ga.role_assignments]),
            'empty_groups': len([ga for ga in group_analyses if ga.members_count == 0]),
            'average_roles_per_user': sum(len(ua.active_roles) + len(ua.eligible_roles) for ua in user_analyses) / len(user_analyses) if user_analyses else 0
        }
    
    def export_report(self, report: AnalysisReport, filename: Optional[str] = None) -> str:
        """Export analysis report to JSON file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"pim_analysis_report_{timestamp}.json"
        
        # Convert dataclasses to dict for JSON serialization
        report_dict = {
            'timestamp': report.timestamp,
            'tenant_id': report.tenant_id,
            'summary': report.summary,
            'user_analyses': [asdict(ua) for ua in report.user_analyses],
            'group_analyses': [asdict(ga) for ga in report.group_analyses],
            'orphaned_permissions': [asdict(op) for op in report.orphaned_permissions],
            'over_privileged_users': report.over_privileged_users,
            'recommendations': report.recommendations
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report_dict, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Analysis report exported to {filename}")
        return filename
