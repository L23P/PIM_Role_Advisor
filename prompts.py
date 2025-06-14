"""
OpenAI Prompts for PIM Role Advisor
This module contains all the prompts used for different types of analysis
"""

def get_role_recommendation_prompt(entra_roles, pim_groups, az_groups, question):
    """
    Generate a prompt for role recommendations based on user questions
    """
    entra_text = "\n".join(f"{r['displayName']} [{r['id']}]" for r in entra_roles)
    pim_text = "\n".join(f"{g['displayName']} [{g['id']}]" for g in pim_groups)
    az_text = "\n".join(f"{g['displayName']} [{g['id']}]" for g in az_groups)

    return f"""
Available Entra Roles:
{entra_text}

Available PIM Groups:
{pim_text}

Available Azure Groups:
{az_text}

User Question: {question}

Instructions: Provide a clear response that starts with "The least privileged role required to {question.lower()} is:" followed by the SPECIFIC ROLE NAME (not a mapping). 

After your role recommendation, add a section titled "How this recommendation was determined:" and explain:

1. The specific permissions this role includes that are relevant to the task
2. Why other roles that could perform this task were not recommended (identify the specific alternative roles that have the required permissions but are more permissive, and explain why they were excluded in favor of the least privileged option)
3. State "Reference:" followed by https://docs.microsoft.com/en-us/azure/active-directory/roles/permissions-reference# (and then add the name of the role here using - in place of spaces, e.g. "Privileged Role Administrator" becomes "privileged-role-administrator")
4. Detail any corresponding PIM groups that have been set up for this permission in the current environment

Do NOT use "=>" symbols. Be specific about which single role is recommended as the minimum required permission.
"""

def get_user_analysis_prompt(user_analysis, context=None):
    """
    Generate a prompt for analyzing individual users
    """
    return f"""
Analyze this user's RBAC configuration and provide specific recommendations:

User Information:
- Name: {user_analysis.get('name', 'Unknown')}
- Email: {user_analysis.get('email', 'Unknown')}
- Department: {user_analysis.get('department', 'Unknown')}
- Job Title: {user_analysis.get('job_title', 'Unknown')}
- Risk Level: {user_analysis.get('risk_level', 'Unknown')}

Active Roles:
{chr(10).join([f"- {role.get('role_name', 'Unknown')}" for role in user_analysis.get('active_roles', [])])}

Eligible Roles:
{chr(10).join([f"- {role.get('role_name', 'Unknown')}" for role in user_analysis.get('eligible_roles', [])])}

Group Memberships:
{chr(10).join([f"- {group}" for group in user_analysis.get('group_memberships', [])])}

Last Sign-in: {user_analysis.get('last_signin', 'Unknown')}

Context:
{context if context else 'Standard analysis'}

Provide 2-3 specific, actionable recommendations for this user focusing on:
1. Principle of least privilege
2. Role consolidation opportunities
3. Security risk mitigation
4. PIM best practices

Format as a numbered list.
"""

def get_group_analysis_prompt(group_analysis, context=None):
    """
    Generate a prompt for analyzing groups
    """
    return f"""
Analyze this group's configuration and provide optimization recommendations:

Group Information:
- Name: {group_analysis.get('name', 'Unknown')}
- Type: {group_analysis.get('type', 'Unknown')}
- Members Count: {group_analysis.get('members_count', 0)}
- Usage Score: {group_analysis.get('usage_score', 'Unknown')}

Role Assignments:
{chr(10).join([f"- {role.get('role_name', 'Unknown')}" for role in group_analysis.get('role_assignments', [])])}

Member Overlap: {group_analysis.get('member_overlap', 'Unknown')}

Context:
{context if context else 'Standard analysis'}

Provide 2-3 specific recommendations for optimizing this group focusing on:
1. Group efficiency and utilization
2. Role assignment optimization
3. Member overlap reduction
4. Security posture improvement

Format as a numbered list.
"""

def get_global_analysis_prompt(analysis_summary):
    """
    Generate a prompt for global environment analysis
    """
    return f"""
Analyze this Entra ID environment and provide strategic RBAC recommendations:

Environment Summary:
- Total Users: {analysis_summary.get('total_users', 0)}
- Total Groups: {analysis_summary.get('total_groups', 0)}
- Total Role Assignments: {analysis_summary.get('total_role_assignments', 0)}
- High Risk Users: {analysis_summary.get('high_risk_users', 0)}
- Medium Risk Users: {analysis_summary.get('medium_risk_users', 0)}
- Low Risk Users: {analysis_summary.get('low_risk_users', 0)}
- Over-privileged Users: {analysis_summary.get('over_privileged_users', 0)}
- Orphaned Permissions: {analysis_summary.get('orphaned_permissions_count', 0)}
- PIM Adoption Rate: {analysis_summary.get('pim_adoption_rate', 'Unknown')}%

Risk Distribution:
- Critical Issues: {analysis_summary.get('critical_issues', 0)}
- High Priority Items: {analysis_summary.get('high_priority_items', 0)}
- Medium Priority Items: {analysis_summary.get('medium_priority_items', 0)}

Provide 5-7 strategic recommendations for improving this environment's RBAC posture:

Focus on:
1. Overall security posture improvements
2. PIM adoption strategies
3. Role assignment optimization
4. Risk mitigation priorities
5. Compliance and governance
6. Operational efficiency

Format as a numbered list with clear, actionable items.
"""

def get_system_message():
    """
    Get the system message for OpenAI API calls
    """
    return """You are an expert Microsoft Azure Identity and Access Management consultant specializing in Privileged Identity Management (PIM) and RBAC optimization. 

Your role is to analyze Entra ID environments and provide specific, actionable security recommendations. Focus on:
- Principle of least privilege
- Zero trust security model
- PIM best practices
- Risk mitigation strategies
- Compliance with security frameworks
- Operational efficiency

Always provide practical, implementable recommendations that organizations can act upon immediately."""

def get_role_recommendation_system_message():
    """
    Get the system message specifically for role recommendations
    """
    return """You are a Microsoft Azure role assignment expert. When users ask about permissions needed for specific tasks, always start your response with 'The least privileged role required to [task] is:' and then provide the specific role recommendations. Focus on the minimum permissions needed while maintaining security best practices."""
