from fastapi import APIRouter, Request, HTTPException, BackgroundTasks
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from typing import Optional

from auth import get_token_interactive
from pim_analyzer import PIMAnalyzer, AnalysisReport

router = APIRouter()
templates = Jinja2Templates(directory="templates")

# Global variable to store the latest analysis result
latest_analysis: Optional[AnalysisReport] = None
analysis_in_progress = False

@router.get("/analysis", response_class=HTMLResponse)
async def analysis_dashboard(request: Request):
    """Display the analysis dashboard"""
    return templates.TemplateResponse("analysis.html", {
        "request": request,
        "has_analysis": latest_analysis is not None,
        "analysis_in_progress": analysis_in_progress
    })

@router.post("/analysis/start")
async def start_analysis(background_tasks: BackgroundTasks):
    """Start a comprehensive PIM analysis"""
    global analysis_in_progress
    
    if analysis_in_progress:
        raise HTTPException(status_code=400, detail="Analysis already in progress")
    
    # Check if we have a cached token first
    from auth import get_cached_token
    cached_token = get_cached_token()
    
    if not cached_token:
        return {
            "status": "error", 
            "message": "No authentication token available. Please authenticate first.",
            "require_auth": True
        }
    
    try:
        # Start analysis in background with cached token
        background_tasks.add_task(run_analysis, cached_token)
        analysis_in_progress = True
        
        return {"status": "started", "message": "Analysis started in background"}
        
    except Exception as e:
        return {"status": "error", "message": f"Failed to start analysis: {str(e)}"}

@router.get("/analysis/status")
async def get_analysis_status():
    """Get the current analysis status"""
    return {
        "in_progress": analysis_in_progress,
        "has_results": latest_analysis is not None,
        "last_analysis": latest_analysis.timestamp if latest_analysis else None
    }

@router.get("/analysis/results")
async def get_analysis_results():
    """Get the latest analysis results"""
    if not latest_analysis:
        raise HTTPException(status_code=404, detail="No analysis results available")
    
    # Return comprehensive analysis results
    return {
        "timestamp": latest_analysis.timestamp,
        "summary": latest_analysis.summary,
        "recommendations": latest_analysis.recommendations,
        "high_risk_users": [
            {
                "name": ua.user_name,
                "email": ua.user_email,
                "risk_level": ua.risk_level,
                "active_roles_count": len(ua.active_roles),
                "eligible_roles_count": len(ua.eligible_roles),
                "recommendations": ua.recommendations
            }
            for ua in latest_analysis.user_analyses if ua.risk_level == "High"
        ],
        "over_privileged_users": latest_analysis.over_privileged_users,
        "orphaned_permissions_count": len(latest_analysis.orphaned_permissions),
        "group_insights": [
            {
                "name": ga.group_name,
                "members_count": ga.members_count,
                "roles_count": len(ga.role_assignments),
                "usage_score": ga.usage_score,
                "recommendations": ga.recommendations
            }
            for ga in latest_analysis.group_analyses if ga.recommendations and "optimized" not in ga.recommendations[0].lower()
        ]
    }

@router.get("/analysis/users")
async def get_user_analysis(skip: int = 0, limit: int = 50, risk_level: Optional[str] = None):
    """Get detailed user analysis results with pagination"""
    if not latest_analysis:
        raise HTTPException(status_code=404, detail="No analysis results available")
    
    users = latest_analysis.user_analyses
    
    # Filter by risk level if specified
    if risk_level:
        users = [ua for ua in users if ua.risk_level.lower() == risk_level.lower()]
    
    # Apply pagination
    total = len(users)
    users_page = users[skip:skip + limit]
    
    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "users": [
            {
                "id": ua.user_id,
                "name": ua.user_name,
                "email": ua.user_email,
                "department": ua.department,
                "job_title": ua.job_title,
                "risk_level": ua.risk_level,
                "active_roles": [
                    {
                        "role_name": role.role_name,
                        "assignment_type": role.assignment_type,
                        "scope": role.scope
                    }
                    for role in ua.active_roles
                ],
                "eligible_roles": [
                    {
                        "role_name": role.role_name,
                        "assignment_type": role.assignment_type,
                        "scope": role.scope
                    }
                    for role in ua.eligible_roles
                ],
                "group_memberships": ua.group_memberships,
                "last_signin": ua.last_signin,
                "recommendations": ua.recommendations
            }
            for ua in users_page
        ]
    }

@router.get("/analysis/groups")
async def get_group_analysis(skip: int = 0, limit: int = 50):
    """Get detailed group analysis results with pagination"""
    if not latest_analysis:
        raise HTTPException(status_code=404, detail="No analysis results available")
    
    groups = latest_analysis.group_analyses
    
    # Apply pagination
    total = len(groups)
    groups_page = groups[skip:skip + limit]
    
    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "groups": [
            {
                "id": ga.group_id,
                "name": ga.group_name,
                "type": ga.group_type,
                "members_count": ga.members_count,
                "roles": [
                    {
                        "role_name": role.role_name,
                        "assignment_type": role.assignment_type,
                        "scope": role.scope
                    }
                    for role in ga.role_assignments
                ],
                "member_overlap": ga.member_overlap,
                "usage_score": ga.usage_score,
                "recommendations": ga.recommendations
            }
            for ga in groups_page
        ]
    }

@router.get("/analysis/recommendations")
async def get_recommendations():
    """Get AI-powered recommendations for RBAC optimization"""
    if not latest_analysis:
        raise HTTPException(status_code=404, detail="No analysis results available")
    
    # Categorize recommendations
    recommendations = {
        "security": [],
        "optimization": [],
        "compliance": [],
        "general": []
    }
    
    for rec in latest_analysis.recommendations:
        rec_lower = rec.lower()
        if any(keyword in rec_lower for keyword in ['risk', 'security', 'privilege']):
            recommendations["security"].append(rec)
        elif any(keyword in rec_lower for keyword in ['empty', 'overlap', 'consolidat']):
            recommendations["optimization"].append(rec)
        elif any(keyword in rec_lower for keyword in ['review', 'verify', 'clean']):
            recommendations["compliance"].append(rec)
        else:
            recommendations["general"].append(rec)
    
    # Add user-specific recommendations
    user_recommendations = {}
    for ua in latest_analysis.user_analyses:
        if ua.risk_level in ['High', 'Medium'] and ua.recommendations:
            user_recommendations[ua.user_name] = {
                "risk_level": ua.risk_level,
                "recommendations": ua.recommendations
            }
    
    # Add group-specific recommendations
    group_recommendations = {}
    for ga in latest_analysis.group_analyses:
        if ga.recommendations and "optimized" not in ga.recommendations[0].lower():
            group_recommendations[ga.group_name] = {
                "usage_score": ga.usage_score,
                "recommendations": ga.recommendations
            }
    
    return {
        "global_recommendations": recommendations,
        "user_recommendations": user_recommendations,
        "group_recommendations": group_recommendations,
        "summary": {
            "total_recommendations": len(latest_analysis.recommendations),
            "high_risk_users": len([ua for ua in latest_analysis.user_analyses if ua.risk_level == "High"]),
            "optimization_opportunities": len(group_recommendations)
        }
    }

@router.get("/analysis/export")
async def export_analysis():
    """Export the latest analysis results"""
    if not latest_analysis:
        raise HTTPException(status_code=404, detail="No analysis results available")
    
    try:
        analyzer = PIMAnalyzer("")  # Token not needed for export
        filename = analyzer.export_report(latest_analysis)
        
        return {
            "status": "success",
            "filename": filename,
            "message": f"Analysis exported to {filename}"
        }
    except Exception as e:
        return {
            "status": "error", 
            "message": f"Export failed: {str(e)}"
        }

@router.get("/auth/status")
async def auth_status():
    """Check if we have a valid cached token"""
    from auth import get_cached_token
    cached_token = get_cached_token()
    return {
        "authenticated": cached_token is not None,
        "message": "Token available" if cached_token else "No valid token available"
    }

@router.post("/auth/authenticate")
async def authenticate_user():
    """Trigger authentication process"""
    print("=== WEB AUTHENTICATION REQUEST RECEIVED ===")
    try:
        print("Step 1: Importing authentication module...")
        from auth import get_cached_token
        
        # First check if we already have a cached token
        cached_token = get_cached_token()
        if cached_token:
            print("Step 2: Found valid cached token, no authentication needed")
            return {
                "status": "success",
                "message": "Already authenticated with cached token",
                "token_length": len(cached_token)
            }
        
        print("Step 2: No cached token found, starting interactive authentication...")
        print("IMPORTANT: Check the console/terminal for authentication code!")
        
        from auth import get_token_interactive
        print("Step 3: Starting token acquisition process...")
        print("NOTE: This will display an authentication code in the console.")
        print("You need to:")
        print("1. Look at the console/terminal where this server is running")
        print("2. Copy the authentication code shown there")
        print("3. Visit the URL provided in the console")
        print("4. Enter the code to complete authentication")
        
        token = get_token_interactive()
        
        print(f"Step 4: Authentication completed! Token length: {len(token) if token else 0}")
        
        return {
            "status": "success",
            "message": "Authentication successful! Check console for any authentication codes.",
            "token_length": len(token) if token else 0
        }
    except Exception as e:
        print(f"=== AUTHENTICATION FAILED ===")
        print(f"Error: {str(e)}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return {
            "status": "error",
            "message": f"Authentication failed: {str(e)}. Check console for details."
        }

async def run_analysis(token: str):
    """Background task to run the PIM analysis"""
    global latest_analysis, analysis_in_progress
    
    try:
        print("=== STARTING COMPREHENSIVE AI-POWERED PIM ANALYSIS ===")
        print(f"Token length: {len(token) if token else 'No token'}")
        
        print("Step 1: Creating PIM analyzer instance...")
        analyzer = PIMAnalyzer(token)
        print("Step 2: Analyzer created successfully")
        
        print("Step 3: Starting environment scan...")
        result = await analyzer.scan_environment()
        print("Step 4: Environment scan completed!")
        
        print(f"Step 5: Analyzing results - Users: {result.summary.get('total_users', 0)}, Role Assignments: {result.summary.get('total_role_assignments', 0)}")
        
        # Check if we got meaningful data
        if (result.summary.get('total_users', 0) > 0 and 
            result.summary.get('total_role_assignments', 0) > 0):
            latest_analysis = result
            print("Step 6: Exporting report...")
            analyzer.export_report(result)
            print("=== AI-POWERED ANALYSIS COMPLETED SUCCESSFULLY! ===")
        else:
            raise Exception("Analysis returned limited data - check permissions")
            
    except Exception as e:
        import traceback
        print(f"=== ANALYSIS FAILED ===")
        print(f"Error: {str(e)}")
        print(f"Traceback: {traceback.format_exc()}")
        print("Please ensure you have the following permissions:")
        print("- Global Administrator, Global Reader, or Security Reader role")
        print("- Directory.Read.All, RoleManagement.Read.Directory")
        print("- User.Read.All, Group.Read.All")
        print("- PrivilegedAccess.Read.AzureAD (for PIM data)")
        latest_analysis = None
    finally:
        analysis_in_progress = False
        print("=== ANALYSIS PROCESS FINISHED ===")

async def run_analysis_with_auth():
    """Background task to authenticate and run the PIM analysis"""
    global latest_analysis, analysis_in_progress
    
    try:
        print("=== STARTING COMPREHENSIVE AI-POWERED PIM ANALYSIS ===")
        
        print("Step 1: Getting authentication token...")
        token = get_token_interactive()
        print(f"Step 2: Token obtained successfully (length: {len(token) if token else 'No token'})")
        
        # Now run the actual analysis
        await run_analysis(token)
        
    except Exception as e:
        import traceback
        print(f"=== AUTHENTICATION OR ANALYSIS FAILED ===")
        print(f"Error: {str(e)}")
        print(f"Traceback: {traceback.format_exc()}")
        print("Please ensure you have:")
        print("- Proper Azure AD app registration")
        print("- Required permissions: Directory.Read.All, RoleManagement.Read.Directory, etc.")
        print("- Global Administrator, Global Reader, or Security Reader role")
        latest_analysis = None
        analysis_in_progress = False
