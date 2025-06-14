import os
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from dotenv import load_dotenv
from auth import get_token_interactive
from analysis_routes import router as analysis_router
from prompts import get_role_recommendation_prompt, get_role_recommendation_system_message
import aiohttp
import requests
import asyncio

# Load environment variables from .env file
load_dotenv()

# Azure OpenAI configuration
API_KEY = os.getenv('AZURE_OPENAI_API_KEY')
ENDPOINT = os.getenv('AZURE_OPENAI_ENDPOINT')
DEPLOYMENT = os.getenv('AZURE_OPENAI_DEPLOYMENT')
API_VERSION = '2024-12-01-preview'
URI = f"{ENDPOINT}/openai/deployments/{DEPLOYMENT}/chat/completions?api-version={API_VERSION}"

# Create FastAPI app
app = FastAPI(
    title="PIM Role Advisor", 
    description="Advanced RBAC Analytics for Entra ID",
    version="1.0.0"
)

# Configure templates directory
templates = Jinja2Templates(directory="templates")

# Include analysis routes - TESTING IF ROUTER REGISTRATION WORKS
app.include_router(analysis_router)

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request, "response": ""})

@app.get("/auth/callback", response_class=HTMLResponse)
async def auth_callback(request: Request):
    # This route handles the OAuth callback
    return templates.TemplateResponse("index.html", {"request": request, "response": "Authentication complete. You can now ask your question again."})

@app.post("/ask", response_class=HTMLResponse)
async def ask(request: Request, question: str = Form(...)):
    try:
        print(f"\n--- Processing question: '{question[:50]}...' ---")
        
        # Get a token for Microsoft Graph API
        try:
            token = get_token_interactive()
            headers = {"Authorization": f"Bearer {token}"}
            print("Successfully obtained authentication token")
        except Exception as auth_error:
            print(f"Authentication failed: {str(auth_error)}")
            error_details = str(auth_error)
            return templates.TemplateResponse("index.html", {
                "request": request, 
                "response": f"Authentication failed. Please try again.\n\nError: {error_details}"
            })        # Query Microsoft Graph API with timeout and better error handling
        print("Querying Microsoft Graph API...")
        timeout = aiohttp.ClientTimeout(total=30)  # 30 second timeout
        async with aiohttp.ClientSession(headers=headers, timeout=timeout) as session:
            try:
                # Use asyncio.gather for concurrent requests
                entra_roles_task = session.get("https://graph.microsoft.com/beta/roleManagement/directory/roleDefinitions")
                pim_groups_task = session.get("https://graph.microsoft.com/v1.0/groups?$filter=startswith(displayName,'PIM-Entra')")
                az_groups_task = session.get("https://graph.microsoft.com/v1.0/groups?$filter=startswith(displayName,'PIM-AzRes-')")
                
                entra_roles_resp, pim_groups_resp, az_groups_resp = await asyncio.gather(
                    entra_roles_task, pim_groups_task, az_groups_task
                )
                if entra_roles_resp.status != 200 or pim_groups_resp.status != 200 or az_groups_resp.status != 200:
                    print(f"API error: Entra: {entra_roles_resp.status}, PIM: {pim_groups_resp.status}, Azure: {az_groups_resp.status}")
                    error_text = await entra_roles_resp.text()
                    raise Exception(f"Microsoft Graph API returned error: {error_text[:200]}...")
                
                # Parse responses
                entra_roles = (await entra_roles_resp.json())['value']
                pim_groups = (await pim_groups_resp.json())['value']
                az_groups = (await az_groups_resp.json())['value']
                
                print(f"Retrieved {len(entra_roles)} Entra roles, {len(pim_groups)} PIM groups, {len(az_groups)} Azure groups")
            except Exception as api_error:
                print(f"API request failed: {str(api_error)}")
                raise Exception(f"Error querying Microsoft Graph API: {str(api_error)}")
          # Build the prompt for Azure OpenAI
        prompt = get_role_recommendation_prompt(entra_roles, pim_groups, az_groups, question)
        print("Sending request to Azure OpenAI...")
        
        response = requests.post(
            URI,
            headers={'api-key': API_KEY, 'Content-Type': 'application/json'},
            json={
                'model': DEPLOYMENT,
                'temperature': 0.7,
                'max_tokens': 2048,
                'messages': [
                    {"role": "system", "content": get_role_recommendation_system_message()},
                    {"role": "user", "content": prompt}
                ]
            },
            timeout=30  # Add timeout to prevent hanging
        )
        
        if response.status_code != 200:
            print(f"OpenAI API error: {response.status_code}")
            error_text = response.text
            raise Exception(f"Azure OpenAI returned error {response.status_code}: {error_text[:200]}...")
        
        response_json = response.json()
        answer = response_json['choices'][0]['message']['content']
        print("Successfully received response from Azure OpenAI")
        
        return templates.TemplateResponse("index.html", {"request": request, "response": answer})
    
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        print(f"ERROR: {str(e)}")
        print(f"TRACEBACK: {error_details}")
        return templates.TemplateResponse("index.html", {
            "request": request, 
            "response": f"An error occurred: {str(e)}\n\nPlease check the console for more details."
        })

@app.get("/test")
async def test():
    return {"message": "Server is working!", "status": "ok"}

# Run the application directly when executed as a script
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)

