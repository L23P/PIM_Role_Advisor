import os
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from dotenv import load_dotenv
from auth import get_token_interactive
import aiohttp
import asyncio
import pandas as pd
import requests

load_dotenv()

API_KEY = os.getenv('AZURE_OPENAI_API_KEY')
ENDPOINT = os.getenv('AZURE_OPENAI_ENDPOINT')
DEPLOYMENT = os.getenv('AZURE_OPENAI_DEPLOYMENT')
API_VERSION = '2024-12-01-preview'
URI = f"{ENDPOINT}/openai/deployments/{DEPLOYMENT}/chat/completions?api-version={API_VERSION}"

app = FastAPI()
templates = Jinja2Templates(directory="templates")

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request, "response": ""})

@app.post("/ask", response_class=HTMLResponse)
async def ask(request: Request, question: str = Form(...)):
    token = get_token_interactive()
    headers = {"Authorization": f"Bearer {token}"}

    async with aiohttp.ClientSession(headers=headers) as session:
        entra_roles_resp = await session.get("https://graph.microsoft.com/beta/roleManagement/directory/roleDefinitions")
        pim_groups_resp = await session.get("https://graph.microsoft.com/v1.0/groups?$filter=startswith(displayName,'PIM-Entra')")
        az_groups_resp = await session.get("https://graph.microsoft.com/v1.0/groups?$filter=startswith(displayName,'PIM-AzRes-')")

        entra_roles = (await entra_roles_resp.json())['value']
        pim_groups = (await pim_groups_resp.json())['value']
        az_groups = (await az_groups_resp.json())['value']

    prompt = build_prompt(entra_roles, pim_groups, az_groups, question)

    response = requests.post(
        URI,
        headers={'api-key': API_KEY, 'Content-Type': 'application/json'},
        json={
            'model': DEPLOYMENT,
            'temperature': 0.7,
            'max_tokens': 2048,
            'messages': [
                {"role": "system", "content": "Advise on role assignments."},
                {"role": "user", "content": prompt}
            ]
        }
    )

    answer = response.json()['choices'][0]['message']['content']

    return templates.TemplateResponse("index.html", {"request": request, "response": answer})

def build_prompt(entra_roles, pim_groups, az_groups, question):
    entra_text = "\n".join(f"{r['displayName']} [{r['id']}]" for r in entra_roles)
    pim_text = "\n".join(f"{g['displayName']} [{g['id']}]" for g in pim_groups)
    az_text = "\n".join(f"{g['displayName']} [{g['id']}]" for g in az_groups)

    return f"""
Entra Roles:
{entra_text}

PIM Groups:
{pim_text}

Azure Groups:
{az_text}

User Question:
{question}

Format: Role => Recommended Group(s)
Least privilege prioritized.
"""

