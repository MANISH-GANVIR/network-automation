from fastapi.staticfiles import StaticFiles
import os

from backend.projects.vpn_automation.asa.web_wrapper import run_web
from backend.ai.ai_chat import ai_chat
from fastapi import FastAPI, Body
from fastapi.middleware.cors import CORSMiddleware

from backend.projects.vpn_automation.asa.web_wrapper import run_web

app = FastAPI(title="Automation Backend")

# ----------------------------
# CORS
# ----------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ----------------------------
# LOGIN
# ----------------------------
@app.post("/login")
def login(payload: dict = Body(default={})):
    username = (payload or {}).get("username")
    password = (payload or {}).get("password")

    if username and password:
        return {"success": True}

    return {"success": False}


# ----------------------------
# GENERIC ASA ROUTE
# Works for: discovery, reset, update, build, troubleshoot
# ----------------------------
@app.post("/asa/{task}")
def asa_task(task: str, payload: dict = Body(default={})):
    try:
        payload = payload or {}
        seq = payload.get("seq")

        stdout = run_web(
            task=task,
            seq=seq,
            payload=payload
        )

        return {"stdout": stdout}

    except Exception as e:
        return {"error": str(e)}


@app.post("/ai/chat")
def ai_assistant(payload: dict = Body(default={})):

    prompt = payload.get("message", "")

    answer = ai_chat(prompt)

    return {
        "response": answer
    }

# Serve frontend
if os.path.exists("./frontend"):
    app.mount("/", StaticFiles(directory="./frontend", html=True), name="frontend")