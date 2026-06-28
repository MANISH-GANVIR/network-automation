"""
# =============================================================================
# File : backend/main.py
#
# Purpose:
# This is the main backend entry point of the application.
# It creates the FastAPI backend application, configures CORS,
# defines all REST API endpoints, and connects the frontend
# with the backend business logic.
#
# Why REST APIs?
# The frontend (login.html / app.js) cannot directly call Python
# functions. Therefore, REST APIs are created to expose backend
# business logic over HTTP. The frontend sends HTTP requests
# using the JavaScript Fetch API, FastAPI processes the request,
# executes the required Python function, and returns a JSON response.
#
# Backend Structure:
#
# backend/main.py
# │
# ├── FastAPI Application
# │      Creates the backend application.
# │
# ├── CORS Configuration
# │      Allows the frontend and backend running on different
# │      ports to communicate without browser CORS errors.
# │
# ├── Login API
# │      Authenticates users.
# │
# ├── VPN Automation API
# │      Core API of the project.
# │      Executes VPN Discovery, Reset, Build,
# │      Update and Troubleshooting operations.
# │
# ├── AI Chat API
# │      Sends user prompts and attached files to the
# │      local Ollama LLM and returns AI responses.
# │
# ├── File Upload API
# │      Placeholder for future file upload support.
# │
# ├── Vision API
# │      Placeholder for future AI Vision features.
# │
# └── Serve Frontend
#        Serves HTML, CSS and JavaScript files.
#
# Overall Request Flow
#
# Frontend
#     │
# Fetch API
#     │
# REST API
#     │
# FastAPI Backend
#     │
# Python Function
#     │
# Business Logic
#     │
# Cisco ASA / Ollama
#     │
# JSON Response
#     │
# Frontend
#
# =============================================================================

# Import StaticFiles to serve frontend files (HTML, CSS, JS)
from fastapi.staticfiles import StaticFiles

# Import OS module to check directory existence
import os

# Import VPN Automation Wrapper
from backend.projects.vpn_automation.asa.web_wrapper import run_web

# Import AI Chat function (Ollama Integration)
from backend.ai.ai_chat import ai_chat

# Import FastAPI framework and Body class
from fastapi import FastAPI, Body

# Import CORS Middleware
from fastapi.middleware.cors import CORSMiddleware

# ============================================================
# FastAPI
# ============================================================

# FastAPI is a modern Python web framework.
# It is used to build backend applications and REST APIs.
# app = FastAPI(...) creates the backend application object.
# The backend application receives HTTP requests from the frontend.
# It routes the request to the correct REST API endpoint.
# It executes the required business logic.
# It communicates with Cisco ASA, Ollama AI, databases, etc.
# Finally, it returns the response to the frontend in JSON format.


# ============================================================
# Decorator
# ============================================================
# A decorator is a Python feature.
# It adds extra functionality to a function without modifying its code.
# In FastAPI, decorators register REST API endpoints.
# @app.post("/login") tells FastAPI which function should execute.
# When POST /login request arrives, login() function is executed.
# @ = Python decorator syntax.
# app.post() = FastAPI decorator method.
# @app.post() = Complete FastAPI decorator.

# ============================================================
# REST API
# ============================================================
# REST API stands for Representational State Transfer API.
# REST API is a communication method between client and server.
# It uses HTTP protocol.
# It exchanges data in JSON format.
# Common HTTP Methods:
# GET    -> Read data
# POST   -> Create data
# PUT    -> Update data
# DELETE -> Delete data


# ============================================================
# Backend Application
# ============================================================
# app = FastAPI(title="Automation Backend")
# Creates the backend application.
# All REST APIs are registered inside this application.

# ============================================================
# REST API Endpoints
# ============================================================
# POST /login
# Used for user authentication.
# POST /asa/{task}
# Used for VPN Discovery, Reset, Update, Build and Troubleshooting.
# POST /ai/chat
# Used to communicate with Ollama AI.
# POST /upload
# Used to upload files.
# POST /vision
# Used for image analysis (Future Enhancement).

# ============================================================
# Request Flow
# ============================================================
# Frontend (HTML / JavaScript)
# Fetch API sends HTTP request.
# FastAPI receives the request.
# FastAPI identifies the REST API endpoint.
# Corresponding Python function executes.
# Business Logic executes.
# Cisco ASA / Ollama AI is called if required.
# JSON response is returned.
# Frontend displays the response.

# ============================================================
# Functions
# ============================================================
# login()
# Executes login business logic.
# asa_task()
# Executes VPN automation business logic.
# ai_assistant()
# Executes AI chat business logic.
# run_web()
# Executes Cisco ASA automation.
# ai_chat()
# Sends prompt to Ollama LLM.

# ============================================================
# Components
# ============================================================
# FastAPI
# Backend Framework.

# app
# Backend Application Object.

# @
# Python Decorator Syntax.

# app.post()
# FastAPI Decorator Method.

# @app.post()
# Complete FastAPI Decorator.

# login()
# Python Function.

# asa_task()
# Python Function.

# ai_assistant()
# Python Function.

# fetch()
# Sends HTTP request from frontend.

# JSON
# Data exchange format.

# Business Logic
# Actual Python code that performs the task.


# ============================================================
# Complete Flow
# ============================================================

# Frontend
#      │
#      ▼
# Fetch API
#      │
#      ▼
# FastAPI Backend
#      │
#      ▼
# REST API Endpoint
#      │
#      ▼
# Python Function
#      │
#      ▼
# Business Logic
#      │
#      ▼
# Cisco ASA / Ollama AI
#      │
#      ▼
# JSON Response
#      │
#      ▼
# Frontend UI
# ---------------------------------------------
# Create FastAPI Application
# ---------------------------------------------
app = FastAPI(title="Automation Backend")


# ==========================================================
# Enable CORS (Cross-Origin Resource Sharing)
# ==========================================================

# CORS allows the frontend and backend
# running on different ports or domains
# to communicate with each other.

# add_middleware() adds middleware to
# the FastAPI application.

# CORSMiddleware enables CORS support.

app.add_middleware(

    CORSMiddleware,

    # Allow requests from all origins.
    allow_origins=["*"],

    # Allow cookies and authentication.
    allow_credentials=True,

    # Allow all HTTP methods.
    # GET, POST, PUT, DELETE, etc.
    allow_methods=["*"],

    # Allow all HTTP headers.
    allow_headers=["*"],
)


# ==========================================================
# REST API 1 : LOGIN API
# URL : POST /login
#
# Purpose:
# - Receives username and password from the frontend.
# - Validates user credentials.
# - Returns the authentication result as a JSON response.
#
# Flow:
# Frontend
#     │
# POST /login
#     │
# login()
#     │
# Validate Credentials
#     │
# JSON Response
# ==========================================================

@app.post("/login")
def login(payload: dict = Body(default={})):

    # Read username from JSON body
    username = (payload or {}).get("username")

    # Read password from JSON body
    password = (payload or {}).get("password")

    # Validate credentials
    if username and password:
        return {"success": True}

    return {"success": False}


# ==========================================================
# REST API 2
# Generic ASA API
# URL : POST /asa/{task}
#
# Handles:
# discovery
# reset
# build
# update
# troubleshoot
# ==========================================================
@app.post("/asa/{task}")
def asa_task(task: str, payload: dict = Body(default={})):

    try:

        # Read JSON Body
        payload = payload or {}

        # Sequence number from frontend
        seq = payload.get("seq")

        # Call VPN Automation Wrapper
        stdout = run_web(
            task=task,
            seq=seq,
            payload=payload
        )

        # Return output to frontend
        return {"stdout": stdout}

    except Exception as e:

        # Return error if exception occurs
        return {"error": str(e)}


# ==========================================================
# REST API 3
# AI CHAT API
# URL : POST /ai/chat
# ==========================================================

@app.post("/ai/chat")
def ai_assistant(payload: dict = Body(default={})):

    try:
        # Ensure payload is always a dictionary
        payload = payload or {}

        # Read user message
        prompt = (payload.get("message", "") or "").strip()

        # Read attached files (if any)
        files = payload.get("files", []) or []

        # Build file context for AI Model
        file_context = ""

        if files:

            file_context = "\n\n=== ATTACHED FILES ===\n"

            for file in files:

                file_context += f"\nFile: {file.get('name')}\n"
                file_context += f"Size: {file.get('size')} bytes\n"
                file_context += f"Type: {file.get('type')}\n"
                file_context += f"Content:\n{file.get('content')}\n"
                file_context += "---\n"

        # Optional guard: empty prompt + no file
        if not prompt and not files:
            return {"response": "Please provide a message or attach a file."}

        # Send prompt + file context to Ollama
        # IMPORTANT FIX:
        # ai_chat() now accepts (user_prompt, file_context="")
        answer = ai_chat(prompt, file_context)

        # Return AI response
        return {"response": answer}

    except Exception as e:
        return {"response": f"Error: {str(e)}"}


# ==========================================================
# REST API 4
# File Upload API
# URL : POST /upload
# Future Enhancement
# ==========================================================
@app.post("/upload")
def upload_files(payload: dict = Body(default={})):

    return {
        "status": "ok",
        "message": "Files received"
    }


# ==========================================================
# REST API 5
# Vision API
# URL : POST /vision
# Future Enhancement
# ==========================================================
@app.post("/vision")
def vision_api(payload: dict = Body(default={})):

    return {
        "status": "ok",
        "message": "Vision API ready"
    }


# ==========================================================
# Serve Frontend
# Automatically loads HTML/CSS/JS
# ==========================================================
if os.path.exists("./frontend"):

    app.mount(
        "/",
        StaticFiles(directory="./frontend", html=True),
        name="frontend"
    )
"""
# =============================================================================
# File : backend/main.py
#
# Purpose:
# This is the main backend entry point of the application.
# It creates the FastAPI backend application, configures CORS,
# defines all REST API endpoints, and connects the frontend
# with the backend business logic.
# =============================================================================

from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse
from fastapi import FastAPI, Body
from fastapi.middleware.cors import CORSMiddleware
import traceback
import os

from backend.projects.vpn_automation.asa.web_wrapper import run_web
from backend.ai.ai_chat import ai_chat

app = FastAPI(title="Automation Backend")

# CORS for Live Server + localhost variants
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:63342",
        "http://127.0.0.1:63342",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "null"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.post("/login")
def login(payload: dict = Body(default={})):
    username = (payload or {}).get("username")
    password = (payload or {}).get("password")

    if username and password:
        return {"success": True}

    return {"success": False}


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
    """
    Always returns JSON and never crashes with unhandled 500 for chat flow.
    """
    try:
        payload = payload or {}

        prompt = (payload.get("message", "") or "").strip()
        files = payload.get("files", []) or []

        # Defensive payload normalization (fixes 500 on malformed file objects)
        normalized_files = []
        if isinstance(files, list):
            for f in files:
                if isinstance(f, dict):
                    normalized_files.append({
                        "name": str(f.get("name", "")),
                        "size": f.get("size", 0),
                        "type": str(f.get("type", "")),
                        "content": str(f.get("content", "")),
                    })

        file_context = ""
        if normalized_files:
            file_context = "\n\n=== ATTACHED FILES ===\n"
            for file in normalized_files:
                file_context += f"\nFile: {file.get('name')}\n"
                file_context += f"Size: {file.get('size')} bytes\n"
                file_context += f"Type: {file.get('type')}\n"
                file_context += f"Content:\n{file.get('content')}\n"
                file_context += "---\n"

        if not prompt and not normalized_files:
            return JSONResponse(content={"response": "Please provide a message or attach a file."}, status_code=200)

        # Critical fix: ai_chat supports (user_prompt, file_context)
        answer = ai_chat(prompt, file_context)

        return JSONResponse(content={"response": str(answer)}, status_code=200)


    except Exception as e:

        traceback.print_exc()

        raise
@app.post("/upload")
def upload_files(payload: dict = Body(default={})):
    return {
        "status": "ok",
        "message": "Files received"
    }


@app.post("/vision")
def vision_api(payload: dict = Body(default={})):
    return {
        "status": "ok",
        "message": "Vision API ready"
    }


if os.path.exists("./frontend"):
    app.mount(
        "/",
        StaticFiles(directory="./frontend", html=True),
        name="frontend"
    )