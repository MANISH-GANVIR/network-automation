import requests
import json

OLLAMA_URL = "http://127.0.0.1:11434/api/generate"


def ai_chat(user_prompt, file_context=""):
    system_prompt = """
    ROLE:
    You are a Senior Network Automation, Security and DevOps Engineer.

    Expertise:
    - Cisco ASA
    - Palo Alto
    - IPSec VPN
    - IKEv1/IKEv2
    - BGP
    - OSPF
    - Python Network Automation
    - Ansible
    - Terraform
    - DevNet

    TASK:
    Provide accurate answers, troubleshooting guidance, automation recommendations, code examples and operational support for networking, security and infrastructure automation.

    INSTRUCTIONS:
    - Answer in a professional and easy-to-understand manner.
    - For career, LinkedIn, resume, interview and learning questions, answer normally.
    - For coding requests, provide working code examples.
    - For networking questions, provide practical explanations and commands where applicable.
    - For troubleshooting requests, follow the defined troubleshooting format.
    - Keep responses concise but useful.

    INPUT:
    The user's question, log output, configuration snippet, error message, command output or automation request.

    CONTEXT:
    You are embedded inside an Enterprise VPN Automation Portal used by network engineers for VPN operations, Cisco ASA administration, network automation, AI-assisted troubleshooting, Python development, Ansible orchestration and infrastructure management.

    OUTPUT:

    For normal questions:
    - Direct Answer
    - Example (if applicable)

    For troubleshooting questions:
    - Root Cause
    - Severity
    - Verification Commands
    - Recommended Fix
    - Prevention
    """

    prompt = f"""
{system_prompt}

Question:
{user_prompt}

{file_context if file_context else ""}
"""

    try:
        response = requests.post(
            OLLAMA_URL,
            json={
                "model": "qwen3:1.7b",
                "prompt": prompt,
                "stream": False
            },
            timeout=300
        )

        if response.status_code != 200:
            return f"Ollama Error: {response.status_code} - {response.text}"

        # Defensive JSON parse (fixes backend 500 if Ollama returns non-JSON text)
        try:
            data = response.json()
        except json.JSONDecodeError:
            return f"Error: Invalid JSON from Ollama: {response.text[:500]}"

        if not isinstance(data, dict):
            return f"Error: Unexpected Ollama response type: {type(data).__name__}"

        return str(data.get("response", "No response received from Ollama."))

    except requests.exceptions.Timeout:
        return "Error: Ollama took too long to respond (>300s). Try again or restart Ollama."
    except requests.exceptions.ConnectionError:
        return "Error: Cannot connect to Ollama at http://127.0.0.1:11434. Make sure Ollama is running: ollama serve"
    except Exception as e:
        return f"Error: {str(e)}"