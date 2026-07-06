import requests
import json
import re
from typing import Optional, Dict

OLLAMA_URL = "http://127.0.0.1:11434/api/generate"
MODEL_NAME = "qwen3:1.7b"


def _normalize(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").strip().lower())


def _is_greeting(text: str) -> bool:
    t = _normalize(text)
    greetings = {
        "hi", "hii", "hello", "hey", "heyy",
        "good morning", "good evening", "good afternoon",
        "how are you", "kaise ho", "kya haal"
    }
    return t in greetings


def _is_incident(text: str) -> bool:
    t = _normalize(text)
    signals = [
        "alert", "down", "tunnel down", "vpn down", "site to site", "ipsec",
        "ike", "phase 1", "phase 2", "peer", "packet drop", "not working",
        "failed", "failure", "asa", "fortigate", "palo alto", "panorama"
    ]
    return any(s in t for s in signals)


def _extract_first_ipv4(text: str) -> Optional[str]:
    m = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text or "")
    return m.group(0) if m else None


def _extract_field(text: str, key: str) -> Optional[str]:
    """
    Extracts value from patterns like:
    Device: ASA-DC1, Tunnel: VPN_US_INDIA, Status: DOWN
    """
    if not text:
        return None
    pattern = rf"{re.escape(key)}\s*:\s*([^,\n]+)"
    m = re.search(pattern, text, flags=re.IGNORECASE)
    return m.group(1).strip() if m else None


def _build_system_prompt(force_prod_troubleshooting: bool) -> str:
    prod_flag = (
        "FOR THIS REQUEST: Treat as REAL PRODUCTION INCIDENT. Command accuracy is mandatory."
        if force_prod_troubleshooting
        else "Use production troubleshooting format only when user reports real incident."
    )

    return f"""
ROLE
You are a Senior Network Security & Automation Engineer (NOC/L3 on-call style).

EXPERTISE
- Cisco ASA, Palo Alto, Panorama, Fortinet
- IPSec VPN (IKEv1/IKEv2), NAT, ACL, Routing
- BGP, OSPF, Switching
- Azure/AWS Networking
- Python, APIs, FastAPI, Ansible, Terraform, Linux

OBJECTIVE
Give production-safe, command-accurate, step-by-step troubleshooting and fixes.

{prod_flag}

NON-NEGOTIABLE RULES
1) If user greeting only, respond briefly and naturally.
2) If incident is reported, provide runbook-style output (no theory dump).
3) Never hallucinate logs/output/config.
4) Use only vendor-correct commands.
5) Keep it concise, practical, action-oriented.
6) Do not output internal tags like Intent/Reasoning/Classification.
7) If data missing, ask only essential missing inputs (max 5 bullets).

ASA ACCURACY GUARDRAILS (MANDATORY FOR ASA)
Allowed/Preferred commands:
- show interface ip brief
- show interface <outside_if>
- show route
- ping <peer_ip> source <outside_if>
- traceroute <peer_ip>
- show crypto ikev1 sa
- show crypto ikev2 sa
- show crypto ikev2 sa detail
- show crypto ipsec sa peer <peer_ip>
- show run tunnel-group <peer_ip>
- show run crypto ikev1
- show run crypto ikev2
- show run crypto map
- show run nat
- show nat detail
- show access-list
- show access-group
- show asp drop | include <peer_ip>|500|4500|ESP
- packet-tracer input <inside_if> ip <src_ip> <sport> <dst_ip> <dport> detailed
- capture ... (short duration)
- debug crypto ... then undebug all

Avoid invalid/generic commands:
- show vpnvpn
- show firewall policies
- service vpn status
- monitor interface <if>
- show process table (for IPSec RCA)

WHEN INCIDENT: OUTPUT FORMAT (STRICT)
1) Problem Summary
2) Assumptions (only if required)
3) Severity/Impact
4) Step-by-Step Verification (L1 to L7)
   - What to check
   - Exact command(s)
   - Healthy output
   - If unhealthy -> next action
5) Isolation Result
6) Recommended Fix (minimal-risk sequence)
7) Validation After Fix
8) Prevention (3 bullets max)

CODING REQUESTS
If user asks code:
- Return working code first
- Then short explanation
- Include error handling best practices

STYLE
- Professional, brief, production-focused.
- Final answer only.
"""


def _build_user_prompt(user_prompt: str, file_context: str = "") -> str:
    device = _extract_field(user_prompt, "Device")
    tunnel = _extract_field(user_prompt, "Tunnel")
    status = _extract_field(user_prompt, "Status")
    peer = _extract_field(user_prompt, "Peer") or _extract_first_ipv4(user_prompt)

    extracted: Dict[str, Optional[str]] = {
        "device": device,
        "tunnel": tunnel,
        "status": status,
        "peer": peer,
    }

    incident_hints = ""
    if _is_incident(user_prompt):
        incident_hints = "INCIDENT_HINTS:\n"
        for k, v in extracted.items():
            if v:
                incident_hints += f"- {k}: {v}\n"
        incident_hints += (
            "- User expects real production troubleshooting.\n"
            "- Keep response L1->L7, command-first, ASA-valid only.\n"
            "- No generic filler text.\n"
        )

    return f"""
Question:
{user_prompt}

{incident_hints}

{file_context if file_context else ""}
"""


def ai_chat(user_prompt, file_context=""):
    if _is_greeting(user_prompt):
        return "Hello! Kaise help karun aaj?"

    incident_mode = _is_incident(user_prompt)
    system_prompt = _build_system_prompt(force_prod_troubleshooting=incident_mode)
    final_prompt = f"{system_prompt}\n\n{_build_user_prompt(user_prompt, file_context)}"

    try:
        response = requests.post(
            OLLAMA_URL,
            json={
                "model": MODEL_NAME,
                "prompt": final_prompt,
                "stream": False
            },
            timeout=300
        )

        if response.status_code != 200:
            return f"Ollama Error: {response.status_code} - {response.text}"

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