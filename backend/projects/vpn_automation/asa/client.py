# =============================================================================
# client.py (ASA Connection Manager)
# =============================================================================
# Purpose:
# - Provides reusable functions to CONNECT and DISCONNECT from a Cisco ASA firewall.
# - Used by both CLI mode (menu-driven) and Web mode (API-driven).
#
# Key Functions:
# 1) connect_asa()
#    - Creates SSH session to ASA using Netmiko (ConnectHandler)
#    - Fetches hostname (show hostname) for better logs
#    - Enters enable mode (privileged access)
#    - Shows spinner messages ONLY in CLI mode (WEB_MODE not set)
#
# 2) disconnect_asa(conn)
#    - Closes the SSH session cleanly
#    - Shows disconnect spinner ONLY in CLI mode
#
# Benefit:
# - Centralized connection logic (single place to manage ASA login/logout)
# - Prevents duplicated code across modules
# - Ensures stable automation execution and clean session handling
# =============================================================================
from .config import ASA_DEVICE, DRY_RUN
import os
import sys
import re

# DRY RUN FLAG
from .config import ASA_DEVICE, DRY_RUN

# Only import netmiko if NOT dry run
if not DRY_RUN:
    from netmiko import ConnectHandler
    from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException

from backend.utils.spinner import square_spinner


# -----------------------------
# Helper functions (same)
# -----------------------------
def _show(conn, cmd: str, title: str | None = None) -> str:
    if title:
        print(f"\n--- {title} ---")
    print(f"{conn.hostname}# {cmd}")
    out = conn.send_command(cmd) or ""
    print(out.strip())
    return out


def _detect_outside_interface_by_default_route(route_out: str) -> str:
    m = re.search(
        r"^S\*\s+0\.0\.0\.0\s+0\.0\.0\.0\s+\[\d+/\d+\]\s+via\s+\S+,\s+(\S+)",
        route_out,
        re.MULTILINE,
    )
    return m.group(1).strip() if m else "outside"


def _detect_interface_ip_from_show_interface(show_int_out: str) -> str:
    m = re.search(r"\bIP address\s+(\d+\.\d+\.\d+\.\d+)", show_int_out or "")
    return m.group(1).strip() if m else "1.1.1.1"


# -----------------------------
# MAIN CONNECTION FUNCTION
# -----------------------------
def connect_asa():
    # 🔥 DRY RUN MODE
    if DRY_RUN:
        print("🟡 DRY RUN MODE: Using dummy firewall (1.1.1.1)")

        class DummyConn:
            hostname = "dummy-asa"
            outside_iface = "outside"
            outside_ip = "1.1.1.1"

            def send_command(self, cmd):
                print(f"dummy-asa# {cmd}")
                return f"[MOCK OUTPUT] Executed: {cmd}"

            def enable(self):
                pass

            def disconnect(self):
                print("[MOCK] Disconnected")

        return DummyConn()

    # -----------------------------
    # REAL CONNECTION (only if DRY_RUN = False)
    # -----------------------------
    try:
        web_mode = os.getenv("WEB_MODE") == "1"

        if not web_mode:
            square_spinner(f"🔄 Connecting to ({ASA_DEVICE['host']})", 3)

        conn = ConnectHandler(**ASA_DEVICE)
        hostname = conn.send_command("show hostname").strip()

        if not web_mode:
            square_spinner(f"[{hostname}] Successfully logged in", 2)

        conn.enable()

        if not web_mode:
            square_spinner(f"[{hostname}] Enable mode access confirmed", 2)

        conn.hostname = hostname

        print("\nNOTE:")
        print("Detecting outside interface using default route...\n")

        route_out = _show(conn, "show route", "Routing Table")
        outside_by_route = _detect_outside_interface_by_default_route(route_out)

        candidate = outside_by_route
        show_int = _show(conn, f"show interface {candidate}", f"Interface: {candidate}")

        conn.outside_iface = candidate
        conn.outside_ip = _detect_interface_ip_from_show_interface(show_int)

        print("\n[INFO] Outside Interface:", conn.outside_iface)
        print("[INFO] Outside IP:", conn.outside_ip, "\n")

        return conn

    except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
        print(f"[ERROR] ASA connection failed: {e}")
        sys.exit(1)


# -----------------------------
# DISCONNECT
# -----------------------------
def disconnect_asa(conn):
    if DRY_RUN:
        print("[MOCK] Disconnect skipped")
        return

    if os.getenv("WEB_MODE") != "1":
        square_spinner(f"[{conn.hostname}] Disconnecting", 2)

    conn.disconnect()