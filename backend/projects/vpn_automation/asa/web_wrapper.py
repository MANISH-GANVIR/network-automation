import io
import os
from contextlib import redirect_stdout

from .client import connect_asa, disconnect_asa
from .discovery import discover_tunnels
from .reset import reset_vpn, reset_vpn_by_peer_ip   # ✅ changed
from .build import build_vpn
from .update import update_vpn
from .troubleshoot import troubleshoot_vpn

def run_web(task: str, seq: int | None = None, payload: dict | None = None):
    os.environ["WEB_MODE"] = "1"

    buffer = io.StringIO()

    with redirect_stdout(buffer):
        print("\n" + "=" * 70)
        print("        VPN AUTOMATION : ASA OUTPUT (CLI MODE)")
        print("=" * 70 + "\n")
        conn = connect_asa()
        try:
            tunnels = discover_tunnels(conn)

            print("\n" + "-" * 70 + "\n")
            if task == "reset":
                # ✅ NEW: peer_ip based reset
                peer_ip = (payload or {}).get("peer_ip")
                if not peer_ip:
                    print("ERROR: peer_ip required for reset")
                else:
                    reset_vpn_by_peer_ip(conn, tunnels, peer_ip)

            elif task == "build":
                build_vpn(conn)

            elif task == "update":
                update_vpn(conn, payload)

            elif task == "troubleshoot":
                troubleshoot_vpn(conn)

            elif task == "discovery":
                pass

            else:
                print(f"ERROR: Unknown task '{task}'")

        finally:
            if not (payload and payload.get("preview_only")):
                disconnect_asa(conn)
                print("\nDisconnected ✔")

    return buffer.getvalue()