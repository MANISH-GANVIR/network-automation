from .discovery import discover_tunnels
from .menu import show_menu
from .reset import reset_vpn
from .update import update_vpn
from .build import build_vpn
from .troubleshoot import troubleshoot_vpn

def run_asa_vpn_ops(conn):
    while True:
        tunnels = discover_tunnels(conn)  # ✅ refresh every time before menu

        choice = show_menu()

        if choice == "1":
            reset_vpn(conn, tunnels)
        elif choice == "2":
            update_vpn(conn)
        elif choice == "3":
            build_vpn(conn)
        elif choice == "4":
            troubleshoot_vpn(conn)
        elif choice == "5":
            print(f"[{conn.hostname}] Exiting ASA VPN Automation")
            break
        else:
            print("[INFO] Invalid option")