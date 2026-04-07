# -----------------------------------------------------------------------------
# Purpose of this module (main.py)
# -----------------------------------------------------------------------------
# This module is the main entry point for ASA VPN Automation in CLI mode.
#
# Flow:
# 1) Prints a CLI banner.
# 2) Connects to the ASA firewall using connect_asa() from client.py.
# 3) Runs the main operations/menu loop using run_asa_vpn_ops() from asa_vpn_ops.py.
# 4) Ensures the ASA connection is always closed using disconnect_asa() in a finally block,
#    even if an error occurs or the user exits.
#
# Benefit:
# - Central controller for CLI execution
# - Safe resource cleanup (no hanging SSH sessions)
# - Clear separation: connection handling (client.py) and operations (asa_vpn_ops.py)
# -----------------------------------------------------------------------------

from .client import connect_asa, disconnect_asa   # Import functions to connect and disconnect ASA
from .asa_vpn_ops import run_asa_vpn_ops          # Import main ASA VPN operations controller


def main():                                      # Main entry function for ASA CLI automation

    conn = connect_asa()      # Establish connection to ASA firewall
    mode = "CLI"
    print(f"\n{conn.hostname} ({mode})#")
    # Print application banner for CLI mode


    try:                      # Start try block to ensure safe execution
        run_asa_vpn_ops(conn) # Run ASA VPN operations menu and workflows

    finally:                  # Finally block ensures cleanup always runs
        disconnect_asa(conn)  # Disconnect ASA session gracefully
        print("\nDisconnected. Bye 👋\n")  # Print exit message


if __name__ == "__main__":    # Check if script is run directly
    main()                    # Call main() function