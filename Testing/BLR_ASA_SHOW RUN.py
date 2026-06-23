from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException
import sys

# --------------------------------
# CONNECT TO ASA (SAFE METHOD)
# --------------------------------
def connect_asa():
    asa = {
        "device_type": "cisco_asa",
        "host": "10.63.66.10",
        "username": "asaadmin",
        "password": "AsA#Net@4519!",
        # "secret": "enable_password_if_any",
        "port": 22,
        "fast_cli": False,
    }

    try:
        print("[+] Connecting to ASA...")
        conn = ConnectHandler(**asa)
        conn.enable()
        print("[+] Connected to ASA successfully\n")
        return conn

    except NetmikoTimeoutException:
        print("\n❌ Unable to reach ASA")
        print("👉 Please verify:")
        print("   - Office VPN is DISCONNECTED")
        print("   - ASA management IP (10.63.66.10) is reachable")
        print("   - SSH port 22 is open")
        print("   - Try: ping 10.63.66.10\n")
        sys.exit(1)

    except NetmikoAuthenticationException:
        print("\n❌ Authentication failed")
        print("👉 Check username/password or enable password\n")
        sys.exit(1)


# --------------------------------
# SHOW RUNNING-CONFIG
# --------------------------------
def show_run(conn):
    print("========== SHOW RUNNING-CONFIG ==========\n")
    output = conn.send_command(
        "show running-config",
        expect_string=r"#",
        delay_factor=5
    )
    print(output)


# --------------------------------
# MAIN
# --------------------------------
if __name__ == "__main__":
    conn = connect_asa()
    show_run(conn)
    conn.disconnect()
    print("\n[+] ASA show run completed successfully")

