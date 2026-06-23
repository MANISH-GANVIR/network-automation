from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException

# ================================
# ASA CONNECTION DETAILS
# ================================
asa = {
    "device_type": "cisco_asa",
    "host": "10.63.66.10",
    "username": "asaadmin",
    "password": "AsA#Net@4519!",
    "port": 22,
    "fast_cli": False,
    "timeout": 10,
}

PEER_IP = "4.227.229.249"   # change if needed

# ================================
# CONNECT TO ASA
# ================================
try:
    print("\n[+] Connecting to ASA...\n")
    conn = ConnectHandler(**asa)
    conn.enable()
    print("[+] Connected successfully\n")
except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
    print(f"[!] Connection failed: {e}")
    exit(1)


# ================================
# HELPER FUNCTION
# ================================
def run_and_print(title, command):
    print("\n" + "=" * 70)
    print(f"{title}")
    print("=" * 70)
    output = conn.send_command(command)
    print(output if output.strip() else "[No matching logs found]")


# ================================
# VPN LOG SECTIONS
# ================================

run_and_print(
    "FULL LOGGING STATUS",
    "show logging"
)

run_and_print(
    "IKE (PHASE-1) LOGS",
    "show logging | include IKE"
)

run_and_print(
    "IPSEC (PHASE-2) LOGS",
    "show logging | include IPSEC"
)

run_and_print(
    "VPN GENERIC LOGS",
    "show logging | include VPN"
)

run_and_print(
    f"PEER-SPECIFIC LOGS ({PEER_IP})",
    f"show logging | include {PEER_IP}"
)

run_and_print(
    "DENY / BLOCKED TRAFFIC LOGS",
    "show logging | include denied"
)

run_and_print(
    "ACCESS / ACL RELATED LOGS",
    "show logging | include access"
)

# ================================
# DISCONNECT
# ================================
conn.disconnect()
print("\n[+] Log collection completed\n")
