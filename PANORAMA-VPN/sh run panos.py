from panos.firewall import Firewall
import xml.etree.ElementTree as ET


def show_system_info(fw):
    print("\n> show system info")
    print("Fetching system information...\n")

    # Same CLI-style op command
    op_result = fw.op("show system info")

    # Normalize response
    if hasattr(op_result, "tag"):
        root = op_result
    else:
        root = ET.fromstring(op_result)

    hostname = root.findtext(".//hostname", default="N/A")
    ip = root.findtext(".//ip-address", default="N/A")
    model = root.findtext(".//model", default="N/A")
    version = root.findtext(".//sw-version", default="N/A")
    serial = root.findtext(".//serial", default="N/A")
    uptime = root.findtext(".//uptime", default="N/A")

    print("===== Firewall System Information =====")
    print(f"Hostname        : {hostname}")
    print(f"Management IP   : {ip}")
    print(f"Model           : {model}")
    print(f"Serial Number   : {serial}")
    print(f"PAN-OS Version  : {version}")
    print(f"Uptime          : {uptime}")
    print("======================================\n")


def main():
    fw = Firewall(
        hostname="20.232.50.129",
        api_username="netadmin",
        api_password="Epi(0r@2020+"
    )

    print(f"\nSuccessfully connected to {fw.hostname}!\n")
    show_system_info(fw)


if __name__ == "__main__":
    main()