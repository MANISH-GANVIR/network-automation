from pandevice.firewall import Firewall
import xml.etree.ElementTree as ET


def _to_element(op_result):
    """
    fw.op() may return an Element already (common), or string/bytes.
    Normalize to Element.
    """
    if hasattr(op_result, "tag"):
        return op_result
    if isinstance(op_result, bytes):
        op_result = op_result.decode("utf-8", errors="ignore")
    return ET.fromstring(op_result)


def show_system_info(fw: Firewall):
    print("\n> show system info")
    print("Fetching system information...\n")

    # FIX: Use CLI-style op command string (most compatible)
    op_result = fw.op("show system info")

    root = _to_element(op_result)

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

    print(f"Firewall {hostname} is a {model} device.")
    print(f"It is running PAN-OS version {version}.")
    print(f"The device has been up for {uptime}.")
    print(f"Management IP address is {ip}.\n")


def main():
    try:
        fw = Firewall(
            hostname="20.232.50.129",
            api_username="netadmin",
            api_password="Epi(0r@2020+"
        )

        print(f"\nSuccessfully connected to {fw.hostname}!\n")
        show_system_info(fw)

    except Exception as e:
        print("Error:", repr(e))


if __name__ == "__main__":
    main()