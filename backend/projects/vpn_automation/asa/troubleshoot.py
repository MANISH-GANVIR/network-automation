# /asa/troubleshoot.py                  # File path: ASA VPN troubleshooting module

def troubleshoot_vpn(conn):                       # Function to troubleshoot ASA VPN issues
    print("\n[ASA] VPN TROUBLESHOOTING MODE\n")
                                                   # Display troubleshooting mode banner

    peer_ip = input("Enter Peer IP (or n to cancel): ").strip()
                                                   # Ask user for peer IP address

    if peer_ip.lower() == "n":                     # Check if user wants to cancel
        print("[ASA] Troubleshoot cancelled\n")    # Print cancellation message
        return                                    # Exit troubleshooting function

    print("\n[ASA] IKE STATUS\n")                  # Print IKE status section header
    print(conn.send_command("show crypto ikev1 sa"))
                                                   # Display IKEv1 security association status

    print("\n[ASA] IPSEC STATUS\n")                # Print IPsec status section header
    print(conn.send_command("show crypto ipsec sa"))
                                                   # Display IPsec security association status

    print("\n[ASA] LAST CRYPTO LOGS\n")             # Print crypto logs section header
    print(
        conn.send_command(
            "show logging | include IKE|IPSEC|CRYPTO"
        )
    )                                              # Filter and display recent crypto-related logs

    print("\n[ASA] Troubleshoot completed\n")      # Print completion message
