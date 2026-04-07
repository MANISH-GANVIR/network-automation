from backend.utils.spinner import square_spinner   # Import spinner utility (for visual progress, if used)

def build_vpn(conn):                               # Function to build a new ASA VPN tunnel
    print("\n[ASA] BUILD VPN TUNNEL (Guided Mode)\n")  # Display build mode banner

    peer_ip = input("Enter Peer IP (or n to cancel): ").strip()  # Take peer IP input
    if peer_ip.lower() == "n":                      # Check if user wants to cancel
        print("[ASA] Build cancelled\n")            # Print cancellation message
        return                                     # Exit function

    acl_name = input("Enter Crypto ACL name: ").strip()      # Input crypto ACL name
    local_subnet = input("Enter Local Subnet: ").strip()    # Input local subnet
    local_mask = input("Enter Local Mask: ").strip()        # Input local subnet mask
    remote_subnet = input("Enter Remote Subnet: ").strip()  # Input remote subnet
    remote_mask = input("Enter Remote Mask: ").strip()      # Input remote subnet mask
    psk = input("Enter Pre-Shared Key: ").strip()           # Input pre-shared key

    print("\n[ASA] Applying VPN configuration...\n")        # Inform user that config is being applied

    cmds = [                                       # List of ASA CLI configuration commands
        f"access-list {acl_name} extended permit ip "  # Create crypto ACL entry
        f"{local_subnet} {local_mask} {remote_subnet} {remote_mask}",

        f"tunnel-group {peer_ip} type ipsec-l2l",        # Define tunnel-group type
        f"tunnel-group {peer_ip} ipsec-attributes",     # Enter IPsec attributes mode
        f"ikev1 pre-shared-key {psk}"                    # Configure IKEv1 pre-shared key
    ]

    conn.send_config_set(cmds)                     # Push configuration commands to ASA
    conn.save_config()                             # Save running config to startup config

    print("[ASA] VPN tunnel build completed successfully\n")  # Success message
