# /asa/update.py                                  # File path: ASA VPN update module
"""
                                                  # Module docstring (can describe update workflow)
"""

from backend.utils.spinner import square_spinner   # Import spinner utility for CLI progress display


# ================================
# OPTIONAL INPUT HELPERS
# ================================

def optional_input(prompt):                        # Helper function for optional normal input
    value = input(f"{prompt} (or hit ENTER to skip): ").strip()
                                                   # Ask user for input, allow skipping
    return value if value else None                # Return value or None if skipped


def optional_secret_input(prompt):                 # Helper function for optional secret-like input
    print("\n" + "=" * 60)                          # Print separator line
    print(prompt)                                  # Display prompt message
    print("👉 Press ENTER to skip (no change)")     # Instruction to skip
    print("⚠️ Input will be visible while typing") # Warning about visible input
    print("=" * 60)                                # Print separator line
    value = input(">> ").strip()                   # Take user input
    return value if value else None                # Return value or None if skipped


# ================================
# OPTION 2 – UPDATE VPN (ENTERPRISE SAFE)
# ================================

def update_vpn(conn):                              # Main function to update ASA VPN configuration

    peer_ip = input("Enter VPN Peer IP (or n to cancel): ").strip()
                                                   # Ask for VPN peer IP address

    if peer_ip.lower() == "n":                     # Check if user cancels update
        print("[ASA] VPN update cancelled by user\n")
                                                   # Inform user about cancellation
        return                                    # Exit update function

    if not peer_ip:                                # Validate peer IP input
        print("[ASA] Peer IP not provided. Update aborted.\n")
                                                   # Abort update due to missing peer IP
        return

    acl_name = optional_input("Enter Encryption Domain ACL name")
                                                   # Optional input for ACL name


    # ==================================================
    # PRE-UPDATE CAPTURE
    # ==================================================
    print("\n[ASA] Capturing PRE-UPDATE state\n")
                                                   # Inform user about pre-change capture
    print(f"show run tunnel-group {peer_ip}")
    pre_tg = conn.send_command(
        f"show run tunnel-group {peer_ip}"
    )                                              # Capture existing tunnel-group configuration

    pre_acl = (
        conn.send_command(f"show run access-list {acl_name}")
        if acl_name else "ACL NOT PROVIDED – SKIPPED"
    )                                              # Capture existing ACL config if provided


    # ==================================================
    # PSK UPDATE (OPTIONAL)
    # ==================================================
    new_psk = optional_secret_input(
        "[INPUT REQUIRED] Enter NEW PSK"
    )                                              # Optional PSK update input

    if new_psk:                                    # If new PSK is provided
        square_spinner("[ASA] Updating PSK", 2)    # Show spinner while updating PSK

        conn.send_config_set([                     # Push PSK update configuration
            f"tunnel-group {peer_ip} ipsec-attributes",
            f"ikev1 pre-shared-key {new_psk}"
        ])
        conn.save_config()                         # Save configuration to startup-config

        print("[ASA] PSK updated successfully\n")  # Confirm PSK update
    else:
        print("[ASA] PSK unchanged\n")             # Inform PSK was not changed


    # ==================================================
    # ACL UPDATE (OPTIONAL)
    # ==================================================
    if acl_name:                                   # Proceed only if ACL name was provided

        local_subnet = optional_input("Enter Local Subnet IP")
                                                   # Optional local subnet input
        local_mask = optional_input("Enter Local Subnet Mask")
                                                   # Optional local subnet mask
        remote_subnet = optional_input("Enter Remote Subnet IP")
                                                   # Optional remote subnet input
        remote_mask = optional_input("Enter Remote Subnet Mask")
                                                   # Optional remote subnet mask

        if all([local_subnet, local_mask, remote_subnet, remote_mask]):
                                                   # Ensure all ACL parameters are provided
            square_spinner(
                "[ASA] Updating Encryption Domain ACL",
                2
            )                                      # Show spinner while updating ACL

            conn.send_config_set([                 # Push ACL update commands
                f"no access-list {acl_name}",
                f"access-list {acl_name} extended permit ip "
                f"{local_subnet} {local_mask} {remote_subnet} {remote_mask}"
            ])
            conn.save_config()                     # Save updated configuration

            print("[ASA] ACL updated successfully\n")
                                                   # Confirm ACL update
        else:
            print("[ASA] ACL unchanged (incomplete input)\n")
                                                   # Skip ACL update due to incomplete data
    else:
        print("[ASA] ACL update skipped\n")        # ACL update skipped entirely


    # ==================================================
    # POST-UPDATE CAPTURE
    # ==================================================
    print("[ASA] Capturing POST-UPDATE state\n")
                                                   # Inform user about post-change capture
    print(f"show run tunnel-group {peer_ip}")
    post_tg = conn.send_command(
        f"show run tunnel-group {peer_ip}"
    )                                              # Capture tunnel-group after update

    post_acl = (
        conn.send_command(f"show run access-list {acl_name}")
        if acl_name else "ACL NOT UPDATED"
    )                                              # Capture ACL after update if applicable


    # ==================================================
    # CHANGE SUMMARY
    # ==================================================
    print("\n================ CHANGE SUMMARY ================\n")
                                                   # Print summary header

    print("----- TUNNEL GROUP BEFORE -----")         # Pre-change tunnel-group header
    print(pre_tg)                                  # Display pre-change tunnel-group

    print("----- TUNNEL GROUP AFTER ------")         # Post-change tunnel-group header
    print(post_tg)                                 # Display post-change tunnel-group

    print("\n----- ENCRYPTION DOMAIN ACL BEFORE -----")
                                                   # Pre-change ACL header
    print(pre_acl)                                 # Display pre-change ACL

    print("----- ENCRYPTION DOMAIN ACL AFTER ------")
                                                   # Post-change ACL header
    print(post_acl)                                # Display post-change ACL

    print("\n================================================\n")
                                                   # End of summary
