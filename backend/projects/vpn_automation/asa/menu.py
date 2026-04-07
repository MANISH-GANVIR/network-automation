def show_menu():                                   # Function to display VPN automation menu
    print("\n========== === ✅ SELECT VPN OPERATION FROM MENU ✅ === ==========\n")
                                                   # Print menu header

    print("1) Reset VPN Tunnel")                   # Option 1: Reset existing VPN tunnel
    print("2) Update VPN tunnel details")          # Option 2: Update VPN configuration
    print("3) Build VPN tunnel")                   # Option 3: Build new VPN tunnel
    print("4) Troubleshoot VPN issues")            # Option 4: Troubleshoot VPN problems
    print("5) Exit")                               # Option 5: Exit application

    return input("Select an option (1-5): ").strip()
                                                   # Take user input and remove extra spaces
