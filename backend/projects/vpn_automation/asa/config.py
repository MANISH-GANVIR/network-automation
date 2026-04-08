# =========================================
# CONFIGURATION (LEARNING / DRY RUN MODE)
# =========================================

# NOTE:
# This configuration is created for learning and testing purposes only.
# - DRY_RUN = True → No real firewall connection (simulation mode)
# - DRY_RUN = False → Connects to real firewall devices
# - All IPs and credentials below are dummy values
# - No real production data is exposed in this project

DRY_RUN = True  # Enable safe simulation mode


# =========================================
# CISCO ASA DEVICE CONFIGURATION
# =========================================

ASA_DEVICE = {
    "device_type": "cisco_asa",   # Netmiko device type for Cisco ASA
    "host": "1.1.1.1",            # Dummy firewall IP address
    "username": "admin",          # Dummy username
    "password": "admin",          # Dummy password
    "port": 22,                   # SSH port (default: 22)
    "fast_cli": False,            # Better stability for ASA commands
    "timeout": 10                 # Command execution timeout (seconds)
}


















'''
ssh -oKexAlgorithms=+diffie-hellman-group14-sha1 -oHostKeyAlgorithms=+ssh-rsa -oMACs=+hmac-sha1 admin@1.1.1.1                                
admin

The Cisco ASA device supports older SSH algorithms such as diffie-hellman-group14-sha1, ssh-rsa, and hmac-sha1. Modern OpenSSH clients disable these algorithms by default due to security concerns.
Therefore, we explicitly enabled those algorithms in the SSH command to successfully negotiate the connection.
'''