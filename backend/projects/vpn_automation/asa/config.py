DRY_RUN = True

ASA_DEVICE = {
    "device_type": "cisco_asa",
    "host": "1.1.1.1",
    "username": "admin",
    "password": "admin",
    "port": 22,
    "fast_cli": False,
    "timeout": 10
}
'''
ssh -oKexAlgorithms=+diffie-hellman-group14-sha1 -oHostKeyAlgorithms=+ssh-rsa -oMACs=+hmac-sha1 admin@1.1.1.1                                
admin

The Cisco ASA device supports older SSH algorithms such as diffie-hellman-group14-sha1, ssh-rsa, and hmac-sha1. Modern OpenSSH clients disable these algorithms by default due to security concerns.
Therefore, we explicitly enabled those algorithms in the SSH command to successfully negotiate the connection.
'''