'''
NETCONF stands for Network Configuration Protocol.
It is a model-driven network management protocol
used to programmatically configure, retrieve, modify,
and delete network device configuration.
NETCONF uses YANG for data modeling,
XML for data representation, and commonly runs over SSH
on TCP port 830. In Python, I can use the ncclient
library to establish a NETCONF session and retrieve
the running configuration.

“YANG stands for Yet Another Next Generation.
 It is a data modeling language used to define
 the structure of network configuration and
 operational data.”

  Summary:-
 NETCONF
 → YANG + XML + SSH : 830

 RESTCONF
 → YANG + JSON/XML + HTTP/HTTPS : 443

NETCONF OPERATIONS - PYTHON NCCLIENT EXAMPLES
================================================

1. GET
------
Purpose:
Retrieve operational/state information from the network device.

Python Example:
output = conn.get()
print(output.xml)


2. GET-CONFIG
-------------
Purpose:
Retrieve configuration from a datastore.

Python Example:
output = conn.get_config(
    source="running"
)
print(output.xml)


3. EDIT-CONFIG
--------------
Purpose:
Create, modify, or delete configuration.

Python Example:
output = conn.edit_config(
    target="running",
    config=xml_config
)
print(output)


4. COPY-CONFIG
--------------
Purpose:
Copy configuration from one datastore to another.

Python Example:
output = conn.copy_config(
    source="running",
    target="startup"
)
print(output)


5. DELETE-CONFIG
----------------
Purpose:
Delete a configuration datastore, where supported.

Python Example:
output = conn.delete_config(
    target="startup"
)
print(output)


6. LOCK
-------
Purpose:
Lock a datastore so other NETCONF sessions cannot modify it.

Python Example:
output = conn.lock(
    target="running"
)
print(output)


7. UNLOCK
---------
Purpose:
Release the lock on a datastore.

Python Example:
output = conn.unlock(
    target="running"
)
print(output)


8. COMMIT
---------
Purpose:
Apply candidate configuration changes to the running configuration.

Python Example:
output = conn.commit()
print(output)


9. CLOSE-SESSION
----------------
Purpose:
Gracefully terminate the NETCONF session.

Python Example:
conn.close_session()


================================================
QUICK MEMORY
================================================

GET
→ conn.get()

GET-CONFIG
→ conn.get_config(source="running")

EDIT-CONFIG
→ conn.edit_config(target="running", config=xml_config)

COPY-CONFIG
→ conn.copy_config(source="running", target="startup")

DELETE-CONFIG
→ conn.delete_config(target="startup")

LOCK
→ conn.lock(target="running")

UNLOCK
→ conn.unlock(target="running")

COMMIT
→ conn.commit()

CLOSE-SESSION
→ conn.close_session()


================================================
COMMON CONFIGURATION FLOW
================================================

LOCK
  ↓
EDIT-CONFIG
  ↓
COMMIT
  ↓
UNLOCK
  ↓
CLOSE-SESSION


IMPORTANT:
- GET is used for operational/state data.
- GET-CONFIG is used for configuration data.
- EDIT-CONFIG is used to modify configuration.
- COMMIT is mainly used when the device supports
  the candidate datastore and commit capability.
- Exact operations supported can depend on the
  NETCONF capabilities of the network device.
'''

# Import the NETCONF manager from the ncclient library
# manager.connect() is used to establish a NETCONF session
from ncclient import manager


def main():
    try:
        # NETCONF device connection details
        device = {
            "host": "192.168.10.100",
            "port": 830,                  # NETCONF default port
            "username": "admin",
            "password": "admin",
            #"hostkey_verify": False       # Disable SSH host-key verification for lab/testing
        }

        # Establish a NETCONF session with the network device
        conn = manager.connect(**device)

        # Retrieve the running configuration from the device
        output = conn.get_config(
            source="running"  #running   → Active configuration
                              #startup   → Saved configuration
                              #candidate  → Pending configuration

        )

        # Print the NETCONF XML response
        print(output.xml)

        # Close the NETCONF session
        conn.close()

    except Exception as e:
        # Handle connection, authentication, or NETCONF errors
        print("Main Error!\n", e)


# Execute main() when this Python file is run directly
if __name__ == "__main__":
    main()