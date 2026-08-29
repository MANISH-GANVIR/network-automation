'''
 RESTCONF stands for REST Configuration Protocol.
 It is a REST-based network management protocol used
 to configure and retrieve network device data
 programmatically.
 RESTCONF uses YANG for data modeling and commonly
 uses JSON or XML for data representation.
 It works over HTTP or HTTPS and uses REST methods
 such as GET, POST, PUT, PATCH, and DELETE.”

 Summary:-
 NETCONF
 → YANG + XML + SSH : 830

 RESTCONF
 → YANG + JSON/XML + HTTP/HTTPS : 443

 ================================================
RESTCONF OPERATIONS
================================================

RESTCONF
→ REST-based network management protocol
→ Uses YANG for data modeling
→ Uses JSON or XML for data representation
→ Works over HTTP/HTTPS


1. GET
-------
Purpose:
Retrieve data/configuration from the network device.

Python Example:

response = requests.get(
    url,
    auth=(device["username"], device["password"]),
    verify=False
)

print(response.json())


2. POST
--------
Purpose:
Create a new resource or perform an operation.

Python Example:

response = requests.post(
    url,
    json=data,
    auth=(device["username"], device["password"]),
    verify=False
)


3. PUT
-------
Purpose:
Create or completely replace a resource.

Python Example:

response = requests.put(
    url,
    json=data,
    auth=(device["username"], device["password"]),
    verify=False
)


4. PATCH
---------
Purpose:
Modify or partially update an existing resource.

Python Example:

response = requests.patch(
    url,
    json=data,
    auth=(device["username"], device["password"]),
    verify=False
)


5. DELETE
----------
Purpose:
Delete a resource/configuration.

Python Example:

response = requests.delete(
    url,
    auth=(device["username"], device["password"]),
    verify=False
)


================================================
QUICK MEMORY
================================================

GET
→ Read / Retrieve data

POST
→ Create / Perform operation

PUT
→ Replace entire resource

PATCH
→ Partially modify resource

DELETE
→ Delete resource


================================================
RESTCONF FLOW
================================================

Python
  ↓
requests
  ↓
HTTP / HTTPS
  ↓
RESTCONF API
  ↓
YANG Model
  ↓
JSON / XML
  ↓
Network Device


================================================
COMMON RESTCONF PORT
================================================

HTTPS → TCP 443


================================================
IMPORTANT HEADERS
================================================

Accept
→ Tells server what response format we want.

Example:

headers = {
    "Accept": "application/yang-data+json"
}


Content-Type
→ Tells server the format of data we are sending.

Example:

headers = {
    "Content-Type": "application/yang-data+json"
}


QUICK MEMORY:

Accept
→ What do I want BACK?

Content-Type
→ What am I SENDING?


================================================
RESTCONF URL STRUCTURE
================================================

https://<device-ip>/restconf/data/<YANG-resource>


Example:

url = "https://192.168.10.100/restconf/data/<YANG-resource>"


================================================
RESTCONF vs NETCONF
================================================

NETCONF
→ YANG + XML
→ SSH
→ TCP 830
→ ncclient
→ get_config()
→ edit_config()


RESTCONF
→ YANG + JSON/XML
→ HTTP/HTTPS
→ HTTPS commonly TCP 443
→ requests
→ GET / POST / PUT / PATCH / DELETE


================================================
QUICK MEMORY
================================================

NETCONF
→ Python → ncclient → SSH:830 → YANG → XML

RESTCONF
→ Python → requests → HTTPS:443 → YANG → JSON/XML

'''

import requests
def main():
    try:
        # Device connection details
        device = {
            "host": "192.168.10.100",
            "port": 443,
            "username": "admin",
            "password": "admin"
        }

        # ASA REST API CLI endpoint
        url = f"https://{device['host']}:{device['port']}/api/cli"

        # CLI commands that we want to execute on the ASA
        command = {
            "commands": [
                "show version",
                "show running-config",
                "show interface"
            ]
        }

        # Send the CLI commands to the ASA using HTTP POST
        response = requests.post(
            url,
            json=command,
            auth=(device["username"], device["password"]),
        )

        # Display the JSON response returned by the ASA
        print(response.json())

    except Exception as e:
        # Handle any connection, authentication, or API errors
        print("Main Error!\n", e)


# Start the main function
if __name__ == "__main__":
    main()