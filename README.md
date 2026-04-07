ENTERPRISE VPN AUTOMATION PLATFORM

This is a multi-vendor VPN automation platform built in Python to manage the full lifecycle of IPsec VPN tunnels across Cisco ASA and Palo Alto firewalls.

--------------------------------------------------

PROJECT OVERVIEW

This project is designed to automate operational VPN tasks for enterprise network environments.
It helps network and cloud teams reduce manual effort and human errors while managing VPN tunnels.

The platform supports guided workflows for VPN reset, update, build, and troubleshooting operations.
It is modular, extensible, and ready for future web portal and API-based orchestration.

--------------------------------------------------

SUPPORTED FIREWALL VENDORS

1. Cisco ASA
   - CLI-based VPN automation
   - Menu-driven operational workflows
   - Production-tested VPN lifecycle operations

2. Palo Alto Networks
   - Architecture designed for API and CLI automation
   - IPsec VPN lifecycle automation support
   - Vendor-specific modular implementation

--------------------------------------------------

PROJECT STRUCTURE

Automation
|
|-- backend
|   |
|   |-- projects
|   |   |
|   |   |-- vpn_automation
|   |       |
|   |       |-- asa
|   |       |   |
|   |       |   |-- run_asa.py        (CLI entry point)
|   |       |   |-- menu.py           (Menu handling)
|   |       |   |-- client.py         (Firewall connectivity)
|   |       |   |-- discovery.py      (VPN discovery)
|   |       |   |-- reset.py          (VPN reset workflow)
|   |       |   |-- update.py         (VPN update workflow)
|   |       |   |-- build.py          (VPN build workflow)
|   |       |   |-- troubleshoot.py   (VPN troubleshooting)
|   |       |   |-- config.py
|   |       |   |-- web_wrapper.py    (Web/API extension layer)
|   |       |
|   |       |-- paloalto
|   |           |
|   |           |-- Palo Alto VPN automation modules
|   |
|   |-- utils
|       |
|       |-- spinner.py
|
|-- frontend
|   |
|   |-- login.html
|   |-- dashboard.html
|   |-- app.js
|   |-- style.css
|
|-- flow.txt
|-- .gitignore
|-- README.txt

--------------------------------------------------

HOW TO RUN (CISCO ASA - CLI MODE)

Run the following command from the project root:

python backend/projects/vpn_automation/asa/run_asa.py

--------------------------------------------------

VPN AUTOMATION MENU (CISCO ASA)

Once the script is executed, the following menu is displayed:

1) Reset VPN Tunnel
2) Update VPN tunnel details
3) Build VPN tunnel
4) Troubleshoot VPN issues
5) Exit

--------------------------------------------------

MENU OPERATIONS DETAILS

1) Reset VPN Tunnel
- Displays available VPN tunnels
- Allows selection using crypto-map sequence
- Clears IKE and IPsec security associations

Example commands executed:
clear crypto ikev1 sa
clear crypto ipsec sa peer <peer-ip>

--------------------------------------------------

2) Update VPN Tunnel Details
- Updates existing VPN tunnel configurations
- Supports peer IP, subnet, and policy changes
- Ensures controlled configuration updates

--------------------------------------------------

3) Build VPN Tunnel
- Builds new VPN tunnels using predefined templates
- Configures crypto-maps, ACLs, transform-sets, and tunnel-groups
- Eliminates manual configuration errors

--------------------------------------------------

4) Troubleshoot VPN Issues
- Checks tunnel status
- Verifies IKE and IPsec SAs
- Identifies common VPN issues
- Provides guided troubleshooting output

--------------------------------------------------

AUTHENTICATION AND CONNECTIVITY

- Secure SSH-based connectivity to firewalls
- Enable-mode access verification
- Centralized command execution
- Designed for audit logging and RBAC integration

--------------------------------------------------

WEB PORTAL (FUTURE SCOPE)

The project includes a frontend UI and web wrapper layer for:
- User authentication
- Project selection
- Firewall vendor selection (ASA / Palo Alto)
- Workflow-driven VPN operations

--------------------------------------------------

TECHNOLOGY STACK

Backend: Python 3
Automation: Cisco ASA CLI, Palo Alto APIs / CLI
Frontend: HTML, CSS, JavaScript
Version Control: Git and GitHub
IDE: PyCharm

--------------------------------------------------

KEY HIGHLIGHTS

- Multi-vendor VPN automation (Cisco ASA and Palo Alto)
- Menu-driven guided CLI workflows
- Modular and extensible architecture
- Enterprise-ready automation design
- Reduces manual VPN operational effort
- Designed for scalability and governance

--------------------------------------------------

FUTURE ENHANCEMENTS

- Web-based VPN automation portal
- Role-Based Access Control (RBAC)
- REST API orchestration
- Database-backed user and project management
- Centralized audit logging
- Support for additional firewall vendors

--------------------------------------------------

AUTHOR

Manish Ganvir
Senior IT Developer – Cloud and Network Automation
GitHub: https://github.com/manish-epicor

--------------------------------------------------

LICENSE

MIT License
