ENTERPRISE VPN AUTOMATION PLATFORM (LEARNING PROJECT)

This is a learning-based multi-vendor VPN automation platform built using Python to understand and automate the lifecycle of IPsec VPN tunnels across Cisco ASA and Palo Alto firewalls.

--------------------------------------------------

PROJECT PURPOSE

This project was developed as a hands-on learning initiative to:

- Understand real-world VPN operations
- Automate repetitive network tasks
- Reduce manual configuration errors
- Explore multi-vendor firewall automation

--------------------------------------------------

WHAT I LEARNED

- Network automation using Python
- SSH-based device communication (CLI automation)
- VPN lifecycle operations (Build, Update, Reset, Troubleshoot)
- Modular project design for scalability
- Basics of frontend-backend integration

--------------------------------------------------

SUPPORTED FIREWALL VENDORS

1. Cisco ASA
   - CLI-based VPN automation
   - Menu-driven workflows
   - Real-world VPN operations simulation

2. Palo Alto Networks
   - Designed for API and CLI automation
   - Modular architecture for scalability

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
|   |       |-- paloalto
|   |
|   |-- utils
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

FEATURES IMPLEMENTED

- VPN Tunnel Reset
- VPN Configuration Update
- VPN Tunnel Build
- VPN Troubleshooting
- Menu-driven CLI interface

--------------------------------------------------

CONNECTIVITY

- SSH-based firewall connection
- Enable-mode validation
- Command execution automation

--------------------------------------------------

FRONTEND (LEARNING UI)

- Basic login page
- Dashboard UI (static)
- Designed for future API integration

--------------------------------------------------

TECHNOLOGY STACK

Backend: Python 3
Automation: CLI (Cisco ASA), API-ready (Palo Alto)
Frontend: HTML, CSS, JavaScript
Version Control: Git, GitHub

--------------------------------------------------

KEY HIGHLIGHTS

- Learning-focused automation project
- Multi-vendor design approach
- Modular and extensible architecture
- Real-world enterprise use case simulation

--------------------------------------------------

FUTURE IMPROVEMENTS

- Web-based automation portal
- REST API integration
- Role-Based Access Control (RBAC)
- Logging and monitoring
- Support for additional vendors

--------------------------------------------------

AUTHOR

Manish Ganvir

--------------------------------------------------

LICENSE

This project is created for learning and educational purposes only.