# -----------------------------------------------------------------------------
# Purpose of this module (run_asa.py)
# -----------------------------------------------------------------------------
# This file is a launcher script for the ASA VPN Automation CLI.
# It does the following:
# 1) Prints a welcome banner for the user.
# 2) Finds the project root directory (BASE_DIR) relative to this file location.
# 3) Changes the current working directory to the project root using os.chdir(BASE_DIR)
#    so all imports and relative paths work correctly.
# 4) Executes the main ASA VPN automation module using the same Python interpreter:
#       python -m backend.projects.vpn_automation.asa.main
# 5) Exits cleanly after the main program finishes.
# -----------------------------------------------------------------------------

import subprocess  # Used to run another program/command (here: run the main module)
import sys         # Gives access to the current Python interpreter path (sys.executable) and exit()
import os          # Used for path handling and changing the working directory

# =============================================================================
# Friendly Welcome Banner (CLI startup message)
# =============================================================================
print("\n" + "*" * 75)
print("        \t\t\t\t WELCOME TO VPN AUTOMATION 🙂")
print("      \t\t\t\t  (Make Your VPN Operations Easy!)")
print("*" * 75 + "\n")

# =============================================================================
# Step 1: Find and switch to the Project Root Directory
# -----------------------------------------------------------------------------
# Goal:
# - Ensure the script always runs from the project root folder.
# - This makes relative imports, file paths, and module execution predictable.
#
# How it works:
# - __file__ = the path of this current script file.
# - os.path.dirname(__file__) = folder where this script exists.
# - "../../../../" = go up 4 folders from this script folder (adjust if structure changes).
# - os.path.join(...) = combine base folder + relative up-level path safely.
# - os.path.abspath(...) = convert that result to a clean absolute path.
# An absolute path is the complete, fixed location of a file or folder
# starting from the root of the system (drive root on Windows or / on Linux/macOS).
# It does not depend on the current working directory, so it always points to the same place.
#
# Examples:Windows: C:\Users\manish.ganvir\PycharmProjects\Automation
#     Linux/macOS: /home/manish/Automation

# =============================================================================
BASE_DIR = os.path.abspath(         # Convert the path to an absolute, cleaned path
    os.path.join(                   # Join path parts safely (Windows/Linux compatible)
        os.path.dirname(__file__),  # Start from the folder containing this script
        "../../../../"              # Move up 4 directory levels to reach project root
    )
)

# Change current working directory to the project root
# Benefit: running modules/resources becomes stable regardless of where user starts the script from
os.chdir(BASE_DIR)
# Syntax: os.chdir(path) → changes the current working directory
# to 'path' (here: project root BASE_DIR)
# os.chdir(BASE_DIR) Sets the program’s current working directory to BASE_DIR.
# All relative paths (like ./assets, ./logs, module runs, file reads)
# work correctly no matter where you run the script from.

# =============================================================================
# Step 2: Build the command to run the "real" VPN Automation program
# -----------------------------------------------------------------------------
# sys.executable:
# - Absolute path of the Python interpreter currently running this file.
# - Ensures the same Python environment/venv is used to run the main module.
#
# "-m":
# - Runs a Python module using its dotted path (package.module).
#
# "backend.projects.vpn_automation.asa.main":
# - The main entry module for the ASA VPN automation CLI.
# =============================================================================
cmd = [
    sys.executable,   # Current Python interpreter (keeps venv consistent)
    "-m",              # Run the target as a Python module
    "backend.projects.vpn_automation.asa.main" # Dotted module path to the main CLI program
]

# =============================================================================
# Step 3: Execute the main VPN Automation CLI module
# -----------------------------------------------------------------------------
# subprocess.run(cmd):
# - Starts the main program (menu-based CLI).
# - Blocks (waits) until the main program finishes.
# =============================================================================
subprocess.run(cmd)

# =============================================================================
# Step 4: Exit this launcher script cleanly
# -----------------------------------------------------------------------------
# sys.exit(0):
# - Ends the current script with success status code 0.
# =============================================================================
sys.exit(0)