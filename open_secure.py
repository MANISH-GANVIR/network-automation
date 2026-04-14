# ==============================
# PASSWORD PROTECTED FILE VIEWER
# ==============================

import os
import getpass

# 🔐 Set your password here
PASSWORD = "Manish@10"

# 📂 File name (change if needed)
FILE_NAME = "InterviewQ&A.txt"


def clear_screen():
    # Clear terminal screen
    os.system('cls' if os.name == 'nt' else 'clear')


def show_file():
    try:
        with open(FILE_NAME, "r", encoding="utf-8") as f:
            content = f.read()
            print("\n📄 FILE CONTENT:\n")
            print(content)
    except FileNotFoundError:
        print("❌ File not found!")
    except Exception as e:
        print(f"❌ Error: {e}")


def main():
    clear_screen()
    print("===================================")
    print(" 🔐 SECURE FILE ACCESS SYSTEM")
    print("===================================")

    # 🔑 Hidden password input
    user_input = getpass.getpass("Enter password: ")

    if user_input == PASSWORD:
        print("\n✅ Access Granted\n")
        show_file()
    else:
        print("\n❌ Wrong Password! Access Denied")


if __name__ == "__main__":
    main()