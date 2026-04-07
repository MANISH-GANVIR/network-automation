from netmiko import ConnectHandler
import re
import time
from tabulate import tabulate  # pip install tabulate

# ASA Connection Details
ASA_DEVICE = {
    "device_type": "cisco_asa",
    "host": "10.63.66.10",
    "username": "asaadmin",
    "password": "AsA#Net@4519!",
    "port": 22,
    "fast_cli": False,
    "timeout": 10
}


def extract_version(version_output):
    """Extract ASA version from show version output"""
    match = re.search(r"Version\s+(\d+\.\d+)", version_output)
    return match.group(1) if match else "Unknown"


def check_strong_encryption_license(conn):
    """Check if strong encryption (3DES-AES) is enabled"""
    output = conn.send_command("show version | include Encryption")
    return "3DES-AES : Enabled" in output or "Encryption-3DES-AES : Enabled" in output


def get_phase1_encryption_algos(conn):
    """Discover Phase 1 (IKEv1) encryption algorithms"""
    try:
        conn.send_command("configure terminal", expect_string=r"#")

        output = conn.send_command(
            "crypto ikev1 policy 999",
            expect_string=r"#",
            delay_factor=2
        )

        output = conn.send_command(
            "encryption ?",
            expect_string=r"#",
            delay_factor=2
        )

        encryption_algos = []
        for line in output.splitlines():
            if any(algo in line.lower() for algo in ["aes", "3des", "des"]):
                parts = line.split()
                if parts:
                    algo = parts[0]
                    description = " ".join(parts[1:]) if len(parts) > 1 else ""
                    encryption_algos.append({
                        "algorithm": algo,
                        "description": description
                    })

        conn.send_command("exit", expect_string=r"#")
        conn.send_command("no crypto ikev1 policy 999", expect_string=r"#")
        conn.send_command("exit", expect_string=r"#")

        return encryption_algos

    except Exception as e:
        print(f"[ERROR] Failed to get Phase 1 encryption algorithms: {e}")
        return []


def get_phase1_hash_algos(conn):
    """Discover Phase 1 (IKEv1) hash algorithms"""
    try:
        conn.send_command("configure terminal", expect_string=r"#")

        output = conn.send_command(
            "crypto ikev1 policy 999",
            expect_string=r"#",
            delay_factor=2
        )

        output = conn.send_command(
            "hash ?",
            expect_string=r"#",
            delay_factor=2
        )

        hash_algos = []
        for line in output.splitlines():
            if any(algo in line.lower() for algo in ["sha", "md5"]):
                parts = line.split()
                if parts:
                    algo = parts[0]
                    description = " ".join(parts[1:]) if len(parts) > 1 else ""
                    hash_algos.append({
                        "algorithm": algo,
                        "description": description
                    })

        conn.send_command("exit", expect_string=r"#")
        conn.send_command("no crypto ikev1 policy 999", expect_string=r"#")
        conn.send_command("exit", expect_string=r"#")

        return hash_algos

    except Exception as e:
        print(f"[ERROR] Failed to get Phase 1 hash algorithms: {e}")
        return []


def get_phase1_dh_groups(conn):
    """Discover Phase 1 (IKEv1) DH groups"""
    try:
        conn.send_command("configure terminal", expect_string=r"#")

        output = conn.send_command(
            "crypto ikev1 policy 999",
            expect_string=r"#",
            delay_factor=2
        )

        output = conn.send_command(
            "group ?",
            expect_string=r"#",
            delay_factor=2
        )

        dh_groups = []
        for line in output.splitlines():
            if "group" in line.lower() or re.match(r"^\s*\d+", line):
                parts = line.split()
                if parts and parts[0].isdigit():
                    group = parts[0]
                    description = " ".join(parts[1:]) if len(parts) > 1 else ""
                    dh_groups.append({
                        "algorithm": f"group {group}",
                        "description": description
                    })

        conn.send_command("exit", expect_string=r"#")
        conn.send_command("no crypto ikev1 policy 999", expect_string=r"#")
        conn.send_command("exit", expect_string=r"#")

        return dh_groups

    except Exception as e:
        print(f"[ERROR] Failed to get Phase 1 DH groups: {e}")
        return []


def get_supported_encryption_algos(conn):
    """Discover Phase 2 (IPsec) encryption algorithms"""
    try:
        conn.send_command("configure terminal", expect_string=r"#")

        output = conn.send_command(
            "crypto ipsec ikev1 transform-set TEMP_TEST ?",
            expect_string=r"#",
            delay_factor=2
        )

        encryption_algos = []
        for line in output.splitlines():
            if line.strip().startswith("esp-"):
                parts = line.split()
                if parts:
                    algo = parts[0]
                    description = " ".join(parts[1:]) if len(parts) > 1 else ""
                    encryption_algos.append({
                        "algorithm": algo,
                        "description": description
                    })

        conn.send_command("exit", expect_string=r"#")
        return encryption_algos

    except Exception as e:
        print(f"[ERROR] Failed to get Phase 2 encryption algorithms: {e}")
        return []


def get_supported_integrity_algos(conn):
    """Discover Phase 2 (IPsec) integrity algorithms"""
    try:
        conn.send_command("configure terminal", expect_string=r"#")

        output = conn.send_command(
            "crypto ipsec ikev1 transform-set TEMP_TEST esp-aes ?",
            expect_string=r"#",
            delay_factor=2
        )

        integrity_algos = []
        for line in output.splitlines():
            if "hmac" in line.lower() and line.strip().startswith("esp-"):
                parts = line.split()
                if parts:
                    algo = parts[0]
                    description = " ".join(parts[1:]) if len(parts) > 1 else ""
                    integrity_algos.append({
                        "algorithm": algo,
                        "description": description
                    })

        conn.send_command("exit", expect_string=r"#")
        return integrity_algos

    except Exception as e:
        print(f"[ERROR] Failed to get Phase 2 integrity algorithms: {e}")
        return []


def test_transform_set(conn, name, encryption, integrity=None):
    """Test if a transform-set configuration is accepted"""
    try:
        conn.send_command("configure terminal", expect_string=r"#")

        if integrity:
            cmd = f"crypto ipsec ikev1 transform-set {name} {encryption} {integrity}"
        else:
            cmd = f"crypto ipsec ikev1 transform-set {name} {encryption}"

        output = conn.send_command(cmd, expect_string=r"#")

        if any(keyword in output for keyword in ["Invalid", "ERROR", "% ", "incomplete"]):
            conn.send_command("exit", expect_string=r"#")
            return False, output.strip()

        conn.send_command(f"no crypto ipsec ikev1 transform-set {name}", expect_string=r"#")
        conn.send_command("exit", expect_string=r"#")

        return True, "Configuration accepted"

    except Exception as e:
        try:
            conn.send_command("exit", expect_string=r"#")
        except:
            pass
        return False, str(e)


def print_summary_table(phase1_data, phase2_data):
    """Print final summary table with Phase 1 and Phase 2 algorithms"""

    print("\n" + "=" * 100)
    print("📊 DEVICE SUPPORTED TRANSFORM-SETS - COMPLETE SUMMARY")
    print("=" * 100 + "\n")

    # Phase 1 Table
    print("🔐 PHASE 1 (IKEv1 POLICY) - Supported Algorithms:\n")

    phase1_table = []

    # Encryption
    if phase1_data.get("encryption"):
        for algo in phase1_data["encryption"]:
            phase1_table.append([
                "Encryption",
                algo["algorithm"],
                algo["description"]
            ])

    # Hash
    if phase1_data.get("hash"):
        for algo in phase1_data["hash"]:
            phase1_table.append([
                "Hash",
                algo["algorithm"],
                algo["description"]
            ])

    # DH Group
    if phase1_data.get("dh_group"):
        for algo in phase1_data["dh_group"]:
            phase1_table.append([
                "DH Group",
                algo["algorithm"],
                algo["description"]
            ])

    print(tabulate(
        phase1_table,
        headers=["Parameter", "Algorithm", "Description"],
        tablefmt="grid",
        maxcolwidths=[15, 20, 50]
    ))

    print("\n" + "-" * 100 + "\n")

    # Phase 2 Table
    print("🔐 PHASE 2 (IPsec TRANSFORM-SET) - Supported Algorithms:\n")

    phase2_table = []

    # Encryption
    if phase2_data.get("encryption"):
        for algo in phase2_data["encryption"]:
            phase2_table.append([
                "Encryption",
                algo["algorithm"],
                algo["description"]
            ])

    # Integrity
    if phase2_data.get("integrity"):
        for algo in phase2_data["integrity"]:
            phase2_table.append([
                "Integrity",
                algo["algorithm"],
                algo["description"]
            ])

    print(tabulate(
        phase2_table,
        headers=["Parameter", "Algorithm", "Description"],
        tablefmt="grid",
        maxcolwidths=[15, 20, 50]
    ))

    print("\n" + "=" * 100)

    # Recommended Combinations Table
    print("\n📋 RECOMMENDED VPN CONFIGURATIONS:\n")

    recommendations = [
        ["STRONG\n(Recommended)",
         "aes-256\nsha\ngroup 14",
         "esp-aes-256\nesp-sha256-hmac",
         "High security,\ngood performance"],

        ["MODERN\n(Best Performance)",
         "aes-256\nsha256\ngroup 20",
         "esp-aes-gcm-256\n(built-in integrity)",
         "Fastest,\nlatest standard"],

        ["STANDARD\n(Compatible)",
         "aes\nsha\ngroup 5",
         "esp-aes\nesp-sha-hmac",
         "Legacy device\ncompatibility"],
    ]

    print(tabulate(
        recommendations,
        headers=["Profile", "Phase 1\n(IKEv1 Policy)", "Phase 2\n(Transform-Set)", "Notes"],
        tablefmt="fancy_grid",
        maxcolwidths=[15, 25, 30, 25]
    ))

    print("\n" + "=" * 100 + "\n")


def validate_asa_crypto_capabilities():
    """Main function to validate ASA crypto capabilities"""
    print("\n" + "=" * 70)
    print("🔐 ASA IPsec Transform-Set Validation Tool")
    print("=" * 70 + "\n")

    print(f"📡 Connecting to ASA at {ASA_DEVICE['host']}...")

    try:
        conn = ConnectHandler(**ASA_DEVICE)
        print("✅ Connected successfully\n")

        # Get version
        print("📋 Gathering device information...")
        version_output = conn.send_command("show version")
        version = extract_version(version_output)

        model_match = re.search(r"(ASA\d+\S*|ASAv)", version_output)
        model = model_match.group(1) if model_match else "Unknown"

        has_strong_encryption = check_strong_encryption_license(conn)

        print(f"\n📊 Device Details:")
        print(f"  Model   : {model}")
        print(f"  Version : {version}")
        print(f"  Strong Encryption License : {'✅ Enabled' if has_strong_encryption else '❌ Disabled'}")
        print()

        # Phase 1 Discovery
        print("🔍 Discovering Phase 1 (IKEv1) capabilities...")

        phase1_encryption = get_phase1_encryption_algos(conn)
        print(f"  ✅ Found {len(phase1_encryption)} encryption algorithms")

        phase1_hash = get_phase1_hash_algos(conn)
        print(f"  ✅ Found {len(phase1_hash)} hash algorithms")

        phase1_dh = get_phase1_dh_groups(conn)
        print(f"  ✅ Found {len(phase1_dh)} DH groups")

        print("\n" + "-" * 70)

        # Phase 2 Discovery
        print("\n🔍 Discovering Phase 2 (IPsec) capabilities...")

        phase2_encryption = get_supported_encryption_algos(conn)
        print(f"  ✅ Found {len(phase2_encryption)} encryption algorithms")

        phase2_integrity = get_supported_integrity_algos(conn)
        print(f"  ✅ Found {len(phase2_integrity)} integrity algorithms")

        # Store results
        phase1_data = {
            "encryption": phase1_encryption,
            "hash": phase1_hash,
            "dh_group": phase1_dh
        }

        phase2_data = {
            "encryption": phase2_encryption,
            "integrity": phase2_integrity
        }

        # Print final summary table
        print_summary_table(phase1_data, phase2_data)

        # Close connection
        conn.disconnect()
        print("🔌 Disconnected from ASA\n")

        return {
            "model": model,
            "version": version,
            "strong_encryption": has_strong_encryption,
            "phase1": phase1_data,
            "phase2": phase2_data
        }

    except Exception as e:
        print(f"\n❌ ERROR: {e}\n")
        import traceback
        traceback.print_exc()
        return None


if __name__ == "__main__":
    results = validate_asa_crypto_capabilities()

    if results:
        print("=" * 70)
        print("✅ Validation completed successfully")
        print("=" * 70)