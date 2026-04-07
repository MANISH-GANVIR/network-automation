"""
Production-style Policy-Based VPN Automation (PAN-OS) using pan-os-python (v1.12.3)
==================================================================================

What you get (single file, but module-wise sections with comments):
- Excel multi-sheet parsing (one VPN per sheet)
- Epicor form-style parsing (label in col A, Epicor value col C, Customer value col E)
- Runtime mode selection:
    1) Lab Firewall (direct)
    2) Panorama DeviceGroup (central)
- Object creation:
    - IKE Gateway creation
    - IPsec Tunnel creation
    - Proxy-IDs creation (cartesian product for multiple local/remote subnets)
      NOTE: pan-os-python in your environment provides IpsecTunnelIpv4ProxyId
    - AddressObjects creation (1 per subnet)
    - AddressGroups creation (local/remote) for clean rule referencing
    - SecurityRule added to PreRulebase
- Safe prompting for values that are NOT in the form (PSK, local/remote subnet split)
- Optional Commit / Commit-All

Install:
  pip install pandas openpyxl pan-os-python

Run:
  python panorama_policy_based_vpn_automation.py

Security:
- Do NOT hardcode passwords. Use env var PANOS_PASSWORD or prompt.
"""

from __future__ import annotations

import os
import re
import getpass
import traceback
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple, Any

import pandas as pd

from panos.firewall import Firewall
from panos.panorama import Panorama, DeviceGroup
from panos.network import IkeGateway, IpsecTunnel, IpsecTunnelIpv4ProxyId
from panos.objects import AddressObject, AddressGroup
from panos.policies import PreRulebase, SecurityRule


# =============================================================================
# [CONFIG MODULE] - constants & defaults
# =============================================================================

DEFAULT_EXCEL_FILE = "VPN Tunnel Form - V1.2.xlsx"
DEFAULT_DEVICE_GROUP = "VPN-DG"

PASSWORD_ENV = "PANOS_PASSWORD"

# Epicor-style form columns (0-based index)
LABEL_COL = 0      # Column A
EPICOR_COL = 2     # Column C
CUSTOMER_COL = 4   # Column E

# Default security rule zones (override by adding rows in Excel if you want)
DEFAULT_FROM_ZONE = "trust"
DEFAULT_TO_ZONE = "untrust"

# Default local interface for IKE gateway if not provided in Excel
DEFAULT_LOCAL_INTERFACE = "ethernet1/1"


# =============================================================================
# [UTILS MODULE] - helpers
# =============================================================================

def norm(x: Any) -> str:
    """Normalize excel cell values to clean strings."""
    if x is None:
        return ""
    s = str(x).strip()
    return "" if s.lower() == "nan" else s


def safe_name(s: str) -> str:
    """Generate CLI/object safe-ish names."""
    s = norm(s)
    return re.sub(r"[^a-zA-Z0-9_\-\.]", "-", s)


def split_csv(value: str) -> List[str]:
    """Split comma-separated items."""
    return [x.strip() for x in norm(value).split(",") if x.strip()]


def prompt_required(msg: str) -> str:
    """Prompt until a non-empty value is provided."""
    while True:
        v = input(msg).strip()
        if v:
            return v
        print("Value required.")


def prompt_secret(msg: str, env_var: str = PASSWORD_ENV) -> str:
    """Read secret from env var or prompt."""
    v = os.getenv(env_var)
    if v:
        return v
    return getpass.getpass(msg)


def ike_version_normalize(v: str) -> str:
    v = norm(v).lower().replace(" ", "")
    if v in ("ikev2", "v2", "2"):
        return "ikev2"
    if v in ("ikev1", "v1", "1"):
        return "ikev1"
    return v  # will be validated later


# =============================================================================
# [EXCEL PARSER MODULE] - multi-sheet parsing
# =============================================================================

def pick_row_value(df: pd.DataFrame, label: str, prefer_customer: bool = True) -> str:
    """
    Find exact label match in label column and return:
      customer value if present else epicor value (default).
    """
    for r in range(df.shape[0]):
        if norm(df.iat[r, LABEL_COL]) == label:
            epicor = norm(df.iat[r, EPICOR_COL]) if df.shape[1] > EPICOR_COL else ""
            cust = norm(df.iat[r, CUSTOMER_COL]) if df.shape[1] > CUSTOMER_COL else ""
            return (cust or epicor) if prefer_customer else (epicor or cust)
    return ""


def parse_epicor_sheet(sheet_name: str, df: pd.DataFrame) -> Dict[str, str]:
    """
    Parse only what the Epicor form can reliably provide.
    Extra fields can be added as new rows in Excel later.
    """
    df = df.fillna("").astype(str)

    out: Dict[str, str] = {}
    # Core form labels (based on your sample)
    out["VPN Tunnel"] = pick_row_value(df, "VPN Tunnel")
    out["VPN Peer IP Address"] = pick_row_value(df, "VPN Peer IP Address")
    out["IKE Version"] = pick_row_value(df, "IKE Version")
    out["Encryption Domain"] = pick_row_value(df, "Encryption Domain")

    # Optional fields (if you add these rows later in Excel)
    out["Pre-Shared Key"] = pick_row_value(df, "Pre-Shared Key")  # usually missing by design
    out["Local Interface"] = pick_row_value(df, "Local Interface")
    out["From Zone"] = pick_row_value(df, "From Zone")
    out["To Zone"] = pick_row_value(df, "To Zone")
    out["IKE Crypto Profile"] = pick_row_value(df, "IKE Crypto Profile")
    out["IPSec Crypto Profile"] = pick_row_value(df, "IPSec Crypto Profile")

    return out


def parse_excel_workbook(path: str) -> Dict[str, Dict[str, str]]:
    """Read all sheets: 1 sheet = 1 VPN request."""
    xl = pd.ExcelFile(path)
    parsed: Dict[str, Dict[str, str]] = {}
    for sheet in xl.sheet_names:
        df = xl.parse(sheet_name=sheet, header=None)
        data = parse_epicor_sheet(sheet, df)
        # consider sheet valid if it contains at least VPN Tunnel + Peer IP
        if norm(data.get("VPN Tunnel")) and norm(data.get("VPN Peer IP Address")):
            parsed[sheet] = data
    return parsed


# =============================================================================
# [VALIDATION / DATA MODEL MODULE]
# =============================================================================

@dataclass
class VpnSpec:
    sheet: str
    vpn_name: str
    peer_ip: str
    ike_version: str
    local_interface: str
    psk: str
    local_subnets: List[str]
    remote_subnets: List[str]
    from_zone: str
    to_zone: str
    ike_crypto_profile: Optional[str] = None
    ipsec_crypto_profile: Optional[str] = None


def build_spec(sheet: str, d: Dict[str, str]) -> VpnSpec:
    vpn_name = safe_name(d.get("VPN Tunnel", ""))
    peer_ip = norm(d.get("VPN Peer IP Address", ""))
    ike_version = ike_version_normalize(d.get("IKE Version", "")) or "ikev2"

    if not vpn_name:
        raise ValueError(f"Sheet '{sheet}': missing VPN Tunnel value.")
    if not peer_ip:
        raise ValueError(f"Sheet '{sheet}': missing VPN Peer IP Address value.")

    if ike_version not in ("ikev1", "ikev2"):
        raise ValueError(f"Sheet '{sheet}': invalid IKE Version '{d.get('IKE Version')}'. Use IKEv1/IKEv2.")

    # PSK usually not in form -> prompt later if missing
    psk = norm(d.get("Pre-Shared Key", ""))

    local_interface = norm(d.get("Local Interface", "")) or DEFAULT_LOCAL_INTERFACE
    from_zone = norm(d.get("From Zone", "")) or DEFAULT_FROM_ZONE
    to_zone = norm(d.get("To Zone", "")) or DEFAULT_TO_ZONE

    # IMPORTANT: Epicor form has only ONE 'Encryption Domain' row; no local/remote split.
    # We'll prompt unless you encode: local=...; remote=...
    enc_domain = norm(d.get("Encryption Domain", ""))

    local_subnets: List[str] = []
    remote_subnets: List[str] = []
    if enc_domain and ("local=" in enc_domain.lower() and "remote=" in enc_domain.lower()):
        m_local = re.search(r"local\s*=\s*([^;]+)", enc_domain, flags=re.IGNORECASE)
        m_remote = re.search(r"remote\s*=\s*([^;]+)", enc_domain, flags=re.IGNORECASE)
        if m_local:
            local_subnets = split_csv(m_local.group(1))
        if m_remote:
            remote_subnets = split_csv(m_remote.group(1))

    ike_crypto_profile = norm(d.get("IKE Crypto Profile", "")) or None
    ipsec_crypto_profile = norm(d.get("IPSec Crypto Profile", "")) or None

    return VpnSpec(
        sheet=sheet,
        vpn_name=vpn_name,
        peer_ip=peer_ip,
        ike_version=ike_version,
        local_interface=local_interface,
        psk=psk,
        local_subnets=local_subnets,
        remote_subnets=remote_subnets,
        from_zone=from_zone,
        to_zone=to_zone,
        ike_crypto_profile=ike_crypto_profile,
        ipsec_crypto_profile=ipsec_crypto_profile,
    )


def ensure_runtime_inputs(spec: VpnSpec) -> None:
    """Prompt for missing fields that are not in the Epicor form."""
    if not spec.psk:
        spec.psk = getpass.getpass(f"[{spec.vpn_name}] Enter Pre-Shared Key (PSK): ").strip()
        if not spec.psk:
            raise ValueError(f"[{spec.vpn_name}] PSK is required.")

    if not spec.local_subnets:
        spec.local_subnets = split_csv(prompt_required(f"[{spec.vpn_name}] Enter LOCAL subnet(s) CIDR (comma-separated): "))
    if not spec.remote_subnets:
        spec.remote_subnets = split_csv(prompt_required(f"[{spec.vpn_name}] Enter REMOTE subnet(s) CIDR (comma-separated): "))

    if not spec.local_subnets or not spec.remote_subnets:
        raise ValueError(f"[{spec.vpn_name}] Both local and remote subnets must be provided.")


# =============================================================================
# [PAN-OS DEPLOYMENT MODULE] - create objects (Policy-based)
# =============================================================================

def deploy_policy_based_vpn(parent, spec: VpnSpec) -> None:
    """
    parent:
      - Firewall (lab)
      - DeviceGroup (Panorama)

    Creation order (recommended):
      1) IKE Gateway
      2) IPsec Tunnel
      3) Proxy-IDs (children of tunnel) -> IpsecTunnelIpv4ProxyId
      4) AddressObjects + AddressGroups
      5) SecurityRule in PreRulebase
    """
    vpn = spec.vpn_name
    gw_name = f"gw-{vpn}"
    ipsec_name = f"ipsec-{vpn}"

    # --- 1) IKE Gateway ---
    print(f"  [1/5] IKE Gateway: {gw_name}")
    ike = IkeGateway(name=gw_name)
    parent.add(ike)

    ike.version = spec.ike_version
    ike.interface = spec.local_interface
    ike.peer_ip_type = "ip"
    ike.peer_ip_value = spec.peer_ip
    ike.authentication_type = "pre-shared-key"
    ike.pre_shared_key = spec.psk

    if spec.ike_crypto_profile:
        ike.ike_crypto_profile = spec.ike_crypto_profile

    ike.create()

    # --- 2) IPsec Tunnel ---
    print(f"  [2/5] IPsec Tunnel: {ipsec_name}")
    ipsec = IpsecTunnel(name=ipsec_name)
    parent.add(ipsec)

    ipsec.ike_gateway = gw_name
    if spec.ipsec_crypto_profile:
        ipsec.ipsec_crypto_profile = spec.ipsec_crypto_profile

    ipsec.create()

    # --- 3) Proxy-IDs (after ipsec.create) ---
    print("  [3/5] Proxy-IDs")
    idx = 1
    for l in spec.local_subnets:
        for r in spec.remote_subnets:
            proxy = IpsecTunnelIpv4ProxyId(name=f"proxy{idx}", local=l, remote=r)
            ipsec.add(proxy)
            proxy.create()
            idx += 1

    # --- 4) AddressObjects + AddressGroups ---
    print("  [4/5] Address Objects + Groups")
    local_members: List[str] = []
    remote_members: List[str] = []

    for i, cidr in enumerate(spec.local_subnets, start=1):
        obj = AddressObject(name=f"{vpn}-local-{i:03d}", value=cidr)
        parent.add(obj)
        obj.create()
        local_members.append(obj.name)

    for i, cidr in enumerate(spec.remote_subnets, start=1):
        obj = AddressObject(name=f"{vpn}-remote-{i:03d}", value=cidr)
        parent.add(obj)
        obj.create()
        remote_members.append(obj.name)

    local_group = AddressGroup(name=f"{vpn}-local", static_value=local_members)
    remote_group = AddressGroup(name=f"{vpn}-remote", static_value=remote_members)
    parent.add(local_group)
    parent.add(remote_group)
    local_group.create()
    remote_group.create()

    # --- 5) Security rule (PreRulebase) ---
    print("  [5/5] Security Rule (PreRulebase)")
    pre = PreRulebase()
    parent.add(pre)

    rule = SecurityRule(
        name=f"vpn-{vpn}",
        fromzone=[spec.from_zone],
        tozone=[spec.to_zone],
        source=[local_group.name],
        destination=[remote_group.name],
        application=["any"],
        service=["application-default"],
        action="allow",
        description=f"VPN {vpn} created by automation (sheet={spec.sheet})",
    )
    pre.add(rule)
    rule.create()

    print("  Deployment complete.")


# =============================================================================
# [LOGIN / COMMIT MODULE] - firewall vs panorama
# =============================================================================

def connect_parent() -> Tuple[str, Any, Optional[Panorama], Optional[str]]:
    print("Select Login Mode:")
    print("1 = Lab Palo Alto Firewall")
    print("2 = Production Panorama (Device Group)")
    mode = input("Enter option: ").strip()

    username = prompt_required("Username: ")
    password = input("Password: ")

    if mode == "1":
        host = prompt_required("Lab Firewall IP/Hostname: ")
        fw = Firewall(hostname=host, api_username=username, api_password=password)
        print(f"Connected object created for Firewall: {host}")
        return "firewall", fw, None, None

    if mode == "2":
        pano_host = prompt_required("Panorama IP/Hostname: ")
        dg_name = input(f"Device Group [{DEFAULT_DEVICE_GROUP}]: ").strip() or DEFAULT_DEVICE_GROUP

        pano = Panorama(hostname=pano_host, api_username=username, api_password=password)
        dg = DeviceGroup(dg_name)
        pano.add(dg)

        print(f"Connected object created for Panorama: {pano_host} | DeviceGroup: {dg_name}")
        return "panorama", dg, pano, dg_name

    raise ValueError("Invalid selection. Choose 1 or 2.")


def do_commit(mode: str, parent: Any, pano: Optional[Panorama], dg_name: Optional[str]) -> None:
    answer = input("Commit changes now? (yes/no): ").strip().lower()
    if answer != "yes":
        print("Skipped commit.")
        return

    if mode == "firewall":
        print("Committing on Firewall...")
        parent.commit()
        print("Commit finished.")
        return

    print(f"Commit-All on Panorama for device-group '{dg_name}' ...")
    pano.commit_all(devicegroup=dg_name)
    print("Commit-All finished.")


# =============================================================================
# [MAIN MODULE]
# =============================================================================

def main() -> None:
    try:
        excel_path = input(f"Excel file path [{DEFAULT_EXCEL_FILE}]: ").strip() or DEFAULT_EXCEL_FILE
        vpn_sheets = parse_excel_workbook(excel_path)

        if not vpn_sheets:
            raise ValueError(
                "No VPN sheets detected. Ensure each sheet contains rows for "
                "'VPN Tunnel' and 'VPN Peer IP Address'."
            )

        mode, parent, pano, dg_name = connect_parent()
        print("\nStarting deployment for all sheets...\n")

        for sheet, d in vpn_sheets.items():
            spec = build_spec(sheet, d)
            ensure_runtime_inputs(spec)

            print(f"=== Sheet: {sheet} | VPN: {spec.vpn_name} ===")
            deploy_policy_based_vpn(parent, spec)
            print()

        do_commit(mode, parent, pano, dg_name)
        print("\nAll VPNs processed successfully.")

    except Exception as e:
        print("ERROR:", e)
        traceback.print_exc()


if __name__ == "__main__":
    main()