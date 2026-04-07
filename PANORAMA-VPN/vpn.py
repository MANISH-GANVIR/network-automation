#C:\Users\manish.ganvir\OneDrive - Epicor\Desktop\VPN Tunnel Form - V1.2.demo3.xlsx
"""
VPN Automation - FULL UPDATED FILE (as you asked)

What this version guarantees (per your exact requirements):
1) Terminal table shows ONLY 3 columns:
      Parameter | Epicor | Customer
   (No "Chosen" column)

2) VPN Filter / Access Lists:
   - If Excel has NA -> keep NA
   - If Excel is blank/missing -> table will show:
         Customer = "NA (default any)"
     and deployment will default to ANY/ANY (service=["any"], application=["any"]).

3) Encryption Domain handling (IMPORTANT):
   - Epicor column value = LOCAL subnet(s)
   - Customer column value = REMOTE subnet(s)
   - Supports multiple comma-separated subnets
   - If template has merged/shifted "Encryption Domain" row, script uses fallback detection
     (contains-match in label column A) so local/remote subnets get extracted.

4) Debug/trace:
   - TRACE prints module timing and every API create call label so you can see where it hangs.
   - Socket timeout enabled to avoid infinite hang.

Dependencies:
  pip install pandas openpyxl pan-os-python
"""


from __future__ import annotations

import re
import sys
import time
import socket
import getpass
import traceback
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple, Any

import pandas as pd

from panos.firewall import Firewall
from panos.panorama import Panorama, DeviceGroup

from panos.network import (
    IkeCryptoProfile,
    IpsecCryptoProfile,
    IkeGateway,
    IpsecTunnel,
    IpsecTunnelIpv4ProxyId,
)

from panos.objects import AddressObject, AddressGroup, ServiceObject
from panos.policies import PreRulebase, SecurityRule


# =============================================================================
# [CONFIG MODULE]
# =============================================================================

DEFAULT_EXCEL_FILE = "VPN Tunnel Form - V1.2.xlsx"
DEFAULT_DEVICE_GROUP = "VPN-DG"

# Epicor form columns (0-based): A=label, C=Epicor, E=Customer
LABEL_COL = 0
EPICOR_COL = 2
CUSTOMER_COL = 4

DEFAULT_FROM_ZONE = "trust"
DEFAULT_TO_ZONE = "untrust"
DEFAULT_LOCAL_INTERFACE = "ethernet1/1"

TRACE = False
DEBUG_TRACEBACK = True
API_SOCKET_TIMEOUT = 20  # seconds


# =============================================================================
# [TRACE/UTILS MODULE]
# =============================================================================

def log(msg: str) -> None:
    if TRACE:
        print(msg, flush=True)


def timed(label: str):
    class _T:
        def __enter__(self):
            self.t0 = time.time()
            log(f"[TRACE] START: {label}")
            return self

        def __exit__(self, exc_type, exc, tb):
            dt = time.time() - self.t0
            if exc_type:
                log(f"[TRACE] FAIL : {label} ({dt:.2f}s) -> {exc}")
            else:
                log(f"[TRACE] DONE : {label} ({dt:.2f}s)")
    return _T()


def norm(x: Any) -> str:
    if x is None:
        return ""
    s = str(x).strip()
    return "" if s.lower() == "nan" else s


def norm_lc(x: Any) -> str:
    return norm(x).lower()


def norm_label(s: Any) -> str:
    s = norm(s).lower()
    s = s.replace(":", "")
    s = s.replace("|", " ")
    s = re.sub(r"\s+", " ", s).strip()
    return s


def safe_name(s: str) -> str:
    s = norm(s)
    s = re.sub(r"[^a-zA-Z0-9_\-\.]", "-", s)
    return s[:63]


def split_csv(s: str) -> List[str]:
    s = norm(s).replace("\n", ",")
    return [x.strip() for x in s.split(",") if x.strip()]


def prompt_required(msg: str) -> str:
    while True:
        v = input(msg).strip()
        if v:
            return v
        print("Value required.")


def strip_wrapping_quotes(p: str) -> str:
    p = (p or "").strip()
    if (p.startswith('"') and p.endswith('"')) or (p.startswith("'") and p.endswith("'")):
        p = p[1:-1].strip()
    return p


def excel_locked_check(path: str) -> None:
    """
    If Excel file is open/locked -> friendly warning and exit (no traceback).
    """
    try:
        with open(path, "rb") as f:
            f.read(1)
    except PermissionError:
        print("\nWARNING: Your Excel file is OPEN/LOCKED (Permission denied).")
        print("Kindly SAVE and CLOSE the Excel file first, then run the script again.")
        print(f"File: {path}\n")
        sys.exit(1)


# =============================================================================
# [VALIDATION MODULE]
# =============================================================================

IKE_VERSION_MAP = {
    "ikev1": "ikev1",
    "ike v1": "ikev1",
    "ikev1 (main mode)": "ikev1",
    "v1": "ikev1",
    "1": "ikev1",
    "ikev2": "ikev2",
    "ike v2": "ikev2",
    "ikev2 (main mode)": "ikev2",
    "v2": "ikev2",
    "2": "ikev2",
}

IKE_ENCRYPTION_MAP = {
    "aes-128": "aes-128-cbc",
    "aes128": "aes-128-cbc",
    "aes-192": "aes-192-cbc",
    "aes192": "aes-192-cbc",
    "aes-256": "aes-256-cbc",
    "aes256": "aes-256-cbc",
    "3des": "3des",
}

IKE_HASH_PRF_MAP = {
    "sha1": "sha1",
    "sha-1": "sha1",
    "sha256": "sha256",
    "sha-256": "sha256",
    "sha384": "sha384",
    "sha-384": "sha384",
    "sha512": "sha512",
    "sha-512": "sha512",
}

DH_GROUP_MAP = {
    "group2": "group2",
    "group 2": "group2",
    "2": "group2",
    "group5": "group5",
    "group 5": "group5",
    "5": "group5",
    "group14": "group14",
    "group 14": "group14",
    "14": "group14",
    "group19": "group19",
    "group 19": "group19",
    "19": "group19",
    "group20": "group20",
    "group 20": "group20",
    "20": "group20",
}

IPSEC_PROTOCOL_MAP = {"esp": "esp"}

IPSEC_ENCRYPTION_MAP = {
    "aes-128": "aes-128-cbc",
    "aes-256": "aes-256-cbc",
    "aes-128-cbc": "aes-128-cbc",
    "aes-256-cbc": "aes-256-cbc",
    "aes-128-gcm": "aes-128-gcm",
    "aes-256-gcm": "aes-256-gcm",
}

IPSEC_AUTH_MAP = {
    "sha1": "sha1",
    "sha-1": "sha1",
    "sha256": "sha256",
    "sha-256": "sha256",
    "sha384": "sha384",
    "sha-384": "sha384",
    "sha512": "sha512",
    "sha-512": "sha512",
    "none": "none",
    "null": "none",
}

PFS_MAP = {
    "disabled": None,
    "none": None,
    "no": None,
    "false": None,
    "group2": "group2",
    "group 2": "group2",
    "group5": "group5",
    "group 5": "group5",
    "group14": "group14",
    "group 14": "group14",
    "group19": "group19",
    "group 19": "group19",
    "group20": "group20",
    "group 20": "group20",
}


def must_map(label: str, value: str, mapping: Dict[str, Any]) -> Any:
    key = norm_lc(value)
    if key not in mapping:
        raise ValueError(f"Unsupported {label}: '{value}'. Supported: {sorted(set(mapping.keys()))}")
    return mapping[key]


def must_int(label: str, value: str, minv: int = 1, maxv: int = 10**9) -> int:
    v = norm(value)
    m = re.search(r"(\d+)", v)
    if not m:
        raise ValueError(f"{label} must be an integer (seconds). Got: '{value}'")
    i = int(m.group(1))
    if i < minv or i > maxv:
        raise ValueError(f"{label} out of range ({minv}-{maxv}). Got: {i}")
    return i


# =============================================================================
# [EXCEL PARSING + TABLE MODULE]
# =============================================================================

@dataclass
class ExtractedField:
    key: str
    label: str
    epicor: str
    customer: str
    chosen: str  # internal only (not displayed)


def ascii_table(title: str, rows: List[List[str]]) -> str:
    widths = [0] * len(rows[0])
    for r in rows:
        for i, cell in enumerate(r):
            widths[i] = max(widths[i], len(cell))

    def fmt_row(r: List[str]) -> str:
        return "| " + " | ".join(r[i].ljust(widths[i]) for i in range(len(r))) + " |"

    sep = "+-" + "-+-".join("-" * w for w in widths) + "-+"
    out = [title, sep, fmt_row(rows[0]), sep]
    for r in rows[1:]:
        out.append(fmt_row(r))
    out.append(sep)
    return "\n".join(out)


def choose_value(epicor: str, customer: str) -> str:
    e = norm(epicor)
    c = norm(customer)
    return c or e


def find_label_row(df: pd.DataFrame, label: str, start_row: int = 0) -> Optional[int]:
    target = norm_label(label)
    for r in range(start_row, df.shape[0]):
        if norm_label(df.iat[r, LABEL_COL]) == target:
            return r
    return None


def pick_row_value_raw(df: pd.DataFrame, label: str, start_row: int = 0) -> Tuple[str, str]:
    r = find_label_row(df, label, start_row=start_row)
    if r is None:
        return "", ""
    epicor = norm(df.iat[r, EPICOR_COL]) if df.shape[1] > EPICOR_COL else ""
    customer = norm(df.iat[r, CUSTOMER_COL]) if df.shape[1] > CUSTOMER_COL else ""
    return epicor, customer


def find_phase_row(df: pd.DataFrame, contains_text: str) -> Optional[int]:
    t = contains_text.lower()
    for r in range(df.shape[0]):
        if t in norm_label(df.iat[r, LABEL_COL]):
            return r
    return None


def pick_encryption_domain(df: pd.DataFrame) -> Tuple[str, str]:
    """
    IMPORTANT: handles merged/shifted templates.
    Returns (epicor_local, customer_remote).
    """
    e, c = pick_row_value_raw(df, "Encryption Domain")
    if e or c:
        return e, c

    # fallback: contains search in col A
    for r in range(df.shape[0]):
        lbl = norm(df.iat[r, LABEL_COL])
        if "encryption domain" in lbl.lower():
            epicor = norm(df.iat[r, EPICOR_COL]) if df.shape[1] > EPICOR_COL else ""
            customer = norm(df.iat[r, CUSTOMER_COL]) if df.shape[1] > CUSTOMER_COL else ""
            if epicor or customer:
                return epicor, customer

    return "", ""


def extract_fields_for_sheet(df: pd.DataFrame) -> List[ExtractedField]:
    df = df.fillna("").astype(str)
    fields: List[ExtractedField] = []

    # General
    e, c = pick_row_value_raw(df, "VPN Tunnel")
    fields.append(ExtractedField("general.vpn_tunnel", "VPN Tunnel", e, c, choose_value(e, c)))

    e, c = pick_row_value_raw(df, "VPN Peer IP Address")
    fields.append(ExtractedField("general.peer_ip", "VPN Peer IP Address", e, c, choose_value(e, c)))

    e, c = pick_row_value_raw(df, "VPN Peer Device Type")
    fields.append(ExtractedField("general.peer_vendor", "VPN Peer Device Type", e, c, choose_value(e, c)))

    # VPN Filter: if missing -> DEFAULT NA (any/any)
    e, c = pick_row_value_raw(df, "VPN Filter / Access Lists")
    chosen_filter = choose_value(e, c)
    if not chosen_filter:
        chosen_filter = "NA"
    fields.append(ExtractedField("general.vpn_filter", "VPN Filter / Access Lists", e, c, chosen_filter))

    # Encryption Domain: Epicor=LOCAL, Customer=REMOTE
    e, c = pick_encryption_domain(df)
    fields.append(ExtractedField("enc.local", "Encryption Domain (LOCAL)", e, "", norm(e)))
    fields.append(ExtractedField("enc.remote", "Encryption Domain (REMOTE)", "", c, norm(c)))

    # Phase 1
    for key, label in [
        ("phase1.ike_version", "IKE Version"),
        ("phase1.encryption", "Encryption Algorithm"),
        ("phase1.hash_prf", "Hash Algorithm / PRF"),
        ("phase1.dh_group", "DH Group"),
        ("phase1.sa_lifetime", "SA Lifetime"),
    ]:
        e, c = pick_row_value_raw(df, label)
        fields.append(ExtractedField(key, f"Phase 1 | {label}", e, c, choose_value(e, c)))

    # Phase 2 (after header)
    phase2_row = find_phase_row(df, "Phase 2") or 0
    for key, label in [
        ("phase2.protocol", "IPSec Protocol"),
        ("phase2.encryption", "Encryption Algorithm"),
        ("phase2.hash", "Hash Algorithm"),
        ("phase2.pfs", "PFS"),
        ("phase2.sa_lifetime", "SA Lifetime"),
    ]:
        e, c = pick_row_value_raw(df, label, start_row=phase2_row)
        fields.append(ExtractedField(key, f"Phase 2 | {label}", e, c, choose_value(e, c)))

    return fields


def print_extracted_table(sheet_name: str, fields: List[ExtractedField]) -> None:
    """
    3 columns only.
    But: VPN Filter default is displayed as NA (default any/any) when Excel blank.
    """
    rows = [["Parameter", "Epicor", "Customer"]]
    for f in fields:
        epicor = f.epicor
        customer = f.customer

        if f.key == "general.vpn_filter":
            if not norm(epicor) and not norm(customer):
                epicor = "any"
                customer = "any"

        rows.append([f.label, epicor, customer])

    print()
    print(ascii_table(f"=== Extracted values for sheet: {sheet_name} ===", rows))
    print()


def fields_to_chosen_dict(fields: List[ExtractedField]) -> Dict[str, str]:
    return {f.key: f.chosen for f in fields}


def read_excel_workbook_with_table(path: str, show_tables: bool = True) -> List[Tuple[str, Dict[str, str]]]:
    with timed("Excel read workbook"):
        xl = pd.ExcelFile(path)

    out: List[Tuple[str, Dict[str, str]]] = []
    for sheet in xl.sheet_names:
        with timed(f"Excel parse sheet '{sheet}'"):
            df = xl.parse(sheet_name=sheet, header=None)
            fields = extract_fields_for_sheet(df)
            chosen = fields_to_chosen_dict(fields)

        if norm(chosen.get("general.vpn_tunnel")) and norm(chosen.get("general.peer_ip")):
            if show_tables:
                print_extracted_table(sheet, fields)
            out.append((sheet, chosen))

    return out


# =============================================================================
# [SPEC / PROFILE BUILDER MODULE]
# =============================================================================

@dataclass
class VpnSpec:
    sheet: str
    vpn_name: str
    peer_ip: str
    vendor: str
    vpn_filter: str

    ike_version: str
    ike_encryption: str
    ike_hash: str
    ike_dh: str
    ike_lifetime: int

    ipsec_protocol: str
    ipsec_encryption: str
    ipsec_auth: str
    ipsec_pfs: Optional[str]
    ipsec_lifetime: int

    psk: str
    local_subnets: List[str]
    remote_subnets: List[str]

    local_interface: str = DEFAULT_LOCAL_INTERFACE
    from_zone: str = DEFAULT_FROM_ZONE
    to_zone: str = DEFAULT_TO_ZONE


def build_spec_from_chosen(sheet: str, chosen: Dict[str, str]) -> VpnSpec:
    with timed(f"Build spec for sheet '{sheet}'"):
        vpn_name_raw = chosen.get("general.vpn_tunnel", "")
        peer_ip_raw = chosen.get("general.peer_ip", "")
        vendor_raw = chosen.get("general.peer_vendor", "")

        vpn_filter = chosen.get("general.vpn_filter", "NA") or "NA"

        local_raw = chosen.get("enc.local", "")
        remote_raw = chosen.get("enc.remote", "")

        ike_version_raw = chosen.get("phase1.ike_version", "")
        ike_enc_raw = chosen.get("phase1.encryption", "")
        ike_hash_raw = chosen.get("phase1.hash_prf", "")
        ike_dh_raw = chosen.get("phase1.dh_group", "")
        ike_lifetime_raw = chosen.get("phase1.sa_lifetime", "")

        ipsec_protocol_raw = chosen.get("phase2.protocol", "")
        ipsec_enc_raw = chosen.get("phase2.encryption", "")
        ipsec_hash_raw = chosen.get("phase2.hash", "")
        ipsec_pfs_raw = chosen.get("phase2.pfs", "")
        ipsec_lifetime_raw = chosen.get("phase2.sa_lifetime", "")

        ike_version = must_map("IKE Version", ike_version_raw, IKE_VERSION_MAP)
        ike_enc = must_map("IKE Encryption Algorithm", ike_enc_raw, IKE_ENCRYPTION_MAP)
        ike_hash = must_map("IKE Hash Algorithm / PRF", ike_hash_raw, IKE_HASH_PRF_MAP)
        ike_dh = must_map("IKE DH Group", ike_dh_raw, DH_GROUP_MAP)
        ike_life = must_int("IKE SA Lifetime", ike_lifetime_raw, minv=60)

        ipsec_protocol = must_map("IPSec Protocol", ipsec_protocol_raw, IPSEC_PROTOCOL_MAP)
        ipsec_enc = must_map("IPSec Encryption Algorithm", ipsec_enc_raw, IPSEC_ENCRYPTION_MAP)
        ipsec_auth = must_map("IPSec Hash/Authentication Algorithm", ipsec_hash_raw, IPSEC_AUTH_MAP)
        ipsec_pfs = must_map("IPSec PFS", ipsec_pfs_raw, PFS_MAP)
        ipsec_life = must_int("IPSec SA Lifetime", ipsec_lifetime_raw, minv=60)

        vpn_name = safe_name(vpn_name_raw)
        peer_ip = norm(peer_ip_raw)
        if not vpn_name:
            raise ValueError(f"[{sheet}] Missing VPN Tunnel value")
        if not peer_ip:
            raise ValueError(f"[{sheet}] Missing VPN Peer IP Address value")

        psk = ""

        local_subnets = split_csv(local_raw)
        remote_subnets = split_csv(remote_raw)

        # If subnet missing -> keep empty (commands will still generate)
        if not local_subnets:
            local_subnets = [""]

        if not remote_subnets:
            remote_subnets = [""]
        return VpnSpec(
            sheet=sheet,
            vpn_name=vpn_name,
            peer_ip=peer_ip,
            vendor=norm(vendor_raw),
            vpn_filter=vpn_filter,

            ike_version=ike_version,
            ike_encryption=ike_enc,
            ike_hash=ike_hash,
            ike_dh=ike_dh,
            ike_lifetime=ike_life,

            ipsec_protocol=ipsec_protocol,
            ipsec_encryption=ipsec_enc,
            ipsec_auth=ipsec_auth,
            ipsec_pfs=ipsec_pfs,
            ipsec_lifetime=ipsec_life,

            psk=psk,
            local_subnets=local_subnets,
            remote_subnets=remote_subnets,
        )


def profile_names(spec: VpnSpec) -> Tuple[str, str]:
    ike = safe_name(
        f"auto-ike-{spec.ike_version}-{spec.ike_encryption}-{spec.ike_hash}-{spec.ike_dh}-{spec.ike_lifetime}"
    )
    ipsec = safe_name(
        f"auto-ipsec-{spec.ipsec_encryption}-{spec.ipsec_auth}-pfs{spec.ipsec_pfs or 'none'}-{spec.ipsec_lifetime}"
    )
    return ike, ipsec


def api_create(obj, label: str) -> None:
    with timed(f"API create: {label}"):
        obj.create()


def ensure_ike_crypto_profile(parent, name: str, spec: VpnSpec) -> None:
    with timed("Ensure IKE Crypto Profile"):
        existing = {o.name for o in IkeCryptoProfile.refreshall(parent, add=False)}
        if name in existing:
            log(f"  - Reusing IKE Crypto Profile: {name}")
            return

        log(f"  - Creating IKE Crypto Profile: {name}")
        prof = IkeCryptoProfile(
            name=name,
            encryption=[spec.ike_encryption],
            hash=[spec.ike_hash],
            dh_group=[spec.ike_dh],
            lifetime_seconds=spec.ike_lifetime,
        )
        parent.add(prof)
        api_create(prof, f"IkeCryptoProfile '{name}'")


def ensure_ipsec_crypto_profile(parent, name: str, spec: VpnSpec) -> None:
    with timed("Ensure IPSec Crypto Profile"):
        existing = {o.name for o in IpsecCryptoProfile.refreshall(parent, add=False)}
        if name in existing:
            log(f"  - Reusing IPSec Crypto Profile: {name}")
            return

        log(f"  - Creating IPSec Crypto Profile: {name}")
        prof = IpsecCryptoProfile(
            name=name,
            esp_encryption=[spec.ipsec_encryption],
            esp_authentication=[spec.ipsec_auth] if spec.ipsec_auth != "none" else [],
            lifetime_seconds=spec.ipsec_lifetime,
            dh_group=spec.ipsec_pfs,
        )
        parent.add(prof)
        api_create(prof, f"IpsecCryptoProfile '{name}'")


# =============================================================================
# [VPN FILTER MODULE] - matches your NA/blank/ports rules
# =============================================================================

SERVICE_RE = re.compile(r"^\s*(tcp|udp)\s+(\d{1,5})\s*$", flags=re.IGNORECASE)


def parse_vpn_filter(raw: str) -> List[Tuple[str, int]]:
    raw = norm(raw)

    if not raw:
        log("[WARN] VPN Filter blank. Defaulting to ANY.")
        return []

    if raw.strip().lower() == "na":
        return []

    parts = re.split(r"[;,]\s*", raw)
    out: List[Tuple[str, int]] = []
    for p in parts:
        p = p.strip()
        if not p:
            continue
        m = SERVICE_RE.match(p)
        if not m:
            raise ValueError(f"Unsupported VPN Filter entry '{p}'. Use 'TCP 443' format or NA.")
        proto = m.group(1).lower()
        port = int(m.group(2))
        if port < 1 or port > 65535:
            raise ValueError(f"Invalid port '{port}' in VPN Filter.")
        out.append((proto, port))
    return out


def ensure_service_objects(parent, vpn_name: str, services: List[Tuple[str, int]]) -> List[str]:
    with timed("Ensure ServiceObjects"):
        if not services:
            return ["any"]

        existing = {o.name for o in ServiceObject.refreshall(parent, add=False)}
        created_names: List[str] = []

        for proto, port in services:
            name = safe_name(f"{vpn_name}-svc-{proto}-{port}")
            if name not in existing:
                log(f"  - Creating ServiceObject: {name} ({proto}/{port})")
                svc = ServiceObject(name=name, protocol=proto, destination_port=str(port))
                parent.add(svc)
                api_create(svc, f"ServiceObject '{name}'")
                existing.add(name)
            else:
                log(f"  - Reusing ServiceObject: {name}")
            created_names.append(name)

        return created_names

#---------------------------------------------------------------------------------------
def generate_cli_commands(spec):

    vpn = spec.vpn_name
    peer = spec.peer_ip
    local = spec.local_subnets[0] if spec.local_subnets else ""
    remote = spec.remote_subnets[0] if spec.remote_subnets else ""

    print("\n=========== GENERATED PALO ALTO COMMANDS ===========\n")

    print("# ==== CRYPTO PROFILES ====")

    print(f"set template <TEMPLATE_NAME> config network ike crypto-profiles ike-crypto-profiles IKE-PROF encryption {spec.ike_encryption}")
    print(f"set template <TEMPLATE_NAME> config network ike crypto-profiles ike-crypto-profiles IKE-PROF hash {spec.ike_hash}")
    print(f"set template <TEMPLATE_NAME> config network ike crypto-profiles ike-crypto-profiles IKE-PROF dh-group {spec.ike_dh}")
    print(f"set template <TEMPLATE_NAME> config network ike crypto-profiles ike-crypto-profiles IKE-PROF lifetime hours {spec.ike_lifetime}")

    print(f"set template <TEMPLATE_NAME> config network ike crypto-profiles ipsec-crypto-profiles IPSEC-PROF esp encryption {spec.ipsec_encryption}")
    print(f"set template <TEMPLATE_NAME> config network ike crypto-profiles ipsec-crypto-profiles IPSEC-PROF esp authentication {spec.ipsec_auth}")
    print(f"set template <TEMPLATE_NAME> config network ike crypto-profiles ipsec-crypto-profiles IPSEC-PROF dh-group {spec.ipsec_pfs}")
    print(f"set template <TEMPLATE_NAME> config network ike crypto-profiles ike-crypto-profiles IKE-PROF lifetime hours {spec.ike_lifetime}")

    print("\n# ==== TUNNEL INTERFACE ====")

    print(f"set template <TEMPLATE_NAME> config network interface tunnel units tunnel.10 comment \"S2S to {vpn}\"")
    print("set template <TEMPLATE_NAME> config vsys vsys1 zone VPN-ZONE network layer3 [ tunnel.10 ]")
    print("set template <TEMPLATE_NAME> config network virtual-router default interface [ tunnel.10 ]")

    print("\n# ==== IKE GATEWAY ====")

    print(f"set template <TEMPLATE_NAME> config network ike gateway GW-{vpn} authentication pre-shared-key key {spec.psk}")
    print(f"set template <TEMPLATE_NAME> config network ike gateway GW-{vpn} protocol {spec.ike_version} ike-crypto-profile IKE-PROF")
    print("set template <TEMPLATE_NAME> config network ike gateway GW-{vpn} local-address interface <WAN_INTERFACE>")
    print(f"set template <TEMPLATE_NAME> config network ike gateway GW-{vpn} peer-address ip {peer}")

    print("\n# ==== IPSEC TUNNEL ====")

    print(f"set template <TEMPLATE_NAME> config network tunnel ipsec TUN-{vpn} tunnel-interface tunnel.10")
    print(f"set template <TEMPLATE_NAME> config network tunnel ipsec TUN-{vpn} anti-replay yes")
    print(f"set template <TEMPLATE_NAME> config network tunnel ipsec TUN-{vpn} auto-key ike-gateway GW-{vpn}")
    print(f"set template <TEMPLATE_NAME> config network tunnel ipsec TUN-{vpn} auto-key ipsec-crypto-profile IPSEC-PROF")

    print("\n# ==== PROXY ID ====")

    print(f"set template <TEMPLATE_NAME> config network tunnel ipsec TUN-{vpn} auto-key proxy-id VPN-1 local {local} remote {remote} protocol any")

    print("\n# ==== ROUTING ====")

    print(f"set template <TEMPLATE_NAME> config network virtual-router default routing-table ip static-route RT-to-{vpn} destination {remote} interface tunnel.10 metric 10")

    print("\n# ==== SECURITY POLICY ====")

    print(f"set device-group <DEVICE_GROUP> pre-rulebase security rules S2S-OUT from [ trust ] to [ VPN-ZONE ] source any destination {remote} application any service application-default action allow")

    print(f"set device-group <DEVICE_GROUP> pre-rulebase security rules S2S-IN from [ VPN-ZONE ] to [ trust ] source {remote} destination any application any service application-default action allow")



# =============================================================================
# [DEPLOY MODULE]
# =============================================================================

def deploy_policy_based_vpn(parent, spec: VpnSpec) -> None:
    with timed(f"Deploy VPN '{spec.vpn_name}'"):
        vpn = spec.vpn_name
        gw_name = f"gw-{vpn}"
        ipsec_name = f"ipsec-{vpn}"

        ike_prof_name, ipsec_prof_name = profile_names(spec)
        log(f"== Deploy VPN '{vpn}' ==")

        ensure_ike_crypto_profile(parent, ike_prof_name, spec)
        ensure_ipsec_crypto_profile(parent, ipsec_prof_name, spec)

        log(f"  - Creating IKE Gateway: {gw_name}")
        ike = IkeGateway(name=gw_name)
        parent.add(ike)
        ike.version = spec.ike_version
        ike.interface = spec.local_interface
        ike.peer_ip_type = "ip"
        ike.peer_ip_value = spec.peer_ip
        ike.authentication_type = "pre-shared-key"
        ike.pre_shared_key = spec.psk
        ike.ike_crypto_profile = ike_prof_name
        api_create(ike, f"IkeGateway '{gw_name}'")

        log(f"  - Creating IPsec Tunnel: {ipsec_name}")
        ipsec = IpsecTunnel(name=ipsec_name)
        parent.add(ipsec)
        ipsec.ike_gateway = gw_name
        ipsec.ipsec_crypto_profile = ipsec_prof_name
        api_create(ipsec, f"IpsecTunnel '{ipsec_name}'")

        log("  - Creating Proxy-IDs")
        idx = 1
        for l in spec.local_subnets:
            for r in spec.remote_subnets:
                name = f"proxy{idx}"
                pid = IpsecTunnelIpv4ProxyId(name=name, local=l, remote=r)
                ipsec.add(pid)
                api_create(pid, f"ProxyId '{ipsec_name}/{name}' local={l} remote={r}")
                idx += 1

        log("  - Creating AddressObjects + AddressGroups")
        local_members: List[str] = []
        remote_members: List[str] = []

        for i, cidr in enumerate(spec.local_subnets, start=1):
            ao = AddressObject(name=f"{vpn}-local-{i:03d}", value=cidr)
            parent.add(ao)
            api_create(ao, f"AddressObject '{ao.name}'={cidr}")
            local_members.append(ao.name)

        for i, cidr in enumerate(spec.remote_subnets, start=1):
            ao = AddressObject(name=f"{vpn}-remote-{i:03d}", value=cidr)
            parent.add(ao)
            api_create(ao, f"AddressObject '{ao.name}'={cidr}")
            remote_members.append(ao.name)

        local_group = AddressGroup(name=f"{vpn}-local", static_value=local_members)
        remote_group = AddressGroup(name=f"{vpn}-remote", static_value=remote_members)
        parent.add(local_group)
        parent.add(remote_group)
        api_create(local_group, f"AddressGroup '{local_group.name}'")
        api_create(remote_group, f"AddressGroup '{remote_group.name}'")

        service_pairs = parse_vpn_filter(spec.vpn_filter)
        service_names = ensure_service_objects(parent, vpn, service_pairs)

        log("  - Creating Security Rule (PreRulebase)")
        pre = PreRulebase()
        parent.add(pre)

        rule = SecurityRule(
            name=f"vpn-{vpn}",
            fromzone=[spec.from_zone],
            tozone=[spec.to_zone],
            source=[local_group.name],
            destination=[remote_group.name],
            application=["any"],
            service=service_names,
            action="allow",
            description=f"VPN {vpn} managed by automation (sheet={spec.sheet})",
        )
        pre.add(rule)
        api_create(rule, f"SecurityRule 'vpn-{vpn}'")

        log(f"== Done VPN '{vpn}' ==")

# =============================================================================
# Show existing tunnels module (per your request to see existing tunnels before deployment)
# ============================================================================

def show_existing_ipsec_tunnels(parent, title: str = "Existing IPSec Tunnels") -> None:
    """
    Prints existing IPSec tunnels visible at the current 'parent' scope.
    - Firewall mode: tunnels on the firewall
    - Panorama DG mode: tunnels in that Device Group
    """
    print(f"\n=== {title} ===")
    try:
        tunnels = IpsecTunnel.refreshall(parent, add=False)
        if not tunnels:
            print("(none found)")
            return

        # Print just names (and optionally tunnel-interface if present)
        for t in tunnels:
            # Some versions have t.tunnel_interface, else just name
            ti = getattr(t, "tunnel_interface", "") or ""
            if ti:
                print(f"- {t.name}  (tunnel_if={ti})")
            else:
                print(f"- {t.name}")
    except Exception as e:
        print(f"WARNING: Unable to fetch IPSec tunnels: {e}")

#===========================================================
#VPN Diagnosis
#=


def op_cmd_xml(device, cmd: str) -> str:

    result = device.op(cmd)

    if hasattr(result, "tag"):
        return ET.tostring(result, encoding="unicode")

    return str(result)


def show_vpn_op_diagnostics(device):

    print("\n=========== VPN GATEWAYS ===========\n")

    try:
        res = device.op("show vpn gateway")

        for entry in res.findall(".//entry"):

            name = entry.findtext("name")
            peer = entry.findtext(".//peer-id")
            enc = entry.findtext(".//enc")
            hash_alg = entry.findtext(".//hash")
            dh = entry.findtext(".//dh")
            life = entry.findtext(".//life")

            print(f"Gateway Name : {name}")
            print(f"Peer ID      : {peer}")
            print(f"Encryption   : {enc}")
            print(f"Hash         : {hash_alg}")
            print(f"DH Group     : {dh}")
            print(f"Lifetime     : {life}")
            print("-----------------------------------")

    except Exception as e:
        print("Gateway fetch failed:", e)

    print("\n=========== VPN TUNNELS ===========\n")

    try:
        res = device.op("show vpn tunnel")

        for entry in res.findall(".//entry"):

            name = entry.findtext("name")
            gw = entry.findtext("gw")
            local_ip = entry.findtext("TSi_ip")
            local_pref = entry.findtext("TSi_prefix")
            remote_ip = entry.findtext("TSr_ip")
            remote_pref = entry.findtext("TSr_prefix")
            enc = entry.findtext("enc")
            hash_alg = entry.findtext("hash")

            print(f"Tunnel Name  : {name}")
            print(f"Gateway      : {gw}")
            print(f"Local Net    : {local_ip}/{local_pref}")
            print(f"Remote Net   : {remote_ip}/{remote_pref}")
            print(f"Encryption   : {enc}")
            print(f"Hash         : {hash_alg}")
            print("-----------------------------------")

    except Exception as e:
        print("Tunnel fetch failed:", e)

    print("\n=========== IKE SA ===========\n")

    try:
        res = device.op("show vpn ike-sa")

        entries = res.findall(".//entry")

        if not entries:
            print("No active IKE SA")

        for entry in entries:
            print(ET.tostring(entry, encoding="unicode"))

    except Exception as e:
        print("IKE SA fetch failed:", e)

    print("\n=========== IPSEC SA ===========\n")

    try:
        res = device.op("show vpn ipsec-sa")

        entries = res.findall(".//entry")

        if not entries:
            print("No active IPSec SA")

        for entry in entries:
            print(ET.tostring(entry, encoding="unicode"))

    except Exception as e:
        print("IPSec SA fetch failed:", e)
# =============================================================================
# [LOGIN MODULE]
# =============================================================================

def connect_parent() -> Tuple[str, Any, Optional[Panorama], Optional[str]]:
    log("[TRACE] Enter connect_parent()")
    print("Select Login Mode:")
    print("1 = Lab Palo Alto Firewall")
    print("2 = Production Panorama (Device Group)")
    mode = input("Enter option: ").strip()

    # You asked earlier to inbuild these:
    username = "netadmin"
    password = "Epi(0r@2020+"  # NOT RECOMMENDED

    socket.setdefaulttimeout(API_SOCKET_TIMEOUT)

    if mode == "1":
        host = "20.232.50.129"
        log(f"[TRACE] Creating Firewall object for host={host} timeout={API_SOCKET_TIMEOUT}s")
        fw = Firewall(hostname=host, api_username=username, api_password=password)
        show_existing_ipsec_tunnels(fw, title=f"Existing IPSec Tunnels on Firewall {host}")
        show_vpn_op_diagnostics(fw)
        return "firewall", fw, None, None

    if mode == "2":
        pano_host = prompt_required("Panorama IP/Hostname: ").strip()
        dg_name = input(f"Device Group [{DEFAULT_DEVICE_GROUP}]: ").strip() or DEFAULT_DEVICE_GROUP
        log(f"[TRACE] Creating Panorama object for host={pano_host} dg={dg_name} timeout={API_SOCKET_TIMEOUT}s")
        pano = Panorama(hostname=pano_host, api_username=username, api_password=password)
        dg = DeviceGroup(dg_name)
        pano.add(dg)
        show_existing_ipsec_tunnels(dg, title=f"Existing IPSec Tunnels in Device Group {dg_name}")
        return "panorama", dg, pano, dg_name

    raise ValueError("Invalid selection. Choose 1 or 2.")




# =============================================================================
# [MAIN MODULE]
# =============================================================================

def main() -> None:
    excel_path = strip_wrapping_quotes(input(f"Excel file path [{DEFAULT_EXCEL_FILE}]: ").strip() or DEFAULT_EXCEL_FILE)
    excel_locked_check(excel_path)

    try:

        # ---------------- SHOW CURRENT VPN CONFIG ----------------
        print("\n========== CURRENT VPN CONFIG ==========\n")

        try:
            fw = Firewall(hostname="20.232.50.129", api_username="netadmin", api_password="Epi(0r@2020+")
            show_existing_ipsec_tunnels(fw)
            show_vpn_op_diagnostics(fw)
        except Exception as e:
            print("Unable to fetch current VPN config:", e)

        print("\n========================================\n")

        with timed("Read workbook + print tables"):
            sheet_dicts = read_excel_workbook_with_table(excel_path, show_tables=True)

        if not sheet_dicts:
            raise ValueError("No valid VPN sheets found. Ensure each sheet has 'VPN Tunnel' and 'VPN Peer IP Address'.")

        mode = None
        parent = None
        pano = None
        dg_name = None

        failures: List[Tuple[str, str]] = []

        for sheet, chosen in sheet_dicts:
            try:
                spec = build_spec_from_chosen(sheet, chosen)
                print(f"\nGenerating commands from Extracted values for excel sheet: {sheet}\n")
                generate_cli_commands(spec)
                print()
            except Exception as e:
                failures.append((sheet, str(e)))
                print(f"ERROR [{sheet}]: {e}")
                if DEBUG_TRACEBACK:
                    traceback.print_exc()
                print("Continuing to next sheet...\n")



        if failures:
            print("\nSome VPNs failed:")
            for sheet, msg in failures:
                print(f" - {sheet}: {msg}")
            sys.exit(2)

        print("\nAll VPNs processed successfully.")

    except Exception as e:
        print("FATAL ERROR:", e)
        if DEBUG_TRACEBACK:
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()