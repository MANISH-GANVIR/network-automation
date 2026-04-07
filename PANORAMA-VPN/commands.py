#C:\Users\manish.ganvir\OneDrive - Epicor\Desktop\VPN Tunnel Form - V1.2.demo3.xlsx
from __future__ import annotations
import re
import sys
import traceback
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple, Any

import pandas as pd

# =============================================================================
# [CONFIG MODULE]
# =============================================================================

DEFAULT_EXCEL_FILE = "VPN Tunnel Form - V1.2.xlsx"

# Epicor form columns (0-based): A=label, C=Epicor, E=Customer
LABEL_COL = 0
EPICOR_COL = 2
CUSTOMER_COL = 4

DEBUG_TRACEBACK = True


# =============================================================================
# [TRACE/UTILS MODULE]
# =============================================================================

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


def must_int(label: str, value: str, minv: int = 1, maxv: int = 10 ** 9) -> int:
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
    """
    Read ALL sheets from Excel workbook.
    Returns list of (sheet_name, chosen_dict) tuples.
    """
    xl = pd.ExcelFile(path)

    out: List[Tuple[str, Dict[str, str]]] = []

    print(f"\n{'=' * 80}")
    print(f"Total sheets found in Excel: {len(xl.sheet_names)}")
    print(f"Sheet names: {xl.sheet_names}")
    print(f"{'=' * 80}\n")

    for sheet in xl.sheet_names:
        df = xl.parse(sheet_name=sheet, header=None)
        fields = extract_fields_for_sheet(df)
        chosen = fields_to_chosen_dict(fields)

        # Check if sheet has valid VPN data
        if norm(chosen.get("general.vpn_tunnel")) and norm(chosen.get("general.peer_ip")):
            if show_tables:
                print_extracted_table(sheet, fields)
            out.append((sheet, chosen))
        else:
            print(f"⚠️  SKIPPED SHEET '{sheet}' - Missing VPN Tunnel or Peer IP Address\n")

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

    local_interface: str = "ethernet1/1"
    from_zone: str = "trust"
    to_zone: str = "untrust"


def build_spec_from_chosen(sheet: str, chosen: Dict[str, str]) -> VpnSpec:
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


# =============================================================================
# [COMMAND GENERATION MODULE]
# =============================================================================

def generate_cli_commands(spec: VpnSpec) -> None:
    vpn = spec.vpn_name
    peer = spec.peer_ip
    local = spec.local_subnets[0] if spec.local_subnets else ""
    remote = spec.remote_subnets[0] if spec.remote_subnets else ""

    print("\n" + "=" * 80)
    print(f"📋 COMMANDS FOR TAB: [{spec.sheet}]")
    print("=" * 80 + "\n")

    print("# ==== CRYPTO PROFILES ====")
    #================== IKE CRYPTO PROFILE ======================#
    # set template <TEMPLATE_NAME> config network ike crypto-profiles ike-crypto-profiles <IKE_PROFILE_NAME> encryption <ENCRYPTION_TYPE> <HASH_TYPE>
    print(
        f"set template <TEMPLATE_NAME> config network ike crypto-profiles ike-crypto-profiles IKE-PROF encryption {spec.ike_encryption}")

    # set template <TEMPLATE_NAME> config network ike crypto-profiles ike-crypto-profiles <IKE_PROFILE_NAME> authentication  <HASH_TYPE>
    print(
        f"set template <TEMPLATE_NAME> config network ike crypto-profiles ike-crypto-profiles IKE-PROF hash {spec.ike_hash}")

    # set template <TEMPLATE_NAME> config network ike crypto-profiles ike-crypto-profiles <IKE_PROFILE_NAME> dh-group <DH_GROUP>
    print(
        f"set template <TEMPLATE_NAME> config network ike crypto-profiles ike-crypto-profiles IKE-PROF dh-group {spec.ike_dh}")

    # set template <TEMPLATE_NAME> config network ike crypto-profiles ike-crypto-profiles <IKE_PROFILE_NAME> lifetime seconds <TIME>
    print(
        f"set template <TEMPLATE_NAME> config network ike crypto-profiles ike-crypto-profiles IKE-PROF lifetime seconds {spec.ike_lifetime}")
    # =======================IPSEC CRYPTO PROFILE=============================

    # set template <TEMPLATE_NAME> config network ike crypto-profiles ipsec-crypto-profiles <IPSEC_PROFILE_NAME> esp encryption <ENCRYPTION_TYPE>
    print(
        f"set template <TEMPLATE_NAME> config network ike crypto-profiles ipsec-crypto-profiles IPSEC-PROF esp encryption {spec.ipsec_encryption}")
    # set template <TEMPLATE_NAME> config network ike crypto-profiles ipsec-crypto-profiles <IPSEC_PROFILE_NAME> esp authentication <HASH_TYPE>
    print(
        f"set template <TEMPLATE_NAME> config network ike crypto-profiles ipsec-crypto-profiles IPSEC-PROF esp authentication {spec.ipsec_auth}")

    # set template <TEMPLATE_NAME> config network ike crypto-profiles ipsec-crypto-profiles <IPSEC_PROFILE_NAME> dh-group <DH_GROUP>
    print(
        f"set template <TEMPLATE_NAME> config network ike crypto-profiles ipsec-crypto-profiles IPSEC-PROF dh-group {spec.ipsec_pfs}")
    # set template <TEMPLATE_NAME> config network ike crypto-profiles ipsec-crypto-profiles <IPSEC_PROFILE_NAME> lifetime seconds <TIME>
    print(
        f"set template <TEMPLATE_NAME> config network ike crypto-profiles ike-crypto-profiles IKE-PROF lifetime seconds {spec.ike_lifetime}")
#======================================================================
    print("\n# ==== TUNNEL INTERFACE / ZONE / VR ====")

    #set template <TEMPLATE_NAME> config network interface tunnel units tunnel.<TUNNEL_ID> comment "S2S to <PEER_NAME>"
    print(f"set template <TEMPLATE_NAME> config network interface tunnel units tunnel.10 comment \"S2S to {vpn}\"")

    #set template <TEMPLATE_NAME> config vsys <vsys1> zone <VPN_ZONE_NAME> network layer3 [ tunnel.<TUNNEL_ID> ]
    print("set template <TEMPLATE_NAME> config vsys vsys1 zone VPN-ZONE network layer3 [ tunnel.10 ]")

    #set template <TEMPLATE_NAME> config network virtual-router <VR_NAME> interface [ tunnel.<TUNNEL_ID> ]
    print("set template <TEMPLATE_NAME> config network virtual-router default interface [ tunnel.10 ]")
#======================================================================
    print("\n# ==== IKE GATEWAY ====")

    #set template <TEMPLATE_NAME> config network ike gateway GW-<PEER_NAME> authentication pre-shared-key key <PSK>
    print(
        f"set template <TEMPLATE_NAME> config network ike gateway GW-{vpn} authentication pre-shared-key key {spec.psk}")

    #set template <TEMPLATE_NAME> config network ike gateway GW-<PEER_NAME> protocol <IKE_VERSION> ike-crypto-profile <IKE_PROFILE_NAME>
    print(
        f"set template <TEMPLATE_NAME> config network ike gateway GW-{vpn} protocol {spec.ike_version} ike-crypto-profile IKE-PROF")

    #set template <TEMPLATE_NAME> config network ike gateway GW-<PEER_NAME> local-address interface <WAN_INTERFACE>
    print("set template <TEMPLATE_NAME> config network ike gateway GW-{vpn} local-address interface <WAN_INTERFACE>")

    #set template <TEMPLATE_NAME> config network ike gateway GW-<PEER_NAME> peer-address ip <PEER_PUBLIC_IP>
    print(f"set template <TEMPLATE_NAME> config network ike gateway GW-{vpn} peer-address ip {peer}")
#================================================================
    print("\n# ==== IPSEC TUNNEL ====")

    #set template <TEMPLATE_NAME> config network tunnel ipsec TUN-<PEER_NAME> tunnel-interface tunnel.<TUNNEL_ID>
    print(f"set template <TEMPLATE_NAME> config network tunnel ipsec TUN-{vpn} tunnel-interface tunnel.10")

    #set template <TEMPLATE_NAME> config network tunnel ipsec TUN-<PEER_NAME> anti-replay <yes|no>
    print(f"set template <TEMPLATE_NAME> config network tunnel ipsec TUN-{vpn} anti-replay yes")

    #set template <TEMPLATE_NAME> config network tunnel ipsec TUN-<PEER_NAME> auto-key ike-gateway GW-<PEER_NAME>
    print(f"set template <TEMPLATE_NAME> config network tunnel ipsec TUN-{vpn} auto-key ike-gateway GW-{vpn}")

    #set template <TEMPLATE_NAME> config network tunnel ipsec TUN-<PEER_NAME> auto-key ipsec-crypto-profile <IPSEC_PROFILE_NAME>
    print(f"set template <TEMPLATE_NAME> config network tunnel ipsec TUN-{vpn} auto-key ipsec-crypto-profile IPSEC-PROF")
#==================================================================================
    print("\n# ==== PROXY ID (For policy-based PEER) ====")

    #set template <TEMPLATE_NAME> config network tunnel ipsec TUN-<PEER_NAME> auto-key proxy-id <PROXY_ID_NAME> local <LOCAL_SUBNET> remote <REMOTE_SUBNET> protocol <PROTOCOL>
    print(
        f"set template <TEMPLATE_NAME> config network tunnel ipsec TUN-{vpn} auto-key proxy-id VPN-1 local {local} remote {remote} protocol any")
#==================================================================================
    print("\n# ==== ROUTING ====")
    #set template <TEMPLATE_NAME> config network virtual-router <VR_NAME> routing-table ip static-route RT-to-<PEER_NAME> destination <REMOTE_SUBNET> interface tunnel.<TUNNEL_ID> metric <METRIC>
    print(
        f"set template <TEMPLATE_NAME> config network virtual-router default routing-table ip static-route RT-to-{vpn} destination {remote} interface tunnel.10 metric 10")
#==================================================================================
    print("\n# ==== SECURITY POLICY ====")
    #set device-group <DEVICE_GROUP> pre-rulebase security rules <RULE_NAME_OUT> from [ <SOURCE_ZONE> ] to [ <VPN_ZONE> ] source any destination <REMOTE_SUBNET> application any service application-default action allow
    print(
        f"set device-group <DEVICE_GROUP> pre-rulebase security rules S2S-OUT from [ trust ] to [ VPN-ZONE ] source any destination {remote} application any service application-default action allow")

    #set device-group <DEVICE_GROUP> pre-rulebase security rules <RULE_NAME_IN> from [ <VPN_ZONE> ] to [ <DEST_ZONE> ] source <REMOTE_SUBNET> destination any application any service application-default action allow
    print(
        f"set device-group <DEVICE_GROUP> pre-rulebase security rules S2S-IN from [ VPN-ZONE ] to [ trust ] source {remote} destination any application any service application-default action allow")

    print("\n" + "=" * 80 + "\n")


# =============================================================================
# [MAIN MODULE]
# =============================================================================

def main() -> None:
    excel_path = strip_wrapping_quotes(input(f"Excel file path [{DEFAULT_EXCEL_FILE}]: ").strip() or DEFAULT_EXCEL_FILE)
    excel_locked_check(excel_path)

    try:
        # Read ALL sheets from Excel
        sheet_dicts = read_excel_workbook_with_table(excel_path, show_tables=True)

        if not sheet_dicts:
            raise ValueError("No valid VPN sheets found. Ensure each sheet has 'VPN Tunnel' and 'VPN Peer IP Address'.")

        failures: List[Tuple[str, str]] = []

        # Process each sheet
        for sheet, chosen in sheet_dicts:
            try:
                spec = build_spec_from_chosen(sheet, chosen)
                generate_cli_commands(spec)
            except Exception as e:
                failures.append((sheet, str(e)))
                print(f"\n❌ ERROR [{sheet}]: {e}\n")
                if DEBUG_TRACEBACK:
                    traceback.print_exc()
                print("Continuing to next sheet...\n")

        # Summary
        print("\n" + "=" * 80)
        print("📊 PROCESSING SUMMARY")
        print("=" * 80)
        print(f"✅ Successfully processed: {len(sheet_dicts) - len(failures)} sheets")
        if failures:
            print(f"❌ Failed: {len(failures)} sheets")
            for sheet, msg in failures:
                print(f"   - {sheet}: {msg}")
            sys.exit(2)
        else:
            print("✅ All VPNs processed successfully!")
        print("=" * 80 + "\n")

    except Exception as e:
        print("\n❌ FATAL ERROR:", e)
        if DEBUG_TRACEBACK:
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()