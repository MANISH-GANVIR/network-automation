import re
from typing import List, Tuple, Optional

import time
import re

from backend.projects.vpn_automation.asa.client import disconnect_asa
# =========================# =========================# =========================
WARN_REMOTE_ADD = "⚠️ WARNING: Adding a remote subnet may impact production VPN traffic. Use change window and update remote side."
WARN_REMOTE_REPLACE = "🚨 WARNING: Replacing an active VPN remote subnet may impact traffic. Use change window and update remote side."
# =========================# =========================# =========================
WARN_LOCAL_ADD = "⚠️ WARNING: VPN traffic may be impacted if remote side is not updated. Do you want to proceed?"
WARN_LOCAL_REPLACE = "🚨 WARNING: VPN traffic may be impacted if remote side is not updated. Do you want to proceed?"
# =========================# =========================# =========================

# =========================
# Session init (pager off)
# Call this ONCE at the start of update_vpn(conn)
# =========================
def _session_init(conn) -> None:
    try:
        conn.send_command("terminal pager 0")
    except Exception:
        pass


# =========================
# Show-command retry wrapper (ONLY for show commands)
# - Max 2 attempts
# - Small delay between retries
# - No retries for config commands
# =========================
def _show(conn, cmd: str) -> str:
    last_exc = None
    for attempt in (1, 2):
        try:
            out = conn.send_command(cmd)
            return out if out is not None else ""
        except Exception as e:
            last_exc = e
            if attempt == 1:
                time.sleep(0.35)
    return f"__ERROR__:{last_exc}"


# =========================
# Robust tunnel-group existence check with fallback
# Primary:
#   regex on `show run tunnel-group <peer_ip>` output:
#     ^\s*tunnel-group\s+<peer_ip>\b
# Fallback (only if primary output is empty/partial):
#   show run tunnel-group | include ^tunnel-group <peer_ip>
# =========================
def _tunnel_group_exists(conn, peer_ip: str) -> bool:
    peer_ip = (peer_ip or "").strip()
    if not peer_ip:
        return False

    pat = re.compile(rf"^\s*tunnel-group\s+{re.escape(peer_ip)}\b", re.IGNORECASE)

    primary = _show(conn, f"show run tunnel-group {peer_ip}")
    if primary and not primary.startswith("__ERROR__:"):
        for line in primary.splitlines():
            if pat.search(line):
                return True

        # If we got *some* output but no match, treat as "not found" (not a paging fallback case)
        return False

    # Fallback only when output is empty or error (likely paging/partial/transport quirk)
    fallback = _show(conn, f"show run tunnel-group | include ^tunnel-group {peer_ip}")
    if fallback and not fallback.startswith("__ERROR__:"):
        for line in fallback.splitlines():
            if pat.search(line):
                return True

    return False
# =========================
# Validation helpers
# =========================

_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def _is_valid_ipv4(ip: str) -> bool:
    ip = (ip or "").strip()
    if not ip or not _IPV4_RE.match(ip):
        return False
    parts = ip.split(".")
    try:
        nums = [int(p) for p in parts]
    except ValueError:
        return False
    return all(0 <= n <= 255 for n in nums)


def _is_valid_netmask(mask: str) -> bool:
    mask = (mask or "").strip()
    if not _is_valid_ipv4(mask):
        return False
    parts = [int(p) for p in mask.split(".")]
    bits = "".join(f"{p:08b}" for p in parts)
    return "01" not in bits


def _normalize_ws(s: str) -> str:
    return "\n".join(line.rstrip() for line in (s or "").splitlines()).strip()


def _confirm(prompt: str) -> bool:
    import os

    # 🔥 WEB MODE: Auto-continue (no user input)
    if os.getenv("WEB_MODE") == "1":
        print("[WEB_MODE] Auto-continuing (override enabled)")
        return True

    # CLI MODE: Ask user
    while True:
        ans = input(prompt).strip().lower()
        if ans in ("y", "yes"):
            return True
        if ans in ("n", "no"):
            return False
        print("[INFO] Please enter 'y' or 'n'.")


# =========================
# ASA command helpers
# =========================

def _show(conn, cmd: str) -> str:
    try:
        out = conn.send_command(cmd)
        return out if out is not None else ""
    except Exception as e:
        return f"__ERROR__:{e}"


def _lines(text: str) -> List[str]:
    return [ln.rstrip("\r") for ln in (text or "").splitlines()]


# =========================
# Robust detection & parsing
# =========================

def _tunnel_group_exists(show_run_tg: str, peer_ip: str) -> bool:
    """
    Robust detection:
    - Parse output line-by-line
    - True if any line starts with: "tunnel-group <peer_ip>"
    - Avoid brittle substring "in" matching
    """
    if not show_run_tg or show_run_tg.startswith("__ERROR__:"):
        return False
    prefix = f"tunnel-group {peer_ip}".lower()
    for ln in _lines(show_run_tg):
        s = ln.strip()
        if s.lower().startswith(prefix):
            return True
    return False


def _extract_psk_masked(_: str) -> str:
    return "*****"


def _parse_crypto_map_run(crypto_map_run: str) -> List[dict]:
    """
    Parse 'show run crypto map' lines into map entries keyed by (name, seq).
    Returns list of dicts:
      {
        "name": str, "seq": str,
        "peer": Optional[str],
        "match_acl": Optional[str],
        "pfs": Optional[str],
        "transform_set": Optional[str],
        "reverse_route": bool,
        "lifetime_kb_unlimited": bool,
        "raw_lines": [str]
      }
    Robust:
    - line-by-line startswith("crypto map ")
    - no substring-only logic for identification
    """
    if not crypto_map_run or crypto_map_run.startswith("__ERROR__:"):
        return []

    entries: dict[tuple[str, str], dict] = {}

    for ln in _lines(crypto_map_run):
        s = ln.strip()
        if not s.lower().startswith("crypto map "):
            continue

        parts = s.split()
        if len(parts) < 5:
            continue

        # crypto map <name> <seq> <rest...>
        name = parts[2]
        seq = parts[3]

        key = (name, seq)
        if key not in entries:
            entries[key] = {
                "name": name,
                "seq": seq,
                "peer": None,
                "match_acl": None,
                "pfs": None,
                "transform_set": None,
                "reverse_route": False,
                "lifetime_kb_unlimited": False,
                "raw_lines": [],
            }

        entries[key]["raw_lines"].append(s)

        # match address
        if len(parts) >= 7 and parts[4].lower() == "match" and parts[5].lower() == "address":
            entries[key]["match_acl"] = parts[6]
            continue

        # set ...
        if parts[4].lower() == "set":
            # set peer <ip>
            if len(parts) >= 7 and parts[5].lower() == "peer":
                entries[key]["peer"] = parts[6]
                continue
            # set pfs groupX
            if len(parts) >= 7 and parts[5].lower() == "pfs":
                entries[key]["pfs"] = parts[6]
                continue
            # set ikev1 transform-set NAME
            if len(parts) >= 8 and parts[5].lower() == "ikev1" and parts[6].lower() == "transform-set":
                entries[key]["transform_set"] = parts[7]
                continue
            # set reverse-route
            if len(parts) >= 6 and parts[5].lower() == "reverse-route":
                entries[key]["reverse_route"] = True
                continue
            # set security-association lifetime kilobytes unlimited
            if (
                len(parts) >= 9
                and parts[5].lower() == "security-association"
                and parts[6].lower() == "lifetime"
                and parts[7].lower() == "kilobytes"
                and parts[8].lower() == "unlimited"
            ):
                entries[key]["lifetime_kb_unlimited"] = True
                continue

    return list(entries.values())


def _get_crypto_map_for_peer(conn, peer_ip: str) -> Optional[Tuple[str, str]]:
    crypto_map_run = _show(conn, "show run crypto map")
    if crypto_map_run.startswith("__ERROR__:"):
        return None
    for entry in _parse_crypto_map_run(crypto_map_run):
        if entry.get("peer") == peer_ip:
            return entry["name"], entry["seq"]
    return None


def _get_phase2_section_text(conn, map_name: str, seq: str) -> str:
    crypto_map_run = _show(conn, "show run crypto map")
    if crypto_map_run.startswith("__ERROR__:"):
        return crypto_map_run
    prefix = f"crypto map {map_name} {seq} ".lower()
    lines = []
    for ln in _lines(crypto_map_run):
        s = ln.strip()
        if s.lower().startswith(prefix):
            lines.append(s)
    return _normalize_ws("\n".join(lines))


def _get_transform_set_for_map_seq(crypto_map_run: str, map_name: str, seq: str) -> Optional[str]:
    for entry in _parse_crypto_map_run(crypto_map_run):
        if entry["name"] == map_name and entry["seq"] == str(seq):
            return entry.get("transform_set")
    return None


def _get_acl_name_for_map_seq(conn, map_name: str, seq: str) -> Optional[str]:
    crypto_map_run = _show(conn, "show run crypto map")
    if crypto_map_run.startswith("__ERROR__:"):
        return None
    for entry in _parse_crypto_map_run(crypto_map_run):
        if entry["name"] == map_name and entry["seq"] == str(seq):
            return entry.get("match_acl")
    return None


def _parse_acl_subnet_pairs(acl_run: str) -> List[Tuple[str, str, str, str]]:
    """
    Parse ONLY subnet-based ACL lines like:
      access-list NAME extended permit ip 192.168.10.0 255.255.255.0 10.2.5.0 255.255.255.0
    Ignore object-group lines; preserve them (we won't delete them anyway).
    """
    pairs: List[Tuple[str, str, str, str]] = []
    if not acl_run or acl_run.startswith("__ERROR__:"):
        return pairs

    for ln in _lines(acl_run):
        s = ln.strip()
        if not s.lower().startswith("access-list "):
            continue
        if "object-group" in s.lower():
            continue
        m = re.search(
            r"^access-list\s+\S+\s+extended\s+permit\s+ip\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*$",
            s,
            re.IGNORECASE,
        )
        if not m:
            continue
        l_ip, l_mask, r_ip, r_mask = m.group(1), m.group(2), m.group(3), m.group(4)
        if _is_valid_ipv4(l_ip) and _is_valid_netmask(l_mask) and _is_valid_ipv4(r_ip) and _is_valid_netmask(r_mask):
            pairs.append((l_ip, l_mask, r_ip, r_mask))
    return pairs

def _parse_object_networks(show_run: str) -> dict:
    """
    Parse object network definitions from show run output.
    Returns:
      {
        "10.2.5.0_24": ("10.2.5.0", "255.255.255.0"),
        ...
      }
    Supports:
      object network NAME
       subnet A.B.C.D W.X.Y.Z
      object network NAME
       host A.B.C.D   (mask treated as 255.255.255.255)
    """
    objs: dict[str, tuple[str, str]] = {}
    if not show_run or show_run.startswith("__ERROR__:"):
        return objs

    current = None
    for ln in _lines(show_run):
        s = ln.rstrip()
        m = re.match(r"^\s*object network\s+(\S+)\s*$", s, re.IGNORECASE)
        if m:
            current = m.group(1)
            continue

        if current:
            m2 = re.match(r"^\s*subnet\s+(\S+)\s+(\S+)\s*$", s, re.IGNORECASE)
            if m2 and _is_valid_ipv4(m2.group(1)) and _is_valid_netmask(m2.group(2)):
                objs[current] = (m2.group(1), m2.group(2))
                current = None
                continue

            m3 = re.match(r"^\s*host\s+(\S+)\s*$", s, re.IGNORECASE)
            if m3 and _is_valid_ipv4(m3.group(1)):
                objs[current] = (m3.group(1), "255.255.255.255")
                current = None
                continue

    return objs

def find_local_object_name(conn, ip, mask):
    output = conn.send_command("show run object network")

    current_obj = None
    for line in output.splitlines():
        line = line.strip()

        if line.startswith("object network"):
            current_obj = line.split()[-1]

        elif line.startswith("subnet") and current_obj:
            parts = line.split()
            if parts[1] == ip and parts[2] == mask:
                return current_obj

    return None

def _parse_object_group_network_members(show_run: str, group_name: str) -> list[str]:
    """
    Parse:
      object-group network <GROUP>
       network-object object <OBJNAME>
    Returns list of object names referenced by the group.
    """
    members: list[str] = []
    if not show_run or show_run.startswith("__ERROR__:") or not group_name:
        return members

    in_group = False
    for ln in _lines(show_run):
        s = ln.strip()

        if re.match(rf"^object-group\s+network\s+{re.escape(group_name)}\s*$", s, re.IGNORECASE):
            in_group = True
            continue

        if in_group:
            # next object-group starts -> stop
            if re.match(r"^object-group\s+", s, re.IGNORECASE):
                break

            m = re.match(r"^network-object\s+object\s+(\S+)\s*$", s, re.IGNORECASE)
            if m:
                members.append(m.group(1))
    return members


def _find_remote_object_group_from_acl(acl_run: str, acl_name: str) -> Optional[str]:
    """
    If ACL contains:
      access-list <acl_name> ... permit ip object-group <LOCAL_GRP> object-group <REMOTE_GRP>
    Return <REMOTE_GRP>.
    """
    if not acl_run or acl_run.startswith("__ERROR__:"):
        return None

    for ln in _lines(acl_run):
        s = ln.strip()
        m = re.match(
            rf"^access-list\s+{re.escape(acl_name)}\s+extended\s+permit\s+ip\s+object-group\s+\S+\s+object-group\s+(\S+)\s*$",
            s,
            re.IGNORECASE,
        )
        if m:
            return m.group(1)
    return None


def _format_subnet(ip: str, mask: str) -> str:
    return f"{ip} {mask}"


def _remote_exists_everywhere(remote_ip: str, remote_mask: str,
                              direct_pairs: list[tuple[str, str, str, str]],
                              og_remote_subnets: list[tuple[str, str]]) -> bool:
    # direct ACL
    for (_l_ip, _l_mask, r_ip, r_mask) in direct_pairs:
        if r_ip == remote_ip and r_mask == remote_mask:
            return True
    # object-group resolved
    for (r_ip, r_mask) in og_remote_subnets:
        if r_ip == remote_ip and r_mask == remote_mask:
            return True
    return False


def _unique_remote_subnets(direct_pairs: list[tuple[str, str, str, str]],
                           og_remote_subnets: list[tuple[str, str]]) -> list[tuple[str, str]]:
    s = set()
    for (_l_ip, _l_mask, r_ip, r_mask) in direct_pairs:
        s.add((r_ip, r_mask))
    for (r_ip, r_mask) in og_remote_subnets:
        s.add((r_ip, r_mask))
    return sorted(s)


def _best_effort_rollback(conn, cmds: list[str]) -> None:
    """
    Best-effort rollback:
    expects cmds are the *reverse* commands (e.g. 'no access-list ...', 'no network-object ...').
    """
    if not cmds:
        return
    try:
        print("\n[ROLLBACK] Attempting best-effort rollback...\n")
        conn.send_config_set(cmds)
        try:
            conn.save_config()
        except Exception:
            pass
        print("[ROLLBACK] Completed (best-effort).")
    except Exception as e:
        print(f"[ROLLBACK] Failed (best-effort): {e}")




def _display_current_config(peer_ip: str,
                            acl_name: Optional[str],
                            acl_pairs: List[Tuple[str, str, str, str]],
                            map_name: Optional[str],
                            seq: Optional[str],
                            transform_set: Optional[str],
                            psk_masked: str,
                            conn=None) -> None:
    print("\n================ CURRENT VPN CONFIG (BEFORE UPDATE) ================\n")
    print(f"Peer IP              : {peer_ip}")

    if acl_name:
        print(f"Encryption-Domain ACL : {acl_name}")
    else:
        print("Encryption-Domain ACL : N/A")

    local_direct = sorted({(l_ip, l_mask) for (l_ip, l_mask, _, _) in acl_pairs})
    remote_direct = sorted({(r_ip, r_mask) for (_, _, r_ip, r_mask) in acl_pairs})

    og_remote_subnets: list[tuple[str, str]] = []
    if conn and acl_name:
        acl_run = _show(conn, f"show run access-list {acl_name}")
        remote_group = _find_remote_object_group_from_acl(acl_run, acl_name)
        if remote_group:
            full_run = _show(conn, "show run")
            obj_map = _parse_object_networks(full_run)
            og_members = _parse_object_group_network_members(full_run, remote_group)
            for obj_name in og_members:
                if obj_name in obj_map:
                    og_remote_subnets.append(obj_map[obj_name])

    all_remotes = sorted(set(remote_direct) | set(og_remote_subnets))

    print("\nLocal Subnet(s):")
    if local_direct:
        for (l_ip, l_mask) in local_direct:
            print(f"  - {l_ip} {l_mask}")
    else:
        print("  - N/A")

    print("\nRemote Subnet(s):")
    if all_remotes:
        for (r_ip, r_mask) in all_remotes:
            print(f"  - {r_ip} {r_mask}")
    else:
        print("  - N/A")

    print("\nPhase-2 Encryption:")
    if map_name and seq:
        print(f"  Crypto Map         : {map_name} {seq}")
    else:
        print("  Crypto Map         : N/A")
    print(f"  IKEv1 Transform-Set: {transform_set or 'N/A'}")

    print("\nPre-Shared Key:")
    print(f"  ikev1 pre-shared-key {psk_masked}")

    print("\n=====================================================================\n")


# =========================
# Menu helpers
# =========================

def _prompt_menu_choice() -> str:
    print("What VPN setting do you want to update?\n")
    print("1) Update Peer IP (ADD new peer; keep old)")
    print("2) Update Local Subnet (ADD)")
    print("3) Update Remote Subnet (ADD)")
    print("4) Update Phase-2 Encryption (MODIFY if different)")
    print("5) Update Pre-Shared Key (MODIFY)")
    print("6) Cancel")
    return input("\nSelect an option (1-6): ").strip()


def _peer_ip_duplicate_exists(conn, new_peer_ip: str) -> bool:
    out = _show(conn, f"show run tunnel-group {new_peer_ip}")
    return _tunnel_group_exists(out, new_peer_ip)


def _prompt_acl_name_if_missing(existing_acl_name: Optional[str]) -> Optional[str]:
    if existing_acl_name:
        return existing_acl_name
    acl_name = input("Enter Encryption-Domain ACL name (required for subnet update) (or n to cancel): ").strip()
    if acl_name.lower() == "n" or not acl_name:
        return None
    return acl_name


# =========================
# Update operations (NON-DESTRUCTIVE)
# =========================

def _update_peer_ip_add(conn, existing_peer_ip: str, new_peer_ip: str) -> bool:
    cm = _get_crypto_map_for_peer(conn, existing_peer_ip)
    crypto_map_run = _show(conn, "show run crypto map")
    if crypto_map_run.startswith("__ERROR__:"):
        print("[ERROR] Failed to read crypto map configuration.")
        return False
    if not cm:
        print("[ERROR] Could not locate crypto map entry for the existing peer; cannot clone settings.")
        return False

    map_name, seq_str = cm
    parsed_entries = _parse_crypto_map_run(crypto_map_run)

    base_entry = None
    for e in parsed_entries:
        if e["name"] == map_name and e["seq"] == seq_str:
            base_entry = e
            break
    if not base_entry:
        print("[ERROR] Failed to parse base crypto map entry.")
        return False

    acl_name = base_entry.get("match_acl")
    pfs = base_entry.get("pfs")
    ts = base_entry.get("transform_set")
    lifetime_unlimited = bool(base_entry.get("lifetime_kb_unlimited"))
    reverse_route = bool(base_entry.get("reverse_route"))

    existing_seqs = set()
    for e in parsed_entries:
        if e["name"] == map_name:
            try:
                existing_seqs.add(int(e["seq"]))
            except Exception:
                pass
    new_seq = (max(existing_seqs) + 1) if existing_seqs else 1
    while new_seq in existing_seqs:
        new_seq += 1

    before_full = _normalize_ws(_show(conn, "show run crypto map"))

    # Preserve default-group-policy from existing tunnel-group
    tg_cfg = _show(conn, f"show run tunnel-group {existing_peer_ip}")
    gp_line = None
    for ln in _lines(tg_cfg):
        s = ln.strip()
        if s.lower().startswith("default-group-policy "):
            gp_line = s
            break

    cmds: List[str] = []
    if acl_name:
        cmds.append(f"crypto map {map_name} {new_seq} match address {acl_name}")
    cmds.append(f"crypto map {map_name} {new_seq} set peer {new_peer_ip}")
    if pfs:
        cmds.append(f"crypto map {map_name} {new_seq} set pfs {pfs}")
    if ts:
        cmds.append(f"crypto map {map_name} {new_seq} set ikev1 transform-set {ts}")
    if lifetime_unlimited:
        cmds.append(f"crypto map {map_name} {new_seq} set security-association lifetime kilobytes unlimited")
    if reverse_route:
        cmds.append(f"crypto map {map_name} {new_seq} set reverse-route")

    cmds.append(f"tunnel-group {new_peer_ip} type ipsec-l2l")
    cmds.append(f"tunnel-group {new_peer_ip} general-attributes")
    if gp_line:
        cmds.append(gp_line)

    conn.send_config_set(cmds)
    try:
        conn.save_config()
    except Exception:
        pass

    after_full = _normalize_ws(_show(conn, "show run crypto map"))

    print("\n================ CHANGE CONTROL (Update Peer IP - NON-DESTRUCTIVE) ================\n")
    print("----- BEFORE (show run crypto map) -----")
    print(before_full or "N/A")
    print("\n----- AFTER  (show run crypto map) -----")
    print(after_full or "N/A")
    print("\n==================================================================================\n")
    return True


def _update_local_subnet_add(conn, acl_name: str, acl_pairs: List[Tuple[str, str, str, str]],
                             new_local_ip: str, new_local_mask: str) -> bool:
    before_full = _normalize_ws(_show(conn, f"show run access-list {acl_name}"))

    local_exists = any(l_ip == new_local_ip and l_mask == new_local_mask for (l_ip, l_mask, _, _) in acl_pairs)
    if local_exists:
        print("[WARNING] Local subnet already configured.")
        if not _confirm("Do you still want to continue? (y/n): "):
            print("[INFO] Update cancelled.")
            return False

    remotes = sorted({(r_ip, r_mask) for (_, _, r_ip, r_mask) in acl_pairs})
    existing_full = set(acl_pairs)

    cmds: List[str] = []
    for r_ip, r_mask in remotes:
        if (new_local_ip, new_local_mask, r_ip, r_mask) in existing_full:
            continue
        cmds.append(f"access-list {acl_name} extended permit ip {new_local_ip} {new_local_mask} {r_ip} {r_mask}")

    if cmds:
        conn.send_config_set(cmds)
        try:
            conn.save_config()
        except Exception:
            pass

    after_full = _normalize_ws(_show(conn, f"show run access-list {acl_name}"))

    print("\n================ CHANGE CONTROL (Update Local Subnet - NON-DESTRUCTIVE) ================\n")
    print("----- BEFORE (show run access-list) -----")
    print(before_full or "N/A")
    print("\n----- AFTER  (show run access-list) -----")
    print(after_full or "N/A")
    print("\n=======================================================================================\n")
    return True


def _ensure_object_network_exists(conn, obj_name: str, ip: str, mask: str) -> bool:
    """
    Idempotent: if object exists with same subnet -> ok.
    If object exists with different subnet -> do NOT modify (safe).
    If not exists -> create.
    """
    show_run = _show(conn, f"show run object network {obj_name}")
    if show_run and not show_run.startswith("__ERROR__:") and f"object network {obj_name}" in show_run:
        # object exists; check if subnet already matches
        if re.search(rf"\bsubnet\s+{re.escape(ip)}\s+{re.escape(mask)}\b", show_run):
            return True
        print(f"[ERROR] Object '{obj_name}' already exists with different subnet. Aborting to prevent conflict.")
        return False

    cmds = [
        f"object network {obj_name}",
        f"subnet {ip} {mask}",
    ]
    conn.send_config_set(cmds)
    return True


def _object_name_for_subnet(ip: str, mask: str) -> str:
    """
    Follow existing naming convention seen in config: 10.2.5.0_24
    We'll generate *_24 only for /24 masks; else use mask replaced.
    """
    if mask == "255.255.255.0":
        return f"{ip}_24"
    # generic
    safe_mask = mask.replace(".", "_")
    return f"{ip}_{safe_mask}"


def _add_remote_subnet_objectgroup_mode(conn, acl_name: str,
                                       local_subnets: list[tuple[str, str]],
                                       remote_ip: str, remote_mask: str,
                                       remote_group: str) -> bool:
    """
    Add new remote subnet by:
      - creating object network
      - adding it to remote object-group
      - ensuring direct ACL lines exist for each local subnet (idempotent)
    """
    show_run = _show(conn, "show run")
    objects = _parse_object_networks(show_run)

    obj_name = _object_name_for_subnet(remote_ip, remote_mask)

    # If object exists but points elsewhere: fail safe
    if obj_name in objects and objects[obj_name] != (remote_ip, remote_mask):
        print(f"[ERROR] Object '{obj_name}' exists but subnet mismatch. Aborting.")
        return False

    # Create object if needed
    if not _ensure_object_network_exists(conn, obj_name, remote_ip, remote_mask):
        return False

    # Add to object-group if not already
    og_run = _show(conn, f"show run object-group id {remote_group}")
    already_member = re.search(rf"\bnetwork-object\s+object\s+{re.escape(obj_name)}\b", og_run or "", re.IGNORECASE)
    if not already_member:
        conn.send_config_set([
            f"object-group network {remote_group}",
            f"network-object object {obj_name}",
        ])

    # Ensure ACL lines exist for each local subnet (direct permit ip local remote)
    acl_run = _show(conn, f"show run access-list {acl_name}")
    direct_pairs = _parse_acl_subnet_pairs(acl_run)
    existing = set(direct_pairs)

    add_cmds: list[str] = []
    for (l_ip, l_mask) in local_subnets:
        if (l_ip, l_mask, remote_ip, remote_mask) in existing:
            continue
        add_cmds.append(f"access-list {acl_name} extended permit ip {l_ip} {l_mask} {remote_ip} {remote_mask}")

    if add_cmds:
        conn.send_config_set(add_cmds)

    try:
        conn.save_config()
    except Exception:
        pass

    return True


def _replace_remote_subnet_direct_acl(conn, acl_name: str,
                                     local_subnets: list[tuple[str, str]],
                                     old_remote: tuple[str, str],
                                     new_remote: tuple[str, str]) -> bool:
    old_ip, old_mask = old_remote
    new_ip, new_mask = new_remote

    # BEFORE snapshot (production-style evidence)
    before_full = _normalize_ws(_show(conn, f"show run access-list {acl_name}"))

    # Build forward + rollback commands (idempotent)
    forward: list[str] = []
    rollback: list[str] = []

    for (l_ip, l_mask) in local_subnets:
        # Remove old
        forward.append(f"no access-list {acl_name} extended permit ip {l_ip} {l_mask} {old_ip} {old_mask}")
        # Add new
        forward.append(f"access-list {acl_name} extended permit ip {l_ip} {l_mask} {new_ip} {new_mask}")

        # Rollback (reverse)
        rollback.append(f"no access-list {acl_name} extended permit ip {l_ip} {l_mask} {new_ip} {new_mask}")
        rollback.append(f"access-list {acl_name} extended permit ip {l_ip} {l_mask} {old_ip} {old_mask}")

    try:
        # Apply
        conn.send_config_set(forward)

        # Commit
        try:
            conn.save_config()
        except Exception:
            pass

        # AFTER snapshot
        after_full = _normalize_ws(_show(conn, f"show run access-list {acl_name}"))

        # Production-style change control output
        print("\n================ CHANGE CONTROL (Replace Remote Subnet) ================\n")
        print(f"ACL Name   : {acl_name}")
        print(f"Replaced   : {old_ip} {old_mask}  →  {new_ip} {new_mask}")
        print("\n----- COMMANDS APPLIED -----")
        for c in forward:
            print(c)

        print("\n----- BEFORE (show run access-list) -----")
        print(before_full or "N/A")
        print("\n----- AFTER  (show run access-list) -----")
        print(after_full or "N/A")
        print("\n=======================================================================\n")

        # Quick verification: ensure old removed and new present (best-effort)
        if f"{old_ip} {old_mask}" in (after_full or "") and f"{new_ip} {new_mask}" not in (after_full or ""):
            print("[WARNING] Post-check indicates ACL may not have updated as expected. Please verify manually.\n")

        # 🔥 OBJECT-GROUP CLEANUP - Replace mode
        acl_run_check = _show(conn, f"show run access-list {acl_name}")
        remote_group_check = _find_remote_object_group_from_acl(acl_run_check, acl_name)

        if remote_group_check:
            print(f"\n[INFO] Attempting to update object-group: {remote_group_check}")

            old_obj_name = _object_name_for_subnet(old_ip, old_mask)
            new_obj_name = _object_name_for_subnet(new_ip, new_mask)

            try:
                conn.send_config_set([
                    f"object-group network {remote_group_check}",
                    f"no network-object object {old_obj_name}"
                ])
                print(f"[SUCCESS] Removed {old_obj_name} from {remote_group_check}")
            except Exception as og_err:
                print(f"[WARNING] Could not remove from object-group: {og_err}")

            try:
                conn.send_config_set([
                    f"object network {new_obj_name}",
                    f"subnet {new_ip} {new_mask}",
                    f"object-group network {remote_group_check}",
                    f"network-object object {new_obj_name}"
                ])
                print(f"[SUCCESS] Added {new_obj_name} to {remote_group_check}")
            except Exception as og_err:
                print(f"[WARNING] Could not add to object-group: {og_err}")

        return True


    except Exception as e:
        print(f"[ERROR] Replace failed: {e}")
        _best_effort_rollback(conn, rollback)
        return False


def _update_remote_subnet_add(conn, acl_name: str, acl_pairs: List[Tuple[str, str, str, str]],
                              new_remote_ip: str, new_remote_mask: str) -> bool:
    before_full = _normalize_ws(_show(conn, f"show run access-list {acl_name}"))

    remote_exists = any(r_ip == new_remote_ip and r_mask == new_remote_mask for (_, _, r_ip, r_mask) in acl_pairs)
    if remote_exists:
        print("[WARNING] Remote subnet already configured.")
        if not _confirm("Do you still want to continue? (y/n): "):
            print("[INFO] Update cancelled.")
            return False

    locals_ = sorted({(l_ip, l_mask) for (l_ip, l_mask, _, _) in acl_pairs})
    existing_full = set(acl_pairs)

    cmds: List[str] = []
    for l_ip, l_mask in locals_:
        if (l_ip, l_mask, new_remote_ip, new_remote_mask) in existing_full:
            continue
        cmds.append(f"access-list {acl_name} extended permit ip {l_ip} {l_mask} {new_remote_ip} {new_remote_mask}")

    if cmds:
        conn.send_config_set(cmds)
        try:
            conn.save_config()
        except Exception:
            pass

    after_full = _normalize_ws(_show(conn, f"show run access-list {acl_name}"))

    print("\n================ CHANGE CONTROL (Update Remote Subnet - NON-DESTRUCTIVE) ================\n")
    print("----- BEFORE (show run access-list) -----")
    print(before_full or "N/A")
    print("\n----- AFTER  (show run access-list) -----")
    print(after_full or "N/A")
    print("\n========================================================================================\n")
    return True


def _update_phase2_encryption_modify(conn, map_name: str, seq: str, new_transform_set: str) -> bool:
    crypto_map_run = _show(conn, "show run crypto map")
    if crypto_map_run.startswith("__ERROR__:"):
        print("[ERROR] Failed to read crypto map configuration.")
        return False

    current_ts = _get_transform_set_for_map_seq(crypto_map_run, map_name, seq)
    if current_ts and current_ts.strip() == new_transform_set.strip():
        print("[INFO] Phase-2 encryption already configured.")
        return False

    before_full = _normalize_ws(_show(conn, "show run crypto map"))

    conn.send_config_set([f"crypto map {map_name} {seq} set ikev1 transform-set {new_transform_set}"])
    try:
        conn.save_config()
    except Exception:
        pass

    after_full = _normalize_ws(_show(conn, "show run crypto map"))

    print("\n================ CHANGE CONTROL (Update Phase-2 Encryption) ================\n")
    print("----- BEFORE (show run crypto map) -----")
    print(before_full or "N/A")
    print("\n----- AFTER  (show run crypto map) -----")
    print(after_full or "N/A")
    print("\n============================================================================\n")
    return True


def _update_psk_modify(conn, peer_ip: str, new_psk: str) -> bool:
    print("[WARNING] Pre-Shared Key will be updated.")
    if not _confirm("Do you want to continue? (y/n): "):
        print("[INFO] Update cancelled.")
        return False

    before_full = _normalize_ws(_show(conn, f"show run tunnel-group {peer_ip}"))

    conn.send_config_set([
        f"tunnel-group {peer_ip} ipsec-attributes",
        f"ikev1 pre-shared-key {new_psk}",
    ])
    try:
        conn.save_config()
    except Exception:
        pass

    after_full = _normalize_ws(_show(conn, f"show run tunnel-group {peer_ip}"))

    print("\n================ CHANGE CONTROL (Update Pre-Shared Key) ================\n")
    print("----- BEFORE (show run tunnel-group) -----")
    print(before_full or "N/A")
    print("\n----- AFTER  (show run tunnel-group) -----")
    print(after_full or "N/A")
    print("\n=======================================================================\n")
    return True


# =========================
# Public entrypoint
# =========================

def update_vpn(conn, payload=None):

    conn_ref = None
    try:
        conn_ref = conn

        if payload is None:
            peer_ip = input("Enter Peer IP of VPN you want to update: ").strip()
        else:
            peer_ip = payload.get("peer_ip", "").strip()
            print(f"Enter Peer IP of VPN you want to update: {peer_ip}")

        if peer_ip.lower() == "n" or not peer_ip:
            print("[INFO] Update cancelled.")
            return
        if not _is_valid_ipv4(peer_ip):
            print("[ERROR] Invalid Peer IP format.")
            return

        tg_cfg = _show(conn_ref, f"show run tunnel-group {peer_ip}")
        if not _tunnel_group_exists(tg_cfg, peer_ip):
            print(f"[ERROR] Tunnel-group for peer '{peer_ip}' not found on ASA. Update aborted.")
            return

        cm = _get_crypto_map_for_peer(conn_ref, peer_ip)
        crypto_map_run = _show(conn_ref, "show run crypto map")

        map_name = seq = None
        acl_name = None
        transform_set = None

        if cm and not crypto_map_run.startswith("__ERROR__:"):
            map_name, seq = cm
            acl_name = _get_acl_name_for_map_seq(conn_ref, map_name, seq)
            transform_set = _get_transform_set_for_map_seq(crypto_map_run, map_name, seq)

        acl_pairs: List[Tuple[str, str, str, str]] = []
        if acl_name:
            acl_run = _show(conn_ref, f"show run access-list {acl_name}")
            acl_pairs = _parse_acl_subnet_pairs(acl_run)

        psk_masked = _extract_psk_masked(tg_cfg)
        _display_current_config(
            peer_ip=peer_ip,
            acl_name=acl_name,
            acl_pairs=acl_pairs,
            map_name=map_name,
            seq=seq,
            transform_set=transform_set,
            psk_masked=psk_masked,
            conn=conn_ref,
        )
        # ================= PREVIEW MODE (WEB STEP 1) =================
        if payload is not None and payload.get("preview_only") is True:
            return
        # =============================================================

        if payload is None:
            choice = _prompt_menu_choice()
        else:
            choice = str(payload.get("choice") or payload.get("option") or "").strip()

            print("What VPN setting do you want to update?\n")
            print("1) Update Peer IP (ADD new peer; keep old)")
            print("2) Update Local Subnet (ADD)")
            print("3) Update Remote Subnet (ADD)")
            print("4) Update Phase-2 Encryption (MODIFY if different)")
            print("5) Update Pre-Shared Key (MODIFY)")
            print("6) Cancel")
            print(f"\nSelect an option (1-6): {choice}")

        if choice == "6":
            print("[INFO] Update cancelled.")
            return

        if choice == "1":
            if payload is None:
                new_peer_ip = input("What is the new Peer IP? ").strip()
            else:
                new_peer_ip = payload.get("new_peer_ip", "").strip()
                print(f"What is the new Peer IP? {new_peer_ip}")

            if not _is_valid_ipv4(new_peer_ip):
                print("[ERROR] Invalid new Peer IP format.")
                return
            if new_peer_ip == peer_ip:
                print("[INFO] New Peer IP is same as current. No change required.")
                return

            if _peer_ip_duplicate_exists(conn_ref, new_peer_ip):
                print("[WARNING] Peer IP already exists.")
                if not _confirm("Do you want to continue? (y/n): "):
                    print("[INFO] Update cancelled.")
                    return

            ok = _update_peer_ip_add(conn_ref, peer_ip, new_peer_ip)
            if ok:
                print("[SUCCESS] Peer IP update completed.")
            return

        if choice in ("2", "3"):

            # Web mode
            if payload is not None:
                acl_name2 = acl_name  # 👈 use detected ACL directly
            else:
                acl_name2 = _prompt_acl_name_if_missing(acl_name)

            if not acl_name2:
                print("[INFO] Subnet update cancelled.")
                return

            acl_run2 = _show(conn_ref, f"show run access-list {acl_name2}")
            acl_pairs2 = _parse_acl_subnet_pairs(acl_run2)

            if not acl_pairs2:
                print("[ERROR] No subnet-based ACL entries found for this ACL.")
                return

            if choice == "2":
                # ---------- Local subnet action (ADD / REPLACE / DELETE) ----------
                if payload is None:
                    print("\nLocal Subnet Options:")
                    print("1) Add New Local Subnet")
                    print("2) Replace Existing Local Subnet")
                    print("3) Delete Local Subnet")  # ✅ ADD KAR
                    sub_choice = input("\nSelect an option (1-3): ").strip()
                    local_action = "add" if sub_choice == "1" else "replace" if sub_choice == "2" else "delete" if sub_choice == "3" else ""
                else:
                    local_action = (payload.get("local_action") or "add").strip().lower()

                if local_action not in ("add", "replace", "delete"):  # ✅ "delete" add kar
                    print("[ERROR] Invalid local subnet action.")
                    return

                # Current locals/remotes from ACL (authoritative)
                existing_locals = sorted({(l_ip, l_mask) for (l_ip, l_mask, _, _) in acl_pairs2})
                existing_remotes = sorted({(r_ip, r_mask) for (_, _, r_ip, r_mask) in acl_pairs2})
                existing_full = set(acl_pairs2)

                if not existing_remotes:
                    print("[ERROR] No remote subnets found in ACL. Cannot proceed.")
                    return

                # ---------- ADD ----------
                if local_action == "add":
                    if payload is None:
                        new_local_ip = input("Enter new Local Subnet IP: ").strip()
                        new_local_mask = input("Enter new Local Subnet Mask: ").strip()
                    else:
                        new_local_ip = payload.get("new_local_ip", "").strip()
                        new_local_mask = payload.get("new_local_mask", "").strip()
                        print(f"Enter new Local Subnet IP: {new_local_ip}")
                        print(f"Enter new Local Subnet Mask: {new_local_mask}")

                    if not _is_valid_ipv4(new_local_ip) or not _is_valid_netmask(new_local_mask):
                        print("[ERROR] Invalid Local subnet IP or mask.")
                        return

                    # ✅ Confirm BEFORE applying (CLI + WEB)
                    print("\n" + WARN_LOCAL_ADD + "\n")
                    if payload is None:
                        if not _confirm("Do you want to proceed? (y/n): "):
                            print("[INFO] Add cancelled.")
                            return
                    else:
                        if payload.get("user_confirmed_local") is not True:
                            print("[INFO] Cancelled by user.")
                            return

                    ok = _update_local_subnet_add(conn_ref, acl_name2, acl_pairs2, new_local_ip, new_local_mask)
                    if ok:
                        print("[SUCCESS] Local subnet update completed.")
                        # YEH CODE COPY KARO AUR 4 LOCATIONS PE PASTE KARO:

                        # ✅ REFRESH AFTER UPDATE
                        print("\n================ CURRENT CONFIG (AFTER UPDATE) ================\n")

                        acl_run_after = _show(conn_ref, f"show run access-list {acl_name2}")
                        acl_pairs_after = _parse_acl_subnet_pairs(acl_run_after)

                        local_direct_after = sorted({(l_ip, l_mask) for (l_ip, l_mask, _, _) in acl_pairs_after})
                        remote_direct_after = sorted({(r_ip, r_mask) for (_, _, r_ip, r_mask) in acl_pairs_after})

                        og_remote_after: list[tuple[str, str]] = []
                        remote_group_after = _find_remote_object_group_from_acl(acl_run_after, acl_name2)
                        if remote_group_after:
                            full_run_after = _show(conn_ref, "show run")
                            obj_map_after = _parse_object_networks(full_run_after)
                            og_members_after = _parse_object_group_network_members(full_run_after, remote_group_after)
                            for obj_name in og_members_after:
                                if obj_name in obj_map_after:
                                    og_remote_after.append(obj_map_after[obj_name])

                        all_remotes_after = sorted(set(remote_direct_after) | set(og_remote_after))

                        print("Local Subnet(s):")
                        for (l_ip, l_mask) in local_direct_after:
                            print(f"  - {l_ip} {l_mask}")

                        print("\nRemote Subnet(s):")
                        for (r_ip, r_mask) in all_remotes_after:
                            print(f"  - {r_ip} {r_mask}")

                        print("\n==================================================================\n")
                    return

                # ---------- REPLACE ----------
                if local_action == "replace":
                    # show existing locals (CLI visibility)
                    print("\nExisting Local Subnet(s):")
                    for i, (l_ip, l_mask) in enumerate(existing_locals, start=1):
                        print(f"{i}) {l_ip} {l_mask}")

                    if payload is None:
                        old_local_ip = input("\nEnter OLD Local Subnet IP (to replace): ").strip()
                        old_local_mask = input("Enter OLD Local Subnet Mask (to replace): ").strip()
                        new_local_ip = input("Enter NEW Local Subnet IP: ").strip()
                        new_local_mask = input("Enter NEW Local Subnet Mask: ").strip()
                    else:
                        old_local_ip = (payload.get("old_local_ip") or "").strip()
                        old_local_mask = (payload.get("old_local_mask") or "").strip()
                        new_local_ip = (payload.get("new_local_ip") or "").strip()
                        new_local_mask = (payload.get("new_local_mask") or "").strip()

                        print(f"\nEnter OLD Local Subnet IP (to replace): {old_local_ip}")
                        print(f"Enter OLD Local Subnet Mask (to replace): {old_local_mask}")
                        print(f"Enter NEW Local Subnet IP: {new_local_ip}")
                        print(f"Enter NEW Local Subnet Mask: {new_local_mask}")

                    if (
                            not _is_valid_ipv4(old_local_ip) or not _is_valid_netmask(old_local_mask)
                            or not _is_valid_ipv4(new_local_ip) or not _is_valid_netmask(new_local_mask)
                    ):
                        print("[ERROR] Invalid Input")
                        return

                    old_local = (old_local_ip, old_local_mask)
                    if old_local not in existing_locals:
                        print("[ERROR] Invalid Input")
                        return

                    if (new_local_ip, new_local_mask) == old_local:
                        print("[INFO] New local subnet is same as old. No changes made.")
                        return

                    # duplicate check: new local already exists
                    if (new_local_ip, new_local_mask) in existing_locals:
                        print("[ERROR] Local subnet already exists. No changes made.")
                        return

                    # ✅ Confirm BEFORE applying (CLI + WEB)
                    print("\n--------------------------------------------------")
                    print("Please confirm that you want to replace:\n")
                    print(f"Old Local Subnet:\n{old_local_ip} {old_local_mask}\n")
                    print(f"With New Local Subnet:\n{new_local_ip} {new_local_mask}\n")
                    print("\n" + WARN_LOCAL_REPLACE + "\n")
                    print("\t1) Yes, I confirm and proceed")
                    print("\t2) No, cancel operation")
                    print("--------------------------------------------------\n")

                    if payload is None:
                        ans = input("Select an option (1-2): ").strip()
                        if ans != "1":
                            print("[INFO] Replace cancelled.")
                            return
                    else:
                        if payload.get("user_confirmed_local") is not True:
                            print("[INFO] Cancelled by user.")
                            return

                    # Apply replace: remove old local + add new local for each remote
                    before_full = _normalize_ws(_show(conn_ref, f"show run access-list {acl_name2}"))

                    forward: list[str] = []
                    rollback: list[str] = []

                    for (r_ip, r_mask) in existing_remotes:
                        # remove old pairing
                        forward.append(
                            f"no access-list {acl_name2} extended permit ip {old_local_ip} {old_local_mask} {r_ip} {r_mask}")
                        # add new pairing
                        forward.append(
                            f"access-list {acl_name2} extended permit ip {new_local_ip} {new_local_mask} {r_ip} {r_mask}")

                        # rollback reverse
                        rollback.append(
                            f"no access-list {acl_name2} extended permit ip {new_local_ip} {new_local_mask} {r_ip} {r_mask}")
                        rollback.append(
                            f"access-list {acl_name2} extended permit ip {old_local_ip} {old_local_mask} {r_ip} {r_mask}")

                    try:
                        conn_ref.send_config_set(forward)
                        try:
                            conn_ref.save_config()
                        except Exception:
                            pass
                    except Exception as e:
                        print(f"[ERROR] Replace failed: {e}")
                        _best_effort_rollback(conn_ref, rollback)
                        return

                    after_full = _normalize_ws(_show(conn_ref, f"show run access-list {acl_name2}"))

                    print("\n================ CHANGE CONTROL (Replace Local Subnet) ================\n")
                    print(f"ACL Name   : {acl_name2}")
                    print(f"Replaced   : {old_local_ip} {old_local_mask}  →  {new_local_ip} {new_local_mask}")
                    print("\n----- COMMANDS APPLIED -----")
                    for c in forward:
                        print(c)
                    print("\n----- BEFORE (show run access-list) -----")
                    print(before_full or "N/A")
                    print("\n----- AFTER  (show run access-list) -----")
                    print(after_full or "N/A")
                    print("\n=======================================================================\n")

                    print("[SUCCESS] Local subnet replaced successfully.\n")
                    # YEH CODE COPY KARO AUR 3 LOCATIONS PE PASTE KARO:

                    # ✅ REFRESH AFTER UPDATE
                    print("\n================ CURRENT CONFIG (AFTER UPDATE) ================\n")

                    acl_run_after = _show(conn_ref, f"show run access-list {acl_name2}")
                    acl_pairs_after = _parse_acl_subnet_pairs(acl_run_after)

                    local_direct_after = sorted({(l_ip, l_mask) for (l_ip, l_mask, _, _) in acl_pairs_after})
                    remote_direct_after = sorted({(r_ip, r_mask) for (_, _, r_ip, r_mask) in acl_pairs_after})

                    og_remote_after: list[tuple[str, str]] = []
                    remote_group_after = _find_remote_object_group_from_acl(acl_run_after, acl_name2)
                    if remote_group_after:
                        full_run_after = _show(conn_ref, "show run")
                        obj_map_after = _parse_object_networks(full_run_after)
                        og_members_after = _parse_object_group_network_members(full_run_after, remote_group_after)
                        for obj_name in og_members_after:
                            if obj_name in obj_map_after:
                                og_remote_after.append(obj_map_after[obj_name])

                    all_remotes_after = sorted(set(remote_direct_after) | set(og_remote_after))

                    print("Local Subnet(s):")
                    for (l_ip, l_mask) in local_direct_after:
                        print(f"  - {l_ip} {l_mask}")

                    print("\nRemote Subnet(s):")
                    for (r_ip, r_mask) in all_remotes_after:
                        print(f"  - {r_ip} {r_mask}")

                    print("\n==================================================================\n")
                    return

                # ---------- DELETE ----------
                if local_action == "delete":
                    # show existing locals (CLI visibility)
                    print("\nExisting Local Subnet(s):")
                    for i, (l_ip, l_mask) in enumerate(existing_locals, start=1):
                        print(f"{i}) {l_ip} {l_mask}")

                    if payload is None:
                        delete_local_ip = input("\nEnter Local Subnet IP (to delete): ").strip()
                        delete_local_mask = input("Enter Local Subnet Mask (to delete): ").strip()
                    else:
                        delete_local_ip = (payload.get("delete_local_ip") or "").strip()
                        delete_local_mask = (payload.get("delete_local_mask") or "").strip()

                        print(f"\nEnter Local Subnet IP (to delete): {delete_local_ip}")
                        print(f"Enter Local Subnet Mask (to delete): {delete_local_mask}")

                    if not _is_valid_ipv4(delete_local_ip) or not _is_valid_netmask(delete_local_mask):
                        print("[ERROR] Invalid Input")
                        return

                    delete_local = (delete_local_ip, delete_local_mask)
                    if delete_local not in existing_locals:
                        print("[ERROR] Local subnet not found.")
                        return

                    # ✅ Confirm BEFORE applying (CLI + WEB)
                    print("\n--------------------------------------------------")
                    print("Please confirm that you want to DELETE:\n")
                    print(f"Local Subnet:\n{delete_local_ip} {delete_local_mask}\n")
                    print("🚨 This will remove ALL related ACL entries.\n")
                    print("\t1) Yes, I confirm and proceed")
                    print("\t2) No, cancel operation")
                    print("--------------------------------------------------\n")

                    if payload is None:
                        ans = input("Select an option (1-2): ").strip()
                        if ans != "1":
                            print("[INFO] Delete cancelled.")
                            return
                    else:
                        if payload.get("user_confirmed_delete") is not True:
                            print("[INFO] Cancelled by user.")
                            return

                    # Apply delete: remove all ACL lines with this local subnet
                    before_full = _normalize_ws(_show(conn_ref, f"show run access-list {acl_name2}"))

                    forward: list[str] = []
                    rollback: list[str] = []

                    for (r_ip, r_mask) in existing_remotes:
                        # remove the ACL line
                        forward.append(
                            f"no access-list {acl_name2} extended permit ip {delete_local_ip} {delete_local_mask} {r_ip} {r_mask}")

                        # rollback - add it back
                        rollback.append(
                            f"access-list {acl_name2} extended permit ip {delete_local_ip} {delete_local_mask} {r_ip} {r_mask}")

                    try:
                        conn_ref.send_config_set(forward)
                        try:
                            conn_ref.save_config()
                        except Exception:
                            pass
                    except Exception as e:
                        print(f"[ERROR] Delete failed: {e}")
                        _best_effort_rollback(conn_ref, rollback)
                        return

                    after_full = _normalize_ws(_show(conn_ref, f"show run access-list {acl_name2}"))

                    print("\n================ CHANGE CONTROL (Delete Local Subnet) ================\n")
                    print(f"ACL Name   : {acl_name2}")
                    print(f"Deleted    : {delete_local_ip} {delete_local_mask}")
                    print("\n----- COMMANDS APPLIED -----")
                    for c in forward:
                        print(c)
                    print("\n----- BEFORE (show run access-list) -----")
                    print(before_full or "N/A")
                    print("\n----- AFTER  (show run access-list) -----")
                    print(after_full or "N/A")
                    print("\n=======================================================================\n")

                    print("[SUCCESS] Local subnet deleted successfully.\n")

                    # ✅ REFRESH AFTER UPDATE
                    print("\n================ CURRENT CONFIG (AFTER UPDATE) ================\n")

                    acl_run_after = _show(conn_ref, f"show run access-list {acl_name2}")
                    acl_pairs_after = _parse_acl_subnet_pairs(acl_run_after)

                    local_direct_after = sorted({(l_ip, l_mask) for (l_ip, l_mask, _, _) in acl_pairs_after})
                    remote_direct_after = sorted({(r_ip, r_mask) for (_, _, r_ip, r_mask) in acl_pairs_after})

                    og_remote_after: list[tuple[str, str]] = []
                    remote_group_after = _find_remote_object_group_from_acl(acl_run_after, acl_name2)
                    if remote_group_after:
                        full_run_after = _show(conn_ref, "show run")
                        obj_map_after = _parse_object_networks(full_run_after)
                        og_members_after = _parse_object_group_network_members(full_run_after, remote_group_after)
                        for obj_name in og_members_after:
                            if obj_name in obj_map_after:
                                og_remote_after.append(obj_map_after[obj_name])

                    all_remotes_after = sorted(set(remote_direct_after) | set(og_remote_after))

                    print("Local Subnet(s):")
                    for (l_ip, l_mask) in local_direct_after:
                        print(f"  - {l_ip} {l_mask}")

                    print("\nRemote Subnet(s):")
                    for (r_ip, r_mask) in all_remotes_after:
                        print(f"  - {r_ip} {r_mask}")

                    print("\n==================================================================\n")
                    return
            if choice == "3":
                # ========= Remote subnet sub-options (ADD / REPLACE / DELETE) =========
                if payload is None:
                    print("\nRemote Subnet Options:")
                    print("1) Add New Remote Subnet")
                    print("2) Replace Existing Remote Subnet")
                    print("3) Delete Remote Subnet")  # ✅ ADD KAR
                    sub_choice = input("\nSelect an option (1-3): ").strip()
                    remote_action = "add" if sub_choice == "1" else "replace" if sub_choice == "2" else "delete" if sub_choice == "3" else ""
                else:
                    remote_action = (payload.get("remote_action") or "add").strip().lower()

                # Gather current state
                acl_run_current = _show(conn_ref, f"show run access-list {acl_name2}")
                direct_pairs_current = _parse_acl_subnet_pairs(acl_run_current)

                # local subnets from current ACL pairs (authoritative)
                local_subnets_set = sorted({(l_ip, l_mask) for (l_ip, l_mask, _, _) in direct_pairs_current})
                if not local_subnets_set:
                    print("[ERROR] No local subnets found in ACL. Cannot proceed.")
                    return

                # object-group remote subnets (if ACL has object-group permit line)
                remote_group = _find_remote_object_group_from_acl(acl_run_current, acl_name2)
                og_remote_subnets: list[tuple[str, str]] = []
                if remote_group:
                    full_run = _show(conn_ref, "show run")
                    obj_map = _parse_object_networks(full_run)
                    og_members = _parse_object_group_network_members(full_run, remote_group)
                    for obj_name in og_members:
                        if obj_name in obj_map:
                            og_remote_subnets.append(obj_map[obj_name])

                existing_remotes = _unique_remote_subnets(direct_pairs_current, og_remote_subnets)
                if not existing_remotes:
                    print("[ERROR] No existing remote subnets found.")
                    return

                if remote_action not in ("add", "replace","delete"):
                    print("[ERROR] Invalid remote subnet action.")
                    return

                # -------- ADD NEW REMOTE SUBNET --------
                if remote_action == "add":
                    if payload is None:
                        new_remote_ip = input("Enter new Remote Subnet IP: ").strip()
                        new_remote_mask = input("Enter new Remote Subnet Mask: ").strip()
                    else:
                        new_remote_ip = payload.get("new_remote_ip", "").strip()
                        new_remote_mask = payload.get("new_remote_mask", "").strip()
                        print(f"Enter new Remote Subnet IP: {new_remote_ip}")
                        print(f"Enter new Remote Subnet Mask: {new_remote_mask}")

                    if not _is_valid_ipv4(new_remote_ip) or not _is_valid_netmask(new_remote_mask):
                        print("[ERROR] Invalid Remote subnet IP or mask.")
                        return

                    # Step 2: strict duplicate check everywhere
                    if _remote_exists_everywhere(new_remote_ip, new_remote_mask, direct_pairs_current,
                                                 og_remote_subnets):
                        print("[ERROR] Remote subnet already exists (object-group/ACL). No changes made.")
                        return

                    print("\n" + WARN_REMOTE_ADD + "\n")

                    # CLI confirmation (only in terminal mode)
                    if payload is None:
                        if not _confirm("Do you want to proceed? (y/n): "):
                            print("[INFO] Add cancelled.")
                            return
                    else:
                        # WEB confirmation (GUI must send this flag)
                        if payload.get("user_confirmed_add") is not True:
                            print("[INFO] Cancelled by user.")
                            return

                    # Step 3: ASA handling
                    if remote_group:
                        ok = _add_remote_subnet_objectgroup_mode(
                            conn_ref,
                            acl_name=acl_name2,
                            local_subnets=local_subnets_set,
                            remote_ip=new_remote_ip,
                            remote_mask=new_remote_mask,
                            remote_group=remote_group,
                        )
                    else:
                        # fallback to existing direct ACL add logic (keep as-is)
                        ok = _update_remote_subnet_add(conn_ref, acl_name2, direct_pairs_current, new_remote_ip,
                                                       new_remote_mask)

                    if ok:
                        print("\nRemote subnet added successfully.\n")

                        # ✅ Proof (production style)
                        after_acl = _normalize_ws(_show(conn_ref, f"show run access-list {acl_name2}"))
                        print("----- AFTER (show run access-list) -----")
                        print(after_acl or "N/A")
                        print("---------------------------------------\n")

                        print("⚠️ WARNING: May impact production VPN traffic. Use change window and update remote side.\n")

                        # ✅ REFRESH AFTER UPDATE
                        print("\n================ CURRENT CONFIG (AFTER UPDATE) ================\n")

                        acl_run_after = _show(conn_ref, f"show run access-list {acl_name2}")
                        acl_pairs_after = _parse_acl_subnet_pairs(acl_run_after)

                        local_direct_after = sorted({(l_ip, l_mask) for (l_ip, l_mask, _, _) in acl_pairs_after})
                        remote_direct_after = sorted({(r_ip, r_mask) for (_, _, r_ip, r_mask) in acl_pairs_after})

                        og_remote_after: list[tuple[str, str]] = []
                        remote_group_after = _find_remote_object_group_from_acl(acl_run_after, acl_name2)
                        if remote_group_after:
                            full_run_after = _show(conn_ref, "show run")
                            obj_map_after = _parse_object_networks(full_run_after)
                            og_members_after = _parse_object_group_network_members(full_run_after, remote_group_after)
                            for obj_name in og_members_after:
                                if obj_name in obj_map_after:
                                    og_remote_after.append(obj_map_after[obj_name])

                        all_remotes_after = sorted(set(remote_direct_after) | set(og_remote_after))

                        print("Local Subnet(s):")
                        for (l_ip, l_mask) in local_direct_after:
                            print(f"  - {l_ip} {l_mask}")

                        print("\nRemote Subnet(s):")
                        for (r_ip, r_mask) in remote_direct_after:
                            print(f"  - {r_ip} {r_mask}")

                        print("\n==================================================================\n")
                    return

                # -------- REPLACE EXISTING REMOTE SUBNET --------
                if remote_action == "replace":
                    # Step 1: display existing remotes (reference)
                    print("\nExisting Remote Subnet(s):")
                    for i, (r_ip, r_mask) in enumerate(existing_remotes, start=1):
                        print(f"{i}) {r_ip} {r_mask}")

                    # OLD remote subnet (IP + Mask) - production input
                    if payload is None:
                        old_remote_ip = input("\nEnter OLD Remote Subnet IP (to replace): ").strip()
                        old_remote_mask = input("Enter OLD Remote Subnet Mask (to replace): ").strip()
                    else:
                        old_remote_ip = (payload.get("old_remote_ip") or "").strip()
                        old_remote_mask = (payload.get("old_remote_mask") or "").strip()
                        print(f"\nEnter OLD Remote Subnet IP (to replace): {old_remote_ip}")
                        print(f"Enter OLD Remote Subnet Mask (to replace): {old_remote_mask}")

                    if not _is_valid_ipv4(old_remote_ip) or not _is_valid_netmask(old_remote_mask):
                        print("[ERROR] Invalid Input")
                        return

                    old_remote = (old_remote_ip, old_remote_mask)
                    if old_remote not in existing_remotes:
                        print("[ERROR] Invalid Input")
                        return

                    # Step 2: NEW remote subnet
                    if payload is None:
                        new_remote_ip = input("Enter NEW Remote Subnet IP: ").strip()
                        new_remote_mask = input("Enter NEW Remote Subnet Mask: ").strip()
                    else:
                        new_remote_ip = (payload.get("new_remote_ip") or "").strip()
                        new_remote_mask = (payload.get("new_remote_mask") or "").strip()
                        print(f"Enter NEW Remote Subnet IP: {new_remote_ip}")
                        print(f"Enter NEW Remote Subnet Mask: {new_remote_mask}")

                    # Step 3 validate + duplicate
                    if not _is_valid_ipv4(new_remote_ip) or not _is_valid_netmask(new_remote_mask):
                        print("[ERROR] Invalid Input")
                        return

                    if (new_remote_ip, new_remote_mask) == old_remote:
                        print("[INFO] New remote subnet is same as old. No changes made.")
                        return

                    if _remote_exists_everywhere(new_remote_ip, new_remote_mask, direct_pairs_current,
                                                 og_remote_subnets):
                        print("[ERROR] Remote subnet already exists (object-group/ACL). No changes made.")
                        return

                    # Step 4 confirmation (CLI only)
                    print("\n--------------------------------------------------")
                    print("Please confirm that you want to replace:\n")
                    print(f"Old Subnet:\n{old_remote[0]} {old_remote[1]}\n")
                    print(f"With New Subnet:\n{new_remote_ip} {new_remote_mask}\n")
                    print("\n" + WARN_REMOTE_REPLACE + "\n")
                    print("\t1) Yes, I confirm and proceed")
                    print("\t2) No, cancel operation")
                    print("--------------------------------------------------\n")

                    if payload is None:
                        ans = input("Select an option (1-2): ").strip()
                        if ans != "1":
                            print("[INFO] Replace cancelled.")
                            return
                    else:
                        # WEB mode: keep consistent (auto-continue)
                        pass

                    # ✅ WEB: require explicit GUI confirmation
                    if payload is not None and payload.get("user_confirmed") is not True:
                        print("[INFO] Cancelled by user.")
                        return

                    # Step 5 apply (direct ACL replace - safest & idempotent)
                    ok = _replace_remote_subnet_direct_acl(
                        conn_ref,
                        acl_name=acl_name2,
                        local_subnets=local_subnets_set,
                        old_remote=old_remote,
                        new_remote=(new_remote_ip, new_remote_mask),
                    )

                    if not ok:
                        print("[ERROR] Replace failed.")
                        return

                    # Step 7 message
                    print("\nUpdate is successfully completed.\n")
                    print(WARN_REMOTE_ADD + "\n")

                    # YEH CODE COPY KARO AUR 3 LOCATIONS PE PASTE KARO:

                    # ✅ REFRESH AFTER UPDATE
                    print("\n================ CURRENT CONFIG (AFTER UPDATE) ================\n")

                    acl_run_after = _show(conn_ref, f"show run access-list {acl_name2}")
                    acl_pairs_after = _parse_acl_subnet_pairs(acl_run_after)

                    local_direct_after = sorted({(l_ip, l_mask) for (l_ip, l_mask, _, _) in acl_pairs_after})
                    remote_direct_after = sorted({(r_ip, r_mask) for (_, _, r_ip, r_mask) in acl_pairs_after})

                    og_remote_after: list[tuple[str, str]] = []
                    remote_group_after = _find_remote_object_group_from_acl(acl_run_after, acl_name2)
                    if remote_group_after:
                        full_run_after = _show(conn_ref, "show run")
                        obj_map_after = _parse_object_networks(full_run_after)
                        og_members_after = _parse_object_group_network_members(full_run_after, remote_group_after)
                        for obj_name in og_members_after:
                            if obj_name in obj_map_after:
                                og_remote_after.append(obj_map_after[obj_name])

                    all_remotes_after = sorted(set(remote_direct_after) | set(og_remote_after))

                    print("Local Subnet(s):")
                    for (l_ip, l_mask) in local_direct_after:
                        print(f"  - {l_ip} {l_mask}")

                    print("\nRemote Subnet(s):")
                    for (r_ip, r_mask) in all_remotes_after:
                        print(f"  - {r_ip} {r_mask}")

                    print("\n==================================================================\n")


                    return
                # -------- DELETE EXISTING REMOTE SUBNET --------
                if remote_action == "delete":
                    # Step 1: display existing remotes (reference)
                    print("\nExisting Remote Subnet(s):")
                    for i, (r_ip, r_mask) in enumerate(existing_remotes, start=1):
                        print(f"{i}) {r_ip} {r_mask}")

                    # Remote subnet to delete (IP + Mask)
                    if payload is None:
                        delete_remote_ip = input("\nEnter Remote Subnet IP (to delete): ").strip()
                        delete_remote_mask = input("Enter Remote Subnet Mask (to delete): ").strip()
                    else:
                        delete_remote_ip = (payload.get("delete_remote_ip") or "").strip()
                        delete_remote_mask = (payload.get("delete_remote_mask") or "").strip()
                        print(f"\nEnter Remote Subnet IP (to delete): {delete_remote_ip}")
                        print(f"Enter Remote Subnet Mask (to delete): {delete_remote_mask}")

                    if not _is_valid_ipv4(delete_remote_ip) or not _is_valid_netmask(delete_remote_mask):
                        print("[ERROR] Invalid Input")
                        return

                    delete_remote = (delete_remote_ip, delete_remote_mask)
                    if delete_remote not in existing_remotes:
                        print("[ERROR] Remote subnet not found.")
                        return

                    # Step 2: confirmation (CLI + WEB)
                    print("\n--------------------------------------------------")
                    print("Please confirm that you want to DELETE:\n")
                    print(f"Remote Subnet:\n{delete_remote_ip} {delete_remote_mask}\n")
                    print("🚨 This will remove ALL related ACL entries.\n")
                    print("\t1) Yes, I confirm and proceed")
                    print("\t2) No, cancel operation")
                    print("--------------------------------------------------\n")

                    if payload is None:
                        ans = input("Select an option (1-2): ").strip()
                        if ans != "1":
                            print("[INFO] Delete cancelled.")
                            return
                    else:
                        if payload.get("user_confirmed_delete") is not True:
                            print("[INFO] Cancelled by user.")
                            return

                    # Step 3: Apply delete
                    before_full = _normalize_ws(_show(conn_ref, f"show run access-list {acl_name2}"))

                    forward: list[str] = []
                    rollback: list[str] = []

                    for (l_ip, l_mask) in local_subnets_set:
                        # remove the ACL line
                        forward.append(
                            f"no access-list {acl_name2} extended permit ip {l_ip} {l_mask} {delete_remote_ip} {delete_remote_mask}")

                        # rollback - add it back
                        rollback.append(
                            f"access-list {acl_name2} extended permit ip {l_ip} {l_mask} {delete_remote_ip} {delete_remote_mask}")

                    try:
                        conn_ref.send_config_set(forward)
                        try:
                            conn_ref.save_config()
                        except Exception:
                            pass
                    except Exception as e:
                        print(f"[ERROR] Delete failed: {e}")
                        _best_effort_rollback(conn_ref, rollback)
                        return
                    try:
                        conn_ref.send_config_set(forward)
                        try:
                            conn_ref.save_config()
                        except Exception:
                            pass

                        # 🔥 OBJECT-GROUP CLEANUP
                        if remote_group:
                            obj_name = find_local_object_name(conn_ref, delete_remote_ip, delete_remote_mask)
                            if obj_name:
                                try:
                                    conn_ref.send_config_set([
                                        f"object-group network {remote_group}",
                                        f"no network-object object {obj_name}"
                                    ])
                                    print(f"[SUCCESS] Removed {obj_name} from {remote_group}")
                                except Exception as og_err:
                                    print(f"[WARNING] Could not remove from object-group: {og_err}")

                    except Exception as e:
                        print(f"[ERROR] Delete failed: {e}")
                        _best_effort_rollback(conn_ref, rollback)
                        return

        #            after_full = _normalize_ws(_show(conn_ref, f"show run access-list {acl_name2}"))
                    after_full = _normalize_ws(_show(conn_ref, f"show run access-list {acl_name2}"))

                    print("\n================ CHANGE CONTROL (Delete Remote Subnet) ================\n")
                    print(f"ACL Name   : {acl_name2}")
                    print(f"Deleted    : {delete_remote_ip} {delete_remote_mask}")
                    print("\n----- COMMANDS APPLIED -----")
                    for c in forward:
                        print(c)
                    print("\n----- BEFORE (show run access-list) -----")
                    print(before_full or "N/A")
                    print("\n----- AFTER  (show run access-list) -----")
                    print(after_full or "N/A")
                    print("\n=======================================================================\n")

                    print("[SUCCESS] Remote subnet deleted successfully.\n")

                    # ✅ REFRESH AFTER UPDATE
                    print("\n================ CURRENT CONFIG (AFTER UPDATE) ================\n")

                    acl_run_after = _show(conn_ref, f"show run access-list {acl_name2}")
                    acl_pairs_after = _parse_acl_subnet_pairs(acl_run_after)

                    local_direct_after = sorted({(l_ip, l_mask) for (l_ip, l_mask, _, _) in acl_pairs_after})
                    remote_direct_after = sorted({(r_ip, r_mask) for (_, _, r_ip, r_mask) in acl_pairs_after})

                    og_remote_after: list[tuple[str, str]] = []
                    remote_group_after = _find_remote_object_group_from_acl(acl_run_after, acl_name2)
                    if remote_group_after:
                        full_run_after = _show(conn_ref, "show run")
                        obj_map_after = _parse_object_networks(full_run_after)
                        og_members_after = _parse_object_group_network_members(full_run_after, remote_group_after)
                        for obj_name in og_members_after:
                            if obj_name in obj_map_after:
                                og_remote_after.append(obj_map_after[obj_name])

                    all_remotes_after = sorted(set(remote_direct_after) | set(og_remote_after))

                    print("Local Subnet(s):")
                    for (l_ip, l_mask) in local_direct_after:
                        print(f"  - {l_ip} {l_mask}")

                    print("\nRemote Subnet(s):")
                    for (r_ip, r_mask) in all_remotes_after:
                        print(f"  - {r_ip} {r_mask}")

                    print("\n==================================================================\n")
                    return

        if choice == "4":
            if not (map_name and seq):
                print("[ERROR] Crypto map entry for this peer was not found; cannot update Phase-2 encryption.")
                return
            if payload is None:
                new_ts = input("Enter new IKEv1 transform-set name: ").strip()
            else:
                new_ts = payload.get("new_transform_set", "").strip()
                print(f"Enter new IKEv1 transform-set name: {new_ts}")

            if not new_ts:
                print("[INFO] No transform-set provided. Update cancelled.")
                return

            ok = _update_phase2_encryption_modify(conn_ref, map_name, seq, new_ts)
            if ok:
                print("[SUCCESS] Phase-2 encryption update completed.")
            return

        if choice == "5":
            if payload is None:
                new_psk = input("Enter NEW Pre-Shared Key (ENTER to skip): ").strip()
            else:
                new_psk = payload.get("new_psk", "").strip()
                print("Enter NEW Pre-Shared Key (ENTER to skip): *****")

            if not new_psk:
                print("[INFO] PSK unchanged (skipped).")
                return

            ok = _update_psk_modify(conn_ref, peer_ip, new_psk)
            if ok:
                print("[SUCCESS] PSK update completed.")
            return

        print("[INFO] Invalid option. No changes applied.")
        return

    except Exception as e:
        print(f"[ERROR] Unexpected error in update workflow: {e}")
        return

    finally:
        # IMPORTANT:
        # Do NOT disconnect here (CLI or WEB).
        # - CLI lifecycle managed by main.py
        # - WEB lifecycle managed by web_wrapper.py
        try:
            _ = conn_ref
        except Exception:
            pass

