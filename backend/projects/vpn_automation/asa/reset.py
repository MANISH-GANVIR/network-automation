from backend.utils.spinner import square_spinner
import ipaddress

def _extract_info_lines(output: str) -> str:
    """Return only useful lines (hide confirm prompt)."""
    lines = []
    for line in (output or "").splitlines():
        s = line.strip()
        if not s:
            continue
        if "do you want to logoff the vpn session" in s.lower():
            continue
        if s.startswith("INFO:"):
            lines.append(s)
    return "\n".join(lines)

def _asa_logoff_tunnel_group(conn, tunnel_group: str) -> str:
    cmd = f"vpn-sessiondb logoff tunnel-group {tunnel_group}"
    out1 = conn.send_command_timing(cmd, read_timeout=60)

    if "[confirm]" in (out1 or "").lower():
        out2 = conn.send_command_timing("\n", read_timeout=60)
    else:
        out2 = ""

    return _extract_info_lines(out1 + "\n" + out2)

def _normalize_ip(ip: str) -> str:
    return str(ip).strip()

def _is_valid_ipv4(ip: str) -> bool:
    try:
        ipaddress.IPv4Address(_normalize_ip(ip))
        return True
    except Exception:
        return False

def reset_vpn_by_peer_ip(conn, tunnels, peer_ip: str):
    """WEB helper: reset using peer IP (no interactive input)."""
    peer_ip = _normalize_ip(peer_ip)

    print("\nAVAILABLE TUNNELS:")
    for t in tunnels:
        print(f"Seq {t['seq']} → {t['name']} | Peer {t['peer_ip']} | Status {t['status']}")

    if not _is_valid_ipv4(peer_ip):
        print("[ERROR] Invalid peer IP format")
        return

    selected = next(
        (t for t in tunnels if _normalize_ip(t.get("peer_ip", "")) == peer_ip),
        None
    )
    if not selected:
        print("[ERROR] Peer IP not found in discovered tunnels")
        return

    square_spinner(f"[{conn.hostname}] Resetting VPN tunnel", 2)
    print("\n\n")
    print(f"{conn.hostname}#vpn-sessiondb logoff tunnel-group {selected['peer_ip']}\n")

    info = _asa_logoff_tunnel_group(conn, selected["peer_ip"])
    if info:
        print(info)

    print("\nPost-reset verification:")
    print(conn.send_command("show crypto ikev1 sa", read_timeout=60))
    print(conn.send_command("show crypto ipsec sa", read_timeout=60))

def reset_vpn(conn, tunnels):
    """CLI helper: now takes Peer IP as input instead of sequence number."""
    print("\nAVAILABLE TUNNELS:")
    for t in tunnels:
        print(f"Seq {t['seq']} → {t['name']} | Peer {t['peer_ip']} | Status {t['status']}")

    peer_ip = input("\nEnter the Peer IP of the tunnel to reset (or press 'n' to cancel): ").strip()
    if peer_ip.lower() == "n":
        print("[INFO] Reset cancelled")
        return

    return reset_vpn_by_peer_ip(conn, tunnels, peer_ip)

# (Optional) keep old API if needed
def reset_vpn_by_seq(conn, tunnels, seq: int):
    seq_str = str(seq).strip()

    print("\nAVAILABLE TUNNELS:")
    for t in tunnels:
        print(f"Seq {t['seq']} → {t['name']} | Peer {t['peer_ip']} | Status {t['status']}")

    selected = next((t for t in tunnels if str(t.get("seq")).strip() == seq_str), None)
    if not selected:
        print("[ERROR] Invalid sequence")
        return

    square_spinner(f"[{conn.hostname}] Resetting VPN tunnel", 2)

    print(f"{conn.hostname}# vpn-sessiondb logoff tunnel-group {selected['peer_ip']}")

    info = _asa_logoff_tunnel_group(conn, selected["peer_ip"])
    if info:
        print(info)

    print("\nPost-reset verification:")
    print(conn.send_command("show crypto ikev1 sa", read_timeout=60))
    print(conn.send_command("show crypto ipsec sa", read_timeout=60))