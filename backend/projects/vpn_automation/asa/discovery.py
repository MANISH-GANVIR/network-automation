import re

def _run_show(conn, cmd: str, title: str | None = None) -> str:
    if title:
        print(f"\n--- {title} ---")
    print(f"{conn.hostname}# {cmd}")
    out = conn.send_command(cmd) or ""
    print(out.strip())
    return out

def discover_tunnels(conn):
    outside_iface = getattr(conn, "outside_iface", "N/A")
    outside_ip = getattr(conn, "outside_ip", "N/A")

    ike = _run_show(conn, "show crypto ikev1 sa", "IKEv1 SAs (Phase 1)")
    ipsec = _run_show(conn, "show crypto ipsec sa", "IPsec SAs (Phase 2)")
    crypto = _run_show(conn, "show run crypto map", "Crypto Map Configuration")

    tunnels = []
    for line in crypto.splitlines():
        match = re.search(r"crypto map (\S+) (\d+) set peer (\S+)", line)
        if match:
            crypto_map, seq, peer_ip = match.groups()
            status = "UP" if (peer_ip in ike or peer_ip in ipsec) else "DOWN"
            tunnels.append({
                "seq": seq,
                "name": f"ASA-BLR-TUN-{seq}",
                "local_ip": outside_ip,
                "outside_iface": outside_iface,
                "peer_ip": peer_ip,
                "crypto_map": crypto_map,
                "status": status
            })

    print("\n========== === ✅ DISCOVERED VPN TUNNELS ✅=== ==========\n")
    print("| Seq | Tunnel Name    | Outside Iface     | Local IP      | Peer IP         | Crypto Map   | Status |")
    print("|-----|---------------|-------------------|---------------|-----------------|--------------|--------|")

    for t in tunnels:
        print(
            f"| {t['seq']:<3} | {t['name']:<13} | {t['outside_iface']:<17} | {t['local_ip']:<13} "
            f"| {t['peer_ip']:<15} | {t['crypto_map']:<12} | {t['status']:<6} |"
        )

    return tunnels