#!/usr/bin/env python3
"""Generate Lab 6 Wireshark captures as real .pcap files (open in Wireshark).

Each capture is crafted packet-by-packet with realistic Ethernet/IP headers,
correct protocol fields, and believable inter-packet timing, so Wireshark
dissects them exactly like live traffic.

Usage:
    python3 scripts/generate_captures.py

Output (captures/):
    01-dns-query-response.pcap     DNS query + response (A record)
    02-dhcp-dora.pcap              DHCP Discover/Offer/Request/ACK
    03-tcp-handshake.pcap          TCP 3-way handshake (SYN, SYN-ACK, ACK)
    04-icmp-echo.pcap              ICMP Echo Request + Echo Reply
    05-failed-connection.pcap      3 failure signatures: retransmit/timeout,
                                   RST (refused), ICMP port unreachable
"""
from __future__ import annotations

import sys
from pathlib import Path

from scapy.all import (  # noqa: F401  (explicit re-export for clarity)
    BOOTP, DHCP, DNS, DNSQR, DNSRR, ICMP, IP, TCP, UDP, Ether, Raw,
    wrpcap, rdpcap, mac2str,
)

OUT_DIR = Path(__file__).resolve().parent.parent / "captures"
OUT_DIR.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# Cast of characters (kept consistent across captures)
# ---------------------------------------------------------------------------
CLIENT_MAC = "00:11:22:33:44:55"
GW_MAC = "00:aa:bb:cc:dd:01"
DNS_MAC = "00:aa:bb:cc:dd:53"
SRV_MAC = "00:aa:bb:cc:dd:80"

CLIENT = "192.168.10.10"
GATEWAY = "192.168.10.1"
DNS_SRV = "192.168.10.53"
WEB_SRV = "93.184.216.34"          # documentation address (example.com)
OFFICE_B_SRV = "10.20.20.10"       # silent / filtered host
DEAD_NET_HOST = "10.99.99.99"      # unroutable destination

T0 = 1_700_000_000.0               # fixed base timestamp (deterministic pcaps)


def eth(src: str, dst: str):
    return Ether(src=src, dst=dst)


# ---------------------------------------------------------------------------
# 01 - DNS query + response
# ---------------------------------------------------------------------------
def build_dns():
    qid = 0x1A2B
    sport = 53531
    query = (
        eth(CLIENT_MAC, GW_MAC)
        / IP(src=CLIENT, dst=DNS_SRV)
        / UDP(sport=sport, dport=53)
        / DNS(id=qid, rd=1, qd=DNSQR(qname="www.lab6.local", qtype="A"))
    )
    query.time = T0
    resp = (
        eth(DNS_MAC, CLIENT_MAC)
        / IP(src=DNS_SRV, dst=CLIENT)
        / UDP(sport=53, dport=sport)
        / DNS(id=qid, qr=1, aa=1, rd=1, ra=1,
              qd=DNSQR(qname="www.lab6.local", qtype="A"),
              an=DNSRR(rrname="www.lab6.local", ttl=300, rdata=WEB_SRV))
    )
    resp.time = T0 + 0.0234
    return [query, resp]


# ---------------------------------------------------------------------------
# 02 - DHCP DORA
# ---------------------------------------------------------------------------
def build_dhcp():
    xid = 0x12345678
    ch = mac2str(CLIENT_MAC)
    bcast = "ff:ff:ff:ff:ff:ff"

    discover = (
        eth(CLIENT_MAC, bcast)
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP(chaddr=ch, xid=xid, flags=0x8000)
        / DHCP(options=[("message-type", "discover"), "end"])
    )
    discover.time = T0

    offer = (
        eth(GW_MAC, bcast)
        / IP(src=GATEWAY, dst="255.255.255.255")
        / UDP(sport=67, dport=68)
        / BOOTP(op=2, yiaddr="192.168.10.50", siaddr=GATEWAY, chaddr=ch, xid=xid)
        / DHCP(options=[("message-type", "offer"),
                        ("subnet_mask", "255.255.255.0"),
                        ("router", GATEWAY),
                        ("name_server", DNS_SRV),
                        ("lease_time", 86400), "end"])
    )
    offer.time = T0 + 0.0521

    request = (
        eth(CLIENT_MAC, bcast)
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP(chaddr=ch, xid=xid, flags=0x8000)
        / DHCP(options=[("message-type", "request"),
                        ("requested_addr", "192.168.10.50"),
                        ("server_id", GATEWAY), "end"])
    )
    request.time = T0 + 0.0817

    ack = (
        eth(GW_MAC, bcast)
        / IP(src=GATEWAY, dst="255.255.255.255")
        / UDP(sport=67, dport=68)
        / BOOTP(op=2, yiaddr="192.168.10.50", siaddr=GATEWAY, chaddr=ch, xid=xid)
        / DHCP(options=[("message-type", "ack"),
                        ("subnet_mask", "255.255.255.0"),
                        ("router", GATEWAY),
                        ("name_server", DNS_SRV),
                        ("lease_time", 86400), "end"])
    )
    ack.time = T0 + 0.1249
    return [discover, offer, request, ack]


# ---------------------------------------------------------------------------
# 03 - TCP 3-way handshake
# ---------------------------------------------------------------------------
def build_tcp():
    sport = 45678
    cseq, sseq = 1000, 5000

    syn = (
        eth(CLIENT_MAC, GW_MAC)
        / IP(src=CLIENT, dst=WEB_SRV)
        / TCP(sport=sport, dport=80, seq=cseq, flags="S", window=64240,
              options=[("MSS", 1460), ("NOP", None), ("WScale", 7)])
    )
    syn.time = T0

    synack = (
        eth(SRV_MAC, CLIENT_MAC)
        / IP(src=WEB_SRV, dst=CLIENT)
        / TCP(sport=80, dport=sport, seq=sseq, ack=cseq + 1, flags="SA",
              window=65160, options=[("MSS", 1460)])
    )
    synack.time = T0 + 0.0452

    ack = (
        eth(CLIENT_MAC, GW_MAC)
        / IP(src=CLIENT, dst=WEB_SRV)
        / TCP(sport=sport, dport=80, seq=cseq + 1, ack=sseq + 1, flags="A",
              window=64240)
    )
    ack.time = T0 + 0.0459
    return [syn, synack, ack]


# ---------------------------------------------------------------------------
# 04 - ICMP echo request / reply
# ---------------------------------------------------------------------------
def build_icmp():
    ident, seq = 0x1A2B, 1
    payload = b"wireshark-lab6-ping-payload-0123456789abcdef"

    req = (
        eth(CLIENT_MAC, GW_MAC)
        / IP(src=CLIENT, dst=GATEWAY)
        / ICMP(type=8, id=ident, seq=seq)
        / Raw(load=payload)
    )
    req.time = T0

    rep = (
        eth(GW_MAC, CLIENT_MAC)
        / IP(src=GATEWAY, dst=CLIENT)
        / ICMP(type=0, id=ident, seq=seq)
        / Raw(load=payload)
    )
    rep.time = T0 + 0.0012
    return [req, rep]


# ---------------------------------------------------------------------------
# 05 - Failed connection: three signatures in one capture
# ---------------------------------------------------------------------------
def build_failed():
    pkts = []

    # --- A: blackholed host -> SYN retransmissions, then timeout ---
    sport_a, seq_a = 45679, 2000
    t = T0
    for delta in (0, 1.0, 3.0, 7.0):          # exponential-ish backoff
        p = (
            eth(CLIENT_MAC, GW_MAC)
            / IP(src=CLIENT, dst=OFFICE_B_SRV)
            / TCP(sport=sport_a, dport=80, seq=seq_a, flags="S", window=64240)
        )
        p.time = t + delta
        pkts.append(p)
    # ...then silence. No response ever arrives: classic filtered/blackhole.

    # --- B: closed port -> immediate RST (connection refused) ---
    sport_b, seq_b = 45680, 3000
    syn_b = (
        eth(CLIENT_MAC, GW_MAC)
        / IP(src=CLIENT, dst=OFFICE_B_SRV)
        / TCP(sport=sport_b, dport=22, seq=seq_b, flags="S", window=64240)
    )
    syn_b.time = T0 + 10.0
    rst_b = (
        eth(SRV_MAC, CLIENT_MAC)
        / IP(src=OFFICE_B_SRV, dst=CLIENT)
        / TCP(sport=22, dport=sport_b, seq=4000, ack=seq_b + 1, flags="RA",
              window=0)
    )
    rst_b.time = T0 + 10.0018
    pkts += [syn_b, rst_b]

    # --- C: unroutable destination -> ICMP port unreachable ---
    sport_c, seq_c = 45681, 5000
    syn_c = (
        eth(CLIENT_MAC, GW_MAC)
        / IP(src=CLIENT, dst=DEAD_NET_HOST)
        / TCP(sport=sport_c, dport=80, seq=seq_c, flags="S", window=64240)
    )
    syn_c.time = T0 + 12.0
    # gateway returns ICMP type 3 code 3, embedding original IP + 8 bytes
    orig_ip = IP(src=CLIENT, dst=DEAD_NET_HOST)
    orig_tcp = TCP(sport=sport_c, dport=80, seq=seq_c, flags="S")
    unreach = (
        eth(GW_MAC, CLIENT_MAC)
        / IP(src=GATEWAY, dst=CLIENT)
        / ICMP(type=3, code=3)
        / orig_ip
        / orig_tcp
    )
    unreach.time = T0 + 12.0011
    pkts += [syn_c, unreach]

    return pkts


# ---------------------------------------------------------------------------
def main() -> int:
    builds = [
        ("01-dns-query-response.pcap", build_dns()),
        ("02-dhcp-dora.pcap", build_dhcp()),
        ("03-tcp-handshake.pcap", build_tcp()),
        ("04-icmp-echo.pcap", build_icmp()),
        ("05-failed-connection.pcap", build_failed()),
    ]
    for fname, pkts in builds:
        out = OUT_DIR / fname
        wrpcap(str(out), pkts)
        # verify: re-read and sanity check
        back = rdpcap(str(out))
        assert len(back) == len(pkts), f"{fname}: {len(back)} != {len(pkts)}"
        print(f"  {fname}: {len(back)} packets, {out.stat().st_size} bytes")

    print("all captures generated and re-readable")
    return 0


if __name__ == "__main__":
    sys.exit(main())
