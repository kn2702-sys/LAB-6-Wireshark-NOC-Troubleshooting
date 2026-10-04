# Lab 6: Wireshark NOC Troubleshooting Lab

Packet analysis is the most underrated skill on a NOC résumé — and the
easiest to fake. This lab produces **evidence**: five real `.pcap` files you
open in Wireshark, each paired with an analysis guide that teaches you what
to look at, what it proves, and the one-liner you'd say on a bridge call.

> **Résumé line:** *Produced and analyzed Wireshark captures covering DNS,
> DHCP, TCP handshakes, ICMP, and failure signatures (retransmissions,
> resets, unreachable) — with a written RCA for a blackholed connection.*

## The captures

| # | File | Packets | What it proves you can read |
|---|------|---------|----------------------------|
| 1 | `captures/01-dns-query-response.pcap` | 2 | Query/response pairing, qtype, rcode |
| 2 | `captures/02-dhcp-dora.pcap` | 4 | DORA sequence, transaction IDs, lease options |
| 3 | `captures/03-tcp-handshake.pcap` | 3 | SYN → SYN-ACK → ACK, seq/ack chaining |
| 4 | `captures/04-icmp-echo.pcap` | 2 | Echo request/reply pairing, RTT baseline |
| 5 | `captures/05-failed-connection.pcap` | 8 | **Three failure signatures** — see below |

Open any of them in Wireshark (File → Open). They were crafted
packet-by-packet with realistic headers and timing, so they dissect exactly
like live traffic.

## The failure signatures (capture 05)

| Attempt | You see | It means |
|---------|---------|----------|
| A (pkts 1–4) | SYN retransmits, doubling backoff, then silence | **Blackhole** — silent drop somewhere |
| B (pkts 5–6) | Immediate RST,ACK | **Refused** — host alive, port closed |
| C (pkts 7–8) | ICMP type 3 code 3 from the gateway | **Unreachable** — path device refusing |

Full analysis: [docs/05-FAILED-CONNECTION.md](docs/05-FAILED-CONNECTION.md).
The written RCA for Attempt A: [docs/RCA.md](docs/RCA.md).

## Repository contents

```
captures/
  01-dns-query-response.pcap
  02-dhcp-dora.pcap
  03-tcp-handshake.pcap
  04-icmp-echo.pcap
  05-failed-connection.pcap
docs/
  01-DNS.md  02-DHCP.md  03-TCP.md  04-ICMP.md   # per-capture analysis guides
  05-FAILED-CONNECTION.md                        # the three signatures
  RCA.md                                         # NOC-format root-cause write-up
scripts/
  generate_captures.py                           # regenerates all 5 pcaps (scapy)
```

## How to work through it (30 minutes)

1. Open capture 01 in Wireshark. Filter `dns`. Match the transaction IDs
   yourself before reading [docs/01-DNS.md](docs/01-DNS.md).
2. Capture 02, filter `bootp`. Find the four Option-53 values and say
   "DORA" out loud. Then read [docs/02-DHCP.md](docs/02-DHCP.md).
3. Capture 03. Trace the seq/ack chain with a pen. Then read
   [docs/03-TCP.md](docs/03-TCP.md) — including *why* the handshake exists.
4. Capture 04, filter `icmp`. Note the 1.2ms RTT — that's your baseline.
5. Capture 05. **Before** reading the guide, write down what you think
   each attempt's root cause is. Then check yourself against
   [docs/05-FAILED-CONNECTION.md](docs/05-FAILED-CONNECTION.md).
6. Read [docs/RCA.md](docs/RCA.md) — this is what a finished NOC
   investigation looks like on paper.

## Capture it yourself (real commands)

Every capture in this repo can be reproduced live. The pattern is always
`tshark` + an action:

```bash
tshark -i any -f "udp port 53" -w dns.pcap &   nslookup www.example.com; kill %1
tshark -i eth0 -f "udp port 67 or 68" -w dhcp.pcap &  # + renew your lease; kill %1
tshark -i any -f "tcp port 80" -w tcp.pcap &    curl -s -o /dev/null http://example.com; kill %1
tshark -i any -f "icmp" -w icmp.pcap &          ping -c 4 192.168.10.1; kill %1
tshark -i any -f "tcp" -w failed.pcap &        curl --connect-timeout 5 http://10.20.20.10; kill %1
```

Each analysis guide repeats its own capture's command.

## Regenerating the captures

```bash
python3 -m venv /tmp/pcap-venv && /tmp/pcap-venv/bin/pip install scapy
/tmp/pcap-venv/bin/python scripts/generate_captures.py
```

Deterministic: same packets, same timestamps, every run. The script
re-reads each pcap and asserts packet counts as a sanity check.

## Requirements

- Wireshark (any recent version) to open the captures.
- Python 3 + scapy only if you want to regenerate them.

## Talking about this in interviews

- "I don't just know the TCP handshake — I can show you one, packet by
  packet, and trace the sequence numbers."
- "A timeout with retransmissions and *no* RST or ICMP is a blackhole —
  I localize it by capturing at successive hops until the SYNs stop."
- "An immediate RST means the host is alive and refused — that's a
  host/service problem, not a network problem. The signature tells you
  where to look before you touch anything."
- "I wrote an RCA in NOC format: timeline, packet evidence, root cause,
  fix, prevention. It's in the repo."
