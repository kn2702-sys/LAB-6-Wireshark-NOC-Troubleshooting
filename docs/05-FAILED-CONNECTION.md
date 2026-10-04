# 05 — Failed connection: three signatures, three root causes

**File:** `captures/05-failed-connection.pcap` (8 packets)
**Wireshark filters:** `tcp.flags.syn==1`, `tcp.flags.reset==1`, `icmp`

This is the valuable one. One capture, three failed connections, three
completely different failure signatures. Learn to tell them apart at a
glance — in a NOC, the signature *is* the diagnosis.

## Attempt A — packets 1–4: retransmissions → timeout (blackhole)

```
t+0s  SYN  192.168.10.10:45679 → 10.20.20.10:80   seq 2000
t+1s  SYN  (retransmission, same seq 2000)          ← Wireshark flags "TCP Retransmission"
t+3s  SYN  (retransmission, same seq 2000)
t+7s  SYN  (retransmission, same seq 2000)
then: silence
```

**Signature:** same sequence number repeated, backoff doubling
(1s → 2s → 4s), **zero response packets** — no SYN-ACK, no RST, no ICMP.

**Meaning:** packets are being **silently dropped** somewhere. The server
never sees the SYN, or its replies never return. Typical causes: firewall
ACL drop without logging, missing return route, host firewall silently
dropping.

**NOC read:** *"SYN retransmits with doubling backoff, no response of any
kind — blackhole between client and server. Capture at the next hop to
localize."*

## Attempt B — packets 5–6: RST (connection refused)

```
t+10s     SYN      192.168.10.10:45680 → 10.20.20.10:22  seq 3000
t+10.002s RST,ACK  10.20.20.10:22 → 192.168.10.10:45680
```

**Signature:** immediate `RST,ACK`, ~2ms later, window 0.

**Meaning:** the server is **alive** (it answered!) but nothing listens on
port 22 — or a firewall *rejected* (vs dropped) the connection. This fails
fast and loud, which is actually good news: you know exactly where the
refusal came from.

**NOC read:** *"Immediate RST from 10.20.20.10 — host is up, port 22
closed or rejected. Not a network problem; check the service/firewall on
the host."*

## Attempt C — packets 7–8: ICMP unreachable

```
t+12s       SYN   192.168.10.10:45681 → 10.99.99.99:80
t+12.001s   ICMP  192.168.10.1 → 192.168.10.10  type 3, code 3
```

**Signature:** ICMP Destination Unreachable, code 3 (port unreachable),
from the gateway — with the original IP header + 8 bytes embedded.

**Meaning:** a router *on the path* is telling you the destination can't
be reached. Code 3 = nothing listening (or administratively filtered);
code 0 = no route to network; code 1 = no route to host. The embedded
original headers let you match the error to the exact failed packet.

**NOC read:** *"ICMP 3/3 from the gateway for our SYN to 10.99.99.99 —
path device is refusing; check routing/filtering toward that
destination."*

## The cheat sheet

| What you see | What it means | Where to look |
|---|---|---|
| SYN retransmits, nothing back | Silent drop / blackhole | Every hop — find where SYNs stop |
| Immediate RST | Host alive, port closed/rejected | The destination host's service + firewall |
| ICMP 3/0, 3/1 | No route | Routing tables toward the destination |
| ICMP 3/3 | Port unreachable / filtered | Destination host or path firewall |
| ICMP 3/13 | Administratively prohibited | A firewall ACL is doing its job — read it |

## The RCA

See [RCA.md](RCA.md) — a full NOC-format root-cause write-up for Attempt A.
