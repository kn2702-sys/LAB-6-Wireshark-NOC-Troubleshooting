# 04 — ICMP: echo request and reply

**File:** `captures/04-icmp-echo.pcap` (2 packets)
**Wireshark filter:** `icmp`

## What to look at

| # | Packet | Type | ID | Seq | Meaning |
|---|--------|------|----|-----|---------|
| 1 | `192.168.10.10 → 192.168.10.1` | 8 (Echo Request) | `0x1a2b` | 1 | "Are you there?" |
| 2 | `192.168.10.1 → 192.168.10.10` | 0 (Echo Reply) | `0x1a2b` | 1 | "Yes." |

The **Identifier** and **Sequence number** match between request and reply
— that's how `ping` pairs them up when many are in flight. The payload
(`wireshark-lab6-ping-payload-…`) is echoed back byte-for-byte; a reply
with a *corrupted* payload would indicate a data-path problem, not just a
reachability problem.

Reply arrived 1.2ms after the request. That delta is your baseline RTT to
the gateway — every latency complaint gets compared against a number like
this.

## The checks that matter

1. **Type 8 → Type 0.** The two types that matter most: 8 = request, 0 =
   reply. Also know Type 3 (Destination Unreachable — see capture 05) and
   Type 11 (Time Exceeded — the basis of traceroute).
2. **Request with no reply** → host down, or ICMP blocked (very common:
   many firewalls drop ICMP while TCP works fine — "ping fails" ≠ "network
   down").
3. **Reply from an unexpected source** → something else answered (proxy
   ARP, a middlebox). Always check *who* replied, not just *that* someone
   did.

## Capture it yourself

```bash
tshark -i any -f "icmp" -w icmp.pcap &
ping -c 4 192.168.10.1
kill %1
```

## NOC one-liner

*"Echo request/reply paired on ID 0x1a2b, 1.2ms RTT, payload intact —
gateway reachable, path clean at layer 3."*
