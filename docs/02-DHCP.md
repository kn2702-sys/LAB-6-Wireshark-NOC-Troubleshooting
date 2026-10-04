# 02 — DHCP: the DORA handshake

**File:** `captures/02-dhcp-dora.pcap` (4 packets)
**Wireshark filter:** `bootp`

## What to look at

All four packets share one **transaction ID** (`0x12345678`) — that's how
you know they belong to the same conversation. Click each packet and read
DHCP Option 53 (the message type):

| # | Packet | Src → Dst | Option 53 | Key fields |
|---|--------|-----------|-----------|------------|
| 1 | **D**iscover | `0.0.0.0:68 → 255.255.255.255:67` | Discover (1) | Client has no IP yet, so it shouts to everyone (broadcast) |
| 2 | **O**ffer | `192.168.10.1:67 → 255.255.255.255:67` | Offer (2) | `yiaddr = 192.168.10.50` — "you can have this one" |
| 3 | **R**equest | `0.0.0.0:68 → 255.255.255.255:67` | Request (3) | "I'll take 192.168.10.50" (+ server identifier) |
| 4 | **A**CK | `192.168.10.1:67 → 255.255.255.255:67` | ACK (5) | Lease confirmed: mask, router, DNS, lease time 86400s |

**Memorize: D-O-R-A — Discover, Offer, Request, ACK.**

## The checks that matter

1. **Same transaction ID across all four** — different XIDs mean different
   conversations (or a client restarting mid-handshake).
2. **Broadcast vs unicast** — early packets are broadcast because the
   client has no address and doesn't know the server's. The ACK can be
   broadcast here too (client still can't receive unicast reliably).
3. **The offered options** — expand Option 51/1/3/6 in packet 4: lease
   time, subnet mask, default router, DNS server. A client with "no
   internet but has an IP" usually got a bad *option* (wrong gateway/DNS),
   not a failed DORA.
4. **Timing** — whole exchange in ~125ms. A DORA that stalls between
   Discover and Offer means: no DHCP server on the segment, or a
   relay/helper-address problem.

## Failure variants to recognize

- **Discover with no Offer** → no server, or blocked UDP 67/68.
- **Offer but no Request** → client rejected the offer (address conflict
  detection) or died.
- **NAK (type 6)** instead of ACK → server refused (moved subnets, bad
  requested address).

## Capture it yourself

```bash
tshark -i eth0 -f "udp port 67 or udp port 68" -w dhcp.pcap &
# then release/renew the interface address
kill %1
```

## NOC one-liner

*"DORA completed in 125ms on XID 0x12345678, leased 192.168.10.50 with
gateway .1 and DNS .53 — DHCP is healthy."*
