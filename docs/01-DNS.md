# 01 — DNS: query and response

**File:** `captures/01-dns-query-response.pcap` (2 packets)
**Wireshark filter:** `dns`

## What to look at

Open the capture and click packet 1, then expand the DNS section:

| Field | Packet 1 (query) | Packet 2 (response) |
|-------|------------------|---------------------|
| Source → Destination | `192.168.10.10` → `192.168.10.53` | `192.168.10.53` → `192.168.10.10` |
| UDP ports | `53531 → 53` | `53 → 53531` |
| Transaction ID | `0x1a2b` | `0x1a2b` (must match) |
| Flags | Standard query, recursion desired | Response, recursion available |
| Question | `www.lab6.local`, type **A** | (repeated) |
| Answer | — | `www.lab6.local → 93.184.216.34`, TTL 300 |

## The checks that matter

1. **Transaction ID match** — the response's ID (`0x1a2b`) equals the
   query's. A response with a different ID is not an answer to *your*
   question (this is also the basis of DNS spoofing defenses).
2. **Query type** — `A` means "give me the IPv4 address." Know the common
   ones: `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `PTR`.
3. **Response code** — `No error (0)` here. `NXDOMAIN (3)` means "that name
   doesn't exist" — the single most useful DNS failure signal in a NOC.
4. **Timing** — 23ms between query and response. Slow DNS looks exactly
   like a slow *application* to users; always check name resolution before
   blaming the app.

## Capture it yourself

```bash
tshark -i any -f "udp port 53" -w dns.pcap &
nslookup www.example.com
kill %1
```

## NOC one-liner

*"DNS resolved in 23ms, answer 93.184.216.34, rcode 0 — name resolution is
healthy, moving up the stack."*
