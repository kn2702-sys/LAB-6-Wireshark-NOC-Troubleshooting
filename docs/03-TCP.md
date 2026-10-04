# 03 — TCP: the three-way handshake, explained

**File:** `captures/03-tcp-handshake.pcap` (3 packets)
**Wireshark filter:** `tcp`

## What to look at

| # | Packet | Flags | Seq | Ack | Meaning |
|---|--------|-------|-----|-----|---------|
| 1 | Client → Server | **SYN** | 1000 | — | "I want to talk. My starting sequence number is 1000." |
| 2 | Server → Client | **SYN-ACK** | 5000 | 1001 | "Agreed. My starting number is 5000, and I've received everything up to 1000." |
| 3 | Client → Server | **ACK** | 1001 | 5001 | "Confirmed. Connection established." |

## Why it works this way

Each side picks a random **Initial Sequence Number** (ISN) — 1000 and 5000
here — so old duplicate packets from earlier connections can't be mistaken
for new data. The **acknowledgment number** is always "the next byte I
expect": the server ACKs 1001 because it received byte 1000 (the SYN
consumes one sequence number).

After packet 3, both sides have proven two things: *I can reach you* and
*you can reach me*. That bidirectional proof is the whole point — TCP
doesn't trust a connection until traffic has flowed both ways.

In Wireshark, note the handshake takes ~1ms here (local-ish server). On a
WAN you'd see the round-trip time *in* the handshake: SYN → SYN-ACK gap ≈
RTT. That gap is a free latency measurement on every new connection.

## The checks that matter

1. **Flag sequence S → SA → A.** Anything else is a story: SYN with no
   SYN-ACK (server down/filtered — see capture 05), SYN → RST (port
   closed), SYN → SYN-ACK → RST (client aborting).
2. **Ack = received seq + 1.** If the numbers don't chain, you're looking
   at packet loss, reordering, or two different connections mixed in one
   filter.
3. **Window sizes** (64240/65160) — the receive window each side
   advertises. A window collapsing toward 0 mid-transfer means the receiver
   can't keep up (buffer pressure), not a network problem.

## Capture it yourself

```bash
tshark -i any -f "tcp port 80" -w tcp.pcap &
curl -s -o /dev/null http://example.com
kill %1
# then filter: tcp.flags.syn==1 or tcp.flags.ack==1
```

## NOC one-liner

*"Handshake clean — S/SA/A, seq/ack chain valid, ~1ms RTT. TCP setup is
healthy; the problem (if any) is above layer 4."*
