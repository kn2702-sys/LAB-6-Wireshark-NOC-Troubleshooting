# RCA: Intermittent application timeouts to 10.20.20.10:80

**Incident:** Users report the internal web app at `10.20.20.10` timing out.
**File:** `captures/05-failed-connection.pcap`, packets 1–4 (Attempt A)
**Severity:** Service-impacting for affected users | **Status:** Resolved

## Summary

Connections from `192.168.10.10` to `10.20.20.10:80` never complete. The
client sends a SYN, retransmits it three times with exponential backoff,
and receives **nothing** — no SYN-ACK, no RST, no ICMP error. The connection
dies by timeout.

## Timeline (from the capture)

| Time | Packet | What happened |
|------|--------|---------------|
| t+0.0s | 1 | SYN `192.168.10.10:45679 → 10.20.20.10:80`, seq 2000 |
| t+1.0s | 2 | SYN retransmission (same seq 2000) — Wireshark: *"TCP Retransmission"* |
| t+3.0s | 3 | SYN retransmission (same seq 2000) |
| t+7.0s | 4 | SYN retransmission (same seq 2000) |
| after | — | Silence. Client gives up. |

## Evidence

- All four SYNs carry the **same sequence number** (2000) — these are
  retransmissions of one attempt, not four separate connections.
- Backoff intervals (1s → 2s → 4s) are the TCP stack's retransmission
  timer doubling, exactly as designed.
- **Zero response packets**: no SYN-ACK (would mean the server is alive),
  no RST (would mean port closed — see Attempt B in the same capture),
  no ICMP unreachable (would mean a router is refusing — see Attempt C).
- Contrast with packets 5–6 (RST → "connection refused", fail fast) and
  7–8 (ICMP 3/3 → "no route / filtered by an intermediate"). Three
  signatures, three different root causes — this one is the quietest.

## Root cause

Packets are being **silently dropped between client and server** — a
blackhole. The server never sees the SYN (or its replies never return).
In production this is typically: an ACL drop on an intermediate firewall
with no logging, a missing return route, or a host firewall (iptables /
Windows Firewall) dropping inbound silently.

## Resolution

1. Confirmed the drop location by capturing at successive hops (client →
   gateway → server segment) to find where SYNs stop.
2. Found and corrected the offending filter (example: missing firewall
   rule permitting `192.168.10.0/24 → 10.20.20.10:80`).
3. Re-tested: SYN → SYN-ACK → ACK, application loads.

## Prevention

- Firewall changes for this path now require a documented rule review;
  silent drops on inter-site paths log to the SIEM.
- Added a synthetic TCP check (SYN → expect SYN-ACK) to monitoring for
  `10.20.20.10:80` — a blackhole now pages *before* users notice.
- Attached this capture to the runbook entry for "application timeout,
  no RST, no ICMP" so the next on-call starts at packet 1, not at guess 1.

## Why this RCA matters

Most timeout tickets die in "the network is slow." Four packets proved it
wasn't slow — it was a blackhole, and proved *where the evidence pointed*.
That is the whole job: replace guessing with packets.
