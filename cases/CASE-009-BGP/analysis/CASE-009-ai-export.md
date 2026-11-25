# Packet capture analysis: Packet breakdown: 16 packets, 8 kinds of message (BGP, ICMP)

Almnjoy Labs Packet Analyzer 0.2.0 · TShark (Wireshark) 4.2.2 (Git v4.2.2 packaged as 4.2.2-1.1build3). · full detail (real addresses)

## How to read this (for the AI)

- This file was produced by the Almnjoy Labs Packet Analyzer from one or more packet captures. A deterministic engine
  (tshark, the Wireshark dissector, plus pandas) computed every number here. Treat the numbers as ground truth;
  do not invent figures that are not in this file. If you need a number that is not here, say what to measure.
- Every finding has a Wireshark display filter (and example frame numbers). Quote the filter when you rely on a finding
  so the person can verify it in Wireshark.
- Findings marked **artifact** come from where the capture started or stopped. They are not failures.
- Timings are as seen at the capture point. One capture shows *that* something happened; captures at both ends show *where*.
- The person's own question is below. Answer it first, then say what else in the data matters and what to capture next.

## The person's question

> Break down the individual BGP messages (OPEN, KEEPALIVE, UPDATE, NOTIFICATION, ROUTE-REFRESH) and the IP SLA pings, before, during and after the ISP A failure. Show what we can see in each packet.

- When it happened: 11:11:59 (+10.3 s into the capture)

## Capture

- Source: 2 captures (pcap)
- Packets: 216, duration 155.596 s, 25.9 KB, started 2026-11-25 11:11:48 CST
- Link: HQ1-CORE-R1 Et0/2 <-> ISPA-R1 Et0/2 (143 frames, +0.0 s to +155.6 s)
- Link: HQ1-CORE-R2 Et0/2 <-> ISPB-R1 Et0/2 (73 frames, +0.2 s to +153.4 s)

## Verdict (engine)

**info**: Packet breakdown: 16 packets, 8 kinds of message (BGP, ICMP)

- ISPA-R1 (100.100.255.1) <-> HQ1-CORE-R1 (100.100.255.2): 6 KEEPALIVE, 1 NOTIFICATION, 2 OPEN, 2 ROUTE-REFRESH, 11 UPDATE; closed by HQ1-CORE-R1 (100.100.255.2) at 11:12:14.637 (Cease / Administrative shutdown); re-established at 11:14:00.291 after 105.7 s down
- ISPB-R1 (100.200.255.1) <-> HQ1-CORE-R2 (100.200.255.2): 5 KEEPALIVE, 3 UPDATE; up the whole capture
- Probe 100.100.255.2 -> 100.200.1.1 every 5.0 s: 15 answered, 17 failed; first failure 11:11:59.269 (ICMP 3/13 communication administratively prohibited (ACL)); 15.4 s later: BGP NOTIFICATION 100.100.255.2 -> 100.100.255.1
- 7 UPDATEs ISPA-R1 -> HQ1-CORE-R1 at 11:14:00.298: 7 prefix(es) announced, End-of-RIB
- 3 UPDATEs HQ1-CORE-R1 -> ISPA-R1 at 11:14:00.300: 3 prefix(es) announced, End-of-RIB
- UPDATE ISPA-R1 -> HQ1-CORE-R1: announce 198.51.100.0/25, 198.51.100.0/24
- UPDATE ISPB-R1 -> HQ1-CORE-R2: announce 198.51.100.0/25
- UPDATE ISPB-R1 -> HQ1-CORE-R2: withdraw 198.51.100.0/25

Key numbers: Frames 216; Duration 155.6 s; Links 2; BGP sessions 2; BGP messages 30; Notifications 1; Probes ok / failed 15 / 17; Failure to reaction 15.4 s

## Findings

Most important first. Severity: critical > warning > info > ok > artifact.

1. **[warning] Probe to 100.200.1.1 started failing at 11:11:59.269** (probes)
   Last answered probe 11:11:54.270; from 11:11:59.269 on: ICMP 3/13 communication administratively prohibited (ACL) from 100.100.255.1. The reporting router is telling you an ACL dropped the probe: the path past it is blocked on purpose. An IP SLA operation counts this as a failure; a track object on it goes down after its delay.
   Filter: `icmp && ip.addr == 100.200.1.1 && icmp.type != 8` · frames 15
   +0.3 s from the time given
2. **[warning] BGP session closed by HQ1-CORE-R1: Cease / Administrative shutdown** (bgp)
   ISPA-R1 (100.100.255.1) <-> HQ1-CORE-R1 (100.100.255.2): HQ1-CORE-R1 (100.100.255.2) sent a NOTIFICATION (Cease / Administrative shutdown) at 11:12:14.637 and closed TCP. Administrative shutdown means the sender's own config shut the neighbor: a person, or a script / EEM applet. 
   Filter: `bgp.type == 3 && ip.src == 100.100.255.2` · frames 23
   +15.6 s from the time given
3. **[warning] Forwarding loop for 198.51.100.10: 9 packet(s) died of TTL past this capture point** (icmp)
   Packets from 34.107.243.93 to 198.51.100.10 crossed this link with TTL 115 and 198.51.100.140 answered TTL-exceeded about 64 ms later, quoting TTL 1: each one went round about 114 more hops before dying. A traceroute starts with TTL 1, 2, 3..., so a high TTL here means a loop beyond the capture point, not a traceroute (11:13:17.714 to 11:13:49.770).
   Filter: `icmp.type == 11 && icmp.ip.dst == 198.51.100.10 || ip.dst == 198.51.100.10` · frames 36, 38, 40, 42, 44, 46, 49, 52
   +25.7 s from the time given
4. **[warning] 16 ping(s) refused with ICMP unreachable** (icmp)
   31 echo requests, 15 replies, 16 answered by an ICMP error instead of a reply. That is a router on the path saying no, not packet loss.
   Filter: `icmp.type==3`
5. **[info] 16 packets broken down field by field** (breakdown)
   Kinds: ICMP echo request, ICMP echo reply, BGP KEEPALIVE, ICMP unreachable, admin prohibited, BGP NOTIFICATION, BGP UPDATE, BGP OPEN, BGP ROUTE-REFRESH.
   Filter: `bgp || icmp`
6. **[info] 9 reconnect attempt(s) refused** (bgp)
   ISPA-R1 (100.100.255.1) kept opening TCP 179 to HQ1-CORE-R1 (100.100.255.2) (11:12:24.715 to 11:13:56.892, every 8-14 s) and every SYN got a RST back. A shut-down or unconfigured neighbor refuses the connection; the other side keeps trying on its connect-retry timer.
   Filter: `ip.addr==100.100.255.1 && ip.addr==100.100.255.2 && tcp.port==179 && (tcp.flags.syn == 1 || tcp.flags.reset == 1)` · frames 35
   +25.7 s from the time given
7. **[info] Session re-established at 11:14:00.291, down 105.7 s** (bgp)
   ISPA-R1 (100.100.255.1) <-> HQ1-CORE-R1 (100.100.255.2): OPEN exchange at 11:14:00.291 (HQ1-CORE-R1 AS 65001, hold 180 s, router ID 10.255.1.1; ISPA-R1 AS 65100, hold 180 s, router ID 100.100.254.1; capabilities: 4-byte AS, Enhanced route refresh, Multiprotocol, Route refresh, Route refresh (Cisco)). Each side then sends a KEEPALIVE to confirm, and the table exchange (UPDATEs) follows.
   Filter: `bgp.type == 1 && ip.addr == 100.100.255.1` · frames 114
   +121.3 s from the time given
8. **[info] 7 UPDATEs ISPA-R1 -> HQ1-CORE-R1 at 11:14:00.298: 7 prefix(es) announced, End-of-RIB** (bgp)
   Table exchange in one burst: 203.0.113.0/24 (AS_PATH 65100 65002); 198.51.100.0/25 (AS_PATH 65100 65200 65001 65001 65001 65001); 198.51.100.128/25, 198.51.100.0/24 (AS_PATH 65100 65200 65001); 100.200.0.0/16 (AS_PATH 65100 65200); 100.100.0.0/16 (AS_PATH 65100); 0.0.0.0/0 (AS_PATH 65100); End-of-RIB (empty UPDATE: that was the whole table).
   Filter: `bgp.type == 2 && ip.src == 100.100.255.1` · frames 121, 121, 121, 121, 121, 121, 121
   +121.3 s from the time given
9. **[info] 3 UPDATEs HQ1-CORE-R1 -> ISPA-R1 at 11:14:00.300: 3 prefix(es) announced, End-of-RIB** (bgp)
   Table exchange in one burst: 198.51.100.128/25 (AS_PATH 65001 65001 65001 65001); 198.51.100.0/25, 198.51.100.0/24 (AS_PATH 65001); End-of-RIB (empty UPDATE: that was the whole table).
   Filter: `bgp.type == 2 && ip.src == 100.100.255.2` · frames 123, 123, 123
   +121.3 s from the time given
10. **[info] UPDATE ISPA-R1 -> HQ1-CORE-R1: announce 198.51.100.0/25, 198.51.100.0/24** (bgp)
   At 11:14:00.302, AS_PATH 65100 65001, NEXT_HOP 100.100.255.2.
   Filter: `bgp.type == 2 && ip.src == 100.100.255.1` · frames 125
   +121.3 s from the time given
11. **[info] UPDATE ISPB-R1 -> HQ1-CORE-R2: announce 198.51.100.0/25** (bgp)
   At 11:12:14.643, AS_PATH 65200 65100 65001, NEXT_HOP 100.200.255.1.
   Filter: `bgp.type == 2 && ip.src == 100.200.255.1` · frames 14
   +0.3 s from the time given
12. **[info] UPDATE ISPB-R1 -> HQ1-CORE-R2: withdraw 198.51.100.0/25** (bgp)
   At 11:12:44.741.
   Filter: `bgp.type == 2 && ip.src == 100.200.255.1` · frames 21
   +15.3 s from the time given
13. **[info] UPDATE ISPB-R1 -> HQ1-CORE-R2: announce 198.51.100.0/25** (bgp)
   At 11:14:00.304, AS_PATH 65200 65100 65001, NEXT_HOP 100.200.255.1.
   Filter: `bgp.type == 2 && ip.src == 100.200.255.1` · frames 67
   +69.7 s from the time given
14. **[info] Periodic probe 100.100.255.2 -> 100.200.1.1 every 5.0 s** (probes)
   32 echo requests on a steady 5.0 s interval: this is IP SLA icmp-echo (one source, one target, fixed frequency). 15 answered (median 2.5 ms), 17 failed.
   Filter: `icmp && ip.addr == 100.100.255.2 && ip.addr == 100.200.1.1`
15. **[info] 15.4 s after the first failed probe: BGP NOTIFICATION 100.100.255.2 -> 100.100.255.1** (probes)
   First failed probe 11:11:59.269, then BGP NOTIFICATION 100.100.255.2 -> 100.100.255.1 at 11:12:14.637. When a probe drives a track object, the gap is the track's `delay down` plus the time an EEM applet (or the routing process) takes to act.
   Filter: `bgp.type == 3` · frames 23
   +15.6 s from the time given
16. **[info] 17 conversation(s) across 8 service(s)** (flows)
   17 conversation(s), mostly other IP: ICMP on 100.200.1.1, 189 bps, 29% of bytes. Traffic by pattern: other IP 54%, request / response 28%, keepalive / heartbeat 9%.
   Filter: `ip`
17. **[info] 17 ICMP destination-unreachable message(s)** (icmp)
   Reasons: administratively prohibited (17).
   Filter: `icmp.type==3` · frames 15, 17, 20, 22, 30, 34, 39, 42
   +0.3 s from the time given
18. **[info] 9 connection attempt(s) refused with RST** (tcp)
   The server answered the SYN with a RST: it is up and reachable, but nothing accepts on that port (BGP port 179: the neighbor is shut down or not configured on that side, so it refuses the peer's connect-retry).
   Filter: `tcp.flags.syn==1 && tcp.flags.ack==0 && tcp.port in {179}` · frames 35, 45, 55, 63, 70, 78, 88, 97
   +25.7 s from the time given
19. **[ok] ISPB-R1 heard from every 26.7 s** (bgp)
   2 KEEPALIVE(s) on ISPB-R1 (100.200.255.1) <-> HQ1-CORE-R2 (100.200.255.2); gaps between its BGP messages 18.0 to 52.2 s. Any BGP message (KEEPALIVE or UPDATE) restarts the keepalive timer. IOS sends one every third of the hold time (default 60 s of 180) and jitters it a little lower, so 45 to 60 s apart is normal.
   Filter: `bgp.type == 4 && ip.src == 100.200.255.1`
20. **[ok] HQ1-CORE-R2 heard from every 53.8 s** (bgp)
   3 KEEPALIVE(s) on ISPB-R1 (100.200.255.1) <-> HQ1-CORE-R2 (100.200.255.2); gaps between its BGP messages 52.2 to 55.3 s. Any BGP message (KEEPALIVE or UPDATE) restarts the keepalive timer. IOS sends one every third of the hold time (default 60 s of 180) and jitters it a little lower, so 45 to 60 s apart is normal.
   Filter: `bgp.type == 4 && ip.src == 100.200.255.2`

## Details by area

### Capture overview

216 frames over 155.6 s (25.9 KB), 15 addresses, 13 TCP connections.

**Captures merged onto one timeline**

| Link | File | Frames | From (s) | To (s) |
|---|---|---|---|---|
| HQ1-CORE-R1 Et0/2 <-> ISPA-R1 Et0/2 | P1-ISPA-link_HQ1-CORE-R1-Et0-2.pcap | 143 | 0.0 | 155.6 |
| HQ1-CORE-R2 Et0/2 <-> ISPB-R1 Et0/2 | P2-ISPB-link_HQ1-CORE-R2-Et0-2.pcap | 73 | 0.2 | 153.4 |

**Protocol mix**

| Protocol | Frames | Share |
|---|---|---|
| ICMP | 73 | 33.8% |
| TCP | 48 | 22.2% |
| LOOP | 32 | 14.8% |
| BGP | 21 | 9.7% |
| LLDP | 17 | 7.9% |
| CDP | 13 | 6.0% |
| ESP | 12 | 5.6% |

**Top conversations**

| Hosts | Frames | Bytes |
|---|---|---|
| 100.100.255.1 <-> 100.100.255.2 | 61 | 4.6 KB |
| 100.100.255.2 <-> 100.200.1.1 | 47 | 3.6 KB |
| 100.200.255.1 <-> 100.200.255.2 | 16 | 1.1 KB |
| aa:bb:cc:00:19:20 <-> aa:bb:cc:00:19:20 | 16 | 960 B |
| aa:bb:cc:00:18:20 <-> aa:bb:cc:00:18:20 | 16 | 960 B |
| 100.200.255.10 <-> 100.200.255.2 | 12 | 1.9 KB |
| 198.51.100.140 <-> 34.107.243.93 | 9 | 630 B |
| 198.51.100.10 <-> 34.107.243.93 | 9 | 594 B |
| 01:80:c2:00:00:0e <-> aa:bb:cc:00:12:20 | 6 | 2.2 KB |
| 01:80:c2:00:00:0e <-> aa:bb:cc:00:18:20 | 6 | 2.3 KB |
| 01:80:c2:00:00:0e <-> aa:bb:cc:00:14:20 | 5 | 1.9 KB |
| 01:00:0c:cc:cc:cc <-> aa:bb:cc:00:18:20 | 4 | 1.6 KB |

### Packet breakdown

16 packets, one of every kind of BGP, ICMP message in the capture, decoded field by field. Click a field to light up its bytes. Rare messages (UPDATE, NOTIFICATION, OPEN) are all shown; routine ones (KEEPALIVE, ping) once per sender.

**Packets broken down below**

| # | Clock | Message | From -> to | Bytes | Frame |
|---|---|---|---|---|---|
| 1 | 11:11:49.270 | ICMP echo request | HQ1-CORE-R1 -> ISPA-R1 | 78 | 2 |
| 2 | 11:11:49.272 | ICMP echo reply | ISPA-R1 -> HQ1-CORE-R1 | 78 | 3 |
| 3 | 11:11:56.033 | BGP KEEPALIVE | ISPA-R1 -> HQ1-CORE-R1 | 73 | 9 |
| 4 | 11:11:56.594 | BGP KEEPALIVE | ISPB-R1 -> HQ1-CORE-R2 | 73 | 4 |
| 5 | 11:11:59.008 | BGP KEEPALIVE | HQ1-CORE-R1 -> ISPA-R1 | 73 | 12 |
| 6 | 11:11:59.271 | ICMP unreachable, admin prohibited | ISPA-R1 -> HQ1-CORE-R1 | 70 | 15 |
| 7 | 11:12:14.637 | BGP NOTIFICATION | HQ1-CORE-R1 -> ISPA-R1 | 75 | 23 |
| 8 | 11:12:14.643 | BGP UPDATE | ISPB-R1 -> HQ1-CORE-R2 | 110 | 14 |
| 9 | 11:12:44.741 | BGP UPDATE | ISPB-R1 -> HQ1-CORE-R2 | 82 | 21 |
| 10 | 11:14:00.291 | BGP OPEN | HQ1-CORE-R1 -> ISPA-R1 | 111 | 114 |
| 11 | 11:14:00.292 | BGP OPEN | ISPA-R1 -> HQ1-CORE-R1 | 111 | 116 |
| 12 | 11:14:00.295 | BGP ROUTE-REFRESH | ISPA-R1 -> HQ1-CORE-R1 | 77 | 120 |
| 13 | 11:14:00.298 | BGP UPDATE | ISPA-R1 -> HQ1-CORE-R1 | 426 | 121 |
| 14 | 11:14:00.300 | BGP UPDATE | HQ1-CORE-R1 -> ISPA-R1 | 196 | 123 |
| 15 | 11:14:00.302 | BGP UPDATE | ISPA-R1 -> HQ1-CORE-R1 | 110 | 125 |
| 16 | 11:14:00.304 | BGP UPDATE | ISPB-R1 -> HQ1-CORE-R2 | 110 | 67 |

Packets decoded field by field:

#### #1 ICMP echo request: HQ1-CORE-R1 -> ISPA-R1

11:11:49.270 (+0.593 s), frame 2, 78 bytes, HQ1-CORE-R1 Et0/2 <-> ISPA-R1 Et0/2

The probe itself.

- **Ethernet II, Src: aa:bb:cc:00:18:20, Dst: aa:bb:cc:00:12:20**
  - Destination: aa:bb:cc:00:12:20 _(offset 0, 6 B)_
  - Source: aa:bb:cc:00:18:20 _(offset 6, 6 B)_
  - Type: IPv4 (0x0800) _(offset 12, 2 B)_
- **Internet Protocol Version 4, Src: 100.100.255.2, Dst: 100.200.1.1**
  - 0100 .... = Version: 4 _(offset 14, 1 B)_
  - .... 0101 = Header Length: 20 bytes (5) _(offset 14, 1 B)_
  - Differentiated Services Field: 0x00 (DSCP: CS0, ECN: Not-ECT) _(offset 15, 1 B)_
    - 0000 00.. = Differentiated Services Codepoint: Default (0) _(offset 15, 1 B)_
    - .... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0) _(offset 15, 1 B)_
  - Total Length: 64 _(offset 16, 2 B)_
  - Identification: 0x0134 (308) _(offset 18, 2 B)_
  - 000. .... = Flags: 0x0 _(offset 20, 1 B)_
    - 0... .... = Reserved bit: Not set _(offset 20, 1 B)_
    - .0.. .... = Don't fragment: Not set _(offset 20, 1 B)_
    - ..0. .... = More fragments: Not set _(offset 20, 1 B)_
  - ...0 0000 0000 0000 = Fragment Offset: 0 _(offset 20, 2 B)_
  - Time to Live: 255 _(offset 22, 1 B)_
  - Protocol: ICMP (1) _(offset 23, 1 B)_
  - Header Checksum: 0xf158 [validation disabled] _(offset 24, 2 B)_
  - Source Address: 100.100.255.2 _(offset 26, 4 B)_
  - Destination Address: 100.200.1.1 _(offset 30, 4 B)_
- **Internet Control Message Protocol**
  - Type: 8 (Echo (ping) request) _(offset 34, 1 B)_
  - Code: 0 _(offset 35, 1 B)_
  - Checksum: 0xe5d1 [correct] _(offset 36, 2 B)_
  - Identifier (BE): 281 (0x0119) _(offset 38, 2 B)_
  - Identifier (LE): 6401 (0x1901) _(offset 38, 2 B)_
  - Sequence Number (BE): 1 (0x0001) _(offset 40, 2 B)_
  - Sequence Number (LE): 256 (0x0100) _(offset 40, 2 B)_
  - data
    - Data: 000000005513ae5cabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd00000000 _(offset 42, 36 B)_
    - Length: 36

#### #2 ICMP echo reply: ISPA-R1 -> HQ1-CORE-R1

11:11:49.272 (+0.595 s), frame 3, 78 bytes, HQ1-CORE-R1 Et0/2 <-> ISPA-R1 Et0/2

The target answering.

- **Ethernet II, Src: aa:bb:cc:00:12:20, Dst: aa:bb:cc:00:18:20**
  - Destination: aa:bb:cc:00:18:20 _(offset 0, 6 B)_
  - Source: aa:bb:cc:00:12:20 _(offset 6, 6 B)_
  - Type: IPv4 (0x0800) _(offset 12, 2 B)_
- **Internet Protocol Version 4, Src: 100.200.1.1, Dst: 100.100.255.2**
  - 0100 .... = Version: 4 _(offset 14, 1 B)_
  - .... 0101 = Header Length: 20 bytes (5) _(offset 14, 1 B)_
  - Differentiated Services Field: 0x00 (DSCP: CS0, ECN: Not-ECT) _(offset 15, 1 B)_
    - 0000 00.. = Differentiated Services Codepoint: Default (0) _(offset 15, 1 B)_
    - .... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0) _(offset 15, 1 B)_
  - Total Length: 64 _(offset 16, 2 B)_
  - Identification: 0x0134 (308) _(offset 18, 2 B)_
  - 000. .... = Flags: 0x0 _(offset 20, 1 B)_
    - 0... .... = Reserved bit: Not set _(offset 20, 1 B)_
    - .0.. .... = Don't fragment: Not set _(offset 20, 1 B)_
    - ..0. .... = More fragments: Not set _(offset 20, 1 B)_
  - ...0 0000 0000 0000 = Fragment Offset: 0 _(offset 20, 2 B)_
  - Time to Live: 254 _(offset 22, 1 B)_
  - Protocol: ICMP (1) _(offset 23, 1 B)_
  - Header Checksum: 0xf258 [validation disabled] _(offset 24, 2 B)_
  - Source Address: 100.200.1.1 _(offset 26, 4 B)_
  - Destination Address: 100.100.255.2 _(offset 30, 4 B)_
- **Internet Control Message Protocol**
  - Type: 0 (Echo (ping) reply) _(offset 34, 1 B)_
  - Code: 0 _(offset 35, 1 B)_
  - Checksum: 0xedd1 [correct] _(offset 36, 2 B)_
  - Identifier (BE): 281 (0x0119) _(offset 38, 2 B)_
  - Identifier (LE): 6401 (0x1901) _(offset 38, 2 B)_
  - Sequence Number (BE): 1 (0x0001) _(offset 40, 2 B)_
  - Sequence Number (LE): 256 (0x0100) _(offset 40, 2 B)_
  - data
    - Data: 000000005513ae5cabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd00000000 _(offset 42, 36 B)_
    - Length: 36

#### #3 BGP KEEPALIVE: ISPA-R1 -> HQ1-CORE-R1

11:11:56.033 (+7.356 s), frame 9, 73 bytes, HQ1-CORE-R1 Et0/2 <-> ISPA-R1 Et0/2

Header only: marker, length 19, type 4. Nothing else in it. Its whole job is to reset the peer's hold timer.

- **Ethernet II, Src: aa:bb:cc:00:12:20, Dst: aa:bb:cc:00:18:20**
  - Destination: aa:bb:cc:00:18:20 _(offset 0, 6 B)_
  - Source: aa:bb:cc:00:12:20 _(offset 6, 6 B)_
  - Type: IPv4 (0x0800) _(offset 12, 2 B)_
- **Internet Protocol Version 4, Src: 100.100.255.1, Dst: 100.100.255.2**
  - 0100 .... = Version: 4 _(offset 14, 1 B)_
  - .... 0101 = Header Length: 20 bytes (5) _(offset 14, 1 B)_
  - Differentiated Services Field: 0xc0 (DSCP: CS6, ECN: Not-ECT) _(offset 15, 1 B)_
    - 1100 00.. = Differentiated Services Codepoint: Class Selector 6 (48) _(offset 15, 1 B)_
    - .... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0) _(offset 15, 1 B)_
  - Total Length: 59 _(offset 16, 2 B)_
  - Identification: 0x677c (26492) _(offset 18, 2 B)_
  - 010. .... = Flags: 0x2, Don't fragment _(offset 20, 1 B)_
    - 0... .... = Reserved bit: Not set _(offset 20, 1 B)_
    - .1.. .... = Don't fragment: Set _(offset 20, 1 B)_
    - ..0. .... = More fragments: Not set _(offset 20, 1 B)_
  - ...0 0000 0000 0000 = Fragment Offset: 0 _(offset 20, 2 B)_
  - Time to Live: 1 _(offset 22, 1 B)_
  - Protocol: TCP (6) _(offset 23, 1 B)_
  - Header Checksum: 0x4ab4 [validation disabled] _(offset 24, 2 B)_
  - Source Address: 100.100.255.1 _(offset 26, 4 B)_
  - Destination Address: 100.100.255.2 _(offset 30, 4 B)_
- **Transmission Control Protocol, Src Port: 179, Dst Port: 20305, Seq: 1, Ack: 1, Len: 19**
  - TCP Segment Len: 19
  - Sequence Number: 1    (relative sequence number) _(offset 38, 4 B)_
  - Acknowledgment Number: 1    (relative ack number) _(offset 42, 4 B)_
  - 0101 .... = Header Length: 20 bytes (5) _(offset 46, 1 B)_
  - Flags: 0x018 (PSH, ACK) _(offset 46, 2 B)_
    - 000. .... .... = Reserved: Not set _(offset 46, 1 B)_
    - ...0 .... .... = Accurate ECN: Not set _(offset 46, 1 B)_
    - .... 0... .... = Congestion Window Reduced: Not set _(offset 47, 1 B)_
    - .... .0.. .... = ECN-Echo: Not set _(offset 47, 1 B)_
    - .... ..0. .... = Urgent: Not set _(offset 47, 1 B)_
    - .... ...1 .... = Acknowledgment: Set _(offset 47, 1 B)_
    - .... .... 1... = Push: Set _(offset 47, 1 B)_
    - .... .... .0.. = Reset: Not set _(offset 47, 1 B)_
    - .... .... ..0. = Syn: Not set _(offset 47, 1 B)_
    - .... .... ...0 = Fin: Not set _(offset 47, 1 B)_
    - TCP Flags: ·······AP··· _(offset 46, 2 B)_
  - Window: 16004 _(offset 48, 2 B)_
  - Window size scaling factor: -1 (unknown) _(offset 48, 2 B)_
  - Checksum: 0xe5d8 [unverified] _(offset 50, 2 B)_
  - Urgent Pointer: 0 _(offset 52, 2 B)_
  - Timestamps
- **Border Gateway Protocol - KEEPALIVE Message**
  - Marker: ffffffffffffffffffffffffffffffff _(offset 54, 16 B)_
  - Length: 19 _(offset 70, 2 B)_
  - Type: KEEPALIVE Message (4) _(offset 72, 1 B)_

#### #4 BGP KEEPALIVE: ISPB-R1 -> HQ1-CORE-R2

11:11:56.594 (+7.916 s), frame 4, 73 bytes, HQ1-CORE-R2 Et0/2 <-> ISPB-R1 Et0/2

Header only: marker, length 19, type 4. Nothing else in it. Its whole job is to reset the peer's hold timer.

- **Ethernet II, Src: aa:bb:cc:00:14:20, Dst: aa:bb:cc:00:19:20**
  - Destination: aa:bb:cc:00:19:20 _(offset 0, 6 B)_
  - Source: aa:bb:cc:00:14:20 _(offset 6, 6 B)_
  - Type: IPv4 (0x0800) _(offset 12, 2 B)_
- **Internet Protocol Version 4, Src: 100.200.255.1, Dst: 100.200.255.2**
  - 0100 .... = Version: 4 _(offset 14, 1 B)_
  - .... 0101 = Header Length: 20 bytes (5) _(offset 14, 1 B)_
  - Differentiated Services Field: 0xc0 (DSCP: CS6, ECN: Not-ECT) _(offset 15, 1 B)_
    - 1100 00.. = Differentiated Services Codepoint: Class Selector 6 (48) _(offset 15, 1 B)_
    - .... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0) _(offset 15, 1 B)_
  - Total Length: 59 _(offset 16, 2 B)_
  - Identification: 0x2d6c (11628) _(offset 18, 2 B)_
  - 010. .... = Flags: 0x2, Don't fragment _(offset 20, 1 B)_
    - 0... .... = Reserved bit: Not set _(offset 20, 1 B)_
    - .1.. .... = Don't fragment: Set _(offset 20, 1 B)_
    - ..0. .... = More fragments: Not set _(offset 20, 1 B)_
  - ...0 0000 0000 0000 = Fragment Offset: 0 _(offset 20, 2 B)_
  - Time to Live: 1 _(offset 22, 1 B)_
  - Protocol: TCP (6) _(offset 23, 1 B)_
  - Header Checksum: 0x83fc [validation disabled] _(offset 24, 2 B)_
  - Source Address: 100.200.255.1 _(offset 26, 4 B)_
  - Destination Address: 100.200.255.2 _(offset 30, 4 B)_
- **Transmission Control Protocol, Src Port: 179, Dst Port: 20076, Seq: 1, Ack: 1, Len: 19**
  - TCP Segment Len: 19
  - Sequence Number: 1    (relative sequence number) _(offset 38, 4 B)_
  - Acknowledgment Number: 1    (relative ack number) _(offset 42, 4 B)_
  - 0101 .... = Header Length: 20 bytes (5) _(offset 46, 1 B)_
  - Flags: 0x018 (PSH, ACK) _(offset 46, 2 B)_
    - 000. .... .... = Reserved: Not set _(offset 46, 1 B)_
    - ...0 .... .... = Accurate ECN: Not set _(offset 46, 1 B)_
    - .... 0... .... = Congestion Window Reduced: Not set _(offset 47, 1 B)_
    - .... .0.. .... = ECN-Echo: Not set _(offset 47, 1 B)_
    - .... ..0. .... = Urgent: Not set _(offset 47, 1 B)_
    - .... ...1 .... = Acknowledgment: Set _(offset 47, 1 B)_
    - .... .... 1... = Push: Set _(offset 47, 1 B)_
    - .... .... .0.. = Reset: Not set _(offset 47, 1 B)_
    - .... .... ..0. = Syn: Not set _(offset 47, 1 B)_
    - .... .... ...0 = Fin: Not set _(offset 47, 1 B)_
    - TCP Flags: ·······AP··· _(offset 46, 2 B)_
  - Window: 15586 _(offset 48, 2 B)_
  - Window size scaling factor: -1 (unknown) _(offset 48, 2 B)_
  - Checksum: 0x0541 [unverified] _(offset 50, 2 B)_
  - Urgent Pointer: 0 _(offset 52, 2 B)_
  - Timestamps
- **Border Gateway Protocol - KEEPALIVE Message**
  - Marker: ffffffffffffffffffffffffffffffff _(offset 54, 16 B)_
  - Length: 19 _(offset 70, 2 B)_
  - Type: KEEPALIVE Message (4) _(offset 72, 1 B)_

#### #5 BGP KEEPALIVE: HQ1-CORE-R1 -> ISPA-R1

11:11:59.008 (+10.330 s), frame 12, 73 bytes, HQ1-CORE-R1 Et0/2 <-> ISPA-R1 Et0/2

Header only: marker, length 19, type 4. Nothing else in it. Its whole job is to reset the peer's hold timer.

- **Ethernet II, Src: aa:bb:cc:00:18:20, Dst: aa:bb:cc:00:12:20**
  - Destination: aa:bb:cc:00:12:20 _(offset 0, 6 B)_
  - Source: aa:bb:cc:00:18:20 _(offset 6, 6 B)_
  - Type: IPv4 (0x0800) _(offset 12, 2 B)_
- **Internet Protocol Version 4, Src: 100.100.255.2, Dst: 100.100.255.1**
  - 0100 .... = Version: 4 _(offset 14, 1 B)_
  - .... 0101 = Header Length: 20 bytes (5) _(offset 14, 1 B)_
  - Differentiated Services Field: 0xc0 (DSCP: CS6, ECN: Not-ECT) _(offset 15, 1 B)_
    - 1100 00.. = Differentiated Services Codepoint: Class Selector 6 (48) _(offset 15, 1 B)_
    - .... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0) _(offset 15, 1 B)_
  - Total Length: 59 _(offset 16, 2 B)_
  - Identification: 0x78e8 (30952) _(offset 18, 2 B)_
  - 010. .... = Flags: 0x2, Don't fragment _(offset 20, 1 B)_
    - 0... .... = Reserved bit: Not set _(offset 20, 1 B)_
    - .1.. .... = Don't fragment: Set _(offset 20, 1 B)_
    - ..0. .... = More fragments: Not set _(offset 20, 1 B)_
  - ...0 0000 0000 0000 = Fragment Offset: 0 _(offset 20, 2 B)_
  - Time to Live: 1 _(offset 22, 1 B)_
  - Protocol: TCP (6) _(offset 23, 1 B)_
  - Header Checksum: 0x3948 [validation disabled] _(offset 24, 2 B)_
  - Source Address: 100.100.255.2 _(offset 26, 4 B)_
  - Destination Address: 100.100.255.1 _(offset 30, 4 B)_
- **Transmission Control Protocol, Src Port: 20305, Dst Port: 179, Seq: 1, Ack: 20, Len: 19**
  - TCP Segment Len: 19
  - Sequence Number: 1    (relative sequence number) _(offset 38, 4 B)_
  - Acknowledgment Number: 20    (relative ack number) _(offset 42, 4 B)_
  - 0101 .... = Header Length: 20 bytes (5) _(offset 46, 1 B)_
  - Flags: 0x018 (PSH, ACK) _(offset 46, 2 B)_
    - 000. .... .... = Reserved: Not set _(offset 46, 1 B)_
    - ...0 .... .... = Accurate ECN: Not set _(offset 46, 1 B)_
    - .... 0... .... = Congestion Window Reduced: Not set _(offset 47, 1 B)_
    - .... .0.. .... = ECN-Echo: Not set _(offset 47, 1 B)_
    - .... ..0. .... = Urgent: Not set _(offset 47, 1 B)_
    - .... ...1 .... = Acknowledgment: Set _(offset 47, 1 B)_
    - .... .... 1... = Push: Set _(offset 47, 1 B)_
    - .... .... .0.. = Reset: Not set _(offset 47, 1 B)_
    - .... .... ..0. = Syn: Not set _(offset 47, 1 B)_
    - .... .... ...0 = Fin: Not set _(offset 47, 1 B)_
    - TCP Flags: ·······AP··· _(offset 46, 2 B)_
  - Window: 15320 _(offset 48, 2 B)_
  - Window size scaling factor: -1 (unknown) _(offset 48, 2 B)_
  - Checksum: 0xe871 [unverified] _(offset 50, 2 B)_
  - Urgent Pointer: 0 _(offset 52, 2 B)_
  - Timestamps
- **Border Gateway Protocol - KEEPALIVE Message**
  - Marker: ffffffffffffffffffffffffffffffff _(offset 54, 16 B)_
  - Length: 19 _(offset 70, 2 B)_
  - Type: KEEPALIVE Message (4) _(offset 72, 1 B)_

#### #6 ICMP unreachable, admin prohibited: ISPA-R1 -> HQ1-CORE-R1

11:11:59.271 (+10.593 s), frame 15, 70 bytes, HQ1-CORE-R1 Et0/2 <-> ISPA-R1 Et0/2

A router on the path refusing the probe, with the original packet's header quoted inside.

- **Ethernet II, Src: aa:bb:cc:00:12:20, Dst: aa:bb:cc:00:18:20**
  - Destination: aa:bb:cc:00:18:20 _(offset 0, 6 B)_
  - Source: aa:bb:cc:00:12:20 _(offset 6, 6 B)_
  - Type: IPv4 (0x0800) _(offset 12, 2 B)_
- **Internet Protocol Version 4, Src: 100.100.255.1, Dst: 100.100.255.2**
  - 0100 .... = Version: 4 _(offset 14, 1 B)_
  - .... 0101 = Header Length: 20 bytes (5) _(offset 14, 1 B)_
  - Differentiated Services Field: 0x00 (DSCP: CS0, ECN: Not-ECT) _(offset 15, 1 B)_
    - 0000 00.. = Differentiated Services Codepoint: Default (0) _(offset 15, 1 B)_
    - .... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0) _(offset 15, 1 B)_
  - Total Length: 56 _(offset 16, 2 B)_
  - Identification: 0x47e8 (18408) _(offset 18, 2 B)_
  - 000. .... = Flags: 0x0 _(offset 20, 1 B)_
    - 0... .... = Reserved bit: Not set _(offset 20, 1 B)_
    - .0.. .... = Don't fragment: Not set _(offset 20, 1 B)_
    - ..0. .... = More fragments: Not set _(offset 20, 1 B)_
  - ...0 0000 0000 0000 = Fragment Offset: 0 _(offset 20, 2 B)_
  - Time to Live: 255 _(offset 22, 1 B)_
  - Protocol: ICMP (1) _(offset 23, 1 B)_
  - Header Checksum: 0xad0f [validation disabled] _(offset 24, 2 B)_
  - Source Address: 100.100.255.1 _(offset 26, 4 B)_
  - Destination Address: 100.100.255.2 _(offset 30, 4 B)_
- **Internet Control Message Protocol**
  - Type: 3 (Destination unreachable) _(offset 34, 1 B)_
  - Code: 13 (Communication administratively filtered) _(offset 35, 1 B)_
  - Checksum: 0x3517 [correct] _(offset 36, 2 B)_
  - Unused: 00000000 _(offset 38, 4 B)_

#### #7 BGP NOTIFICATION: HQ1-CORE-R1 -> ISPA-R1

11:12:14.637 (+25.959 s), frame 23, 75 bytes, HQ1-CORE-R1 Et0/2 <-> ISPA-R1 Et0/2

The last BGP message of a session: an error code and subcode, then the sender closes TCP.

- **Ethernet II, Src: aa:bb:cc:00:18:20, Dst: aa:bb:cc:00:12:20**
  - Destination: aa:bb:cc:00:12:20 _(offset 0, 6 B)_
  - Source: aa:bb:cc:00:18:20 _(offset 6, 6 B)_
  - Type: IPv4 (0x0800) _(offset 12, 2 B)_
- **Internet Protocol Version 4, Src: 100.100.255.2, Dst: 100.100.255.1**
  - 0100 .... = Version: 4 _(offset 14, 1 B)_
  - .... 0101 = Header Length: 20 bytes (5) _(offset 14, 1 B)_
  - Differentiated Services Field: 0xc0 (DSCP: CS6, ECN: Not-ECT) _(offset 15, 1 B)_
    - 1100 00.. = Differentiated Services Codepoint: Class Selector 6 (48) _(offset 15, 1 B)_
    - .... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0) _(offset 15, 1 B)_
  - Total Length: 61 _(offset 16, 2 B)_
  - Identification: 0x78e9 (30953) _(offset 18, 2 B)_
  - 010. .... = Flags: 0x2, Don't fragment _(offset 20, 1 B)_
    - 0... .... = Reserved bit: Not set _(offset 20, 1 B)_
    - .1.. .... = Don't fragment: Set _(offset 20, 1 B)_
    - ..0. .... = More fragments: Not set _(offset 20, 1 B)_
  - ...0 0000 0000 0000 = Fragment Offset: 0 _(offset 20, 2 B)_
  - Time to Live: 1 _(offset 22, 1 B)_
  - Protocol: TCP (6) _(offset 23, 1 B)_
  - Header Checksum: 0x3945 [validation disabled] _(offset 24, 2 B)_
  - Source Address: 100.100.255.2 _(offset 26, 4 B)_
  - Destination Address: 100.100.255.1 _(offset 30, 4 B)_
- **Transmission Control Protocol, Src Port: 20305, Dst Port: 179, Seq: 20, Ack: 20, Len: 21**
  - TCP Segment Len: 21
  - Sequence Number: 20    (relative sequence number) _(offset 38, 4 B)_
  - Acknowledgment Number: 20    (relative ack number) _(offset 42, 4 B)_
  - 0101 .... = Header Length: 20 bytes (5) _(offset 46, 1 B)_
  - Flags: 0x018 (PSH, ACK) _(offset 46, 2 B)_
    - 000. .... .... = Reserved: Not set _(offset 46, 1 B)_
    - ...0 .... .... = Accurate ECN: Not set _(offset 46, 1 B)_
    - .... 0... .... = Congestion Window Reduced: Not set _(offset 47, 1 B)_
    - .... .0.. .... = ECN-Echo: Not set _(offset 47, 1 B)_
    - .... ..0. .... = Urgent: Not set _(offset 47, 1 B)_
    - .... ...1 .... = Acknowledgment: Set _(offset 47, 1 B)_
    - .... .... 1... = Push: Set _(offset 47, 1 B)_
    - .... .... .0.. = Reset: Not set _(offset 47, 1 B)_
    - .... .... ..0. = Syn: Not set _(offset 47, 1 B)_
    - .... .... ...0 = Fin: Not set _(offset 47, 1 B)_
    - TCP Flags: ·······AP··· _(offset 46, 2 B)_
  - Window: 15320 _(offset 48, 2 B)_
  - Window size scaling factor: -1 (unknown) _(offset 48, 2 B)_
  - Checksum: 0xe754 [unverified] _(offset 50, 2 B)_
  - Urgent Pointer: 0 _(offset 52, 2 B)_
  - Timestamps
- **Border Gateway Protocol - NOTIFICATION Message**
  - Marker: ffffffffffffffffffffffffffffffff _(offset 54, 16 B)_
  - Length: 21 _(offset 70, 2 B)_
  - Type: NOTIFICATION Message (3) _(offset 72, 1 B)_
  - Major error Code: Cease (6) _(offset 73, 1 B)_
  - Minor error Code (Cease): Administratively Shutdown (2) _(offset 74, 1 B)_

#### #8 BGP UPDATE: ISPB-R1 -> HQ1-CORE-R2

11:12:14.643 (+25.966 s), frame 14, 110 bytes, HQ1-CORE-R2 Et0/2 <-> ISPB-R1 Et0/2

Announces and/or withdraws prefixes. Withdrawn routes first, then the path attributes, then the prefixes (NLRI) that share them.

- **Ethernet II, Src: aa:bb:cc:00:14:20, Dst: aa:bb:cc:00:19:20**
  - Destination: aa:bb:cc:00:19:20 _(offset 0, 6 B)_
  - Source: aa:bb:cc:00:14:20 _(offset 6, 6 B)_
  - Type: IPv4 (0x0800) _(offset 12, 2 B)_
- **Internet Protocol Version 4, Src: 100.200.255.1, Dst: 100.200.255.2**
  - 0100 .... = Version: 4 _(offset 14, 1 B)_
  - .... 0101 = Header Length: 20 bytes (5) _(offset 14, 1 B)_
  - Differentiated Services Field: 0xc0 (DSCP: CS6, ECN: Not-ECT) _(offset 15, 1 B)_
    - 1100 00.. = Differentiated Services Codepoint: Class Selector 6 (48) _(offset 15, 1 B)_
    - .... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0) _(offset 15, 1 B)_
  - Total Length: 96 _(offset 16, 2 B)_
  - Identification: 0x2d6e (11630) _(offset 18, 2 B)_
  - 010. .... = Flags: 0x2, Don't fragment _(offset 20, 1 B)_
    - 0... .... = Reserved bit: Not set _(offset 20, 1 B)_
    - .1.. .... = Don't fragment: Set _(offset 20, 1 B)_
    - ..0. .... = More fragments: Not set _(offset 20, 1 B)_
  - ...0 0000 0000 0000 = Fragment Offset: 0 _(offset 20, 2 B)_
  - Time to Live: 1 _(offset 22, 1 B)_
  - Protocol: TCP (6) _(offset 23, 1 B)_
  - Header Checksum: 0x83d5 [validation disabled] _(offset 24, 2 B)_
  - Source Address: 100.200.255.1 _(offset 26, 4 B)_
  - Destination Address: 100.200.255.2 _(offset 30, 4 B)_
- **Transmission Control Protocol, Src Port: 179, Dst Port: 20076, Seq: 20, Ack: 20, Len: 56**
  - TCP Segment Len: 56
  - Sequence Number: 20    (relative sequence number) _(offset 38, 4 B)_
  - Acknowledgment Number: 20    (relative ack number) _(offset 42, 4 B)_
  - 0101 .... = Header Length: 20 bytes (5) _(offset 46, 1 B)_
  - Flags: 0x018 (PSH, ACK) _(offset 46, 2 B)_
    - 000. .... .... = Reserved: Not set _(offset 46, 1 B)_
    - ...0 .... .... = Accurate ECN: Not set _(offset 46, 1 B)_
    - .... 0... .... = Congestion Window Reduced: Not set _(offset 47, 1 B)_
    - .... .0.. .... = ECN-Echo: Not set _(offset 47, 1 B)_
    - .... ..0. .... = Urgent: Not set _(offset 47, 1 B)_
    - .... ...1 .... = Acknowledgment: Set _(offset 47, 1 B)_
    - .... .... 1... = Push: Set _(offset 47, 1 B)_
    - .... .... .0.. = Reset: Not set _(offset 47, 1 B)_
    - .... .... ..0. = Syn: Not set _(offset 47, 1 B)_
    - .... .... ...0 = Fin: Not set _(offset 47, 1 B)_
    - TCP Flags: ·······AP··· _(offset 46, 2 B)_
  - Window: 15567 _(offset 48, 2 B)_
  - Window size scaling factor: -1 (unknown) _(offset 48, 2 B)_
  - Checksum: 0xb1b5 [unverified] _(offset 50, 2 B)_
  - Urgent Pointer: 0 _(offset 52, 2 B)_
  - Timestamps
- **Border Gateway Protocol - UPDATE Message**
  - Marker: ffffffffffffffffffffffffffffffff _(offset 54, 16 B)_
  - Length: 56 _(offset 70, 2 B)_
  - Type: UPDATE Message (2) _(offset 72, 1 B)_
  - Withdrawn Routes Length: 0 _(offset 73, 2 B)_
  - Total Path Attribute Length: 28 _(offset 75, 2 B)_
  - Path attributes _(offset 77, 28 B)_
    - Path Attribute - ORIGIN: IGP _(offset 77, 4 B)_
      - Flags: 0x40, Transitive, Well-known, Complete _(offset 77, 1 B)_
        - 0... .... = Optional: Not set _(offset 77, 1 B)_
        - .1.. .... = Transitive: Set _(offset 77, 1 B)_
        - ..0. .... = Partial: Not set _(offset 77, 1 B)_
        - ...0 .... = Extended-Length: Not set _(offset 77, 1 B)_
        - .... 0000 = Unused: 0x0 _(offset 77, 1 B)_
      - Type Code: ORIGIN (1) _(offset 78, 1 B)_
      - Length: 1 _(offset 79, 1 B)_
      - Origin: IGP (0) _(offset 80, 1 B)_
    - Path Attribute - AS_PATH: 65200 65100 65001  _(offset 81, 17 B)_
      - Flags: 0x40, Transitive, Well-known, Complete _(offset 81, 1 B)_
        - 0... .... = Optional: Not set _(offset 81, 1 B)_
        - .1.. .... = Transitive: Set _(offset 81, 1 B)_
        - ..0. .... = Partial: Not set _(offset 81, 1 B)_
        - ...0 .... = Extended-Length: Not set _(offset 81, 1 B)_
        - .... 0000 = Unused: 0x0 _(offset 81, 1 B)_
      - Type Code: AS_PATH (2) _(offset 82, 1 B)_
      - Length: 14 _(offset 83, 1 B)_
      - AS Path segment: 65200 65100 65001 _(offset 84, 14 B)_
        - Segment type: AS_SEQUENCE (2) _(offset 84, 1 B)_
        - Segment length (number of ASN): 3 _(offset 85, 1 B)_
        - AS4: 65200 _(offset 86, 4 B)_
        - AS4: 65100 _(offset 90, 4 B)_
        - AS4: 65001 _(offset 94, 4 B)_
    - Path Attribute - NEXT_HOP: 100.200.255.1  _(offset 98, 7 B)_
      - Flags: 0x40, Transitive, Well-known, Complete _(offset 98, 1 B)_
        - 0... .... = Optional: Not set _(offset 98, 1 B)_
        - .1.. .... = Transitive: Set _(offset 98, 1 B)_
        - ..0. .... = Partial: Not set _(offset 98, 1 B)_
        - ...0 .... = Extended-Length: Not set _(offset 98, 1 B)_
        - .... 0000 = Unused: 0x0 _(offset 98, 1 B)_
      - Type Code: NEXT_HOP (3) _(offset 99, 1 B)_
      - Length: 4 _(offset 100, 1 B)_
      - Next hop: 100.200.255.1 _(offset 101, 4 B)_
  - Network Layer Reachability Information (NLRI) _(offset 105, 5 B)_
    - 198.51.100.0/25 _(offset 105, 5 B)_
      - NLRI prefix length: 25 _(offset 105, 1 B)_
      - NLRI prefix: 198.51.100.0 _(offset 106, 4 B)_

#### #9 BGP UPDATE: ISPB-R1 -> HQ1-CORE-R2

11:12:44.741 (+56.064 s), frame 21, 82 bytes, HQ1-CORE-R2 Et0/2 <-> ISPB-R1 Et0/2

Announces and/or withdraws prefixes. Withdrawn routes first, then the path attributes, then the prefixes (NLRI) that share them.

- **Ethernet II, Src: aa:bb:cc:00:14:20, Dst: aa:bb:cc:00:19:20**
  - Destination: aa:bb:cc:00:19:20 _(offset 0, 6 B)_
  - Source: aa:bb:cc:00:14:20 _(offset 6, 6 B)_
  - Type: IPv4 (0x0800) _(offset 12, 2 B)_
- **Internet Protocol Version 4, Src: 100.200.255.1, Dst: 100.200.255.2**
  - 0100 .... = Version: 4 _(offset 14, 1 B)_
  - .... 0101 = Header Length: 20 bytes (5) _(offset 14, 1 B)_
  - Differentiated Services Field: 0xc0 (DSCP: CS6, ECN: Not-ECT) _(offset 15, 1 B)_
    - 1100 00.. = Differentiated Services Codepoint: Class Selector 6 (48) _(offset 15, 1 B)_
    - .... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0) _(offset 15, 1 B)_
  - Total Length: 68 _(offset 16, 2 B)_
  - Identification: 0x2d6f (11631) _(offset 18, 2 B)_
  - 010. .... = Flags: 0x2, Don't fragment _(offset 20, 1 B)_
    - 0... .... = Reserved bit: Not set _(offset 20, 1 B)_
    - .1.. .... = Don't fragment: Set _(offset 20, 1 B)_
    - ..0. .... = More fragments: Not set _(offset 20, 1 B)_
  - ...0 0000 0000 0000 = Fragment Offset: 0 _(offset 20, 2 B)_
  - Time to Live: 1 _(offset 22, 1 B)_
  - Protocol: TCP (6) _(offset 23, 1 B)_
  - Header Checksum: 0x83f0 [validation disabled] _(offset 24, 2 B)_
  - Source Address: 100.200.255.1 _(offset 26, 4 B)_
  - Destination Address: 100.200.255.2 _(offset 30, 4 B)_
- **Transmission Control Protocol, Src Port: 179, Dst Port: 20076, Seq: 76, Ack: 20, Len: 28**
  - TCP Segment Len: 28
  - Sequence Number: 76    (relative sequence number) _(offset 38, 4 B)_
  - Acknowledgment Number: 20    (relative ack number) _(offset 42, 4 B)_
  - 0101 .... = Header Length: 20 bytes (5) _(offset 46, 1 B)_
  - Flags: 0x018 (PSH, ACK) _(offset 46, 2 B)_
    - 000. .... .... = Reserved: Not set _(offset 46, 1 B)_
    - ...0 .... .... = Accurate ECN: Not set _(offset 46, 1 B)_
    - .... 0... .... = Congestion Window Reduced: Not set _(offset 47, 1 B)_
    - .... .0.. .... = ECN-Echo: Not set _(offset 47, 1 B)_
    - .... ..0. .... = Urgent: Not set _(offset 47, 1 B)_
    - .... ...1 .... = Acknowledgment: Set _(offset 47, 1 B)_
    - .... .... 1... = Push: Set _(offset 47, 1 B)_
    - .... .... .0.. = Reset: Not set _(offset 47, 1 B)_
    - .... .... ..0. = Syn: Not set _(offset 47, 1 B)_
    - .... .... ...0 = Fin: Not set _(offset 47, 1 B)_
    - TCP Flags: ·······AP··· _(offset 46, 2 B)_
  - Window: 15567 _(offset 48, 2 B)_
  - Window size scaling factor: -1 (unknown) _(offset 48, 2 B)_
  - Checksum: 0xd796 [unverified] _(offset 50, 2 B)_
  - Urgent Pointer: 0 _(offset 52, 2 B)_
  - Timestamps
- **Border Gateway Protocol - UPDATE Message**
  - Marker: ffffffffffffffffffffffffffffffff _(offset 54, 16 B)_
  - Length: 28 _(offset 70, 2 B)_
  - Type: UPDATE Message (2) _(offset 72, 1 B)_
  - Withdrawn Routes Length: 5 _(offset 73, 2 B)_
  - Withdrawn Routes _(offset 75, 5 B)_
    - 198.51.100.0/25 _(offset 75, 5 B)_
      - Withdrawn route prefix length: 25 _(offset 75, 1 B)_
      - Withdrawn prefix: 198.51.100.0 _(offset 76, 4 B)_
  - Total Path Attribute Length: 0 _(offset 80, 2 B)_

#### #10 BGP OPEN: HQ1-CORE-R1 -> ISPA-R1

11:14:00.291 (+131.613 s), frame 114, 111 bytes, HQ1-CORE-R1 Et0/2 <-> ISPA-R1 Et0/2

Starts the session: version, AS, hold time, router ID, capabilities.

- **Ethernet II, Src: aa:bb:cc:00:18:20, Dst: aa:bb:cc:00:12:20**
  - Destination: aa:bb:cc:00:12:20 _(offset 0, 6 B)_
  - Source: aa:bb:cc:00:18:20 _(offset 6, 6 B)_
  - Type: IPv4 (0x0800) _(offset 12, 2 B)_
- **Internet Protocol Version 4, Src: 100.100.255.2, Dst: 100.100.255.1**
  - 0100 .... = Version: 4 _(offset 14, 1 B)_
  - .... 0101 = Header Length: 20 bytes (5) _(offset 14, 1 B)_
  - Differentiated Services Field: 0xc0 (DSCP: CS6, ECN: Not-ECT) _(offset 15, 1 B)_
    - 1100 00.. = Differentiated Services Codepoint: Class Selector 6 (48) _(offset 15, 1 B)_
    - .... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0) _(offset 15, 1 B)_
  - Total Length: 97 _(offset 16, 2 B)_
  - Identification: 0xffce (65486) _(offset 18, 2 B)_
  - 010. .... = Flags: 0x2, Don't fragment _(offset 20, 1 B)_
    - 0... .... = Reserved bit: Not set _(offset 20, 1 B)_
    - .1.. .... = Don't fragment: Set _(offset 20, 1 B)_
    - ..0. .... = More fragments: Not set _(offset 20, 1 B)_
  - ...0 0000 0000 0000 = Fragment Offset: 0 _(offset 20, 2 B)_
  - Time to Live: 1 _(offset 22, 1 B)_
  - Protocol: TCP (6) _(offset 23, 1 B)_
  - Header Checksum: 0xb23b [validation disabled] _(offset 24, 2 B)_
  - Source Address: 100.100.255.2 _(offset 26, 4 B)_
  - Destination Address: 100.100.255.1 _(offset 30, 4 B)_
- **Transmission Control Protocol, Src Port: 21381, Dst Port: 179, Seq: 1, Ack: 1, Len: 57**
  - TCP Segment Len: 57
  - Sequence Number: 1    (relative sequence number) _(offset 38, 4 B)_
  - Acknowledgment Number: 1    (relative ack number) _(offset 42, 4 B)_
  - 0101 .... = Header Length: 20 bytes (5) _(offset 46, 1 B)_
  - Flags: 0x018 (PSH, ACK) _(offset 46, 2 B)_
    - 000. .... .... = Reserved: Not set _(offset 46, 1 B)_
    - ...0 .... .... = Accurate ECN: Not set _(offset 46, 1 B)_
    - .... 0... .... = Congestion Window Reduced: Not set _(offset 47, 1 B)_
    - .... .0.. .... = ECN-Echo: Not set _(offset 47, 1 B)_
    - .... ..0. .... = Urgent: Not set _(offset 47, 1 B)_
    - .... ...1 .... = Acknowledgment: Set _(offset 47, 1 B)_
    - .... .... 1... = Push: Set _(offset 47, 1 B)_
    - .... .... .0.. = Reset: Not set _(offset 47, 1 B)_
    - .... .... ..0. = Syn: Not set _(offset 47, 1 B)_
    - .... .... ...0 = Fin: Not set _(offset 47, 1 B)_
    - TCP Flags: ·······AP··· _(offset 46, 2 B)_
  - Window: 16384 _(offset 48, 2 B)_
  - Window size scaling factor: 1 _(offset 48, 2 B)_
  - Checksum: 0x5d9b [unverified] _(offset 50, 2 B)_
  - Urgent Pointer: 0 _(offset 52, 2 B)_
  - Timestamps
- **Border Gateway Protocol - OPEN Message**
  - Marker: ffffffffffffffffffffffffffffffff _(offset 54, 16 B)_
  - Length: 57 _(offset 70, 2 B)_
  - Type: OPEN Message (1) _(offset 72, 1 B)_
  - Version: 4 _(offset 73, 1 B)_
  - My AS: 65001 _(offset 74, 2 B)_
  - Hold Time: 180 _(offset 76, 2 B)_
  - BGP Identifier: 10.255.1.1 _(offset 78, 4 B)_
  - Optional Parameters Length: 28 _(offset 82, 1 B)_
  - Optional Parameters _(offset 83, 28 B)_
    - Optional Parameter: Capability _(offset 83, 8 B)_
      - Parameter Type: Capability (2) _(offset 83, 1 B)_
      - Parameter Length: 6 _(offset 84, 1 B)_
      - Capability: Multiprotocol extensions capability _(offset 85, 6 B)_
        - Type: Multiprotocol extensions capability (1) _(offset 85, 1 B)_
        - Length: 4 _(offset 86, 1 B)_
        - AFI: IPv4 (1) _(offset 87, 2 B)_
        - Reserved: 00 _(offset 89, 1 B)_
        - SAFI: Unicast (1) _(offset 90, 1 B)_
    - Optional Parameter: Capability _(offset 91, 4 B)_
      - Parameter Type: Capability (2) _(offset 91, 1 B)_
      - Parameter Length: 2 _(offset 92, 1 B)_
      - Capability: Route refresh capability (Cisco) _(offset 93, 2 B)_
        - Type: Route refresh capability (Cisco) (128) _(offset 93, 1 B)_
        - Length: 0 _(offset 94, 1 B)_
    - Optional Parameter: Capability _(offset 95, 4 B)_
      - Parameter Type: Capability (2) _(offset 95, 1 B)_
      - Parameter Length: 2 _(offset 96, 1 B)_
      - Capability: Route refresh capability _(offset 97, 2 B)_
        - Type: Route refresh capability (2) _(offset 97, 1 B)_
        - Length: 0 _(offset 98, 1 B)_
    - Optional Parameter: Capability _(offset 99, 4 B)_
      - Parameter Type: Capability (2) _(offset 99, 1 B)_
      - Parameter Length: 2 _(offset 100, 1 B)_
      - Capability: Enhanced route refresh capability _(offset 101, 2 B)_
        - Type: Enhanced route refresh capability (70) _(offset 101, 1 B)_
        - Length: 0 _(offset 102, 1 B)_
    - Optional Parameter: Capability _(offset 103, 8 B)_
      - Parameter Type: Capability (2) _(offset 103, 1 B)_
      - Parameter Length: 6 _(offset 104, 1 B)_
      - Capability: Support for 4-octet AS number capability _(offset 105, 6 B)_
        - Type: Support for 4-octet AS number capability (65) _(offset 105, 1 B)_
        - Length: 4 _(offset 106, 1 B)_
        - AS Number: 65001 _(offset 107, 4 B)_

#### #11 BGP OPEN: ISPA-R1 -> HQ1-CORE-R1

11:14:00.292 (+131.615 s), frame 116, 111 bytes, HQ1-CORE-R1 Et0/2 <-> ISPA-R1 Et0/2

Starts the session: version, AS, hold time, router ID, capabilities.

- **Ethernet II, Src: aa:bb:cc:00:12:20, Dst: aa:bb:cc:00:18:20**
  - Destination: aa:bb:cc:00:18:20 _(offset 0, 6 B)_
  - Source: aa:bb:cc:00:12:20 _(offset 6, 6 B)_
  - Type: IPv4 (0x0800) _(offset 12, 2 B)_
- **Internet Protocol Version 4, Src: 100.100.255.1, Dst: 100.100.255.2**
  - 0100 .... = Version: 4 _(offset 14, 1 B)_
  - .... 0101 = Header Length: 20 bytes (5) _(offset 14, 1 B)_
  - Differentiated Services Field: 0xc0 (DSCP: CS6, ECN: Not-ECT) _(offset 15, 1 B)_
    - 1100 00.. = Differentiated Services Codepoint: Class Selector 6 (48) _(offset 15, 1 B)_
    - .... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0) _(offset 15, 1 B)_
  - Total Length: 97 _(offset 16, 2 B)_
  - Identification: 0xd9b8 (55736) _(offset 18, 2 B)_
  - 010. .... = Flags: 0x2, Don't fragment _(offset 20, 1 B)_
    - 0... .... = Reserved bit: Not set _(offset 20, 1 B)_
    - .1.. .... = Don't fragment: Set _(offset 20, 1 B)_
    - ..0. .... = More fragments: Not set _(offset 20, 1 B)_
  - ...0 0000 0000 0000 = Fragment Offset: 0 _(offset 20, 2 B)_
  - Time to Live: 1 _(offset 22, 1 B)_
  - Protocol: TCP (6) _(offset 23, 1 B)_
  - Header Checksum: 0xd851 [validation disabled] _(offset 24, 2 B)_
  - Source Address: 100.100.255.1 _(offset 26, 4 B)_
  - Destination Address: 100.100.255.2 _(offset 30, 4 B)_
- **Transmission Control Protocol, Src Port: 179, Dst Port: 21381, Seq: 1, Ack: 58, Len: 57**
  - TCP Segment Len: 57
  - Sequence Number: 1    (relative sequence number) _(offset 38, 4 B)_
  - Acknowledgment Number: 58    (relative ack number) _(offset 42, 4 B)_
  - 0101 .... = Header Length: 20 bytes (5) _(offset 46, 1 B)_
  - Flags: 0x018 (PSH, ACK) _(offset 46, 2 B)_
    - 000. .... .... = Reserved: Not set _(offset 46, 1 B)_
    - ...0 .... .... = Accurate ECN: Not set _(offset 46, 1 B)_
    - .... 0... .... = Congestion Window Reduced: Not set _(offset 47, 1 B)_
    - .... .0.. .... = ECN-Echo: Not set _(offset 47, 1 B)_
    - .... ..0. .... = Urgent: Not set _(offset 47, 1 B)_
    - .... ...1 .... = Acknowledgment: Set _(offset 47, 1 B)_
    - .... .... 1... = Push: Set _(offset 47, 1 B)_
    - .... .... .0.. = Reset: Not set _(offset 47, 1 B)_
    - .... .... ..0. = Syn: Not set _(offset 47, 1 B)_
    - .... .... ...0 = Fin: Not set _(offset 47, 1 B)_
    - TCP Flags: ·······AP··· _(offset 46, 2 B)_
  - Window: 16327 _(offset 48, 2 B)_
  - Window size scaling factor: 1 _(offset 48, 2 B)_
  - Checksum: 0xa3d1 [unverified] _(offset 50, 2 B)_
  - Urgent Pointer: 0 _(offset 52, 2 B)_
  - Timestamps
- **Border Gateway Protocol - OPEN Message**
  - Marker: ffffffffffffffffffffffffffffffff _(offset 54, 16 B)_
  - Length: 57 _(offset 70, 2 B)_
  - Type: OPEN Message (1) _(offset 72, 1 B)_
  - Version: 4 _(offset 73, 1 B)_
  - My AS: 65100 _(offset 74, 2 B)_
  - Hold Time: 180 _(offset 76, 2 B)_
  - BGP Identifier: 100.100.254.1 _(offset 78, 4 B)_
  - Optional Parameters Length: 28 _(offset 82, 1 B)_
  - Optional Parameters _(offset 83, 28 B)_
    - Optional Parameter: Capability _(offset 83, 8 B)_
      - Parameter Type: Capability (2) _(offset 83, 1 B)_
      - Parameter Length: 6 _(offset 84, 1 B)_
      - Capability: Multiprotocol extensions capability _(offset 85, 6 B)_
        - Type: Multiprotocol extensions capability (1) _(offset 85, 1 B)_
        - Length: 4 _(offset 86, 1 B)_
        - AFI: IPv4 (1) _(offset 87, 2 B)_
        - Reserved: 00 _(offset 89, 1 B)_
        - SAFI: Unicast (1) _(offset 90, 1 B)_
    - Optional Parameter: Capability _(offset 91, 4 B)_
      - Parameter Type: Capability (2) _(offset 91, 1 B)_
      - Parameter Length: 2 _(offset 92, 1 B)_
      - Capability: Route refresh capability (Cisco) _(offset 93, 2 B)_
        - Type: Route refresh capability (Cisco) (128) _(offset 93, 1 B)_
        - Length: 0 _(offset 94, 1 B)_
    - Optional Parameter: Capability _(offset 95, 4 B)_
      - Parameter Type: Capability (2) _(offset 95, 1 B)_
      - Parameter Length: 2 _(offset 96, 1 B)_
      - Capability: Route refresh capability _(offset 97, 2 B)_
        - Type: Route refresh capability (2) _(offset 97, 1 B)_
        - Length: 0 _(offset 98, 1 B)_
    - Optional Parameter: Capability _(offset 99, 4 B)_
      - Parameter Type: Capability (2) _(offset 99, 1 B)_
      - Parameter Length: 2 _(offset 100, 1 B)_
      - Capability: Enhanced route refresh capability _(offset 101, 2 B)_
        - Type: Enhanced route refresh capability (70) _(offset 101, 1 B)_
        - Length: 0 _(offset 102, 1 B)_
    - Optional Parameter: Capability _(offset 103, 8 B)_
      - Parameter Type: Capability (2) _(offset 103, 1 B)_
      - Parameter Length: 6 _(offset 104, 1 B)_
      - Capability: Support for 4-octet AS number capability _(offset 105, 6 B)_
        - Type: Support for 4-octet AS number capability (65) _(offset 105, 1 B)_
        - Length: 4 _(offset 106, 1 B)_
        - AS Number: 65100 _(offset 107, 4 B)_

#### #12 BGP ROUTE-REFRESH: ISPA-R1 -> HQ1-CORE-R1

11:14:00.295 (+131.617 s), frame 120, 77 bytes, HQ1-CORE-R1 Et0/2 <-> ISPA-R1 Et0/2

Asks the peer to resend its table, or (enhanced route refresh) marks the start (BoRR) or end (EoRR) of a resend.

- **Ethernet II, Src: aa:bb:cc:00:12:20, Dst: aa:bb:cc:00:18:20**
  - Destination: aa:bb:cc:00:18:20 _(offset 0, 6 B)_
  - Source: aa:bb:cc:00:12:20 _(offset 6, 6 B)_
  - Type: IPv4 (0x0800) _(offset 12, 2 B)_
- **Internet Protocol Version 4, Src: 100.100.255.1, Dst: 100.100.255.2**
  - 0100 .... = Version: 4 _(offset 14, 1 B)_
  - .... 0101 = Header Length: 20 bytes (5) _(offset 14, 1 B)_
  - Differentiated Services Field: 0xc0 (DSCP: CS6, ECN: Not-ECT) _(offset 15, 1 B)_
    - 1100 00.. = Differentiated Services Codepoint: Class Selector 6 (48) _(offset 15, 1 B)_
    - .... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0) _(offset 15, 1 B)_
  - Total Length: 63 _(offset 16, 2 B)_
  - Identification: 0xd9ba (55738) _(offset 18, 2 B)_
  - 010. .... = Flags: 0x2, Don't fragment _(offset 20, 1 B)_
    - 0... .... = Reserved bit: Not set _(offset 20, 1 B)_
    - .1.. .... = Don't fragment: Set _(offset 20, 1 B)_
    - ..0. .... = More fragments: Not set _(offset 20, 1 B)_
  - ...0 0000 0000 0000 = Fragment Offset: 0 _(offset 20, 2 B)_
  - Time to Live: 1 _(offset 22, 1 B)_
  - Protocol: TCP (6) _(offset 23, 1 B)_
  - Header Checksum: 0xd871 [validation disabled] _(offset 24, 2 B)_
  - Source Address: 100.100.255.1 _(offset 26, 4 B)_
  - Destination Address: 100.100.255.2 _(offset 30, 4 B)_
- **Transmission Control Protocol, Src Port: 179, Dst Port: 21381, Seq: 77, Ack: 77, Len: 23**
  - TCP Segment Len: 23
  - Sequence Number: 77    (relative sequence number) _(offset 38, 4 B)_
  - Acknowledgment Number: 77    (relative ack number) _(offset 42, 4 B)_
  - 0101 .... = Header Length: 20 bytes (5) _(offset 46, 1 B)_
  - Flags: 0x018 (PSH, ACK) _(offset 46, 2 B)_
    - 000. .... .... = Reserved: Not set _(offset 46, 1 B)_
    - ...0 .... .... = Accurate ECN: Not set _(offset 46, 1 B)_
    - .... 0... .... = Congestion Window Reduced: Not set _(offset 47, 1 B)_
    - .... .0.. .... = ECN-Echo: Not set _(offset 47, 1 B)_
    - .... ..0. .... = Urgent: Not set _(offset 47, 1 B)_
    - .... ...1 .... = Acknowledgment: Set _(offset 47, 1 B)_
    - .... .... 1... = Push: Set _(offset 47, 1 B)_
    - .... .... .0.. = Reset: Not set _(offset 47, 1 B)_
    - .... .... ..0. = Syn: Not set _(offset 47, 1 B)_
    - .... .... ...0 = Fin: Not set _(offset 47, 1 B)_
    - TCP Flags: ·······AP··· _(offset 46, 2 B)_
  - Window: 16308 _(offset 48, 2 B)_
  - Window size scaling factor: 1 _(offset 48, 2 B)_
  - Checksum: 0x8546 [unverified] _(offset 50, 2 B)_
  - Urgent Pointer: 0 _(offset 52, 2 B)_
  - Timestamps
- **Border Gateway Protocol - ROUTE-REFRESH Message**
  - Marker: ffffffffffffffffffffffffffffffff _(offset 54, 16 B)_
  - Length: 23 _(offset 70, 2 B)_
  - Type: ROUTE-REFRESH Message (5) _(offset 72, 1 B)_
  - Address family identifier (AFI): IPv4 (1) _(offset 73, 2 B)_
  - Subtype: Demarcation of the beginning of a route refresh (1) _(offset 75, 1 B)_
  - Subsequent address family identifier (SAFI): Unicast (1) _(offset 76, 1 B)_

#### #13 BGP UPDATE: ISPA-R1 -> HQ1-CORE-R1

11:14:00.298 (+131.621 s), frame 121, 426 bytes, HQ1-CORE-R1 Et0/2 <-> ISPA-R1 Et0/2

Announces and/or withdraws prefixes. Withdrawn routes first, then the path attributes, then the prefixes (NLRI) that share them.

- **Ethernet II, Src: aa:bb:cc:00:12:20, Dst: aa:bb:cc:00:18:20**
  - Destination: aa:bb:cc:00:18:20 _(offset 0, 6 B)_
  - Source: aa:bb:cc:00:12:20 _(offset 6, 6 B)_
  - Type: IPv4 (0x0800) _(offset 12, 2 B)_
- **Internet Protocol Version 4, Src: 100.100.255.1, Dst: 100.100.255.2**
  - 0100 .... = Version: 4 _(offset 14, 1 B)_
  - .... 0101 = Header Length: 20 bytes (5) _(offset 14, 1 B)_
  - Differentiated Services Field: 0xc0 (DSCP: CS6, ECN: Not-ECT) _(offset 15, 1 B)_
    - 1100 00.. = Differentiated Services Codepoint: Class Selector 6 (48) _(offset 15, 1 B)_
    - .... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0) _(offset 15, 1 B)_
  - Total Length: 412 _(offset 16, 2 B)_
  - Identification: 0xd9bb (55739) _(offset 18, 2 B)_
  - 010. .... = Flags: 0x2, Don't fragment _(offset 20, 1 B)_
    - 0... .... = Reserved bit: Not set _(offset 20, 1 B)_
    - .1.. .... = Don't fragment: Set _(offset 20, 1 B)_
    - ..0. .... = More fragments: Not set _(offset 20, 1 B)_
  - ...0 0000 0000 0000 = Fragment Offset: 0 _(offset 20, 2 B)_
  - Time to Live: 1 _(offset 22, 1 B)_
  - Protocol: TCP (6) _(offset 23, 1 B)_
  - Header Checksum: 0xd713 [validation disabled] _(offset 24, 2 B)_
  - Source Address: 100.100.255.1 _(offset 26, 4 B)_
  - Destination Address: 100.100.255.2 _(offset 30, 4 B)_
- **Transmission Control Protocol, Src Port: 179, Dst Port: 21381, Seq: 100, Ack: 77, Len: 372**
  - TCP Segment Len: 372
  - Sequence Number: 100    (relative sequence number) _(offset 38, 4 B)_
  - Acknowledgment Number: 77    (relative ack number) _(offset 42, 4 B)_
  - 0101 .... = Header Length: 20 bytes (5) _(offset 46, 1 B)_
  - Flags: 0x018 (PSH, ACK) _(offset 46, 2 B)_
    - 000. .... .... = Reserved: Not set _(offset 46, 1 B)_
    - ...0 .... .... = Accurate ECN: Not set _(offset 46, 1 B)_
    - .... 0... .... = Congestion Window Reduced: Not set _(offset 47, 1 B)_
    - .... .0.. .... = ECN-Echo: Not set _(offset 47, 1 B)_
    - .... ..0. .... = Urgent: Not set _(offset 47, 1 B)_
    - .... ...1 .... = Acknowledgment: Set _(offset 47, 1 B)_
    - .... .... 1... = Push: Set _(offset 47, 1 B)_
    - .... .... .0.. = Reset: Not set _(offset 47, 1 B)_
    - .... .... ..0. = Syn: Not set _(offset 47, 1 B)_
    - .... .... ...0 = Fin: Not set _(offset 47, 1 B)_
    - TCP Flags: ·······AP··· _(offset 46, 2 B)_
  - Window: 16308 _(offset 48, 2 B)_
  - Window size scaling factor: 1 _(offset 48, 2 B)_
  - Checksum: 0xfd45 [unverified] _(offset 50, 2 B)_
  - Urgent Pointer: 0 _(offset 52, 2 B)_
  - Timestamps
- **Border Gateway Protocol - UPDATE Message**
  - Marker: ffffffffffffffffffffffffffffffff _(offset 54, 16 B)_
  - Length: 51 _(offset 70, 2 B)_
  - Type: UPDATE Message (2) _(offset 72, 1 B)_
  - Withdrawn Routes Length: 0 _(offset 73, 2 B)_
  - Total Path Attribute Length: 24 _(offset 75, 2 B)_
  - Path attributes _(offset 77, 24 B)_
    - Path Attribute - ORIGIN: IGP _(offset 77, 4 B)_
      - Flags: 0x40, Transitive, Well-known, Complete _(offset 77, 1 B)_
        - 0... .... = Optional: Not set _(offset 77, 1 B)_
        - .1.. .... = Transitive: Set _(offset 77, 1 B)_
        - ..0. .... = Partial: Not set _(offset 77, 1 B)_
        - ...0 .... = Extended-Length: Not set _(offset 77, 1 B)_
        - .... 0000 = Unused: 0x0 _(offset 77, 1 B)_
      - Type Code: ORIGIN (1) _(offset 78, 1 B)_
      - Length: 1 _(offset 79, 1 B)_
      - Origin: IGP (0) _(offset 80, 1 B)_
    - Path Attribute - AS_PATH: 65100 65002  _(offset 81, 13 B)_
      - Flags: 0x40, Transitive, Well-known, Complete _(offset 81, 1 B)_
        - 0... .... = Optional: Not set _(offset 81, 1 B)_
        - .1.. .... = Transitive: Set _(offset 81, 1 B)_
        - ..0. .... = Partial: Not set _(offset 81, 1 B)_
        - ...0 .... = Extended-Length: Not set _(offset 81, 1 B)_
        - .... 0000 = Unused: 0x0 _(offset 81, 1 B)_
      - Type Code: AS_PATH (2) _(offset 82, 1 B)_
      - Length: 10 _(offset 83, 1 B)_
      - AS Path segment: 65100 65002 _(offset 84, 10 B)_
        - Segment type: AS_SEQUENCE (2) _(offset 84, 1 B)_
        - Segment length (number of ASN): 2 _(offset 85, 1 B)_
        - AS4: 65100 _(offset 86, 4 B)_
        - AS4: 65002 _(offset 90, 4 B)_
    - Path Attribute - NEXT_HOP: 100.100.255.1  _(offset 94, 7 B)_
      - Flags: 0x40, Transitive, Well-known, Complete _(offset 94, 1 B)_
        - 0... .... = Optional: Not set _(offset 94, 1 B)_
        - .1.. .... = Transitive: Set _(offset 94, 1 B)_
        - ..0. .... = Partial: Not set _(offset 94, 1 B)_
        - ...0 .... = Extended-Length: Not set _(offset 94, 1 B)_
        - .... 0000 = Unused: 0x0 _(offset 94, 1 B)_
      - Type Code: NEXT_HOP (3) _(offset 95, 1 B)_
      - Length: 4 _(offset 96, 1 B)_
      - Next hop: 100.100.255.1 _(offset 97, 4 B)_
  - Network Layer Reachability Information (NLRI) _(offset 101, 4 B)_
    - 203.0.113.0/24 _(offset 101, 4 B)_
      - NLRI prefix length: 24 _(offset 101, 1 B)_
      - NLRI prefix: 203.0.113.0 _(offset 102, 3 B)_
- **Border Gateway Protocol - UPDATE Message**
  - Marker: ffffffffffffffffffffffffffffffff _(offset 105, 16 B)_
  - Length: 68 _(offset 121, 2 B)_
  - Type: UPDATE Message (2) _(offset 123, 1 B)_
  - Withdrawn Routes Length: 0 _(offset 124, 2 B)_
  - Total Path Attribute Length: 40 _(offset 126, 2 B)_
  - Path attributes _(offset 128, 40 B)_
    - Path Attribute - ORIGIN: IGP _(offset 128, 4 B)_
      - Flags: 0x40, Transitive, Well-known, Complete _(offset 128, 1 B)_
        - 0... .... = Optional: Not set _(offset 128, 1 B)_
        - .1.. .... = Transitive: Set _(offset 128, 1 B)_
        - ..0. .... = Partial: Not set _(offset 128, 1 B)_
        - ...0 .... = Extended-Length: Not set _(offset 128, 1 B)_
        - .... 0000 = Unused: 0x0 _(offset 128, 1 B)_
      - Type Code: ORIGIN (1) _(offset 129, 1 B)_
      - Length: 1 _(offset 130, 1 B)_
      - Origin: IGP (0) _(offset 131, 1 B)_
    - Path Attribute - AS_PATH: 65100 65200 65001 65001 65001 65001  _(offset 132, 29 B)_
      - Flags: 0x40, Transitive, Well-known, Complete _(offset 132, 1 B)_
        - 0... .... = Optional: Not set _(offset 132, 1 B)_
        - .1.. .... = Transitive: Set _(offset 132, 1 B)_
        - ..0. .... = Partial: Not set _(offset 132, 1 B)_
        - ...0 .... = Extended-Length: Not set _(offset 132, 1 B)_
        - .... 0000 = Unused: 0x0 _(offset 132, 1 B)_
      - Type Code: AS_PATH (2) _(offset 133, 1 B)_
      - Length: 26 _(offset 134, 1 B)_
      - AS Path segment: 65100 65200 65001 65001 65001 65001 _(offset 135, 26 B)_
        - Segment type: AS_SEQUENCE (2) _(offset 135, 1 B)_
        - Segment length (number of ASN): 6 _(offset 136, 1 B)_
        - AS4: 65100 _(offset 137, 4 B)_
        - AS4: 65200 _(offset 141, 4 B)_
        - AS4: 65001 _(offset 145, 4 B)_
        - AS4: 65001 _(offset 149, 4 B)_
        - AS4: 65001 _(offset 153, 4 B)_
        - AS4: 65001 _(offset 157, 4 B)_
    - Path Attribute - NEXT_HOP: 100.100.255.1  _(offset 161, 7 B)_
      - Flags: 0x40, Transitive, Well-known, Complete _(offset 161, 1 B)_
        - 0... .... = Optional: Not set _(offset 161, 1 B)_
        - .1.. .... = Transitive: Set _(offset 161, 1 B)_
        - ..0. .... = Partial: Not set _(offset 161, 1 B)_
        - ...0 .... = Extended-Length: Not set _(offset 161, 1 B)_
        - .... 0000 = Unused: 0x0 _(offset 161, 1 B)_
      - Type Code: NEXT_HOP (3) _(offset 162, 1 B)_
      - Length: 4 _(offset 163, 1 B)_
      - Next hop: 100.100.255.1 _(offset 164, 4 B)_
  - Network Layer Reachability Information (NLRI) _(offset 168, 5 B)_
    - 198.51.100.0/25 _(offset 168, 5 B)_
      - NLRI prefix length: 25 _(offset 168, 1 B)_
      - NLRI prefix: 198.51.100.0 _(offset 169, 4 B)_
- **Border Gateway Protocol - UPDATE Message**
  - Marker: ffffffffffffffffffffffffffffffff _(offset 173, 16 B)_
  - Length: 60 _(offset 189, 2 B)_
  - Type: UPDATE Message (2) _(offset 191, 1 B)_
  - Withdrawn Routes Length: 0 _(offset 192, 2 B)_
  - Total Path Attribute Length: 28 _(offset 194, 2 B)_
  - Path attributes _(offset 196, 28 B)_
    - Path Attribute - ORIGIN: IGP _(offset 196, 4 B)_
      - Flags: 0x40, Transitive, Well-known, Complete _(offset 196, 1 B)_
        - 0... .... = Optional: Not set _(offset 196, 1 B)_
        - .1.. .... = Transitive: Set _(offset 196, 1 B)_
        - ..0. .... = Partial: Not set _(offset 196, 1 B)_
        - ...0 .... = Extended-Length: Not set _(offset 196, 1 B)_
        - .... 0000 = Unused: 0x0 _(offset 196, 1 B)_
      - Type Code: ORIGIN (1) _(offset 197, 1 B)_
      - Length: 1 _(offset 198, 1 B)_
      - Origin: IGP (0) _(offset 199, 1 B)_
    - Path Attribute - AS_PATH: 65100 65200 65001  _(offset 200, 17 B)_
      - Flags: 0x40, Transitive, Well-known, Complete _(offset 200, 1 B)_
        - 0... .... = Optional: Not set _(offset 200, 1 B)_
        - .1.. .... = Transitive: Set _(offset 200, 1 B)_
        - ..0. .... = Partial: Not set _(offset 200, 1 B)_
        - ...0 .... = Extended-Length: Not set _(offset 200, 1 B)_
        - .... 0000 = Unused: 0x0 _(offset 200, 1 B)_
      - Type Code: AS_PATH (2) _(offset 201, 1 B)_
      - Length: 14 _(offset 202, 1 B)_
      - AS Path segment: 65100 65200 65001 _(offset 203, 14 B)_
        - Segment type: AS_SEQUENCE (2) _(offset 203, 1 B)_
        - Segment length (number of ASN): 3 _(offset 204, 1 B)_
        - AS4: 65100 _(offset 205, 4 B)_
        - AS4: 65200 _(offset 209, 4 B)_
        - AS4: 65001 _(offset 213, 4 B)_
    - Path Attribute - NEXT_HOP: 100.100.255.1  _(offset 217, 7 B)_
      - Flags: 0x40, Transitive, Well-known, Complete _(offset 217, 1 B)_
        - 0... .... = Optional: Not set _(offset 217, 1 B)_
        - .1.. .... = Transitive: Set _(offset 217, 1 B)_
        - ..0. .... = Partial: Not set _(offset 217, 1 B)_
        - ...0 .... = Extended-Length: Not set _(offset 217, 1 B)_
        - .... 0000 = Unused: 0x0 _(offset 217, 1 B)_
      - Type Code: NEXT_HOP (3) _(offset 218, 1 B)_
      - Length: 4 _(offset 219, 1 B)_
      - Next hop: 100.100.255.1 _(offset 220, 4 B)_
  - Network Layer Reachability Information (NLRI) _(offset 224, 9 B)_
    - 198.51.100.128/25 _(offset 224, 5 B)_
      - NLRI prefix length: 25 _(offset 224, 1 B)_
      - NLRI prefix: 198.51.100.128 _(offset 225, 4 B)_
    - 198.51.100.0/24 _(offset 229, 4 B)_
      - NLRI prefix length: 24 _(offset 229, 1 B)_
      - NLRI prefix: 198.51.100.0 _(offset 230, 3 B)_
- **Border Gateway Protocol - UPDATE Message**
  - Marker: ffffffffffffffffffffffffffffffff _(offset 233, 16 B)_
  - Length: 50 _(offset 249, 2 B)_
  - Type: UPDATE Message (2) _(offset 251, 1 B)_
  - Withdrawn Routes Length: 0 _(offset 252, 2 B)_
  - Total Path Attribute Length: 24 _(offset 254, 2 B)_
  - Path attributes _(offset 256, 24 B)_
    - Path Attribute - ORIGIN: IGP _(offset 256, 4 B)_
      - Flags: 0x40, Transitive, Well-known, Complete _(offset 256, 1 B)_
        - 0... .... = Optional: Not set _(offset 256, 1 B)_
        - .1.. .... = Transitive: Set _(offset 256, 1 B)_
        - ..0. .... = Partial: Not set _(offset 256, 1 B)_
        - ...0 .... = Extended-Length: Not set _(offset 256, 1 B)_
        - .... 0000 = Unused: 0x0 _(offset 256, 1 B)_
      - Type Code: ORIGIN (1) _(offset 257, 1 B)_
      - Length: 1 _(offset 258, 1 B)_
      - Origin: IGP (0) _(offset 259, 1 B)_
    - Path Attribute - AS_PATH: 65100 65200  _(offset 260, 13 B)_
      - Flags: 0x40, Transitive, Well-known, Complete _(offset 260, 1 B)_
        - 0... .... = Optional: Not set _(offset 260, 1 B)_
        - .1.. .... = Transitive: Set _(offset 260, 1 B)_
        - ..0. .... = Partial: Not set _(offset 260, 1 B)_
        - ...0 .... = Extended-Length: Not set _(offset 260, 1 B)_
        - .... 0000 = Unused: 0x0 _(offset 260, 1 B)_
      - Type Code: AS_PATH (2) _(offset 261, 1 B)_
      - Length: 10 _(offset 262, 1 B)_
      - AS Path segment: 65100 65200 _(offset 263, 10 B)_
        - Segment type: AS_SEQUENCE (2) _(offset 263, 1 B)_
        - Segment length (number of ASN): 2 _(offset 264, 1 B)_
        - AS4: 65100 _(offset 265, 4 B)_
        - AS4: 65200 _(offset 269, 4 B)_
    - Path Attribute - NEXT_HOP: 100.100.255.1  _(offset 273, 7 B)_
      - Flags: 0x40, Transitive, Well-known, Complete _(offset 273, 1 B)_
        - 0... .... = Optional: Not set _(offset 273, 1 B)_
        - .1.. .... = Transitive: Set _(offset 273, 1 B)_
        - ..0. .... = Partial: Not set _(offset 273, 1 B)_
        - ...0 .... = Extended-Length: Not set _(offset 273, 1 B)_
        - .... 0000 = Unused: 0x0 _(offset 273, 1 B)_
      - Type Code: NEXT_HOP (3) _(offset 274, 1 B)_
      - Length: 4 _(offset 275, 1 B)_
      - Next hop: 100.100.255.1 _(offset 276, 4 B)_
  - Network Layer Reachability Information (NLRI) _(offset 280, 3 B)_
    - 100.200.0.0/16 _(offset 280, 3 B)_
      - NLRI prefix length: 16 _(offset 280, 1 B)_
      - NLRI prefix: 100.200.0.0 _(offset 281, 2 B)_
- **Border Gateway Protocol - UPDATE Message**
  - Marker: ffffffffffffffffffffffffffffffff _(offset 283, 16 B)_
  - Length: 53 _(offset 299, 2 B)_
  - Type: UPDATE Message (2) _(offset 301, 1 B)_
  - Withdrawn Routes Length: 0 _(offset 302, 2 B)_
  - Total Path Attribute Length: 27 _(offset 304, 2 B)_
  - Path attributes _(offset 306, 27 B)_
    - Path Attribute - ORIGIN: IGP _(offset 306, 4 B)_
      - Flags: 0x40, Transitive, Well-known, Complete _(offset 306, 1 B)_
        - 0... .... = Optional: Not set _(offset 306, 1 B)_
        - .1.. .... = Transitive: Set _(offset 306, 1 B)_
        - ..0. .... = Partial: Not set _(offset 306, 1 B)_
        - ...0 .... = Extended-Length: Not set _(offset 306, 1 B)_
        - .... 0000 = Unused: 0x0 _(offset 306, 1 B)_
      - Type Code: ORIGIN (1) _(offset 307, 1 B)_
      - Length: 1 _(offset 308, 1 B)_
      - Origin: IGP (0) _(offset 309, 1 B)_
    - Path Attribute - AS_PATH: 65100  _(offset 310, 9 B)_
      - Flags: 0x40, Transitive, Well-known, Complete _(offset 310, 1 B)_
        - 0... .... = Optional: Not set _(offset 310, 1 B)_
        - .1.. .... = Transitive: Set _(offset 310, 1 B)_
        - ..0. .... = Partial: Not set _(offset 310, 1 B)_
        - ...0 .... = Extended-Length: Not set _(offset 310, 1 B)_
        - .... 0000 = Unused: 0x0 _(offset 310, 1 B)_
      - Type Code: AS_PATH (2) _(offset 311, 1 B)_
      - Length: 6 _(offset 312, 1 B)_
      - AS Path segment: 65100 _(offset 313, 6 B)_
        - Segment type: AS_SEQUENCE (2) _(offset 313, 1 B)_
        - Segment length (number of ASN): 1 _(offset 314, 1 B)_
        - AS4: 65100 _(offset 315, 4 B)_
    - Path Attribute - NEXT_HOP: 100.100.255.1  _(offset 319, 7 B)_
      - Flags: 0x40, Transitive, Well-known, Complete _(offset 319, 1 B)_
        - 0... .... = Optional: Not set _(offset 319, 1 B)_
        - .1.. .... = Transitive: Set _(offset 319, 1 B)_
        - ..0. .... = Partial: Not set _(offset 319, 1 B)_
        - ...0 .... = Extended-Length: Not set _(offset 319, 1 B)_
        - .... 0000 = Unused: 0x0 _(offset 319, 1 B)_
      - Type Code: NEXT_HOP (3) _(offset 320, 1 B)_
      - Length: 4 _(offset 321, 1 B)_
      - Next hop: 100.100.255.1 _(offset 322, 4 B)_
    - Path Attribute - MULTI_EXIT_DISC: 0 _(offset 326, 7 B)_
      - Flags: 0x80, Optional, Non-transitive, Complete _(offset 326, 1 B)_
        - 1... .... = Optional: Set _(offset 326, 1 B)_
        - .0.. .... = Transitive: Not set _(offset 326, 1 B)_
        - ..0. .... = Partial: Not set _(offset 326, 1 B)_
        - ...0 .... = Extended-Length: Not set _(offset 326, 1 B)_
        - .... 0000 = Unused: 0x0 _(offset 326, 1 B)_
      - Type Code: MULTI_EXIT_DISC (4) _(offset 327, 1 B)_
      - Length: 4 _(offset 328, 1 B)_
      - Multiple exit discriminator: 0 _(offset 329, 4 B)_
  - Network Layer Reachability Information (NLRI) _(offset 333, 3 B)_
    - 100.100.0.0/16 _(offset 333, 3 B)_
      - NLRI prefix length: 16 _(offset 333, 1 B)_
      - NLRI prefix: 100.100.0.0 _(offset 334, 2 B)_
- **Border Gateway Protocol - UPDATE Message**
  - Marker: ffffffffffffffffffffffffffffffff _(offset 336, 16 B)_
  - Length: 44 _(offset 352, 2 B)_
  - Type: UPDATE Message (2) _(offset 354, 1 B)_
  - Withdrawn Routes Length: 0 _(offset 355, 2 B)_
  - Total Path Attribute Length: 20 _(offset 357, 2 B)_
  - Path attributes _(offset 359, 20 B)_
    - Path Attribute - ORIGIN: IGP _(offset 359, 4 B)_
      - Flags: 0x40, Transitive, Well-known, Complete _(offset 359, 1 B)_
        - 0... .... = Optional: Not set _(offset 359, 1 B)_
        - .1.. .... = Transitive: Set _(offset 359, 1 B)_
        - ..0. .... = Partial: Not set _(offset 359, 1 B)_
        - ...0 .... = Extended-Length: Not set _(offset 359, 1 B)_
        - .... 0000 = Unused: 0x0 _(offset 359, 1 B)_
      - Type Code: ORIGIN (1) _(offset 360, 1 B)_
      - Length: 1 _(offset 361, 1 B)_
      - Origin: IGP (0) _(offset 362, 1 B)_
    - Path Attribute - AS_PATH: 65100  _(offset 363, 9 B)_
      - Flags: 0x40, Transitive, Well-known, Complete _(offset 363, 1 B)_
        - 0... .... = Optional: Not set _(offset 363, 1 B)_
        - .1.. .... = Transitive: Set _(offset 363, 1 B)_
        - ..0. .... = Partial: Not set _(offset 363, 1 B)_
        - ...0 .... = Extended-Length: Not set _(offset 363, 1 B)_
        - .... 0000 = Unused: 0x0 _(offset 363, 1 B)_
      - Type Code: AS_PATH (2) _(offset 364, 1 B)_
      - Length: 6 _(offset 365, 1 B)_
      - AS Path segment: 65100 _(offset 366, 6 B)_
        - Segment type: AS_SEQUENCE (2) _(offset 366, 1 B)_
        - Segment length (number of ASN): 1 _(offset 367, 1 B)_
        - AS4: 65100 _(offset 368, 4 B)_
    - Path Attribute - NEXT_HOP: 100.100.255.1  _(offset 372, 7 B)_
      - Flags: 0x40, Transitive, Well-known, Complete _(offset 372, 1 B)_
        - 0... .... = Optional: Not set _(offset 372, 1 B)_
        - .1.. .... = Transitive: Set _(offset 372, 1 B)_
        - ..0. .... = Partial: Not set _(offset 372, 1 B)_
        - ...0 .... = Extended-Length: Not set _(offset 372, 1 B)_
        - .... 0000 = Unused: 0x0 _(offset 372, 1 B)_
      - Type Code: NEXT_HOP (3) _(offset 373, 1 B)_
      - Length: 4 _(offset 374, 1 B)_
      - Next hop: 100.100.255.1 _(offset 375, 4 B)_
  - Network Layer Reachability Information (NLRI) _(offset 379, 1 B)_
    - 0.0.0.0/0 _(offset 379, 1 B)_
      - NLRI prefix length: 0 _(offset 379, 1 B)_
      - NLRI prefix: 0.0.0.0
- **Border Gateway Protocol - ROUTE-REFRESH Message**
  - Marker: ffffffffffffffffffffffffffffffff _(offset 380, 16 B)_
  - Length: 23 _(offset 396, 2 B)_
  - Type: ROUTE-REFRESH Message (5) _(offset 398, 1 B)_
  - Address family identifier (AFI): IPv4 (1) _(offset 399, 2 B)_
  - Subtype: Demarcation of the ending of a route refresh (2) _(offset 401, 1 B)_
  - Subsequent address family identifier (SAFI): Unicast (1) _(offset 402, 1 B)_
- **Border Gateway Protocol - UPDATE Message**
  - Marker: ffffffffffffffffffffffffffffffff _(offset 403, 16 B)_
  - Length: 23 _(offset 419, 2 B)_
  - Type: UPDATE Message (2) _(offset 421, 1 B)_
  - Withdrawn Routes Length: 0 _(offset 422, 2 B)_
  - Total Path Attribute Length: 0 _(offset 424, 2 B)_

#### #14 BGP UPDATE: HQ1-CORE-R1 -> ISPA-R1

11:14:00.300 (+131.622 s), frame 123, 196 bytes, HQ1-CORE-R1 Et0/2 <-> ISPA-R1 Et0/2

Announces and/or withdraws prefixes. Withdrawn routes first, then the path attributes, then the prefixes (NLRI) that share them.

- **Ethernet II, Src: aa:bb:cc:00:18:20, Dst: aa:bb:cc:00:12:20**
  - Destination: aa:bb:cc:00:12:20 _(offset 0, 6 B)_
  - Source: aa:bb:cc:00:18:20 _(offset 6, 6 B)_
  - Type: IPv4 (0x0800) _(offset 12, 2 B)_
- **Internet Protocol Version 4, Src: 100.100.255.2, Dst: 100.100.255.1**
  - 0100 .... = Version: 4 _(offset 14, 1 B)_
  - .... 0101 = Header Length: 20 bytes (5) _(offset 14, 1 B)_
  - Differentiated Services Field: 0xc0 (DSCP: CS6, ECN: Not-ECT) _(offset 15, 1 B)_
    - 1100 00.. = Differentiated Services Codepoint: Class Selector 6 (48) _(offset 15, 1 B)_
    - .... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0) _(offset 15, 1 B)_
  - Total Length: 182 _(offset 16, 2 B)_
  - Identification: 0xffd2 (65490) _(offset 18, 2 B)_
  - 010. .... = Flags: 0x2, Don't fragment _(offset 20, 1 B)_
    - 0... .... = Reserved bit: Not set _(offset 20, 1 B)_
    - .1.. .... = Don't fragment: Set _(offset 20, 1 B)_
    - ..0. .... = More fragments: Not set _(offset 20, 1 B)_
  - ...0 0000 0000 0000 = Fragment Offset: 0 _(offset 20, 2 B)_
  - Time to Live: 1 _(offset 22, 1 B)_
  - Protocol: TCP (6) _(offset 23, 1 B)_
  - Header Checksum: 0xb1e2 [validation disabled] _(offset 24, 2 B)_
  - Source Address: 100.100.255.2 _(offset 26, 4 B)_
  - Destination Address: 100.100.255.1 _(offset 30, 4 B)_
- **Transmission Control Protocol, Src Port: 21381, Dst Port: 179, Seq: 96, Ack: 77, Len: 142**
  - TCP Segment Len: 142
  - Sequence Number: 96    (relative sequence number) _(offset 38, 4 B)_
  - Acknowledgment Number: 77    (relative ack number) _(offset 42, 4 B)_
  - 0101 .... = Header Length: 20 bytes (5) _(offset 46, 1 B)_
  - Flags: 0x018 (PSH, ACK) _(offset 46, 2 B)_
    - 000. .... .... = Reserved: Not set _(offset 46, 1 B)_
    - ...0 .... .... = Accurate ECN: Not set _(offset 46, 1 B)_
    - .... 0... .... = Congestion Window Reduced: Not set _(offset 47, 1 B)_
    - .... .0.. .... = ECN-Echo: Not set _(offset 47, 1 B)_
    - .... ..0. .... = Urgent: Not set _(offset 47, 1 B)_
    - .... ...1 .... = Acknowledgment: Set _(offset 47, 1 B)_
    - .... .... 1... = Push: Set _(offset 47, 1 B)_
    - .... .... .0.. = Reset: Not set _(offset 47, 1 B)_
    - .... .... ..0. = Syn: Not set _(offset 47, 1 B)_
    - .... .... ...0 = Fin: Not set _(offset 47, 1 B)_
    - TCP Flags: ·······AP··· _(offset 46, 2 B)_
  - Window: 16308 _(offset 48, 2 B)_
  - Window size scaling factor: 1 _(offset 48, 2 B)_
  - Checksum: 0x3715 [unverified] _(offset 50, 2 B)_
  - Urgent Pointer: 0 _(offset 52, 2 B)_
  - Timestamps
- **Border Gateway Protocol - UPDATE Message**
  - Marker: ffffffffffffffffffffffffffffffff _(offset 54, 16 B)_
  - Length: 60 _(offset 70, 2 B)_
  - Type: UPDATE Message (2) _(offset 72, 1 B)_
  - Withdrawn Routes Length: 0 _(offset 73, 2 B)_
  - Total Path Attribute Length: 32 _(offset 75, 2 B)_
  - Path attributes _(offset 77, 32 B)_
    - Path Attribute - ORIGIN: IGP _(offset 77, 4 B)_
      - Flags: 0x40, Transitive, Well-known, Complete _(offset 77, 1 B)_
        - 0... .... = Optional: Not set _(offset 77, 1 B)_
        - .1.. .... = Transitive: Set _(offset 77, 1 B)_
        - ..0. .... = Partial: Not set _(offset 77, 1 B)_
        - ...0 .... = Extended-Length: Not set _(offset 77, 1 B)_
        - .... 0000 = Unused: 0x0 _(offset 77, 1 B)_
      - Type Code: ORIGIN (1) _(offset 78, 1 B)_
      - Length: 1 _(offset 79, 1 B)_
      - Origin: IGP (0) _(offset 80, 1 B)_
    - Path Attribute - AS_PATH: 65001 65001 65001 65001  _(offset 81, 21 B)_
      - Flags: 0x40, Transitive, Well-known, Complete _(offset 81, 1 B)_
        - 0... .... = Optional: Not set _(offset 81, 1 B)_
        - .1.. .... = Transitive: Set _(offset 81, 1 B)_
        - ..0. .... = Partial: Not set _(offset 81, 1 B)_
        - ...0 .... = Extended-Length: Not set _(offset 81, 1 B)_
        - .... 0000 = Unused: 0x0 _(offset 81, 1 B)_
      - Type Code: AS_PATH (2) _(offset 82, 1 B)_
      - Length: 18 _(offset 83, 1 B)_
      - AS Path segment: 65001 65001 65001 65001 _(offset 84, 18 B)_
        - Segment type: AS_SEQUENCE (2) _(offset 84, 1 B)_
        - Segment length (number of ASN): 4 _(offset 85, 1 B)_
        - AS4: 65001 _(offset 86, 4 B)_
        - AS4: 65001 _(offset 90, 4 B)_
        - AS4: 65001 _(offset 94, 4 B)_
        - AS4: 65001 _(offset 98, 4 B)_
    - Path Attribute - NEXT_HOP: 100.100.255.2  _(offset 102, 7 B)_
      - Flags: 0x40, Transitive, Well-known, Complete _(offset 102, 1 B)_
        - 0... .... = Optional: Not set _(offset 102, 1 B)_
        - .1.. .... = Transitive: Set _(offset 102, 1 B)_
        - ..0. .... = Partial: Not set _(offset 102, 1 B)_
        - ...0 .... = Extended-Length: Not set _(offset 102, 1 B)_
        - .... 0000 = Unused: 0x0 _(offset 102, 1 B)_
      - Type Code: NEXT_HOP (3) _(offset 103, 1 B)_
      - Length: 4 _(offset 104, 1 B)_
      - Next hop: 100.100.255.2 _(offset 105, 4 B)_
  - Network Layer Reachability Information (NLRI) _(offset 109, 5 B)_
    - 198.51.100.128/25 _(offset 109, 5 B)_
      - NLRI prefix length: 25 _(offset 109, 1 B)_
      - NLRI prefix: 198.51.100.128 _(offset 110, 4 B)_
- **Border Gateway Protocol - UPDATE Message**
  - Marker: ffffffffffffffffffffffffffffffff _(offset 114, 16 B)_
  - Length: 59 _(offset 130, 2 B)_
  - Type: UPDATE Message (2) _(offset 132, 1 B)_
  - Withdrawn Routes Length: 0 _(offset 133, 2 B)_
  - Total Path Attribute Length: 27 _(offset 135, 2 B)_
  - Path attributes _(offset 137, 27 B)_
    - Path Attribute - ORIGIN: IGP _(offset 137, 4 B)_
      - Flags: 0x40, Transitive, Well-known, Complete _(offset 137, 1 B)_
        - 0... .... = Optional: Not set _(offset 137, 1 B)_
        - .1.. .... = Transitive: Set _(offset 137, 1 B)_
        - ..0. .... = Partial: Not set _(offset 137, 1 B)_
        - ...0 .... = Extended-Length: Not set _(offset 137, 1 B)_
        - .... 0000 = Unused: 0x0 _(offset 137, 1 B)_
      - Type Code: ORIGIN (1) _(offset 138, 1 B)_
      - Length: 1 _(offset 139, 1 B)_
      - Origin: IGP (0) _(offset 140, 1 B)_
    - Path Attribute - AS_PATH: 65001  _(offset 141, 9 B)_
      - Flags: 0x40, Transitive, Well-known, Complete _(offset 141, 1 B)_
        - 0... .... = Optional: Not set _(offset 141, 1 B)_
        - .1.. .... = Transitive: Set _(offset 141, 1 B)_
        - ..0. .... = Partial: Not set _(offset 141, 1 B)_
        - ...0 .... = Extended-Length: Not set _(offset 141, 1 B)_
        - .... 0000 = Unused: 0x0 _(offset 141, 1 B)_
      - Type Code: AS_PATH (2) _(offset 142, 1 B)_
      - Length: 6 _(offset 143, 1 B)_
      - AS Path segment: 65001 _(offset 144, 6 B)_
        - Segment type: AS_SEQUENCE (2) _(offset 144, 1 B)_
        - Segment length (number of ASN): 1 _(offset 145, 1 B)_
        - AS4: 65001 _(offset 146, 4 B)_
    - Path Attribute - NEXT_HOP: 100.100.255.2  _(offset 150, 7 B)_
      - Flags: 0x40, Transitive, Well-known, Complete _(offset 150, 1 B)_
        - 0... .... = Optional: Not set _(offset 150, 1 B)_
        - .1.. .... = Transitive: Set _(offset 150, 1 B)_
        - ..0. .... = Partial: Not set _(offset 150, 1 B)_
        - ...0 .... = Extended-Length: Not set _(offset 150, 1 B)_
        - .... 0000 = Unused: 0x0 _(offset 150, 1 B)_
      - Type Code: NEXT_HOP (3) _(offset 151, 1 B)_
      - Length: 4 _(offset 152, 1 B)_
      - Next hop: 100.100.255.2 _(offset 153, 4 B)_
    - Path Attribute - MULTI_EXIT_DISC: 0 _(offset 157, 7 B)_
      - Flags: 0x80, Optional, Non-transitive, Complete _(offset 157, 1 B)_
        - 1... .... = Optional: Set _(offset 157, 1 B)_
        - .0.. .... = Transitive: Not set _(offset 157, 1 B)_
        - ..0. .... = Partial: Not set _(offset 157, 1 B)_
        - ...0 .... = Extended-Length: Not set _(offset 157, 1 B)_
        - .... 0000 = Unused: 0x0 _(offset 157, 1 B)_
      - Type Code: MULTI_EXIT_DISC (4) _(offset 158, 1 B)_
      - Length: 4 _(offset 159, 1 B)_
      - Multiple exit discriminator: 0 _(offset 160, 4 B)_
  - Network Layer Reachability Information (NLRI) _(offset 164, 9 B)_
    - 198.51.100.0/25 _(offset 164, 5 B)_
      - NLRI prefix length: 25 _(offset 164, 1 B)_
      - NLRI prefix: 198.51.100.0 _(offset 165, 4 B)_
    - 198.51.100.0/24 _(offset 169, 4 B)_
      - NLRI prefix length: 24 _(offset 169, 1 B)_
      - NLRI prefix: 198.51.100.0 _(offset 170, 3 B)_
- **Border Gateway Protocol - UPDATE Message**
  - Marker: ffffffffffffffffffffffffffffffff _(offset 173, 16 B)_
  - Length: 23 _(offset 189, 2 B)_
  - Type: UPDATE Message (2) _(offset 191, 1 B)_
  - Withdrawn Routes Length: 0 _(offset 192, 2 B)_
  - Total Path Attribute Length: 0 _(offset 194, 2 B)_

#### #15 BGP UPDATE: ISPA-R1 -> HQ1-CORE-R1

11:14:00.302 (+131.624 s), frame 125, 110 bytes, HQ1-CORE-R1 Et0/2 <-> ISPA-R1 Et0/2

Announces and/or withdraws prefixes. Withdrawn routes first, then the path attributes, then the prefixes (NLRI) that share them.

- **Ethernet II, Src: aa:bb:cc:00:12:20, Dst: aa:bb:cc:00:18:20**
  - Destination: aa:bb:cc:00:18:20 _(offset 0, 6 B)_
  - Source: aa:bb:cc:00:12:20 _(offset 6, 6 B)_
  - Type: IPv4 (0x0800) _(offset 12, 2 B)_
- **Internet Protocol Version 4, Src: 100.100.255.1, Dst: 100.100.255.2**
  - 0100 .... = Version: 4 _(offset 14, 1 B)_
  - .... 0101 = Header Length: 20 bytes (5) _(offset 14, 1 B)_
  - Differentiated Services Field: 0xc0 (DSCP: CS6, ECN: Not-ECT) _(offset 15, 1 B)_
    - 1100 00.. = Differentiated Services Codepoint: Class Selector 6 (48) _(offset 15, 1 B)_
    - .... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0) _(offset 15, 1 B)_
  - Total Length: 96 _(offset 16, 2 B)_
  - Identification: 0xd9bd (55741) _(offset 18, 2 B)_
  - 010. .... = Flags: 0x2, Don't fragment _(offset 20, 1 B)_
    - 0... .... = Reserved bit: Not set _(offset 20, 1 B)_
    - .1.. .... = Don't fragment: Set _(offset 20, 1 B)_
    - ..0. .... = More fragments: Not set _(offset 20, 1 B)_
  - ...0 0000 0000 0000 = Fragment Offset: 0 _(offset 20, 2 B)_
  - Time to Live: 1 _(offset 22, 1 B)_
  - Protocol: TCP (6) _(offset 23, 1 B)_
  - Header Checksum: 0xd84d [validation disabled] _(offset 24, 2 B)_
  - Source Address: 100.100.255.1 _(offset 26, 4 B)_
  - Destination Address: 100.100.255.2 _(offset 30, 4 B)_
- **Transmission Control Protocol, Src Port: 179, Dst Port: 21381, Seq: 491, Ack: 238, Len: 56**
  - TCP Segment Len: 56
  - Sequence Number: 491    (relative sequence number) _(offset 38, 4 B)_
  - Acknowledgment Number: 238    (relative ack number) _(offset 42, 4 B)_
  - 0101 .... = Header Length: 20 bytes (5) _(offset 46, 1 B)_
  - Flags: 0x018 (PSH, ACK) _(offset 46, 2 B)_
    - 000. .... .... = Reserved: Not set _(offset 46, 1 B)_
    - ...0 .... .... = Accurate ECN: Not set _(offset 46, 1 B)_
    - .... 0... .... = Congestion Window Reduced: Not set _(offset 47, 1 B)_
    - .... .0.. .... = ECN-Echo: Not set _(offset 47, 1 B)_
    - .... ..0. .... = Urgent: Not set _(offset 47, 1 B)_
    - .... ...1 .... = Acknowledgment: Set _(offset 47, 1 B)_
    - .... .... 1... = Push: Set _(offset 47, 1 B)_
    - .... .... .0.. = Reset: Not set _(offset 47, 1 B)_
    - .... .... ..0. = Syn: Not set _(offset 47, 1 B)_
    - .... .... ...0 = Fin: Not set _(offset 47, 1 B)_
    - TCP Flags: ·······AP··· _(offset 46, 2 B)_
  - Window: 16147 _(offset 48, 2 B)_
  - Window size scaling factor: 1 _(offset 48, 2 B)_
  - Checksum: 0x4cc5 [unverified] _(offset 50, 2 B)_
  - Urgent Pointer: 0 _(offset 52, 2 B)_
  - Timestamps
- **Border Gateway Protocol - UPDATE Message**
  - Marker: ffffffffffffffffffffffffffffffff _(offset 54, 16 B)_
  - Length: 56 _(offset 70, 2 B)_
  - Type: UPDATE Message (2) _(offset 72, 1 B)_
  - Withdrawn Routes Length: 0 _(offset 73, 2 B)_
  - Total Path Attribute Length: 24 _(offset 75, 2 B)_
  - Path attributes _(offset 77, 24 B)_
    - Path Attribute - ORIGIN: IGP _(offset 77, 4 B)_
      - Flags: 0x40, Transitive, Well-known, Complete _(offset 77, 1 B)_
        - 0... .... = Optional: Not set _(offset 77, 1 B)_
        - .1.. .... = Transitive: Set _(offset 77, 1 B)_
        - ..0. .... = Partial: Not set _(offset 77, 1 B)_
        - ...0 .... = Extended-Length: Not set _(offset 77, 1 B)_
        - .... 0000 = Unused: 0x0 _(offset 77, 1 B)_
      - Type Code: ORIGIN (1) _(offset 78, 1 B)_
      - Length: 1 _(offset 79, 1 B)_
      - Origin: IGP (0) _(offset 80, 1 B)_
    - Path Attribute - AS_PATH: 65100 65001  _(offset 81, 13 B)_
      - Flags: 0x40, Transitive, Well-known, Complete _(offset 81, 1 B)_
        - 0... .... = Optional: Not set _(offset 81, 1 B)_
        - .1.. .... = Transitive: Set _(offset 81, 1 B)_
        - ..0. .... = Partial: Not set _(offset 81, 1 B)_
        - ...0 .... = Extended-Length: Not set _(offset 81, 1 B)_
        - .... 0000 = Unused: 0x0 _(offset 81, 1 B)_
      - Type Code: AS_PATH (2) _(offset 82, 1 B)_
      - Length: 10 _(offset 83, 1 B)_
      - AS Path segment: 65100 65001 _(offset 84, 10 B)_
        - Segment type: AS_SEQUENCE (2) _(offset 84, 1 B)_
        - Segment length (number of ASN): 2 _(offset 85, 1 B)_
        - AS4: 65100 _(offset 86, 4 B)_
        - AS4: 65001 _(offset 90, 4 B)_
    - Path Attribute - NEXT_HOP: 100.100.255.2  _(offset 94, 7 B)_
      - Flags: 0x40, Transitive, Well-known, Complete _(offset 94, 1 B)_
        - 0... .... = Optional: Not set _(offset 94, 1 B)_
        - .1.. .... = Transitive: Set _(offset 94, 1 B)_
        - ..0. .... = Partial: Not set _(offset 94, 1 B)_
        - ...0 .... = Extended-Length: Not set _(offset 94, 1 B)_
        - .... 0000 = Unused: 0x0 _(offset 94, 1 B)_
      - Type Code: NEXT_HOP (3) _(offset 95, 1 B)_
      - Length: 4 _(offset 96, 1 B)_
      - Next hop: 100.100.255.2 _(offset 97, 4 B)_
  - Network Layer Reachability Information (NLRI) _(offset 101, 9 B)_
    - 198.51.100.0/25 _(offset 101, 5 B)_
      - NLRI prefix length: 25 _(offset 101, 1 B)_
      - NLRI prefix: 198.51.100.0 _(offset 102, 4 B)_
    - 198.51.100.0/24 _(offset 106, 4 B)_
      - NLRI prefix length: 24 _(offset 106, 1 B)_
      - NLRI prefix: 198.51.100.0 _(offset 107, 3 B)_

#### #16 BGP UPDATE: ISPB-R1 -> HQ1-CORE-R2

11:14:00.304 (+131.626 s), frame 67, 110 bytes, HQ1-CORE-R2 Et0/2 <-> ISPB-R1 Et0/2

Announces and/or withdraws prefixes. Withdrawn routes first, then the path attributes, then the prefixes (NLRI) that share them.

- **Ethernet II, Src: aa:bb:cc:00:14:20, Dst: aa:bb:cc:00:19:20**
  - Destination: aa:bb:cc:00:19:20 _(offset 0, 6 B)_
  - Source: aa:bb:cc:00:14:20 _(offset 6, 6 B)_
  - Type: IPv4 (0x0800) _(offset 12, 2 B)_
- **Internet Protocol Version 4, Src: 100.200.255.1, Dst: 100.200.255.2**
  - 0100 .... = Version: 4 _(offset 14, 1 B)_
  - .... 0101 = Header Length: 20 bytes (5) _(offset 14, 1 B)_
  - Differentiated Services Field: 0xc0 (DSCP: CS6, ECN: Not-ECT) _(offset 15, 1 B)_
    - 1100 00.. = Differentiated Services Codepoint: Class Selector 6 (48) _(offset 15, 1 B)_
    - .... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0) _(offset 15, 1 B)_
  - Total Length: 96 _(offset 16, 2 B)_
  - Identification: 0x2d73 (11635) _(offset 18, 2 B)_
  - 010. .... = Flags: 0x2, Don't fragment _(offset 20, 1 B)_
    - 0... .... = Reserved bit: Not set _(offset 20, 1 B)_
    - .1.. .... = Don't fragment: Set _(offset 20, 1 B)_
    - ..0. .... = More fragments: Not set _(offset 20, 1 B)_
  - ...0 0000 0000 0000 = Fragment Offset: 0 _(offset 20, 2 B)_
  - Time to Live: 1 _(offset 22, 1 B)_
  - Protocol: TCP (6) _(offset 23, 1 B)_
  - Header Checksum: 0x83d0 [validation disabled] _(offset 24, 2 B)_
  - Source Address: 100.200.255.1 _(offset 26, 4 B)_
  - Destination Address: 100.200.255.2 _(offset 30, 4 B)_
- **Transmission Control Protocol, Src Port: 179, Dst Port: 20076, Seq: 123, Ack: 58, Len: 56**
  - TCP Segment Len: 56
  - Sequence Number: 123    (relative sequence number) _(offset 38, 4 B)_
  - Acknowledgment Number: 58    (relative ack number) _(offset 42, 4 B)_
  - 0101 .... = Header Length: 20 bytes (5) _(offset 46, 1 B)_
  - Flags: 0x018 (PSH, ACK) _(offset 46, 2 B)_
    - 000. .... .... = Reserved: Not set _(offset 46, 1 B)_
    - ...0 .... .... = Accurate ECN: Not set _(offset 46, 1 B)_
    - .... 0... .... = Congestion Window Reduced: Not set _(offset 47, 1 B)_
    - .... .0.. .... = ECN-Echo: Not set _(offset 47, 1 B)_
    - .... ..0. .... = Urgent: Not set _(offset 47, 1 B)_
    - .... ...1 .... = Acknowledgment: Set _(offset 47, 1 B)_
    - .... .... 1... = Push: Set _(offset 47, 1 B)_
    - .... .... .0.. = Reset: Not set _(offset 47, 1 B)_
    - .... .... ..0. = Syn: Not set _(offset 47, 1 B)_
    - .... .... ...0 = Fin: Not set _(offset 47, 1 B)_
    - TCP Flags: ·······AP··· _(offset 46, 2 B)_
  - Window: 15529 _(offset 48, 2 B)_
  - Window size scaling factor: -1 (unknown) _(offset 48, 2 B)_
  - Checksum: 0xb14e [unverified] _(offset 50, 2 B)_
  - Urgent Pointer: 0 _(offset 52, 2 B)_
  - Timestamps
- **Border Gateway Protocol - UPDATE Message**
  - Marker: ffffffffffffffffffffffffffffffff _(offset 54, 16 B)_
  - Length: 56 _(offset 70, 2 B)_
  - Type: UPDATE Message (2) _(offset 72, 1 B)_
  - Withdrawn Routes Length: 0 _(offset 73, 2 B)_
  - Total Path Attribute Length: 28 _(offset 75, 2 B)_
  - Path attributes _(offset 77, 28 B)_
    - Path Attribute - ORIGIN: IGP _(offset 77, 4 B)_
      - Flags: 0x40, Transitive, Well-known, Complete _(offset 77, 1 B)_
        - 0... .... = Optional: Not set _(offset 77, 1 B)_
        - .1.. .... = Transitive: Set _(offset 77, 1 B)_
        - ..0. .... = Partial: Not set _(offset 77, 1 B)_
        - ...0 .... = Extended-Length: Not set _(offset 77, 1 B)_
        - .... 0000 = Unused: 0x0 _(offset 77, 1 B)_
      - Type Code: ORIGIN (1) _(offset 78, 1 B)_
      - Length: 1 _(offset 79, 1 B)_
      - Origin: IGP (0) _(offset 80, 1 B)_
    - Path Attribute - AS_PATH: 65200 65100 65001  _(offset 81, 17 B)_
      - Flags: 0x40, Transitive, Well-known, Complete _(offset 81, 1 B)_
        - 0... .... = Optional: Not set _(offset 81, 1 B)_
        - .1.. .... = Transitive: Set _(offset 81, 1 B)_
        - ..0. .... = Partial: Not set _(offset 81, 1 B)_
        - ...0 .... = Extended-Length: Not set _(offset 81, 1 B)_
        - .... 0000 = Unused: 0x0 _(offset 81, 1 B)_
      - Type Code: AS_PATH (2) _(offset 82, 1 B)_
      - Length: 14 _(offset 83, 1 B)_
      - AS Path segment: 65200 65100 65001 _(offset 84, 14 B)_
        - Segment type: AS_SEQUENCE (2) _(offset 84, 1 B)_
        - Segment length (number of ASN): 3 _(offset 85, 1 B)_
        - AS4: 65200 _(offset 86, 4 B)_
        - AS4: 65100 _(offset 90, 4 B)_
        - AS4: 65001 _(offset 94, 4 B)_
    - Path Attribute - NEXT_HOP: 100.200.255.1  _(offset 98, 7 B)_
      - Flags: 0x40, Transitive, Well-known, Complete _(offset 98, 1 B)_
        - 0... .... = Optional: Not set _(offset 98, 1 B)_
        - .1.. .... = Transitive: Set _(offset 98, 1 B)_
        - ..0. .... = Partial: Not set _(offset 98, 1 B)_
        - ...0 .... = Extended-Length: Not set _(offset 98, 1 B)_
        - .... 0000 = Unused: 0x0 _(offset 98, 1 B)_
      - Type Code: NEXT_HOP (3) _(offset 99, 1 B)_
      - Length: 4 _(offset 100, 1 B)_
      - Next hop: 100.200.255.1 _(offset 101, 4 B)_
  - Network Layer Reachability Information (NLRI) _(offset 105, 5 B)_
    - 198.51.100.0/25 _(offset 105, 5 B)_
      - NLRI prefix length: 25 _(offset 105, 1 B)_
      - NLRI prefix: 198.51.100.0 _(offset 106, 4 B)_

### BGP sessions and messages

2 BGP session(s), 30 BGP message(s): 14 UPDATE, 11 KEEPALIVE, 2 OPEN, 2 ROUTE-REFRESH, 1 NOTIFICATION.

**BGP sessions**

| Peers | Up when capture started | Messages | Keepalive rhythm | Ended | Reconnect attempts |
|---|---|---|---|---|---|
| ISPA-R1 (100.100.255.1) <-> HQ1-CORE-R1 (100.100.255.2) | opened in capture | KEEPALIVE 6, NOTIFICATION 1, OPEN 2, ROUTE-REFRESH 2, UPDATE 11 | - | closed by HQ1-CORE-R1 (100.100.255.2) at 11:12:14.637: Cease / Administrative shutdown; re-established at 11:14:00.291 (OPEN), down 105.7 s | 9 refused, 1 accepted |
| ISPB-R1 (100.200.255.1) <-> HQ1-CORE-R2 (100.200.255.2) | yes, no OPEN seen | KEEPALIVE 5, UPDATE 3 | ISPB-R1 every 26.7 s (18-52 s); HQ1-CORE-R2 every 53.8 s (52-55 s) | still up at the end | - |

**UPDATE messages (announce and withdraw)**

| Clock | From -> to | Announces | Withdraws | AS_PATH | NEXT_HOP | Other attributes | Frame |
|---|---|---|---|---|---|---|---|
| 11:14:00.298 | ISPA-R1 (100.100.255.1) -> HQ1-CORE-R1 (100.100.255.2) | 203.0.113.0/24 | - | 65100 65002 | 100.100.255.1 | origin IGP | 121 |
| 11:14:00.298 | ISPA-R1 (100.100.255.1) -> HQ1-CORE-R1 (100.100.255.2) | 198.51.100.0/25 | - | 65100 65200 65001 65001 65001 65001 | 100.100.255.1 | origin IGP | 121 |
| 11:14:00.298 | ISPA-R1 (100.100.255.1) -> HQ1-CORE-R1 (100.100.255.2) | 198.51.100.128/25, 198.51.100.0/24 | - | 65100 65200 65001 | 100.100.255.1 | origin IGP | 121 |
| 11:14:00.298 | ISPA-R1 (100.100.255.1) -> HQ1-CORE-R1 (100.100.255.2) | 100.200.0.0/16 | - | 65100 65200 | 100.100.255.1 | origin IGP | 121 |
| 11:14:00.298 | ISPA-R1 (100.100.255.1) -> HQ1-CORE-R1 (100.100.255.2) | 100.100.0.0/16 | - | 65100 | 100.100.255.1 | origin IGP, MED 0 | 121 |
| 11:14:00.298 | ISPA-R1 (100.100.255.1) -> HQ1-CORE-R1 (100.100.255.2) | 0.0.0.0/0 | - | 65100 | 100.100.255.1 | origin IGP | 121 |
| 11:14:00.298 | ISPA-R1 (100.100.255.1) -> HQ1-CORE-R1 (100.100.255.2) | - | - | - | - | - | 121 |
| 11:14:00.300 | HQ1-CORE-R1 (100.100.255.2) -> ISPA-R1 (100.100.255.1) | 198.51.100.128/25 | - | 65001 65001 65001 65001 | 100.100.255.2 | origin IGP | 123 |
| 11:14:00.300 | HQ1-CORE-R1 (100.100.255.2) -> ISPA-R1 (100.100.255.1) | 198.51.100.0/25, 198.51.100.0/24 | - | 65001 | 100.100.255.2 | origin IGP, MED 0 | 123 |
| 11:14:00.300 | HQ1-CORE-R1 (100.100.255.2) -> ISPA-R1 (100.100.255.1) | - | - | - | - | - | 123 |
| 11:14:00.302 | ISPA-R1 (100.100.255.1) -> HQ1-CORE-R1 (100.100.255.2) | 198.51.100.0/25, 198.51.100.0/24 | - | 65100 65001 | 100.100.255.2 | origin IGP | 125 |
| 11:12:14.643 | ISPB-R1 (100.200.255.1) -> HQ1-CORE-R2 (100.200.255.2) | 198.51.100.0/25 | - | 65200 65100 65001 | 100.200.255.1 | origin IGP | 14 |
| 11:12:44.741 | ISPB-R1 (100.200.255.1) -> HQ1-CORE-R2 (100.200.255.2) | - | 198.51.100.0/25 | - | - | - | 21 |
| 11:14:00.304 | ISPB-R1 (100.200.255.1) -> HQ1-CORE-R2 (100.200.255.2) | 198.51.100.0/25 | - | 65200 65100 65001 | 100.200.255.1 | origin IGP | 67 |

**NOTIFICATION messages**

| Clock | From -> to | Reason | Frame |
|---|---|---|---|
| 11:12:14.637 | HQ1-CORE-R1 (100.100.255.2) -> ISPA-R1 (100.100.255.1) | Cease / Administrative shutdown | 23 |

**Every BGP message on the wire**

| Clock | At (s) | From -> to | Message | BGP bytes | Frame |
|---|---|---|---|---|---|
| 11:11:56.033 | 7.36 | ISPA-R1 (100.100.255.1) -> HQ1-CORE-R1 (100.100.255.2) | KEEPALIVE | 19 | 9 |
| 11:11:56.594 | 7.92 | ISPB-R1 (100.200.255.1) -> HQ1-CORE-R2 (100.200.255.2) | KEEPALIVE | 19 | 4 |
| 11:11:59.008 | 10.33 | HQ1-CORE-R1 (100.100.255.2) -> ISPA-R1 (100.100.255.1) | KEEPALIVE | 19 | 12 |
| 11:12:07.271 | 18.59 | HQ1-CORE-R2 (100.200.255.2) -> ISPB-R1 (100.200.255.1) | KEEPALIVE | 19 | 10 |
| 11:12:14.637 | 25.96 | HQ1-CORE-R1 (100.100.255.2) -> ISPA-R1 (100.100.255.1) | NOTIFICATION: Cease / Administrative shutdown | 21 | 23 |
| 11:12:14.643 | 25.97 | ISPB-R1 (100.200.255.1) -> HQ1-CORE-R2 (100.200.255.2) | UPDATE: +1 / -0 prefix(es) | 56 | 14 |
| 11:12:44.741 | 56.06 | ISPB-R1 (100.200.255.1) -> HQ1-CORE-R2 (100.200.255.2) | UPDATE: +0 / -1 prefix(es) | 28 | 21 |
| 11:13:02.578 | 73.90 | HQ1-CORE-R2 (100.200.255.2) -> ISPB-R1 (100.200.255.1) | KEEPALIVE | 19 | 30 |
| 11:13:36.956 | 108.28 | ISPB-R1 (100.200.255.1) -> HQ1-CORE-R2 (100.200.255.2) | KEEPALIVE | 19 | 53 |
| 11:13:54.814 | 126.14 | HQ1-CORE-R2 (100.200.255.2) -> ISPB-R1 (100.200.255.1) | KEEPALIVE | 19 | 65 |
| 11:14:00.291 | 131.61 | HQ1-CORE-R1 (100.100.255.2) -> ISPA-R1 (100.100.255.1) | OPEN | 57 | 114 |
| 11:14:00.292 | 131.61 | ISPA-R1 (100.100.255.1) -> HQ1-CORE-R1 (100.100.255.2) | OPEN | 57 | 116 |
| 11:14:00.292 | 131.62 | ISPA-R1 (100.100.255.1) -> HQ1-CORE-R1 (100.100.255.2) | KEEPALIVE | 19 | 117 |
| 11:14:00.294 | 131.62 | HQ1-CORE-R1 (100.100.255.2) -> ISPA-R1 (100.100.255.1) | KEEPALIVE | 19 | 119 |
| 11:14:00.295 | 131.62 | ISPA-R1 (100.100.255.1) -> HQ1-CORE-R1 (100.100.255.2) | ROUTE-REFRESH BoRR (begin) | 23 | 120 |
| 11:14:00.298 | 131.62 | ISPA-R1 (100.100.255.1) -> HQ1-CORE-R1 (100.100.255.2) | UPDATE: +1 / -0 prefix(es) | 51 | 121 |
| 11:14:00.298 | 131.62 | ISPA-R1 (100.100.255.1) -> HQ1-CORE-R1 (100.100.255.2) | UPDATE (End-of-RIB) | 23 | 121 |
| 11:14:00.298 | 131.62 | ISPA-R1 (100.100.255.1) -> HQ1-CORE-R1 (100.100.255.2) | ROUTE-REFRESH EoRR (end) | 23 | 121 |
| 11:14:00.298 | 131.62 | ISPA-R1 (100.100.255.1) -> HQ1-CORE-R1 (100.100.255.2) | UPDATE: +1 / -0 prefix(es) | 44 | 121 |
| 11:14:00.298 | 131.62 | ISPA-R1 (100.100.255.1) -> HQ1-CORE-R1 (100.100.255.2) | UPDATE: +1 / -0 prefix(es) | 53 | 121 |
| 11:14:00.298 | 131.62 | ISPA-R1 (100.100.255.1) -> HQ1-CORE-R1 (100.100.255.2) | UPDATE: +1 / -0 prefix(es) | 50 | 121 |
| 11:14:00.298 | 131.62 | ISPA-R1 (100.100.255.1) -> HQ1-CORE-R1 (100.100.255.2) | UPDATE: +2 / -0 prefix(es) | 60 | 121 |
| 11:14:00.298 | 131.62 | ISPA-R1 (100.100.255.1) -> HQ1-CORE-R1 (100.100.255.2) | UPDATE: +1 / -0 prefix(es) | 68 | 121 |
| 11:14:00.300 | 131.62 | HQ1-CORE-R1 (100.100.255.2) -> ISPA-R1 (100.100.255.1) | KEEPALIVE | 19 | 122 |
| 11:14:00.300 | 131.62 | HQ1-CORE-R1 (100.100.255.2) -> ISPA-R1 (100.100.255.1) | UPDATE: +1 / -0 prefix(es) | 60 | 123 |
| 11:14:00.300 | 131.62 | HQ1-CORE-R1 (100.100.255.2) -> ISPA-R1 (100.100.255.1) | UPDATE (End-of-RIB) | 23 | 123 |
| 11:14:00.300 | 131.62 | HQ1-CORE-R1 (100.100.255.2) -> ISPA-R1 (100.100.255.1) | UPDATE: +2 / -0 prefix(es) | 59 | 123 |
| 11:14:00.301 | 131.62 | ISPA-R1 (100.100.255.1) -> HQ1-CORE-R1 (100.100.255.2) | KEEPALIVE | 19 | 124 |
| 11:14:00.302 | 131.62 | ISPA-R1 (100.100.255.1) -> HQ1-CORE-R1 (100.100.255.2) | UPDATE: +2 / -0 prefix(es) | 56 | 125 |
| 11:14:00.304 | 131.63 | ISPB-R1 (100.200.255.1) -> HQ1-CORE-R2 (100.200.255.2) | UPDATE: +1 / -0 prefix(es) | 56 | 67 |

### Probes (IP SLA and other periodic pings)

100.100.255.2 -> 100.200.1.1 every 5.0 s: 15 ok, 17 failed.

**Probe series**

| Source -> target | Interval | Probes | Answered | Failed | Median RTT | Changes |
|---|---|---|---|---|---|---|
| 100.100.255.2 -> 100.200.1.1 | 5.0 s | 32 | 15 | 17 | 2.5 ms | 11:11:59.269 failing (ICMP 3/13 communication administratively prohibited (ACL)); 11:13:24.269 ok |

### Link and Layer 2

0 link-level event(s). 

**Neighbors announced on this link**

| Protocol | Frames | Device |
|---|---|---|
| LLDP | 17 | HQ1-CORE-R1.almnjoy.lab, ISPA-R1.almnjoy.lab, ISPB-R1.almnjoy.lab |
| CDP | 13 | HQ1-CORE-R1.almnjoy.lab, HQ1-CORE-R2.almnjoy.lab, ISPA-R1.almnjoy.lab, ISPB-R1.almnjoy.lab |

### ICMP

31 pings / 15 replies, 17 unreachable, 9 TTL exceeded.

**Destination unreachable**

| Reason | Count |
|---|---|
| administratively prohibited | 17 |

### Traffic patterns

17 conversation(s), mostly other IP: ICMP on 100.200.1.1, 189 bps, 29% of bytes.

**What the traffic is (grouped by server and port)**

| Server | Service | Looks like | Conversations | Clients | Bytes | Share | Avg rate | Client -> server / back |
|---|---|---|---|---|---|---|---|---|
| 100.200.1.1 | ICMP | Other IP | 1 | 1 | 3.6 KB | 29.0% | 189 bps | 2.4 KB / 1.1 KB |
| 100.100.255.1 | BGP 179 | Request / response | 2 | 1 | 2.3 KB | 18.5% | 150 bps | 1.1 KB / 1.2 KB |
| 100.200.255.10 | ESP | Other IP | 1 | 1 | 1.9 KB | 15.4% | 124 bps | 972 B / 972 B |
| 100.100.255.2 | ICMP | Keepalive / heartbeat | 1 | 1 | 1.2 KB | 9.4% | 119 bps | 1.2 KB / 0 B |
| 100.200.255.1 | BGP 179 | Request / response | 1 | 1 | 1.1 KB | 9.1% | 74 bps | 519 B / 628 B |
| 100.100.255.2 | BGP 179 | Polling every ~12 s | 9 | 1 | 1.1 KB | 9.0% | 98 bps | 594 B / 540 B |
| 198.51.100.140 | ICMP | Other IP | 1 | 1 | 630 B | 5.0% | 157 bps | 0 B / 630 B |
| 34.107.243.93 | HTTPS 443 | Other IP | 1 | 1 | 594 B | 4.7% | 148 bps | 0 B / 594 B |

**Largest individual conversations**

| Client | Server | Service | Looks like | Packets | Bytes | Lasted | Rate | Filter |
|---|---|---|---|---|---|---|---|---|
| 100.100.255.2: | 100.200.1.1 | ICMP | Other IP | 47 | 3.6 KB | 155.0 s | 189 bps | ip.addr==100.100.255.2 && ip.addr==100.200.1.1 |
| 100.200.255.2: | 100.200.255.10 | ESP | Other IP | 12 | 1.9 KB | 125.1 s | 124 bps | ip.addr==100.200.255.2 && ip.addr==100.200.255.10 |
| 100.100.255.2:21381 | 100.100.255.1 | BGP 179 | Request / response | 17 | 1.7 KB | 0.1 s | 0 bps | ip.addr==100.100.255.2 && ip.addr==100.100.255.1 |
| 100.100.255.1: | 100.100.255.2 | ICMP | Keepalive / heartbeat | 17 | 1.2 KB | 80.0 s | 119 bps | ip.addr==100.100.255.1 && ip.addr==100.100.255.2 |
| 100.200.255.2:20076 | 100.200.255.1 | BGP 179 | Request / response | 16 | 1.1 KB | 123.8 s | 74 bps | ip.addr==100.200.255.2 && ip.addr==100.200.255.1 |
| 34.107.243.93:1026 | 198.51.100.140 | ICMP | Other IP | 9 | 630 B | 32.1 s | 157 bps | ip.addr==34.107.243.93 && ip.addr==198.51.100.140 |
| 198.51.100.10:1026 | 34.107.243.93 | HTTPS 443 | Other IP | 9 | 594 B | 32.1 s | 148 bps | ip.addr==198.51.100.10 && ip.addr==34.107.243.93 |
| 100.100.255.2:20305 | 100.100.255.1 | BGP 179 | Request / response | 9 | 581 B | 18.6 s | 250 bps | ip.addr==100.100.255.2 && ip.addr==100.100.255.1 |
| 100.100.255.1:64631 | 100.100.255.2 | BGP 179 | Polling every ~12 s | 2 | 126 B | 0.0 s | 0 bps | ip.addr==100.100.255.1 && ip.addr==100.100.255.2 |
| 100.100.255.1:50623 | 100.100.255.2 | BGP 179 | Polling every ~12 s | 2 | 126 B | 0.0 s | 0 bps | ip.addr==100.100.255.1 && ip.addr==100.100.255.2 |
| 100.100.255.1:15825 | 100.100.255.2 | BGP 179 | Polling every ~12 s | 2 | 126 B | 0.0 s | 0 bps | ip.addr==100.100.255.1 && ip.addr==100.100.255.2 |
| 100.100.255.1:56611 | 100.100.255.2 | BGP 179 | Polling every ~12 s | 2 | 126 B | 0.0 s | 0 bps | ip.addr==100.100.255.1 && ip.addr==100.100.255.2 |
| 100.100.255.1:41933 | 100.100.255.2 | BGP 179 | Polling every ~12 s | 2 | 126 B | 0.0 s | 0 bps | ip.addr==100.100.255.1 && ip.addr==100.100.255.2 |
| 100.100.255.1:35458 | 100.100.255.2 | BGP 179 | Polling every ~12 s | 2 | 126 B | 0.0 s | 0 bps | ip.addr==100.100.255.1 && ip.addr==100.100.255.2 |
| 100.100.255.1:33036 | 100.100.255.2 | BGP 179 | Polling every ~12 s | 2 | 126 B | 0.0 s | 0 bps | ip.addr==100.100.255.1 && ip.addr==100.100.255.2 |

### TCP health

13 TCP connections, 8 retransmissions, 9 resets. Handshake RTT median 1.4 ms.

**By service (server:port)**

| Service | Conns | Data segs | Retransmits | Retx rate | Dup ACKs | Resets | Worst stall | Handshake p50 |
|---|---|---|---|---|---|---|---|---|
| 34.107.243.93:443 | 1 | 0 | 8 | 0.0% | 0 | 0 | - | n/a |
| 100.100.255.2:179 | 9 | 0 | 0 | 0.0% | 0 | 9 | - | n/a |
| 100.100.255.1:179 | 2 | 13 | 0 | 0.0% | 0 | 0 | - | 1.4 ms |
| 100.200.255.1:179 | 1 | 8 | 0 | 0.0% | 0 | 0 | - | n/a |

**Worst connections**

| Stream | Client | Server | Frames | Retx | Dup ACK | RST | Longest stall | Filter |
|---|---|---|---|---|---|---|---|---|
| 12 | 198.51.100.10:1026 | 34.107.243.93:443 | 9 | 8 | 0 | 0 | - | tcp.stream eq 12 |
| 0 | 100.100.255.2:20305 | 100.100.255.1:179 | 9 | 0 | 0 | 0 | - | tcp.stream eq 0 |
| 1 | 100.100.255.1:64631 | 100.100.255.2:179 | 2 | 0 | 0 | 1 by server | - | tcp.stream eq 1 |
| 2 | 100.100.255.1:56611 | 100.100.255.2:179 | 2 | 0 | 0 | 1 by server | - | tcp.stream eq 2 |
| 3 | 100.100.255.1:15825 | 100.100.255.2:179 | 2 | 0 | 0 | 1 by server | - | tcp.stream eq 3 |
| 4 | 100.100.255.1:50623 | 100.100.255.2:179 | 2 | 0 | 0 | 1 by server | - | tcp.stream eq 4 |
| 5 | 100.100.255.1:41933 | 100.100.255.2:179 | 2 | 0 | 0 | 1 by server | - | tcp.stream eq 5 |
| 6 | 100.100.255.1:35458 | 100.100.255.2:179 | 2 | 0 | 0 | 1 by server | - | tcp.stream eq 6 |
| 7 | 100.100.255.1:33036 | 100.100.255.2:179 | 2 | 0 | 0 | 1 by server | - | tcp.stream eq 7 |
| 8 | 100.100.255.1:30881 | 100.100.255.2:179 | 2 | 0 | 0 | 1 by server | - | tcp.stream eq 8 |
| 9 | 100.100.255.1:60942 | 100.100.255.2:179 | 2 | 0 | 0 | 1 by server | - | tcp.stream eq 9 |
| 10 | 100.100.255.2:21381 | 100.100.255.1:179 | 17 | 0 | 0 | 0 | - | tcp.stream eq 10 |

### Spanning tree and Layer 2 control plane

**Who is on each end (CDP / LLDP)**

| Link | Proto | Device | Its port | Source MAC |
|---|---|---|---|---|
| HQ1-CORE-R1 Et0/2 <-> ISPA-R1 Et0/2 | CDP | HQ1-CORE-R1 | Ethernet0/2 | aa:bb:cc:00:18:20 |
| HQ1-CORE-R1 Et0/2 <-> ISPA-R1 Et0/2 | CDP | ISPA-R1 | Ethernet0/2 | aa:bb:cc:00:12:20 |
| HQ1-CORE-R1 Et0/2 <-> ISPA-R1 Et0/2 | LLDP | HQ1-CORE-R1 | Et0/2 | aa:bb:cc:00:18:20 |
| HQ1-CORE-R1 Et0/2 <-> ISPA-R1 Et0/2 | LLDP | ISPA-R1 | Et0/2 | aa:bb:cc:00:12:20 |
| HQ1-CORE-R2 Et0/2 <-> ISPB-R1 Et0/2 | CDP | HQ1-CORE-R2 | Ethernet0/2 | aa:bb:cc:00:19:20 |
| HQ1-CORE-R2 Et0/2 <-> ISPB-R1 Et0/2 | CDP | ISPB-R1 | Ethernet0/2 | aa:bb:cc:00:14:20 |
| HQ1-CORE-R2 Et0/2 <-> ISPB-R1 Et0/2 | LLDP | ISPB-R1 | Et0/2 | aa:bb:cc:00:14:20 |

### MTU and fragmentation

Largest frame 426 B. SYN MSS 1460-1460.

## Notes from the engine

- Merged 2 captures onto one clock. Frame numbers in this report are per file; the link label says which file.

## Appendix: all facts (JSON)

```json
{
 "source": "2 captures",
 "kind": "pcap",
 "focus": {
  "src": [],
  "dst": [],
  "ports": [],
  "question": "Break down the individual BGP messages (OPEN, KEEPALIVE, UPDATE, NOTIFICATION, ROUTE-REFRESH) and the IP SLA pings, before, during and after the ISP A failure. Show what we can see in each packet.",
  "intents": [
   "breakdown",
   "bgp",
   "probes",
   "link"
  ],
  "auto": false,
  "protos": [
   "bgp",
   "icmp"
  ],
  "when": "11:11:59",
  "when_t": 10.322,
  "display_filter": ""
 },
 "overview": {
  "packets": 216,
  "duration_s": 155.596,
  "bytes": 26482.0,
  "bytes_h": "25.9 KB",
  "start": "2026-11-25 11:11:48 CST",
  "avg_pps": 1.4,
  "focus_packets": 216,
  "tcp_streams": 13,
  "hosts": 15
 },
 "findings": [
  {
   "severity": "warning",
   "category": "probes",
   "title": "Probe to 100.200.1.1 started failing at 11:11:59.269",
   "detail": "Last answered probe 11:11:54.270; from 11:11:59.269 on: ICMP 3/13 communication administratively prohibited (ACL) from 100.100.255.1. The reporting router is telling you an ACL dropped the probe: the path past it is blocked on purpose. An IP SLA operation counts this as a failure; a track object on it goes down after its delay.",
   "evidence": "icmp && ip.addr == 100.200.1.1 && icmp.type != 8",
   "frames": [
    15
   ],
   "metrics": {
    "from_when_s": 0.3,
    "near_when": true
   }
  },
  {
   "severity": "warning",
   "category": "bgp",
   "title": "BGP session closed by HQ1-CORE-R1: Cease / Administrative shutdown",
   "detail": "ISPA-R1 (100.100.255.1) <-> HQ1-CORE-R1 (100.100.255.2): HQ1-CORE-R1 (100.100.255.2) sent a NOTIFICATION (Cease / Administrative shutdown) at 11:12:14.637 and closed TCP. Administrative shutdown means the sender's own config shut the neighbor: a person, or a script / EEM applet. ",
   "evidence": "bgp.type == 3 && ip.src == 100.100.255.2",
   "frames": [
    23
   ],
   "metrics": {
    "from_when_s": 15.6,
    "near_when": true
   }
  },
  {
   "severity": "warning",
   "category": "icmp",
   "title": "Forwarding loop for 198.51.100.10: 9 packet(s) died of TTL past this capture point",
   "detail": "Packets from 34.107.243.93 to 198.51.100.10 crossed this link with TTL 115 and 198.51.100.140 answered TTL-exceeded about 64 ms later, quoting TTL 1: each one went round about 114 more hops before dying. A traceroute starts with TTL 1, 2, 3..., so a high TTL here means a loop beyond the capture point, not a traceroute (11:13:17.714 to 11:13:49.770).",
   "evidence": "icmp.type == 11 && icmp.ip.dst == 198.51.100.10 || ip.dst == 198.51.100.10",
   "frames": [
    36,
    38,
    40,
    42,
    44,
    46,
    49,
    52,
    61
   ],
   "metrics": {
    "packets": 9,
    "hops": 114,
    "from_when_s": 25.7,
    "near_when": true
   }
  },
  {
   "severity": "warning",
   "category": "icmp",
   "title": "16 ping(s) refused with ICMP unreachable",
   "detail": "31 echo requests, 15 replies, 16 answered by an ICMP error instead of a reply. That is a router on the path saying no, not packet loss.",
   "evidence": "icmp.type==3",
   "frames": [],
   "metrics": {}
  },
  {
   "severity": "info",
   "category": "breakdown",
   "title": "16 packets broken down field by field",
   "detail": "Kinds: ICMP echo request, ICMP echo reply, BGP KEEPALIVE, ICMP unreachable, admin prohibited, BGP NOTIFICATION, BGP UPDATE, BGP OPEN, BGP ROUTE-REFRESH.",
   "evidence": "bgp || icmp",
   "frames": [],
   "metrics": {}
  },
  {
   "severity": "info",
   "category": "bgp",
   "title": "9 reconnect attempt(s) refused",
   "detail": "ISPA-R1 (100.100.255.1) kept opening TCP 179 to HQ1-CORE-R1 (100.100.255.2) (11:12:24.715 to 11:13:56.892, every 8-14 s) and every SYN got a RST back. A shut-down or unconfigured neighbor refuses the connection; the other side keeps trying on its connect-retry timer.",
   "evidence": "ip.addr==100.100.255.1 && ip.addr==100.100.255.2 && tcp.port==179 && (tcp.flags.syn == 1 || tcp.flags.reset == 1)",
   "frames": [
    35
   ],
   "metrics": {
    "from_when_s": 25.7,
    "near_when": true
   }
  },
  {
   "severity": "info",
   "category": "bgp",
   "title": "Session re-established at 11:14:00.291, down 105.7 s",
   "detail": "ISPA-R1 (100.100.255.1) <-> HQ1-CORE-R1 (100.100.255.2): OPEN exchange at 11:14:00.291 (HQ1-CORE-R1 AS 65001, hold 180 s, router ID 10.255.1.1; ISPA-R1 AS 65100, hold 180 s, router ID 100.100.254.1; capabilities: 4-byte AS, Enhanced route refresh, Multiprotocol, Route refresh, Route refresh (Cisco)). Each side then sends a KEEPALIVE to confirm, and the table exchange (UPDATEs) follows.",
   "evidence": "bgp.type == 1 && ip.addr == 100.100.255.1",
   "frames": [
    114
   ],
   "metrics": {
    "from_when_s": 121.3,
    "near_when": false
   }
  },
  {
   "severity": "info",
   "category": "bgp",
   "title": "7 UPDATEs ISPA-R1 -> HQ1-CORE-R1 at 11:14:00.298: 7 prefix(es) announced, End-of-RIB",
   "detail": "Table exchange in one burst: 203.0.113.0/24 (AS_PATH 65100 65002); 198.51.100.0/25 (AS_PATH 65100 65200 65001 65001 65001 65001); 198.51.100.128/25, 198.51.100.0/24 (AS_PATH 65100 65200 65001); 100.200.0.0/16 (AS_PATH 65100 65200); 100.100.0.0/16 (AS_PATH 65100); 0.0.0.0/0 (AS_PATH 65100); End-of-RIB (empty UPDATE: that was the whole table).",
   "evidence": "bgp.type == 2 && ip.src == 100.100.255.1",
   "frames": [
    121,
    121,
    121,
    121,
    121,
    121,
    121
   ],
   "metrics": {
    "from_when_s": 121.3,
    "near_when": false
   }
  },
  {
   "severity": "info",
   "category": "bgp",
   "title": "3 UPDATEs HQ1-CORE-R1 -> ISPA-R1 at 11:14:00.300: 3 prefix(es) announced, End-of-RIB",
   "detail": "Table exchange in one burst: 198.51.100.128/25 (AS_PATH 65001 65001 65001 65001); 198.51.100.0/25, 198.51.100.0/24 (AS_PATH 65001); End-of-RIB (empty UPDATE: that was the whole table).",
   "evidence": "bgp.type == 2 && ip.src == 100.100.255.2",
   "frames": [
    123,
    123,
    123
   ],
   "metrics": {
    "from_when_s": 121.3,
    "near_when": false
   }
  },
  {
   "severity": "info",
   "category": "bgp",
   "title": "UPDATE ISPA-R1 -> HQ1-CORE-R1: announce 198.51.100.0/25, 198.51.100.0/24",
   "detail": "At 11:14:00.302, AS_PATH 65100 65001, NEXT_HOP 100.100.255.2.",
   "evidence": "bgp.type == 2 && ip.src == 100.100.255.1",
   "frames": [
    125
   ],
   "metrics": {
    "from_when_s": 121.3,
    "near_when": false
   }
  },
  {
   "severity": "info",
   "category": "bgp",
   "title": "UPDATE ISPB-R1 -> HQ1-CORE-R2: announce 198.51.100.0/25",
   "detail": "At 11:12:14.643, AS_PATH 65200 65100 65001, NEXT_HOP 100.200.255.1.",
   "evidence": "bgp.type == 2 && ip.src == 100.200.255.1",
   "frames": [
    14
   ],
   "metrics": {
    "from_when_s": 0.3,
    "near_when": true
   }
  },
  {
   "severity": "info",
   "category": "bgp",
   "title": "UPDATE ISPB-R1 -> HQ1-CORE-R2: withdraw 198.51.100.0/25",
   "detail": "At 11:12:44.741.",
   "evidence": "bgp.type == 2 && ip.src == 100.200.255.1",
   "frames": [
    21
   ],
   "metrics": {
    "from_when_s": 15.3,
    "near_when": true
   }
  },
  {
   "severity": "info",
   "category": "bgp",
   "title": "UPDATE ISPB-R1 -> HQ1-CORE-R2: announce 198.51.100.0/25",
   "detail": "At 11:14:00.304, AS_PATH 65200 65100 65001, NEXT_HOP 100.200.255.1.",
   "evidence": "bgp.type == 2 && ip.src == 100.200.255.1",
   "frames": [
    67
   ],
   "metrics": {
    "from_when_s": 69.7,
    "near_when": false
   }
  },
  {
   "severity": "info",
   "category": "probes",
   "title": "Periodic probe 100.100.255.2 -> 100.200.1.1 every 5.0 s",
   "detail": "32 echo requests on a steady 5.0 s interval: this is IP SLA icmp-echo (one source, one target, fixed frequency). 15 answered (median 2.5 ms), 17 failed.",
   "evidence": "icmp && ip.addr == 100.100.255.2 && ip.addr == 100.200.1.1",
   "frames": [],
   "metrics": {}
  },
  {
   "severity": "info",
   "category": "probes",
   "title": "15.4 s after the first failed probe: BGP NOTIFICATION 100.100.255.2 -> 100.100.255.1",
   "detail": "First failed probe 11:11:59.269, then BGP NOTIFICATION 100.100.255.2 -> 100.100.255.1 at 11:12:14.637. When a probe drives a track object, the gap is the track's `delay down` plus the time an EEM applet (or the routing process) takes to act.",
   "evidence": "bgp.type == 3",
   "frames": [
    23
   ],
   "metrics": {
    "from_when_s": 15.6,
    "near_when": true
   }
  },
  {
   "severity": "info",
   "category": "flows",
   "title": "17 conversation(s) across 8 service(s)",
   "detail": "17 conversation(s), mostly other IP: ICMP on 100.200.1.1, 189 bps, 29% of bytes. Traffic by pattern: other IP 54%, request / response 28%, keepalive / heartbeat 9%.",
   "evidence": "ip",
   "frames": [],
   "metrics": {}
  },
  {
   "severity": "info",
   "category": "icmp",
   "title": "17 ICMP destination-unreachable message(s)",
   "detail": "Reasons: administratively prohibited (17).",
   "evidence": "icmp.type==3",
   "frames": [
    15,
    17,
    20,
    22,
    30,
    34,
    39,
    42
   ],
   "metrics": {
    "from_when_s": 0.3,
    "near_when": true
   }
  },
  {
   "severity": "info",
   "category": "tcp",
   "title": "9 connection attempt(s) refused with RST",
   "detail": "The server answered the SYN with a RST: it is up and reachable, but nothing accepts on that port (BGP port 179: the neighbor is shut down or not configured on that side, so it refuses the peer's connect-retry).",
   "evidence": "tcp.flags.syn==1 && tcp.flags.ack==0 && tcp.port in {179}",
   "frames": [
    35,
    45,
    55,
    63,
    70,
    78,
    88,
    97
   ],
   "metrics": {
    "from_when_s": 25.7,
    "near_when": true
   }
  },
  {
   "severity": "ok",
   "category": "bgp",
   "title": "ISPB-R1 heard from every 26.7 s",
   "detail": "2 KEEPALIVE(s) on ISPB-R1 (100.200.255.1) <-> HQ1-CORE-R2 (100.200.255.2); gaps between its BGP messages 18.0 to 52.2 s. Any BGP message (KEEPALIVE or UPDATE) restarts the keepalive timer. IOS sends one every third of the hold time (default 60 s of 180) and jitters it a little lower, so 45 to 60 s apart is normal.",
   "evidence": "bgp.type == 4 && ip.src == 100.200.255.1",
   "frames": [],
   "metrics": {}
  },
  {
   "severity": "ok",
   "category": "bgp",
   "title": "HQ1-CORE-R2 heard from every 53.8 s",
   "detail": "3 KEEPALIVE(s) on ISPB-R1 (100.200.255.1) <-> HQ1-CORE-R2 (100.200.255.2); gaps between its BGP messages 52.2 to 55.3 s. Any BGP message (KEEPALIVE or UPDATE) restarts the keepalive timer. IOS sends one every third of the hold time (default 60 s of 180) and jitters it a little lower, so 45 to 60 s apart is normal.",
   "evidence": "bgp.type == 4 && ip.src == 100.200.255.2",
   "frames": [],
   "metrics": {}
  }
 ],
 "sections": {
  "overview": {
   "summary": "216 frames over 155.6 s (25.9 KB), 15 addresses, 13 TCP connections.",
   "data": {
    "timeline": {
     "x": [
      0.0,
      2.59,
      5.19,
      7.78,
      10.37,
      12.97,
      15.56,
      18.15,
      20.75,
      23.34,
      25.93,
      28.53,
      31.12,
      33.71,
      36.31,
      38.9,
      41.49,
      44.09,
      46.68,
      49.27,
      51.87,
      54.46,
      57.05,
      59.65,
      62.24,
      64.83,
      67.43,
      70.02,
      72.61,
      75.2,
      77.8,
      80.39,
      82.98,
      85.58,
      88.17,
      90.76,
      93.36,
      95.95,
      98.54,
      101.14,
      103.73,
      106.32,
      108.92,
      111.51,
      114.1,
      116.7,
      119.29,
      121.88,
      124.48,
      127.07,
      129.66,
      132.26,
      134.85,
      137.44,
      140.04,
      142.63,
      145.22,
      147.82,
      150.41,
      153.0
     ],
     "all": [
      7,
      2,
      4,
      5,
      3,
      1,
      4,
      6,
      0,
      3,
      8,
      3,
      2,
      5,
      0,
      3,
      2,
      2,
      0,
      7,
      1,
      6,
      0,
      5,
      4,
      2,
      1,
      4,
      5,
      2,
      2,
      2,
      4,
      2,
      11,
      7,
      4,
      2,
      5,
      1,
      6,
      4,
      4,
      1,
      2,
      3,
      6,
      2,
      6,
      2,
      22,
      1,
      2,
      0,
      4,
      2,
      3,
      0,
      4,
      5
     ],
     "focus": [],
     "retx": [
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      3,
      2,
      0,
      1,
      0,
      0,
      1,
      0,
      0,
      0,
      0,
      0,
      1,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0
     ],
     "rst": [
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      1,
      0,
      0,
      0,
      0,
      0,
      1,
      0,
      0,
      0,
      0,
      1,
      0,
      0,
      0,
      1,
      0,
      0,
      0,
      1,
      0,
      0,
      1,
      0,
      0,
      0,
      0,
      1,
      0,
      0,
      0,
      0,
      1,
      0,
      0,
      0,
      1,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0
     ],
     "bin_s": 2.593,
     "when": 10.322
    }
   },
   "tables": [
    {
     "title": "Captures merged onto one timeline",
     "columns": [
      "Link",
      "File",
      "Frames",
      "From (s)",
      "To (s)"
     ],
     "rows": [
      [
       "HQ1-CORE-R1 Et0/2 <-> ISPA-R1 Et0/2",
       "P1-ISPA-link_HQ1-CORE-R1-Et0-2.pcap",
       143,
       "0.0",
       "155.6"
      ],
      [
       "HQ1-CORE-R2 Et0/2 <-> ISPB-R1 Et0/2",
       "P2-ISPB-link_HQ1-CORE-R2-Et0-2.pcap",
       73,
       "0.2",
       "153.4"
      ]
     ]
    },
    {
     "title": "Protocol mix",
     "columns": [
      "Protocol",
      "Frames",
      "Share"
     ],
     "rows": [
      [
       "ICMP",
       73,
       "33.8%"
      ],
      [
       "TCP",
       48,
       "22.2%"
      ],
      [
       "LOOP",
       32,
       "14.8%"
      ],
      [
       "BGP",
       21,
       "9.7%"
      ],
      [
       "LLDP",
       17,
       "7.9%"
      ],
      [
       "CDP",
       13,
       "6.0%"
      ],
      [
       "ESP",
       12,
       "5.6%"
      ]
     ]
    },
    {
     "title": "Top conversations",
     "columns": [
      "Hosts",
      "Frames",
      "Bytes"
     ],
     "rows": [
      [
       "100.100.255.1 <-> 100.100.255.2",
       61,
       "4.6 KB"
      ],
      [
       "100.100.255.2 <-> 100.200.1.1",
       47,
       "3.6 KB"
      ],
      [
       "100.200.255.1 <-> 100.200.255.2",
       16,
       "1.1 KB"
      ],
      [
       "aa:bb:cc:00:19:20 <-> aa:bb:cc:00:19:20",
       16,
       "960 B"
      ],
      [
       "aa:bb:cc:00:18:20 <-> aa:bb:cc:00:18:20",
       16,
       "960 B"
      ],
      [
       "100.200.255.10 <-> 100.200.255.2",
       12,
       "1.9 KB"
      ],
      [
       "198.51.100.140 <-> 34.107.243.93",
       9,
       "630 B"
      ],
      [
       "198.51.100.10 <-> 34.107.243.93",
       9,
       "594 B"
      ],
      [
       "01:80:c2:00:00:0e <-> aa:bb:cc:00:12:20",
       6,
       "2.2 KB"
      ],
      [
       "01:80:c2:00:00:0e <-> aa:bb:cc:00:18:20",
       6,
       "2.3 KB"
      ],
      [
       "01:80:c2:00:00:0e <-> aa:bb:cc:00:14:20",
       5,
       "1.9 KB"
      ],
      [
       "01:00:0c:cc:cc:cc <-> aa:bb:cc:00:18:20",
       4,
       "1.6 KB"
      ]
     ]
    }
   ]
  },
  "breakdown": {
   "summary": "16 packets, one of every kind of BGP, ICMP message in the capture, decoded field by field. Click a field to light up its bytes. Rare messages (UPDATE, NOTIFICATION, OPEN) are all shown; routine ones (KEEPALIVE, ping) once per sender.",
   "data": {
    "cards": [
     {
      "n": 1,
      "kind": "ICMP echo request",
      "t": 0.593,
      "clock": "11:11:49.270",
      "from": "HQ1-CORE-R1",
      "to": "ISPA-R1",
      "src": "100.100.255.2",
      "dst": "100.200.1.1",
      "frame": 2,
      "link": "HQ1-CORE-R1 Et0/2 <-> ISPA-R1 Et0/2",
      "len": 78,
      "summary": "The probe itself.",
      "layers": [
       {
        "proto": "eth",
        "title": "Ethernet II, Src: aa:bb:cc:00:18:20, Dst: aa:bb:cc:00:12:20",
        "pos": 0,
        "size": 14,
        "note": "Layer 2 frame. Only matters on this one wire: the next hop rewrites both MAC addresses.",
        "fields": [
         {
          "name": "eth.dst",
          "text": "Destination: aa:bb:cc:00:12:20",
          "pos": 0,
          "size": 6,
          "note": "Who on this wire should take the frame."
         },
         {
          "name": "eth.src",
          "text": "Source: aa:bb:cc:00:18:20",
          "pos": 6,
          "size": 6,
          "note": "Which interface put it on the wire."
         },
         {
          "name": "eth.type",
          "text": "Type: IPv4 (0x0800)",
          "pos": 12,
          "size": 2,
          "note": "What comes next: 0x0800 IPv4, 0x86dd IPv6, 0x8100 VLAN tag, 0x0806 ARP."
         }
        ]
       },
       {
        "proto": "ip",
        "title": "Internet Protocol Version 4, Src: 100.100.255.2, Dst: 100.200.1.1",
        "pos": 14,
        "size": 20,
        "note": "Layer 3 header. Source and destination stay the same end to end (unless NAT rewrites them); TTL drops by one per router.",
        "fields": [
         {
          "name": "ip.version",
          "text": "0100 .... = Version: 4",
          "pos": 14,
          "size": 1,
          "note": "4 = IPv4."
         },
         {
          "name": "ip.hdr_len",
          "text": ".... 0101 = Header Length: 20 bytes (5)",
          "pos": 14,
          "size": 1,
          "note": "Header length. 20 bytes means no IP options."
         },
         {
          "name": "ip.dsfield",
          "text": "Differentiated Services Field: 0x00 (DSCP: CS0, ECN: Not-ECT)",
          "pos": 15,
          "size": 1,
          "note": "DSCP + ECN. Routers mark control traffic like BGP CS6 (DSCP 48, byte 0xc0) so QoS keeps it alive under load.",
          "children": [
           {
            "name": "ip.dsfield.dscp",
            "text": "0000 00.. = Differentiated Services Codepoint: Default (0)",
            "pos": 15,
            "size": 1,
            "note": "DSCP class. 48 = CS6, the class for routing protocols."
           },
           {
            "name": "ip.dsfield.ecn",
            "text": ".... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0)",
            "pos": 15,
            "size": 1
           }
          ]
         },
         {
          "name": "ip.len",
          "text": "Total Length: 64",
          "pos": 16,
          "size": 2,
          "note": "Total IP packet length (header + payload)."
         },
         {
          "name": "ip.id",
          "text": "Identification: 0x0134 (308)",
          "pos": 18,
          "size": 2,
          "note": "Identification. Unique per packet from a sender; also how you match the same packet in two captures."
         },
         {
          "name": "ip.flags",
          "text": "000. .... = Flags: 0x0",
          "pos": 20,
          "size": 1,
          "note": "Fragmentation flags. DF set = routers must not fragment it.",
          "children": [
           {
            "name": "ip.flags.rb",
            "text": "0... .... = Reserved bit: Not set",
            "pos": 20,
            "size": 1
           },
           {
            "name": "ip.flags.df",
            "text": ".0.. .... = Don't fragment: Not set",
            "pos": 20,
            "size": 1,
            "note": "Don't Fragment. If the packet is too big for a link it is dropped and an ICMP 'fragmentation needed' comes back."
           },
           {
            "name": "ip.flags.mf",
            "text": "..0. .... = More fragments: Not set",
            "pos": 20,
            "size": 1
           }
          ]
         },
         {
          "name": "ip.frag_offset",
          "text": "...0 0000 0000 0000 = Fragment Offset: 0",
          "pos": 20,
          "size": 2,
          "note": "Where this fragment sits in the original packet. 0 = not fragmented (or first piece)."
         },
         {
          "name": "ip.ttl",
          "text": "Time to Live: 255",
          "pos": 22,
          "size": 1,
          "note": "Time to live. Each router subtracts one; at 0 the packet dies and ICMP time-exceeded goes back. eBGP peers default to TTL 1 (directly connected) unless ebgp-multihop or ttl-security is set."
         },
         {
          "name": "ip.proto",
          "text": "Protocol: ICMP (1)",
          "pos": 23,
          "size": 1,
          "note": "What the payload is: 1 ICMP, 6 TCP, 17 UDP, 50 ESP, 89 OSPF, 88 EIGRP."
         },
         {
          "name": "ip.checksum",
          "text": "Header Checksum: 0xf158 [validation disabled]",
          "pos": 24,
          "size": 2,
          "note": "Header checksum, recomputed by every router because TTL changes."
         },
         {
          "name": "ip.src",
          "text": "Source Address: 100.100.255.2",
          "pos": 26,
          "size": 4,
          "note": "Original sender."
         },
         {
          "name": "ip.dst",
          "text": "Destination Address: 100.200.1.1",
          "pos": 30,
          "size": 4,
          "note": "Final destination."
         }
        ]
       },
       {
        "proto": "icmp",
        "title": "Internet Control Message Protocol",
        "pos": 34,
        "size": 44,
        "note": "Control messages for IP: ping (echo request / reply) and the error reports routers send back when they can't deliver.",
        "fields": [
         {
          "name": "icmp.type",
          "text": "Type: 8 (Echo (ping) request)",
          "pos": 34,
          "size": 1,
          "note": "Echo request (ping)."
         },
         {
          "name": "icmp.code",
          "text": "Code: 0",
          "pos": 35,
          "size": 1,
          "note": "Detail for the type. For type 3: 0 net, 1 host, 3 port unreachable, 4 fragmentation needed, 13 communication administratively prohibited (an ACL said no)."
         },
         {
          "name": "icmp.checksum",
          "text": "Checksum: 0xe5d1 [correct]",
          "pos": 36,
          "size": 2,
          "note": "Checksum over the ICMP message."
         },
         {
          "name": "icmp.ident",
          "text": "Identifier (BE): 281 (0x0119)",
          "pos": 38,
          "size": 2,
          "note": "Identifier: ties replies to the process that sent the pings (IP SLA uses one per operation)."
         },
         {
          "name": "icmp.ident_le",
          "text": "Identifier (LE): 6401 (0x1901)",
          "pos": 38,
          "size": 2
         },
         {
          "name": "icmp.seq",
          "text": "Sequence Number (BE): 1 (0x0001)",
          "pos": 40,
          "size": 2,
          "note": "Sequence number: counts the pings in a series."
         },
         {
          "name": "icmp.seq_le",
          "text": "Sequence Number (LE): 256 (0x0100)",
          "pos": 40,
          "size": 2
         },
         {
          "name": "data",
          "text": "data",
          "pos": -1,
          "size": 0,
          "children": [
           {
            "name": "data.data",
            "text": "Data: 000000005513ae5cabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd00000000",
            "pos": 42,
            "size": 36
           },
           {
            "name": "data.len",
            "text": "Length: 36",
            "pos": 42,
            "size": 0
           }
          ]
         }
        ]
       }
      ],
      "focus": "icmp"
     },
     {
      "n": 2,
      "kind": "ICMP echo reply",
      "t": 0.595,
      "clock": "11:11:49.272",
      "from": "ISPA-R1",
      "to": "HQ1-CORE-R1",
      "src": "100.200.1.1",
      "dst": "100.100.255.2",
      "frame": 3,
      "link": "HQ1-CORE-R1 Et0/2 <-> ISPA-R1 Et0/2",
      "len": 78,
      "summary": "The target answering.",
      "layers": [
       {
        "proto": "eth",
        "title": "Ethernet II, Src: aa:bb:cc:00:12:20, Dst: aa:bb:cc:00:18:20",
        "pos": 0,
        "size": 14,
        "note": "Layer 2 frame. Only matters on this one wire: the next hop rewrites both MAC addresses.",
        "fields": [
         {
          "name": "eth.dst",
          "text": "Destination: aa:bb:cc:00:18:20",
          "pos": 0,
          "size": 6,
          "note": "Who on this wire should take the frame."
         },
         {
          "name": "eth.src",
          "text": "Source: aa:bb:cc:00:12:20",
          "pos": 6,
          "size": 6,
          "note": "Which interface put it on the wire."
         },
         {
          "name": "eth.type",
          "text": "Type: IPv4 (0x0800)",
          "pos": 12,
          "size": 2,
          "note": "What comes next: 0x0800 IPv4, 0x86dd IPv6, 0x8100 VLAN tag, 0x0806 ARP."
         }
        ]
       },
       {
        "proto": "ip",
        "title": "Internet Protocol Version 4, Src: 100.200.1.1, Dst: 100.100.255.2",
        "pos": 14,
        "size": 20,
        "note": "Layer 3 header. Source and destination stay the same end to end (unless NAT rewrites them); TTL drops by one per router.",
        "fields": [
         {
          "name": "ip.version",
          "text": "0100 .... = Version: 4",
          "pos": 14,
          "size": 1,
          "note": "4 = IPv4."
         },
         {
          "name": "ip.hdr_len",
          "text": ".... 0101 = Header Length: 20 bytes (5)",
          "pos": 14,
          "size": 1,
          "note": "Header length. 20 bytes means no IP options."
         },
         {
          "name": "ip.dsfield",
          "text": "Differentiated Services Field: 0x00 (DSCP: CS0, ECN: Not-ECT)",
          "pos": 15,
          "size": 1,
          "note": "DSCP + ECN. Routers mark control traffic like BGP CS6 (DSCP 48, byte 0xc0) so QoS keeps it alive under load.",
          "children": [
           {
            "name": "ip.dsfield.dscp",
            "text": "0000 00.. = Differentiated Services Codepoint: Default (0)",
            "pos": 15,
            "size": 1,
            "note": "DSCP class. 48 = CS6, the class for routing protocols."
           },
           {
            "name": "ip.dsfield.ecn",
            "text": ".... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0)",
            "pos": 15,
            "size": 1
           }
          ]
         },
         {
          "name": "ip.len",
          "text": "Total Length: 64",
          "pos": 16,
          "size": 2,
          "note": "Total IP packet length (header + payload)."
         },
         {
          "name": "ip.id",
          "text": "Identification: 0x0134 (308)",
          "pos": 18,
          "size": 2,
          "note": "Identification. Unique per packet from a sender; also how you match the same packet in two captures."
         },
         {
          "name": "ip.flags",
          "text": "000. .... = Flags: 0x0",
          "pos": 20,
          "size": 1,
          "note": "Fragmentation flags. DF set = routers must not fragment it.",
          "children": [
           {
            "name": "ip.flags.rb",
            "text": "0... .... = Reserved bit: Not set",
            "pos": 20,
            "size": 1
           },
           {
            "name": "ip.flags.df",
            "text": ".0.. .... = Don't fragment: Not set",
            "pos": 20,
            "size": 1,
            "note": "Don't Fragment. If the packet is too big for a link it is dropped and an ICMP 'fragmentation needed' comes back."
           },
           {
            "name": "ip.flags.mf",
            "text": "..0. .... = More fragments: Not set",
            "pos": 20,
            "size": 1
           }
          ]
         },
         {
          "name": "ip.frag_offset",
          "text": "...0 0000 0000 0000 = Fragment Offset: 0",
          "pos": 20,
          "size": 2,
          "note": "Where this fragment sits in the original packet. 0 = not fragmented (or first piece)."
         },
         {
          "name": "ip.ttl",
          "text": "Time to Live: 254",
          "pos": 22,
          "size": 1,
          "note": "Time to live. Each router subtracts one; at 0 the packet dies and ICMP time-exceeded goes back. eBGP peers default to TTL 1 (directly connected) unless ebgp-multihop or ttl-security is set."
         },
         {
          "name": "ip.proto",
          "text": "Protocol: ICMP (1)",
          "pos": 23,
          "size": 1,
          "note": "What the payload is: 1 ICMP, 6 TCP, 17 UDP, 50 ESP, 89 OSPF, 88 EIGRP."
         },
         {
          "name": "ip.checksum",
          "text": "Header Checksum: 0xf258 [validation disabled]",
          "pos": 24,
          "size": 2,
          "note": "Header checksum, recomputed by every router because TTL changes."
         },
         {
          "name": "ip.src",
          "text": "Source Address: 100.200.1.1",
          "pos": 26,
          "size": 4,
          "note": "Original sender."
         },
         {
          "name": "ip.dst",
          "text": "Destination Address: 100.100.255.2",
          "pos": 30,
          "size": 4,
          "note": "Final destination."
         }
        ]
       },
       {
        "proto": "icmp",
        "title": "Internet Control Message Protocol",
        "pos": 34,
        "size": 44,
        "note": "Control messages for IP: ping (echo request / reply) and the error reports routers send back when they can't deliver.",
        "fields": [
         {
          "name": "icmp.type",
          "text": "Type: 0 (Echo (ping) reply)",
          "pos": 34,
          "size": 1,
          "note": "Echo reply."
         },
         {
          "name": "icmp.code",
          "text": "Code: 0",
          "pos": 35,
          "size": 1,
          "note": "Detail for the type. For type 3: 0 net, 1 host, 3 port unreachable, 4 fragmentation needed, 13 communication administratively prohibited (an ACL said no)."
         },
         {
          "name": "icmp.checksum",
          "text": "Checksum: 0xedd1 [correct]",
          "pos": 36,
          "size": 2,
          "note": "Checksum over the ICMP message."
         },
         {
          "name": "icmp.ident",
          "text": "Identifier (BE): 281 (0x0119)",
          "pos": 38,
          "size": 2,
          "note": "Identifier: ties replies to the process that sent the pings (IP SLA uses one per operation)."
         },
         {
          "name": "icmp.ident_le",
          "text": "Identifier (LE): 6401 (0x1901)",
          "pos": 38,
          "size": 2
         },
         {
          "name": "icmp.seq",
          "text": "Sequence Number (BE): 1 (0x0001)",
          "pos": 40,
          "size": 2,
          "note": "Sequence number: counts the pings in a series."
         },
         {
          "name": "icmp.seq_le",
          "text": "Sequence Number (LE): 256 (0x0100)",
          "pos": 40,
          "size": 2
         },
         {
          "name": "data",
          "text": "data",
          "pos": -1,
          "size": 0,
          "children": [
           {
            "name": "data.data",
            "text": "Data: 000000005513ae5cabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd00000000",
            "pos": 42,
            "size": 36
           },
           {
            "name": "data.len",
            "text": "Length: 36",
            "pos": 42,
            "size": 0
           }
          ]
         }
        ]
       }
      ],
      "focus": "icmp"
     },
     {
      "n": 3,
      "kind": "BGP KEEPALIVE",
      "t": 7.356,
      "clock": "11:11:56.033",
      "from": "ISPA-R1",
      "to": "HQ1-CORE-R1",
      "src": "100.100.255.1",
      "dst": "100.100.255.2",
      "frame": 9,
      "link": "HQ1-CORE-R1 Et0/2 <-> ISPA-R1 Et0/2",
      "len": 73,
      "summary": "Header only: marker, length 19, type 4. Nothing else in it. Its whole job is to reset the peer's hold timer.",
      "layers": [
       {
        "proto": "eth",
        "title": "Ethernet II, Src: aa:bb:cc:00:12:20, Dst: aa:bb:cc:00:18:20",
        "pos": 0,
        "size": 14,
        "note": "Layer 2 frame. Only matters on this one wire: the next hop rewrites both MAC addresses.",
        "fields": [
         {
          "name": "eth.dst",
          "text": "Destination: aa:bb:cc:00:18:20",
          "pos": 0,
          "size": 6,
          "note": "Who on this wire should take the frame."
         },
         {
          "name": "eth.src",
          "text": "Source: aa:bb:cc:00:12:20",
          "pos": 6,
          "size": 6,
          "note": "Which interface put it on the wire."
         },
         {
          "name": "eth.type",
          "text": "Type: IPv4 (0x0800)",
          "pos": 12,
          "size": 2,
          "note": "What comes next: 0x0800 IPv4, 0x86dd IPv6, 0x8100 VLAN tag, 0x0806 ARP."
         }
        ]
       },
       {
        "proto": "ip",
        "title": "Internet Protocol Version 4, Src: 100.100.255.1, Dst: 100.100.255.2",
        "pos": 14,
        "size": 20,
        "note": "Layer 3 header. Source and destination stay the same end to end (unless NAT rewrites them); TTL drops by one per router.",
        "fields": [
         {
          "name": "ip.version",
          "text": "0100 .... = Version: 4",
          "pos": 14,
          "size": 1,
          "note": "4 = IPv4."
         },
         {
          "name": "ip.hdr_len",
          "text": ".... 0101 = Header Length: 20 bytes (5)",
          "pos": 14,
          "size": 1,
          "note": "Header length. 20 bytes means no IP options."
         },
         {
          "name": "ip.dsfield",
          "text": "Differentiated Services Field: 0xc0 (DSCP: CS6, ECN: Not-ECT)",
          "pos": 15,
          "size": 1,
          "note": "DSCP + ECN. Routers mark control traffic like BGP CS6 (DSCP 48, byte 0xc0) so QoS keeps it alive under load.",
          "children": [
           {
            "name": "ip.dsfield.dscp",
            "text": "1100 00.. = Differentiated Services Codepoint: Class Selector 6 (48)",
            "pos": 15,
            "size": 1,
            "note": "DSCP class. 48 = CS6, the class for routing protocols."
           },
           {
            "name": "ip.dsfield.ecn",
            "text": ".... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0)",
            "pos": 15,
            "size": 1
           }
          ]
         },
         {
          "name": "ip.len",
          "text": "Total Length: 59",
          "pos": 16,
          "size": 2,
          "note": "Total IP packet length (header + payload)."
         },
         {
          "name": "ip.id",
          "text": "Identification: 0x677c (26492)",
          "pos": 18,
          "size": 2,
          "note": "Identification. Unique per packet from a sender; also how you match the same packet in two captures."
         },
         {
          "name": "ip.flags",
          "text": "010. .... = Flags: 0x2, Don't fragment",
          "pos": 20,
          "size": 1,
          "note": "Fragmentation flags. DF set = routers must not fragment it.",
          "children": [
           {
            "name": "ip.flags.rb",
            "text": "0... .... = Reserved bit: Not set",
            "pos": 20,
            "size": 1
           },
           {
            "name": "ip.flags.df",
            "text": ".1.. .... = Don't fragment: Set",
            "pos": 20,
            "size": 1,
            "note": "Don't Fragment. If the packet is too big for a link it is dropped and an ICMP 'fragmentation needed' comes back."
           },
           {
            "name": "ip.flags.mf",
            "text": "..0. .... = More fragments: Not set",
            "pos": 20,
            "size": 1
           }
          ]
         },
         {
          "name": "ip.frag_offset",
          "text": "...0 0000 0000 0000 = Fragment Offset: 0",
          "pos": 20,
          "size": 2,
          "note": "Where this fragment sits in the original packet. 0 = not fragmented (or first piece)."
         },
         {
          "name": "ip.ttl",
          "text": "Time to Live: 1",
          "pos": 22,
          "size": 1,
          "note": "Time to live. Each router subtracts one; at 0 the packet dies and ICMP time-exceeded goes back. eBGP peers default to TTL 1 (directly connected) unless ebgp-multihop or ttl-security is set."
         },
         {
          "name": "ip.proto",
          "text": "Protocol: TCP (6)",
          "pos": 23,
          "size": 1,
          "note": "What the payload is: 1 ICMP, 6 TCP, 17 UDP, 50 ESP, 89 OSPF, 88 EIGRP."
         },
         {
          "name": "ip.checksum",
          "text": "Header Checksum: 0x4ab4 [validation disabled]",
          "pos": 24,
          "size": 2,
          "note": "Header checksum, recomputed by every router because TTL changes."
         },
         {
          "name": "ip.src",
          "text": "Source Address: 100.100.255.1",
          "pos": 26,
          "size": 4,
          "note": "Original sender."
         },
         {
          "name": "ip.dst",
          "text": "Destination Address: 100.100.255.2",
          "pos": 30,
          "size": 4,
          "note": "Final destination."
         }
        ]
       },
       {
        "proto": "tcp",
        "title": "Transmission Control Protocol, Src Port: 179, Dst Port: 20305, Seq: 1, Ack: 1, Len: 19",
        "pos": 34,
        "size": 20,
        "note": "Transport. BGP rides TCP port 179, so every BGP message is acknowledged, ordered and resent by TCP, not by BGP.",
        "fields": [
         {
          "name": "tcp.len",
          "text": "TCP Segment Len: 19",
          "pos": 34,
          "size": 0,
          "note": "Payload bytes in this segment. 0 = a pure ACK or control segment."
         },
         {
          "name": "tcp.seq",
          "text": "Sequence Number: 1    (relative sequence number)",
          "pos": 38,
          "size": 4,
          "note": "Sequence number (relative): byte position of this segment's first data byte."
         },
         {
          "name": "tcp.ack",
          "text": "Acknowledgment Number: 1    (relative ack number)",
          "pos": 42,
          "size": 4,
          "note": "Acknowledgement: the next byte this side expects from the other."
         },
         {
          "name": "tcp.hdr_len",
          "text": "0101 .... = Header Length: 20 bytes (5)",
          "pos": 46,
          "size": 1,
          "note": "TCP header length. 20 = no options; 32 = timestamps; larger on a SYN with MSS / window scale / SACK."
         },
         {
          "name": "tcp.flags",
          "text": "Flags: 0x018 (PSH, ACK)",
          "pos": 46,
          "size": 2,
          "note": "Control bits. SYN opens, FIN closes cleanly, RST aborts, ACK acknowledges, PSH says deliver now.",
          "children": [
           {
            "name": "tcp.flags.res",
            "text": "000. .... .... = Reserved: Not set",
            "pos": 46,
            "size": 1
           },
           {
            "name": "tcp.flags.ae",
            "text": "...0 .... .... = Accurate ECN: Not set",
            "pos": 46,
            "size": 1
           },
           {
            "name": "tcp.flags.cwr",
            "text": ".... 0... .... = Congestion Window Reduced: Not set",
            "pos": 47,
            "size": 1
           },
           {
            "name": "tcp.flags.ece",
            "text": ".... .0.. .... = ECN-Echo: Not set",
            "pos": 47,
            "size": 1
           },
           {
            "name": "tcp.flags.urg",
            "text": ".... ..0. .... = Urgent: Not set",
            "pos": 47,
            "size": 1
           },
           {
            "name": "tcp.flags.ack",
            "text": ".... ...1 .... = Acknowledgment: Set",
            "pos": 47,
            "size": 1,
            "note": "ACK: the acknowledgement number is valid."
           },
           {
            "name": "tcp.flags.push",
            "text": ".... .... 1... = Push: Set",
            "pos": 47,
            "size": 1,
            "note": "PSH: hand the data to the application now."
           },
           {
            "name": "tcp.flags.reset",
            "text": ".... .... .0.. = Reset: Not set",
            "pos": 47,
            "size": 1,
            "note": "RST: refuse or abort. A RST answering a SYN means nothing is listening on that port, or the application refuses this peer (a shut-down BGP neighbor does exactly this)."
           },
           {
            "name": "tcp.flags.syn",
            "text": ".... .... ..0. = Syn: Not set",
            "pos": 47,
            "size": 1,
            "note": "SYN: open a connection."
           },
           {
            "name": "tcp.flags.fin",
            "text": ".... .... ...0 = Fin: Not set",
            "pos": 47,
            "size": 1,
            "note": "FIN: this side has nothing more to send; a clean close."
           },
           {
            "name": "tcp.flags.str",
            "text": "TCP Flags: \u00b7\u00b7\u00b7\u00b7\u00b7\u00b7\u00b7AP\u00b7\u00b7\u00b7",
            "pos": 46,
            "size": 2
           }
          ]
         },
         {
          "name": "tcp.window_size_value",
          "text": "Window: 16004",
          "pos": 48,
          "size": 2,
          "note": "Receive window: how many bytes the sender can accept right now."
         },
         {
          "name": "tcp.window_size_scalefactor",
          "text": "Window size scaling factor: -1 (unknown)",
          "pos": 48,
          "size": 2
         },
         {
          "name": "tcp.checksum",
          "text": "Checksum: 0xe5d8 [unverified]",
          "pos": 50,
          "size": 2,
          "note": "Checksum over header + payload."
         },
         {
          "name": "tcp.urgent_pointer",
          "text": "Urgent Pointer: 0",
          "pos": 52,
          "size": 2,
          "note": "Unused by BGP."
         },
         {
          "name": "",
          "text": "Timestamps",
          "pos": 34,
          "size": 0
         }
        ]
       },
       {
        "proto": "bgp",
        "title": "Border Gateway Protocol - KEEPALIVE Message",
        "pos": 54,
        "size": 19,
        "note": "Border Gateway Protocol: routers in different (eBGP) or the same (iBGP) autonomous systems swap reachability. Every message starts with the same 19-byte header: 16-byte marker, 2-byte length, 1-byte type.",
        "fields": [
         {
          "name": "bgp.marker",
          "text": "Marker: ffffffffffffffffffffffffffffffff",
          "pos": 54,
          "size": 16,
          "note": "16 bytes of 0xff. Kept for compatibility (it once carried authentication); every BGP message has it."
         },
         {
          "name": "bgp.length",
          "text": "Length: 19",
          "pos": 70,
          "size": 2,
          "note": "Whole BGP message length in bytes, header included. Minimum 19 (a KEEPALIVE), maximum 4096 (65535 with extended messages)."
         },
         {
          "name": "bgp.type",
          "text": "Type: KEEPALIVE Message (4)",
          "pos": 72,
          "size": 1,
          "note": "KEEPALIVE: header only, 19 bytes, nothing else. 'I'm still here.' Sent every third of the hold time; if the hold timer runs out with nothing heard, the session drops."
         }
        ]
       }
      ],
      "focus": "bgp"
     },
     {
      "n": 4,
      "kind": "BGP KEEPALIVE",
      "t": 7.916,
      "clock": "11:11:56.594",
      "from": "ISPB-R1",
      "to": "HQ1-CORE-R2",
      "src": "100.200.255.1",
      "dst": "100.200.255.2",
      "frame": 4,
      "link": "HQ1-CORE-R2 Et0/2 <-> ISPB-R1 Et0/2",
      "len": 73,
      "summary": "Header only: marker, length 19, type 4. Nothing else in it. Its whole job is to reset the peer's hold timer.",
      "layers": [
       {
        "proto": "eth",
        "title": "Ethernet II, Src: aa:bb:cc:00:14:20, Dst: aa:bb:cc:00:19:20",
        "pos": 0,
        "size": 14,
        "note": "Layer 2 frame. Only matters on this one wire: the next hop rewrites both MAC addresses.",
        "fields": [
         {
          "name": "eth.dst",
          "text": "Destination: aa:bb:cc:00:19:20",
          "pos": 0,
          "size": 6,
          "note": "Who on this wire should take the frame."
         },
         {
          "name": "eth.src",
          "text": "Source: aa:bb:cc:00:14:20",
          "pos": 6,
          "size": 6,
          "note": "Which interface put it on the wire."
         },
         {
          "name": "eth.type",
          "text": "Type: IPv4 (0x0800)",
          "pos": 12,
          "size": 2,
          "note": "What comes next: 0x0800 IPv4, 0x86dd IPv6, 0x8100 VLAN tag, 0x0806 ARP."
         }
        ]
       },
       {
        "proto": "ip",
        "title": "Internet Protocol Version 4, Src: 100.200.255.1, Dst: 100.200.255.2",
        "pos": 14,
        "size": 20,
        "note": "Layer 3 header. Source and destination stay the same end to end (unless NAT rewrites them); TTL drops by one per router.",
        "fields": [
         {
          "name": "ip.version",
          "text": "0100 .... = Version: 4",
          "pos": 14,
          "size": 1,
          "note": "4 = IPv4."
         },
         {
          "name": "ip.hdr_len",
          "text": ".... 0101 = Header Length: 20 bytes (5)",
          "pos": 14,
          "size": 1,
          "note": "Header length. 20 bytes means no IP options."
         },
         {
          "name": "ip.dsfield",
          "text": "Differentiated Services Field: 0xc0 (DSCP: CS6, ECN: Not-ECT)",
          "pos": 15,
          "size": 1,
          "note": "DSCP + ECN. Routers mark control traffic like BGP CS6 (DSCP 48, byte 0xc0) so QoS keeps it alive under load.",
          "children": [
           {
            "name": "ip.dsfield.dscp",
            "text": "1100 00.. = Differentiated Services Codepoint: Class Selector 6 (48)",
            "pos": 15,
            "size": 1,
            "note": "DSCP class. 48 = CS6, the class for routing protocols."
           },
           {
            "name": "ip.dsfield.ecn",
            "text": ".... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0)",
            "pos": 15,
            "size": 1
           }
          ]
         },
         {
          "name": "ip.len",
          "text": "Total Length: 59",
          "pos": 16,
          "size": 2,
          "note": "Total IP packet length (header + payload)."
         },
         {
          "name": "ip.id",
          "text": "Identification: 0x2d6c (11628)",
          "pos": 18,
          "size": 2,
          "note": "Identification. Unique per packet from a sender; also how you match the same packet in two captures."
         },
         {
          "name": "ip.flags",
          "text": "010. .... = Flags: 0x2, Don't fragment",
          "pos": 20,
          "size": 1,
          "note": "Fragmentation flags. DF set = routers must not fragment it.",
          "children": [
           {
            "name": "ip.flags.rb",
            "text": "0... .... = Reserved bit: Not set",
            "pos": 20,
            "size": 1
           },
           {
            "name": "ip.flags.df",
            "text": ".1.. .... = Don't fragment: Set",
            "pos": 20,
            "size": 1,
            "note": "Don't Fragment. If the packet is too big for a link it is dropped and an ICMP 'fragmentation needed' comes back."
           },
           {
            "name": "ip.flags.mf",
            "text": "..0. .... = More fragments: Not set",
            "pos": 20,
            "size": 1
           }
          ]
         },
         {
          "name": "ip.frag_offset",
          "text": "...0 0000 0000 0000 = Fragment Offset: 0",
          "pos": 20,
          "size": 2,
          "note": "Where this fragment sits in the original packet. 0 = not fragmented (or first piece)."
         },
         {
          "name": "ip.ttl",
          "text": "Time to Live: 1",
          "pos": 22,
          "size": 1,
          "note": "Time to live. Each router subtracts one; at 0 the packet dies and ICMP time-exceeded goes back. eBGP peers default to TTL 1 (directly connected) unless ebgp-multihop or ttl-security is set."
         },
         {
          "name": "ip.proto",
          "text": "Protocol: TCP (6)",
          "pos": 23,
          "size": 1,
          "note": "What the payload is: 1 ICMP, 6 TCP, 17 UDP, 50 ESP, 89 OSPF, 88 EIGRP."
         },
         {
          "name": "ip.checksum",
          "text": "Header Checksum: 0x83fc [validation disabled]",
          "pos": 24,
          "size": 2,
          "note": "Header checksum, recomputed by every router because TTL changes."
         },
         {
          "name": "ip.src",
          "text": "Source Address: 100.200.255.1",
          "pos": 26,
          "size": 4,
          "note": "Original sender."
         },
         {
          "name": "ip.dst",
          "text": "Destination Address: 100.200.255.2",
          "pos": 30,
          "size": 4,
          "note": "Final destination."
         }
        ]
       },
       {
        "proto": "tcp",
        "title": "Transmission Control Protocol, Src Port: 179, Dst Port: 20076, Seq: 1, Ack: 1, Len: 19",
        "pos": 34,
        "size": 20,
        "note": "Transport. BGP rides TCP port 179, so every BGP message is acknowledged, ordered and resent by TCP, not by BGP.",
        "fields": [
         {
          "name": "tcp.len",
          "text": "TCP Segment Len: 19",
          "pos": 34,
          "size": 0,
          "note": "Payload bytes in this segment. 0 = a pure ACK or control segment."
         },
         {
          "name": "tcp.seq",
          "text": "Sequence Number: 1    (relative sequence number)",
          "pos": 38,
          "size": 4,
          "note": "Sequence number (relative): byte position of this segment's first data byte."
         },
         {
          "name": "tcp.ack",
          "text": "Acknowledgment Number: 1    (relative ack number)",
          "pos": 42,
          "size": 4,
          "note": "Acknowledgement: the next byte this side expects from the other."
         },
         {
          "name": "tcp.hdr_len",
          "text": "0101 .... = Header Length: 20 bytes (5)",
          "pos": 46,
          "size": 1,
          "note": "TCP header length. 20 = no options; 32 = timestamps; larger on a SYN with MSS / window scale / SACK."
         },
         {
          "name": "tcp.flags",
          "text": "Flags: 0x018 (PSH, ACK)",
          "pos": 46,
          "size": 2,
          "note": "Control bits. SYN opens, FIN closes cleanly, RST aborts, ACK acknowledges, PSH says deliver now.",
          "children": [
           {
            "name": "tcp.flags.res",
            "text": "000. .... .... = Reserved: Not set",
            "pos": 46,
            "size": 1
           },
           {
            "name": "tcp.flags.ae",
            "text": "...0 .... .... = Accurate ECN: Not set",
            "pos": 46,
            "size": 1
           },
           {
            "name": "tcp.flags.cwr",
            "text": ".... 0... .... = Congestion Window Reduced: Not set",
            "pos": 47,
            "size": 1
           },
           {
            "name": "tcp.flags.ece",
            "text": ".... .0.. .... = ECN-Echo: Not set",
            "pos": 47,
            "size": 1
           },
           {
            "name": "tcp.flags.urg",
            "text": ".... ..0. .... = Urgent: Not set",
            "pos": 47,
            "size": 1
           },
           {
            "name": "tcp.flags.ack",
            "text": ".... ...1 .... = Acknowledgment: Set",
            "pos": 47,
            "size": 1,
            "note": "ACK: the acknowledgement number is valid."
           },
           {
            "name": "tcp.flags.push",
            "text": ".... .... 1... = Push: Set",
            "pos": 47,
            "size": 1,
            "note": "PSH: hand the data to the application now."
           },
           {
            "name": "tcp.flags.reset",
            "text": ".... .... .0.. = Reset: Not set",
            "pos": 47,
            "size": 1,
            "note": "RST: refuse or abort. A RST answering a SYN means nothing is listening on that port, or the application refuses this peer (a shut-down BGP neighbor does exactly this)."
           },
           {
            "name": "tcp.flags.syn",
            "text": ".... .... ..0. = Syn: Not set",
            "pos": 47,
            "size": 1,
            "note": "SYN: open a connection."
           },
           {
            "name": "tcp.flags.fin",
            "text": ".... .... ...0 = Fin: Not set",
            "pos": 47,
            "size": 1,
            "note": "FIN: this side has nothing more to send; a clean close."
           },
           {
            "name": "tcp.flags.str",
            "text": "TCP Flags: \u00b7\u00b7\u00b7\u00b7\u00b7\u00b7\u00b7AP\u00b7\u00b7\u00b7",
            "pos": 46,
            "size": 2
           }
          ]
         },
         {
          "name": "tcp.window_size_value",
          "text": "Window: 15586",
          "pos": 48,
          "size": 2,
          "note": "Receive window: how many bytes the sender can accept right now."
         },
         {
          "name": "tcp.window_size_scalefactor",
          "text": "Window size scaling factor: -1 (unknown)",
          "pos": 48,
          "size": 2
         },
         {
          "name": "tcp.checksum",
          "text": "Checksum: 0x0541 [unverified]",
          "pos": 50,
          "size": 2,
          "note": "Checksum over header + payload."
         },
         {
          "name": "tcp.urgent_pointer",
          "text": "Urgent Pointer: 0",
          "pos": 52,
          "size": 2,
          "note": "Unused by BGP."
         },
         {
          "name": "",
          "text": "Timestamps",
          "pos": 34,
          "size": 0
         }
        ]
       },
       {
        "proto": "bgp",
        "title": "Border Gateway Protocol - KEEPALIVE Message",
        "pos": 54,
        "size": 19,
        "note": "Border Gateway Protocol: routers in different (eBGP) or the same (iBGP) autonomous systems swap reachability. Every message starts with the same 19-byte header: 16-byte marker, 2-byte length, 1-byte type.",
        "fields": [
         {
          "name": "bgp.marker",
          "text": "Marker: ffffffffffffffffffffffffffffffff",
          "pos": 54,
          "size": 16,
          "note": "16 bytes of 0xff. Kept for compatibility (it once carried authentication); every BGP message has it."
         },
         {
          "name": "bgp.length",
          "text": "Length: 19",
          "pos": 70,
          "size": 2,
          "note": "Whole BGP message length in bytes, header included. Minimum 19 (a KEEPALIVE), maximum 4096 (65535 with extended messages)."
         },
         {
          "name": "bgp.type",
          "text": "Type: KEEPALIVE Message (4)",
          "pos": 72,
          "size": 1,
          "note": "KEEPALIVE: header only, 19 bytes, nothing else. 'I'm still here.' Sent every third of the hold time; if the hold timer runs out with nothing heard, the session drops."
         }
        ]
       }
      ],
      "focus": "bgp"
     },
     {
      "n": 5,
      "kind": "BGP KEEPALIVE",
      "t": 10.33,
      "clock": "11:11:59.008",
      "from": "HQ1-CORE-R1",
      "to": "ISPA-R1",
      "src": "100.100.255.2",
      "dst": "100.100.255.1",
      "frame": 12,
      "link": "HQ1-CORE-R1 Et0/2 <-> ISPA-R1 Et0/2",
      "len": 73,
      "summary": "Header only: marker, length 19, type 4. Nothing else in it. Its whole job is to reset the peer's hold timer.",
      "layers": [
       {
        "proto": "eth",
        "title": "Ethernet II, Src: aa:bb:cc:00:18:20, Dst: aa:bb:cc:00:12:20",
        "pos": 0,
        "size": 14,
        "note": "Layer 2 frame. Only matters on this one wire: the next hop rewrites both MAC addresses.",
        "fields": [
         {
          "name": "eth.dst",
          "text": "Destination: aa:bb:cc:00:12:20",
          "pos": 0,
          "size": 6,
          "note": "Who on this wire should take the frame."
         },
         {
          "name": "eth.src",
          "text": "Source: aa:bb:cc:00:18:20",
          "pos": 6,
          "size": 6,
          "note": "Which interface put it on the wire."
         },
         {
          "name": "eth.type",
          "text": "Type: IPv4 (0x0800)",
          "pos": 12,
          "size": 2,
          "note": "What comes next: 0x0800 IPv4, 0x86dd IPv6, 0x8100 VLAN tag, 0x0806 ARP."
         }
        ]
       },
       {
        "proto": "ip",
        "title": "Internet Protocol Version 4, Src: 100.100.255.2, Dst: 100.100.255.1",
        "pos": 14,
        "size": 20,
        "note": "Layer 3 header. Source and destination stay the same end to end (unless NAT rewrites them); TTL drops by one per router.",
        "fields": [
         {
          "name": "ip.version",
          "text": "0100 .... = Version: 4",
          "pos": 14,
          "size": 1,
          "note": "4 = IPv4."
         },
         {
          "name": "ip.hdr_len",
          "text": ".... 0101 = Header Length: 20 bytes (5)",
          "pos": 14,
          "size": 1,
          "note": "Header length. 20 bytes means no IP options."
         },
         {
          "name": "ip.dsfield",
          "text": "Differentiated Services Field: 0xc0 (DSCP: CS6, ECN: Not-ECT)",
          "pos": 15,
          "size": 1,
          "note": "DSCP + ECN. Routers mark control traffic like BGP CS6 (DSCP 48, byte 0xc0) so QoS keeps it alive under load.",
          "children": [
           {
            "name": "ip.dsfield.dscp",
            "text": "1100 00.. = Differentiated Services Codepoint: Class Selector 6 (48)",
            "pos": 15,
            "size": 1,
            "note": "DSCP class. 48 = CS6, the class for routing protocols."
           },
           {
            "name": "ip.dsfield.ecn",
            "text": ".... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0)",
            "pos": 15,
            "size": 1
           }
          ]
         },
         {
          "name": "ip.len",
          "text": "Total Length: 59",
          "pos": 16,
          "size": 2,
          "note": "Total IP packet length (header + payload)."
         },
         {
          "name": "ip.id",
          "text": "Identification: 0x78e8 (30952)",
          "pos": 18,
          "size": 2,
          "note": "Identification. Unique per packet from a sender; also how you match the same packet in two captures."
         },
         {
          "name": "ip.flags",
          "text": "010. .... = Flags: 0x2, Don't fragment",
          "pos": 20,
          "size": 1,
          "note": "Fragmentation flags. DF set = routers must not fragment it.",
          "children": [
           {
            "name": "ip.flags.rb",
            "text": "0... .... = Reserved bit: Not set",
            "pos": 20,
            "size": 1
           },
           {
            "name": "ip.flags.df",
            "text": ".1.. .... = Don't fragment: Set",
            "pos": 20,
            "size": 1,
            "note": "Don't Fragment. If the packet is too big for a link it is dropped and an ICMP 'fragmentation needed' comes back."
           },
           {
            "name": "ip.flags.mf",
            "text": "..0. .... = More fragments: Not set",
            "pos": 20,
            "size": 1
           }
          ]
         },
         {
          "name": "ip.frag_offset",
          "text": "...0 0000 0000 0000 = Fragment Offset: 0",
          "pos": 20,
          "size": 2,
          "note": "Where this fragment sits in the original packet. 0 = not fragmented (or first piece)."
         },
         {
          "name": "ip.ttl",
          "text": "Time to Live: 1",
          "pos": 22,
          "size": 1,
          "note": "Time to live. Each router subtracts one; at 0 the packet dies and ICMP time-exceeded goes back. eBGP peers default to TTL 1 (directly connected) unless ebgp-multihop or ttl-security is set."
         },
         {
          "name": "ip.proto",
          "text": "Protocol: TCP (6)",
          "pos": 23,
          "size": 1,
          "note": "What the payload is: 1 ICMP, 6 TCP, 17 UDP, 50 ESP, 89 OSPF, 88 EIGRP."
         },
         {
          "name": "ip.checksum",
          "text": "Header Checksum: 0x3948 [validation disabled]",
          "pos": 24,
          "size": 2,
          "note": "Header checksum, recomputed by every router because TTL changes."
         },
         {
          "name": "ip.src",
          "text": "Source Address: 100.100.255.2",
          "pos": 26,
          "size": 4,
          "note": "Original sender."
         },
         {
          "name": "ip.dst",
          "text": "Destination Address: 100.100.255.1",
          "pos": 30,
          "size": 4,
          "note": "Final destination."
         }
        ]
       },
       {
        "proto": "tcp",
        "title": "Transmission Control Protocol, Src Port: 20305, Dst Port: 179, Seq: 1, Ack: 20, Len: 19",
        "pos": 34,
        "size": 20,
        "note": "Transport. BGP rides TCP port 179, so every BGP message is acknowledged, ordered and resent by TCP, not by BGP.",
        "fields": [
         {
          "name": "tcp.len",
          "text": "TCP Segment Len: 19",
          "pos": 34,
          "size": 0,
          "note": "Payload bytes in this segment. 0 = a pure ACK or control segment."
         },
         {
          "name": "tcp.seq",
          "text": "Sequence Number: 1    (relative sequence number)",
          "pos": 38,
          "size": 4,
          "note": "Sequence number (relative): byte position of this segment's first data byte."
         },
         {
          "name": "tcp.ack",
          "text": "Acknowledgment Number: 20    (relative ack number)",
          "pos": 42,
          "size": 4,
          "note": "Acknowledgement: the next byte this side expects from the other."
         },
         {
          "name": "tcp.hdr_len",
          "text": "0101 .... = Header Length: 20 bytes (5)",
          "pos": 46,
          "size": 1,
          "note": "TCP header length. 20 = no options; 32 = timestamps; larger on a SYN with MSS / window scale / SACK."
         },
         {
          "name": "tcp.flags",
          "text": "Flags: 0x018 (PSH, ACK)",
          "pos": 46,
          "size": 2,
          "note": "Control bits. SYN opens, FIN closes cleanly, RST aborts, ACK acknowledges, PSH says deliver now.",
          "children": [
           {
            "name": "tcp.flags.res",
            "text": "000. .... .... = Reserved: Not set",
            "pos": 46,
            "size": 1
           },
           {
            "name": "tcp.flags.ae",
            "text": "...0 .... .... = Accurate ECN: Not set",
            "pos": 46,
            "size": 1
           },
           {
            "name": "tcp.flags.cwr",
            "text": ".... 0... .... = Congestion Window Reduced: Not set",
            "pos": 47,
            "size": 1
           },
           {
            "name": "tcp.flags.ece",
            "text": ".... .0.. .... = ECN-Echo: Not set",
            "pos": 47,
            "size": 1
           },
           {
            "name": "tcp.flags.urg",
            "text": ".... ..0. .... = Urgent: Not set",
            "pos": 47,
            "size": 1
           },
           {
            "name": "tcp.flags.ack",
            "text": ".... ...1 .... = Acknowledgment: Set",
            "pos": 47,
            "size": 1,
            "note": "ACK: the acknowledgement number is valid."
           },
           {
            "name": "tcp.flags.push",
            "text": ".... .... 1... = Push: Set",
            "pos": 47,
            "size": 1,
            "note": "PSH: hand the data to the application now."
           },
           {
            "name": "tcp.flags.reset",
            "text": ".... .... .0.. = Reset: Not set",
            "pos": 47,
            "size": 1,
            "note": "RST: refuse or abort. A RST answering a SYN means nothing is listening on that port, or the application refuses this peer (a shut-down BGP neighbor does exactly this)."
           },
           {
            "name": "tcp.flags.syn",
            "text": ".... .... ..0. = Syn: Not set",
            "pos": 47,
            "size": 1,
            "note": "SYN: open a connection."
           },
           {
            "name": "tcp.flags.fin",
            "text": ".... .... ...0 = Fin: Not set",
            "pos": 47,
            "size": 1,
            "note": "FIN: this side has nothing more to send; a clean close."
           },
           {
            "name": "tcp.flags.str",
            "text": "TCP Flags: \u00b7\u00b7\u00b7\u00b7\u00b7\u00b7\u00b7AP\u00b7\u00b7\u00b7",
            "pos": 46,
            "size": 2
           }
          ]
         },
         {
          "name": "tcp.window_size_value",
          "text": "Window: 15320",
          "pos": 48,
          "size": 2,
          "note": "Receive window: how many bytes the sender can accept right now."
         },
         {
          "name": "tcp.window_size_scalefactor",
          "text": "Window size scaling factor: -1 (unknown)",
          "pos": 48,
          "size": 2
         },
         {
          "name": "tcp.checksum",
          "text": "Checksum: 0xe871 [unverified]",
          "pos": 50,
          "size": 2,
          "note": "Checksum over header + payload."
         },
         {
          "name": "tcp.urgent_pointer",
          "text": "Urgent Pointer: 0",
          "pos": 52,
          "size": 2,
          "note": "Unused by BGP."
         },
         {
          "name": "",
          "text": "Timestamps",
          "pos": 34,
          "size": 0
         }
        ]
       },
       {
        "proto": "bgp",
        "title": "Border Gateway Protocol - KEEPALIVE Message",
        "pos": 54,
        "size": 19,
        "note": "Border Gateway Protocol: routers in different (eBGP) or the same (iBGP) autonomous systems swap reachability. Every message starts with the same 19-byte header: 16-byte marker, 2-byte length, 1-byte type.",
        "fields": [
         {
          "name": "bgp.marker",
          "text": "Marker: ffffffffffffffffffffffffffffffff",
          "pos": 54,
          "size": 16,
          "note": "16 bytes of 0xff. Kept for compatibility (it once carried authentication); every BGP message has it."
         },
         {
          "name": "bgp.length",
          "text": "Length: 19",
          "pos": 70,
          "size": 2,
          "note": "Whole BGP message length in bytes, header included. Minimum 19 (a KEEPALIVE), maximum 4096 (65535 with extended messages)."
         },
         {
          "name": "bgp.type",
          "text": "Type: KEEPALIVE Message (4)",
          "pos": 72,
          "size": 1,
          "note": "KEEPALIVE: header only, 19 bytes, nothing else. 'I'm still here.' Sent every third of the hold time; if the hold timer runs out with nothing heard, the session drops."
         }
        ]
       }
      ],
      "focus": "bgp"
     },
     {
      "n": 6,
      "kind": "ICMP unreachable, admin prohibited",
      "t": 10.593,
      "clock": "11:11:59.271",
      "from": "ISPA-R1",
      "to": "HQ1-CORE-R1",
      "src": "100.100.255.1",
      "dst": "100.100.255.2",
      "frame": 15,
      "link": "HQ1-CORE-R1 Et0/2 <-> ISPA-R1 Et0/2",
      "len": 70,
      "summary": "A router on the path refusing the probe, with the original packet's header quoted inside.",
      "layers": [
       {
        "proto": "eth",
        "title": "Ethernet II, Src: aa:bb:cc:00:12:20, Dst: aa:bb:cc:00:18:20",
        "pos": 0,
        "size": 14,
        "note": "Layer 2 frame. Only matters on this one wire: the next hop rewrites both MAC addresses.",
        "fields": [
         {
          "name": "eth.dst",
          "text": "Destination: aa:bb:cc:00:18:20",
          "pos": 0,
          "size": 6,
          "note": "Who on this wire should take the frame."
         },
         {
          "name": "eth.src",
          "text": "Source: aa:bb:cc:00:12:20",
          "pos": 6,
          "size": 6,
          "note": "Which interface put it on the wire."
         },
         {
          "name": "eth.type",
          "text": "Type: IPv4 (0x0800)",
          "pos": 12,
          "size": 2,
          "note": "What comes next: 0x0800 IPv4, 0x86dd IPv6, 0x8100 VLAN tag, 0x0806 ARP."
         }
        ]
       },
       {
        "proto": "ip",
        "title": "Internet Protocol Version 4, Src: 100.100.255.1, Dst: 100.100.255.2",
        "pos": 14,
        "size": 20,
        "note": "Layer 3 header. Source and destination stay the same end to end (unless NAT rewrites them); TTL drops by one per router.",
        "fields": [
         {
          "name": "ip.version",
          "text": "0100 .... = Version: 4",
          "pos": 14,
          "size": 1,
          "note": "4 = IPv4."
         },
         {
          "name": "ip.hdr_len",
          "text": ".... 0101 = Header Length: 20 bytes (5)",
          "pos": 14,
          "size": 1,
          "note": "Header length. 20 bytes means no IP options."
         },
         {
          "name": "ip.dsfield",
          "text": "Differentiated Services Field: 0x00 (DSCP: CS0, ECN: Not-ECT)",
          "pos": 15,
          "size": 1,
          "note": "DSCP + ECN. Routers mark control traffic like BGP CS6 (DSCP 48, byte 0xc0) so QoS keeps it alive under load.",
          "children": [
           {
            "name": "ip.dsfield.dscp",
            "text": "0000 00.. = Differentiated Services Codepoint: Default (0)",
            "pos": 15,
            "size": 1,
            "note": "DSCP class. 48 = CS6, the class for routing protocols."
           },
           {
            "name": "ip.dsfield.ecn",
            "text": ".... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0)",
            "pos": 15,
            "size": 1
           }
          ]
         },
         {
          "name": "ip.len",
          "text": "Total Length: 56",
          "pos": 16,
          "size": 2,
          "note": "Total IP packet length (header + payload)."
         },
         {
          "name": "ip.id",
          "text": "Identification: 0x47e8 (18408)",
          "pos": 18,
          "size": 2,
          "note": "Identification. Unique per packet from a sender; also how you match the same packet in two captures."
         },
         {
          "name": "ip.flags",
          "text": "000. .... = Flags: 0x0",
          "pos": 20,
          "size": 1,
          "note": "Fragmentation flags. DF set = routers must not fragment it.",
          "children": [
           {
            "name": "ip.flags.rb",
            "text": "0... .... = Reserved bit: Not set",
            "pos": 20,
            "size": 1
           },
           {
            "name": "ip.flags.df",
            "text": ".0.. .... = Don't fragment: Not set",
            "pos": 20,
            "size": 1,
            "note": "Don't Fragment. If the packet is too big for a link it is dropped and an ICMP 'fragmentation needed' comes back."
           },
           {
            "name": "ip.flags.mf",
            "text": "..0. .... = More fragments: Not set",
            "pos": 20,
            "size": 1
           }
          ]
         },
         {
          "name": "ip.frag_offset",
          "text": "...0 0000 0000 0000 = Fragment Offset: 0",
          "pos": 20,
          "size": 2,
          "note": "Where this fragment sits in the original packet. 0 = not fragmented (or first piece)."
         },
         {
          "name": "ip.ttl",
          "text": "Time to Live: 255",
          "pos": 22,
          "size": 1,
          "note": "Time to live. Each router subtracts one; at 0 the packet dies and ICMP time-exceeded goes back. eBGP peers default to TTL 1 (directly connected) unless ebgp-multihop or ttl-security is set."
         },
         {
          "name": "ip.proto",
          "text": "Protocol: ICMP (1)",
          "pos": 23,
          "size": 1,
          "note": "What the payload is: 1 ICMP, 6 TCP, 17 UDP, 50 ESP, 89 OSPF, 88 EIGRP."
         },
         {
          "name": "ip.checksum",
          "text": "Header Checksum: 0xad0f [validation disabled]",
          "pos": 24,
          "size": 2,
          "note": "Header checksum, recomputed by every router because TTL changes."
         },
         {
          "name": "ip.src",
          "text": "Source Address: 100.100.255.1",
          "pos": 26,
          "size": 4,
          "note": "Original sender."
         },
         {
          "name": "ip.dst",
          "text": "Destination Address: 100.100.255.2",
          "pos": 30,
          "size": 4,
          "note": "Final destination."
         }
        ]
       },
       {
        "proto": "icmp",
        "title": "Internet Control Message Protocol",
        "pos": 34,
        "size": 36,
        "note": "Control messages for IP: ping (echo request / reply) and the error reports routers send back when they can't deliver.",
        "fields": [
         {
          "name": "icmp.type",
          "text": "Type: 3 (Destination unreachable)",
          "pos": 34,
          "size": 1,
          "note": "Destination unreachable: a router could not (or would not) deliver the packet. The original header rides inside."
         },
         {
          "name": "icmp.code",
          "text": "Code: 13 (Communication administratively filtered)",
          "pos": 35,
          "size": 1,
          "note": "Communication administratively prohibited: an ACL or firewall on the reporting router blocked it."
         },
         {
          "name": "icmp.checksum",
          "text": "Checksum: 0x3517 [correct]",
          "pos": 36,
          "size": 2,
          "note": "Checksum over the ICMP message."
         },
         {
          "name": "icmp.unused",
          "text": "Unused: 00000000",
          "pos": 38,
          "size": 4
         }
        ]
       }
      ],
      "focus": "icmp"
     },
     {
      "n": 7,
      "kind": "BGP NOTIFICATION",
      "t": 25.959,
      "clock": "11:12:14.637",
      "from": "HQ1-CORE-R1",
      "to": "ISPA-R1",
      "src": "100.100.255.2",
      "dst": "100.100.255.1",
      "frame": 23,
      "link": "HQ1-CORE-R1 Et0/2 <-> ISPA-R1 Et0/2",
      "len": 75,
      "summary": "The last BGP message of a session: an error code and subcode, then the sender closes TCP.",
      "layers": [
       {
        "proto": "eth",
        "title": "Ethernet II, Src: aa:bb:cc:00:18:20, Dst: aa:bb:cc:00:12:20",
        "pos": 0,
        "size": 14,
        "note": "Layer 2 frame. Only matters on this one wire: the next hop rewrites both MAC addresses.",
        "fields": [
         {
          "name": "eth.dst",
          "text": "Destination: aa:bb:cc:00:12:20",
          "pos": 0,
          "size": 6,
          "note": "Who on this wire should take the frame."
         },
         {
          "name": "eth.src",
          "text": "Source: aa:bb:cc:00:18:20",
          "pos": 6,
          "size": 6,
          "note": "Which interface put it on the wire."
         },
         {
          "name": "eth.type",
          "text": "Type: IPv4 (0x0800)",
          "pos": 12,
          "size": 2,
          "note": "What comes next: 0x0800 IPv4, 0x86dd IPv6, 0x8100 VLAN tag, 0x0806 ARP."
         }
        ]
       },
       {
        "proto": "ip",
        "title": "Internet Protocol Version 4, Src: 100.100.255.2, Dst: 100.100.255.1",
        "pos": 14,
        "size": 20,
        "note": "Layer 3 header. Source and destination stay the same end to end (unless NAT rewrites them); TTL drops by one per router.",
        "fields": [
         {
          "name": "ip.version",
          "text": "0100 .... = Version: 4",
          "pos": 14,
          "size": 1,
          "note": "4 = IPv4."
         },
         {
          "name": "ip.hdr_len",
          "text": ".... 0101 = Header Length: 20 bytes (5)",
          "pos": 14,
          "size": 1,
          "note": "Header length. 20 bytes means no IP options."
         },
         {
          "name": "ip.dsfield",
          "text": "Differentiated Services Field: 0xc0 (DSCP: CS6, ECN: Not-ECT)",
          "pos": 15,
          "size": 1,
          "note": "DSCP + ECN. Routers mark control traffic like BGP CS6 (DSCP 48, byte 0xc0) so QoS keeps it alive under load.",
          "children": [
           {
            "name": "ip.dsfield.dscp",
            "text": "1100 00.. = Differentiated Services Codepoint: Class Selector 6 (48)",
            "pos": 15,
            "size": 1,
            "note": "DSCP class. 48 = CS6, the class for routing protocols."
           },
           {
            "name": "ip.dsfield.ecn",
            "text": ".... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0)",
            "pos": 15,
            "size": 1
           }
          ]
         },
         {
          "name": "ip.len",
          "text": "Total Length: 61",
          "pos": 16,
          "size": 2,
          "note": "Total IP packet length (header + payload)."
         },
         {
          "name": "ip.id",
          "text": "Identification: 0x78e9 (30953)",
          "pos": 18,
          "size": 2,
          "note": "Identification. Unique per packet from a sender; also how you match the same packet in two captures."
         },
         {
          "name": "ip.flags",
          "text": "010. .... = Flags: 0x2, Don't fragment",
          "pos": 20,
          "size": 1,
          "note": "Fragmentation flags. DF set = routers must not fragment it.",
          "children": [
           {
            "name": "ip.flags.rb",
            "text": "0... .... = Reserved bit: Not set",
            "pos": 20,
            "size": 1
           },
           {
            "name": "ip.flags.df",
            "text": ".1.. .... = Don't fragment: Set",
            "pos": 20,
            "size": 1,
            "note": "Don't Fragment. If the packet is too big for a link it is dropped and an ICMP 'fragmentation needed' comes back."
           },
           {
            "name": "ip.flags.mf",
            "text": "..0. .... = More fragments: Not set",
            "pos": 20,
            "size": 1
           }
          ]
         },
         {
          "name": "ip.frag_offset",
          "text": "...0 0000 0000 0000 = Fragment Offset: 0",
          "pos": 20,
          "size": 2,
          "note": "Where this fragment sits in the original packet. 0 = not fragmented (or first piece)."
         },
         {
          "name": "ip.ttl",
          "text": "Time to Live: 1",
          "pos": 22,
          "size": 1,
          "note": "Time to live. Each router subtracts one; at 0 the packet dies and ICMP time-exceeded goes back. eBGP peers default to TTL 1 (directly connected) unless ebgp-multihop or ttl-security is set."
         },
         {
          "name": "ip.proto",
          "text": "Protocol: TCP (6)",
          "pos": 23,
          "size": 1,
          "note": "What the payload is: 1 ICMP, 6 TCP, 17 UDP, 50 ESP, 89 OSPF, 88 EIGRP."
         },
         {
          "name": "ip.checksum",
          "text": "Header Checksum: 0x3945 [validation disabled]",
          "pos": 24,
          "size": 2,
          "note": "Header checksum, recomputed by every router because TTL changes."
         },
         {
          "name": "ip.src",
          "text": "Source Address: 100.100.255.2",
          "pos": 26,
          "size": 4,
          "note": "Original sender."
         },
         {
          "name": "ip.dst",
          "text": "Destination Address: 100.100.255.1",
          "pos": 30,
          "size": 4,
          "note": "Final destination."
         }
        ]
       },
       {
        "proto": "tcp",
        "title": "Transmission Control Protocol, Src Port: 20305, Dst Port: 179, Seq: 20, Ack: 20, Len: 21",
        "pos": 34,
        "size": 20,
        "note": "Transport. BGP rides TCP port 179, so every BGP message is acknowledged, ordered and resent by TCP, not by BGP.",
        "fields": [
         {
          "name": "tcp.len",
          "text": "TCP Segment Len: 21",
          "pos": 34,
          "size": 0,
          "note": "Payload bytes in this segment. 0 = a pure ACK or control segment."
         },
         {
          "name": "tcp.seq",
          "text": "Sequence Number: 20    (relative sequence number)",
          "pos": 38,
          "size": 4,
          "note": "Sequence number (relative): byte position of this segment's first data byte."
         },
         {
          "name": "tcp.ack",
          "text": "Acknowledgment Number: 20    (relative ack number)",
          "pos": 42,
          "size": 4,
          "note": "Acknowledgement: the next byte this side expects from the other."
         },
         {
          "name": "tcp.hdr_len",
          "text": "0101 .... = Header Length: 20 bytes (5)",
          "pos": 46,
          "size": 1,
          "note": "TCP header length. 20 = no options; 32 = timestamps; larger on a SYN with MSS / window scale / SACK."
         },
         {
          "name": "tcp.flags",
          "text": "Flags: 0x018 (PSH, ACK)",
          "pos": 46,
          "size": 2,
          "note": "Control bits. SYN opens, FIN closes cleanly, RST aborts, ACK acknowledges, PSH says deliver now.",
          "children": [
           {
            "name": "tcp.flags.res",
            "text": "000. .... .... = Reserved: Not set",
            "pos": 46,
            "size": 1
           },
           {
            "name": "tcp.flags.ae",
            "text": "...0 .... .... = Accurate ECN: Not set",
            "pos": 46,
            "size": 1
           },
           {
            "name": "tcp.flags.cwr",
            "text": ".... 0... .... = Congestion Window Reduced: Not set",
            "pos": 47,
            "size": 1
           },
           {
            "name": "tcp.flags.ece",
            "text": ".... .0.. .... = ECN-Echo: Not set",
            "pos": 47,
            "size": 1
           },
           {
            "name": "tcp.flags.urg",
            "text": ".... ..0. .... = Urgent: Not set",
            "pos": 47,
            "size": 1
           },
           {
            "name": "tcp.flags.ack",
            "text": ".... ...1 .... = Acknowledgment: Set",
            "pos": 47,
            "size": 1,
            "note": "ACK: the acknowledgement number is valid."
           },
           {
            "name": "tcp.flags.push",
            "text": ".... .... 1... = Push: Set",
            "pos": 47,
            "size": 1,
            "note": "PSH: hand the data to the application now."
           },
           {
            "name": "tcp.flags.reset",
            "text": ".... .... .0.. = Reset: Not set",
            "pos": 47,
            "size": 1,
            "note": "RST: refuse or abort. A RST answering a SYN means nothing is listening on that port, or the application refuses this peer (a shut-down BGP neighbor does exactly this)."
           },
           {
            "name": "tcp.flags.syn",
            "text": ".... .... ..0. = Syn: Not set",
            "pos": 47,
            "size": 1,
            "note": "SYN: open a connection."
           },
           {
            "name": "tcp.flags.fin",
            "text": ".... .... ...0 = Fin: Not set",
            "pos": 47,
            "size": 1,
            "note": "FIN: this side has nothing more to send; a clean close."
           },
           {
            "name": "tcp.flags.str",
            "text": "TCP Flags: \u00b7\u00b7\u00b7\u00b7\u00b7\u00b7\u00b7AP\u00b7\u00b7\u00b7",
            "pos": 46,
            "size": 2
           }
          ]
         },
         {
          "name": "tcp.window_size_value",
          "text": "Window: 15320",
          "pos": 48,
          "size": 2,
          "note": "Receive window: how many bytes the sender can accept right now."
         },
         {
          "name": "tcp.window_size_scalefactor",
          "text": "Window size scaling factor: -1 (unknown)",
          "pos": 48,
          "size": 2
         },
         {
          "name": "tcp.checksum",
          "text": "Checksum: 0xe754 [unverified]",
          "pos": 50,
          "size": 2,
          "note": "Checksum over header + payload."
         },
         {
          "name": "tcp.urgent_pointer",
          "text": "Urgent Pointer: 0",
          "pos": 52,
          "size": 2,
          "note": "Unused by BGP."
         },
         {
          "name": "",
          "text": "Timestamps",
          "pos": 34,
          "size": 0
         }
        ]
       },
       {
        "proto": "bgp",
        "title": "Border Gateway Protocol - NOTIFICATION Message",
        "pos": 54,
        "size": 21,
        "note": "Border Gateway Protocol: routers in different (eBGP) or the same (iBGP) autonomous systems swap reachability. Every message starts with the same 19-byte header: 16-byte marker, 2-byte length, 1-byte type.",
        "fields": [
         {
          "name": "bgp.marker",
          "text": "Marker: ffffffffffffffffffffffffffffffff",
          "pos": 54,
          "size": 16,
          "note": "16 bytes of 0xff. Kept for compatibility (it once carried authentication); every BGP message has it."
         },
         {
          "name": "bgp.length",
          "text": "Length: 21",
          "pos": 70,
          "size": 2,
          "note": "Whole BGP message length in bytes, header included. Minimum 19 (a KEEPALIVE), maximum 4096 (65535 with extended messages)."
         },
         {
          "name": "bgp.type",
          "text": "Type: NOTIFICATION Message (3)",
          "pos": 72,
          "size": 1,
          "note": "NOTIFICATION: an error or a deliberate stop. The session is torn down right after it."
         },
         {
          "name": "bgp.notify.major_error",
          "text": "Major error Code: Cease (6)",
          "pos": 73,
          "size": 1,
          "note": "Cease: not an error in the protocol, someone or something chose to stop the session."
         },
         {
          "name": "bgp.notify.minor_error_cease",
          "text": "Minor error Code (Cease): Administratively Shutdown (2)",
          "pos": 74,
          "size": 1,
          "note": "Administrative shutdown: the sender's config says `neighbor ... shutdown` (by hand, or by a script/EEM)."
         }
        ]
       }
      ],
      "focus": "bgp"
     },
     {
      "n": 8,
      "kind": "BGP UPDATE",
      "t": 25.966,
      "clock": "11:12:14.643",
      "from": "ISPB-R1",
      "to": "HQ1-CORE-R2",
      "src": "100.200.255.1",
      "dst": "100.200.255.2",
      "frame": 14,
      "link": "HQ1-CORE-R2 Et0/2 <-> ISPB-R1 Et0/2",
      "len": 110,
      "summary": "Announces and/or withdraws prefixes. Withdrawn routes first, then the path attributes, then the prefixes (NLRI) that share them.",
      "layers": [
       {
        "proto": "eth",
        "title": "Ethernet II, Src: aa:bb:cc:00:14:20, Dst: aa:bb:cc:00:19:20",
        "pos": 0,
        "size": 14,
        "note": "Layer 2 frame. Only matters on this one wire: the next hop rewrites both MAC addresses.",
        "fields": [
         {
          "name": "eth.dst",
          "text": "Destination: aa:bb:cc:00:19:20",
          "pos": 0,
          "size": 6,
          "note": "Who on this wire should take the frame."
         },
         {
          "name": "eth.src",
          "text": "Source: aa:bb:cc:00:14:20",
          "pos": 6,
          "size": 6,
          "note": "Which interface put it on the wire."
         },
         {
          "name": "eth.type",
          "text": "Type: IPv4 (0x0800)",
          "pos": 12,
          "size": 2,
          "note": "What comes next: 0x0800 IPv4, 0x86dd IPv6, 0x8100 VLAN tag, 0x0806 ARP."
         }
        ]
       },
       {
        "proto": "ip",
        "title": "Internet Protocol Version 4, Src: 100.200.255.1, Dst: 100.200.255.2",
        "pos": 14,
        "size": 20,
        "note": "Layer 3 header. Source and destination stay the same end to end (unless NAT rewrites them); TTL drops by one per router.",
        "fields": [
         {
          "name": "ip.version",
          "text": "0100 .... = Version: 4",
          "pos": 14,
          "size": 1,
          "note": "4 = IPv4."
         },
         {
          "name": "ip.hdr_len",
          "text": ".... 0101 = Header Length: 20 bytes (5)",
          "pos": 14,
          "size": 1,
          "note": "Header length. 20 bytes means no IP options."
         },
         {
          "name": "ip.dsfield",
          "text": "Differentiated Services Field: 0xc0 (DSCP: CS6, ECN: Not-ECT)",
          "pos": 15,
          "size": 1,
          "note": "DSCP + ECN. Routers mark control traffic like BGP CS6 (DSCP 48, byte 0xc0) so QoS keeps it alive under load.",
          "children": [
           {
            "name": "ip.dsfield.dscp",
            "text": "1100 00.. = Differentiated Services Codepoint: Class Selector 6 (48)",
            "pos": 15,
            "size": 1,
            "note": "DSCP class. 48 = CS6, the class for routing protocols."
           },
           {
            "name": "ip.dsfield.ecn",
            "text": ".... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0)",
            "pos": 15,
            "size": 1
           }
          ]
         },
         {
          "name": "ip.len",
          "text": "Total Length: 96",
          "pos": 16,
          "size": 2,
          "note": "Total IP packet length (header + payload)."
         },
         {
          "name": "ip.id",
          "text": "Identification: 0x2d6e (11630)",
          "pos": 18,
          "size": 2,
          "note": "Identification. Unique per packet from a sender; also how you match the same packet in two captures."
         },
         {
          "name": "ip.flags",
          "text": "010. .... = Flags: 0x2, Don't fragment",
          "pos": 20,
          "size": 1,
          "note": "Fragmentation flags. DF set = routers must not fragment it.",
          "children": [
           {
            "name": "ip.flags.rb",
            "text": "0... .... = Reserved bit: Not set",
            "pos": 20,
            "size": 1
           },
           {
            "name": "ip.flags.df",
            "text": ".1.. .... = Don't fragment: Set",
            "pos": 20,
            "size": 1,
            "note": "Don't Fragment. If the packet is too big for a link it is dropped and an ICMP 'fragmentation needed' comes back."
           },
           {
            "name": "ip.flags.mf",
            "text": "..0. .... = More fragments: Not set",
            "pos": 20,
            "size": 1
           }
          ]
         },
         {
          "name": "ip.frag_offset",
          "text": "...0 0000 0000 0000 = Fragment Offset: 0",
          "pos": 20,
          "size": 2,
          "note": "Where this fragment sits in the original packet. 0 = not fragmented (or first piece)."
         },
         {
          "name": "ip.ttl",
          "text": "Time to Live: 1",
          "pos": 22,
          "size": 1,
          "note": "Time to live. Each router subtracts one; at 0 the packet dies and ICMP time-exceeded goes back. eBGP peers default to TTL 1 (directly connected) unless ebgp-multihop or ttl-security is set."
         },
         {
          "name": "ip.proto",
          "text": "Protocol: TCP (6)",
          "pos": 23,
          "size": 1,
          "note": "What the payload is: 1 ICMP, 6 TCP, 17 UDP, 50 ESP, 89 OSPF, 88 EIGRP."
         },
         {
          "name": "ip.checksum",
          "text": "Header Checksum: 0x83d5 [validation disabled]",
          "pos": 24,
          "size": 2,
          "note": "Header checksum, recomputed by every router because TTL changes."
         },
         {
          "name": "ip.src",
          "text": "Source Address: 100.200.255.1",
          "pos": 26,
          "size": 4,
          "note": "Original sender."
         },
         {
          "name": "ip.dst",
          "text": "Destination Address: 100.200.255.2",
          "pos": 30,
          "size": 4,
          "note": "Final destination."
         }
        ]
       },
       {
        "proto": "tcp",
        "title": "Transmission Control Protocol, Src Port: 179, Dst Port: 20076, Seq: 20, Ack: 20, Len: 56",
        "pos": 34,
        "size": 20,
        "note": "Transport. BGP rides TCP port 179, so every BGP message is acknowledged, ordered and resent by TCP, not by BGP.",
        "fields": [
         {
          "name": "tcp.len",
          "text": "TCP Segment Len: 56",
          "pos": 34,
          "size": 0,
          "note": "Payload bytes in this segment. 0 = a pure ACK or control segment."
         },
         {
          "name": "tcp.seq",
          "text": "Sequence Number: 20    (relative sequence number)",
          "pos": 38,
          "size": 4,
          "note": "Sequence number (relative): byte position of this segment's first data byte."
         },
         {
          "name": "tcp.ack",
          "text": "Acknowledgment Number: 20    (relative ack number)",
          "pos": 42,
          "size": 4,
          "note": "Acknowledgement: the next byte this side expects from the other."
         },
         {
          "name": "tcp.hdr_len",
          "text": "0101 .... = Header Length: 20 bytes (5)",
          "pos": 46,
          "size": 1,
          "note": "TCP header length. 20 = no options; 32 = timestamps; larger on a SYN with MSS / window scale / SACK."
         },
         {
          "name": "tcp.flags",
          "text": "Flags: 0x018 (PSH, ACK)",
          "pos": 46,
          "size": 2,
          "note": "Control bits. SYN opens, FIN closes cleanly, RST aborts, ACK acknowledges, PSH says deliver now.",
          "children": [
           {
            "name": "tcp.flags.res",
            "text": "000. .... .... = Reserved: Not set",
            "pos": 46,
            "size": 1
           },
           {
            "name": "tcp.flags.ae",
            "text": "...0 .... .... = Accurate ECN: Not set",
            "pos": 46,
            "size": 1
           },
           {
            "name": "tcp.flags.cwr",
            "text": ".... 0... .... = Congestion Window Reduced: Not set",
            "pos": 47,
            "size": 1
           },
           {
            "name": "tcp.flags.ece",
            "text": ".... .0.. .... = ECN-Echo: Not set",
            "pos": 47,
            "size": 1
           },
           {
            "name": "tcp.flags.urg",
            "text": ".... ..0. .... = Urgent: Not set",
            "pos": 47,
            "size": 1
           },
           {
            "name": "tcp.flags.ack",
            "text": ".... ...1 .... = Acknowledgment: Set",
            "pos": 47,
            "size": 1,
            "note": "ACK: the acknowledgement number is valid."
           },
           {
            "name": "tcp.flags.push",
            "text": ".... .... 1... = Push: Set",
            "pos": 47,
            "size": 1,
            "note": "PSH: hand the data to the application now."
           },
           {
            "name": "tcp.flags.reset",
            "text": ".... .... .0.. = Reset: Not set",
            "pos": 47,
            "size": 1,
            "note": "RST: refuse or abort. A RST answering a SYN means nothing is listening on that port, or the application refuses this peer (a shut-down BGP neighbor does exactly this)."
           },
           {
            "name": "tcp.flags.syn",
            "text": ".... .... ..0. = Syn: Not set",
            "pos": 47,
            "size": 1,
            "note": "SYN: open a connection."
           },
           {
            "name": "tcp.flags.fin",
            "text": ".... .... ...0 = Fin: Not set",
            "pos": 47,
            "size": 1,
            "note": "FIN: this side has nothing more to send; a clean close."
           },
           {
            "name": "tcp.flags.str",
            "text": "TCP Flags: \u00b7\u00b7\u00b7\u00b7\u00b7\u00b7\u00b7AP\u00b7\u00b7\u00b7",
            "pos": 46,
            "size": 2
           }
          ]
         },
         {
          "name": "tcp.window_size_value",
          "text": "Window: 15567",
          "pos": 48,
          "size": 2,
          "note": "Receive window: how many bytes the sender can accept right now."
         },
         {
          "name": "tcp.window_size_scalefactor",
          "text": "Window size scaling factor: -1 (unknown)",
          "pos": 48,
          "size": 2
         },
         {
          "name": "tcp.checksum",
          "text": "Checksum: 0xb1b5 [unverified]",
          "pos": 50,
          "size": 2,
          "note": "Checksum over header + payload."
         },
         {
          "name": "tcp.urgent_pointer",
          "text": "Urgent Pointer: 0",
          "pos": 52,
          "size": 2,
          "note": "Unused by BGP."
         },
         {
          "name": "",
          "text": "Timestamps",
          "pos": 34,
          "size": 0
         }
        ]
       },
       {
        "proto": "bgp",
        "title": "Border Gateway Protocol - UPDATE Message",
        "pos": 54,
        "size": 56,
        "note": "Border Gateway Protocol: routers in different (eBGP) or the same (iBGP) autonomous systems swap reachability. Every message starts with the same 19-byte header: 16-byte marker, 2-byte length, 1-byte type.",
        "fields": [
         {
          "name": "bgp.marker",
          "text": "Marker: ffffffffffffffffffffffffffffffff",
          "pos": 54,
          "size": 16,
          "note": "16 bytes of 0xff. Kept for compatibility (it once carried authentication); every BGP message has it."
         },
         {
          "name": "bgp.length",
          "text": "Length: 56",
          "pos": 70,
          "size": 2,
          "note": "Whole BGP message length in bytes, header included. Minimum 19 (a KEEPALIVE), maximum 4096 (65535 with extended messages)."
         },
         {
          "name": "bgp.type",
          "text": "Type: UPDATE Message (2)",
          "pos": 72,
          "size": 1,
          "note": "UPDATE: announces prefixes (with their path attributes) and/or withdraws prefixes."
         },
         {
          "name": "bgp.update.withdrawn_routes.length",
          "text": "Withdrawn Routes Length: 0",
          "pos": 73,
          "size": 2,
          "note": "Bytes of withdrawn prefixes that follow. 0 = this UPDATE withdraws nothing."
         },
         {
          "name": "bgp.update.path_attributes.length",
          "text": "Total Path Attribute Length: 28",
          "pos": 75,
          "size": 2,
          "note": "Bytes of path attributes. 0 = a pure withdraw."
         },
         {
          "name": "bgp.update.path_attributes",
          "text": "Path attributes",
          "pos": 77,
          "size": 28,
          "children": [
           {
            "name": "bgp.update.path_attribute",
            "text": "Path Attribute - ORIGIN: IGP",
            "pos": 77,
            "size": 4,
            "note": "ORIGIN attribute (well-known, mandatory).",
            "children": [
             {
              "name": "bgp.update.path_attribute.flags",
              "text": "Flags: 0x40, Transitive, Well-known, Complete",
              "pos": 77,
              "size": 1,
              "note": "Attribute flags: Optional (vs well-known), Transitive (pass it on), Partial, Extended length.",
              "children": [
               {
                "name": "bgp.update.path_attribute.flags.optional",
                "text": "0... .... = Optional: Not set",
                "pos": 77,
                "size": 1,
                "note": "Well-known attributes (ORIGIN, AS_PATH, NEXT_HOP, LOCAL_PREF) must be understood by every BGP router; optional ones (MED, communities) may not be."
               },
               {
                "name": "bgp.update.path_attribute.flags.transitive",
                "text": ".1.. .... = Transitive: Set",
                "pos": 77,
                "size": 1,
                "note": "Transitive: a router that doesn't understand an optional attribute still passes it on."
               },
               {
                "name": "bgp.update.path_attribute.flags.partial",
                "text": "..0. .... = Partial: Not set",
                "pos": 77,
                "size": 1
               },
               {
                "name": "bgp.update.path_attribute.flags.extended_length",
                "text": "...0 .... = Extended-Length: Not set",
                "pos": 77,
                "size": 1
               },
               {
                "name": "bgp.update.path_attribute.flags.unused",
                "text": ".... 0000 = Unused: 0x0",
                "pos": 77,
                "size": 1
               }
              ]
             },
             {
              "name": "bgp.update.path_attribute.type_code",
              "text": "Type Code: ORIGIN (1)",
              "pos": 78,
              "size": 1,
              "note": "Which attribute: 1 ORIGIN, 2 AS_PATH, 3 NEXT_HOP, 4 MED, 5 LOCAL_PREF, 8 COMMUNITIES."
             },
             {
              "name": "bgp.update.path_attribute.length",
              "text": "Length: 1",
              "pos": 79,
              "size": 1
             },
             {
              "name": "bgp.update.path_attribute.origin",
              "text": "Origin: IGP (0)",
              "pos": 80,
              "size": 1,
              "note": "How the route entered BGP: IGP (network statement), EGP, or Incomplete (redistributed). Best path prefers IGP < EGP < Incomplete."
             }
            ]
           },
           {
            "name": "bgp.update.path_attribute",
            "text": "Path Attribute - AS_PATH: 65200 65100 65001 ",
            "pos": 81,
            "size": 17,
            "note": "AS_PATH: every AS the route passed through. Shorter wins in best-path (after weight, local-pref, locally originated).",
            "children": [
             {
              "name": "bgp.update.path_attribute.flags",
              "text": "Flags: 0x40, Transitive, Well-known, Complete",
              "pos": 81,
              "size": 1,
              "note": "Attribute flags: Optional (vs well-known), Transitive (pass it on), Partial, Extended length.",
              "children": [
               {
                "name": "bgp.update.path_attribute.flags.optional",
                "text": "0... .... = Optional: Not set",
                "pos": 81,
                "size": 1,
                "note": "Well-known attributes (ORIGIN, AS_PATH, NEXT_HOP, LOCAL_PREF) must be understood by every BGP router; optional ones (MED, communities) may not be."
               },
               {
                "name": "bgp.update.path_attribute.flags.transitive",
                "text": ".1.. .... = Transitive: Set",
                "pos": 81,
                "size": 1,
                "note": "Transitive: a router that doesn't understand an optional attribute still passes it on."
               },
               {
                "name": "bgp.update.path_attribute.flags.partial",
                "text": "..0. .... = Partial: Not set",
                "pos": 81,
                "size": 1
               },
               {
                "name": "bgp.update.path_attribute.flags.extended_length",
                "text": "...0 .... = Extended-Length: Not set",
                "pos": 81,
                "size": 1
               },
               {
                "name": "bgp.update.path_attribute.flags.unused",
                "text": ".... 0000 = Unused: 0x0",
                "pos": 81,
                "size": 1
               }
              ]
             },
             {
              "name": "bgp.update.path_attribute.type_code",
              "text": "Type Code: AS_PATH (2)",
              "pos": 82,
              "size": 1,
              "note": "Which attribute: 1 ORIGIN, 2 AS_PATH, 3 NEXT_HOP, 4 MED, 5 LOCAL_PREF, 8 COMMUNITIES."
             },
             {
              "name": "bgp.update.path_attribute.length",
              "text": "Length: 14",
              "pos": 83,
              "size": 1
             },
             {
              "name": "bgp.update.path_attribute.as_path_segment",
              "text": "AS Path segment: 65200 65100 65001",
              "pos": 84,
              "size": 14,
              "children": [
               {
                "name": "bgp.update.path_attribute.as_path_segment.type",
                "text": "Segment type: AS_SEQUENCE (2)",
                "pos": 84,
                "size": 1,
                "note": "AS_SEQUENCE = ordered list of ASes the route crossed; AS_SET = an unordered set (from aggregation)."
               },
               {
                "name": "bgp.update.path_attribute.as_path_segment.length",
                "text": "Segment length (number of ASN): 3",
                "pos": 85,
                "size": 1,
                "note": "How many AS numbers follow."
               },
               {
                "name": "bgp.update.path_attribute.as_path_segment.as4",
                "text": "AS4: 65200",
                "pos": 86,
                "size": 4,
                "note": "One AS on the path, newest first: the leftmost AS is the neighbor that sent it, the rightmost is where the route started. A router that finds its own AS in the path drops the route (loop prevention)."
               },
               {
                "name": "bgp.update.path_attribute.as_path_segment.as4",
                "text": "AS4: 65100",
                "pos": 90,
                "size": 4,
                "note": "One AS on the path, newest first: the leftmost AS is the neighbor that sent it, the rightmost is where the route started. A router that finds its own AS in the path drops the route (loop prevention)."
               },
               {
                "name": "bgp.update.path_attribute.as_path_segment.as4",
                "text": "AS4: 65001",
                "pos": 94,
                "size": 4,
                "note": "One AS on the path, newest first: the leftmost AS is the neighbor that sent it, the rightmost is where the route started. A router that finds its own AS in the path drops the route (loop prevention)."
               }
              ]
             }
            ]
           },
           {
            "name": "bgp.update.path_attribute",
            "text": "Path Attribute - NEXT_HOP: 100.200.255.1 ",
            "pos": 98,
            "size": 7,
            "note": "NEXT_HOP attribute (well-known, mandatory).",
            "children": [
             {
              "name": "bgp.update.path_attribute.flags",
              "text": "Flags: 0x40, Transitive, Well-known, Complete",
              "pos": 98,
              "size": 1,
              "note": "Attribute flags: Optional (vs well-known), Transitive (pass it on), Partial, Extended length.",
              "children": [
               {
                "name": "bgp.update.path_attribute.flags.optional",
                "text": "0... .... = Optional: Not set",
                "pos": 98,
                "size": 1,
                "note": "Well-known attributes (ORIGIN, AS_PATH, NEXT_HOP, LOCAL_PREF) must be understood by every BGP router; optional ones (MED, communities) may not be."
               },
               {
                "name": "bgp.update.path_attribute.flags.transitive",
                "text": ".1.. .... = Transitive: Set",
                "pos": 98,
                "size": 1,
                "note": "Transitive: a router that doesn't understand an optional attribute still passes it on."
               },
               {
                "name": "bgp.update.path_attribute.flags.partial",
                "text": "..0. .... = Partial: Not set",
                "pos": 98,
                "size": 1
               },
               {
                "name": "bgp.update.path_attribute.flags.extended_length",
                "text": "...0 .... = Extended-Length: Not set",
                "pos": 98,
                "size": 1
               },
               {
                "name": "bgp.update.path_attribute.flags.unused",
                "text": ".... 0000 = Unused: 0x0",
                "pos": 98,
                "size": 1
               }
              ]
             },
             {
              "name": "bgp.update.path_attribute.type_code",
              "text": "Type Code: NEXT_HOP (3)",
              "pos": 99,
              "size": 1,
              "note": "Which attribute: 1 ORIGIN, 2 AS_PATH, 3 NEXT_HOP, 4 MED, 5 LOCAL_PREF, 8 COMMUNITIES."
             },
             {
              "name": "bgp.update.path_attribute.length",
              "text": "Length: 4",
              "pos": 100,
              "size": 1
             },
             {
              "name": "bgp.update.path_attribute.next_hop",
              "text": "Next hop: 100.200.255.1",
              "pos": 101,
              "size": 4,
              "note": "Where to send traffic for these prefixes. eBGP sets it to the sender's own address; iBGP passes it through unless next-hop-self."
             }
            ]
           }
          ]
         },
         {
          "name": "bgp.update.nlri",
          "text": "Network Layer Reachability Information (NLRI)",
          "pos": 105,
          "size": 5,
          "note": "NLRI: the prefixes this UPDATE announces, all sharing the attributes above.",
          "children": [
           {
            "name": "",
            "text": "198.51.100.0/25",
            "pos": 105,
            "size": 5,
            "children": [
             {
              "name": "bgp.prefix_length",
              "text": "NLRI prefix length: 25",
              "pos": 105,
              "size": 1,
              "note": "Prefix length in bits. Only as many address bytes as needed follow (a /25 needs 4)."
             },
             {
              "name": "bgp.nlri_prefix",
              "text": "NLRI prefix: 198.51.100.0",
              "pos": 106,
              "size": 4,
              "note": "The prefix being announced."
             }
            ]
           }
          ]
         }
        ]
       }
      ],
      "focus": "bgp"
     },
     {
      "n": 9,
      "kind": "BGP UPDATE",
      "t": 56.064,
      "clock": "11:12:44.741",
      "from": "ISPB-R1",
      "to": "HQ1-CORE-R2",
      "src": "100.200.255.1",
      "dst": "100.200.255.2",
      "frame": 21,
      "link": "HQ1-CORE-R2 Et0/2 <-> ISPB-R1 Et0/2",
      "len": 82,
      "summary": "Announces and/or withdraws prefixes. Withdrawn routes first, then the path attributes, then the prefixes (NLRI) that share them.",
      "layers": [
       {
        "proto": "eth",
        "title": "Ethernet II, Src: aa:bb:cc:00:14:20, Dst: aa:bb:cc:00:19:20",
        "pos": 0,
        "size": 14,
        "note": "Layer 2 frame. Only matters on this one wire: the next hop rewrites both MAC addresses.",
        "fields": [
         {
          "name": "eth.dst",
          "text": "Destination: aa:bb:cc:00:19:20",
          "pos": 0,
          "size": 6,
          "note": "Who on this wire should take the frame."
         },
         {
          "name": "eth.src",
          "text": "Source: aa:bb:cc:00:14:20",
          "pos": 6,
          "size": 6,
          "note": "Which interface put it on the wire."
         },
         {
          "name": "eth.type",
          "text": "Type: IPv4 (0x0800)",
          "pos": 12,
          "size": 2,
          "note": "What comes next: 0x0800 IPv4, 0x86dd IPv6, 0x8100 VLAN tag, 0x0806 ARP."
         }
        ]
       },
       {
        "proto": "ip",
        "title": "Internet Protocol Version 4, Src: 100.200.255.1, Dst: 100.200.255.2",
        "pos": 14,
        "size": 20,
        "note": "Layer 3 header. Source and destination stay the same end to end (unless NAT rewrites them); TTL drops by one per router.",
        "fields": [
         {
          "name": "ip.version",
          "text": "0100 .... = Version: 4",
          "pos": 14,
          "size": 1,
          "note": "4 = IPv4."
         },
         {
          "name": "ip.hdr_len",
          "text": ".... 0101 = Header Length: 20 bytes (5)",
          "pos": 14,
          "size": 1,
          "note": "Header length. 20 bytes means no IP options."
         },
         {
          "name": "ip.dsfield",
          "text": "Differentiated Services Field: 0xc0 (DSCP: CS6, ECN: Not-ECT)",
          "pos": 15,
          "size": 1,
          "note": "DSCP + ECN. Routers mark control traffic like BGP CS6 (DSCP 48, byte 0xc0) so QoS keeps it alive under load.",
          "children": [
           {
            "name": "ip.dsfield.dscp",
            "text": "1100 00.. = Differentiated Services Codepoint: Class Selector 6 (48)",
            "pos": 15,
            "size": 1,
            "note": "DSCP class. 48 = CS6, the class for routing protocols."
           },
           {
            "name": "ip.dsfield.ecn",
            "text": ".... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0)",
            "pos": 15,
            "size": 1
           }
          ]
         },
         {
          "name": "ip.len",
          "text": "Total Length: 68",
          "pos": 16,
          "size": 2,
          "note": "Total IP packet length (header + payload)."
         },
         {
          "name": "ip.id",
          "text": "Identification: 0x2d6f (11631)",
          "pos": 18,
          "size": 2,
          "note": "Identification. Unique per packet from a sender; also how you match the same packet in two captures."
         },
         {
          "name": "ip.flags",
          "text": "010. .... = Flags: 0x2, Don't fragment",
          "pos": 20,
          "size": 1,
          "note": "Fragmentation flags. DF set = routers must not fragment it.",
          "children": [
           {
            "name": "ip.flags.rb",
            "text": "0... .... = Reserved bit: Not set",
            "pos": 20,
            "size": 1
           },
           {
            "name": "ip.flags.df",
            "text": ".1.. .... = Don't fragment: Set",
            "pos": 20,
            "size": 1,
            "note": "Don't Fragment. If the packet is too big for a link it is dropped and an ICMP 'fragmentation needed' comes back."
           },
           {
            "name": "ip.flags.mf",
            "text": "..0. .... = More fragments: Not set",
            "pos": 20,
            "size": 1
           }
          ]
         },
         {
          "name": "ip.frag_offset",
          "text": "...0 0000 0000 0000 = Fragment Offset: 0",
          "pos": 20,
          "size": 2,
          "note": "Where this fragment sits in the original packet. 0 = not fragmented (or first piece)."
         },
         {
          "name": "ip.ttl",
          "text": "Time to Live: 1",
          "pos": 22,
          "size": 1,
          "note": "Time to live. Each router subtracts one; at 0 the packet dies and ICMP time-exceeded goes back. eBGP peers default to TTL 1 (directly connected) unless ebgp-multihop or ttl-security is set."
         },
         {
          "name": "ip.proto",
          "text": "Protocol: TCP (6)",
          "pos": 23,
          "size": 1,
          "note": "What the payload is: 1 ICMP, 6 TCP, 17 UDP, 50 ESP, 89 OSPF, 88 EIGRP."
         },
         {
          "name": "ip.checksum",
          "text": "Header Checksum: 0x83f0 [validation disabled]",
          "pos": 24,
          "size": 2,
          "note": "Header checksum, recomputed by every router because TTL changes."
         },
         {
          "name": "ip.src",
          "text": "Source Address: 100.200.255.1",
          "pos": 26,
          "size": 4,
          "note": "Original sender."
         },
         {
          "name": "ip.dst",
          "text": "Destination Address: 100.200.255.2",
          "pos": 30,
          "size": 4,
          "note": "Final destination."
         }
        ]
       },
       {
        "proto": "tcp",
        "title": "Transmission Control Protocol, Src Port: 179, Dst Port: 20076, Seq: 76, Ack: 20, Len: 28",
        "pos": 34,
        "size": 20,
        "note": "Transport. BGP rides TCP port 179, so every BGP message is acknowledged, ordered and resent by TCP, not by BGP.",
        "fields": [
         {
          "name": "tcp.len",
          "text": "TCP Segment Len: 28",
          "pos": 34,
          "size": 0,
          "note": "Payload bytes in this segment. 0 = a pure ACK or control segment."
         },
         {
          "name": "tcp.seq",
          "text": "Sequence Number: 76    (relative sequence number)",
          "pos": 38,
          "size": 4,
          "note": "Sequence number (relative): byte position of this segment's first data byte."
         },
         {
          "name": "tcp.ack",
          "text": "Acknowledgment Number: 20    (relative ack number)",
          "pos": 42,
          "size": 4,
          "note": "Acknowledgement: the next byte this side expects from the other."
         },
         {
          "name": "tcp.hdr_len",
          "text": "0101 .... = Header Length: 20 bytes (5)",
          "pos": 46,
          "size": 1,
          "note": "TCP header length. 20 = no options; 32 = timestamps; larger on a SYN with MSS / window scale / SACK."
         },
         {
          "name": "tcp.flags",
          "text": "Flags: 0x018 (PSH, ACK)",
          "pos": 46,
          "size": 2,
          "note": "Control bits. SYN opens, FIN closes cleanly, RST aborts, ACK acknowledges, PSH says deliver now.",
          "children": [
           {
            "name": "tcp.flags.res",
            "text": "000. .... .... = Reserved: Not set",
            "pos": 46,
            "size": 1
           },
           {
            "name": "tcp.flags.ae",
            "text": "...0 .... .... = Accurate ECN: Not set",
            "pos": 46,
            "size": 1
           },
           {
            "name": "tcp.flags.cwr",
            "text": ".... 0... .... = Congestion Window Reduced: Not set",
            "pos": 47,
            "size": 1
           },
           {
            "name": "tcp.flags.ece",
            "text": ".... .0.. .... = ECN-Echo: Not set",
            "pos": 47,
            "size": 1
           },
           {
            "name": "tcp.flags.urg",
            "text": ".... ..0. .... = Urgent: Not set",
            "pos": 47,
            "size": 1
           },
           {
            "name": "tcp.flags.ack",
            "text": ".... ...1 .... = Acknowledgment: Set",
            "pos": 47,
            "size": 1,
            "note": "ACK: the acknowledgement number is valid."
           },
           {
            "name": "tcp.flags.push",
            "text": ".... .... 1... = Push: Set",
            "pos": 47,
            "size": 1,
            "note": "PSH: hand the data to the application now."
           },
           {
            "name": "tcp.flags.reset",
            "text": ".... .... .0.. = Reset: Not set",
            "pos": 47,
            "size": 1,
            "note": "RST: refuse or abort. A RST answering a SYN means nothing is listening on that port, or the application refuses this peer (a shut-down BGP neighbor does exactly this)."
           },
           {
            "name": "tcp.flags.syn",
            "text": ".... .... ..0. = Syn: Not set",
            "pos": 47,
            "size": 1,
            "note": "SYN: open a connection."
           },
           {
            "name": "tcp.flags.fin",
            "text": ".... .... ...0 = Fin: Not set",
            "pos": 47,
            "size": 1,
            "note": "FIN: this side has nothing more to send; a clean close."
           },
           {
            "name": "tcp.flags.str",
            "text": "TCP Flags: \u00b7\u00b7\u00b7\u00b7\u00b7\u00b7\u00b7AP\u00b7\u00b7\u00b7",
            "pos": 46,
            "size": 2
           }
          ]
         },
         {
          "name": "tcp.window_size_value",
          "text": "Window: 15567",
          "pos": 48,
          "size": 2,
          "note": "Receive window: how many bytes the sender can accept right now."
         },
         {
          "name": "tcp.window_size_scalefactor",
          "text": "Window size scaling factor: -1 (unknown)",
          "pos": 48,
          "size": 2
         },
         {
          "name": "tcp.checksum",
          "text": "Checksum: 0xd796 [unverified]",
          "pos": 50,
          "size": 2,
          "note": "Checksum over header + payload."
         },
         {
          "name": "tcp.urgent_pointer",
          "text": "Urgent Pointer: 0",
          "pos": 52,
          "size": 2,
          "note": "Unused by BGP."
         },
         {
          "name": "",
          "text": "Timestamps",
          "pos": 34,
          "size": 0
         }
        ]
       },
       {
        "proto": "bgp",
        "title": "Border Gateway Protocol - UPDATE Message",
        "pos": 54,
        "size": 28,
        "note": "Border Gateway Protocol: routers in different (eBGP) or the same (iBGP) autonomous systems swap reachability. Every message starts with the same 19-byte header: 16-byte marker, 2-byte length, 1-byte type.",
        "fields": [
         {
          "name": "bgp.marker",
          "text": "Marker: ffffffffffffffffffffffffffffffff",
          "pos": 54,
          "size": 16,
          "note": "16 bytes of 0xff. Kept for compatibility (it once carried authentication); every BGP message has it."
         },
         {
          "name": "bgp.length",
          "text": "Length: 28",
          "pos": 70,
          "size": 2,
          "note": "Whole BGP message length in bytes, header included. Minimum 19 (a KEEPALIVE), maximum 4096 (65535 with extended messages)."
         },
         {
          "name": "bgp.type",
          "text": "Type: UPDATE Message (2)",
          "pos": 72,
          "size": 1,
          "note": "UPDATE: announces prefixes (with their path attributes) and/or withdraws prefixes."
         },
         {
          "name": "bgp.update.withdrawn_routes.length",
          "text": "Withdrawn Routes Length: 5",
          "pos": 73,
          "size": 2,
          "note": "Bytes of withdrawn prefixes that follow. 0 = this UPDATE withdraws nothing."
         },
         {
          "name": "bgp.update.withdrawn_routes",
          "text": "Withdrawn Routes",
          "pos": 75,
          "size": 5,
          "note": "Prefixes the sender no longer reaches. A withdraw needs no attributes.",
          "children": [
           {
            "name": "",
            "text": "198.51.100.0/25",
            "pos": 75,
            "size": 5,
            "children": [
             {
              "name": "bgp.prefix_length",
              "text": "Withdrawn route prefix length: 25",
              "pos": 75,
              "size": 1,
              "note": "Prefix length in bits. Only as many address bytes as needed follow (a /25 needs 4)."
             },
             {
              "name": "bgp.withdrawn_prefix",
              "text": "Withdrawn prefix: 198.51.100.0",
              "pos": 76,
              "size": 4,
              "note": "A prefix being taken back."
             }
            ]
           }
          ]
         },
         {
          "name": "bgp.update.path_attributes.length",
          "text": "Total Path Attribute Length: 0",
          "pos": 80,
          "size": 2,
          "note": "Bytes of path attributes. 0 = a pure withdraw."
         }
        ]
       }
      ],
      "focus": "bgp"
     },
     {
      "n": 10,
      "kind": "BGP OPEN",
      "t": 131.613,
      "clock": "11:14:00.291",
      "from": "HQ1-CORE-R1",
      "to": "ISPA-R1",
      "src": "100.100.255.2",
      "dst": "100.100.255.1",
      "frame": 114,
      "link": "HQ1-CORE-R1 Et0/2 <-> ISPA-R1 Et0/2",
      "len": 111,
      "summary": "Starts the session: version, AS, hold time, router ID, capabilities.",
      "layers": [
       {
        "proto": "eth",
        "title": "Ethernet II, Src: aa:bb:cc:00:18:20, Dst: aa:bb:cc:00:12:20",
        "pos": 0,
        "size": 14,
        "note": "Layer 2 frame. Only matters on this one wire: the next hop rewrites both MAC addresses.",
        "fields": [
         {
          "name": "eth.dst",
          "text": "Destination: aa:bb:cc:00:12:20",
          "pos": 0,
          "size": 6,
          "note": "Who on this wire should take the frame."
         },
         {
          "name": "eth.src",
          "text": "Source: aa:bb:cc:00:18:20",
          "pos": 6,
          "size": 6,
          "note": "Which interface put it on the wire."
         },
         {
          "name": "eth.type",
          "text": "Type: IPv4 (0x0800)",
          "pos": 12,
          "size": 2,
          "note": "What comes next: 0x0800 IPv4, 0x86dd IPv6, 0x8100 VLAN tag, 0x0806 ARP."
         }
        ]
       },
       {
        "proto": "ip",
        "title": "Internet Protocol Version 4, Src: 100.100.255.2, Dst: 100.100.255.1",
        "pos": 14,
        "size": 20,
        "note": "Layer 3 header. Source and destination stay the same end to end (unless NAT rewrites them); TTL drops by one per router.",
        "fields": [
         {
          "name": "ip.version",
          "text": "0100 .... = Version: 4",
          "pos": 14,
          "size": 1,
          "note": "4 = IPv4."
         },
         {
          "name": "ip.hdr_len",
          "text": ".... 0101 = Header Length: 20 bytes (5)",
          "pos": 14,
          "size": 1,
          "note": "Header length. 20 bytes means no IP options."
         },
         {
          "name": "ip.dsfield",
          "text": "Differentiated Services Field: 0xc0 (DSCP: CS6, ECN: Not-ECT)",
          "pos": 15,
          "size": 1,
          "note": "DSCP + ECN. Routers mark control traffic like BGP CS6 (DSCP 48, byte 0xc0) so QoS keeps it alive under load.",
          "children": [
           {
            "name": "ip.dsfield.dscp",
            "text": "1100 00.. = Differentiated Services Codepoint: Class Selector 6 (48)",
            "pos": 15,
            "size": 1,
            "note": "DSCP class. 48 = CS6, the class for routing protocols."
           },
           {
            "name": "ip.dsfield.ecn",
            "text": ".... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0)",
            "pos": 15,
            "size": 1
           }
          ]
         },
         {
          "name": "ip.len",
          "text": "Total Length: 97",
          "pos": 16,
          "size": 2,
          "note": "Total IP packet length (header + payload)."
         },
         {
          "name": "ip.id",
          "text": "Identification: 0xffce (65486)",
          "pos": 18,
          "size": 2,
          "note": "Identification. Unique per packet from a sender; also how you match the same packet in two captures."
         },
         {
          "name": "ip.flags",
          "text": "010. .... = Flags: 0x2, Don't fragment",
          "pos": 20,
          "size": 1,
          "note": "Fragmentation flags. DF set = routers must not fragment it.",
          "children": [
           {
            "name": "ip.flags.rb",
            "text": "0... .... = Reserved bit: Not set",
            "pos": 20,
            "size": 1
           },
           {
            "name": "ip.flags.df",
            "text": ".1.. .... = Don't fragment: Set",
            "pos": 20,
            "size": 1,
            "note": "Don't Fragment. If the packet is too big for a link it is dropped and an ICMP 'fragmentation needed' comes back."
           },
           {
            "name": "ip.flags.mf",
            "text": "..0. .... = More fragments: Not set",
            "pos": 20,
            "size": 1
           }
          ]
         },
         {
          "name": "ip.frag_offset",
          "text": "...0 0000 0000 0000 = Fragment Offset: 0",
          "pos": 20,
          "size": 2,
          "note": "Where this fragment sits in the original packet. 0 = not fragmented (or first piece)."
         },
         {
          "name": "ip.ttl",
          "text": "Time to Live: 1",
          "pos": 22,
          "size": 1,
          "note": "Time to live. Each router subtracts one; at 0 the packet dies and ICMP time-exceeded goes back. eBGP peers default to TTL 1 (directly connected) unless ebgp-multihop or ttl-security is set."
         },
         {
          "name": "ip.proto",
          "text": "Protocol: TCP (6)",
          "pos": 23,
          "size": 1,
          "note": "What the payload is: 1 ICMP, 6 TCP, 17 UDP, 50 ESP, 89 OSPF, 88 EIGRP."
         },
         {
          "name": "ip.checksum",
          "text": "Header Checksum: 0xb23b [validation disabled]",
          "pos": 24,
          "size": 2,
          "note": "Header checksum, recomputed by every router because TTL changes."
         },
         {
          "name": "ip.src",
          "text": "Source Address: 100.100.255.2",
          "pos": 26,
          "size": 4,
          "note": "Original sender."
         },
         {
          "name": "ip.dst",
          "text": "Destination Address: 100.100.255.1",
          "pos": 30,
          "size": 4,
          "note": "Final destination."
         }
        ]
       },
       {
        "proto": "tcp",
        "title": "Transmission Control Protocol, Src Port: 21381, Dst Port: 179, Seq: 1, Ack: 1, Len: 57",
        "pos": 34,
        "size": 20,
        "note": "Transport. BGP rides TCP port 179, so every BGP message is acknowledged, ordered and resent by TCP, not by BGP.",
        "fields": [
         {
          "name": "tcp.len",
          "text": "TCP Segment Len: 57",
          "pos": 34,
          "size": 0,
          "note": "Payload bytes in this segment. 0 = a pure ACK or control segment."
         },
         {
          "name": "tcp.seq",
          "text": "Sequence Number: 1    (relative sequence number)",
          "pos": 38,
          "size": 4,
          "note": "Sequence number (relative): byte position of this segment's first data byte."
         },
         {
          "name": "tcp.ack",
          "text": "Acknowledgment Number: 1    (relative ack number)",
          "pos": 42,
          "size": 4,
          "note": "Acknowledgement: the next byte this side expects from the other."
         },
         {
          "name": "tcp.hdr_len",
          "text": "0101 .... = Header Length: 20 bytes (5)",
          "pos": 46,
          "size": 1,
          "note": "TCP header length. 20 = no options; 32 = timestamps; larger on a SYN with MSS / window scale / SACK."
         },
         {
          "name": "tcp.flags",
          "text": "Flags: 0x018 (PSH, ACK)",
          "pos": 46,
          "size": 2,
          "note": "Control bits. SYN opens, FIN closes cleanly, RST aborts, ACK acknowledges, PSH says deliver now.",
          "children": [
           {
            "name": "tcp.flags.res",
            "text": "000. .... .... = Reserved: Not set",
            "pos": 46,
            "size": 1
           },
           {
            "name": "tcp.flags.ae",
            "text": "...0 .... .... = Accurate ECN: Not set",
            "pos": 46,
            "size": 1
           },
           {
            "name": "tcp.flags.cwr",
            "text": ".... 0... .... = Congestion Window Reduced: Not set",
            "pos": 47,
            "size": 1
           },
           {
            "name": "tcp.flags.ece",
            "text": ".... .0.. .... = ECN-Echo: Not set",
            "pos": 47,
            "size": 1
           },
           {
            "name": "tcp.flags.urg",
            "text": ".... ..0. .... = Urgent: Not set",
            "pos": 47,
            "size": 1
           },
           {
            "name": "tcp.flags.ack",
            "text": ".... ...1 .... = Acknowledgment: Set",
            "pos": 47,
            "size": 1,
            "note": "ACK: the acknowledgement number is valid."
           },
           {
            "name": "tcp.flags.push",
            "text": ".... .... 1... = Push: Set",
            "pos": 47,
            "size": 1,
            "note": "PSH: hand the data to the application now."
           },
           {
            "name": "tcp.flags.reset",
            "text": ".... .... .0.. = Reset: Not set",
            "pos": 47,
            "size": 1,
            "note": "RST: refuse or abort. A RST answering a SYN means nothing is listening on that port, or the application refuses this peer (a shut-down BGP neighbor does exactly this)."
           },
           {
            "name": "tcp.flags.syn",
            "text": ".... .... ..0. = Syn: Not set",
            "pos": 47,
            "size": 1,
            "note": "SYN: open a connection."
           },
           {
            "name": "tcp.flags.fin",
            "text": ".... .... ...0 = Fin: Not set",
            "pos": 47,
            "size": 1,
            "note": "FIN: this side has nothing more to send; a clean close."
           },
           {
            "name": "tcp.flags.str",
            "text": "TCP Flags: \u00b7\u00b7\u00b7\u00b7\u00b7\u00b7\u00b7AP\u00b7\u00b7\u00b7",
            "pos": 46,
            "size": 2
           }
          ]
         },
         {
          "name": "tcp.window_size_value",
          "text": "Window: 16384",
          "pos": 48,
          "size": 2,
          "note": "Receive window: how many bytes the sender can accept right now."
         },
         {
          "name": "tcp.window_size_scalefactor",
          "text": "Window size scaling factor: 1",
          "pos": 48,
          "size": 2
         },
         {
          "name": "tcp.checksum",
          "text": "Checksum: 0x5d9b [unverified]",
          "pos": 50,
          "size": 2,
          "note": "Checksum over header + payload."
         },
         {
          "name": "tcp.urgent_pointer",
          "text": "Urgent Pointer: 0",
          "pos": 52,
          "size": 2,
          "note": "Unused by BGP."
         },
         {
          "name": "",
          "text": "Timestamps",
          "pos": 34,
          "size": 0
         }
        ]
       },
       {
        "proto": "bgp",
        "title": "Border Gateway Protocol - OPEN Message",
        "pos": 54,
        "size": 57,
        "note": "Border Gateway Protocol: routers in different (eBGP) or the same (iBGP) autonomous systems swap reachability. Every message starts with the same 19-byte header: 16-byte marker, 2-byte length, 1-byte type.",
        "fields": [
         {
          "name": "bgp.marker",
          "text": "Marker: ffffffffffffffffffffffffffffffff",
          "pos": 54,
          "size": 16,
          "note": "16 bytes of 0xff. Kept for compatibility (it once carried authentication); every BGP message has it."
         },
         {
          "name": "bgp.length",
          "text": "Length: 57",
          "pos": 70,
          "size": 2,
          "note": "Whole BGP message length in bytes, header included. Minimum 19 (a KEEPALIVE), maximum 4096 (65535 with extended messages)."
         },
         {
          "name": "bgp.type",
          "text": "Type: OPEN Message (1)",
          "pos": 72,
          "size": 1,
          "note": "OPEN: first message after TCP connects. Carries AS, hold time, router ID and capabilities."
         },
         {
          "name": "bgp.open.version",
          "text": "Version: 4",
          "pos": 73,
          "size": 1,
          "note": "BGP version. Always 4."
         },
         {
          "name": "bgp.open.myas",
          "text": "My AS: 65001",
          "pos": 74,
          "size": 2,
          "note": "Sender's AS number (2-byte field; 23456 here means 'see the 4-byte AS capability')."
         },
         {
          "name": "bgp.open.holdtime",
          "text": "Hold Time: 180",
          "pos": 76,
          "size": 2,
          "note": "Hold time the sender proposes. Both sides use the lower value; keepalives go every third of it. IOS default 180 s hold, 60 s keepalive."
         },
         {
          "name": "bgp.open.identifier",
          "text": "BGP Identifier: 10.255.1.1",
          "pos": 78,
          "size": 4,
          "note": "BGP router ID. Must be unique; ties break on it in best-path selection."
         },
         {
          "name": "bgp.open.opt.len",
          "text": "Optional Parameters Length: 28",
          "pos": 82,
          "size": 1
         },
         {
          "name": "bgp.open.opt",
          "text": "Optional Parameters",
          "pos": 83,
          "size": 28,
          "children": [
           {
            "name": "bgp.open.opt.param",
            "text": "Optional Parameter: Capability",
            "pos": 83,
            "size": 8,
            "children": [
             {
              "name": "bgp.open.opt.param.type",
              "text": "Parameter Type: Capability (2)",
              "pos": 83,
              "size": 1
             },
             {
              "name": "bgp.open.opt.param.len",
              "text": "Parameter Length: 6",
              "pos": 84,
              "size": 1
             },
             {
              "name": "bgp.cap",
              "text": "Capability: Multiprotocol extensions capability",
              "pos": 85,
              "size": 6,
              "children": [
               {
                "name": "bgp.cap.type",
                "text": "Type: Multiprotocol extensions capability (1)",
                "pos": 85,
                "size": 1,
                "note": "Multiprotocol (MP-BGP): which address families this speaker wants (AFI/SAFI below). IPv4 unicast here."
               },
               {
                "name": "bgp.cap.length",
                "text": "Length: 4",
                "pos": 86,
                "size": 1
               },
               {
                "name": "bgp.cap.mp.afi",
                "text": "AFI: IPv4 (1)",
                "pos": 87,
                "size": 2
               },
               {
                "name": "bgp.cap.reserved",
                "text": "Reserved: 00",
                "pos": 89,
                "size": 1
               },
               {
                "name": "bgp.cap.mp.safi",
                "text": "SAFI: Unicast (1)",
                "pos": 90,
                "size": 1
               }
              ]
             }
            ]
           },
           {
            "name": "bgp.open.opt.param",
            "text": "Optional Parameter: Capability",
            "pos": 91,
            "size": 4,
            "children": [
             {
              "name": "bgp.open.opt.param.type",
              "text": "Parameter Type: Capability (2)",
              "pos": 91,
              "size": 1
             },
             {
              "name": "bgp.open.opt.param.len",
              "text": "Parameter Length: 2",
              "pos": 92,
              "size": 1
             },
             {
              "name": "bgp.cap",
              "text": "Capability: Route refresh capability (Cisco)",
              "pos": 93,
              "size": 2,
              "children": [
               {
                "name": "bgp.cap.type",
                "text": "Type: Route refresh capability (Cisco) (128)",
                "pos": 93,
                "size": 1,
                "note": "Route refresh, the old Cisco-specific code (128) before the standard (2) existed. IOS still sends both."
               },
               {
                "name": "bgp.cap.length",
                "text": "Length: 0",
                "pos": 94,
                "size": 1
               }
              ]
             }
            ]
           },
           {
            "name": "bgp.open.opt.param",
            "text": "Optional Parameter: Capability",
            "pos": 95,
            "size": 4,
            "children": [
             {
              "name": "bgp.open.opt.param.type",
              "text": "Parameter Type: Capability (2)",
              "pos": 95,
              "size": 1
             },
             {
              "name": "bgp.open.opt.param.len",
              "text": "Parameter Length: 2",
              "pos": 96,
              "size": 1
             },
             {
              "name": "bgp.cap",
              "text": "Capability: Route refresh capability",
              "pos": 97,
              "size": 2,
              "children": [
               {
                "name": "bgp.cap.type",
                "text": "Type: Route refresh capability (2)",
                "pos": 97,
                "size": 1,
                "note": "Route refresh: the peer may ask me to resend my table without tearing the session down (clear ip bgp ... soft in)."
               },
               {
                "name": "bgp.cap.length",
                "text": "Length: 0",
                "pos": 98,
                "size": 1
               }
              ]
             }
            ]
           },
           {
            "name": "bgp.open.opt.param",
            "text": "Optional Parameter: Capability",
            "pos": 99,
            "size": 4,
            "children": [
             {
              "name": "bgp.open.opt.param.type",
              "text": "Parameter Type: Capability (2)",
              "pos": 99,
              "size": 1
             },
             {
              "name": "bgp.open.opt.param.len",
              "text": "Parameter Length: 2",
              "pos": 100,
              "size": 1
             },
             {
              "name": "bgp.cap",
              "text": "Capability: Enhanced route refresh capability",
              "pos": 101,
              "size": 2,
              "children": [
               {
                "name": "bgp.cap.type",
                "text": "Type: Enhanced route refresh capability (70)",
                "pos": 101,
                "size": 1,
                "note": "Enhanced route refresh: a resend is framed by BoRR / EoRR markers so the peer can drop stale routes afterwards."
               },
               {
                "name": "bgp.cap.length",
                "text": "Length: 0",
                "pos": 102,
                "size": 1
               }
              ]
             }
            ]
           },
           {
            "name": "bgp.open.opt.param",
            "text": "Optional Parameter: Capability",
            "pos": 103,
            "size": 8,
            "children": [
             {
              "name": "bgp.open.opt.param.type",
              "text": "Parameter Type: Capability (2)",
              "pos": 103,
              "size": 1
             },
             {
              "name": "bgp.open.opt.param.len",
              "text": "Parameter Length: 6",
              "pos": 104,
              "size": 1
             },
             {
              "name": "bgp.cap",
              "text": "Capability: Support for 4-octet AS number capability",
              "pos": 105,
              "size": 6,
              "children": [
               {
                "name": "bgp.cap.type",
                "text": "Type: Support for 4-octet AS number capability (65)",
                "pos": 105,
                "size": 1,
                "note": "4-byte AS numbers: the real AS rides here; AS_PATH then carries 4-byte numbers."
               },
               {
                "name": "bgp.cap.length",
                "text": "Length: 4",
                "pos": 106,
                "size": 1
               },
               {
                "name": "bgp.cap.4as",
                "text": "AS Number: 65001",
                "pos": 107,
                "size": 4
               }
              ]
             }
            ]
           }
          ]
         }
        ]
       }
      ],
      "focus": "bgp"
     },
     {
      "n": 11,
      "kind": "BGP OPEN",
      "t": 131.615,
      "clock": "11:14:00.292",
      "from": "ISPA-R1",
      "to": "HQ1-CORE-R1",
      "src": "100.100.255.1",
      "dst": "100.100.255.2",
      "frame": 116,
      "link": "HQ1-CORE-R1 Et0/2 <-> ISPA-R1 Et0/2",
      "len": 111,
      "summary": "Starts the session: version, AS, hold time, router ID, capabilities.",
      "layers": [
       {
        "proto": "eth",
        "title": "Ethernet II, Src: aa:bb:cc:00:12:20, Dst: aa:bb:cc:00:18:20",
        "pos": 0,
        "size": 14,
        "note": "Layer 2 frame. Only matters on this one wire: the next hop rewrites both MAC addresses.",
        "fields": [
         {
          "name": "eth.dst",
          "text": "Destination: aa:bb:cc:00:18:20",
          "pos": 0,
          "size": 6,
          "note": "Who on this wire should take the frame."
         },
         {
          "name": "eth.src",
          "text": "Source: aa:bb:cc:00:12:20",
          "pos": 6,
          "size": 6,
          "note": "Which interface put it on the wire."
         },
         {
          "name": "eth.type",
          "text": "Type: IPv4 (0x0800)",
          "pos": 12,
          "size": 2,
          "note": "What comes next: 0x0800 IPv4, 0x86dd IPv6, 0x8100 VLAN tag, 0x0806 ARP."
         }
        ]
       },
       {
        "proto": "ip",
        "title": "Internet Protocol Version 4, Src: 100.100.255.1, Dst: 100.100.255.2",
        "pos": 14,
        "size": 20,
        "note": "Layer 3 header. Source and destination stay the same end to end (unless NAT rewrites them); TTL drops by one per router.",
        "fields": [
         {
          "name": "ip.version",
          "text": "0100 .... = Version: 4",
          "pos": 14,
          "size": 1,
          "note": "4 = IPv4."
         },
         {
          "name": "ip.hdr_len",
          "text": ".... 0101 = Header Length: 20 bytes (5)",
          "pos": 14,
          "size": 1,
          "note": "Header length. 20 bytes means no IP options."
         },
         {
          "name": "ip.dsfield",
          "text": "Differentiated Services Field: 0xc0 (DSCP: CS6, ECN: Not-ECT)",
          "pos": 15,
          "size": 1,
          "note": "DSCP + ECN. Routers mark control traffic like BGP CS6 (DSCP 48, byte 0xc0) so QoS keeps it alive under load.",
          "children": [
           {
            "name": "ip.dsfield.dscp",
            "text": "1100 00.. = Differentiated Services Codepoint: Class Selector 6 (48)",
            "pos": 15,
            "size": 1,
            "note": "DSCP class. 48 = CS6, the class for routing protocols."
           },
           {
            "name": "ip.dsfield.ecn",
            "text": ".... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0)",
            "pos": 15,
            "size": 1
           }
          ]
         },
         {
          "name": "ip.len",
          "text": "Total Length: 97",
          "pos": 16,
          "size": 2,
          "note": "Total IP packet length (header + payload)."
         },
         {
          "name": "ip.id",
          "text": "Identification: 0xd9b8 (55736)",
          "pos": 18,
          "size": 2,
          "note": "Identification. Unique per packet from a sender; also how you match the same packet in two captures."
         },
         {
          "name": "ip.flags",
          "text": "010. .... = Flags: 0x2, Don't fragment",
          "pos": 20,
          "size": 1,
          "note": "Fragmentation flags. DF set = routers must not fragment it.",
          "children": [
           {
            "name": "ip.flags.rb",
            "text": "0... .... = Reserved bit: Not set",
            "pos": 20,
            "size": 1
           },
           {
            "name": "ip.flags.df",
            "text": ".1.. .... = Don't fragment: Set",
            "pos": 20,
            "size": 1,
            "note": "Don't Fragment. If the packet is too big for a link it is dropped and an ICMP 'fragmentation needed' comes back."
           },
           {
            "name": "ip.flags.mf",
            "text": "..0. .... = More fragments: Not set",
            "pos": 20,
            "size": 1
           }
          ]
         },
         {
          "name": "ip.frag_offset",
          "text": "...0 0000 0000 0000 = Fragment Offset: 0",
          "pos": 20,
          "size": 2,
          "note": "Where this fragment sits in the original packet. 0 = not fragmented (or first piece)."
         },
         {
          "name": "ip.ttl",
          "text": "Time to Live: 1",
          "pos": 22,
          "size": 1,
          "note": "Time to live. Each router subtracts one; at 0 the packet dies and ICMP time-exceeded goes back. eBGP peers default to TTL 1 (directly connected) unless ebgp-multihop or ttl-security is set."
         },
         {
          "name": "ip.proto",
          "text": "Protocol: TCP (6)",
          "pos": 23,
          "size": 1,
          "note": "What the payload is: 1 ICMP, 6 TCP, 17 UDP, 50 ESP, 89 OSPF, 88 EIGRP."
         },
         {
          "name": "ip.checksum",
          "text": "Header Checksum: 0xd851 [validation disabled]",
          "pos": 24,
          "size": 2,
          "note": "Header checksum, recomputed by every router because TTL changes."
         },
         {
          "name": "ip.src",
          "text": "Source Address: 100.100.255.1",
          "pos": 26,
          "size": 4,
          "note": "Original sender."
         },
         {
          "name": "ip.dst",
          "text": "Destination Address: 100.100.255.2",
          "pos": 30,
          "size": 4,
          "note": "Final destination."
         }
        ]
       },
       {
        "proto": "tcp",
        "title": "Transmission Control Protocol, Src Port: 179, Dst Port: 21381, Seq: 1, Ack: 58, Len: 57",
        "pos": 34,
        "size": 20,
        "note": "Transport. BGP rides TCP port 179, so every BGP message is acknowledged, ordered and resent by TCP, not by BGP.",
        "fields": [
         {
          "name": "tcp.len",
          "text": "TCP Segment Len: 57",
          "pos": 34,
          "size": 0,
          "note": "Payload bytes in this segment. 0 = a pure ACK or control segment."
         },
         {
          "name": "tcp.seq",
          "text": "Sequence Number: 1    (relative sequence number)",
          "pos": 38,
          "size": 4,
          "note": "Sequence number (relative): byte position of this segment's first data byte."
         },
         {
          "name": "tcp.ack",
          "text": "Acknowledgment Number: 58    (relative ack number)",
          "pos": 42,
          "size": 4,
          "note": "Acknowledgement: the next byte this side expects from the other."
         },
         {
          "name": "tcp.hdr_len",
          "text": "0101 .... = Header Length: 20 bytes (5)",
          "pos": 46,
          "size": 1,
          "note": "TCP header length. 20 = no options; 32 = timestamps; larger on a SYN with MSS / window scale / SACK."
         },
         {
          "name": "tcp.flags",
          "text": "Flags: 0x018 (PSH, ACK)",
          "pos": 46,
          "size": 2,
          "note": "Control bits. SYN opens, FIN closes cleanly, RST aborts, ACK acknowledges, PSH says deliver now.",
          "children": [
           {
            "name": "tcp.flags.res",
            "text": "000. .... .... = Reserved: Not set",
            "pos": 46,
            "size": 1
           },
           {
            "name": "tcp.flags.ae",
            "text": "...0 .... .... = Accurate ECN: Not set",
            "pos": 46,
            "size": 1
           },
           {
            "name": "tcp.flags.cwr",
            "text": ".... 0... .... = Congestion Window Reduced: Not set",
            "pos": 47,
            "size": 1
           },
           {
            "name": "tcp.flags.ece",
            "text": ".... .0.. .... = ECN-Echo: Not set",
            "pos": 47,
            "size": 1
           },
           {
            "name": "tcp.flags.urg",
            "text": ".... ..0. .... = Urgent: Not set",
            "pos": 47,
            "size": 1
           },
           {
            "name": "tcp.flags.ack",
            "text": ".... ...1 .... = Acknowledgment: Set",
            "pos": 47,
            "size": 1,
            "note": "ACK: the acknowledgement number is valid."
           },
           {
            "name": "tcp.flags.push",
            "text": ".... .... 1... = Push: Set",
            "pos": 47,
            "size": 1,
            "note": "PSH: hand the data to the application now."
           },
           {
            "name": "tcp.flags.reset",
            "text": ".... .... .0.. = Reset: Not set",
            "pos": 47,
            "size": 1,
            "note": "RST: refuse or abort. A RST answering a SYN means nothing is listening on that port, or the application refuses this peer (a shut-down BGP neighbor does exactly this)."
           },
           {
            "name": "tcp.flags.syn",
            "text": ".... .... ..0. = Syn: Not set",
            "pos": 47,
            "size": 1,
            "note": "SYN: open a connection."
           },
           {
            "name": "tcp.flags.fin",
            "text": ".... .... ...0 = Fin: Not set",
            "pos": 47,
            "size": 1,
            "note": "FIN: this side has nothing more to send; a clean close."
           },
           {
            "name": "tcp.flags.str",
            "text": "TCP Flags: \u00b7\u00b7\u00b7\u00b7\u00b7\u00b7\u00b7AP\u00b7\u00b7\u00b7",
            "pos": 46,
            "size": 2
           }
          ]
         },
         {
          "name": "tcp.window_size_value",
          "text": "Window: 16327",
          "pos": 48,
          "size": 2,
          "note": "Receive window: how many bytes the sender can accept right now."
         },
         {
          "name": "tcp.window_size_scalefactor",
          "text": "Window size scaling factor: 1",
          "pos": 48,
          "size": 2
         },
         {
          "name": "tcp.checksum",
          "text": "Checksum: 0xa3d1 [unverified]",
          "pos": 50,
          "size": 2,
          "note": "Checksum over header + payload."
         },
         {
          "name": "tcp.urgent_pointer",
          "text": "Urgent Pointer: 0",
          "pos": 52,
          "size": 2,
          "note": "Unused by BGP."
         },
         {
          "name": "",
          "text": "Timestamps",
          "pos": 34,
          "size": 0
         }
        ]
       },
       {
        "proto": "bgp",
        "title": "Border Gateway Protocol - OPEN Message",
        "pos": 54,
        "size": 57,
        "note": "Border Gateway Protocol: routers in different (eBGP) or the same (iBGP) autonomous systems swap reachability. Every message starts with the same 19-byte header: 16-byte marker, 2-byte length, 1-byte type.",
        "fields": [
         {
          "name": "bgp.marker",
          "text": "Marker: ffffffffffffffffffffffffffffffff",
          "pos": 54,
          "size": 16,
          "note": "16 bytes of 0xff. Kept for compatibility (it once carried authentication); every BGP message has it."
         },
         {
          "name": "bgp.length",
          "text": "Length: 57",
          "pos": 70,
          "size": 2,
          "note": "Whole BGP message length in bytes, header included. Minimum 19 (a KEEPALIVE), maximum 4096 (65535 with extended messages)."
         },
         {
          "name": "bgp.type",
          "text": "Type: OPEN Message (1)",
          "pos": 72,
          "size": 1,
          "note": "OPEN: first message after TCP connects. Carries AS, hold time, router ID and capabilities."
         },
         {
          "name": "bgp.open.version",
          "text": "Version: 4",
          "pos": 73,
          "size": 1,
          "note": "BGP version. Always 4."
         },
         {
          "name": "bgp.open.myas",
          "text": "My AS: 65100",
          "pos": 74,
          "size": 2,
          "note": "Sender's AS number (2-byte field; 23456 here means 'see the 4-byte AS capability')."
         },
         {
          "name": "bgp.open.holdtime",
          "text": "Hold Time: 180",
          "pos": 76,
          "size": 2,
          "note": "Hold time the sender proposes. Both sides use the lower value; keepalives go every third of it. IOS default 180 s hold, 60 s keepalive."
         },
         {
          "name": "bgp.open.identifier",
          "text": "BGP Identifier: 100.100.254.1",
          "pos": 78,
          "size": 4,
          "note": "BGP router ID. Must be unique; ties break on it in best-path selection."
         },
         {
          "name": "bgp.open.opt.len",
          "text": "Optional Parameters Length: 28",
          "pos": 82,
          "size": 1
         },
         {
          "name": "bgp.open.opt",
          "text": "Optional Parameters",
          "pos": 83,
          "size": 28,
          "children": [
           {
            "name": "bgp.open.opt.param",
            "text": "Optional Parameter: Capability",
            "pos": 83,
            "size": 8,
            "children": [
             {
              "name": "bgp.open.opt.param.type",
              "text": "Parameter Type: Capability (2)",
              "pos": 83,
              "size": 1
             },
             {
              "name": "bgp.open.opt.param.len",
              "text": "Parameter Length: 6",
              "pos": 84,
              "size": 1
             },
             {
              "name": "bgp.cap",
              "text": "Capability: Multiprotocol extensions capability",
              "pos": 85,
              "size": 6,
              "children": [
               {
                "name": "bgp.cap.type",
                "text": "Type: Multiprotocol extensions capability (1)",
                "pos": 85,
                "size": 1,
                "note": "Multiprotocol (MP-BGP): which address families this speaker wants (AFI/SAFI below). IPv4 unicast here."
               },
               {
                "name": "bgp.cap.length",
                "text": "Length: 4",
                "pos": 86,
                "size": 1
               },
               {
                "name": "bgp.cap.mp.afi",
                "text": "AFI: IPv4 (1)",
                "pos": 87,
                "size": 2
               },
               {
                "name": "bgp.cap.reserved",
                "text": "Reserved: 00",
                "pos": 89,
                "size": 1
               },
               {
                "name": "bgp.cap.mp.safi",
                "text": "SAFI: Unicast (1)",
                "pos": 90,
                "size": 1
               }
              ]
             }
            ]
           },
           {
            "name": "bgp.open.opt.param",
            "text": "Optional Parameter: Capability",
            "pos": 91,
            "size": 4,
            "children": [
             {
              "name": "bgp.open.opt.param.type",
              "text": "Parameter Type: Capability (2)",
              "pos": 91,
              "size": 1
             },
             {
              "name": "bgp.open.opt.param.len",
              "text": "Parameter Length: 2",
              "pos": 92,
              "size": 1
             },
             {
              "name": "bgp.cap",
              "text": "Capability: Route refresh capability (Cisco)",
              "pos": 93,
              "size": 2,
              "children": [
               {
                "name": "bgp.cap.type",
                "text": "Type: Route refresh capability (Cisco) (128)",
                "pos": 93,
                "size": 1,
                "note": "Route refresh, the old Cisco-specific code (128) before the standard (2) existed. IOS still sends both."
               },
               {
                "name": "bgp.cap.length",
                "text": "Length: 0",
                "pos": 94,
                "size": 1
               }
              ]
             }
            ]
           },
           {
            "name": "bgp.open.opt.param",
            "text": "Optional Parameter: Capability",
            "pos": 95,
            "size": 4,
            "children": [
             {
              "name": "bgp.open.opt.param.type",
              "text": "Parameter Type: Capability (2)",
              "pos": 95,
              "size": 1
             },
             {
              "name": "bgp.open.opt.param.len",
              "text": "Parameter Length: 2",
              "pos": 96,
              "size": 1
             },
             {
              "name": "bgp.cap",
              "text": "Capability: Route refresh capability",
              "pos": 97,
              "size": 2,
              "children": [
               {
                "name": "bgp.cap.type",
                "text": "Type: Route refresh capability (2)",
                "pos": 97,
                "size": 1,
                "note": "Route refresh: the peer may ask me to resend my table without tearing the session down (clear ip bgp ... soft in)."
               },
               {
                "name": "bgp.cap.length",
                "text": "Length: 0",
                "pos": 98,
                "size": 1
               }
              ]
             }
            ]
           },
           {
            "name": "bgp.open.opt.param",
            "text": "Optional Parameter: Capability",
            "pos": 99,
            "size": 4,
            "children": [
             {
              "name": "bgp.open.opt.param.type",
              "text": "Parameter Type: Capability (2)",
              "pos": 99,
              "size": 1
             },
             {
              "name": "bgp.open.opt.param.len",
              "text": "Parameter Length: 2",
              "pos": 100,
              "size": 1
             },
             {
              "name": "bgp.cap",
              "text": "Capability: Enhanced route refresh capability",
              "pos": 101,
              "size": 2,
              "children": [
               {
                "name": "bgp.cap.type",
                "text": "Type: Enhanced route refresh capability (70)",
                "pos": 101,
                "size": 1,
                "note": "Enhanced route refresh: a resend is framed by BoRR / EoRR markers so the peer can drop stale routes afterwards."
               },
               {
                "name": "bgp.cap.length",
                "text": "Length: 0",
                "pos": 102,
                "size": 1
               }
              ]
             }
            ]
           },
           {
            "name": "bgp.open.opt.param",
            "text": "Optional Parameter: Capability",
            "pos": 103,
            "size": 8,
            "children": [
             {
              "name": "bgp.open.opt.param.type",
              "text": "Parameter Type: Capability (2)",
              "pos": 103,
              "size": 1
             },
             {
              "name": "bgp.open.opt.param.len",
              "text": "Parameter Length: 6",
              "pos": 104,
              "size": 1
             },
             {
              "name": "bgp.cap",
              "text": "Capability: Support for 4-octet AS number capability",
              "pos": 105,
              "size": 6,
              "children": [
               {
                "name": "bgp.cap.type",
                "text": "Type: Support for 4-octet AS number capability (65)",
                "pos": 105,
                "size": 1,
                "note": "4-byte AS numbers: the real AS rides here; AS_PATH then carries 4-byte numbers."
               },
               {
                "name": "bgp.cap.length",
                "text": "Length: 4",
                "pos": 106,
                "size": 1
               },
               {
                "name": "bgp.cap.4as",
                "text": "AS Number: 65100",
                "pos": 107,
                "size": 4
               }
              ]
             }
            ]
           }
          ]
         }
        ]
       }
      ],
      "focus": "bgp"
     },
     {
      "n": 12,
      "kind": "BGP ROUTE-REFRESH",
      "t": 131.617,
      "clock": "11:14:00.295",
      "from": "ISPA-R1",
      "to": "HQ1-CORE-R1",
      "src": "100.100.255.1",
      "dst": "100.100.255.2",
      "frame": 120,
      "link": "HQ1-CORE-R1 Et0/2 <-> ISPA-R1 Et0/2",
      "len": 77,
      "summary": "Asks the peer to resend its table, or (enhanced route refresh) marks the start (BoRR) or end (EoRR) of a resend.",
      "layers": [
       {
        "proto": "eth",
        "title": "Ethernet II, Src: aa:bb:cc:00:12:20, Dst: aa:bb:cc:00:18:20",
        "pos": 0,
        "size": 14,
        "note": "Layer 2 frame. Only matters on this one wire: the next hop rewrites both MAC addresses.",
        "fields": [
         {
          "name": "eth.dst",
          "text": "Destination: aa:bb:cc:00:18:20",
          "pos": 0,
          "size": 6,
          "note": "Who on this wire should take the frame."
         },
         {
          "name": "eth.src",
          "text": "Source: aa:bb:cc:00:12:20",
          "pos": 6,
          "size": 6,
          "note": "Which interface put it on the wire."
         },
         {
          "name": "eth.type",
          "text": "Type: IPv4 (0x0800)",
          "pos": 12,
          "size": 2,
          "note": "What comes next: 0x0800 IPv4, 0x86dd IPv6, 0x8100 VLAN tag, 0x0806 ARP."
         }
        ]
       },
       {
        "proto": "ip",
        "title": "Internet Protocol Version 4, Src: 100.100.255.1, Dst: 100.100.255.2",
        "pos": 14,
        "size": 20,
        "note": "Layer 3 header. Source and destination stay the same end to end (unless NAT rewrites them); TTL drops by one per router.",
        "fields": [
         {
          "name": "ip.version",
          "text": "0100 .... = Version: 4",
          "pos": 14,
          "size": 1,
          "note": "4 = IPv4."
         },
         {
          "name": "ip.hdr_len",
          "text": ".... 0101 = Header Length: 20 bytes (5)",
          "pos": 14,
          "size": 1,
          "note": "Header length. 20 bytes means no IP options."
         },
         {
          "name": "ip.dsfield",
          "text": "Differentiated Services Field: 0xc0 (DSCP: CS6, ECN: Not-ECT)",
          "pos": 15,
          "size": 1,
          "note": "DSCP + ECN. Routers mark control traffic like BGP CS6 (DSCP 48, byte 0xc0) so QoS keeps it alive under load.",
          "children": [
           {
            "name": "ip.dsfield.dscp",
            "text": "1100 00.. = Differentiated Services Codepoint: Class Selector 6 (48)",
            "pos": 15,
            "size": 1,
            "note": "DSCP class. 48 = CS6, the class for routing protocols."
           },
           {
            "name": "ip.dsfield.ecn",
            "text": ".... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0)",
            "pos": 15,
            "size": 1
           }
          ]
         },
         {
          "name": "ip.len",
          "text": "Total Length: 63",
          "pos": 16,
          "size": 2,
          "note": "Total IP packet length (header + payload)."
         },
         {
          "name": "ip.id",
          "text": "Identification: 0xd9ba (55738)",
          "pos": 18,
          "size": 2,
          "note": "Identification. Unique per packet from a sender; also how you match the same packet in two captures."
         },
         {
          "name": "ip.flags",
          "text": "010. .... = Flags: 0x2, Don't fragment",
          "pos": 20,
          "size": 1,
          "note": "Fragmentation flags. DF set = routers must not fragment it.",
          "children": [
           {
            "name": "ip.flags.rb",
            "text": "0... .... = Reserved bit: Not set",
            "pos": 20,
            "size": 1
           },
           {
            "name": "ip.flags.df",
            "text": ".1.. .... = Don't fragment: Set",
            "pos": 20,
            "size": 1,
            "note": "Don't Fragment. If the packet is too big for a link it is dropped and an ICMP 'fragmentation needed' comes back."
           },
           {
            "name": "ip.flags.mf",
            "text": "..0. .... = More fragments: Not set",
            "pos": 20,
            "size": 1
           }
          ]
         },
         {
          "name": "ip.frag_offset",
          "text": "...0 0000 0000 0000 = Fragment Offset: 0",
          "pos": 20,
          "size": 2,
          "note": "Where this fragment sits in the original packet. 0 = not fragmented (or first piece)."
         },
         {
          "name": "ip.ttl",
          "text": "Time to Live: 1",
          "pos": 22,
          "size": 1,
          "note": "Time to live. Each router subtracts one; at 0 the packet dies and ICMP time-exceeded goes back. eBGP peers default to TTL 1 (directly connected) unless ebgp-multihop or ttl-security is set."
         },
         {
          "name": "ip.proto",
          "text": "Protocol: TCP (6)",
          "pos": 23,
          "size": 1,
          "note": "What the payload is: 1 ICMP, 6 TCP, 17 UDP, 50 ESP, 89 OSPF, 88 EIGRP."
         },
         {
          "name": "ip.checksum",
          "text": "Header Checksum: 0xd871 [validation disabled]",
          "pos": 24,
          "size": 2,
          "note": "Header checksum, recomputed by every router because TTL changes."
         },
         {
          "name": "ip.src",
          "text": "Source Address: 100.100.255.1",
          "pos": 26,
          "size": 4,
          "note": "Original sender."
         },
         {
          "name": "ip.dst",
          "text": "Destination Address: 100.100.255.2",
          "pos": 30,
          "size": 4,
          "note": "Final destination."
         }
        ]
       },
       {
        "proto": "tcp",
        "title": "Transmission Control Protocol, Src Port: 179, Dst Port: 21381, Seq: 77, Ack: 77, Len: 23",
        "pos": 34,
        "size": 20,
        "note": "Transport. BGP rides TCP port 179, so every BGP message is acknowledged, ordered and resent by TCP, not by BGP.",
        "fields": [
         {
          "name": "tcp.len",
          "text": "TCP Segment Len: 23",
          "pos": 34,
          "size": 0,
          "note": "Payload bytes in this segment. 0 = a pure ACK or control segment."
         },
         {
          "name": "tcp.seq",
          "text": "Sequence Number: 77    (relative sequence number)",
          "pos": 38,
          "size": 4,
          "note": "Sequence number (relative): byte position of this segment's first data byte."
         },
         {
          "name": "tcp.ack",
          "text": "Acknowledgment Number: 77    (relative ack number)",
          "pos": 42,
          "size": 4,
          "note": "Acknowledgement: the next byte this side expects from the other."
         },
         {
          "name": "tcp.hdr_len",
          "text": "0101 .... = Header Length: 20 bytes (5)",
          "pos": 46,
          "size": 1,
          "note": "TCP header length. 20 = no options; 32 = timestamps; larger on a SYN with MSS / window scale / SACK."
         },
         {
          "name": "tcp.flags",
          "text": "Flags: 0x018 (PSH, ACK)",
          "pos": 46,
          "size": 2,
          "note": "Control bits. SYN opens, FIN closes cleanly, RST aborts, ACK acknowledges, PSH says deliver now.",
          "children": [
           {
            "name": "tcp.flags.res",
            "text": "000. .... .... = Reserved: Not set",
            "pos": 46,
            "size": 1
           },
           {
            "name": "tcp.flags.ae",
            "text": "...0 .... .... = Accurate ECN: Not set",
            "pos": 46,
            "size": 1
           },
           {
            "name": "tcp.flags.cwr",
            "text": ".... 0... .... = Congestion Window Reduced: Not set",
            "pos": 47,
            "size": 1
           },
           {
            "name": "tcp.flags.ece",
            "text": ".... .0.. .... = ECN-Echo: Not set",
            "pos": 47,
            "size": 1
           },
           {
            "name": "tcp.flags.urg",
            "text": ".... ..0. .... = Urgent: Not set",
            "pos": 47,
            "size": 1
           },
           {
            "name": "tcp.flags.ack",
            "text": ".... ...1 .... = Acknowledgment: Set",
            "pos": 47,
            "size": 1,
            "note": "ACK: the acknowledgement number is valid."
           },
           {
            "name": "tcp.flags.push",
            "text": ".... .... 1... = Push: Set",
            "pos": 47,
            "size": 1,
            "note": "PSH: hand the data to the application now."
           },
           {
            "name": "tcp.flags.reset",
            "text": ".... .... .0.. = Reset: Not set",
            "pos": 47,
            "size": 1,
            "note": "RST: refuse or abort. A RST answering a SYN means nothing is listening on that port, or the application refuses this peer (a shut-down BGP neighbor does exactly this)."
           },
           {
            "name": "tcp.flags.syn",
            "text": ".... .... ..0. = Syn: Not set",
            "pos": 47,
            "size": 1,
            "note": "SYN: open a connection."
           },
           {
            "name": "tcp.flags.fin",
            "text": ".... .... ...0 = Fin: Not set",
            "pos": 47,
            "size": 1,
            "note": "FIN: this side has nothing more to send; a clean close."
           },
           {
            "name": "tcp.flags.str",
            "text": "TCP Flags: \u00b7\u00b7\u00b7\u00b7\u00b7\u00b7\u00b7AP\u00b7\u00b7\u00b7",
            "pos": 46,
            "size": 2
           }
          ]
         },
         {
          "name": "tcp.window_size_value",
          "text": "Window: 16308",
          "pos": 48,
          "size": 2,
          "note": "Receive window: how many bytes the sender can accept right now."
         },
         {
          "name": "tcp.window_size_scalefactor",
          "text": "Window size scaling factor: 1",
          "pos": 48,
          "size": 2
         },
         {
          "name": "tcp.checksum",
          "text": "Checksum: 0x8546 [unverified]",
          "pos": 50,
          "size": 2,
          "note": "Checksum over header + payload."
         },
         {
          "name": "tcp.urgent_pointer",
          "text": "Urgent Pointer: 0",
          "pos": 52,
          "size": 2,
          "note": "Unused by BGP."
         },
         {
          "name": "",
          "text": "Timestamps",
          "pos": 34,
          "size": 0
         }
        ]
       },
       {
        "proto": "bgp",
        "title": "Border Gateway Protocol - ROUTE-REFRESH Message",
        "pos": 54,
        "size": 23,
        "note": "Border Gateway Protocol: routers in different (eBGP) or the same (iBGP) autonomous systems swap reachability. Every message starts with the same 19-byte header: 16-byte marker, 2-byte length, 1-byte type.",
        "fields": [
         {
          "name": "bgp.marker",
          "text": "Marker: ffffffffffffffffffffffffffffffff",
          "pos": 54,
          "size": 16,
          "note": "16 bytes of 0xff. Kept for compatibility (it once carried authentication); every BGP message has it."
         },
         {
          "name": "bgp.length",
          "text": "Length: 23",
          "pos": 70,
          "size": 2,
          "note": "Whole BGP message length in bytes, header included. Minimum 19 (a KEEPALIVE), maximum 4096 (65535 with extended messages)."
         },
         {
          "name": "bgp.type",
          "text": "Type: ROUTE-REFRESH Message (5)",
          "pos": 72,
          "size": 1,
          "note": "ROUTE-REFRESH: asks the peer to resend its UPDATEs (soft inbound reset)."
         },
         {
          "name": "bgp.route_refresh.afi",
          "text": "Address family identifier (AFI): IPv4 (1)",
          "pos": 73,
          "size": 2,
          "note": "Address family of the refresh (1 = IPv4)."
         },
         {
          "name": "bgp.route_refresh.subtype",
          "text": "Subtype: Demarcation of the beginning of a route refresh (1)",
          "pos": 75,
          "size": 1,
          "note": "BoRR, Beginning of Route Refresh: everything after this is the resent table."
         },
         {
          "name": "bgp.route_refresh.safi",
          "text": "Subsequent address family identifier (SAFI): Unicast (1)",
          "pos": 76,
          "size": 1,
          "note": "Sub-family (1 = unicast)."
         }
        ]
       }
      ],
      "focus": "bgp"
     },
     {
      "n": 13,
      "kind": "BGP UPDATE",
      "t": 131.621,
      "clock": "11:14:00.298",
      "from": "ISPA-R1",
      "to": "HQ1-CORE-R1",
      "src": "100.100.255.1",
      "dst": "100.100.255.2",
      "frame": 121,
      "link": "HQ1-CORE-R1 Et0/2 <-> ISPA-R1 Et0/2",
      "len": 426,
      "summary": "Announces and/or withdraws prefixes. Withdrawn routes first, then the path attributes, then the prefixes (NLRI) that share them.",
      "layers": [
       {
        "proto": "eth",
        "title": "Ethernet II, Src: aa:bb:cc:00:12:20, Dst: aa:bb:cc:00:18:20",
        "pos": 0,
        "size": 14,
        "note": "Layer 2 frame. Only matters on this one wire: the next hop rewrites both MAC addresses.",
        "fields": [
         {
          "name": "eth.dst",
          "text": "Destination: aa:bb:cc:00:18:20",
          "pos": 0,
          "size": 6,
          "note": "Who on this wire should take the frame."
         },
         {
          "name": "eth.src",
          "text": "Source: aa:bb:cc:00:12:20",
          "pos": 6,
          "size": 6,
          "note": "Which interface put it on the wire."
         },
         {
          "name": "eth.type",
          "text": "Type: IPv4 (0x0800)",
          "pos": 12,
          "size": 2,
          "note": "What comes next: 0x0800 IPv4, 0x86dd IPv6, 0x8100 VLAN tag, 0x0806 ARP."
         }
        ]
       },
       {
        "proto": "ip",
        "title": "Internet Protocol Version 4, Src: 100.100.255.1, Dst: 100.100.255.2",
        "pos": 14,
        "size": 20,
        "note": "Layer 3 header. Source and destination stay the same end to end (unless NAT rewrites them); TTL drops by one per router.",
        "fields": [
         {
          "name": "ip.version",
          "text": "0100 .... = Version: 4",
          "pos": 14,
          "size": 1,
          "note": "4 = IPv4."
         },
         {
          "name": "ip.hdr_len",
          "text": ".... 0101 = Header Length: 20 bytes (5)",
          "pos": 14,
          "size": 1,
          "note": "Header length. 20 bytes means no IP options."
         },
         {
          "name": "ip.dsfield",
          "text": "Differentiated Services Field: 0xc0 (DSCP: CS6, ECN: Not-ECT)",
          "pos": 15,
          "size": 1,
          "note": "DSCP + ECN. Routers mark control traffic like BGP CS6 (DSCP 48, byte 0xc0) so QoS keeps it alive under load.",
          "children": [
           {
            "name": "ip.dsfield.dscp",
            "text": "1100 00.. = Differentiated Services Codepoint: Class Selector 6 (48)",
            "pos": 15,
            "size": 1,
            "note": "DSCP class. 48 = CS6, the class for routing protocols."
           },
           {
            "name": "ip.dsfield.ecn",
            "text": ".... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0)",
            "pos": 15,
            "size": 1
           }
          ]
         },
         {
          "name": "ip.len",
          "text": "Total Length: 412",
          "pos": 16,
          "size": 2,
          "note": "Total IP packet length (header + payload)."
         },
         {
          "name": "ip.id",
          "text": "Identification: 0xd9bb (55739)",
          "pos": 18,
          "size": 2,
          "note": "Identification. Unique per packet from a sender; also how you match the same packet in two captures."
         },
         {
          "name": "ip.flags",
          "text": "010. .... = Flags: 0x2, Don't fragment",
          "pos": 20,
          "size": 1,
          "note": "Fragmentation flags. DF set = routers must not fragment it.",
          "children": [
           {
            "name": "ip.flags.rb",
            "text": "0... .... = Reserved bit: Not set",
            "pos": 20,
            "size": 1
           },
           {
            "name": "ip.flags.df",
            "text": ".1.. .... = Don't fragment: Set",
            "pos": 20,
            "size": 1,
            "note": "Don't Fragment. If the packet is too big for a link it is dropped and an ICMP 'fragmentation needed' comes back."
           },
           {
            "name": "ip.flags.mf",
            "text": "..0. .... = More fragments: Not set",
            "pos": 20,
            "size": 1
           }
          ]
         },
         {
          "name": "ip.frag_offset",
          "text": "...0 0000 0000 0000 = Fragment Offset: 0",
          "pos": 20,
          "size": 2,
          "note": "Where this fragment sits in the original packet. 0 = not fragmented (or first piece)."
         },
         {
          "name": "ip.ttl",
          "text": "Time to Live: 1",
          "pos": 22,
          "size": 1,
          "note": "Time to live. Each router subtracts one; at 0 the packet dies and ICMP time-exceeded goes back. eBGP peers default to TTL 1 (directly connected) unless ebgp-multihop or ttl-security is set."
         },
         {
          "name": "ip.proto",
          "text": "Protocol: TCP (6)",
          "pos": 23,
          "size": 1,
          "note": "What the payload is: 1 ICMP, 6 TCP, 17 UDP, 50 ESP, 89 OSPF, 88 EIGRP."
         },
         {
          "name": "ip.checksum",
          "text": "Header Checksum: 0xd713 [validation disabled]",
          "pos": 24,
          "size": 2,
          "note": "Header checksum, recomputed by every router because TTL changes."
         },
         {
          "name": "ip.src",
          "text": "Source Address: 100.100.255.1",
          "pos": 26,
          "size": 4,
          "note": "Original sender."
         },
         {
          "name": "ip.dst",
          "text": "Destination Address: 100.100.255.2",
          "pos": 30,
          "size": 4,
          "note": "Final destination."
         }
        ]
       },
       {
        "proto": "tcp",
        "title": "Transmission Control Protocol, Src Port: 179, Dst Port: 21381, Seq: 100, Ack: 77, Len: 372",
        "pos": 34,
        "size": 20,
        "note": "Transport. BGP rides TCP port 179, so every BGP message is acknowledged, ordered and resent by TCP, not by BGP.",
        "fields": [
         {
          "name": "tcp.len",
          "text": "TCP Segment Len: 372",
          "pos": 34,
          "size": 0,
          "note": "Payload bytes in this segment. 0 = a pure ACK or control segment."
         },
         {
          "name": "tcp.seq",
          "text": "Sequence Number: 100    (relative sequence number)",
          "pos": 38,
          "size": 4,
          "note": "Sequence number (relative): byte position of this segment's first data byte."
         },
         {
          "name": "tcp.ack",
          "text": "Acknowledgment Number: 77    (relative ack number)",
          "pos": 42,
          "size": 4,
          "note": "Acknowledgement: the next byte this side expects from the other."
         },
         {
          "name": "tcp.hdr_len",
          "text": "0101 .... = Header Length: 20 bytes (5)",
          "pos": 46,
          "size": 1,
          "note": "TCP header length. 20 = no options; 32 = timestamps; larger on a SYN with MSS / window scale / SACK."
         },
         {
          "name": "tcp.flags",
          "text": "Flags: 0x018 (PSH, ACK)",
          "pos": 46,
          "size": 2,
          "note": "Control bits. SYN opens, FIN closes cleanly, RST aborts, ACK acknowledges, PSH says deliver now.",
          "children": [
           {
            "name": "tcp.flags.res",
            "text": "000. .... .... = Reserved: Not set",
            "pos": 46,
            "size": 1
           },
           {
            "name": "tcp.flags.ae",
            "text": "...0 .... .... = Accurate ECN: Not set",
            "pos": 46,
            "size": 1
           },
           {
            "name": "tcp.flags.cwr",
            "text": ".... 0... .... = Congestion Window Reduced: Not set",
            "pos": 47,
            "size": 1
           },
           {
            "name": "tcp.flags.ece",
            "text": ".... .0.. .... = ECN-Echo: Not set",
            "pos": 47,
            "size": 1
           },
           {
            "name": "tcp.flags.urg",
            "text": ".... ..0. .... = Urgent: Not set",
            "pos": 47,
            "size": 1
           },
           {
            "name": "tcp.flags.ack",
            "text": ".... ...1 .... = Acknowledgment: Set",
            "pos": 47,
            "size": 1,
            "note": "ACK: the acknowledgement number is valid."
           },
           {
            "name": "tcp.flags.push",
            "text": ".... .... 1... = Push: Set",
            "pos": 47,
            "size": 1,
            "note": "PSH: hand the data to the application now."
           },
           {
            "name": "tcp.flags.reset",
            "text": ".... .... .0.. = Reset: Not set",
            "pos": 47,
            "size": 1,
            "note": "RST: refuse or abort. A RST answering a SYN means nothing is listening on that port, or the application refuses this peer (a shut-down BGP neighbor does exactly this)."
           },
           {
            "name": "tcp.flags.syn",
            "text": ".... .... ..0. = Syn: Not set",
            "pos": 47,
            "size": 1,
            "note": "SYN: open a connection."
           },
           {
            "name": "tcp.flags.fin",
            "text": ".... .... ...0 = Fin: Not set",
            "pos": 47,
            "size": 1,
            "note": "FIN: this side has nothing more to send; a clean close."
           },
           {
            "name": "tcp.flags.str",
            "text": "TCP Flags: \u00b7\u00b7\u00b7\u00b7\u00b7\u00b7\u00b7AP\u00b7\u00b7\u00b7",
            "pos": 46,
            "size": 2
           }
          ]
         },
         {
          "name": "tcp.window_size_value",
          "text": "Window: 16308",
          "pos": 48,
          "size": 2,
          "note": "Receive window: how many bytes the sender can accept right now."
         },
         {
          "name": "tcp.window_size_scalefactor",
          "text": "Window size scaling factor: 1",
          "pos": 48,
          "size": 2
         },
         {
          "name": "tcp.checksum",
          "text": "Checksum: 0xfd45 [unverified]",
          "pos": 50,
          "size": 2,
          "note": "Checksum over header + payload."
         },
         {
          "name": "tcp.urgent_pointer",
          "text": "Urgent Pointer: 0",
          "pos": 52,
          "size": 2,
          "note": "Unused by BGP."
         },
         {
          "name": "",
          "text": "Timestamps",
          "pos": 34,
          "size": 0
         }
        ]
       },
       {
        "proto": "bgp",
        "title": "Border Gateway Protocol - UPDATE Message",
        "pos": 54,
        "size": 51,
        "note": "Border Gateway Protocol: routers in different (eBGP) or the same (iBGP) autonomous systems swap reachability. Every message starts with the same 19-byte header: 16-byte marker, 2-byte length, 1-byte type.",
        "fields": [
         {
          "name": "bgp.marker",
          "text": "Marker: ffffffffffffffffffffffffffffffff",
          "pos": 54,
          "size": 16,
          "note": "16 bytes of 0xff. Kept for compatibility (it once carried authentication); every BGP message has it."
         },
         {
          "name": "bgp.length",
          "text": "Length: 51",
          "pos": 70,
          "size": 2,
          "note": "Whole BGP message length in bytes, header included. Minimum 19 (a KEEPALIVE), maximum 4096 (65535 with extended messages)."
         },
         {
          "name": "bgp.type",
          "text": "Type: UPDATE Message (2)",
          "pos": 72,
          "size": 1,
          "note": "UPDATE: announces prefixes (with their path attributes) and/or withdraws prefixes."
         },
         {
          "name": "bgp.update.withdrawn_routes.length",
          "text": "Withdrawn Routes Length: 0",
          "pos": 73,
          "size": 2,
          "note": "Bytes of withdrawn prefixes that follow. 0 = this UPDATE withdraws nothing."
         },
         {
          "name": "bgp.update.path_attributes.length",
          "text": "Total Path Attribute Length: 24",
          "pos": 75,
          "size": 2,
          "note": "Bytes of path attributes. 0 = a pure withdraw."
         },
         {
          "name": "bgp.update.path_attributes",
          "text": "Path attributes",
          "pos": 77,
          "size": 24,
          "children": [
           {
            "name": "bgp.update.path_attribute",
            "text": "Path Attribute - ORIGIN: IGP",
            "pos": 77,
            "size": 4,
            "note": "ORIGIN attribute (well-known, mandatory).",
            "children": [
             {
              "name": "bgp.update.path_attribute.flags",
              "text": "Flags: 0x40, Transitive, Well-known, Complete",
              "pos": 77,
              "size": 1,
              "note": "Attribute flags: Optional (vs well-known), Transitive (pass it on), Partial, Extended length.",
              "children": [
               {
                "name": "bgp.update.path_attribute.flags.optional",
                "text": "0... .... = Optional: Not set",
                "pos": 77,
                "size": 1,
                "note": "Well-known attributes (ORIGIN, AS_PATH, NEXT_HOP, LOCAL_PREF) must be understood by every BGP router; optional ones (MED, communities) may not be."
               },
               {
                "name": "bgp.update.path_attribute.flags.transitive",
                "text": ".1.. .... = Transitive: Set",
                "pos": 77,
                "size": 1,
                "note": "Transitive: a router that doesn't understand an optional attribute still passes it on."
               },
               {
                "name": "bgp.update.path_attribute.flags.partial",
                "text": "..0. .... = Partial: Not set",
                "pos": 77,
                "size": 1
               },
               {
                "name": "bgp.update.path_attribute.flags.extended_length",
                "text": "...0 .... = Extended-Length: Not set",
                "pos": 77,
                "size": 1
               },
               {
                "name": "bgp.update.path_attribute.flags.unused",
                "text": ".... 0000 = Unused: 0x0",
                "pos": 77,
                "size": 1
               }
              ]
             },
             {
              "name": "bgp.update.path_attribute.type_code",
              "text": "Type Code: ORIGIN (1)",
              "pos": 78,
              "size": 1,
              "note": "Which attribute: 1 ORIGIN, 2 AS_PATH, 3 NEXT_HOP, 4 MED, 5 LOCAL_PREF, 8 COMMUNITIES."
             },
             {
              "name": "bgp.update.path_attribute.length",
              "text": "Length: 1",
              "pos": 79,
              "size": 1
             },
             {
              "name": "bgp.update.path_attribute.origin",
              "text": "Origin: IGP (0)",
              "pos": 80,
              "size": 1,
              "note": "How the route entered BGP: IGP (network statement), EGP, or Incomplete (redistributed). Best path prefers IGP < EGP < Incomplete."
             }
            ]
           },
           {
            "name": "bgp.update.path_attribute",
            "text": "Path Attribute - AS_PATH: 65100 65002 ",
            "pos": 81,
            "size": 13,
            "note": "AS_PATH: every AS the route passed through. Shorter wins in best-path (after weight, local-pref, locally originated).",
            "children": [
             {
              "name": "bgp.update.path_attribute.flags",
              "text": "Flags: 0x40, Transitive, Well-known, Complete",
              "pos": 81,
              "size": 1,
              "note": "Attribute flags: Optional (vs well-known), Transitive (pass it on), Partial, Extended length.",
              "children": [
               {
                "name": "bgp.update.path_attribute.flags.optional",
                "text": "0... .... = Optional: Not set",
                "pos": 81,
                "size": 1,
                "note": "Well-known attributes (ORIGIN, AS_PATH, NEXT_HOP, LOCAL_PREF) must be understood by every BGP router; optional ones (MED, communities) may not be."
               },
               {
                "name": "bgp.update.path_attribute.flags.transitive",
                "text": ".1.. .... = Transitive: Set",
                "pos": 81,
                "size": 1,
                "note": "Transitive: a router that doesn't understand an optional attribute still passes it on."
               },
               {
                "name": "bgp.update.path_attribute.flags.partial",
                "text": "..0. .... = Partial: Not set",
                "pos": 81,
                "size": 1
               },
               {
                "name": "bgp.update.path_attribute.flags.extended_length",
                "text": "...0 .... = Extended-Length: Not set",
                "pos": 81,
                "size": 1
               },
               {
                "name": "bgp.update.path_attribute.flags.unused",
                "text": ".... 0000 = Unused: 0x0",
                "pos": 81,
                "size": 1
               }
              ]
             },
             {
              "name": "bgp.update.path_attribute.type_code",
              "text": "Type Code: AS_PATH (2)",
              "pos": 82,
              "size": 1,
              "note": "Which attribute: 1 ORIGIN, 2 AS_PATH, 3 NEXT_HOP, 4 MED, 5 LOCAL_PREF, 8 COMMUNITIES."
             },
             {
              "name": "bgp.update.path_attribute.length",
              "text": "Length: 10",
              "pos": 83,
              "size": 1
             },
             {
              "name": "bgp.update.path_attribute.as_path_segment",
              "text": "AS Path segment: 65100 65002",
              "pos": 84,
              "size": 10,
              "children": [
               {
                "name": "bgp.update.path_attribute.as_path_segment.type",
                "text": "Segment type: AS_SEQUENCE (2)",
                "pos": 84,
                "size": 1,
                "note": "AS_SEQUENCE = ordered list of ASes the route crossed; AS_SET = an unordered set (from aggregation)."
               },
               {
                "name": "bgp.update.path_attribute.as_path_segment.length",
                "text": "Segment length (number of ASN): 2",
                "pos": 85,
                "size": 1,
                "note": "How many AS numbers follow."
               },
               {
                "name": "bgp.update.path_attribute.as_path_segment.as4",
                "text": "AS4: 65100",
                "pos": 86,
                "size": 4,
                "note": "One AS on the path, newest first: the leftmost AS is the neighbor that sent it, the rightmost is where the route started. A router that finds its own AS in the path drops the route (loop prevention)."
               },
               {
                "name": "bgp.update.path_attribute.as_path_segment.as4",
                "text": "AS4: 65002",
                "pos": 90,
                "size": 4,
                "note": "One AS on the path, newest first: the leftmost AS is the neighbor that sent it, the rightmost is where the route started. A router that finds its own AS in the path drops the route (loop prevention)."
               }
              ]
             }
            ]
           },
           {
            "name": "bgp.update.path_attribute",
            "text": "Path Attribute - NEXT_HOP: 100.100.255.1 ",
            "pos": 94,
            "size": 7,
            "note": "NEXT_HOP attribute (well-known, mandatory).",
            "children": [
             {
              "name": "bgp.update.path_attribute.flags",
              "text": "Flags: 0x40, Transitive, Well-known, Complete",
              "pos": 94,
              "size": 1,
              "note": "Attribute flags: Optional (vs well-known), Transitive (pass it on), Partial, Extended length.",
              "children": [
               {
                "name": "bgp.update.path_attribute.flags.optional",
                "text": "0... .... = Optional: Not set",
                "pos": 94,
                "size": 1,
                "note": "Well-known attributes (ORIGIN, AS_PATH, NEXT_HOP, LOCAL_PREF) must be understood by every BGP router; optional ones (MED, communities) may not be."
               },
               {
                "name": "bgp.update.path_attribute.flags.transitive",
                "text": ".1.. .... = Transitive: Set",
                "pos": 94,
                "size": 1,
                "note": "Transitive: a router that doesn't understand an optional attribute still passes it on."
               },
               {
                "name": "bgp.update.path_attribute.flags.partial",
                "text": "..0. .... = Partial: Not set",
                "pos": 94,
                "size": 1
               },
               {
                "name": "bgp.update.path_attribute.flags.extended_length",
                "text": "...0 .... = Extended-Length: Not set",
                "pos": 94,
                "size": 1
               },
               {
                "name": "bgp.update.path_attribute.flags.unused",
                "text": ".... 0000 = Unused: 0x0",
                "pos": 94,
                "size": 1
               }
              ]
             },
             {
              "name": "bgp.update.path_attribute.type_code",
              "text": "Type Code: NEXT_HOP (3)",
              "pos": 95,
              "size": 1,
              "note": "Which attribute: 1 ORIGIN, 2 AS_PATH, 3 NEXT_HOP, 4 MED, 5 LOCAL_PREF, 8 COMMUNITIES."
             },
             {
              "name": "bgp.update.path_attribute.length",
              "text": "Length: 4",
              "pos": 96,
              "size": 1
             },
             {
              "name": "bgp.update.path_attribute.next_hop",
              "text": "Next hop: 100.100.255.1",
              "pos": 97,
              "size": 4,
              "note": "Where to send traffic for these prefixes. eBGP sets it to the sender's own address; iBGP passes it through unless next-hop-self."
             }
            ]
           }
          ]
         },
         {
          "name": "bgp.update.nlri",
          "text": "Network Layer Reachability Information (NLRI)",
          "pos": 101,
          "size": 4,
          "note": "NLRI: the prefixes this UPDATE announces, all sharing the attributes above.",
          "children": [
           {
            "name": "",
            "text": "203.0.113.0/24",
            "pos": 101,
            "size": 4,
            "children": [
             {
              "name": "bgp.prefix_length",
              "text": "NLRI prefix length: 24",
              "pos": 101,
              "size": 1,
              "note": "Prefix length in bits. Only as many address bytes as needed follow (a /25 needs 4)."
             },
             {
              "name": "bgp.nlri_prefix",
              "text": "NLRI prefix: 203.0.113.0",
              "pos": 102,
              "size": 3,
              "note": "The prefix being announced."
             }
            ]
           }
          ]
         }
        ]
       },
       {
        "proto": "bgp",
        "title": "Border Gateway Protocol - UPDATE Message",
        "pos": 105,
        "size": 68,
        "note": "Border Gateway Protocol: routers in different (eBGP) or the same (iBGP) autonomous systems swap reachability. Every message starts with the same 19-byte header: 16-byte marker, 2-byte length, 1-byte type.",
        "fields": [
         {
          "name": "bgp.marker",
          "text": "Marker: ffffffffffffffffffffffffffffffff",
          "pos": 105,
          "size": 16,
          "note": "16 bytes of 0xff. Kept for compatibility (it once carried authentication); every BGP message has it."
         },
         {
          "name": "bgp.length",
          "text": "Length: 68",
          "pos": 121,
          "size": 2,
          "note": "Whole BGP message length in bytes, header included. Minimum 19 (a KEEPALIVE), maximum 4096 (65535 with extended messages)."
         },
         {
          "name": "bgp.type",
          "text": "Type: UPDATE Message (2)",
          "pos": 123,
          "size": 1,
          "note": "UPDATE: announces prefixes (with their path attributes) and/or withdraws prefixes."
         },
         {
          "name": "bgp.update.withdrawn_routes.length",
          "text": "Withdrawn Routes Length: 0",
          "pos": 124,
          "size": 2,
          "note": "Bytes of withdrawn prefixes that follow. 0 = this UPDATE withdraws nothing."
         },
         {
          "name": "bgp.update.path_attributes.length",
          "text": "Total Path Attribute Length: 40",
          "pos": 126,
          "size": 2,
          "note": "Bytes of path attributes. 0 = a pure withdraw."
         },
         {
          "name": "bgp.update.path_attributes",
          "text": "Path attributes",
          "pos": 128,
          "size": 40,
          "children": [
           {
            "name": "bgp.update.path_attribute",
            "text": "Path Attribute - ORIGIN: IGP",
            "pos": 128,
            "size": 4,
            "note": "ORIGIN attribute (well-known, mandatory).",
            "children": [
             {
              "name": "bgp.update.path_attribute.flags",
              "text": "Flags: 0x40, Transitive, Well-known, Complete",
              "pos": 128,
              "size": 1,
              "note": "Attribute flags: Optional (vs well-known), Transitive (pass it on), Partial, Extended length.",
              "children": [
               {
                "name": "bgp.update.path_attribute.flags.optional",
                "text": "0... .... = Optional: Not set",
                "pos": 128,
                "size": 1,
                "note": "Well-known attributes (ORIGIN, AS_PATH, NEXT_HOP, LOCAL_PREF) must be understood by every BGP router; optional ones (MED, communities) may not be."
               },
               {
                "name": "bgp.update.path_attribute.flags.transitive",
                "text": ".1.. .... = Transitive: Set",
                "pos": 128,
                "size": 1,
                "note": "Transitive: a router that doesn't understand an optional attribute still passes it on."
               },
               {
                "name": "bgp.update.path_attribute.flags.partial",
                "text": "..0. .... = Partial: Not set",
                "pos": 128,
                "size": 1
               },
               {
                "name": "bgp.update.path_attribute.flags.extended_length",
                "text": "...0 .... = Extended-Length: Not set",
                "pos": 128,
                "size": 1
               },
               {
                "name": "bgp.update.path_attribute.flags.unused",
                "text": ".... 0000 = Unused: 0x0",
                "pos": 128,
                "size": 1
               }
              ]
             },
             {
              "name": "bgp.update.path_attribute.type_code",
              "text": "Type Code: ORIGIN (1)",
              "pos": 129,
              "size": 1,
              "note": "Which attribute: 1 ORIGIN, 2 AS_PATH, 3 NEXT_HOP, 4 MED, 5 LOCAL_PREF, 8 COMMUNITIES."
             },
             {
              "name": "bgp.update.path_attribute.length",
              "text": "Length: 1",
              "pos": 130,
              "size": 1
             },
             {
              "name": "bgp.update.path_attribute.origin",
              "text": "Origin: IGP (0)",
              "pos": 131,
              "size": 1,
              "note": "How the route entered BGP: IGP (network statement), EGP, or Incomplete (redistributed). Best path prefers IGP < EGP < Incomplete."
             }
            ]
           },
           {
            "name": "bgp.update.path_attribute",
            "text": "Path Attribute - AS_PATH: 65100 65200 65001 65001 65001 65001 ",
            "pos": 132,
            "size": 29,
            "note": "AS_PATH: every AS the route passed through. Shorter wins in best-path (after weight, local-pref, locally originated).",
            "children": [
             {
              "name": "bgp.update.path_attribute.flags",
              "text": "Flags: 0x40, Transitive, Well-known, Complete",
              "pos": 132,
              "size": 1,
              "note": "Attribute flags: Optional (vs well-known), Transitive (pass it on), Partial, Extended length.",
              "children": [
               {
                "name": "bgp.update.path_attribute.flags.optional",
                "text": "0... .... = Optional: Not set",
                "pos": 132,
                "size": 1,
                "note": "Well-known attributes (ORIGIN, AS_PATH, NEXT_HOP, LOCAL_PREF) must be understood by every BGP router; optional ones (MED, communities) may not be."
               },
               {
                "name": "bgp.update.path_attribute.flags.transitive",
                "text": ".1.. .... = Transitive: Set",
                "pos": 132,
                "size": 1,
                "note": "Transitive: a router that doesn't understand an optional attribute still passes it on."
               },
               {
                "name": "bgp.update.path_attribute.flags.partial",
                "text": "..0. .... = Partial: Not set",
                "pos": 132,
                "size": 1
               },
               {
                "name": "bgp.update.path_attribute.flags.extended_length",
                "text": "...0 .... = Extended-Length: Not set",
                "pos": 132,
                "size": 1
               },
               {
                "name": "bgp.update.path_attribute.flags.unused",
                "text": ".... 0000 = Unused: 0x0",
                "pos": 132,
                "size": 1
               }
              ]
             },
             {
              "name": "bgp.update.path_attribute.type_code",
              "text": "Type Code: AS_PATH (2)",
              "pos": 133,
              "size": 1,
              "note": "Which attribute: 1 ORIGIN, 2 AS_PATH, 3 NEXT_HOP, 4 MED, 5 LOCAL_PREF, 8 COMMUNITIES."
             },
             {
              "name": "bgp.update.path_attribute.length",
              "text": "Length: 26",
              "pos": 134,
              "size": 1
             },
             {
              "name": "bgp.update.path_attribute.as_path_segment",
              "text": "AS Path segment: 65100 65200 65001 65001 65001 65001",
              "pos": 135,
              "size": 26,
              "children": [
               {
                "name": "bgp.update.path_attribute.as_path_segment.type",
                "text": "Segment type: AS_SEQUENCE (2)",
                "pos": 135,
                "size": 1,
                "note": "AS_SEQUENCE = ordered list of ASes the route crossed; AS_SET = an unordered set (from aggregation)."
               },
               {
                "name": "bgp.update.path_attribute.as_path_segment.length",
                "text": "Segment length (number of ASN): 6",
                "pos": 136,
                "size": 1,
                "note": "How many AS numbers follow."
               },
               {
                "name": "bgp.update.path_attribute.as_path_segment.as4",
                "text": "AS4: 65100",
                "pos": 137,
                "size": 4,
                "note": "One AS on the path, newest first: the leftmost AS is the neighbor that sent it, the rightmost is where the route started. A router that finds its own AS in the path drops the route (loop prevention)."
               },
               {
                "name": "bgp.update.path_attribute.as_path_segment.as4",
                "text": "AS4: 65200",
                "pos": 141,
                "size": 4,
                "note": "One AS on the path, newest first: the leftmost AS is the neighbor that sent it, the rightmost is where the route started. A router that finds its own AS in the path drops the route (loop prevention)."
               },
               {
                "name": "bgp.update.path_attribute.as_path_segment.as4",
                "text": "AS4: 65001",
                "pos": 145,
                "size": 4,
                "note": "One AS on the path, newest first: the leftmost AS is the neighbor that sent it, the rightmost is where the route started. A router that finds its own AS in the path drops the route (loop prevention)."
               },
               {
                "name": "bgp.update.path_attribute.as_path_segment.as4",
                "text": "AS4: 65001",
                "pos": 149,
                "size": 4,
                "note": "One AS on the path, newest first: the leftmost AS is the neighbor that sent it, the rightmost is where the route started. A router that finds its own AS in the path drops the route (loop prevention)."
               },
               {
                "name": "bgp.update.path_attribute.as_path_segment.as4",
                "text": "AS4: 65001",
                "pos": 153,
                "size": 4,
                "note": "One AS on the path, newest first: the leftmost AS is the neighbor that sent it, the rightmost is where the route started. A router that finds its own AS in the path drops the route (loop prevention)."
               },
               {
                "name": "bgp.update.path_attribute.as_path_segment.as4",
                "text": "AS4: 65001",
                "pos": 157,
                "size": 4,
                "note": "One AS on the path, newest first: the leftmost AS is the neighbor that sent it, the rightmost is where the route started. A router that finds its own AS in the path drops the route (loop prevention)."
               }
              ]
             }
            ]
           },
           {
            "name": "bgp.update.path_attribute",
            "text": "Path Attribute - NEXT_HOP: 100.100.255.1 ",
            "pos": 161,
            "size": 7,
            "note": "NEXT_HOP attribute (well-known, mandatory).",
            "children": [
             {
              "name": "bgp.update.path_attribute.flags",
              "text": "Flags: 0x40, Transitive, Well-known, Complete",
              "pos": 161,
              "size": 1,
              "note": "Attribute flags: Optional (vs well-known), Transitive (pass it on), Partial, Extended length.",
              "children": [
               {
                "name": "bgp.update.path_attribute.flags.optional",
                "text": "0... .... = Optional: Not set",
                "pos": 161,
                "size": 1,
                "note": "Well-known attributes (ORIGIN, AS_PATH, NEXT_HOP, LOCAL_PREF) must be understood by every BGP router; optional ones (MED, communities) may not be."
               },
               {
                "name": "bgp.update.path_attribute.flags.transitive",
                "text": ".1.. .... = Transitive: Set",
                "pos": 161,
                "size": 1,
                "note": "Transitive: a router that doesn't understand an optional attribute still passes it on."
               },
               {
                "name": "bgp.update.path_attribute.flags.partial",
                "text": "..0. .... = Partial: Not set",
                "pos": 161,
                "size": 1
               },
               {
                "name": "bgp.update.path_attribute.flags.extended_length",
                "text": "...0 .... = Extended-Length: Not set",
                "pos": 161,
                "size": 1
               },
               {
                "name": "bgp.update.path_attribute.flags.unused",
                "text": ".... 0000 = Unused: 0x0",
                "pos": 161,
                "size": 1
               }
              ]
             },
             {
              "name": "bgp.update.path_attribute.type_code",
              "text": "Type Code: NEXT_HOP (3)",
              "pos": 162,
              "size": 1,
              "note": "Which attribute: 1 ORIGIN, 2 AS_PATH, 3 NEXT_HOP, 4 MED, 5 LOCAL_PREF, 8 COMMUNITIES."
             },
             {
              "name": "bgp.update.path_attribute.length",
              "text": "Length: 4",
              "pos": 163,
              "size": 1
             },
             {
              "name": "bgp.update.path_attribute.next_hop",
              "text": "Next hop: 100.100.255.1",
              "pos": 164,
              "size": 4,
              "note": "Where to send traffic for these prefixes. eBGP sets it to the sender's own address; iBGP passes it through unless next-hop-self."
             }
            ]
           }
          ]
         },
         {
          "name": "bgp.update.nlri",
          "text": "Network Layer Reachability Information (NLRI)",
          "pos": 168,
          "size": 5,
          "note": "NLRI: the prefixes this UPDATE announces, all sharing the attributes above.",
          "children": [
           {
            "name": "",
            "text": "198.51.100.0/25",
            "pos": 168,
            "size": 5,
            "children": [
             {
              "name": "bgp.prefix_length",
              "text": "NLRI prefix length: 25",
              "pos": 168,
              "size": 1,
              "note": "Prefix length in bits. Only as many address bytes as needed follow (a /25 needs 4)."
             },
             {
              "name": "bgp.nlri_prefix",
              "text": "NLRI prefix: 198.51.100.0",
              "pos": 169,
              "size": 4,
              "note": "The prefix being announced."
             }
            ]
           }
          ]
         }
        ]
       },
       {
        "proto": "bgp",
        "title": "Border Gateway Protocol - UPDATE Message",
        "pos": 173,
        "size": 60,
        "note": "Border Gateway Protocol: routers in different (eBGP) or the same (iBGP) autonomous systems swap reachability. Every message starts with the same 19-byte header: 16-byte marker, 2-byte length, 1-byte type.",
        "fields": [
         {
          "name": "bgp.marker",
          "text": "Marker: ffffffffffffffffffffffffffffffff",
          "pos": 173,
          "size": 16,
          "note": "16 bytes of 0xff. Kept for compatibility (it once carried authentication); every BGP message has it."
         },
         {
          "name": "bgp.length",
          "text": "Length: 60",
          "pos": 189,
          "size": 2,
          "note": "Whole BGP message length in bytes, header included. Minimum 19 (a KEEPALIVE), maximum 4096 (65535 with extended messages)."
         },
         {
          "name": "bgp.type",
          "text": "Type: UPDATE Message (2)",
          "pos": 191,
          "size": 1,
          "note": "UPDATE: announces prefixes (with their path attributes) and/or withdraws prefixes."
         },
         {
          "name": "bgp.update.withdrawn_routes.length",
          "text": "Withdrawn Routes Length: 0",
          "pos": 192,
          "size": 2,
          "note": "Bytes of withdrawn prefixes that follow. 0 = this UPDATE withdraws nothing."
         },
         {
          "name": "bgp.update.path_attributes.length",
          "text": "Total Path Attribute Length: 28",
          "pos": 194,
          "size": 2,
          "note": "Bytes of path attributes. 0 = a pure withdraw."
         },
         {
          "name": "bgp.update.path_attributes",
          "text": "Path attributes",
          "pos": 196,
          "size": 28,
          "children": [
           {
            "name": "bgp.update.path_attribute",
            "text": "Path Attribute - ORIGIN: IGP",
            "pos": 196,
            "size": 4,
            "note": "ORIGIN attribute (well-known, mandatory).",
            "children": [
             {
              "name": "bgp.update.path_attribute.flags",
              "text": "Flags: 0x40, Transitive, Well-known, Complete",
              "pos": 196,
              "size": 1,
              "note": "Attribute flags: Optional (vs well-known), Transitive (pass it on), Partial, Extended length.",
              "children": [
               {
                "name": "bgp.update.path_attribute.flags.optional",
                "text": "0... .... = Optional: Not set",
                "pos": 196,
                "size": 1,
                "note": "Well-known attributes (ORIGIN, AS_PATH, NEXT_HOP, LOCAL_PREF) must be understood by every BGP router; optional ones (MED, communities) may not be."
               },
               {
                "name": "bgp.update.path_attribute.flags.transitive",
                "text": ".1.. .... = Transitive: Set",
                "pos": 196,
                "size": 1,
                "note": "Transitive: a router that doesn't understand an optional attribute still passes it on."
               },
               {
                "name": "bgp.update.path_attribute.flags.partial",
                "text": "..0. .... = Partial: Not set",
                "pos": 196,
                "size": 1
               },
               {
                "name": "bgp.update.path_attribute.flags.extended_length",
                "text": "...0 .... = Extended-Length: Not set",
                "pos": 196,
                "size": 1
               },
               {
                "name": "bgp.update.path_attribute.flags.unused",
                "text": ".... 0000 = Unused: 0x0",
                "pos": 196,
                "size": 1
               }
              ]
             },
             {
              "name": "bgp.update.path_attribute.type_code",
              "text": "Type Code: ORIGIN (1)",
              "pos": 197,
              "size": 1,
              "note": "Which attribute: 1 ORIGIN, 2 AS_PATH, 3 NEXT_HOP, 4 MED, 5 LOCAL_PREF, 8 COMMUNITIES."
             },
             {
              "name": "bgp.update.path_attribute.length",
              "text": "Length: 1",
              "pos": 198,
              "size": 1
             },
             {
              "name": "bgp.update.path_attribute.origin",
              "text": "Origin: IGP (0)",
              "pos": 199,
              "size": 1,
              "note": "How the route entered BGP: IGP (network statement), EGP, or Incomplete (redistributed). Best path prefers IGP < EGP < Incomplete."
             }
            ]
           },
           {
            "name": "bgp.update.path_attribute",
            "text": "Path Attribute - AS_PATH: 65100 65200 65001 ",
            "pos": 200,
            "size": 17,
            "note": "AS_PATH: every AS the route passed through. Shorter wins in best-path (after weight, local-pref, locally originated).",
            "children": [
             {
              "name": "bgp.update.path_attribute.flags",
              "text": "Flags: 0x40, Transitive, Well-known, Complete",
              "pos": 200,
              "size": 1,
              "note": "Attribute flags: Optional (vs well-known), Transitive (pass it on), Partial, Extended length.",
              "children": [
               {
                "name": "bgp.update.path_attribute.flags.optional",
                "text": "0... .... = Optional: Not set",
                "pos": 200,
                "size": 1,
                "note": "Well-known attributes (ORIGIN, AS_PATH, NEXT_HOP, LOCAL_PREF) must be understood by every BGP router; optional ones (MED, communities) may not be."
               },
               {
                "name": "bgp.update.path_attribute.flags.transitive",
                "text": ".1.. .... = Transitive: Set",
                "pos": 200,
                "size": 1,
                "note": "Transitive: a router that doesn't understand an optional attribute still passes it on."
               },
               {
                "name": "bgp.update.path_attribute.flags.partial",
                "text": "..0. .... = Partial: Not set",
                "pos": 200,
                "size": 1
               },
               {
                "name": "bgp.update.path_attribute.flags.extended_length",
                "text": "...0 .... = Extended-Length: Not set",
                "pos": 200,
                "size": 1
               },
               {
                "name": "bgp.update.path_attribute.flags.unused",
                "text": ".... 0000 = Unused: 0x0",
                "pos": 200,
                "size": 1
               }
              ]
             },
             {
              "name": "bgp.update.path_attribute.type_code",
              "text": "Type Code: AS_PATH (2)",
              "pos": 201,
              "size": 1,
              "note": "Which attribute: 1 ORIGIN, 2 AS_PATH, 3 NEXT_HOP, 4 MED, 5 LOCAL_PREF, 8 COMMUNITIES."
             },
             {
              "name": "bgp.update.path_attribute.length",
              "text": "Length: 14",
              "pos": 202,
              "size": 1
             },
             {
              "name": "bgp.update.path_attribute.as_path_segment",
              "text": "AS Path segment: 65100 65200 65001",
              "pos": 203,
              "size": 14,
              "children": [
               {
                "name": "bgp.update.path_attribute.as_path_segment.type",
                "text": "Segment type: AS_SEQUENCE (2)",
                "pos": 203,
                "size": 1,
                "note": "AS_SEQUENCE = ordered list of ASes the route crossed; AS_SET = an unordered set (from aggregation)."
               },
               {
                "name": "bgp.update.path_attribute.as_path_segment.length",
                "text": "Segment length (number of ASN): 3",
                "pos": 204,
                "size": 1,
                "note": "How many AS numbers follow."
               },
               {
                "name": "bgp.update.path_attribute.as_path_segment.as4",
                "text": "AS4: 65100",
                "pos": 205,
                "size": 4,
                "note": "One AS on the path, newest first: the leftmost AS is the neighbor that sent it, the rightmost is where the route started. A router that finds its own AS in the path drops the route (loop prevention)."
               },
               {
                "name": "bgp.update.path_attribute.as_path_segment.as4",
                "text": "AS4: 65200",
                "pos": 209,
                "size": 4,
                "note": "One AS on the path, newest first: the leftmost AS is the neighbor that sent it, the rightmost is where the route started. A router that finds its own AS in the path drops the route (loop prevention)."
               },
               {
                "name": "bgp.update.path_attribute.as_path_segment.as4",
                "text": "AS4: 65001",
                "pos": 213,
                "size": 4,
                "note": "One AS on the path, newest first: the leftmost AS is the neighbor that sent it, the rightmost is where the route started. A router that finds its own AS in the path drops the route (loop prevention)."
               }
              ]
             }
            ]
           },
           {
            "name": "bgp.update.path_attribute",
            "text": "Path Attribute - NEXT_HOP: 100.100.255.1 ",
            "pos": 217,
            "size": 7,
            "note": "NEXT_HOP attribute (well-known, mandatory).",
            "children": [
             {
              "name": "bgp.update.path_attribute.flags",
              "text": "Flags: 0x40, Transitive, Well-known, Complete",
              "pos": 217,
              "size": 1,
              "note": "Attribute flags: Optional (vs well-known), Transitive (pass it on), Partial, Extended length.",
              "children": [
               {
                "name": "bgp.update.path_attribute.flags.optional",
                "text": "0... .... = Optional: Not set",
                "pos": 217,
                "size": 1,
                "note": "Well-known attributes (ORIGIN, AS_PATH, NEXT_HOP, LOCAL_PREF) must be understood by every BGP router; optional ones (MED, communities) may not be."
               },
               {
                "name": "bgp.update.path_attribute.flags.transitive",
                "text": ".1.. .... = Transitive: Set",
                "pos": 217,
                "size": 1,
                "note": "Transitive: a router that doesn't understand an optional attribute still passes it on."
               },
               {
                "name": "bgp.update.path_attribute.flags.partial",
                "text": "..0. .... = Partial: Not set",
                "pos": 217,
                "size": 1
               },
               {
                "name": "bgp.update.path_attribute.flags.extended_length",
                "text": "...0 .... = Extended-Length: Not set",
                "pos": 217,
                "size": 1
               },
               {
                "name": "bgp.update.path_attribute.flags.unused",
                "text": ".... 0000 = Unused: 0x0",
                "pos": 217,
                "size": 1
               }
              ]
             },
             {
              "name": "bgp.update.path_attribute.type_code",
              "text": "Type Code: NEXT_HOP (3)",
              "pos": 218,
              "size": 1,
              "note": "Which attribute: 1 ORIGIN, 2 AS_PATH, 3 NEXT_HOP, 4 MED, 5 LOCAL_PREF, 8 COMMUNITIES."
             },
             {
              "name": "bgp.update.path_attribute.length",
              "text": "Length: 4",
              "pos": 219,
              "size": 1
             },
             {
              "name": "bgp.update.path_attribute.next_hop",
              "text": "Next hop: 100.100.255.1",
              "pos": 220,
              "size": 4,
              "note": "Where to send traffic for these prefixes. eBGP sets it to the sender's own address; iBGP passes it through unless next-hop-self."
             }
            ]
           }
          ]
         },
         {
          "name": "bgp.update.nlri",
          "text": "Network Layer Reachability Information (NLRI)",
          "pos": 224,
          "size": 9,
          "note": "NLRI: the prefixes this UPDATE announces, all sharing the attributes above.",
          "children": [
           {
            "name": "",
            "text": "198.51.100.128/25",
            "pos": 224,
            "size": 5,
            "children": [
             {
              "name": "bgp.prefix_length",
              "text": "NLRI prefix length: 25",
              "pos": 224,
              "size": 1,
              "note": "Prefix length in bits. Only as many address bytes as needed follow (a /25 needs 4)."
             },
             {
              "name": "bgp.nlri_prefix",
              "text": "NLRI prefix: 198.51.100.128",
              "pos": 225,
              "size": 4,
              "note": "The prefix being announced."
             }
            ]
           },
           {
            "name": "",
            "text": "198.51.100.0/24",
            "pos": 229,
            "size": 4,
            "children": [
             {
              "name": "bgp.prefix_length",
              "text": "NLRI prefix length: 24",
              "pos": 229,
              "size": 1,
              "note": "Prefix length in bits. Only as many address bytes as needed follow (a /25 needs 4)."
             },
             {
              "name": "bgp.nlri_prefix",
              "text": "NLRI prefix: 198.51.100.0",
              "pos": 230,
              "size": 3,
              "note": "The prefix being announced."
             }
            ]
           }
          ]
         }
        ]
       },
       {
        "proto": "bgp",
        "title": "Border Gateway Protocol - UPDATE Message",
        "pos": 233,
        "size": 50,
        "note": "Border Gateway Protocol: routers in different (eBGP) or the same (iBGP) autonomous systems swap reachability. Every message starts with the same 19-byte header: 16-byte marker, 2-byte length, 1-byte type.",
        "fields": [
         {
          "name": "bgp.marker",
          "text": "Marker: ffffffffffffffffffffffffffffffff",
          "pos": 233,
          "size": 16,
          "note": "16 bytes of 0xff. Kept for compatibility (it once carried authentication); every BGP message has it."
         },
         {
          "name": "bgp.length",
          "text": "Length: 50",
          "pos": 249,
          "size": 2,
          "note": "Whole BGP message length in bytes, header included. Minimum 19 (a KEEPALIVE), maximum 4096 (65535 with extended messages)."
         },
         {
          "name": "bgp.type",
          "text": "Type: UPDATE Message (2)",
          "pos": 251,
          "size": 1,
          "note": "UPDATE: announces prefixes (with their path attributes) and/or withdraws prefixes."
         },
         {
          "name": "bgp.update.withdrawn_routes.length",
          "text": "Withdrawn Routes Length: 0",
          "pos": 252,
          "size": 2,
          "note": "Bytes of withdrawn prefixes that follow. 0 = this UPDATE withdraws nothing."
         },
         {
          "name": "bgp.update.path_attributes.length",
          "text": "Total Path Attribute Length: 24",
          "pos": 254,
          "size": 2,
          "note": "Bytes of path attributes. 0 = a pure withdraw."
         },
         {
          "name": "bgp.update.path_attributes",
          "text": "Path attributes",
          "pos": 256,
          "size": 24,
          "children": [
           {
            "name": "bgp.update.path_attribute",
            "text": "Path Attribute - ORIGIN: IGP",
            "pos": 256,
            "size": 4,
            "note": "ORIGIN attribute (well-known, mandatory).",
            "children": [
             {
              "name": "bgp.update.path_attribute.flags",
              "text": "Flags: 0x40, Transitive, Well-known, Complete",
              "pos": 256,
              "size": 1,
              "note": "Attribute flags: Optional (vs well-known), Transitive (pass it on), Partial, Extended length.",
              "children": [
               {
                "name": "bgp.update.path_attribute.flags.optional",
                "text": "0... .... = Optional: Not set",
                "pos": 256,
                "size": 1,
                "note": "Well-known attributes (ORIGIN, AS_PATH, NEXT_HOP, LOCAL_PREF) must be understood by every BGP router; optional ones (MED, communities) may not be."
               },
               {
                "name": "bgp.update.path_attribute.flags.transitive",
                "text": ".1.. .... = Transitive: Set",
                "pos": 256,
                "size": 1,
                "note": "Transitive: a router that doesn't understand an optional attribute still passes it on."
               },
               {
                "name": "bgp.update.path_attribute.flags.partial",
                "text": "..0. .... = Partial: Not set",
                "pos": 256,
                "size": 1
               },
               {
                "name": "bgp.update.path_attribute.flags.extended_length",
                "text": "...0 .... = Extended-Length: Not set",
                "pos": 256,
                "size": 1
               },
               {
                "name": "bgp.update.path_attribute.flags.unused",
                "text": ".... 0000 = Unused: 0x0",
                "pos": 256,
                "size": 1
               }
              ]
             },
             {
              "name": "bgp.update.path_attribute.type_code",
              "text": "Type Code: ORIGIN (1)",
              "pos": 257,
              "size": 1,
              "note": "Which attribute: 1 ORIGIN, 2 AS_PATH, 3 NEXT_HOP, 4 MED, 5 LOCAL_PREF, 8 COMMUNITIES."
             },
             {
              "name": "bgp.update.path_attribute.length",
              "text": "Length: 1",
              "pos": 258,
              "size": 1
             },
             {
              "name": "bgp.update.path_attribute.origin",
              "text": "Origin: IGP (0)",
              "pos": 259,
              "size": 1,
              "note": "How the route entered BGP: IGP (network statement), EGP, or Incomplete (redistributed). Best path prefers IGP < EGP < Incomplete."
             }
            ]
           },
           {
            "name": "bgp.update.path_attribute",
            "text": "Path Attribute - AS_PATH: 65100 65200 ",
            "pos": 260,
            "size": 13,
            "note": "AS_PATH: every AS the route passed through. Shorter wins in best-path (after weight, local-pref, locally originated).",
            "children": [
             {
              "name": "bgp.update.path_attribute.flags",
              "text": "Flags: 0x40, Transitive, Well-known, Complete",
              "pos": 260,
              "size": 1,
              "note": "Attribute flags: Optional (vs well-known), Transitive (pass it on), Partial, Extended length.",
              "children": [
               {
                "name": "bgp.update.path_attribute.flags.optional",
                "text": "0... .... = Optional: Not set",
                "pos": 260,
                "size": 1,
                "note": "Well-known attributes (ORIGIN, AS_PATH, NEXT_HOP, LOCAL_PREF) must be understood by every BGP router; optional ones (MED, communities) may not be."
               },
               {
                "name": "bgp.update.path_attribute.flags.transitive",
                "text": ".1.. .... = Transitive: Set",
                "pos": 260,
                "size": 1,
                "note": "Transitive: a router that doesn't understand an optional attribute still passes it on."
               },
               {
                "name": "bgp.update.path_attribute.flags.partial",
                "text": "..0. .... = Partial: Not set",
                "pos": 260,
                "size": 1
               },
               {
                "name": "bgp.update.path_attribute.flags.extended_length",
                "text": "...0 .... = Extended-Length: Not set",
                "pos": 260,
                "size": 1
               },
               {
                "name": "bgp.update.path_attribute.flags.unused",
                "text": ".... 0000 = Unused: 0x0",
                "pos": 260,
                "size": 1
               }
              ]
             },
             {
              "name": "bgp.update.path_attribute.type_code",
              "text": "Type Code: AS_PATH (2)",
              "pos": 261,
              "size": 1,
              "note": "Which attribute: 1 ORIGIN, 2 AS_PATH, 3 NEXT_HOP, 4 MED, 5 LOCAL_PREF, 8 COMMUNITIES."
             },
             {
              "name": "bgp.update.path_attribute.length",
              "text": "Length: 10",
              "pos": 262,
              "size": 1
             },
             {
              "name": "bgp.update.path_attribute.as_path_segment",
              "text": "AS Path segment: 65100 65200",
              "pos": 263,
              "size": 10,
              "children": [
               {
                "name": "bgp.update.path_attribute.as_path_segment.type",
                "text": "Segment type: AS_SEQUENCE (2)",
                "pos": 263,
                "size": 1,
                "note": "AS_SEQUENCE = ordered list of ASes the route crossed; AS_SET = an unordered set (from aggregation)."
               },
               {
                "name": "bgp.update.path_attribute.as_path_segment.length",
                "text": "Segment length (number of ASN): 2",
                "pos": 264,
                "size": 1,
                "note": "How many AS numbers follow."
               },
               {
                "name": "bgp.update.path_attribute.as_path_segment.as4",
                "text": "AS4: 65100",
                "pos": 265,
                "size": 4,
                "note": "One AS on the path, newest first: the leftmost AS is the neighbor that sent it, the rightmost is where the route started. A router that finds its own AS in the path drops the route (loop prevention)."
               },
               {
                "name": "bgp.update.path_attribute.as_path_segment.as4",
                "text": "AS4: 65200",
                "pos": 269,
                "size": 4,
                "note": "One AS on the path, newest first: the leftmost AS is the neighbor that sent it, the rightmost is where the route started. A router that finds its own AS in the path drops the route (loop prevention)."
               }
              ]
             }
            ]
           },
           {
            "name": "bgp.update.path_attribute",
            "text": "Path Attribute - NEXT_HOP: 100.100.255.1 ",
            "pos": 273,
            "size": 7,
            "note": "NEXT_HOP attribute (well-known, mandatory).",
            "children": [
             {
              "name": "bgp.update.path_attribute.flags",
              "text": "Flags: 0x40, Transitive, Well-known, Complete",
              "pos": 273,
              "size": 1,
              "note": "Attribute flags: Optional (vs well-known), Transitive (pass it on), Partial, Extended length.",
              "children": [
               {
                "name": "bgp.update.path_attribute.flags.optional",
                "text": "0... .... = Optional: Not set",
                "pos": 273,
                "size": 1,
                "note": "Well-known attributes (ORIGIN, AS_PATH, NEXT_HOP, LOCAL_PREF) must be understood by every BGP router; optional ones (MED, communities) may not be."
               },
               {
                "name": "bgp.update.path_attribute.flags.transitive",
                "text": ".1.. .... = Transitive: Set",
                "pos": 273,
                "size": 1,
                "note": "Transitive: a router that doesn't understand an optional attribute still passes it on."
               },
               {
                "name": "bgp.update.path_attribute.flags.partial",
                "text": "..0. .... = Partial: Not set",
                "pos": 273,
                "size": 1
               },
               {
                "name": "bgp.update.path_attribute.flags.extended_length",
                "text": "...0 .... = Extended-Length: Not set",
                "pos": 273,
                "size": 1
               },
               {
                "name": "bgp.update.path_attribute.flags.unused",
                "text": ".... 0000 = Unused: 0x0",
                "pos": 273,
                "size": 1
               }
              ]
             },
             {
              "name": "bgp.update.path_attribute.type_code",
              "text": "Type Code: NEXT_HOP (3)",
              "pos": 274,
              "size": 1,
              "note": "Which attribute: 1 ORIGIN, 2 AS_PATH, 3 NEXT_HOP, 4 MED, 5 LOCAL_PREF, 8 COMMUNITIES."
             },
             {
              "name": "bgp.update.path_attribute.length",
              "text": "Length: 4",
              "pos": 275,
              "size": 1
             },
             {
              "name": "bgp.update.path_attribute.next_hop",
              "text": "Next hop: 100.100.255.1",
              "pos": 276,
              "size": 4,
              "note": "Where to send traffic for these prefixes. eBGP sets it to the sender's own address; iBGP passes it through unless next-hop-self."
             }
            ]
           }
          ]
         },
         {
          "name": "bgp.update.nlri",
          "text": "Network Layer Reachability Information (NLRI)",
          "pos": 280,
          "size": 3,
          "note": "NLRI: the prefixes this UPDATE announces, all sharing the attributes above.",
          "children": [
           {
            "name": "",
            "text": "100.200.0.0/16",
            "pos": 280,
            "size": 3,
            "children": [
             {
              "name": "bgp.prefix_length",
              "text": "NLRI prefix length: 16",
              "pos": 280,
              "size": 1,
              "note": "Prefix length in bits. Only as many address bytes as needed follow (a /25 needs 4)."
             },
             {
              "name": "bgp.nlri_prefix",
              "text": "NLRI prefix: 100.200.0.0",
              "pos": 281,
              "size": 2,
              "note": "The prefix being announced."
             }
            ]
           }
          ]
         }
        ]
       },
       {
        "proto": "bgp",
        "title": "Border Gateway Protocol - UPDATE Message",
        "pos": 283,
        "size": 53,
        "note": "Border Gateway Protocol: routers in different (eBGP) or the same (iBGP) autonomous systems swap reachability. Every message starts with the same 19-byte header: 16-byte marker, 2-byte length, 1-byte type.",
        "fields": [
         {
          "name": "bgp.marker",
          "text": "Marker: ffffffffffffffffffffffffffffffff",
          "pos": 283,
          "size": 16,
          "note": "16 bytes of 0xff. Kept for compatibility (it once carried authentication); every BGP message has it."
         },
         {
          "name": "bgp.length",
          "text": "Length: 53",
          "pos": 299,
          "size": 2,
          "note": "Whole BGP message length in bytes, header included. Minimum 19 (a KEEPALIVE), maximum 4096 (65535 with extended messages)."
         },
         {
          "name": "bgp.type",
          "text": "Type: UPDATE Message (2)",
          "pos": 301,
          "size": 1,
          "note": "UPDATE: announces prefixes (with their path attributes) and/or withdraws prefixes."
         },
         {
          "name": "bgp.update.withdrawn_routes.length",
          "text": "Withdrawn Routes Length: 0",
          "pos": 302,
          "size": 2,
          "note": "Bytes of withdrawn prefixes that follow. 0 = this UPDATE withdraws nothing."
         },
         {
          "name": "bgp.update.path_attributes.length",
          "text": "Total Path Attribute Length: 27",
          "pos": 304,
          "size": 2,
          "note": "Bytes of path attributes. 0 = a pure withdraw."
         },
         {
          "name": "bgp.update.path_attributes",
          "text": "Path attributes",
          "pos": 306,
          "size": 27,
          "children": [
           {
            "name": "bgp.update.path_attribute",
            "text": "Path Attribute - ORIGIN: IGP",
            "pos": 306,
            "size": 4,
            "note": "ORIGIN attribute (well-known, mandatory).",
            "children": [
             {
              "name": "bgp.update.path_attribute.flags",
              "text": "Flags: 0x40, Transitive, Well-known, Complete",
              "pos": 306,
              "size": 1,
              "note": "Attribute flags: Optional (vs well-known), Transitive (pass it on), Partial, Extended length.",
              "children": [
               {
                "name": "bgp.update.path_attribute.flags.optional",
                "text": "0... .... = Optional: Not set",
                "pos": 306,
                "size": 1,
                "note": "Well-known attributes (ORIGIN, AS_PATH, NEXT_HOP, LOCAL_PREF) must be understood by every BGP router; optional ones (MED, communities) may not be."
               },
               {
                "name": "bgp.update.path_attribute.flags.transitive",
                "text": ".1.. .... = Transitive: Set",
                "pos": 306,
                "size": 1,
                "note": "Transitive: a router that doesn't understand an optional attribute still passes it on."
               },
               {
                "name": "bgp.update.path_attribute.flags.partial",
                "text": "..0. .... = Partial: Not set",
                "pos": 306,
                "size": 1
               },
               {
                "name": "bgp.update.path_attribute.flags.extended_length",
                "text": "...0 .... = Extended-Length: Not set",
                "pos": 306,
                "size": 1
               },
               {
                "name": "bgp.update.path_attribute.flags.unused",
                "text": ".... 0000 = Unused: 0x0",
                "pos": 306,
                "size": 1
               }
              ]
             },
             {
              "name": "bgp.update.path_attribute.type_code",
              "text": "Type Code: ORIGIN (1)",
              "pos": 307,
              "size": 1,
              "note": "Which attribute: 1 ORIGIN, 2 AS_PATH, 3 NEXT_HOP, 4 MED, 5 LOCAL_PREF, 8 COMMUNITIES."
             },
             {
              "name": "bgp.update.path_attribute.length",
              "text": "Length: 1",
              "pos": 308,
              "size": 1
             },
             {
              "name": "bgp.update.path_attribute.origin",
              "text": "Origin: IGP (0)",
              "pos": 309,
              "size": 1,
              "note": "How the route entered BGP: IGP (network statement), EGP, or Incomplete (redistributed). Best path prefers IGP < EGP < Incomplete."
             }
            ]
           },
           {
            "name": "bgp.update.path_attribute",
            "text": "Path Attribute - AS_PATH: 65100 ",
            "pos": 310,
            "size": 9,
            "note": "AS_PATH: every AS the route passed through. Shorter wins in best-path (after weight, local-pref, locally originated).",
            "children": [
             {
              "name": "bgp.update.path_attribute.flags",
              "text": "Flags: 0x40, Transitive, Well-known, Complete",
              "pos": 310,
              "size": 1,
              "note": "Attribute flags: Optional (vs well-known), Transitive (pass it on), Partial, Extended length.",
              "children": [
               {
                "name": "bgp.update.path_attribute.flags.optional",
                "text": "0... .... = Optional: Not set",
                "pos": 310,
                "size": 1,
                "note": "Well-known attributes (ORIGIN, AS_PATH, NEXT_HOP, LOCAL_PREF) must be understood by every BGP router; optional ones (MED, communities) may not be."
               },
               {
                "name": "bgp.update.path_attribute.flags.transitive",
                "text": ".1.. .... = Transitive: Set",
                "pos": 310,
                "size": 1,
                "note": "Transitive: a router that doesn't understand an optional attribute still passes it on."
               },
               {
                "name": "bgp.update.path_attribute.flags.partial",
                "text": "..0. .... = Partial: Not set",
                "pos": 310,
                "size": 1
               },
               {
                "name": "bgp.update.path_attribute.flags.extended_length",
                "text": "...0 .... = Extended-Length: Not set",
                "pos": 310,
                "size": 1
               },
               {
                "name": "bgp.update.path_attribute.flags.unused",
                "text": ".... 0000 = Unused: 0x0",
                "pos": 310,
                "size": 1
               }
              ]
             },
             {
              "name": "bgp.update.path_attribute.type_code",
              "text": "Type Code: AS_PATH (2)",
              "pos": 311,
              "size": 1,
              "note": "Which attribute: 1 ORIGIN, 2 AS_PATH, 3 NEXT_HOP, 4 MED, 5 LOCAL_PREF, 8 COMMUNITIES."
             },
             {
              "name": "bgp.update.path_attribute.length",
              "text": "Length: 6",
              "pos": 312,
              "size": 1
             },
             {
              "name": "bgp.update.path_attribute.as_path_segment",
              "text": "AS Path segment: 65100",
              "pos": 313,
              "size": 6,
              "children": [
               {
                "name": "bgp.update.path_attribute.as_path_segment.type",
                "text": "Segment type: AS_SEQUENCE (2)",
                "pos": 313,
                "size": 1,
                "note": "AS_SEQUENCE = ordered list of ASes the route crossed; AS_SET = an unordered set (from aggregation)."
               },
               {
                "name": "bgp.update.path_attribute.as_path_segment.length",
                "text": "Segment length (number of ASN): 1",
                "pos": 314,
                "size": 1,
                "note": "How many AS numbers follow."
               },
               {
                "name": "bgp.update.path_attribute.as_path_segment.as4",
                "text": "AS4: 65100",
                "pos": 315,
                "size": 4,
                "note": "One AS on the path, newest first: the leftmost AS is the neighbor that sent it, the rightmost is where the route started. A router that finds its own AS in the path drops the route (loop prevention)."
               }
              ]
             }
            ]
           },
           {
            "name": "bgp.update.path_attribute",
            "text": "Path Attribute - NEXT_HOP: 100.100.255.1 ",
            "pos": 319,
            "size": 7,
            "note": "NEXT_HOP attribute (well-known, mandatory).",
            "children": [
             {
              "name": "bgp.update.path_attribute.flags",
              "text": "Flags: 0x40, Transitive, Well-known, Complete",
              "pos": 319,
              "size": 1,
              "note": "Attribute flags: Optional (vs well-known), Transitive (pass it on), Partial, Extended length.",
              "children": [
               {
                "name": "bgp.update.path_attribute.flags.optional",
                "text": "0... .... = Optional: Not set",
                "pos": 319,
                "size": 1,
                "note": "Well-known attributes (ORIGIN, AS_PATH, NEXT_HOP, LOCAL_PREF) must be understood by every BGP router; optional ones (MED, communities) may not be."
               },
               {
                "name": "bgp.update.path_attribute.flags.transitive",
                "text": ".1.. .... = Transitive: Set",
                "pos": 319,
                "size": 1,
                "note": "Transitive: a router that doesn't understand an optional attribute still passes it on."
               },
               {
                "name": "bgp.update.path_attribute.flags.partial",
                "text": "..0. .... = Partial: Not set",
                "pos": 319,
                "size": 1
               },
               {
                "name": "bgp.update.path_attribute.flags.extended_length",
                "text": "...0 .... = Extended-Length: Not set",
                "pos": 319,
                "size": 1
               },
               {
                "name": "bgp.update.path_attribute.flags.unused",
                "text": ".... 0000 = Unused: 0x0",
                "pos": 319,
                "size": 1
               }
              ]
             },
             {
              "name": "bgp.update.path_attribute.type_code",
              "text": "Type Code: NEXT_HOP (3)",
              "pos": 320,
              "size": 1,
              "note": "Which attribute: 1 ORIGIN, 2 AS_PATH, 3 NEXT_HOP, 4 MED, 5 LOCAL_PREF, 8 COMMUNITIES."
             },
             {
              "name": "bgp.update.path_attribute.length",
              "text": "Length: 4",
              "pos": 321,
              "size": 1
             },
             {
              "name": "bgp.update.path_attribute.next_hop",
              "text": "Next hop: 100.100.255.1",
              "pos": 322,
              "size": 4,
              "note": "Where to send traffic for these prefixes. eBGP sets it to the sender's own address; iBGP passes it through unless next-hop-self."
             }
            ]
           },
           {
            "name": "bgp.update.path_attribute",
            "text": "Path Attribute - MULTI_EXIT_DISC: 0",
            "pos": 326,
            "size": 7,
            "note": "MED attribute (optional, non-transitive).",
            "children": [
             {
              "name": "bgp.update.path_attribute.flags",
              "text": "Flags: 0x80, Optional, Non-transitive, Complete",
              "pos": 326,
              "size": 1,
              "note": "Attribute flags: Optional (vs well-known), Transitive (pass it on), Partial, Extended length.",
              "children": [
               {
                "name": "bgp.update.path_attribute.flags.optional",
                "text": "1... .... = Optional: Set",
                "pos": 326,
                "size": 1,
                "note": "Well-known attributes (ORIGIN, AS_PATH, NEXT_HOP, LOCAL_PREF) must be understood by every BGP router; optional ones (MED, communities) may not be."
               },
               {
                "name": "bgp.update.path_attribute.flags.transitive",
                "text": ".0.. .... = Transitive: Not set",
                "pos": 326,
                "size": 1,
                "note": "Transitive: a router that doesn't understand an optional attribute still passes it on."
               },
               {
                "name": "bgp.update.path_attribute.flags.partial",
                "text": "..0. .... = Partial: Not set",
                "pos": 326,
                "size": 1
               },
               {
                "name": "bgp.update.path_attribute.flags.extended_length",
                "text": "...0 .... = Extended-Length: Not set",
                "pos": 326,
                "size": 1
               },
               {
                "name": "bgp.update.path_attribute.flags.unused",
                "text": ".... 0000 = Unused: 0x0",
                "pos": 326,
                "size": 1
               }
              ]
             },
             {
              "name": "bgp.update.path_attribute.type_code",
              "text": "Type Code: MULTI_EXIT_DISC (4)",
              "pos": 327,
              "size": 1,
              "note": "Which attribute: 1 ORIGIN, 2 AS_PATH, 3 NEXT_HOP, 4 MED, 5 LOCAL_PREF, 8 COMMUNITIES."
             },
             {
              "name": "bgp.update.path_attribute.length",
              "text": "Length: 4",
              "pos": 328,
              "size": 1
             },
             {
              "name": "bgp.update.path_attribute.multi_exit_disc",
              "text": "Multiple exit discriminator: 0",
              "pos": 329,
              "size": 4,
              "note": "MED: a hint to the neighbor AS about which entry point to prefer. Lower wins. Not passed beyond the next AS."
             }
            ]
           }
          ]
         },
         {
          "name": "bgp.update.nlri",
          "text": "Network Layer Reachability Information (NLRI)",
          "pos": 333,
          "size": 3,
          "note": "NLRI: the prefixes this UPDATE announces, all sharing the attributes above.",
          "children": [
           {
            "name": "",
            "text": "100.100.0.0/16",
            "pos": 333,
            "size": 3,
            "children": [
             {
              "name": "bgp.prefix_length",
              "text": "NLRI prefix length: 16",
              "pos": 333,
              "size": 1,
              "note": "Prefix length in bits. Only as many address bytes as needed follow (a /25 needs 4)."
             },
             {
              "name": "bgp.nlri_prefix",
              "text": "NLRI prefix: 100.100.0.0",
              "pos": 334,
              "size": 2,
              "note": "The prefix being announced."
             }
            ]
           }
          ]
         }
        ]
       },
       {
        "proto": "bgp",
        "title": "Border Gateway Protocol - UPDATE Message",
        "pos": 336,
        "size": 44,
        "note": "Border Gateway Protocol: routers in different (eBGP) or the same (iBGP) autonomous systems swap reachability. Every message starts with the same 19-byte header: 16-byte marker, 2-byte length, 1-byte type.",
        "fields": [
         {
          "name": "bgp.marker",
          "text": "Marker: ffffffffffffffffffffffffffffffff",
          "pos": 336,
          "size": 16,
          "note": "16 bytes of 0xff. Kept for compatibility (it once carried authentication); every BGP message has it."
         },
         {
          "name": "bgp.length",
          "text": "Length: 44",
          "pos": 352,
          "size": 2,
          "note": "Whole BGP message length in bytes, header included. Minimum 19 (a KEEPALIVE), maximum 4096 (65535 with extended messages)."
         },
         {
          "name": "bgp.type",
          "text": "Type: UPDATE Message (2)",
          "pos": 354,
          "size": 1,
          "note": "UPDATE: announces prefixes (with their path attributes) and/or withdraws prefixes."
         },
         {
          "name": "bgp.update.withdrawn_routes.length",
          "text": "Withdrawn Routes Length: 0",
          "pos": 355,
          "size": 2,
          "note": "Bytes of withdrawn prefixes that follow. 0 = this UPDATE withdraws nothing."
         },
         {
          "name": "bgp.update.path_attributes.length",
          "text": "Total Path Attribute Length: 20",
          "pos": 357,
          "size": 2,
          "note": "Bytes of path attributes. 0 = a pure withdraw."
         },
         {
          "name": "bgp.update.path_attributes",
          "text": "Path attributes",
          "pos": 359,
          "size": 20,
          "children": [
           {
            "name": "bgp.update.path_attribute",
            "text": "Path Attribute - ORIGIN: IGP",
            "pos": 359,
            "size": 4,
            "note": "ORIGIN attribute (well-known, mandatory).",
            "children": [
             {
              "name": "bgp.update.path_attribute.flags",
              "text": "Flags: 0x40, Transitive, Well-known, Complete",
              "pos": 359,
              "size": 1,
              "note": "Attribute flags: Optional (vs well-known), Transitive (pass it on), Partial, Extended length.",
              "children": [
               {
                "name": "bgp.update.path_attribute.flags.optional",
                "text": "0... .... = Optional: Not set",
                "pos": 359,
                "size": 1,
                "note": "Well-known attributes (ORIGIN, AS_PATH, NEXT_HOP, LOCAL_PREF) must be understood by every BGP router; optional ones (MED, communities) may not be."
               },
               {
                "name": "bgp.update.path_attribute.flags.transitive",
                "text": ".1.. .... = Transitive: Set",
                "pos": 359,
                "size": 1,
                "note": "Transitive: a router that doesn't understand an optional attribute still passes it on."
               },
               {
                "name": "bgp.update.path_attribute.flags.partial",
                "text": "..0. .... = Partial: Not set",
                "pos": 359,
                "size": 1
               },
               {
                "name": "bgp.update.path_attribute.flags.extended_length",
                "text": "...0 .... = Extended-Length: Not set",
                "pos": 359,
                "size": 1
               },
               {
                "name": "bgp.update.path_attribute.flags.unused",
                "text": ".... 0000 = Unused: 0x0",
                "pos": 359,
                "size": 1
               }
              ]
             },
             {
              "name": "bgp.update.path_attribute.type_code",
              "text": "Type Code: ORIGIN (1)",
              "pos": 360,
              "size": 1,
              "note": "Which attribute: 1 ORIGIN, 2 AS_PATH, 3 NEXT_HOP, 4 MED, 5 LOCAL_PREF, 8 COMMUNITIES."
             },
             {
              "name": "bgp.update.path_attribute.length",
              "text": "Length: 1",
              "pos": 361,
              "size": 1
             },
             {
              "name": "bgp.update.path_attribute.origin",
              "text": "Origin: IGP (0)",
              "pos": 362,
              "size": 1,
              "note": "How the route entered BGP: IGP (network statement), EGP, or Incomplete (redistributed). Best path prefers IGP < EGP < Incomplete."
             }
            ]
           },
           {
            "name": "bgp.update.path_attribute",
            "text": "Path Attribute - AS_PATH: 65100 ",
            "pos": 363,
            "size": 9,
            "note": "AS_PATH: every AS the route passed through. Shorter wins in best-path (after weight, local-pref, locally originated).",
            "children": [
             {
              "name": "bgp.update.path_attribute.flags",
              "text": "Flags: 0x40, Transitive, Well-known, Complete",
              "pos": 363,
              "size": 1,
              "note": "Attribute flags: Optional (vs well-known), Transitive (pass it on), Partial, Extended length.",
              "children": [
               {
                "name": "bgp.update.path_attribute.flags.optional",
                "text": "0... .... = Optional: Not set",
                "pos": 363,
                "size": 1,
                "note": "Well-known attributes (ORIGIN, AS_PATH, NEXT_HOP, LOCAL_PREF) must be understood by every BGP router; optional ones (MED, communities) may not be."
               },
               {
                "name": "bgp.update.path_attribute.flags.transitive",
                "text": ".1.. .... = Transitive: Set",
                "pos": 363,
                "size": 1,
                "note": "Transitive: a router that doesn't understand an optional attribute still passes it on."
               },
               {
                "name": "bgp.update.path_attribute.flags.partial",
                "text": "..0. .... = Partial: Not set",
                "pos": 363,
                "size": 1
               },
               {
                "name": "bgp.update.path_attribute.flags.extended_length",
                "text": "...0 .... = Extended-Length: Not set",
                "pos": 363,
                "size": 1
               },
               {
                "name": "bgp.update.path_attribute.flags.unused",
                "text": ".... 0000 = Unused: 0x0",
                "pos": 363,
                "size": 1
               }
              ]
             },
             {
              "name": "bgp.update.path_attribute.type_code",
              "text": "Type Code: AS_PATH (2)",
              "pos": 364,
              "size": 1,
              "note": "Which attribute: 1 ORIGIN, 2 AS_PATH, 3 NEXT_HOP, 4 MED, 5 LOCAL_PREF, 8 COMMUNITIES."
             },
             {
              "name": "bgp.update.path_attribute.length",
              "text": "Length: 6",
              "pos": 365,
              "size": 1
             },
             {
              "name": "bgp.update.path_attribute.as_path_segment",
              "text": "AS Path segment: 65100",
              "pos": 366,
              "size": 6,
              "children": [
               {
                "name": "bgp.update.path_attribute.as_path_segment.type",
                "text": "Segment type: AS_SEQUENCE (2)",
                "pos": 366,
                "size": 1,
                "note": "AS_SEQUENCE = ordered list of ASes the route crossed; AS_SET = an unordered set (from aggregation)."
               },
               {
                "name": "bgp.update.path_attribute.as_path_segment.length",
                "text": "Segment length (number of ASN): 1",
                "pos": 367,
                "size": 1,
                "note": "How many AS numbers follow."
               },
               {
                "name": "bgp.update.path_attribute.as_path_segment.as4",
                "text": "AS4: 65100",
                "pos": 368,
                "size": 4,
                "note": "One AS on the path, newest first: the leftmost AS is the neighbor that sent it, the rightmost is where the route started. A router that finds its own AS in the path drops the route (loop prevention)."
               }
              ]
             }
            ]
           },
           {
            "name": "bgp.update.path_attribute",
            "text": "Path Attribute - NEXT_HOP: 100.100.255.1 ",
            "pos": 372,
            "size": 7,
            "note": "NEXT_HOP attribute (well-known, mandatory).",
            "children": [
             {
              "name": "bgp.update.path_attribute.flags",
              "text": "Flags: 0x40, Transitive, Well-known, Complete",
              "pos": 372,
              "size": 1,
              "note": "Attribute flags: Optional (vs well-known), Transitive (pass it on), Partial, Extended length.",
              "children": [
               {
                "name": "bgp.update.path_attribute.flags.optional",
                "text": "0... .... = Optional: Not set",
                "pos": 372,
                "size": 1,
                "note": "Well-known attributes (ORIGIN, AS_PATH, NEXT_HOP, LOCAL_PREF) must be understood by every BGP router; optional ones (MED, communities) may not be."
               },
               {
                "name": "bgp.update.path_attribute.flags.transitive",
                "text": ".1.. .... = Transitive: Set",
                "pos": 372,
                "size": 1,
                "note": "Transitive: a router that doesn't understand an optional attribute still passes it on."
               },
               {
                "name": "bgp.update.path_attribute.flags.partial",
                "text": "..0. .... = Partial: Not set",
                "pos": 372,
                "size": 1
               },
               {
                "name": "bgp.update.path_attribute.flags.extended_length",
                "text": "...0 .... = Extended-Length: Not set",
                "pos": 372,
                "size": 1
               },
               {
                "name": "bgp.update.path_attribute.flags.unused",
                "text": ".... 0000 = Unused: 0x0",
                "pos": 372,
                "size": 1
               }
              ]
             },
             {
              "name": "bgp.update.path_attribute.type_code",
              "text": "Type Code: NEXT_HOP (3)",
              "pos": 373,
              "size": 1,
              "note": "Which attribute: 1 ORIGIN, 2 AS_PATH, 3 NEXT_HOP, 4 MED, 5 LOCAL_PREF, 8 COMMUNITIES."
             },
             {
              "name": "bgp.update.path_attribute.length",
              "text": "Length: 4",
              "pos": 374,
              "size": 1
             },
             {
              "name": "bgp.update.path_attribute.next_hop",
              "text": "Next hop: 100.100.255.1",
              "pos": 375,
              "size": 4,
              "note": "Where to send traffic for these prefixes. eBGP sets it to the sender's own address; iBGP passes it through unless next-hop-self."
             }
            ]
           }
          ]
         },
         {
          "name": "bgp.update.nlri",
          "text": "Network Layer Reachability Information (NLRI)",
          "pos": 379,
          "size": 1,
          "note": "NLRI: the prefixes this UPDATE announces, all sharing the attributes above.",
          "children": [
           {
            "name": "",
            "text": "0.0.0.0/0",
            "pos": 379,
            "size": 1,
            "children": [
             {
              "name": "bgp.prefix_length",
              "text": "NLRI prefix length: 0",
              "pos": 379,
              "size": 1,
              "note": "Prefix length in bits. Only as many address bytes as needed follow (a /25 needs 4)."
             },
             {
              "name": "bgp.nlri_prefix",
              "text": "NLRI prefix: 0.0.0.0",
              "pos": 380,
              "size": 0,
              "note": "The prefix being announced."
             }
            ]
           }
          ]
         }
        ]
       },
       {
        "proto": "bgp",
        "title": "Border Gateway Protocol - ROUTE-REFRESH Message",
        "pos": 380,
        "size": 23,
        "note": "Border Gateway Protocol: routers in different (eBGP) or the same (iBGP) autonomous systems swap reachability. Every message starts with the same 19-byte header: 16-byte marker, 2-byte length, 1-byte type.",
        "fields": [
         {
          "name": "bgp.marker",
          "text": "Marker: ffffffffffffffffffffffffffffffff",
          "pos": 380,
          "size": 16,
          "note": "16 bytes of 0xff. Kept for compatibility (it once carried authentication); every BGP message has it."
         },
         {
          "name": "bgp.length",
          "text": "Length: 23",
          "pos": 396,
          "size": 2,
          "note": "Whole BGP message length in bytes, header included. Minimum 19 (a KEEPALIVE), maximum 4096 (65535 with extended messages)."
         },
         {
          "name": "bgp.type",
          "text": "Type: ROUTE-REFRESH Message (5)",
          "pos": 398,
          "size": 1,
          "note": "ROUTE-REFRESH: asks the peer to resend its UPDATEs (soft inbound reset)."
         },
         {
          "name": "bgp.route_refresh.afi",
          "text": "Address family identifier (AFI): IPv4 (1)",
          "pos": 399,
          "size": 2,
          "note": "Address family of the refresh (1 = IPv4)."
         },
         {
          "name": "bgp.route_refresh.subtype",
          "text": "Subtype: Demarcation of the ending of a route refresh (2)",
          "pos": 401,
          "size": 1,
          "note": "EoRR, End of Route Refresh: the resend is complete; routes not refreshed can be dropped."
         },
         {
          "name": "bgp.route_refresh.safi",
          "text": "Subsequent address family identifier (SAFI): Unicast (1)",
          "pos": 402,
          "size": 1,
          "note": "Sub-family (1 = unicast)."
         }
        ]
       },
       {
        "proto": "bgp",
        "title": "Border Gateway Protocol - UPDATE Message",
        "pos": 403,
        "size": 23,
        "note": "Border Gateway Protocol: routers in different (eBGP) or the same (iBGP) autonomous systems swap reachability. Every message starts with the same 19-byte header: 16-byte marker, 2-byte length, 1-byte type.",
        "fields": [
         {
          "name": "bgp.marker",
          "text": "Marker: ffffffffffffffffffffffffffffffff",
          "pos": 403,
          "size": 16,
          "note": "16 bytes of 0xff. Kept for compatibility (it once carried authentication); every BGP message has it."
         },
         {
          "name": "bgp.length",
          "text": "Length: 23",
          "pos": 419,
          "size": 2,
          "note": "Whole BGP message length in bytes, header included. Minimum 19 (a KEEPALIVE), maximum 4096 (65535 with extended messages)."
         },
         {
          "name": "bgp.type",
          "text": "Type: UPDATE Message (2)",
          "pos": 421,
          "size": 1,
          "note": "UPDATE: announces prefixes (with their path attributes) and/or withdraws prefixes."
         },
         {
          "name": "bgp.update.withdrawn_routes.length",
          "text": "Withdrawn Routes Length: 0",
          "pos": 422,
          "size": 2,
          "note": "Bytes of withdrawn prefixes that follow. 0 = this UPDATE withdraws nothing."
         },
         {
          "name": "bgp.update.path_attributes.length",
          "text": "Total Path Attribute Length: 0",
          "pos": 424,
          "size": 2,
          "note": "Bytes of path attributes. 0 = a pure withdraw."
         }
        ]
       }
      ],
      "focus": "bgp"
     },
     {
      "n": 14,
      "kind": "BGP UPDATE",
      "t": 131.622,
      "clock": "11:14:00.300",
      "from": "HQ1-CORE-R1",
      "to": "ISPA-R1",
      "src": "100.100.255.2",
      "dst": "100.100.255.1",
      "frame": 123,
      "link": "HQ1-CORE-R1 Et0/2 <-> ISPA-R1 Et0/2",
      "len": 196,
      "summary": "Announces and/or withdraws prefixes. Withdrawn routes first, then the path attributes, then the prefixes (NLRI) that share them.",
      "layers": [
       {
        "proto": "eth",
        "title": "Ethernet II, Src: aa:bb:cc:00:18:20, Dst: aa:bb:cc:00:12:20",
        "pos": 0,
        "size": 14,
        "note": "Layer 2 frame. Only matters on this one wire: the next hop rewrites both MAC addresses.",
        "fields": [
         {
          "name": "eth.dst",
          "text": "Destination: aa:bb:cc:00:12:20",
          "pos": 0,
          "size": 6,
          "note": "Who on this wire should take the frame."
         },
         {
          "name": "eth.src",
          "text": "Source: aa:bb:cc:00:18:20",
          "pos": 6,
          "size": 6,
          "note": "Which interface put it on the wire."
         },
         {
          "name": "eth.type",
          "text": "Type: IPv4 (0x0800)",
          "pos": 12,
          "size": 2,
          "note": "What comes next: 0x0800 IPv4, 0x86dd IPv6, 0x8100 VLAN tag, 0x0806 ARP."
         }
        ]
       },
       {
        "proto": "ip",
        "title": "Internet Protocol Version 4, Src: 100.100.255.2, Dst: 100.100.255.1",
        "pos": 14,
        "size": 20,
        "note": "Layer 3 header. Source and destination stay the same end to end (unless NAT rewrites them); TTL drops by one per router.",
        "fields": [
         {
          "name": "ip.version",
          "text": "0100 .... = Version: 4",
          "pos": 14,
          "size": 1,
          "note": "4 = IPv4."
         },
         {
          "name": "ip.hdr_len",
          "text": ".... 0101 = Header Length: 20 bytes (5)",
          "pos": 14,
          "size": 1,
          "note": "Header length. 20 bytes means no IP options."
         },
         {
          "name": "ip.dsfield",
          "text": "Differentiated Services Field: 0xc0 (DSCP: CS6, ECN: Not-ECT)",
          "pos": 15,
          "size": 1,
          "note": "DSCP + ECN. Routers mark control traffic like BGP CS6 (DSCP 48, byte 0xc0) so QoS keeps it alive under load.",
          "children": [
           {
            "name": "ip.dsfield.dscp",
            "text": "1100 00.. = Differentiated Services Codepoint: Class Selector 6 (48)",
            "pos": 15,
            "size": 1,
            "note": "DSCP class. 48 = CS6, the class for routing protocols."
           },
           {
            "name": "ip.dsfield.ecn",
            "text": ".... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0)",
            "pos": 15,
            "size": 1
           }
          ]
         },
         {
          "name": "ip.len",
          "text": "Total Length: 182",
          "pos": 16,
          "size": 2,
          "note": "Total IP packet length (header + payload)."
         },
         {
          "name": "ip.id",
          "text": "Identification: 0xffd2 (65490)",
          "pos": 18,
          "size": 2,
          "note": "Identification. Unique per packet from a sender; also how you match the same packet in two captures."
         },
         {
          "name": "ip.flags",
          "text": "010. .... = Flags: 0x2, Don't fragment",
          "pos": 20,
          "size": 1,
          "note": "Fragmentation flags. DF set = routers must not fragment it.",
          "children": [
           {
            "name": "ip.flags.rb",
            "text": "0... .... = Reserved bit: Not set",
            "pos": 20,
            "size": 1
           },
           {
            "name": "ip.flags.df",
            "text": ".1.. .... = Don't fragment: Set",
            "pos": 20,
            "size": 1,
            "note": "Don't Fragment. If the packet is too big for a link it is dropped and an ICMP 'fragmentation needed' comes back."
           },
           {
            "name": "ip.flags.mf",
            "text": "..0. .... = More fragments: Not set",
            "pos": 20,
            "size": 1
           }
          ]
         },
         {
          "name": "ip.frag_offset",
          "text": "...0 0000 0000 0000 = Fragment Offset: 0",
          "pos": 20,
          "size": 2,
          "note": "Where this fragment sits in the original packet. 0 = not fragmented (or first piece)."
         },
         {
          "name": "ip.ttl",
          "text": "Time to Live: 1",
          "pos": 22,
          "size": 1,
          "note": "Time to live. Each router subtracts one; at 0 the packet dies and ICMP time-exceeded goes back. eBGP peers default to TTL 1 (directly connected) unless ebgp-multihop or ttl-security is set."
         },
         {
          "name": "ip.proto",
          "text": "Protocol: TCP (6)",
          "pos": 23,
          "size": 1,
          "note": "What the payload is: 1 ICMP, 6 TCP, 17 UDP, 50 ESP, 89 OSPF, 88 EIGRP."
         },
         {
          "name": "ip.checksum",
          "text": "Header Checksum: 0xb1e2 [validation disabled]",
          "pos": 24,
          "size": 2,
          "note": "Header checksum, recomputed by every router because TTL changes."
         },
         {
          "name": "ip.src",
          "text": "Source Address: 100.100.255.2",
          "pos": 26,
          "size": 4,
          "note": "Original sender."
         },
         {
          "name": "ip.dst",
          "text": "Destination Address: 100.100.255.1",
          "pos": 30,
          "size": 4,
          "note": "Final destination."
         }
        ]
       },
       {
        "proto": "tcp",
        "title": "Transmission Control Protocol, Src Port: 21381, Dst Port: 179, Seq: 96, Ack: 77, Len: 142",
        "pos": 34,
        "size": 20,
        "note": "Transport. BGP rides TCP port 179, so every BGP message is acknowledged, ordered and resent by TCP, not by BGP.",
        "fields": [
         {
          "name": "tcp.len",
          "text": "TCP Segment Len: 142",
          "pos": 34,
          "size": 0,
          "note": "Payload bytes in this segment. 0 = a pure ACK or control segment."
         },
         {
          "name": "tcp.seq",
          "text": "Sequence Number: 96    (relative sequence number)",
          "pos": 38,
          "size": 4,
          "note": "Sequence number (relative): byte position of this segment's first data byte."
         },
         {
          "name": "tcp.ack",
          "text": "Acknowledgment Number: 77    (relative ack number)",
          "pos": 42,
          "size": 4,
          "note": "Acknowledgement: the next byte this side expects from the other."
         },
         {
          "name": "tcp.hdr_len",
          "text": "0101 .... = Header Length: 20 bytes (5)",
          "pos": 46,
          "size": 1,
          "note": "TCP header length. 20 = no options; 32 = timestamps; larger on a SYN with MSS / window scale / SACK."
         },
         {
          "name": "tcp.flags",
          "text": "Flags: 0x018 (PSH, ACK)",
          "pos": 46,
          "size": 2,
          "note": "Control bits. SYN opens, FIN closes cleanly, RST aborts, ACK acknowledges, PSH says deliver now.",
          "children": [
           {
            "name": "tcp.flags.res",
            "text": "000. .... .... = Reserved: Not set",
            "pos": 46,
            "size": 1
           },
           {
            "name": "tcp.flags.ae",
            "text": "...0 .... .... = Accurate ECN: Not set",
            "pos": 46,
            "size": 1
           },
           {
            "name": "tcp.flags.cwr",
            "text": ".... 0... .... = Congestion Window Reduced: Not set",
            "pos": 47,
            "size": 1
           },
           {
            "name": "tcp.flags.ece",
            "text": ".... .0.. .... = ECN-Echo: Not set",
            "pos": 47,
            "size": 1
           },
           {
            "name": "tcp.flags.urg",
            "text": ".... ..0. .... = Urgent: Not set",
            "pos": 47,
            "size": 1
           },
           {
            "name": "tcp.flags.ack",
            "text": ".... ...1 .... = Acknowledgment: Set",
            "pos": 47,
            "size": 1,
            "note": "ACK: the acknowledgement number is valid."
           },
           {
            "name": "tcp.flags.push",
            "text": ".... .... 1... = Push: Set",
            "pos": 47,
            "size": 1,
            "note": "PSH: hand the data to the application now."
           },
           {
            "name": "tcp.flags.reset",
            "text": ".... .... .0.. = Reset: Not set",
            "pos": 47,
            "size": 1,
            "note": "RST: refuse or abort. A RST answering a SYN means nothing is listening on that port, or the application refuses this peer (a shut-down BGP neighbor does exactly this)."
           },
           {
            "name": "tcp.flags.syn",
            "text": ".... .... ..0. = Syn: Not set",
            "pos": 47,
            "size": 1,
            "note": "SYN: open a connection."
           },
           {
            "name": "tcp.flags.fin",
            "text": ".... .... ...0 = Fin: Not set",
            "pos": 47,
            "size": 1,
            "note": "FIN: this side has nothing more to send; a clean close."
           },
           {
            "name": "tcp.flags.str",
            "text": "TCP Flags: \u00b7\u00b7\u00b7\u00b7\u00b7\u00b7\u00b7AP\u00b7\u00b7\u00b7",
            "pos": 46,
            "size": 2
           }
          ]
         },
         {
          "name": "tcp.window_size_value",
          "text": "Window: 16308",
          "pos": 48,
          "size": 2,
          "note": "Receive window: how many bytes the sender can accept right now."
         },
         {
          "name": "tcp.window_size_scalefactor",
          "text": "Window size scaling factor: 1",
          "pos": 48,
          "size": 2
         },
         {
          "name": "tcp.checksum",
          "text": "Checksum: 0x3715 [unverified]",
          "pos": 50,
          "size": 2,
          "note": "Checksum over header + payload."
         },
         {
          "name": "tcp.urgent_pointer",
          "text": "Urgent Pointer: 0",
          "pos": 52,
          "size": 2,
          "note": "Unused by BGP."
         },
         {
          "name": "",
          "text": "Timestamps",
          "pos": 34,
          "size": 0
         }
        ]
       },
       {
        "proto": "bgp",
        "title": "Border Gateway Protocol - UPDATE Message",
        "pos": 54,
        "size": 60,
        "note": "Border Gateway Protocol: routers in different (eBGP) or the same (iBGP) autonomous systems swap reachability. Every message starts with the same 19-byte header: 16-byte marker, 2-byte length, 1-byte type.",
        "fields": [
         {
          "name": "bgp.marker",
          "text": "Marker: ffffffffffffffffffffffffffffffff",
          "pos": 54,
          "size": 16,
          "note": "16 bytes of 0xff. Kept for compatibility (it once carried authentication); every BGP message has it."
         },
         {
          "name": "bgp.length",
          "text": "Length: 60",
          "pos": 70,
          "size": 2,
          "note": "Whole BGP message length in bytes, header included. Minimum 19 (a KEEPALIVE), maximum 4096 (65535 with extended messages)."
         },
         {
          "name": "bgp.type",
          "text": "Type: UPDATE Message (2)",
          "pos": 72,
          "size": 1,
          "note": "UPDATE: announces prefixes (with their path attributes) and/or withdraws prefixes."
         },
         {
          "name": "bgp.update.withdrawn_routes.length",
          "text": "Withdrawn Routes Length: 0",
          "pos": 73,
          "size": 2,
          "note": "Bytes of withdrawn prefixes that follow. 0 = this UPDATE withdraws nothing."
         },
         {
          "name": "bgp.update.path_attributes.length",
          "text": "Total Path Attribute Length: 32",
          "pos": 75,
          "size": 2,
          "note": "Bytes of path attributes. 0 = a pure withdraw."
         },
         {
          "name": "bgp.update.path_attributes",
          "text": "Path attributes",
          "pos": 77,
          "size": 32,
          "children": [
           {
            "name": "bgp.update.path_attribute",
            "text": "Path Attribute - ORIGIN: IGP",
            "pos": 77,
            "size": 4,
            "note": "ORIGIN attribute (well-known, mandatory).",
            "children": [
             {
              "name": "bgp.update.path_attribute.flags",
              "text": "Flags: 0x40, Transitive, Well-known, Complete",
              "pos": 77,
              "size": 1,
              "note": "Attribute flags: Optional (vs well-known), Transitive (pass it on), Partial, Extended length.",
              "children": [
               {
                "name": "bgp.update.path_attribute.flags.optional",
                "text": "0... .... = Optional: Not set",
                "pos": 77,
                "size": 1,
                "note": "Well-known attributes (ORIGIN, AS_PATH, NEXT_HOP, LOCAL_PREF) must be understood by every BGP router; optional ones (MED, communities) may not be."
               },
               {
                "name": "bgp.update.path_attribute.flags.transitive",
                "text": ".1.. .... = Transitive: Set",
                "pos": 77,
                "size": 1,
                "note": "Transitive: a router that doesn't understand an optional attribute still passes it on."
               },
               {
                "name": "bgp.update.path_attribute.flags.partial",
                "text": "..0. .... = Partial: Not set",
                "pos": 77,
                "size": 1
               },
               {
                "name": "bgp.update.path_attribute.flags.extended_length",
                "text": "...0 .... = Extended-Length: Not set",
                "pos": 77,
                "size": 1
               },
               {
                "name": "bgp.update.path_attribute.flags.unused",
                "text": ".... 0000 = Unused: 0x0",
                "pos": 77,
                "size": 1
               }
              ]
             },
             {
              "name": "bgp.update.path_attribute.type_code",
              "text": "Type Code: ORIGIN (1)",
              "pos": 78,
              "size": 1,
              "note": "Which attribute: 1 ORIGIN, 2 AS_PATH, 3 NEXT_HOP, 4 MED, 5 LOCAL_PREF, 8 COMMUNITIES."
             },
             {
              "name": "bgp.update.path_attribute.length",
              "text": "Length: 1",
              "pos": 79,
              "size": 1
             },
             {
              "name": "bgp.update.path_attribute.origin",
              "text": "Origin: IGP (0)",
              "pos": 80,
              "size": 1,
              "note": "How the route entered BGP: IGP (network statement), EGP, or Incomplete (redistributed). Best path prefers IGP < EGP < Incomplete."
             }
            ]
           },
           {
            "name": "bgp.update.path_attribute",
            "text": "Path Attribute - AS_PATH: 65001 65001 65001 65001 ",
            "pos": 81,
            "size": 21,
            "note": "AS_PATH: every AS the route passed through. Shorter wins in best-path (after weight, local-pref, locally originated).",
            "children": [
             {
              "name": "bgp.update.path_attribute.flags",
              "text": "Flags: 0x40, Transitive, Well-known, Complete",
              "pos": 81,
              "size": 1,
              "note": "Attribute flags: Optional (vs well-known), Transitive (pass it on), Partial, Extended length.",
              "children": [
               {
                "name": "bgp.update.path_attribute.flags.optional",
                "text": "0... .... = Optional: Not set",
                "pos": 81,
                "size": 1,
                "note": "Well-known attributes (ORIGIN, AS_PATH, NEXT_HOP, LOCAL_PREF) must be understood by every BGP router; optional ones (MED, communities) may not be."
               },
               {
                "name": "bgp.update.path_attribute.flags.transitive",
                "text": ".1.. .... = Transitive: Set",
                "pos": 81,
                "size": 1,
                "note": "Transitive: a router that doesn't understand an optional attribute still passes it on."
               },
               {
                "name": "bgp.update.path_attribute.flags.partial",
                "text": "..0. .... = Partial: Not set",
                "pos": 81,
                "size": 1
               },
               {
                "name": "bgp.update.path_attribute.flags.extended_length",
                "text": "...0 .... = Extended-Length: Not set",
                "pos": 81,
                "size": 1
               },
               {
                "name": "bgp.update.path_attribute.flags.unused",
                "text": ".... 0000 = Unused: 0x0",
                "pos": 81,
                "size": 1
               }
              ]
             },
             {
              "name": "bgp.update.path_attribute.type_code",
              "text": "Type Code: AS_PATH (2)",
              "pos": 82,
              "size": 1,
              "note": "Which attribute: 1 ORIGIN, 2 AS_PATH, 3 NEXT_HOP, 4 MED, 5 LOCAL_PREF, 8 COMMUNITIES."
             },
             {
              "name": "bgp.update.path_attribute.length",
              "text": "Length: 18",
              "pos": 83,
              "size": 1
             },
             {
              "name": "bgp.update.path_attribute.as_path_segment",
              "text": "AS Path segment: 65001 65001 65001 65001",
              "pos": 84,
              "size": 18,
              "children": [
               {
                "name": "bgp.update.path_attribute.as_path_segment.type",
                "text": "Segment type: AS_SEQUENCE (2)",
                "pos": 84,
                "size": 1,
                "note": "AS_SEQUENCE = ordered list of ASes the route crossed; AS_SET = an unordered set (from aggregation)."
               },
               {
                "name": "bgp.update.path_attribute.as_path_segment.length",
                "text": "Segment length (number of ASN): 4",
                "pos": 85,
                "size": 1,
                "note": "How many AS numbers follow."
               },
               {
                "name": "bgp.update.path_attribute.as_path_segment.as4",
                "text": "AS4: 65001",
                "pos": 86,
                "size": 4,
                "note": "One AS on the path, newest first: the leftmost AS is the neighbor that sent it, the rightmost is where the route started. A router that finds its own AS in the path drops the route (loop prevention)."
               },
               {
                "name": "bgp.update.path_attribute.as_path_segment.as4",
                "text": "AS4: 65001",
                "pos": 90,
                "size": 4,
                "note": "One AS on the path, newest first: the leftmost AS is the neighbor that sent it, the rightmost is where the route started. A router that finds its own AS in the path drops the route (loop prevention)."
               },
               {
                "name": "bgp.update.path_attribute.as_path_segment.as4",
                "text": "AS4: 65001",
                "pos": 94,
                "size": 4,
                "note": "One AS on the path, newest first: the leftmost AS is the neighbor that sent it, the rightmost is where the route started. A router that finds its own AS in the path drops the route (loop prevention)."
               },
               {
                "name": "bgp.update.path_attribute.as_path_segment.as4",
                "text": "AS4: 65001",
                "pos": 98,
                "size": 4,
                "note": "One AS on the path, newest first: the leftmost AS is the neighbor that sent it, the rightmost is where the route started. A router that finds its own AS in the path drops the route (loop prevention)."
               }
              ]
             }
            ]
           },
           {
            "name": "bgp.update.path_attribute",
            "text": "Path Attribute - NEXT_HOP: 100.100.255.2 ",
            "pos": 102,
            "size": 7,
            "note": "NEXT_HOP attribute (well-known, mandatory).",
            "children": [
             {
              "name": "bgp.update.path_attribute.flags",
              "text": "Flags: 0x40, Transitive, Well-known, Complete",
              "pos": 102,
              "size": 1,
              "note": "Attribute flags: Optional (vs well-known), Transitive (pass it on), Partial, Extended length.",
              "children": [
               {
                "name": "bgp.update.path_attribute.flags.optional",
                "text": "0... .... = Optional: Not set",
                "pos": 102,
                "size": 1,
                "note": "Well-known attributes (ORIGIN, AS_PATH, NEXT_HOP, LOCAL_PREF) must be understood by every BGP router; optional ones (MED, communities) may not be."
               },
               {
                "name": "bgp.update.path_attribute.flags.transitive",
                "text": ".1.. .... = Transitive: Set",
                "pos": 102,
                "size": 1,
                "note": "Transitive: a router that doesn't understand an optional attribute still passes it on."
               },
               {
                "name": "bgp.update.path_attribute.flags.partial",
                "text": "..0. .... = Partial: Not set",
                "pos": 102,
                "size": 1
               },
               {
                "name": "bgp.update.path_attribute.flags.extended_length",
                "text": "...0 .... = Extended-Length: Not set",
                "pos": 102,
                "size": 1
               },
               {
                "name": "bgp.update.path_attribute.flags.unused",
                "text": ".... 0000 = Unused: 0x0",
                "pos": 102,
                "size": 1
               }
              ]
             },
             {
              "name": "bgp.update.path_attribute.type_code",
              "text": "Type Code: NEXT_HOP (3)",
              "pos": 103,
              "size": 1,
              "note": "Which attribute: 1 ORIGIN, 2 AS_PATH, 3 NEXT_HOP, 4 MED, 5 LOCAL_PREF, 8 COMMUNITIES."
             },
             {
              "name": "bgp.update.path_attribute.length",
              "text": "Length: 4",
              "pos": 104,
              "size": 1
             },
             {
              "name": "bgp.update.path_attribute.next_hop",
              "text": "Next hop: 100.100.255.2",
              "pos": 105,
              "size": 4,
              "note": "Where to send traffic for these prefixes. eBGP sets it to the sender's own address; iBGP passes it through unless next-hop-self."
             }
            ]
           }
          ]
         },
         {
          "name": "bgp.update.nlri",
          "text": "Network Layer Reachability Information (NLRI)",
          "pos": 109,
          "size": 5,
          "note": "NLRI: the prefixes this UPDATE announces, all sharing the attributes above.",
          "children": [
           {
            "name": "",
            "text": "198.51.100.128/25",
            "pos": 109,
            "size": 5,
            "children": [
             {
              "name": "bgp.prefix_length",
              "text": "NLRI prefix length: 25",
              "pos": 109,
              "size": 1,
              "note": "Prefix length in bits. Only as many address bytes as needed follow (a /25 needs 4)."
             },
             {
              "name": "bgp.nlri_prefix",
              "text": "NLRI prefix: 198.51.100.128",
              "pos": 110,
              "size": 4,
              "note": "The prefix being announced."
             }
            ]
           }
          ]
         }
        ]
       },
       {
        "proto": "bgp",
        "title": "Border Gateway Protocol - UPDATE Message",
        "pos": 114,
        "size": 59,
        "note": "Border Gateway Protocol: routers in different (eBGP) or the same (iBGP) autonomous systems swap reachability. Every message starts with the same 19-byte header: 16-byte marker, 2-byte length, 1-byte type.",
        "fields": [
         {
          "name": "bgp.marker",
          "text": "Marker: ffffffffffffffffffffffffffffffff",
          "pos": 114,
          "size": 16,
          "note": "16 bytes of 0xff. Kept for compatibility (it once carried authentication); every BGP message has it."
         },
         {
          "name": "bgp.length",
          "text": "Length: 59",
          "pos": 130,
          "size": 2,
          "note": "Whole BGP message length in bytes, header included. Minimum 19 (a KEEPALIVE), maximum 4096 (65535 with extended messages)."
         },
         {
          "name": "bgp.type",
          "text": "Type: UPDATE Message (2)",
          "pos": 132,
          "size": 1,
          "note": "UPDATE: announces prefixes (with their path attributes) and/or withdraws prefixes."
         },
         {
          "name": "bgp.update.withdrawn_routes.length",
          "text": "Withdrawn Routes Length: 0",
          "pos": 133,
          "size": 2,
          "note": "Bytes of withdrawn prefixes that follow. 0 = this UPDATE withdraws nothing."
         },
         {
          "name": "bgp.update.path_attributes.length",
          "text": "Total Path Attribute Length: 27",
          "pos": 135,
          "size": 2,
          "note": "Bytes of path attributes. 0 = a pure withdraw."
         },
         {
          "name": "bgp.update.path_attributes",
          "text": "Path attributes",
          "pos": 137,
          "size": 27,
          "children": [
           {
            "name": "bgp.update.path_attribute",
            "text": "Path Attribute - ORIGIN: IGP",
            "pos": 137,
            "size": 4,
            "note": "ORIGIN attribute (well-known, mandatory).",
            "children": [
             {
              "name": "bgp.update.path_attribute.flags",
              "text": "Flags: 0x40, Transitive, Well-known, Complete",
              "pos": 137,
              "size": 1,
              "note": "Attribute flags: Optional (vs well-known), Transitive (pass it on), Partial, Extended length.",
              "children": [
               {
                "name": "bgp.update.path_attribute.flags.optional",
                "text": "0... .... = Optional: Not set",
                "pos": 137,
                "size": 1,
                "note": "Well-known attributes (ORIGIN, AS_PATH, NEXT_HOP, LOCAL_PREF) must be understood by every BGP router; optional ones (MED, communities) may not be."
               },
               {
                "name": "bgp.update.path_attribute.flags.transitive",
                "text": ".1.. .... = Transitive: Set",
                "pos": 137,
                "size": 1,
                "note": "Transitive: a router that doesn't understand an optional attribute still passes it on."
               },
               {
                "name": "bgp.update.path_attribute.flags.partial",
                "text": "..0. .... = Partial: Not set",
                "pos": 137,
                "size": 1
               },
               {
                "name": "bgp.update.path_attribute.flags.extended_length",
                "text": "...0 .... = Extended-Length: Not set",
                "pos": 137,
                "size": 1
               },
               {
                "name": "bgp.update.path_attribute.flags.unused",
                "text": ".... 0000 = Unused: 0x0",
                "pos": 137,
                "size": 1
               }
              ]
             },
             {
              "name": "bgp.update.path_attribute.type_code",
              "text": "Type Code: ORIGIN (1)",
              "pos": 138,
              "size": 1,
              "note": "Which attribute: 1 ORIGIN, 2 AS_PATH, 3 NEXT_HOP, 4 MED, 5 LOCAL_PREF, 8 COMMUNITIES."
             },
             {
              "name": "bgp.update.path_attribute.length",
              "text": "Length: 1",
              "pos": 139,
              "size": 1
             },
             {
              "name": "bgp.update.path_attribute.origin",
              "text": "Origin: IGP (0)",
              "pos": 140,
              "size": 1,
              "note": "How the route entered BGP: IGP (network statement), EGP, or Incomplete (redistributed). Best path prefers IGP < EGP < Incomplete."
             }
            ]
           },
           {
            "name": "bgp.update.path_attribute",
            "text": "Path Attribute - AS_PATH: 65001 ",
            "pos": 141,
            "size": 9,
            "note": "AS_PATH: every AS the route passed through. Shorter wins in best-path (after weight, local-pref, locally originated).",
            "children": [
             {
              "name": "bgp.update.path_attribute.flags",
              "text": "Flags: 0x40, Transitive, Well-known, Complete",
              "pos": 141,
              "size": 1,
              "note": "Attribute flags: Optional (vs well-known), Transitive (pass it on), Partial, Extended length.",
              "children": [
               {
                "name": "bgp.update.path_attribute.flags.optional",
                "text": "0... .... = Optional: Not set",
                "pos": 141,
                "size": 1,
                "note": "Well-known attributes (ORIGIN, AS_PATH, NEXT_HOP, LOCAL_PREF) must be understood by every BGP router; optional ones (MED, communities) may not be."
               },
               {
                "name": "bgp.update.path_attribute.flags.transitive",
                "text": ".1.. .... = Transitive: Set",
                "pos": 141,
                "size": 1,
                "note": "Transitive: a router that doesn't understand an optional attribute still passes it on."
               },
               {
                "name": "bgp.update.path_attribute.flags.partial",
                "text": "..0. .... = Partial: Not set",
                "pos": 141,
                "size": 1
               },
               {
                "name": "bgp.update.path_attribute.flags.extended_length",
                "text": "...0 .... = Extended-Length: Not set",
                "pos": 141,
                "size": 1
               },
               {
                "name": "bgp.update.path_attribute.flags.unused",
                "text": ".... 0000 = Unused: 0x0",
                "pos": 141,
                "size": 1
               }
              ]
             },
             {
              "name": "bgp.update.path_attribute.type_code",
              "text": "Type Code: AS_PATH (2)",
              "pos": 142,
              "size": 1,
              "note": "Which attribute: 1 ORIGIN, 2 AS_PATH, 3 NEXT_HOP, 4 MED, 5 LOCAL_PREF, 8 COMMUNITIES."
             },
             {
              "name": "bgp.update.path_attribute.length",
              "text": "Length: 6",
              "pos": 143,
              "size": 1
             },
             {
              "name": "bgp.update.path_attribute.as_path_segment",
              "text": "AS Path segment: 65001",
              "pos": 144,
              "size": 6,
              "children": [
               {
                "name": "bgp.update.path_attribute.as_path_segment.type",
                "text": "Segment type: AS_SEQUENCE (2)",
                "pos": 144,
                "size": 1,
                "note": "AS_SEQUENCE = ordered list of ASes the route crossed; AS_SET = an unordered set (from aggregation)."
               },
               {
                "name": "bgp.update.path_attribute.as_path_segment.length",
                "text": "Segment length (number of ASN): 1",
                "pos": 145,
                "size": 1,
                "note": "How many AS numbers follow."
               },
               {
                "name": "bgp.update.path_attribute.as_path_segment.as4",
                "text": "AS4: 65001",
                "pos": 146,
                "size": 4,
                "note": "One AS on the path, newest first: the leftmost AS is the neighbor that sent it, the rightmost is where the route started. A router that finds its own AS in the path drops the route (loop prevention)."
               }
              ]
             }
            ]
           },
           {
            "name": "bgp.update.path_attribute",
            "text": "Path Attribute - NEXT_HOP: 100.100.255.2 ",
            "pos": 150,
            "size": 7,
            "note": "NEXT_HOP attribute (well-known, mandatory).",
            "children": [
             {
              "name": "bgp.update.path_attribute.flags",
              "text": "Flags: 0x40, Transitive, Well-known, Complete",
              "pos": 150,
              "size": 1,
              "note": "Attribute flags: Optional (vs well-known), Transitive (pass it on), Partial, Extended length.",
              "children": [
               {
                "name": "bgp.update.path_attribute.flags.optional",
                "text": "0... .... = Optional: Not set",
                "pos": 150,
                "size": 1,
                "note": "Well-known attributes (ORIGIN, AS_PATH, NEXT_HOP, LOCAL_PREF) must be understood by every BGP router; optional ones (MED, communities) may not be."
               },
               {
                "name": "bgp.update.path_attribute.flags.transitive",
                "text": ".1.. .... = Transitive: Set",
                "pos": 150,
                "size": 1,
                "note": "Transitive: a router that doesn't understand an optional attribute still passes it on."
               },
               {
                "name": "bgp.update.path_attribute.flags.partial",
                "text": "..0. .... = Partial: Not set",
                "pos": 150,
                "size": 1
               },
               {
                "name": "bgp.update.path_attribute.flags.extended_length",
                "text": "...0 .... = Extended-Length: Not set",
                "pos": 150,
                "size": 1
               },
               {
                "name": "bgp.update.path_attribute.flags.unused",
                "text": ".... 0000 = Unused: 0x0",
                "pos": 150,
                "size": 1
               }
              ]
             },
             {
              "name": "bgp.update.path_attribute.type_code",
              "text": "Type Code: NEXT_HOP (3)",
              "pos": 151,
              "size": 1,
              "note": "Which attribute: 1 ORIGIN, 2 AS_PATH, 3 NEXT_HOP, 4 MED, 5 LOCAL_PREF, 8 COMMUNITIES."
             },
             {
              "name": "bgp.update.path_attribute.length",
              "text": "Length: 4",
              "pos": 152,
              "size": 1
             },
             {
              "name": "bgp.update.path_attribute.next_hop",
              "text": "Next hop: 100.100.255.2",
              "pos": 153,
              "size": 4,
              "note": "Where to send traffic for these prefixes. eBGP sets it to the sender's own address; iBGP passes it through unless next-hop-self."
             }
            ]
           },
           {
            "name": "bgp.update.path_attribute",
            "text": "Path Attribute - MULTI_EXIT_DISC: 0",
            "pos": 157,
            "size": 7,
            "note": "MED attribute (optional, non-transitive).",
            "children": [
             {
              "name": "bgp.update.path_attribute.flags",
              "text": "Flags: 0x80, Optional, Non-transitive, Complete",
              "pos": 157,
              "size": 1,
              "note": "Attribute flags: Optional (vs well-known), Transitive (pass it on), Partial, Extended length.",
              "children": [
               {
                "name": "bgp.update.path_attribute.flags.optional",
                "text": "1... .... = Optional: Set",
                "pos": 157,
                "size": 1,
                "note": "Well-known attributes (ORIGIN, AS_PATH, NEXT_HOP, LOCAL_PREF) must be understood by every BGP router; optional ones (MED, communities) may not be."
               },
               {
                "name": "bgp.update.path_attribute.flags.transitive",
                "text": ".0.. .... = Transitive: Not set",
                "pos": 157,
                "size": 1,
                "note": "Transitive: a router that doesn't understand an optional attribute still passes it on."
               },
               {
                "name": "bgp.update.path_attribute.flags.partial",
                "text": "..0. .... = Partial: Not set",
                "pos": 157,
                "size": 1
               },
               {
                "name": "bgp.update.path_attribute.flags.extended_length",
                "text": "...0 .... = Extended-Length: Not set",
                "pos": 157,
                "size": 1
               },
               {
                "name": "bgp.update.path_attribute.flags.unused",
                "text": ".... 0000 = Unused: 0x0",
                "pos": 157,
                "size": 1
               }
              ]
             },
             {
              "name": "bgp.update.path_attribute.type_code",
              "text": "Type Code: MULTI_EXIT_DISC (4)",
              "pos": 158,
              "size": 1,
              "note": "Which attribute: 1 ORIGIN, 2 AS_PATH, 3 NEXT_HOP, 4 MED, 5 LOCAL_PREF, 8 COMMUNITIES."
             },
             {
              "name": "bgp.update.path_attribute.length",
              "text": "Length: 4",
              "pos": 159,
              "size": 1
             },
             {
              "name": "bgp.update.path_attribute.multi_exit_disc",
              "text": "Multiple exit discriminator: 0",
              "pos": 160,
              "size": 4,
              "note": "MED: a hint to the neighbor AS about which entry point to prefer. Lower wins. Not passed beyond the next AS."
             }
            ]
           }
          ]
         },
         {
          "name": "bgp.update.nlri",
          "text": "Network Layer Reachability Information (NLRI)",
          "pos": 164,
          "size": 9,
          "note": "NLRI: the prefixes this UPDATE announces, all sharing the attributes above.",
          "children": [
           {
            "name": "",
            "text": "198.51.100.0/25",
            "pos": 164,
            "size": 5,
            "children": [
             {
              "name": "bgp.prefix_length",
              "text": "NLRI prefix length: 25",
              "pos": 164,
              "size": 1,
              "note": "Prefix length in bits. Only as many address bytes as needed follow (a /25 needs 4)."
             },
             {
              "name": "bgp.nlri_prefix",
              "text": "NLRI prefix: 198.51.100.0",
              "pos": 165,
              "size": 4,
              "note": "The prefix being announced."
             }
            ]
           },
           {
            "name": "",
            "text": "198.51.100.0/24",
            "pos": 169,
            "size": 4,
            "children": [
             {
              "name": "bgp.prefix_length",
              "text": "NLRI prefix length: 24",
              "pos": 169,
              "size": 1,
              "note": "Prefix length in bits. Only as many address bytes as needed follow (a /25 needs 4)."
             },
             {
              "name": "bgp.nlri_prefix",
              "text": "NLRI prefix: 198.51.100.0",
              "pos": 170,
              "size": 3,
              "note": "The prefix being announced."
             }
            ]
           }
          ]
         }
        ]
       },
       {
        "proto": "bgp",
        "title": "Border Gateway Protocol - UPDATE Message",
        "pos": 173,
        "size": 23,
        "note": "Border Gateway Protocol: routers in different (eBGP) or the same (iBGP) autonomous systems swap reachability. Every message starts with the same 19-byte header: 16-byte marker, 2-byte length, 1-byte type.",
        "fields": [
         {
          "name": "bgp.marker",
          "text": "Marker: ffffffffffffffffffffffffffffffff",
          "pos": 173,
          "size": 16,
          "note": "16 bytes of 0xff. Kept for compatibility (it once carried authentication); every BGP message has it."
         },
         {
          "name": "bgp.length",
          "text": "Length: 23",
          "pos": 189,
          "size": 2,
          "note": "Whole BGP message length in bytes, header included. Minimum 19 (a KEEPALIVE), maximum 4096 (65535 with extended messages)."
         },
         {
          "name": "bgp.type",
          "text": "Type: UPDATE Message (2)",
          "pos": 191,
          "size": 1,
          "note": "UPDATE: announces prefixes (with their path attributes) and/or withdraws prefixes."
         },
         {
          "name": "bgp.update.withdrawn_routes.length",
          "text": "Withdrawn Routes Length: 0",
          "pos": 192,
          "size": 2,
          "note": "Bytes of withdrawn prefixes that follow. 0 = this UPDATE withdraws nothing."
         },
         {
          "name": "bgp.update.path_attributes.length",
          "text": "Total Path Attribute Length: 0",
          "pos": 194,
          "size": 2,
          "note": "Bytes of path attributes. 0 = a pure withdraw."
         }
        ]
       }
      ],
      "focus": "bgp"
     },
     {
      "n": 15,
      "kind": "BGP UPDATE",
      "t": 131.624,
      "clock": "11:14:00.302",
      "from": "ISPA-R1",
      "to": "HQ1-CORE-R1",
      "src": "100.100.255.1",
      "dst": "100.100.255.2",
      "frame": 125,
      "link": "HQ1-CORE-R1 Et0/2 <-> ISPA-R1 Et0/2",
      "len": 110,
      "summary": "Announces and/or withdraws prefixes. Withdrawn routes first, then the path attributes, then the prefixes (NLRI) that share them.",
      "layers": [
       {
        "proto": "eth",
        "title": "Ethernet II, Src: aa:bb:cc:00:12:20, Dst: aa:bb:cc:00:18:20",
        "pos": 0,
        "size": 14,
        "note": "Layer 2 frame. Only matters on this one wire: the next hop rewrites both MAC addresses.",
        "fields": [
         {
          "name": "eth.dst",
          "text": "Destination: aa:bb:cc:00:18:20",
          "pos": 0,
          "size": 6,
          "note": "Who on this wire should take the frame."
         },
         {
          "name": "eth.src",
          "text": "Source: aa:bb:cc:00:12:20",
          "pos": 6,
          "size": 6,
          "note": "Which interface put it on the wire."
         },
         {
          "name": "eth.type",
          "text": "Type: IPv4 (0x0800)",
          "pos": 12,
          "size": 2,
          "note": "What comes next: 0x0800 IPv4, 0x86dd IPv6, 0x8100 VLAN tag, 0x0806 ARP."
         }
        ]
       },
       {
        "proto": "ip",
        "title": "Internet Protocol Version 4, Src: 100.100.255.1, Dst: 100.100.255.2",
        "pos": 14,
        "size": 20,
        "note": "Layer 3 header. Source and destination stay the same end to end (unless NAT rewrites them); TTL drops by one per router.",
        "fields": [
         {
          "name": "ip.version",
          "text": "0100 .... = Version: 4",
          "pos": 14,
          "size": 1,
          "note": "4 = IPv4."
         },
         {
          "name": "ip.hdr_len",
          "text": ".... 0101 = Header Length: 20 bytes (5)",
          "pos": 14,
          "size": 1,
          "note": "Header length. 20 bytes means no IP options."
         },
         {
          "name": "ip.dsfield",
          "text": "Differentiated Services Field: 0xc0 (DSCP: CS6, ECN: Not-ECT)",
          "pos": 15,
          "size": 1,
          "note": "DSCP + ECN. Routers mark control traffic like BGP CS6 (DSCP 48, byte 0xc0) so QoS keeps it alive under load.",
          "children": [
           {
            "name": "ip.dsfield.dscp",
            "text": "1100 00.. = Differentiated Services Codepoint: Class Selector 6 (48)",
            "pos": 15,
            "size": 1,
            "note": "DSCP class. 48 = CS6, the class for routing protocols."
           },
           {
            "name": "ip.dsfield.ecn",
            "text": ".... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0)",
            "pos": 15,
            "size": 1
           }
          ]
         },
         {
          "name": "ip.len",
          "text": "Total Length: 96",
          "pos": 16,
          "size": 2,
          "note": "Total IP packet length (header + payload)."
         },
         {
          "name": "ip.id",
          "text": "Identification: 0xd9bd (55741)",
          "pos": 18,
          "size": 2,
          "note": "Identification. Unique per packet from a sender; also how you match the same packet in two captures."
         },
         {
          "name": "ip.flags",
          "text": "010. .... = Flags: 0x2, Don't fragment",
          "pos": 20,
          "size": 1,
          "note": "Fragmentation flags. DF set = routers must not fragment it.",
          "children": [
           {
            "name": "ip.flags.rb",
            "text": "0... .... = Reserved bit: Not set",
            "pos": 20,
            "size": 1
           },
           {
            "name": "ip.flags.df",
            "text": ".1.. .... = Don't fragment: Set",
            "pos": 20,
            "size": 1,
            "note": "Don't Fragment. If the packet is too big for a link it is dropped and an ICMP 'fragmentation needed' comes back."
           },
           {
            "name": "ip.flags.mf",
            "text": "..0. .... = More fragments: Not set",
            "pos": 20,
            "size": 1
           }
          ]
         },
         {
          "name": "ip.frag_offset",
          "text": "...0 0000 0000 0000 = Fragment Offset: 0",
          "pos": 20,
          "size": 2,
          "note": "Where this fragment sits in the original packet. 0 = not fragmented (or first piece)."
         },
         {
          "name": "ip.ttl",
          "text": "Time to Live: 1",
          "pos": 22,
          "size": 1,
          "note": "Time to live. Each router subtracts one; at 0 the packet dies and ICMP time-exceeded goes back. eBGP peers default to TTL 1 (directly connected) unless ebgp-multihop or ttl-security is set."
         },
         {
          "name": "ip.proto",
          "text": "Protocol: TCP (6)",
          "pos": 23,
          "size": 1,
          "note": "What the payload is: 1 ICMP, 6 TCP, 17 UDP, 50 ESP, 89 OSPF, 88 EIGRP."
         },
         {
          "name": "ip.checksum",
          "text": "Header Checksum: 0xd84d [validation disabled]",
          "pos": 24,
          "size": 2,
          "note": "Header checksum, recomputed by every router because TTL changes."
         },
         {
          "name": "ip.src",
          "text": "Source Address: 100.100.255.1",
          "pos": 26,
          "size": 4,
          "note": "Original sender."
         },
         {
          "name": "ip.dst",
          "text": "Destination Address: 100.100.255.2",
          "pos": 30,
          "size": 4,
          "note": "Final destination."
         }
        ]
       },
       {
        "proto": "tcp",
        "title": "Transmission Control Protocol, Src Port: 179, Dst Port: 21381, Seq: 491, Ack: 238, Len: 56",
        "pos": 34,
        "size": 20,
        "note": "Transport. BGP rides TCP port 179, so every BGP message is acknowledged, ordered and resent by TCP, not by BGP.",
        "fields": [
         {
          "name": "tcp.len",
          "text": "TCP Segment Len: 56",
          "pos": 34,
          "size": 0,
          "note": "Payload bytes in this segment. 0 = a pure ACK or control segment."
         },
         {
          "name": "tcp.seq",
          "text": "Sequence Number: 491    (relative sequence number)",
          "pos": 38,
          "size": 4,
          "note": "Sequence number (relative): byte position of this segment's first data byte."
         },
         {
          "name": "tcp.ack",
          "text": "Acknowledgment Number: 238    (relative ack number)",
          "pos": 42,
          "size": 4,
          "note": "Acknowledgement: the next byte this side expects from the other."
         },
         {
          "name": "tcp.hdr_len",
          "text": "0101 .... = Header Length: 20 bytes (5)",
          "pos": 46,
          "size": 1,
          "note": "TCP header length. 20 = no options; 32 = timestamps; larger on a SYN with MSS / window scale / SACK."
         },
         {
          "name": "tcp.flags",
          "text": "Flags: 0x018 (PSH, ACK)",
          "pos": 46,
          "size": 2,
          "note": "Control bits. SYN opens, FIN closes cleanly, RST aborts, ACK acknowledges, PSH says deliver now.",
          "children": [
           {
            "name": "tcp.flags.res",
            "text": "000. .... .... = Reserved: Not set",
            "pos": 46,
            "size": 1
           },
           {
            "name": "tcp.flags.ae",
            "text": "...0 .... .... = Accurate ECN: Not set",
            "pos": 46,
            "size": 1
           },
           {
            "name": "tcp.flags.cwr",
            "text": ".... 0... .... = Congestion Window Reduced: Not set",
            "pos": 47,
            "size": 1
           },
           {
            "name": "tcp.flags.ece",
            "text": ".... .0.. .... = ECN-Echo: Not set",
            "pos": 47,
            "size": 1
           },
           {
            "name": "tcp.flags.urg",
            "text": ".... ..0. .... = Urgent: Not set",
            "pos": 47,
            "size": 1
           },
           {
            "name": "tcp.flags.ack",
            "text": ".... ...1 .... = Acknowledgment: Set",
            "pos": 47,
            "size": 1,
            "note": "ACK: the acknowledgement number is valid."
           },
           {
            "name": "tcp.flags.push",
            "text": ".... .... 1... = Push: Set",
            "pos": 47,
            "size": 1,
            "note": "PSH: hand the data to the application now."
           },
           {
            "name": "tcp.flags.reset",
            "text": ".... .... .0.. = Reset: Not set",
            "pos": 47,
            "size": 1,
            "note": "RST: refuse or abort. A RST answering a SYN means nothing is listening on that port, or the application refuses this peer (a shut-down BGP neighbor does exactly this)."
           },
           {
            "name": "tcp.flags.syn",
            "text": ".... .... ..0. = Syn: Not set",
            "pos": 47,
            "size": 1,
            "note": "SYN: open a connection."
           },
           {
            "name": "tcp.flags.fin",
            "text": ".... .... ...0 = Fin: Not set",
            "pos": 47,
            "size": 1,
            "note": "FIN: this side has nothing more to send; a clean close."
           },
           {
            "name": "tcp.flags.str",
            "text": "TCP Flags: \u00b7\u00b7\u00b7\u00b7\u00b7\u00b7\u00b7AP\u00b7\u00b7\u00b7",
            "pos": 46,
            "size": 2
           }
          ]
         },
         {
          "name": "tcp.window_size_value",
          "text": "Window: 16147",
          "pos": 48,
          "size": 2,
          "note": "Receive window: how many bytes the sender can accept right now."
         },
         {
          "name": "tcp.window_size_scalefactor",
          "text": "Window size scaling factor: 1",
          "pos": 48,
          "size": 2
         },
         {
          "name": "tcp.checksum",
          "text": "Checksum: 0x4cc5 [unverified]",
          "pos": 50,
          "size": 2,
          "note": "Checksum over header + payload."
         },
         {
          "name": "tcp.urgent_pointer",
          "text": "Urgent Pointer: 0",
          "pos": 52,
          "size": 2,
          "note": "Unused by BGP."
         },
         {
          "name": "",
          "text": "Timestamps",
          "pos": 34,
          "size": 0
         }
        ]
       },
       {
        "proto": "bgp",
        "title": "Border Gateway Protocol - UPDATE Message",
        "pos": 54,
        "size": 56,
        "note": "Border Gateway Protocol: routers in different (eBGP) or the same (iBGP) autonomous systems swap reachability. Every message starts with the same 19-byte header: 16-byte marker, 2-byte length, 1-byte type.",
        "fields": [
         {
          "name": "bgp.marker",
          "text": "Marker: ffffffffffffffffffffffffffffffff",
          "pos": 54,
          "size": 16,
          "note": "16 bytes of 0xff. Kept for compatibility (it once carried authentication); every BGP message has it."
         },
         {
          "name": "bgp.length",
          "text": "Length: 56",
          "pos": 70,
          "size": 2,
          "note": "Whole BGP message length in bytes, header included. Minimum 19 (a KEEPALIVE), maximum 4096 (65535 with extended messages)."
         },
         {
          "name": "bgp.type",
          "text": "Type: UPDATE Message (2)",
          "pos": 72,
          "size": 1,
          "note": "UPDATE: announces prefixes (with their path attributes) and/or withdraws prefixes."
         },
         {
          "name": "bgp.update.withdrawn_routes.length",
          "text": "Withdrawn Routes Length: 0",
          "pos": 73,
          "size": 2,
          "note": "Bytes of withdrawn prefixes that follow. 0 = this UPDATE withdraws nothing."
         },
         {
          "name": "bgp.update.path_attributes.length",
          "text": "Total Path Attribute Length: 24",
          "pos": 75,
          "size": 2,
          "note": "Bytes of path attributes. 0 = a pure withdraw."
         },
         {
          "name": "bgp.update.path_attributes",
          "text": "Path attributes",
          "pos": 77,
          "size": 24,
          "children": [
           {
            "name": "bgp.update.path_attribute",
            "text": "Path Attribute - ORIGIN: IGP",
            "pos": 77,
            "size": 4,
            "note": "ORIGIN attribute (well-known, mandatory).",
            "children": [
             {
              "name": "bgp.update.path_attribute.flags",
              "text": "Flags: 0x40, Transitive, Well-known, Complete",
              "pos": 77,
              "size": 1,
              "note": "Attribute flags: Optional (vs well-known), Transitive (pass it on), Partial, Extended length.",
              "children": [
               {
                "name": "bgp.update.path_attribute.flags.optional",
                "text": "0... .... = Optional: Not set",
                "pos": 77,
                "size": 1,
                "note": "Well-known attributes (ORIGIN, AS_PATH, NEXT_HOP, LOCAL_PREF) must be understood by every BGP router; optional ones (MED, communities) may not be."
               },
               {
                "name": "bgp.update.path_attribute.flags.transitive",
                "text": ".1.. .... = Transitive: Set",
                "pos": 77,
                "size": 1,
                "note": "Transitive: a router that doesn't understand an optional attribute still passes it on."
               },
               {
                "name": "bgp.update.path_attribute.flags.partial",
                "text": "..0. .... = Partial: Not set",
                "pos": 77,
                "size": 1
               },
               {
                "name": "bgp.update.path_attribute.flags.extended_length",
                "text": "...0 .... = Extended-Length: Not set",
                "pos": 77,
                "size": 1
               },
               {
                "name": "bgp.update.path_attribute.flags.unused",
                "text": ".... 0000 = Unused: 0x0",
                "pos": 77,
                "size": 1
               }
              ]
             },
             {
              "name": "bgp.update.path_attribute.type_code",
              "text": "Type Code: ORIGIN (1)",
              "pos": 78,
              "size": 1,
              "note": "Which attribute: 1 ORIGIN, 2 AS_PATH, 3 NEXT_HOP, 4 MED, 5 LOCAL_PREF, 8 COMMUNITIES."
             },
             {
              "name": "bgp.update.path_attribute.length",
              "text": "Length: 1",
              "pos": 79,
              "size": 1
             },
             {
              "name": "bgp.update.path_attribute.origin",
              "text": "Origin: IGP (0)",
              "pos": 80,
              "size": 1,
              "note": "How the route entered BGP: IGP (network statement), EGP, or Incomplete (redistributed). Best path prefers IGP < EGP < Incomplete."
             }
            ]
           },
           {
            "name": "bgp.update.path_attribute",
            "text": "Path Attribute - AS_PATH: 65100 65001 ",
            "pos": 81,
            "size": 13,
            "note": "AS_PATH: every AS the route passed through. Shorter wins in best-path (after weight, local-pref, locally originated).",
            "children": [
             {
              "name": "bgp.update.path_attribute.flags",
              "text": "Flags: 0x40, Transitive, Well-known, Complete",
              "pos": 81,
              "size": 1,
              "note": "Attribute flags: Optional (vs well-known), Transitive (pass it on), Partial, Extended length.",
              "children": [
               {
                "name": "bgp.update.path_attribute.flags.optional",
                "text": "0... .... = Optional: Not set",
                "pos": 81,
                "size": 1,
                "note": "Well-known attributes (ORIGIN, AS_PATH, NEXT_HOP, LOCAL_PREF) must be understood by every BGP router; optional ones (MED, communities) may not be."
               },
               {
                "name": "bgp.update.path_attribute.flags.transitive",
                "text": ".1.. .... = Transitive: Set",
                "pos": 81,
                "size": 1,
                "note": "Transitive: a router that doesn't understand an optional attribute still passes it on."
               },
               {
                "name": "bgp.update.path_attribute.flags.partial",
                "text": "..0. .... = Partial: Not set",
                "pos": 81,
                "size": 1
               },
               {
                "name": "bgp.update.path_attribute.flags.extended_length",
                "text": "...0 .... = Extended-Length: Not set",
                "pos": 81,
                "size": 1
               },
               {
                "name": "bgp.update.path_attribute.flags.unused",
                "text": ".... 0000 = Unused: 0x0",
                "pos": 81,
                "size": 1
               }
              ]
             },
             {
              "name": "bgp.update.path_attribute.type_code",
              "text": "Type Code: AS_PATH (2)",
              "pos": 82,
              "size": 1,
              "note": "Which attribute: 1 ORIGIN, 2 AS_PATH, 3 NEXT_HOP, 4 MED, 5 LOCAL_PREF, 8 COMMUNITIES."
             },
             {
              "name": "bgp.update.path_attribute.length",
              "text": "Length: 10",
              "pos": 83,
              "size": 1
             },
             {
              "name": "bgp.update.path_attribute.as_path_segment",
              "text": "AS Path segment: 65100 65001",
              "pos": 84,
              "size": 10,
              "children": [
               {
                "name": "bgp.update.path_attribute.as_path_segment.type",
                "text": "Segment type: AS_SEQUENCE (2)",
                "pos": 84,
                "size": 1,
                "note": "AS_SEQUENCE = ordered list of ASes the route crossed; AS_SET = an unordered set (from aggregation)."
               },
               {
                "name": "bgp.update.path_attribute.as_path_segment.length",
                "text": "Segment length (number of ASN): 2",
                "pos": 85,
                "size": 1,
                "note": "How many AS numbers follow."
               },
               {
                "name": "bgp.update.path_attribute.as_path_segment.as4",
                "text": "AS4: 65100",
                "pos": 86,
                "size": 4,
                "note": "One AS on the path, newest first: the leftmost AS is the neighbor that sent it, the rightmost is where the route started. A router that finds its own AS in the path drops the route (loop prevention)."
               },
               {
                "name": "bgp.update.path_attribute.as_path_segment.as4",
                "text": "AS4: 65001",
                "pos": 90,
                "size": 4,
                "note": "One AS on the path, newest first: the leftmost AS is the neighbor that sent it, the rightmost is where the route started. A router that finds its own AS in the path drops the route (loop prevention)."
               }
              ]
             }
            ]
           },
           {
            "name": "bgp.update.path_attribute",
            "text": "Path Attribute - NEXT_HOP: 100.100.255.2 ",
            "pos": 94,
            "size": 7,
            "note": "NEXT_HOP attribute (well-known, mandatory).",
            "children": [
             {
              "name": "bgp.update.path_attribute.flags",
              "text": "Flags: 0x40, Transitive, Well-known, Complete",
              "pos": 94,
              "size": 1,
              "note": "Attribute flags: Optional (vs well-known), Transitive (pass it on), Partial, Extended length.",
              "children": [
               {
                "name": "bgp.update.path_attribute.flags.optional",
                "text": "0... .... = Optional: Not set",
                "pos": 94,
                "size": 1,
                "note": "Well-known attributes (ORIGIN, AS_PATH, NEXT_HOP, LOCAL_PREF) must be understood by every BGP router; optional ones (MED, communities) may not be."
               },
               {
                "name": "bgp.update.path_attribute.flags.transitive",
                "text": ".1.. .... = Transitive: Set",
                "pos": 94,
                "size": 1,
                "note": "Transitive: a router that doesn't understand an optional attribute still passes it on."
               },
               {
                "name": "bgp.update.path_attribute.flags.partial",
                "text": "..0. .... = Partial: Not set",
                "pos": 94,
                "size": 1
               },
               {
                "name": "bgp.update.path_attribute.flags.extended_length",
                "text": "...0 .... = Extended-Length: Not set",
                "pos": 94,
                "size": 1
               },
               {
                "name": "bgp.update.path_attribute.flags.unused",
                "text": ".... 0000 = Unused: 0x0",
                "pos": 94,
                "size": 1
               }
              ]
             },
             {
              "name": "bgp.update.path_attribute.type_code",
              "text": "Type Code: NEXT_HOP (3)",
              "pos": 95,
              "size": 1,
              "note": "Which attribute: 1 ORIGIN, 2 AS_PATH, 3 NEXT_HOP, 4 MED, 5 LOCAL_PREF, 8 COMMUNITIES."
             },
             {
              "name": "bgp.update.path_attribute.length",
              "text": "Length: 4",
              "pos": 96,
              "size": 1
             },
             {
              "name": "bgp.update.path_attribute.next_hop",
              "text": "Next hop: 100.100.255.2",
              "pos": 97,
              "size": 4,
              "note": "Where to send traffic for these prefixes. eBGP sets it to the sender's own address; iBGP passes it through unless next-hop-self."
             }
            ]
           }
          ]
         },
         {
          "name": "bgp.update.nlri",
          "text": "Network Layer Reachability Information (NLRI)",
          "pos": 101,
          "size": 9,
          "note": "NLRI: the prefixes this UPDATE announces, all sharing the attributes above.",
          "children": [
           {
            "name": "",
            "text": "198.51.100.0/25",
            "pos": 101,
            "size": 5,
            "children": [
             {
              "name": "bgp.prefix_length",
              "text": "NLRI prefix length: 25",
              "pos": 101,
              "size": 1,
              "note": "Prefix length in bits. Only as many address bytes as needed follow (a /25 needs 4)."
             },
             {
              "name": "bgp.nlri_prefix",
              "text": "NLRI prefix: 198.51.100.0",
              "pos": 102,
              "size": 4,
              "note": "The prefix being announced."
             }
            ]
           },
           {
            "name": "",
            "text": "198.51.100.0/24",
            "pos": 106,
            "size": 4,
            "children": [
             {
              "name": "bgp.prefix_length",
              "text": "NLRI prefix length: 24",
              "pos": 106,
              "size": 1,
              "note": "Prefix length in bits. Only as many address bytes as needed follow (a /25 needs 4)."
             },
             {
              "name": "bgp.nlri_prefix",
              "text": "NLRI prefix: 198.51.100.0",
              "pos": 107,
              "size": 3,
              "note": "The prefix being announced."
             }
            ]
           }
          ]
         }
        ]
       }
      ],
      "focus": "bgp"
     },
     {
      "n": 16,
      "kind": "BGP UPDATE",
      "t": 131.626,
      "clock": "11:14:00.304",
      "from": "ISPB-R1",
      "to": "HQ1-CORE-R2",
      "src": "100.200.255.1",
      "dst": "100.200.255.2",
      "frame": 67,
      "link": "HQ1-CORE-R2 Et0/2 <-> ISPB-R1 Et0/2",
      "len": 110,
      "summary": "Announces and/or withdraws prefixes. Withdrawn routes first, then the path attributes, then the prefixes (NLRI) that share them.",
      "layers": [
       {
        "proto": "eth",
        "title": "Ethernet II, Src: aa:bb:cc:00:14:20, Dst: aa:bb:cc:00:19:20",
        "pos": 0,
        "size": 14,
        "note": "Layer 2 frame. Only matters on this one wire: the next hop rewrites both MAC addresses.",
        "fields": [
         {
          "name": "eth.dst",
          "text": "Destination: aa:bb:cc:00:19:20",
          "pos": 0,
          "size": 6,
          "note": "Who on this wire should take the frame."
         },
         {
          "name": "eth.src",
          "text": "Source: aa:bb:cc:00:14:20",
          "pos": 6,
          "size": 6,
          "note": "Which interface put it on the wire."
         },
         {
          "name": "eth.type",
          "text": "Type: IPv4 (0x0800)",
          "pos": 12,
          "size": 2,
          "note": "What comes next: 0x0800 IPv4, 0x86dd IPv6, 0x8100 VLAN tag, 0x0806 ARP."
         }
        ]
       },
       {
        "proto": "ip",
        "title": "Internet Protocol Version 4, Src: 100.200.255.1, Dst: 100.200.255.2",
        "pos": 14,
        "size": 20,
        "note": "Layer 3 header. Source and destination stay the same end to end (unless NAT rewrites them); TTL drops by one per router.",
        "fields": [
         {
          "name": "ip.version",
          "text": "0100 .... = Version: 4",
          "pos": 14,
          "size": 1,
          "note": "4 = IPv4."
         },
         {
          "name": "ip.hdr_len",
          "text": ".... 0101 = Header Length: 20 bytes (5)",
          "pos": 14,
          "size": 1,
          "note": "Header length. 20 bytes means no IP options."
         },
         {
          "name": "ip.dsfield",
          "text": "Differentiated Services Field: 0xc0 (DSCP: CS6, ECN: Not-ECT)",
          "pos": 15,
          "size": 1,
          "note": "DSCP + ECN. Routers mark control traffic like BGP CS6 (DSCP 48, byte 0xc0) so QoS keeps it alive under load.",
          "children": [
           {
            "name": "ip.dsfield.dscp",
            "text": "1100 00.. = Differentiated Services Codepoint: Class Selector 6 (48)",
            "pos": 15,
            "size": 1,
            "note": "DSCP class. 48 = CS6, the class for routing protocols."
           },
           {
            "name": "ip.dsfield.ecn",
            "text": ".... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0)",
            "pos": 15,
            "size": 1
           }
          ]
         },
         {
          "name": "ip.len",
          "text": "Total Length: 96",
          "pos": 16,
          "size": 2,
          "note": "Total IP packet length (header + payload)."
         },
         {
          "name": "ip.id",
          "text": "Identification: 0x2d73 (11635)",
          "pos": 18,
          "size": 2,
          "note": "Identification. Unique per packet from a sender; also how you match the same packet in two captures."
         },
         {
          "name": "ip.flags",
          "text": "010. .... = Flags: 0x2, Don't fragment",
          "pos": 20,
          "size": 1,
          "note": "Fragmentation flags. DF set = routers must not fragment it.",
          "children": [
           {
            "name": "ip.flags.rb",
            "text": "0... .... = Reserved bit: Not set",
            "pos": 20,
            "size": 1
           },
           {
            "name": "ip.flags.df",
            "text": ".1.. .... = Don't fragment: Set",
            "pos": 20,
            "size": 1,
            "note": "Don't Fragment. If the packet is too big for a link it is dropped and an ICMP 'fragmentation needed' comes back."
           },
           {
            "name": "ip.flags.mf",
            "text": "..0. .... = More fragments: Not set",
            "pos": 20,
            "size": 1
           }
          ]
         },
         {
          "name": "ip.frag_offset",
          "text": "...0 0000 0000 0000 = Fragment Offset: 0",
          "pos": 20,
          "size": 2,
          "note": "Where this fragment sits in the original packet. 0 = not fragmented (or first piece)."
         },
         {
          "name": "ip.ttl",
          "text": "Time to Live: 1",
          "pos": 22,
          "size": 1,
          "note": "Time to live. Each router subtracts one; at 0 the packet dies and ICMP time-exceeded goes back. eBGP peers default to TTL 1 (directly connected) unless ebgp-multihop or ttl-security is set."
         },
         {
          "name": "ip.proto",
          "text": "Protocol: TCP (6)",
          "pos": 23,
          "size": 1,
          "note": "What the payload is: 1 ICMP, 6 TCP, 17 UDP, 50 ESP, 89 OSPF, 88 EIGRP."
         },
         {
          "name": "ip.checksum",
          "text": "Header Checksum: 0x83d0 [validation disabled]",
          "pos": 24,
          "size": 2,
          "note": "Header checksum, recomputed by every router because TTL changes."
         },
         {
          "name": "ip.src",
          "text": "Source Address: 100.200.255.1",
          "pos": 26,
          "size": 4,
          "note": "Original sender."
         },
         {
          "name": "ip.dst",
          "text": "Destination Address: 100.200.255.2",
          "pos": 30,
          "size": 4,
          "note": "Final destination."
         }
        ]
       },
       {
        "proto": "tcp",
        "title": "Transmission Control Protocol, Src Port: 179, Dst Port: 20076, Seq: 123, Ack: 58, Len: 56",
        "pos": 34,
        "size": 20,
        "note": "Transport. BGP rides TCP port 179, so every BGP message is acknowledged, ordered and resent by TCP, not by BGP.",
        "fields": [
         {
          "name": "tcp.len",
          "text": "TCP Segment Len: 56",
          "pos": 34,
          "size": 0,
          "note": "Payload bytes in this segment. 0 = a pure ACK or control segment."
         },
         {
          "name": "tcp.seq",
          "text": "Sequence Number: 123    (relative sequence number)",
          "pos": 38,
          "size": 4,
          "note": "Sequence number (relative): byte position of this segment's first data byte."
         },
         {
          "name": "tcp.ack",
          "text": "Acknowledgment Number: 58    (relative ack number)",
          "pos": 42,
          "size": 4,
          "note": "Acknowledgement: the next byte this side expects from the other."
         },
         {
          "name": "tcp.hdr_len",
          "text": "0101 .... = Header Length: 20 bytes (5)",
          "pos": 46,
          "size": 1,
          "note": "TCP header length. 20 = no options; 32 = timestamps; larger on a SYN with MSS / window scale / SACK."
         },
         {
          "name": "tcp.flags",
          "text": "Flags: 0x018 (PSH, ACK)",
          "pos": 46,
          "size": 2,
          "note": "Control bits. SYN opens, FIN closes cleanly, RST aborts, ACK acknowledges, PSH says deliver now.",
          "children": [
           {
            "name": "tcp.flags.res",
            "text": "000. .... .... = Reserved: Not set",
            "pos": 46,
            "size": 1
           },
           {
            "name": "tcp.flags.ae",
            "text": "...0 .... .... = Accurate ECN: Not set",
            "pos": 46,
            "size": 1
           },
           {
            "name": "tcp.flags.cwr",
            "text": ".... 0... .... = Congestion Window Reduced: Not set",
            "pos": 47,
            "size": 1
           },
           {
            "name": "tcp.flags.ece",
            "text": ".... .0.. .... = ECN-Echo: Not set",
            "pos": 47,
            "size": 1
           },
           {
            "name": "tcp.flags.urg",
            "text": ".... ..0. .... = Urgent: Not set",
            "pos": 47,
            "size": 1
           },
           {
            "name": "tcp.flags.ack",
            "text": ".... ...1 .... = Acknowledgment: Set",
            "pos": 47,
            "size": 1,
            "note": "ACK: the acknowledgement number is valid."
           },
           {
            "name": "tcp.flags.push",
            "text": ".... .... 1... = Push: Set",
            "pos": 47,
            "size": 1,
            "note": "PSH: hand the data to the application now."
           },
           {
            "name": "tcp.flags.reset",
            "text": ".... .... .0.. = Reset: Not set",
            "pos": 47,
            "size": 1,
            "note": "RST: refuse or abort. A RST answering a SYN means nothing is listening on that port, or the application refuses this peer (a shut-down BGP neighbor does exactly this)."
           },
           {
            "name": "tcp.flags.syn",
            "text": ".... .... ..0. = Syn: Not set",
            "pos": 47,
            "size": 1,
            "note": "SYN: open a connection."
           },
           {
            "name": "tcp.flags.fin",
            "text": ".... .... ...0 = Fin: Not set",
            "pos": 47,
            "size": 1,
            "note": "FIN: this side has nothing more to send; a clean close."
           },
           {
            "name": "tcp.flags.str",
            "text": "TCP Flags: \u00b7\u00b7\u00b7\u00b7\u00b7\u00b7\u00b7AP\u00b7\u00b7\u00b7",
            "pos": 46,
            "size": 2
           }
          ]
         },
         {
          "name": "tcp.window_size_value",
          "text": "Window: 15529",
          "pos": 48,
          "size": 2,
          "note": "Receive window: how many bytes the sender can accept right now."
         },
         {
          "name": "tcp.window_size_scalefactor",
          "text": "Window size scaling factor: -1 (unknown)",
          "pos": 48,
          "size": 2
         },
         {
          "name": "tcp.checksum",
          "text": "Checksum: 0xb14e [unverified]",
          "pos": 50,
          "size": 2,
          "note": "Checksum over header + payload."
         },
         {
          "name": "tcp.urgent_pointer",
          "text": "Urgent Pointer: 0",
          "pos": 52,
          "size": 2,
          "note": "Unused by BGP."
         },
         {
          "name": "",
          "text": "Timestamps",
          "pos": 34,
          "size": 0
         }
        ]
       },
       {
        "proto": "bgp",
        "title": "Border Gateway Protocol - UPDATE Message",
        "pos": 54,
        "size": 56,
        "note": "Border Gateway Protocol: routers in different (eBGP) or the same (iBGP) autonomous systems swap reachability. Every message starts with the same 19-byte header: 16-byte marker, 2-byte length, 1-byte type.",
        "fields": [
         {
          "name": "bgp.marker",
          "text": "Marker: ffffffffffffffffffffffffffffffff",
          "pos": 54,
          "size": 16,
          "note": "16 bytes of 0xff. Kept for compatibility (it once carried authentication); every BGP message has it."
         },
         {
          "name": "bgp.length",
          "text": "Length: 56",
          "pos": 70,
          "size": 2,
          "note": "Whole BGP message length in bytes, header included. Minimum 19 (a KEEPALIVE), maximum 4096 (65535 with extended messages)."
         },
         {
          "name": "bgp.type",
          "text": "Type: UPDATE Message (2)",
          "pos": 72,
          "size": 1,
          "note": "UPDATE: announces prefixes (with their path attributes) and/or withdraws prefixes."
         },
         {
          "name": "bgp.update.withdrawn_routes.length",
          "text": "Withdrawn Routes Length: 0",
          "pos": 73,
          "size": 2,
          "note": "Bytes of withdrawn prefixes that follow. 0 = this UPDATE withdraws nothing."
         },
         {
          "name": "bgp.update.path_attributes.length",
          "text": "Total Path Attribute Length: 28",
          "pos": 75,
          "size": 2,
          "note": "Bytes of path attributes. 0 = a pure withdraw."
         },
         {
          "name": "bgp.update.path_attributes",
          "text": "Path attributes",
          "pos": 77,
          "size": 28,
          "children": [
           {
            "name": "bgp.update.path_attribute",
            "text": "Path Attribute - ORIGIN: IGP",
            "pos": 77,
            "size": 4,
            "note": "ORIGIN attribute (well-known, mandatory).",
            "children": [
             {
              "name": "bgp.update.path_attribute.flags",
              "text": "Flags: 0x40, Transitive, Well-known, Complete",
              "pos": 77,
              "size": 1,
              "note": "Attribute flags: Optional (vs well-known), Transitive (pass it on), Partial, Extended length.",
              "children": [
               {
                "name": "bgp.update.path_attribute.flags.optional",
                "text": "0... .... = Optional: Not set",
                "pos": 77,
                "size": 1,
                "note": "Well-known attributes (ORIGIN, AS_PATH, NEXT_HOP, LOCAL_PREF) must be understood by every BGP router; optional ones (MED, communities) may not be."
               },
               {
                "name": "bgp.update.path_attribute.flags.transitive",
                "text": ".1.. .... = Transitive: Set",
                "pos": 77,
                "size": 1,
                "note": "Transitive: a router that doesn't understand an optional attribute still passes it on."
               },
               {
                "name": "bgp.update.path_attribute.flags.partial",
                "text": "..0. .... = Partial: Not set",
                "pos": 77,
                "size": 1
               },
               {
                "name": "bgp.update.path_attribute.flags.extended_length",
                "text": "...0 .... = Extended-Length: Not set",
                "pos": 77,
                "size": 1
               },
               {
                "name": "bgp.update.path_attribute.flags.unused",
                "text": ".... 0000 = Unused: 0x0",
                "pos": 77,
                "size": 1
               }
              ]
             },
             {
              "name": "bgp.update.path_attribute.type_code",
              "text": "Type Code: ORIGIN (1)",
              "pos": 78,
              "size": 1,
              "note": "Which attribute: 1 ORIGIN, 2 AS_PATH, 3 NEXT_HOP, 4 MED, 5 LOCAL_PREF, 8 COMMUNITIES."
             },
             {
              "name": "bgp.update.path_attribute.length",
              "text": "Length: 1",
              "pos": 79,
              "size": 1
             },
             {
              "name": "bgp.update.path_attribute.origin",
              "text": "Origin: IGP (0)",
              "pos": 80,
              "size": 1,
              "note": "How the route entered BGP: IGP (network statement), EGP, or Incomplete (redistributed). Best path prefers IGP < EGP < Incomplete."
             }
            ]
           },
           {
            "name": "bgp.update.path_attribute",
            "text": "Path Attribute - AS_PATH: 65200 65100 65001 ",
            "pos": 81,
            "size": 17,
            "note": "AS_PATH: every AS the route passed through. Shorter wins in best-path (after weight, local-pref, locally originated).",
            "children": [
             {
              "name": "bgp.update.path_attribute.flags",
              "text": "Flags: 0x40, Transitive, Well-known, Complete",
              "pos": 81,
              "size": 1,
              "note": "Attribute flags: Optional (vs well-known), Transitive (pass it on), Partial, Extended length.",
              "children": [
               {
                "name": "bgp.update.path_attribute.flags.optional",
                "text": "0... .... = Optional: Not set",
                "pos": 81,
                "size": 1,
                "note": "Well-known attributes (ORIGIN, AS_PATH, NEXT_HOP, LOCAL_PREF) must be understood by every BGP router; optional ones (MED, communities) may not be."
               },
               {
                "name": "bgp.update.path_attribute.flags.transitive",
                "text": ".1.. .... = Transitive: Set",
                "pos": 81,
                "size": 1,
                "note": "Transitive: a router that doesn't understand an optional attribute still passes it on."
               },
               {
                "name": "bgp.update.path_attribute.flags.partial",
                "text": "..0. .... = Partial: Not set",
                "pos": 81,
                "size": 1
               },
               {
                "name": "bgp.update.path_attribute.flags.extended_length",
                "text": "...0 .... = Extended-Length: Not set",
                "pos": 81,
                "size": 1
               },
               {
                "name": "bgp.update.path_attribute.flags.unused",
                "text": ".... 0000 = Unused: 0x0",
                "pos": 81,
                "size": 1
               }
              ]
             },
             {
              "name": "bgp.update.path_attribute.type_code",
              "text": "Type Code: AS_PATH (2)",
              "pos": 82,
              "size": 1,
              "note": "Which attribute: 1 ORIGIN, 2 AS_PATH, 3 NEXT_HOP, 4 MED, 5 LOCAL_PREF, 8 COMMUNITIES."
             },
             {
              "name": "bgp.update.path_attribute.length",
              "text": "Length: 14",
              "pos": 83,
              "size": 1
             },
             {
              "name": "bgp.update.path_attribute.as_path_segment",
              "text": "AS Path segment: 65200 65100 65001",
              "pos": 84,
              "size": 14,
              "children": [
               {
                "name": "bgp.update.path_attribute.as_path_segment.type",
                "text": "Segment type: AS_SEQUENCE (2)",
                "pos": 84,
                "size": 1,
                "note": "AS_SEQUENCE = ordered list of ASes the route crossed; AS_SET = an unordered set (from aggregation)."
               },
               {
                "name": "bgp.update.path_attribute.as_path_segment.length",
                "text": "Segment length (number of ASN): 3",
                "pos": 85,
                "size": 1,
                "note": "How many AS numbers follow."
               },
               {
                "name": "bgp.update.path_attribute.as_path_segment.as4",
                "text": "AS4: 65200",
                "pos": 86,
                "size": 4,
                "note": "One AS on the path, newest first: the leftmost AS is the neighbor that sent it, the rightmost is where the route started. A router that finds its own AS in the path drops the route (loop prevention)."
               },
               {
                "name": "bgp.update.path_attribute.as_path_segment.as4",
                "text": "AS4: 65100",
                "pos": 90,
                "size": 4,
                "note": "One AS on the path, newest first: the leftmost AS is the neighbor that sent it, the rightmost is where the route started. A router that finds its own AS in the path drops the route (loop prevention)."
               },
               {
                "name": "bgp.update.path_attribute.as_path_segment.as4",
                "text": "AS4: 65001",
                "pos": 94,
                "size": 4,
                "note": "One AS on the path, newest first: the leftmost AS is the neighbor that sent it, the rightmost is where the route started. A router that finds its own AS in the path drops the route (loop prevention)."
               }
              ]
             }
            ]
           },
           {
            "name": "bgp.update.path_attribute",
            "text": "Path Attribute - NEXT_HOP: 100.200.255.1 ",
            "pos": 98,
            "size": 7,
            "note": "NEXT_HOP attribute (well-known, mandatory).",
            "children": [
             {
              "name": "bgp.update.path_attribute.flags",
              "text": "Flags: 0x40, Transitive, Well-known, Complete",
              "pos": 98,
              "size": 1,
              "note": "Attribute flags: Optional (vs well-known), Transitive (pass it on), Partial, Extended length.",
              "children": [
               {
                "name": "bgp.update.path_attribute.flags.optional",
                "text": "0... .... = Optional: Not set",
                "pos": 98,
                "size": 1,
                "note": "Well-known attributes (ORIGIN, AS_PATH, NEXT_HOP, LOCAL_PREF) must be understood by every BGP router; optional ones (MED, communities) may not be."
               },
               {
                "name": "bgp.update.path_attribute.flags.transitive",
                "text": ".1.. .... = Transitive: Set",
                "pos": 98,
                "size": 1,
                "note": "Transitive: a router that doesn't understand an optional attribute still passes it on."
               },
               {
                "name": "bgp.update.path_attribute.flags.partial",
                "text": "..0. .... = Partial: Not set",
                "pos": 98,
                "size": 1
               },
               {
                "name": "bgp.update.path_attribute.flags.extended_length",
                "text": "...0 .... = Extended-Length: Not set",
                "pos": 98,
                "size": 1
               },
               {
                "name": "bgp.update.path_attribute.flags.unused",
                "text": ".... 0000 = Unused: 0x0",
                "pos": 98,
                "size": 1
               }
              ]
             },
             {
              "name": "bgp.update.path_attribute.type_code",
              "text": "Type Code: NEXT_HOP (3)",
              "pos": 99,
              "size": 1,
              "note": "Which attribute: 1 ORIGIN, 2 AS_PATH, 3 NEXT_HOP, 4 MED, 5 LOCAL_PREF, 8 COMMUNITIES."
             },
             {
              "name": "bgp.update.path_attribute.length",
              "text": "Length: 4",
              "pos": 100,
              "size": 1
             },
             {
              "name": "bgp.update.path_attribute.next_hop",
              "text": "Next hop: 100.200.255.1",
              "pos": 101,
              "size": 4,
              "note": "Where to send traffic for these prefixes. eBGP sets it to the sender's own address; iBGP passes it through unless next-hop-self."
             }
            ]
           }
          ]
         },
         {
          "name": "bgp.update.nlri",
          "text": "Network Layer Reachability Information (NLRI)",
          "pos": 105,
          "size": 5,
          "note": "NLRI: the prefixes this UPDATE announces, all sharing the attributes above.",
          "children": [
           {
            "name": "",
            "text": "198.51.100.0/25",
            "pos": 105,
            "size": 5,
            "children": [
             {
              "name": "bgp.prefix_length",
              "text": "NLRI prefix length: 25",
              "pos": 105,
              "size": 1,
              "note": "Prefix length in bits. Only as many address bytes as needed follow (a /25 needs 4)."
             },
             {
              "name": "bgp.nlri_prefix",
              "text": "NLRI prefix: 198.51.100.0",
              "pos": 106,
              "size": 4,
              "note": "The prefix being announced."
             }
            ]
           }
          ]
         }
        ]
       }
      ],
      "focus": "bgp"
     }
    ],
    "protos": [
     "bgp",
     "icmp"
    ]
   },
   "tables": [
    {
     "title": "Packets broken down below",
     "columns": [
      "#",
      "Clock",
      "Message",
      "From -> to",
      "Bytes",
      "Frame"
     ],
     "rows": [
      [
       1,
       "11:11:49.270",
       "ICMP echo request",
       "HQ1-CORE-R1 -> ISPA-R1",
       78,
       2
      ],
      [
       2,
       "11:11:49.272",
       "ICMP echo reply",
       "ISPA-R1 -> HQ1-CORE-R1",
       78,
       3
      ],
      [
       3,
       "11:11:56.033",
       "BGP KEEPALIVE",
       "ISPA-R1 -> HQ1-CORE-R1",
       73,
       9
      ],
      [
       4,
       "11:11:56.594",
       "BGP KEEPALIVE",
       "ISPB-R1 -> HQ1-CORE-R2",
       73,
       4
      ],
      [
       5,
       "11:11:59.008",
       "BGP KEEPALIVE",
       "HQ1-CORE-R1 -> ISPA-R1",
       73,
       12
      ],
      [
       6,
       "11:11:59.271",
       "ICMP unreachable, admin prohibited",
       "ISPA-R1 -> HQ1-CORE-R1",
       70,
       15
      ],
      [
       7,
       "11:12:14.637",
       "BGP NOTIFICATION",
       "HQ1-CORE-R1 -> ISPA-R1",
       75,
       23
      ],
      [
       8,
       "11:12:14.643",
       "BGP UPDATE",
       "ISPB-R1 -> HQ1-CORE-R2",
       110,
       14
      ],
      [
       9,
       "11:12:44.741",
       "BGP UPDATE",
       "ISPB-R1 -> HQ1-CORE-R2",
       82,
       21
      ],
      [
       10,
       "11:14:00.291",
       "BGP OPEN",
       "HQ1-CORE-R1 -> ISPA-R1",
       111,
       114
      ],
      [
       11,
       "11:14:00.292",
       "BGP OPEN",
       "ISPA-R1 -> HQ1-CORE-R1",
       111,
       116
      ],
      [
       12,
       "11:14:00.295",
       "BGP ROUTE-REFRESH",
       "ISPA-R1 -> HQ1-CORE-R1",
       77,
       120
      ],
      [
       13,
       "11:14:00.298",
       "BGP UPDATE",
       "ISPA-R1 -> HQ1-CORE-R1",
       426,
       121
      ],
      [
       14,
       "11:14:00.300",
       "BGP UPDATE",
       "HQ1-CORE-R1 -> ISPA-R1",
       196,
       123
      ],
      [
       15,
       "11:14:00.302",
       "BGP UPDATE",
       "ISPA-R1 -> HQ1-CORE-R1",
       110,
       125
      ],
      [
       16,
       "11:14:00.304",
       "BGP UPDATE",
       "ISPB-R1 -> HQ1-CORE-R2",
       110,
       67
      ]
     ]
    }
   ]
  },
  "bgp": {
   "summary": "2 BGP session(s), 30 BGP message(s): 14 UPDATE, 11 KEEPALIVE, 2 OPEN, 2 ROUTE-REFRESH, 1 NOTIFICATION.",
   "data": {
    "names": {
     "100.200.255.2": "HQ1-CORE-R2",
     "100.200.255.10": "ISPB-R1",
     "100.100.255.2": "HQ1-CORE-R1",
     "100.200.1.1": "ISPA-R1",
     "100.100.255.1": "ISPA-R1",
     "100.200.255.1": "ISPB-R1",
     "34.107.243.93": "ISPB-R1",
     "198.51.100.140": "HQ1-CORE-R2"
    },
    "sessions": [
     {
      "pair": "100.100.255.1 <-> 100.100.255.2",
      "a": "100.100.255.1",
      "b": "100.100.255.2",
      "a_name": "ISPA-R1 (100.100.255.1)",
      "b_name": "HQ1-CORE-R1 (100.100.255.2)",
      "counts": {
       "UPDATE": 11,
       "KEEPALIVE": 6,
       "OPEN": 2,
       "ROUTE-REFRESH": 2,
       "NOTIFICATION": 1
      },
      "keepalive": {
       "100.100.255.1": {
        "n": 3
       },
       "100.100.255.2": {
        "n": 3
       }
      },
      "opens": [
       {
        "from": "HQ1-CORE-R1 (100.100.255.2)",
        "as": "65001",
        "hold": "180",
        "rid": "10.255.1.1",
        "clock": "11:14:00.291",
        "t": 131.6133,
        "caps": [
         "Multiprotocol",
         "Route refresh (Cisco)",
         "Route refresh",
         "Enhanced route refresh",
         "4-byte AS"
        ],
        "no": 114
       },
       {
        "from": "ISPA-R1 (100.100.255.1)",
        "as": "65100",
        "hold": "180",
        "rid": "100.100.254.1",
        "clock": "11:14:00.292",
        "t": 131.6147,
        "caps": [
         "Multiprotocol",
         "Route refresh (Cisco)",
         "Route refresh",
         "Enhanced route refresh",
         "4-byte AS"
        ],
        "no": 116
       }
      ],
      "notifications": [
       {
        "t": 25.9594,
        "clock": "11:12:14.637",
        "from": "HQ1-CORE-R1 (100.100.255.2)",
        "to": "ISPA-R1 (100.100.255.1)",
        "reason": "Cease / Administrative shutdown",
        "no": 23
       }
      ],
      "updates": [
       {
        "t": 131.6211,
        "clock": "11:14:00.298",
        "from": "ISPA-R1 (100.100.255.1)",
        "to": "HQ1-CORE-R1 (100.100.255.2)",
        "nlri": [
         "203.0.113.0/24"
        ],
        "withdrawn": [],
        "as_path": "65100 65002",
        "next_hop": "100.100.255.1",
        "local_pref": "",
        "med": "",
        "origin": "IGP",
        "no": 121
       },
       {
        "t": 131.6211,
        "clock": "11:14:00.298",
        "from": "ISPA-R1 (100.100.255.1)",
        "to": "HQ1-CORE-R1 (100.100.255.2)",
        "nlri": [
         "198.51.100.0/25"
        ],
        "withdrawn": [],
        "as_path": "65100 65200 65001 65001 65001 65001",
        "next_hop": "100.100.255.1",
        "local_pref": "",
        "med": "",
        "origin": "IGP",
        "no": 121
       },
       {
        "t": 131.6211,
        "clock": "11:14:00.298",
        "from": "ISPA-R1 (100.100.255.1)",
        "to": "HQ1-CORE-R1 (100.100.255.2)",
        "nlri": [
         "198.51.100.128/25",
         "198.51.100.0/24"
        ],
        "withdrawn": [],
        "as_path": "65100 65200 65001",
        "next_hop": "100.100.255.1",
        "local_pref": "",
        "med": "",
        "origin": "IGP",
        "no": 121
       },
       {
        "t": 131.6211,
        "clock": "11:14:00.298",
        "from": "ISPA-R1 (100.100.255.1)",
        "to": "HQ1-CORE-R1 (100.100.255.2)",
        "nlri": [
         "100.200.0.0/16"
        ],
        "withdrawn": [],
        "as_path": "65100 65200",
        "next_hop": "100.100.255.1",
        "local_pref": "",
        "med": "",
        "origin": "IGP",
        "no": 121
       },
       {
        "t": 131.6211,
        "clock": "11:14:00.298",
        "from": "ISPA-R1 (100.100.255.1)",
        "to": "HQ1-CORE-R1 (100.100.255.2)",
        "nlri": [
         "100.100.0.0/16"
        ],
        "withdrawn": [],
        "as_path": "65100",
        "next_hop": "100.100.255.1",
        "local_pref": "",
        "med": "0",
        "origin": "IGP",
        "no": 121
       },
       {
        "t": 131.6211,
        "clock": "11:14:00.298",
        "from": "ISPA-R1 (100.100.255.1)",
        "to": "HQ1-CORE-R1 (100.100.255.2)",
        "nlri": [
         "0.0.0.0/0"
        ],
        "withdrawn": [],
        "as_path": "65100",
        "next_hop": "100.100.255.1",
        "local_pref": "",
        "med": "",
        "origin": "IGP",
        "no": 121
       },
       {
        "t": 131.6211,
        "clock": "11:14:00.298",
        "from": "ISPA-R1 (100.100.255.1)",
        "to": "HQ1-CORE-R1 (100.100.255.2)",
        "nlri": [],
        "withdrawn": [],
        "as_path": "",
        "next_hop": "",
        "local_pref": "",
        "med": "",
        "origin": "",
        "no": 121
       },
       {
        "t": 131.6224,
        "clock": "11:14:00.300",
        "from": "HQ1-CORE-R1 (100.100.255.2)",
        "to": "ISPA-R1 (100.100.255.1)",
        "nlri": [
         "198.51.100.128/25"
        ],
        "withdrawn": [],
        "as_path": "65001 65001 65001 65001",
        "next_hop": "100.100.255.2",
        "local_pref": "",
        "med": "",
        "origin": "IGP",
        "no": 123
       },
       {
        "t": 131.6224,
        "clock": "11:14:00.300",
        "from": "HQ1-CORE-R1 (100.100.255.2)",
        "to": "ISPA-R1 (100.100.255.1)",
        "nlri": [
         "198.51.100.0/25",
         "198.51.100.0/24"
        ],
        "withdrawn": [],
        "as_path": "65001",
        "next_hop": "100.100.255.2",
        "local_pref": "",
        "med": "0",
        "origin": "IGP",
        "no": 123
       },
       {
        "t": 131.6224,
        "clock": "11:14:00.300",
        "from": "HQ1-CORE-R1 (100.100.255.2)",
        "to": "ISPA-R1 (100.100.255.1)",
        "nlri": [],
        "withdrawn": [],
        "as_path": "",
        "next_hop": "",
        "local_pref": "",
        "med": "",
        "origin": "",
        "no": 123
       },
       {
        "t": 131.6244,
        "clock": "11:14:00.302",
        "from": "ISPA-R1 (100.100.255.1)",
        "to": "HQ1-CORE-R1 (100.100.255.2)",
        "nlri": [
         "198.51.100.0/25",
         "198.51.100.0/24"
        ],
        "withdrawn": [],
        "as_path": "65100 65001",
        "next_hop": "100.100.255.2",
        "local_pref": "",
        "med": "",
        "origin": "IGP",
        "no": 125
       }
      ],
      "up_at_start": false,
      "fin": [
       {
        "clock": "11:12:14.639",
        "from": "HQ1-CORE-R1 (100.100.255.2)",
        "t": 25.9617
       },
       {
        "clock": "11:12:14.639",
        "from": "ISPA-R1 (100.100.255.1)",
        "t": 25.9619
       }
      ],
      "connects": [
       {
        "t": 36.0379,
        "clock": "11:12:24.715",
        "from": "ISPA-R1 (100.100.255.1)",
        "to": "HQ1-CORE-R1 (100.100.255.2)",
        "refused": true,
        "no": 35
       },
       {
        "t": 50.3777,
        "clock": "11:12:39.055",
        "from": "ISPA-R1 (100.100.255.1)",
        "to": "HQ1-CORE-R1 (100.100.255.2)",
        "refused": true,
        "no": 45
       },
       {
        "t": 62.6656,
        "clock": "11:12:51.343",
        "from": "ISPA-R1 (100.100.255.1)",
        "to": "HQ1-CORE-R1 (100.100.255.2)",
        "refused": true,
        "no": 55
       },
       {
        "t": 72.9084,
        "clock": "11:13:01.586",
        "from": "ISPA-R1 (100.100.255.1)",
        "to": "HQ1-CORE-R1 (100.100.255.2)",
        "refused": true,
        "no": 63
       },
       {
        "t": 84.1734,
        "clock": "11:13:12.851",
        "from": "ISPA-R1 (100.100.255.1)",
        "to": "HQ1-CORE-R1 (100.100.255.2)",
        "refused": true,
        "no": 70
       },
       {
        "t": 92.3681,
        "clock": "11:13:21.045",
        "from": "ISPA-R1 (100.100.255.1)",
        "to": "HQ1-CORE-R1 (100.100.255.2)",
        "refused": true,
        "no": 78
       },
       {
        "t": 104.6601,
        "clock": "11:13:33.337",
        "from": "ISPA-R1 (100.100.255.1)",
        "to": "HQ1-CORE-R1 (100.100.255.2)",
        "refused": true,
        "no": 88
       },
       {
        "t": 118.9978,
        "clock": "11:13:47.675",
        "from": "ISPA-R1 (100.100.255.1)",
        "to": "HQ1-CORE-R1 (100.100.255.2)",
        "refused": true,
        "no": 97
       },
       {
        "t": 128.2148,
        "clock": "11:13:56.892",
        "from": "ISPA-R1 (100.100.255.1)",
        "to": "HQ1-CORE-R1 (100.100.255.2)",
        "refused": true,
        "no": 106
       },
       {
        "t": 131.6104,
        "clock": "11:14:00.288",
        "from": "HQ1-CORE-R1 (100.100.255.2)",
        "to": "ISPA-R1 (100.100.255.1)",
        "refused": false,
        "no": 111
       }
      ],
      "reopened": {
       "clock": "11:14:00.291",
       "t": 131.6133,
       "down_s": 105.654,
       "no": 114
      }
     },
     {
      "pair": "100.200.255.1 <-> 100.200.255.2",
      "a": "100.200.255.1",
      "b": "100.200.255.2",
      "a_name": "ISPB-R1 (100.200.255.1)",
      "b_name": "HQ1-CORE-R2 (100.200.255.2)",
      "counts": {
       "KEEPALIVE": 5,
       "UPDATE": 3
      },
      "keepalive": {
       "100.200.255.1": {
        "n": 2,
        "msgs": 5,
        "median": 26.7227,
        "min": 18.0496,
        "max": 52.2148
       },
       "100.200.255.2": {
        "n": 3,
        "msgs": 3,
        "median": 53.7718,
        "min": 52.2367,
        "max": 55.3068
       }
      },
      "opens": [],
      "notifications": [],
      "updates": [
       {
        "t": 25.9661,
        "clock": "11:12:14.643",
        "from": "ISPB-R1 (100.200.255.1)",
        "to": "HQ1-CORE-R2 (100.200.255.2)",
        "nlri": [
         "198.51.100.0/25"
        ],
        "withdrawn": [],
        "as_path": "65200 65100 65001",
        "next_hop": "100.200.255.1",
        "local_pref": "",
        "med": "",
        "origin": "IGP",
        "no": 14
       },
       {
        "t": 56.0641,
        "clock": "11:12:44.741",
        "from": "ISPB-R1 (100.200.255.1)",
        "to": "HQ1-CORE-R2 (100.200.255.2)",
        "nlri": [],
        "withdrawn": [
         "198.51.100.0/25"
        ],
        "as_path": "",
        "next_hop": "",
        "local_pref": "",
        "med": "",
        "origin": "",
        "no": 21
       },
       {
        "t": 131.6262,
        "clock": "11:14:00.304",
        "from": "ISPB-R1 (100.200.255.1)",
        "to": "HQ1-CORE-R2 (100.200.255.2)",
        "nlri": [
         "198.51.100.0/25"
        ],
        "withdrawn": [],
        "as_path": "65200 65100 65001",
        "next_hop": "100.200.255.1",
        "local_pref": "",
        "med": "",
        "origin": "IGP",
        "no": 67
       }
      ],
      "up_at_start": true,
      "fin": [],
      "connects": []
     }
    ],
    "messages": [
     {
      "no": 9,
      "epoch": 1795626716.0338,
      "src": "100.100.255.1",
      "dst": "100.100.255.2",
      "sport": "179",
      "dport": "20305",
      "type": "KEEPALIVE",
      "type_n": 4,
      "blen": "19",
      "major": null,
      "minor": null,
      "reason": null,
      "myas": null,
      "hold": null,
      "rid": null,
      "caps": null,
      "subtype": null,
      "nlri": null,
      "withdrawn": null,
      "as_path": null,
      "next_hop": null,
      "local_pref": null,
      "med": null,
      "origin": null,
      "eor": null,
      "t": 7.356,
      "pair": "100.100.255.1 <-> 100.100.255.2"
     },
     {
      "no": 12,
      "epoch": 1795626719.0083,
      "src": "100.100.255.2",
      "dst": "100.100.255.1",
      "sport": "20305",
      "dport": "179",
      "type": "KEEPALIVE",
      "type_n": 4,
      "blen": "19",
      "major": null,
      "minor": null,
      "reason": null,
      "myas": null,
      "hold": null,
      "rid": null,
      "caps": null,
      "subtype": null,
      "nlri": null,
      "withdrawn": null,
      "as_path": null,
      "next_hop": null,
      "local_pref": null,
      "med": null,
      "origin": null,
      "eor": null,
      "t": 10.3305,
      "pair": "100.100.255.1 <-> 100.100.255.2"
     },
     {
      "no": 23,
      "epoch": 1795626734.6372,
      "src": "100.100.255.2",
      "dst": "100.100.255.1",
      "sport": "20305",
      "dport": "179",
      "type": "NOTIFICATION",
      "type_n": 3,
      "blen": "21",
      "major": 6.0,
      "minor": 2.0,
      "reason": "Cease / Administrative shutdown",
      "myas": null,
      "hold": null,
      "rid": null,
      "caps": null,
      "subtype": null,
      "nlri": null,
      "withdrawn": null,
      "as_path": null,
      "next_hop": null,
      "local_pref": null,
      "med": null,
      "origin": null,
      "eor": null,
      "t": 25.9594,
      "pair": "100.100.255.1 <-> 100.100.255.2"
     },
     {
      "no": 114,
      "epoch": 1795626840.2911,
      "src": "100.100.255.2",
      "dst": "100.100.255.1",
      "sport": "21381",
      "dport": "179",
      "type": "OPEN",
      "type_n": 1,
      "blen": "57",
      "major": null,
      "minor": null,
      "reason": null,
      "myas": "65001",
      "hold": "180",
      "rid": "10.255.1.1",
      "caps": [
       "Multiprotocol",
       "Route refresh (Cisco)",
       "Route refresh",
       "Enhanced route refresh",
       "4-byte AS"
      ],
      "subtype": null,
      "nlri": null,
      "withdrawn": null,
      "as_path": null,
      "next_hop": null,
      "local_pref": null,
      "med": null,
      "origin": null,
      "eor": null,
      "t": 131.6133,
      "pair": "100.100.255.1 <-> 100.100.255.2"
     },
     {
      "no": 116,
      "epoch": 1795626840.2925,
      "src": "100.100.255.1",
      "dst": "100.100.255.2",
      "sport": "179",
      "dport": "21381",
      "type": "OPEN",
      "type_n": 1,
      "blen": "57",
      "major": null,
      "minor": null,
      "reason": null,
      "myas": "65100",
      "hold": "180",
      "rid": "100.100.254.1",
      "caps": [
       "Multiprotocol",
       "Route refresh (Cisco)",
       "Route refresh",
       "Enhanced route refresh",
       "4-byte AS"
      ],
      "subtype": null,
      "nlri": null,
      "withdrawn": null,
      "as_path": null,
      "next_hop": null,
      "local_pref": null,
      "med": null,
      "origin": null,
      "eor": null,
      "t": 131.6147,
      "pair": "100.100.255.1 <-> 100.100.255.2"
     },
     {
      "no": 117,
      "epoch": 1795626840.293,
      "src": "100.100.255.1",
      "dst": "100.100.255.2",
      "sport": "179",
      "dport": "21381",
      "type": "KEEPALIVE",
      "type_n": 4,
      "blen": "19",
      "major": null,
      "minor": null,
      "reason": null,
      "myas": null,
      "hold": null,
      "rid": null,
      "caps": null,
      "subtype": null,
      "nlri": null,
      "withdrawn": null,
      "as_path": null,
      "next_hop": null,
      "local_pref": null,
      "med": null,
      "origin": null,
      "eor": null,
      "t": 131.6152,
      "pair": "100.100.255.1 <-> 100.100.255.2"
     },
     {
      "no": 119,
      "epoch": 1795626840.2942,
      "src": "100.100.255.2",
      "dst": "100.100.255.1",
      "sport": "21381",
      "dport": "179",
      "type": "KEEPALIVE",
      "type_n": 4,
      "blen": "19",
      "major": null,
      "minor": null,
      "reason": null,
      "myas": null,
      "hold": null,
      "rid": null,
      "caps": null,
      "subtype": null,
      "nlri": null,
      "withdrawn": null,
      "as_path": null,
      "next_hop": null,
      "local_pref": null,
      "med": null,
      "origin": null,
      "eor": null,
      "t": 131.6164,
      "pair": "100.100.255.1 <-> 100.100.255.2"
     },
     {
      "no": 120,
      "epoch": 1795626840.2952,
      "src": "100.100.255.1",
      "dst": "100.100.255.2",
      "sport": "179",
      "dport": "21381",
      "type": "ROUTE-REFRESH",
      "type_n": 5,
      "blen": "23",
      "major": null,
      "minor": null,
      "reason": null,
      "myas": null,
      "hold": null,
      "rid": null,
      "caps": null,
      "subtype": "BoRR (begin)",
      "nlri": null,
      "withdrawn": null,
      "as_path": null,
      "next_hop": null,
      "local_pref": null,
      "med": null,
      "origin": null,
      "eor": null,
      "t": 131.6174,
      "pair": "100.100.255.1 <-> 100.100.255.2"
     },
     {
      "no": 121,
      "epoch": 1795626840.2988,
      "src": "100.100.255.1",
      "dst": "100.100.255.2",
      "sport": "179",
      "dport": "21381",
      "type": "UPDATE",
      "type_n": 2,
      "blen": "51",
      "major": null,
      "minor": null,
      "reason": null,
      "myas": null,
      "hold": null,
      "rid": null,
      "caps": null,
      "subtype": null,
      "nlri": [
       "203.0.113.0/24"
      ],
      "withdrawn": [],
      "as_path": "65100 65002",
      "next_hop": "100.100.255.1",
      "local_pref": "",
      "med": "",
      "origin": "IGP",
      "eor": null,
      "t": 131.6211,
      "pair": "100.100.255.1 <-> 100.100.255.2"
     },
     {
      "no": 121,
      "epoch": 1795626840.2988,
      "src": "100.100.255.1",
      "dst": "100.100.255.2",
      "sport": "179",
      "dport": "21381",
      "type": "UPDATE",
      "type_n": 2,
      "blen": "68",
      "major": null,
      "minor": null,
      "reason": null,
      "myas": null,
      "hold": null,
      "rid": null,
      "caps": null,
      "subtype": null,
      "nlri": [
       "198.51.100.0/25"
      ],
      "withdrawn": [],
      "as_path": "65100 65200 65001 65001 65001 65001",
      "next_hop": "100.100.255.1",
      "local_pref": "",
      "med": "",
      "origin": "IGP",
      "eor": null,
      "t": 131.6211,
      "pair": "100.100.255.1 <-> 100.100.255.2"
     },
     {
      "no": 121,
      "epoch": 1795626840.2988,
      "src": "100.100.255.1",
      "dst": "100.100.255.2",
      "sport": "179",
      "dport": "21381",
      "type": "UPDATE",
      "type_n": 2,
      "blen": "60",
      "major": null,
      "minor": null,
      "reason": null,
      "myas": null,
      "hold": null,
      "rid": null,
      "caps": null,
      "subtype": null,
      "nlri": [
       "198.51.100.128/25",
       "198.51.100.0/24"
      ],
      "withdrawn": [],
      "as_path": "65100 65200 65001",
      "next_hop": "100.100.255.1",
      "local_pref": "",
      "med": "",
      "origin": "IGP",
      "eor": null,
      "t": 131.6211,
      "pair": "100.100.255.1 <-> 100.100.255.2"
     },
     {
      "no": 121,
      "epoch": 1795626840.2988,
      "src": "100.100.255.1",
      "dst": "100.100.255.2",
      "sport": "179",
      "dport": "21381",
      "type": "UPDATE",
      "type_n": 2,
      "blen": "50",
      "major": null,
      "minor": null,
      "reason": null,
      "myas": null,
      "hold": null,
      "rid": null,
      "caps": null,
      "subtype": null,
      "nlri": [
       "100.200.0.0/16"
      ],
      "withdrawn": [],
      "as_path": "65100 65200",
      "next_hop": "100.100.255.1",
      "local_pref": "",
      "med": "",
      "origin": "IGP",
      "eor": null,
      "t": 131.6211,
      "pair": "100.100.255.1 <-> 100.100.255.2"
     },
     {
      "no": 121,
      "epoch": 1795626840.2988,
      "src": "100.100.255.1",
      "dst": "100.100.255.2",
      "sport": "179",
      "dport": "21381",
      "type": "UPDATE",
      "type_n": 2,
      "blen": "53",
      "major": null,
      "minor": null,
      "reason": null,
      "myas": null,
      "hold": null,
      "rid": null,
      "caps": null,
      "subtype": null,
      "nlri": [
       "100.100.0.0/16"
      ],
      "withdrawn": [],
      "as_path": "65100",
      "next_hop": "100.100.255.1",
      "local_pref": "",
      "med": "0",
      "origin": "IGP",
      "eor": null,
      "t": 131.6211,
      "pair": "100.100.255.1 <-> 100.100.255.2"
     },
     {
      "no": 121,
      "epoch": 1795626840.2988,
      "src": "100.100.255.1",
      "dst": "100.100.255.2",
      "sport": "179",
      "dport": "21381",
      "type": "UPDATE",
      "type_n": 2,
      "blen": "44",
      "major": null,
      "minor": null,
      "reason": null,
      "myas": null,
      "hold": null,
      "rid": null,
      "caps": null,
      "subtype": null,
      "nlri": [
       "0.0.0.0/0"
      ],
      "withdrawn": [],
      "as_path": "65100",
      "next_hop": "100.100.255.1",
      "local_pref": "",
      "med": "",
      "origin": "IGP",
      "eor": null,
      "t": 131.6211,
      "pair": "100.100.255.1 <-> 100.100.255.2"
     },
     {
      "no": 121,
      "epoch": 1795626840.2988,
      "src": "100.100.255.1",
      "dst": "100.100.255.2",
      "sport": "179",
      "dport": "21381",
      "type": "ROUTE-REFRESH",
      "type_n": 5,
      "blen": "23",
      "major": null,
      "minor": null,
      "reason": null,
      "myas": null,
      "hold": null,
      "rid": null,
      "caps": null,
      "subtype": "EoRR (end)",
      "nlri": null,
      "withdrawn": null,
      "as_path": null,
      "next_hop": null,
      "local_pref": null,
      "med": null,
      "origin": null,
      "eor": null,
      "t": 131.6211,
      "pair": "100.100.255.1 <-> 100.100.255.2"
     },
     {
      "no": 121,
      "epoch": 1795626840.2988,
      "src": "100.100.255.1",
      "dst": "100.100.255.2",
      "sport": "179",
      "dport": "21381",
      "type": "UPDATE",
      "type_n": 2,
      "blen": "23",
      "major": null,
      "minor": null,
      "reason": null,
      "myas": null,
      "hold": null,
      "rid": null,
      "caps": null,
      "subtype": null,
      "nlri": [],
      "withdrawn": [],
      "as_path": "",
      "next_hop": "",
      "local_pref": "",
      "med": "",
      "origin": "",
      "eor": true,
      "t": 131.6211,
      "pair": "100.100.255.1 <-> 100.100.255.2"
     },
     {
      "no": 122,
      "epoch": 1795626840.3001,
      "src": "100.100.255.2",
      "dst": "100.100.255.1",
      "sport": "21381",
      "dport": "179",
      "type": "KEEPALIVE",
      "type_n": 4,
      "blen": "19",
      "major": null,
      "minor": null,
      "reason": null,
      "myas": null,
      "hold": null,
      "rid": null,
      "caps": null,
      "subtype": null,
      "nlri": null,
      "withdrawn": null,
      "as_path": null,
      "next_hop": null,
      "local_pref": null,
      "med": null,
      "origin": null,
      "eor": null,
      "t": 131.6223,
      "pair": "100.100.255.1 <-> 100.100.255.2"
     },
     {
      "no": 123,
      "epoch": 1795626840.3002,
      "src": "100.100.255.2",
      "dst": "100.100.255.1",
      "sport": "21381",
      "dport": "179",
      "type": "UPDATE",
      "type_n": 2,
      "blen": "60",
      "major": null,
      "minor": null,
      "reason": null,
      "myas": null,
      "hold": null,
      "rid": null,
      "caps": null,
      "subtype": null,
      "nlri": [
       "198.51.100.128/25"
      ],
      "withdrawn": [],
      "as_path": "65001 65001 65001 65001",
      "next_hop": "100.100.255.2",
      "local_pref": "",
      "med": "",
      "origin": "IGP",
      "eor": null,
      "t": 131.6224,
      "pair": "100.100.255.1 <-> 100.100.255.2"
     },
     {
      "no": 123,
      "epoch": 1795626840.3002,
      "src": "100.100.255.2",
      "dst": "100.100.255.1",
      "sport": "21381",
      "dport": "179",
      "type": "UPDATE",
      "type_n": 2,
      "blen": "59",
      "major": null,
      "minor": null,
      "reason": null,
      "myas": null,
      "hold": null,
      "rid": null,
      "caps": null,
      "subtype": null,
      "nlri": [
       "198.51.100.0/25",
       "198.51.100.0/24"
      ],
      "withdrawn": [],
      "as_path": "65001",
      "next_hop": "100.100.255.2",
      "local_pref": "",
      "med": "0",
      "origin": "IGP",
      "eor": null,
      "t": 131.6224,
      "pair": "100.100.255.1 <-> 100.100.255.2"
     },
     {
      "no": 123,
      "epoch": 1795626840.3002,
      "src": "100.100.255.2",
      "dst": "100.100.255.1",
      "sport": "21381",
      "dport": "179",
      "type": "UPDATE",
      "type_n": 2,
      "blen": "23",
      "major": null,
      "minor": null,
      "reason": null,
      "myas": null,
      "hold": null,
      "rid": null,
      "caps": null,
      "subtype": null,
      "nlri": [],
      "withdrawn": [],
      "as_path": "",
      "next_hop": "",
      "local_pref": "",
      "med": "",
      "origin": "",
      "eor": true,
      "t": 131.6224,
      "pair": "100.100.255.1 <-> 100.100.255.2"
     },
     {
      "no": 124,
      "epoch": 1795626840.302,
      "src": "100.100.255.1",
      "dst": "100.100.255.2",
      "sport": "179",
      "dport": "21381",
      "type": "KEEPALIVE",
      "type_n": 4,
      "blen": "19",
      "major": null,
      "minor": null,
      "reason": null,
      "myas": null,
      "hold": null,
      "rid": null,
      "caps": null,
      "subtype": null,
      "nlri": null,
      "withdrawn": null,
      "as_path": null,
      "next_hop": null,
      "local_pref": null,
      "med": null,
      "origin": null,
      "eor": null,
      "t": 131.6242,
      "pair": "100.100.255.1 <-> 100.100.255.2"
     },
     {
      "no": 125,
      "epoch": 1795626840.3022,
      "src": "100.100.255.1",
      "dst": "100.100.255.2",
      "sport": "179",
      "dport": "21381",
      "type": "UPDATE",
      "type_n": 2,
      "blen": "56",
      "major": null,
      "minor": null,
      "reason": null,
      "myas": null,
      "hold": null,
      "rid": null,
      "caps": null,
      "subtype": null,
      "nlri": [
       "198.51.100.0/25",
       "198.51.100.0/24"
      ],
      "withdrawn": [],
      "as_path": "65100 65001",
      "next_hop": "100.100.255.2",
      "local_pref": "",
      "med": "",
      "origin": "IGP",
      "eor": null,
      "t": 131.6244,
      "pair": "100.100.255.1 <-> 100.100.255.2"
     },
     {
      "no": 4,
      "epoch": 1795626716.5943,
      "src": "100.200.255.1",
      "dst": "100.200.255.2",
      "sport": "179",
      "dport": "20076",
      "type": "KEEPALIVE",
      "type_n": 4,
      "blen": "19",
      "major": null,
      "minor": null,
      "reason": null,
      "myas": null,
      "hold": null,
      "rid": null,
      "caps": null,
      "subtype": null,
      "nlri": null,
      "withdrawn": null,
      "as_path": null,
      "next_hop": null,
      "local_pref": null,
      "med": null,
      "origin": null,
      "eor": null,
      "t": 7.9165,
      "pair": "100.200.255.1 <-> 100.200.255.2"
     },
     {
      "no": 10,
      "epoch": 1795626727.2714,
      "src": "100.200.255.2",
      "dst": "100.200.255.1",
      "sport": "20076",
      "dport": "179",
      "type": "KEEPALIVE",
      "type_n": 4,
      "blen": "19",
      "major": null,
      "minor": null,
      "reason": null,
      "myas": null,
      "hold": null,
      "rid": null,
      "caps": null,
      "subtype": null,
      "nlri": null,
      "withdrawn": null,
      "as_path": null,
      "next_hop": null,
      "local_pref": null,
      "med": null,
      "origin": null,
      "eor": null,
      "t": 18.5936,
      "pair": "100.200.255.1 <-> 100.200.255.2"
     },
     {
      "no": 14,
      "epoch": 1795626734.6439,
      "src": "100.200.255.1",
      "dst": "100.200.255.2",
      "sport": "179",
      "dport": "20076",
      "type": "UPDATE",
      "type_n": 2,
      "blen": "56",
      "major": null,
      "minor": null,
      "reason": null,
      "myas": null,
      "hold": null,
      "rid": null,
      "caps": null,
      "subtype": null,
      "nlri": [
       "198.51.100.0/25"
      ],
      "withdrawn": [],
      "as_path": "65200 65100 65001",
      "next_hop": "100.200.255.1",
      "local_pref": "",
      "med": "",
      "origin": "IGP",
      "eor": null,
      "t": 25.9661,
      "pair": "100.200.255.1 <-> 100.200.255.2"
     },
     {
      "no": 21,
      "epoch": 1795626764.7419,
      "src": "100.200.255.1",
      "dst": "100.200.255.2",
      "sport": "179",
      "dport": "20076",
      "type": "UPDATE",
      "type_n": 2,
      "blen": "28",
      "major": null,
      "minor": null,
      "reason": null,
      "myas": null,
      "hold": null,
      "rid": null,
      "caps": null,
      "subtype": null,
      "nlri": [],
      "withdrawn": [
       "198.51.100.0/25"
      ],
      "as_path": "",
      "next_hop": "",
      "local_pref": "",
      "med": "",
      "origin": "",
      "eor": null,
      "t": 56.0641,
      "pair": "100.200.255.1 <-> 100.200.255.2"
     },
     {
      "no": 30,
      "epoch": 1795626782.5782,
      "src": "100.200.255.2",
      "dst": "100.200.255.1",
      "sport": "20076",
      "dport": "179",
      "type": "KEEPALIVE",
      "type_n": 4,
      "blen": "19",
      "major": null,
      "minor": null,
      "reason": null,
      "myas": null,
      "hold": null,
      "rid": null,
      "caps": null,
      "subtype": null,
      "nlri": null,
      "withdrawn": null,
      "as_path": null,
      "next_hop": null,
      "local_pref": null,
      "med": null,
      "origin": null,
      "eor": null,
      "t": 73.9004,
      "pair": "100.200.255.1 <-> 100.200.255.2"
     },
     {
      "no": 53,
      "epoch": 1795626816.9567,
      "src": "100.200.255.1",
      "dst": "100.200.255.2",
      "sport": "179",
      "dport": "20076",
      "type": "KEEPALIVE",
      "type_n": 4,
      "blen": "19",
      "major": null,
      "minor": null,
      "reason": null,
      "myas": null,
      "hold": null,
      "rid": null,
      "caps": null,
      "subtype": null,
      "nlri": null,
      "withdrawn": null,
      "as_path": null,
      "next_hop": null,
      "local_pref": null,
      "med": null,
      "origin": null,
      "eor": null,
      "t": 108.2789,
      "pair": "100.200.255.1 <-> 100.200.255.2"
     },
     {
      "no": 65,
      "epoch": 1795626834.8149,
      "src": "100.200.255.2",
      "dst": "100.200.255.1",
      "sport": "20076",
      "dport": "179",
      "type": "KEEPALIVE",
      "type_n": 4,
      "blen": "19",
      "major": null,
      "minor": null,
      "reason": null,
      "myas": null,
      "hold": null,
      "rid": null,
      "caps": null,
      "subtype": null,
      "nlri": null,
      "withdrawn": null,
      "as_path": null,
      "next_hop": null,
      "local_pref": null,
      "med": null,
      "origin": null,
      "eor": null,
      "t": 126.1371,
      "pair": "100.200.255.1 <-> 100.200.255.2"
     },
     {
      "no": 67,
      "epoch": 1795626840.304,
      "src": "100.200.255.1",
      "dst": "100.200.255.2",
      "sport": "179",
      "dport": "20076",
      "type": "UPDATE",
      "type_n": 2,
      "blen": "56",
      "major": null,
      "minor": null,
      "reason": null,
      "myas": null,
      "hold": null,
      "rid": null,
      "caps": null,
      "subtype": null,
      "nlri": [
       "198.51.100.0/25"
      ],
      "withdrawn": [],
      "as_path": "65200 65100 65001",
      "next_hop": "100.200.255.1",
      "local_pref": "",
      "med": "",
      "origin": "IGP",
      "eor": null,
      "t": 131.6262,
      "pair": "100.200.255.1 <-> 100.200.255.2"
     }
    ]
   },
   "tables": [
    {
     "title": "BGP sessions",
     "columns": [
      "Peers",
      "Up when capture started",
      "Messages",
      "Keepalive rhythm",
      "Ended",
      "Reconnect attempts"
     ],
     "rows": [
      [
       "ISPA-R1 (100.100.255.1) <-> HQ1-CORE-R1 (100.100.255.2)",
       "opened in capture",
       "KEEPALIVE 6, NOTIFICATION 1, OPEN 2, ROUTE-REFRESH 2, UPDATE 11",
       "-",
       "closed by HQ1-CORE-R1 (100.100.255.2) at 11:12:14.637: Cease / Administrative shutdown; re-established at 11:14:00.291 (OPEN), down 105.7 s",
       "9 refused, 1 accepted"
      ],
      [
       "ISPB-R1 (100.200.255.1) <-> HQ1-CORE-R2 (100.200.255.2)",
       "yes, no OPEN seen",
       "KEEPALIVE 5, UPDATE 3",
       "ISPB-R1 every 26.7 s (18-52 s); HQ1-CORE-R2 every 53.8 s (52-55 s)",
       "still up at the end",
       "-"
      ]
     ]
    },
    {
     "title": "UPDATE messages (announce and withdraw)",
     "columns": [
      "Clock",
      "From -> to",
      "Announces",
      "Withdraws",
      "AS_PATH",
      "NEXT_HOP",
      "Other attributes",
      "Frame"
     ],
     "rows": [
      [
       "11:14:00.298",
       "ISPA-R1 (100.100.255.1) -> HQ1-CORE-R1 (100.100.255.2)",
       "203.0.113.0/24",
       "-",
       "65100 65002",
       "100.100.255.1",
       "origin IGP",
       121
      ],
      [
       "11:14:00.298",
       "ISPA-R1 (100.100.255.1) -> HQ1-CORE-R1 (100.100.255.2)",
       "198.51.100.0/25",
       "-",
       "65100 65200 65001 65001 65001 65001",
       "100.100.255.1",
       "origin IGP",
       121
      ],
      [
       "11:14:00.298",
       "ISPA-R1 (100.100.255.1) -> HQ1-CORE-R1 (100.100.255.2)",
       "198.51.100.128/25, 198.51.100.0/24",
       "-",
       "65100 65200 65001",
       "100.100.255.1",
       "origin IGP",
       121
      ],
      [
       "11:14:00.298",
       "ISPA-R1 (100.100.255.1) -> HQ1-CORE-R1 (100.100.255.2)",
       "100.200.0.0/16",
       "-",
       "65100 65200",
       "100.100.255.1",
       "origin IGP",
       121
      ],
      [
       "11:14:00.298",
       "ISPA-R1 (100.100.255.1) -> HQ1-CORE-R1 (100.100.255.2)",
       "100.100.0.0/16",
       "-",
       "65100",
       "100.100.255.1",
       "origin IGP, MED 0",
       121
      ],
      [
       "11:14:00.298",
       "ISPA-R1 (100.100.255.1) -> HQ1-CORE-R1 (100.100.255.2)",
       "0.0.0.0/0",
       "-",
       "65100",
       "100.100.255.1",
       "origin IGP",
       121
      ],
      [
       "11:14:00.298",
       "ISPA-R1 (100.100.255.1) -> HQ1-CORE-R1 (100.100.255.2)",
       "-",
       "-",
       "-",
       "-",
       "-",
       121
      ],
      [
       "11:14:00.300",
       "HQ1-CORE-R1 (100.100.255.2) -> ISPA-R1 (100.100.255.1)",
       "198.51.100.128/25",
       "-",
       "65001 65001 65001 65001",
       "100.100.255.2",
       "origin IGP",
       123
      ],
      [
       "11:14:00.300",
       "HQ1-CORE-R1 (100.100.255.2) -> ISPA-R1 (100.100.255.1)",
       "198.51.100.0/25, 198.51.100.0/24",
       "-",
       "65001",
       "100.100.255.2",
       "origin IGP, MED 0",
       123
      ],
      [
       "11:14:00.300",
       "HQ1-CORE-R1 (100.100.255.2) -> ISPA-R1 (100.100.255.1)",
       "-",
       "-",
       "-",
       "-",
       "-",
       123
      ],
      [
       "11:14:00.302",
       "ISPA-R1 (100.100.255.1) -> HQ1-CORE-R1 (100.100.255.2)",
       "198.51.100.0/25, 198.51.100.0/24",
       "-",
       "65100 65001",
       "100.100.255.2",
       "origin IGP",
       125
      ],
      [
       "11:12:14.643",
       "ISPB-R1 (100.200.255.1) -> HQ1-CORE-R2 (100.200.255.2)",
       "198.51.100.0/25",
       "-",
       "65200 65100 65001",
       "100.200.255.1",
       "origin IGP",
       14
      ],
      [
       "11:12:44.741",
       "ISPB-R1 (100.200.255.1) -> HQ1-CORE-R2 (100.200.255.2)",
       "-",
       "198.51.100.0/25",
       "-",
       "-",
       "-",
       21
      ],
      [
       "11:14:00.304",
       "ISPB-R1 (100.200.255.1) -> HQ1-CORE-R2 (100.200.255.2)",
       "198.51.100.0/25",
       "-",
       "65200 65100 65001",
       "100.200.255.1",
       "origin IGP",
       67
      ]
     ]
    },
    {
     "title": "NOTIFICATION messages",
     "columns": [
      "Clock",
      "From -> to",
      "Reason",
      "Frame"
     ],
     "rows": [
      [
       "11:12:14.637",
       "HQ1-CORE-R1 (100.100.255.2) -> ISPA-R1 (100.100.255.1)",
       "Cease / Administrative shutdown",
       23
      ]
     ]
    },
    {
     "title": "Every BGP message on the wire",
     "columns": [
      "Clock",
      "At (s)",
      "From -> to",
      "Message",
      "BGP bytes",
      "Frame"
     ],
     "rows": [
      [
       "11:11:56.033",
       "7.36",
       "ISPA-R1 (100.100.255.1) -> HQ1-CORE-R1 (100.100.255.2)",
       "KEEPALIVE",
       "19",
       9
      ],
      [
       "11:11:56.594",
       "7.92",
       "ISPB-R1 (100.200.255.1) -> HQ1-CORE-R2 (100.200.255.2)",
       "KEEPALIVE",
       "19",
       4
      ],
      [
       "11:11:59.008",
       "10.33",
       "HQ1-CORE-R1 (100.100.255.2) -> ISPA-R1 (100.100.255.1)",
       "KEEPALIVE",
       "19",
       12
      ],
      [
       "11:12:07.271",
       "18.59",
       "HQ1-CORE-R2 (100.200.255.2) -> ISPB-R1 (100.200.255.1)",
       "KEEPALIVE",
       "19",
       10
      ],
      [
       "11:12:14.637",
       "25.96",
       "HQ1-CORE-R1 (100.100.255.2) -> ISPA-R1 (100.100.255.1)",
       "NOTIFICATION: Cease / Administrative shutdown",
       "21",
       23
      ],
      [
       "11:12:14.643",
       "25.97",
       "ISPB-R1 (100.200.255.1) -> HQ1-CORE-R2 (100.200.255.2)",
       "UPDATE: +1 / -0 prefix(es)",
       "56",
       14
      ],
      [
       "11:12:44.741",
       "56.06",
       "ISPB-R1 (100.200.255.1) -> HQ1-CORE-R2 (100.200.255.2)",
       "UPDATE: +0 / -1 prefix(es)",
       "28",
       21
      ],
      [
       "11:13:02.578",
       "73.90",
       "HQ1-CORE-R2 (100.200.255.2) -> ISPB-R1 (100.200.255.1)",
       "KEEPALIVE",
       "19",
       30
      ],
      [
       "11:13:36.956",
       "108.28",
       "ISPB-R1 (100.200.255.1) -> HQ1-CORE-R2 (100.200.255.2)",
       "KEEPALIVE",
       "19",
       53
      ],
      [
       "11:13:54.814",
       "126.14",
       "HQ1-CORE-R2 (100.200.255.2) -> ISPB-R1 (100.200.255.1)",
       "KEEPALIVE",
       "19",
       65
      ],
      [
       "11:14:00.291",
       "131.61",
       "HQ1-CORE-R1 (100.100.255.2) -> ISPA-R1 (100.100.255.1)",
       "OPEN",
       "57",
       114
      ],
      [
       "11:14:00.292",
       "131.61",
       "ISPA-R1 (100.100.255.1) -> HQ1-CORE-R1 (100.100.255.2)",
       "OPEN",
       "57",
       116
      ],
      [
       "11:14:00.292",
       "131.62",
       "ISPA-R1 (100.100.255.1) -> HQ1-CORE-R1 (100.100.255.2)",
       "KEEPALIVE",
       "19",
       117
      ],
      [
       "11:14:00.294",
       "131.62",
       "HQ1-CORE-R1 (100.100.255.2) -> ISPA-R1 (100.100.255.1)",
       "KEEPALIVE",
       "19",
       119
      ],
      [
       "11:14:00.295",
       "131.62",
       "ISPA-R1 (100.100.255.1) -> HQ1-CORE-R1 (100.100.255.2)",
       "ROUTE-REFRESH BoRR (begin)",
       "23",
       120
      ],
      [
       "11:14:00.298",
       "131.62",
       "ISPA-R1 (100.100.255.1) -> HQ1-CORE-R1 (100.100.255.2)",
       "UPDATE: +1 / -0 prefix(es)",
       "51",
       121
      ],
      [
       "11:14:00.298",
       "131.62",
       "ISPA-R1 (100.100.255.1) -> HQ1-CORE-R1 (100.100.255.2)",
       "UPDATE (End-of-RIB)",
       "23",
       121
      ],
      [
       "11:14:00.298",
       "131.62",
       "ISPA-R1 (100.100.255.1) -> HQ1-CORE-R1 (100.100.255.2)",
       "ROUTE-REFRESH EoRR (end)",
       "23",
       121
      ],
      [
       "11:14:00.298",
       "131.62",
       "ISPA-R1 (100.100.255.1) -> HQ1-CORE-R1 (100.100.255.2)",
       "UPDATE: +1 / -0 prefix(es)",
       "44",
       121
      ],
      [
       "11:14:00.298",
       "131.62",
       "ISPA-R1 (100.100.255.1) -> HQ1-CORE-R1 (100.100.255.2)",
       "UPDATE: +1 / -0 prefix(es)",
       "53",
       121
      ],
      [
       "11:14:00.298",
       "131.62",
       "ISPA-R1 (100.100.255.1) -> HQ1-CORE-R1 (100.100.255.2)",
       "UPDATE: +1 / -0 prefix(es)",
       "50",
       121
      ],
      [
       "11:14:00.298",
       "131.62",
       "ISPA-R1 (100.100.255.1) -> HQ1-CORE-R1 (100.100.255.2)",
       "UPDATE: +2 / -0 prefix(es)",
       "60",
       121
      ],
      [
       "11:14:00.298",
       "131.62",
       "ISPA-R1 (100.100.255.1) -> HQ1-CORE-R1 (100.100.255.2)",
       "UPDATE: +1 / -0 prefix(es)",
       "68",
       121
      ],
      [
       "11:14:00.300",
       "131.62",
       "HQ1-CORE-R1 (100.100.255.2) -> ISPA-R1 (100.100.255.1)",
       "KEEPALIVE",
       "19",
       122
      ],
      [
       "11:14:00.300",
       "131.62",
       "HQ1-CORE-R1 (100.100.255.2) -> ISPA-R1 (100.100.255.1)",
       "UPDATE: +1 / -0 prefix(es)",
       "60",
       123
      ],
      [
       "11:14:00.300",
       "131.62",
       "HQ1-CORE-R1 (100.100.255.2) -> ISPA-R1 (100.100.255.1)",
       "UPDATE (End-of-RIB)",
       "23",
       123
      ],
      [
       "11:14:00.300",
       "131.62",
       "HQ1-CORE-R1 (100.100.255.2) -> ISPA-R1 (100.100.255.1)",
       "UPDATE: +2 / -0 prefix(es)",
       "59",
       123
      ],
      [
       "11:14:00.301",
       "131.62",
       "ISPA-R1 (100.100.255.1) -> HQ1-CORE-R1 (100.100.255.2)",
       "KEEPALIVE",
       "19",
       124
      ],
      [
       "11:14:00.302",
       "131.62",
       "ISPA-R1 (100.100.255.1) -> HQ1-CORE-R1 (100.100.255.2)",
       "UPDATE: +2 / -0 prefix(es)",
       "56",
       125
      ],
      [
       "11:14:00.304",
       "131.63",
       "ISPB-R1 (100.200.255.1) -> HQ1-CORE-R2 (100.200.255.2)",
       "UPDATE: +1 / -0 prefix(es)",
       "56",
       67
      ]
     ]
    }
   ]
  },
  "probes": {
   "summary": "100.100.255.2 -> 100.200.1.1 every 5.0 s: 15 ok, 17 failed.",
   "data": {
    "series": [
     {
      "src": "100.100.255.2",
      "dst": "100.200.1.1",
      "interval": 5.0,
      "transitions": [
       {
        "t": 10.5921,
        "clock": "11:11:59.269",
        "to": "failing",
        "how": "ICMP 3/13 communication administratively prohibited (ACL)",
        "last_ok_clock": "11:11:54.270",
        "no": 14
       },
       {
        "t": 95.5921,
        "clock": "11:13:24.269",
        "to": "ok",
        "how": "reply",
        "last_ok_clock": "",
        "no": 81
       }
      ],
      "ok": 15,
      "fail": 17,
      "rtt_ms": 2.4881,
      "reaction": {
       "delay_s": 15.3674,
       "what": "BGP NOTIFICATION 100.100.255.2 -> 100.100.255.1",
       "clock": "11:12:14.637"
      }
     }
    ]
   },
   "tables": [
    {
     "title": "Probe series",
     "columns": [
      "Source -> target",
      "Interval",
      "Probes",
      "Answered",
      "Failed",
      "Median RTT",
      "Changes"
     ],
     "rows": [
      [
       "100.100.255.2 -> 100.200.1.1",
       "5.0 s",
       32,
       15,
       17,
       "2.5 ms",
       "11:11:59.269 failing (ICMP 3/13 communication administratively prohibited (ACL)); 11:13:24.269 ok"
      ]
     ]
    }
   ]
  },
  "link": {
   "summary": "0 link-level event(s). ",
   "data": {
    "neighbors": [
     {
      "protocol": "LLDP",
      "frames": 17,
      "names": [
       "HQ1-CORE-R1.almnjoy.lab",
       "ISPA-R1.almnjoy.lab",
       "ISPB-R1.almnjoy.lab"
      ]
     },
     {
      "protocol": "CDP",
      "frames": 13,
      "names": [
       "HQ1-CORE-R1.almnjoy.lab",
       "HQ1-CORE-R2.almnjoy.lab",
       "ISPA-R1.almnjoy.lab",
       "ISPB-R1.almnjoy.lab"
      ]
     }
    ],
    "events": []
   },
   "tables": [
    {
     "title": "Neighbors announced on this link",
     "columns": [
      "Protocol",
      "Frames",
      "Device"
     ],
     "rows": [
      [
       "LLDP",
       17,
       "HQ1-CORE-R1.almnjoy.lab, ISPA-R1.almnjoy.lab, ISPB-R1.almnjoy.lab"
      ],
      [
       "CDP",
       13,
       "HQ1-CORE-R1.almnjoy.lab, HQ1-CORE-R2.almnjoy.lab, ISPA-R1.almnjoy.lab, ISPB-R1.almnjoy.lab"
      ]
     ]
    }
   ]
  },
  "icmp": {
   "summary": "31 pings / 15 replies, 17 unreachable, 9 TTL exceeded.",
   "data": {
    "echo_req": 32,
    "echo_rep": 15,
    "unreachable": 17,
    "ttl_exceeded": 9
   },
   "tables": [
    {
     "title": "Destination unreachable",
     "columns": [
      "Reason",
      "Count"
     ],
     "rows": [
      [
       "administratively prohibited",
       17
      ]
     ]
    }
   ]
  },
  "flows": {
   "summary": "17 conversation(s), mostly other IP: ICMP on 100.200.1.1, 189 bps, 29% of bytes.",
   "data": {
    "conversations": 17,
    "services": [
     {
      "server": "100.200.1.1",
      "service": "ICMP",
      "pattern": "Other IP",
      "flows": 1,
      "clients": 1,
      "bytes": 3666.0,
      "share_pct": 29.0,
      "rate_bps": 189.2087
     },
     {
      "server": "100.100.255.1",
      "service": "BGP 179",
      "pattern": "Request / response",
      "flows": 2,
      "clients": 1,
      "bytes": 2336.0,
      "share_pct": 18.5,
      "rate_bps": 150.2363
     },
     {
      "server": "100.200.255.10",
      "service": "ESP",
      "pattern": "Other IP",
      "flows": 1,
      "clients": 1,
      "bytes": 1944.0,
      "share_pct": 15.4,
      "rate_bps": 124.3123
     },
     {
      "server": "100.100.255.2",
      "service": "ICMP",
      "pattern": "Keepalive / heartbeat",
      "flows": 1,
      "clients": 1,
      "bytes": 1190.0,
      "share_pct": 9.4,
      "rate_bps": 118.9988
     },
     {
      "server": "100.200.255.1",
      "service": "BGP 179",
      "pattern": "Request / response",
      "flows": 1,
      "clients": 1,
      "bytes": 1147.0,
      "share_pct": 9.1,
      "rate_bps": 74.1011
     },
     {
      "server": "100.100.255.2",
      "service": "BGP 179",
      "pattern": "Polling every ~12 s",
      "flows": 9,
      "clients": 1,
      "bytes": 1134.0,
      "share_pct": 9.0,
      "rate_bps": 98.418
     },
     {
      "server": "198.51.100.140",
      "service": "ICMP",
      "pattern": "Other IP",
      "flows": 1,
      "clients": 1,
      "bytes": 630.0,
      "share_pct": 5.0,
      "rate_bps": 157.2223
     },
     {
      "server": "34.107.243.93",
      "service": "HTTPS 443",
      "pattern": "Other IP",
      "flows": 1,
      "clients": 1,
      "bytes": 594.0,
      "share_pct": 4.7,
      "rate_bps": 148.2284
     }
    ],
    "patterns": {
     "Other IP": 54.1,
     "Request / response": 27.6,
     "Keepalive / heartbeat": 9.4,
     "Polling every ~12 s": 9.0
    },
    "rtp": [],
    "headline": "17 conversation(s), mostly other IP: ICMP on 100.200.1.1, 189 bps, 29% of bytes",
    "points": [
     "Traffic by pattern: other IP 54%, request / response 28%, keepalive / heartbeat 9%.",
     "100.200.1.1 ICMP: other IP, 1 conversation(s), 3.6 KB (29%), 189 bps",
     "100.100.255.1 BGP 179: request / response, 2 conversation(s), 2.3 KB (18%), 150 bps",
     "100.200.255.10 ESP: other IP, 1 conversation(s), 1.9 KB (15%), 124 bps"
    ]
   },
   "tables": [
    {
     "title": "What the traffic is (grouped by server and port)",
     "columns": [
      "Server",
      "Service",
      "Looks like",
      "Conversations",
      "Clients",
      "Bytes",
      "Share",
      "Avg rate",
      "Client -> server / back"
     ],
     "rows": [
      [
       "100.200.1.1",
       "ICMP",
       "Other IP",
       1,
       1,
       "3.6 KB",
       "29.0%",
       "189 bps",
       "2.4 KB / 1.1 KB"
      ],
      [
       "100.100.255.1",
       "BGP 179",
       "Request / response",
       2,
       1,
       "2.3 KB",
       "18.5%",
       "150 bps",
       "1.1 KB / 1.2 KB"
      ],
      [
       "100.200.255.10",
       "ESP",
       "Other IP",
       1,
       1,
       "1.9 KB",
       "15.4%",
       "124 bps",
       "972 B / 972 B"
      ],
      [
       "100.100.255.2",
       "ICMP",
       "Keepalive / heartbeat",
       1,
       1,
       "1.2 KB",
       "9.4%",
       "119 bps",
       "1.2 KB / 0 B"
      ],
      [
       "100.200.255.1",
       "BGP 179",
       "Request / response",
       1,
       1,
       "1.1 KB",
       "9.1%",
       "74 bps",
       "519 B / 628 B"
      ],
      [
       "100.100.255.2",
       "BGP 179",
       "Polling every ~12 s",
       9,
       1,
       "1.1 KB",
       "9.0%",
       "98 bps",
       "594 B / 540 B"
      ],
      [
       "198.51.100.140",
       "ICMP",
       "Other IP",
       1,
       1,
       "630 B",
       "5.0%",
       "157 bps",
       "0 B / 630 B"
      ],
      [
       "34.107.243.93",
       "HTTPS 443",
       "Other IP",
       1,
       1,
       "594 B",
       "4.7%",
       "148 bps",
       "0 B / 594 B"
      ]
     ]
    },
    {
     "title": "Largest individual conversations",
     "columns": [
      "Client",
      "Server",
      "Service",
      "Looks like",
      "Packets",
      "Bytes",
      "Lasted",
      "Rate",
      "Filter"
     ],
     "rows": [
      [
       "100.100.255.2:",
       "100.200.1.1",
       "ICMP",
       "Other IP",
       47,
       "3.6 KB",
       "155.0 s",
       "189 bps",
       "ip.addr==100.100.255.2 && ip.addr==100.200.1.1"
      ],
      [
       "100.200.255.2:",
       "100.200.255.10",
       "ESP",
       "Other IP",
       12,
       "1.9 KB",
       "125.1 s",
       "124 bps",
       "ip.addr==100.200.255.2 && ip.addr==100.200.255.10"
      ],
      [
       "100.100.255.2:21381",
       "100.100.255.1",
       "BGP 179",
       "Request / response",
       17,
       "1.7 KB",
       "0.1 s",
       "0 bps",
       "ip.addr==100.100.255.2 && ip.addr==100.100.255.1"
      ],
      [
       "100.100.255.1:",
       "100.100.255.2",
       "ICMP",
       "Keepalive / heartbeat",
       17,
       "1.2 KB",
       "80.0 s",
       "119 bps",
       "ip.addr==100.100.255.1 && ip.addr==100.100.255.2"
      ],
      [
       "100.200.255.2:20076",
       "100.200.255.1",
       "BGP 179",
       "Request / response",
       16,
       "1.1 KB",
       "123.8 s",
       "74 bps",
       "ip.addr==100.200.255.2 && ip.addr==100.200.255.1"
      ],
      [
       "34.107.243.93:1026",
       "198.51.100.140",
       "ICMP",
       "Other IP",
       9,
       "630 B",
       "32.1 s",
       "157 bps",
       "ip.addr==34.107.243.93 && ip.addr==198.51.100.140"
      ],
      [
       "198.51.100.10:1026",
       "34.107.243.93",
       "HTTPS 443",
       "Other IP",
       9,
       "594 B",
       "32.1 s",
       "148 bps",
       "ip.addr==198.51.100.10 && ip.addr==34.107.243.93"
      ],
      [
       "100.100.255.2:20305",
       "100.100.255.1",
       "BGP 179",
       "Request / response",
       9,
       "581 B",
       "18.6 s",
       "250 bps",
       "ip.addr==100.100.255.2 && ip.addr==100.100.255.1"
      ],
      [
       "100.100.255.1:64631",
       "100.100.255.2",
       "BGP 179",
       "Polling every ~12 s",
       2,
       "126 B",
       "0.0 s",
       "0 bps",
       "ip.addr==100.100.255.1 && ip.addr==100.100.255.2"
      ],
      [
       "100.100.255.1:50623",
       "100.100.255.2",
       "BGP 179",
       "Polling every ~12 s",
       2,
       "126 B",
       "0.0 s",
       "0 bps",
       "ip.addr==100.100.255.1 && ip.addr==100.100.255.2"
      ],
      [
       "100.100.255.1:15825",
       "100.100.255.2",
       "BGP 179",
       "Polling every ~12 s",
       2,
       "126 B",
       "0.0 s",
       "0 bps",
       "ip.addr==100.100.255.1 && ip.addr==100.100.255.2"
      ],
      [
       "100.100.255.1:56611",
       "100.100.255.2",
       "BGP 179",
       "Polling every ~12 s",
       2,
       "126 B",
       "0.0 s",
       "0 bps",
       "ip.addr==100.100.255.1 && ip.addr==100.100.255.2"
      ],
      [
       "100.100.255.1:41933",
       "100.100.255.2",
       "BGP 179",
       "Polling every ~12 s",
       2,
       "126 B",
       "0.0 s",
       "0 bps",
       "ip.addr==100.100.255.1 && ip.addr==100.100.255.2"
      ],
      [
       "100.100.255.1:35458",
       "100.100.255.2",
       "BGP 179",
       "Polling every ~12 s",
       2,
       "126 B",
       "0.0 s",
       "0 bps",
       "ip.addr==100.100.255.1 && ip.addr==100.100.255.2"
      ],
      [
       "100.100.255.1:33036",
       "100.100.255.2",
       "BGP 179",
       "Polling every ~12 s",
       2,
       "126 B",
       "0.0 s",
       "0 bps",
       "ip.addr==100.100.255.1 && ip.addr==100.100.255.2"
      ]
     ]
    }
   ]
  },
  "tcp": {
   "summary": "13 TCP connections, 8 retransmissions, 9 resets. Handshake RTT median 1.4 ms.",
   "data": {
    "streams": 13,
    "retx": 8,
    "dupack": 0,
    "rst": 9,
    "retx_data": 0,
    "handshake": {
     "n": 1,
     "min": 0.0014,
     "p50": 0.0014,
     "p90": 0.0014,
     "p95": 0.0014,
     "max": 0.0014,
     "mean": 0.0014
    },
    "services": [
     {
      "service": "34.107.243.93:443",
      "streams": 1,
      "retx": 8,
      "data_segs": 0,
      "retx_rate": 0.0,
      "rst": 0,
      "worst_stall_s": 0.0
     },
     {
      "service": "100.100.255.2:179",
      "streams": 9,
      "retx": 0,
      "data_segs": 0,
      "retx_rate": 0.0,
      "rst": 9,
      "worst_stall_s": 0.0
     },
     {
      "service": "100.100.255.1:179",
      "streams": 2,
      "retx": 0,
      "data_segs": 13,
      "retx_rate": 0.0,
      "rst": 0,
      "worst_stall_s": 0.0
     },
     {
      "service": "100.200.255.1:179",
      "streams": 1,
      "retx": 0,
      "data_segs": 8,
      "retx_rate": 0.0,
      "rst": 0,
      "worst_stall_s": 0.0
     }
    ],
    "one_way": []
   },
   "tables": [
    {
     "title": "By service (server:port)",
     "columns": [
      "Service",
      "Conns",
      "Data segs",
      "Retransmits",
      "Retx rate",
      "Dup ACKs",
      "Resets",
      "Worst stall",
      "Handshake p50"
     ],
     "rows": [
      [
       "34.107.243.93:443",
       1,
       0,
       8,
       "0.0%",
       0,
       0,
       "-",
       "n/a"
      ],
      [
       "100.100.255.2:179",
       9,
       0,
       0,
       "0.0%",
       0,
       9,
       "-",
       "n/a"
      ],
      [
       "100.100.255.1:179",
       2,
       13,
       0,
       "0.0%",
       0,
       0,
       "-",
       "1.4 ms"
      ],
      [
       "100.200.255.1:179",
       1,
       8,
       0,
       "0.0%",
       0,
       0,
       "-",
       "n/a"
      ]
     ]
    },
    {
     "title": "Worst connections",
     "columns": [
      "Stream",
      "Client",
      "Server",
      "Frames",
      "Retx",
      "Dup ACK",
      "RST",
      "Longest stall",
      "Filter"
     ],
     "rows": [
      [
       12,
       "198.51.100.10:1026",
       "34.107.243.93:443",
       9,
       8,
       0,
       "0",
       "-",
       "tcp.stream eq 12"
      ],
      [
       0,
       "100.100.255.2:20305",
       "100.100.255.1:179",
       9,
       0,
       0,
       "0",
       "-",
       "tcp.stream eq 0"
      ],
      [
       1,
       "100.100.255.1:64631",
       "100.100.255.2:179",
       2,
       0,
       0,
       "1 by server",
       "-",
       "tcp.stream eq 1"
      ],
      [
       2,
       "100.100.255.1:56611",
       "100.100.255.2:179",
       2,
       0,
       0,
       "1 by server",
       "-",
       "tcp.stream eq 2"
      ],
      [
       3,
       "100.100.255.1:15825",
       "100.100.255.2:179",
       2,
       0,
       0,
       "1 by server",
       "-",
       "tcp.stream eq 3"
      ],
      [
       4,
       "100.100.255.1:50623",
       "100.100.255.2:179",
       2,
       0,
       0,
       "1 by server",
       "-",
       "tcp.stream eq 4"
      ],
      [
       5,
       "100.100.255.1:41933",
       "100.100.255.2:179",
       2,
       0,
       0,
       "1 by server",
       "-",
       "tcp.stream eq 5"
      ],
      [
       6,
       "100.100.255.1:35458",
       "100.100.255.2:179",
       2,
       0,
       0,
       "1 by server",
       "-",
       "tcp.stream eq 6"
      ],
      [
       7,
       "100.100.255.1:33036",
       "100.100.255.2:179",
       2,
       0,
       0,
       "1 by server",
       "-",
       "tcp.stream eq 7"
      ],
      [
       8,
       "100.100.255.1:30881",
       "100.100.255.2:179",
       2,
       0,
       0,
       "1 by server",
       "-",
       "tcp.stream eq 8"
      ],
      [
       9,
       "100.100.255.1:60942",
       "100.100.255.2:179",
       2,
       0,
       0,
       "1 by server",
       "-",
       "tcp.stream eq 9"
      ],
      [
       10,
       "100.100.255.2:21381",
       "100.100.255.1:179",
       17,
       0,
       0,
       "0",
       "-",
       "tcp.stream eq 10"
      ]
     ]
    }
   ]
  },
  "l2": {
   "summary": "",
   "data": {
    "names": {
     "aa:bb:cc:00:18:20": "HQ1-CORE-R1",
     "aa:bb:cc:00:12:20": "ISPA-R1",
     "aa:bb:cc:00:19:20": "HQ1-CORE-R2",
     "aa:bb:cc:00:14:20": "ISPB-R1"
    },
    "_ports": {
     "aa:bb:cc:00:18:20": "Et0/2",
     "aa:bb:cc:00:12:20": "Et0/2",
     "aa:bb:cc:00:19:20": "Et0/2",
     "aa:bb:cc:00:14:20": "Et0/2"
    },
    "events": []
   },
   "tables": [
    {
     "title": "Who is on each end (CDP / LLDP)",
     "columns": [
      "Link",
      "Proto",
      "Device",
      "Its port",
      "Source MAC"
     ],
     "rows": [
      [
       "HQ1-CORE-R1 Et0/2 <-> ISPA-R1 Et0/2",
       "CDP",
       "HQ1-CORE-R1",
       "Ethernet0/2",
       "aa:bb:cc:00:18:20"
      ],
      [
       "HQ1-CORE-R1 Et0/2 <-> ISPA-R1 Et0/2",
       "CDP",
       "ISPA-R1",
       "Ethernet0/2",
       "aa:bb:cc:00:12:20"
      ],
      [
       "HQ1-CORE-R1 Et0/2 <-> ISPA-R1 Et0/2",
       "LLDP",
       "HQ1-CORE-R1",
       "Et0/2",
       "aa:bb:cc:00:18:20"
      ],
      [
       "HQ1-CORE-R1 Et0/2 <-> ISPA-R1 Et0/2",
       "LLDP",
       "ISPA-R1",
       "Et0/2",
       "aa:bb:cc:00:12:20"
      ],
      [
       "HQ1-CORE-R2 Et0/2 <-> ISPB-R1 Et0/2",
       "CDP",
       "HQ1-CORE-R2",
       "Ethernet0/2",
       "aa:bb:cc:00:19:20"
      ],
      [
       "HQ1-CORE-R2 Et0/2 <-> ISPB-R1 Et0/2",
       "CDP",
       "ISPB-R1",
       "Ethernet0/2",
       "aa:bb:cc:00:14:20"
      ],
      [
       "HQ1-CORE-R2 Et0/2 <-> ISPB-R1 Et0/2",
       "LLDP",
       "ISPB-R1",
       "Et0/2",
       "aa:bb:cc:00:14:20"
      ]
     ]
    }
   ]
  },
  "mtu": {
   "summary": "Largest frame 426 B. SYN MSS 1460-1460.",
   "data": {
    "frag_needed": 0,
    "fragments": 0,
    "max_frame": 426,
    "mss_min": 1460.0,
    "mss_max": 1460.0
   },
   "tables": []
  }
 },
 "warnings": [
  "Merged 2 captures onto one clock. Frame numbers in this report are per file; the link label says which file."
 ],
 "compare": null,
 "verdict": {
  "status": "info",
  "headline": "Packet breakdown: 16 packets, 8 kinds of message (BGP, ICMP)",
  "points": [
   "ISPA-R1 (100.100.255.1) <-> HQ1-CORE-R1 (100.100.255.2): 6 KEEPALIVE, 1 NOTIFICATION, 2 OPEN, 2 ROUTE-REFRESH, 11 UPDATE; closed by HQ1-CORE-R1 (100.100.255.2) at 11:12:14.637 (Cease / Administrative shutdown); re-established at 11:14:00.291 after 105.7 s down",
   "ISPB-R1 (100.200.255.1) <-> HQ1-CORE-R2 (100.200.255.2): 5 KEEPALIVE, 3 UPDATE; up the whole capture",
   "Probe 100.100.255.2 -> 100.200.1.1 every 5.0 s: 15 answered, 17 failed; first failure 11:11:59.269 (ICMP 3/13 communication administratively prohibited (ACL)); 15.4 s later: BGP NOTIFICATION 100.100.255.2 -> 100.100.255.1",
   "7 UPDATEs ISPA-R1 -> HQ1-CORE-R1 at 11:14:00.298: 7 prefix(es) announced, End-of-RIB",
   "3 UPDATEs HQ1-CORE-R1 -> ISPA-R1 at 11:14:00.300: 3 prefix(es) announced, End-of-RIB",
   "UPDATE ISPA-R1 -> HQ1-CORE-R1: announce 198.51.100.0/25, 198.51.100.0/24",
   "UPDATE ISPB-R1 -> HQ1-CORE-R2: announce 198.51.100.0/25",
   "UPDATE ISPB-R1 -> HQ1-CORE-R2: withdraw 198.51.100.0/25"
  ],
  "cause": "",
  "counts": {
   "critical": 0,
   "warning": 4,
   "ok": 2,
   "artifact": 0
  }
 },
 "kpis": [
  {
   "label": "Frames"
  },
  {
   "label": "Duration"
  },
  {
   "label": "Links"
  },
  {
   "label": "BGP sessions"
  },
  {
   "label": "BGP messages"
  },
  {
   "label": "Notifications",
   "tone": "warn"
  },
  {
   "label": "Probes ok / failed",
   "tone": "warn"
  },
  {
   "label": "Failure to reaction"
  }
 ]
}
```
