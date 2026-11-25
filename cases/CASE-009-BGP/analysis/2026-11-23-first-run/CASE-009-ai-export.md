# Packet capture analysis: Packet breakdown: 13 packets, 9 kinds of message (BGP, ICMP)

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

> Break down the individual BGP messages (keepalives, updates, the notification) and the IP SLA pings. Show what we can see in each packet.


## Capture

- Source: 4 captures (pcap)
- Packets: 368, duration 331.039 s, 45.2 KB, started 2026-11-23 18:10:44 CST
- Link: HQ1-CORE-R1 Et0/2 <-> ISPA-R1 Et0/2 (257 frames, +5.0 s to +330.0 s)
- Link: HQ1-CORE-R2 Et0/2 <-> ISPB-R1 Et0/2 (104 frames, +8.6 s to +328.6 s)
- Two taps of one wire merged: HQ1-CORE-R1 Et0/2 <-> ISPA-R1 Et0/2 (common 190, only one side 0, skew -3e-06 s)
- Two taps of one wire merged: HQ1-CORE-R2 Et0/2 <-> ISPB-R1 Et0/2 (common 48, only one side 0, skew -4e-06 s)

## Verdict (engine)

**info**: Packet breakdown: 13 packets, 9 kinds of message (BGP, ICMP)

- ISPA-R1 (100.100.255.1) <-> HQ1-CORE-R1 (100.100.255.2): 5 KEEPALIVE, 1 NOTIFICATION; closed by HQ1-CORE-R1 (100.100.255.2) at 18:12:53.264 (Cease / Administrative shutdown)
- ISPB-R1 (100.200.255.1) <-> HQ1-CORE-R2 (100.200.255.2): 11 KEEPALIVE, 2 UPDATE; up the whole capture
- Probe 100.100.255.2 -> 100.200.1.1 every 5.0 s: 23 answered, 44 failed; first failure 18:12:39.150 (ICMP 3/13 communication administratively prohibited (ACL)); 14.1 s later: BGP NOTIFICATION 100.100.255.2 -> 100.100.255.1
- UPDATE 18:12:53.273 ISPB-R1 -> HQ1-CORE-R2: announce 198.51.100.0/25 (AS_PATH 65200 65100 65001)
- UPDATE 18:13:23.451 ISPB-R1 -> HQ1-CORE-R2: withdraw 198.51.100.0/25

Key numbers: Frames 368; Duration 331.0 s; Links 2; BGP sessions 2; BGP messages 19; Notifications 1; Probes ok / failed 23 / 44; Failure to reaction 14.1 s

## Findings

Most important first. Severity: critical > warning > info > ok > artifact.

1. **[warning] BGP session closed by HQ1-CORE-R1: Cease / Administrative shutdown** (bgp)
   ISPA-R1 (100.100.255.1) <-> HQ1-CORE-R1 (100.100.255.2): HQ1-CORE-R1 (100.100.255.2) sent a NOTIFICATION (Cease / Administrative shutdown) at 18:12:53.264 and closed TCP. Administrative shutdown means the sender's own config shut the neighbor: a person, or a script / EEM applet. 
   Filter: `bgp.type == 3 && ip.src == 100.100.255.2` · frames 89
2. **[warning] Probe to 100.200.1.1 started failing at 18:12:39.150** (probes)
   Last answered probe 18:12:34.150; from 18:12:39.150 on: ICMP 3/13 communication administratively prohibited (ACL) from 100.100.255.1. The reporting router is telling you an ACL dropped the probe: the path past it is blocked on purpose. An IP SLA operation counts this as a failure; a track object on it goes down after its delay.
   Filter: `icmp && ip.addr == 100.200.1.1 && icmp.type != 8` · frames 79
3. **[warning] 43 ping(s) refused with ICMP unreachable** (icmp)
   66 echo requests, 23 replies, 43 answered by an ICMP error instead of a reply. That is a router on the path saying no, not packet loss.
   Filter: `icmp.type==3`
4. **[info] 13 packets broken down field by field** (breakdown)
   Kinds: ICMP echo request, ICMP echo reply, BGP KEEPALIVE, ICMP unreachable, admin prohibited, BGP NOTIFICATION, TCP FIN (port 179), BGP UPDATE, TCP SYN (port 179), TCP RST (port 179).
   Filter: `bgp || icmp`
5. **[info] 20 reconnect attempt(s) refused** (bgp)
   ISPA-R1 (100.100.255.1) kept opening TCP 179 to HQ1-CORE-R1 (100.100.255.2) (18:13:00.571 to 18:16:06.971, every 6-14 s) and every SYN got a RST back. A shut-down or unconfigured neighbor refuses the connection; the other side keeps trying on its connect-retry timer.
   Filter: `ip.addr==100.100.255.1 && ip.addr==100.100.255.2 && tcp.port==179 && (tcp.flags.syn == 1 || tcp.flags.reset == 1)` · frames 101
6. **[info] UPDATE ISPB-R1 -> HQ1-CORE-R2: announce 198.51.100.0/25** (bgp)
   At 18:12:53.273, AS_PATH 65200 65100 65001, NEXT_HOP 100.200.255.1.
   Filter: `bgp.type == 2 && ip.src == 100.200.255.1` · frames 41
7. **[info] UPDATE ISPB-R1 -> HQ1-CORE-R2: withdraw 198.51.100.0/25** (bgp)
   At 18:13:23.451.
   Filter: `bgp.type == 2 && ip.src == 100.200.255.1` · frames 50
8. **[info] Periodic probe 100.100.255.2 -> 100.200.1.1 every 5.0 s** (probes)
   67 echo requests on a steady 5.0 s interval: this is IP SLA icmp-echo (one source, one target, fixed frequency). 23 answered (median 2.5 ms), 44 failed.
   Filter: `icmp && ip.addr == 100.100.255.2 && ip.addr == 100.200.1.1`
9. **[info] 14.1 s after the first failed probe: BGP NOTIFICATION 100.100.255.2 -> 100.100.255.1** (probes)
   First failed probe 18:12:39.150, then BGP NOTIFICATION 100.100.255.2 -> 100.100.255.1 at 18:12:53.264. When a probe drives a track object, the gap is the track's `delay down` plus the time an EEM applet (or the routing process) takes to act.
   Filter: `bgp.type == 3` · frames 89
10. **[info] 27 conversation(s) across 7 service(s)** (flows)
   27 conversation(s), mostly other IP: ICMP on 100.200.1.1, 170 bps, 36% of bytes. Traffic by pattern: other IP 56%, keepalive / heartbeat 16%, request / response 15%.
   Filter: `ip`
11. **[info] 44 ICMP destination-unreachable message(s)** (icmp)
   Reasons: administratively prohibited (44).
   Filter: `icmp.type==3` · frames 79, 83, 87, 95, 99, 104, 107, 113
12. **[info] 20 connection attempt(s) refused with RST** (tcp)
   The server answered the SYN with a RST: it is up and reachable, but nothing accepts on that port (BGP port 179: the neighbor is shut down or not configured on that side, so it refuses the peer's connect-retry).
   Filter: `tcp.flags.syn==1 && tcp.flags.ack==0 && tcp.port in {179}` · frames 101, 109, 114, 123, 128, 137, 146, 157
13. **[ok] ISPA-R1 heard from every 50.2 s** (bgp)
   2 KEEPALIVE(s) on ISPA-R1 (100.100.255.1) <-> HQ1-CORE-R1 (100.100.255.2); gaps between its BGP messages 50.2 to 50.2 s. Any BGP message (KEEPALIVE or UPDATE) restarts the keepalive timer. IOS sends one every third of the hold time (default 60 s of 180) and jitters it a little lower, so 45 to 60 s apart is normal.
   Filter: `bgp.type == 4 && ip.src == 100.100.255.1`
14. **[ok] HQ1-CORE-R1 heard from every 54.8 s** (bgp)
   3 KEEPALIVE(s) on ISPA-R1 (100.100.255.1) <-> HQ1-CORE-R1 (100.100.255.2); gaps between its BGP messages 54.3 to 55.3 s. Any BGP message (KEEPALIVE or UPDATE) restarts the keepalive timer. IOS sends one every third of the hold time (default 60 s of 180) and jitters it a little lower, so 45 to 60 s apart is normal.
   Filter: `bgp.type == 4 && ip.src == 100.100.255.2`
15. **[ok] ISPB-R1 heard from every 52.7 s** (bgp)
   5 KEEPALIVE(s) on ISPB-R1 (100.200.255.1) <-> HQ1-CORE-R2 (100.200.255.2); gaps between its BGP messages 30.2 to 58.0 s. Any BGP message (KEEPALIVE or UPDATE) restarts the keepalive timer. IOS sends one every third of the hold time (default 60 s of 180) and jitters it a little lower, so 45 to 60 s apart is normal.
   Filter: `bgp.type == 4 && ip.src == 100.200.255.1`
16. **[ok] HQ1-CORE-R2 heard from every 55.3 s** (bgp)
   6 KEEPALIVE(s) on ISPB-R1 (100.200.255.1) <-> HQ1-CORE-R2 (100.200.255.2); gaps between its BGP messages 52.2 to 58.4 s. Any BGP message (KEEPALIVE or UPDATE) restarts the keepalive timer. IOS sends one every third of the hold time (default 60 s of 180) and jitters it a little lower, so 45 to 60 s apart is normal.
   Filter: `bgp.type == 4 && ip.src == 100.200.255.2`

## Details by area

### Capture overview

368 frames over 331.0 s (45.2 KB), 14 addresses, 24 TCP connections.

**Captures merged onto one timeline**

| Link | File | Frames | From (s) | To (s) |
|---|---|---|---|---|
| HQ1-CORE-R1 Et0/2 <-> ISPA-R1 Et0/2 | P1-ISPA-link_HQ1-CORE-R1-Et0-2.pcap | 257 | 5.0 | 330.0 |
| HQ1-CORE-R2 Et0/2 <-> ISPB-R1 Et0/2 | P3-ISPB-link_HQ1-CORE-R2-Et0-2.pcap | 104 | 8.6 | 328.6 |

**Protocol mix**

| Protocol | Frames | Share |
|---|---|---|
| ICMP | 134 | 36.4% |
| LOOP | 69 | 18.8% |
| TCP | 63 | 17.1% |
| LLDP | 33 | 9.0% |
| CDP | 24 | 6.5% |
| ESP | 24 | 6.5% |
| BGP | 19 | 5.2% |
| TLSv1.2 | 2 | 0.5% |

**Top conversations**

| Hosts | Frames | Bytes |
|---|---|---|
| 100.100.255.1 <-> 100.100.255.2 | 99 | 6.4 KB |
| 100.100.255.2 <-> 100.200.1.1 | 90 | 6.9 KB |
| aa:bb:cc:00:19:20 <-> aa:bb:cc:00:19:20 | 33 | 1.9 KB |
| aa:bb:cc:00:18:20 <-> aa:bb:cc:00:18:20 | 33 | 1.9 KB |
| 100.200.255.1 <-> 100.200.255.2 | 26 | 1.7 KB |
| 100.200.255.10 <-> 100.200.255.2 | 24 | 3.8 KB |
| 01:80:c2:00:00:0e <-> aa:bb:cc:00:12:20 | 11 | 4.1 KB |
| 01:80:c2:00:00:0e <-> aa:bb:cc:00:18:20 | 11 | 4.2 KB |
| 01:80:c2:00:00:0e <-> aa:bb:cc:00:14:20 | 11 | 4.1 KB |
| 01:00:0c:cc:cc:cc <-> aa:bb:cc:00:14:20 | 6 | 2.4 KB |
| 01:00:0c:cc:cc:cc <-> aa:bb:cc:00:18:20 | 6 | 2.4 KB |
| 01:00:0c:cc:cc:cc <-> aa:bb:cc:00:19:20 | 6 | 2.4 KB |

### Packet breakdown

13 packets, one of every kind of BGP, ICMP message in the capture, decoded field by field. Click a field to light up its bytes. Rare messages (UPDATE, NOTIFICATION, OPEN) are all shown; routine ones (KEEPALIVE, ping) once per sender.

**Packets broken down below**

| # | Clock | Message | From -> to | Bytes | Frame |
|---|---|---|---|---|---|
| 1 | 18:10:44.150 | ICMP echo request | HQ1-CORE-R1 -> ISPA-R1 | 78 | 1 |
| 2 | 18:10:44.153 | ICMP echo reply | ISPA-R1 -> HQ1-CORE-R1 | 78 | 2 |
| 3 | 18:10:44.948 | BGP KEEPALIVE | HQ1-CORE-R2 -> ISPB-R1 | 73 | 1 |
| 4 | 18:10:55.594 | BGP KEEPALIVE | HQ1-CORE-R1 -> ISPA-R1 | 73 | 6 |
| 5 | 18:11:08.944 | BGP KEEPALIVE | ISPB-R1 -> HQ1-CORE-R2 | 73 | 7 |
| 6 | 18:11:33.451 | BGP KEEPALIVE | ISPA-R1 -> HQ1-CORE-R1 | 73 | 30 |
| 7 | 18:12:39.152 | ICMP unreachable, admin prohibited | ISPA-R1 -> HQ1-CORE-R1 | 70 | 79 |
| 8 | 18:12:53.264 | BGP NOTIFICATION | HQ1-CORE-R1 -> ISPA-R1 | 75 | 89 |
| 9 | 18:12:53.265 | TCP FIN (port 179) | HQ1-CORE-R1 -> ISPA-R1 | 60 | 90 |
| 10 | 18:12:53.273 | BGP UPDATE | ISPB-R1 -> HQ1-CORE-R2 | 110 | 41 |
| 11 | 18:13:00.571 | TCP SYN (port 179) | ISPA-R1 -> HQ1-CORE-R1 | 66 | 101 |
| 12 | 18:13:00.572 | TCP RST (port 179) | HQ1-CORE-R1 -> ISPA-R1 | 60 | 102 |
| 13 | 18:13:23.451 | BGP UPDATE | ISPB-R1 -> HQ1-CORE-R2 | 82 | 50 |

Packets decoded field by field:

#### #1 ICMP echo request: HQ1-CORE-R1 -> ISPA-R1

18:10:44.150 (+0.000 s), frame 1, 78 bytes, HQ1-CORE-R1 Et0/2 <-> ISPA-R1 Et0/2

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
  - Identification: 0x00c2 (194) _(offset 18, 2 B)_
  - 000. .... = Flags: 0x0 _(offset 20, 1 B)_
    - 0... .... = Reserved bit: Not set _(offset 20, 1 B)_
    - .0.. .... = Don't fragment: Not set _(offset 20, 1 B)_
    - ..0. .... = More fragments: Not set _(offset 20, 1 B)_
  - ...0 0000 0000 0000 = Fragment Offset: 0 _(offset 20, 2 B)_
  - Time to Live: 255 _(offset 22, 1 B)_
  - Protocol: ICMP (1) _(offset 23, 1 B)_
  - Header Checksum: 0xf1ca [validation disabled] _(offset 24, 2 B)_
  - Source Address: 100.100.255.2 _(offset 26, 4 B)_
  - Destination Address: 100.200.1.1 _(offset 30, 4 B)_
- **Internet Control Message Protocol**
  - Type: 8 (Echo (ping) request) _(offset 34, 1 B)_
  - Code: 0 _(offset 35, 1 B)_
  - Checksum: 0xa654 [correct] _(offset 36, 2 B)_
  - Identifier (BE): 169 (0x00a9) _(offset 38, 2 B)_
  - Identifier (LE): 43264 (0xa900) _(offset 38, 2 B)_
  - Sequence Number (BE): 1 (0x0001) _(offset 40, 2 B)_
  - Sequence Number (LE): 256 (0x0100) _(offset 40, 2 B)_
  - data
    - Data: 000000004c467d7cabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd45ad33ed _(offset 42, 36 B)_
    - Length: 36

#### #2 ICMP echo reply: ISPA-R1 -> HQ1-CORE-R1

18:10:44.153 (+0.003 s), frame 2, 78 bytes, HQ1-CORE-R1 Et0/2 <-> ISPA-R1 Et0/2

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
  - Identification: 0x00c2 (194) _(offset 18, 2 B)_
  - 000. .... = Flags: 0x0 _(offset 20, 1 B)_
    - 0... .... = Reserved bit: Not set _(offset 20, 1 B)_
    - .0.. .... = Don't fragment: Not set _(offset 20, 1 B)_
    - ..0. .... = More fragments: Not set _(offset 20, 1 B)_
  - ...0 0000 0000 0000 = Fragment Offset: 0 _(offset 20, 2 B)_
  - Time to Live: 254 _(offset 22, 1 B)_
  - Protocol: ICMP (1) _(offset 23, 1 B)_
  - Header Checksum: 0xf2ca [validation disabled] _(offset 24, 2 B)_
  - Source Address: 100.200.1.1 _(offset 26, 4 B)_
  - Destination Address: 100.100.255.2 _(offset 30, 4 B)_
- **Internet Control Message Protocol**
  - Type: 0 (Echo (ping) reply) _(offset 34, 1 B)_
  - Code: 0 _(offset 35, 1 B)_
  - Checksum: 0xae54 [correct] _(offset 36, 2 B)_
  - Identifier (BE): 169 (0x00a9) _(offset 38, 2 B)_
  - Identifier (LE): 43264 (0xa900) _(offset 38, 2 B)_
  - Sequence Number (BE): 1 (0x0001) _(offset 40, 2 B)_
  - Sequence Number (LE): 256 (0x0100) _(offset 40, 2 B)_
  - data
    - Data: 000000004c467d7cabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd45ad33ed _(offset 42, 36 B)_
    - Length: 36

#### #3 BGP KEEPALIVE: HQ1-CORE-R2 -> ISPB-R1

18:10:44.948 (+0.798 s), frame 1, 73 bytes, HQ1-CORE-R2 Et0/2 <-> ISPB-R1 Et0/2

Header only: marker, length 19, type 4. Nothing else in it. Its whole job is to reset the peer's hold timer.

- **Ethernet II, Src: aa:bb:cc:00:19:20, Dst: aa:bb:cc:00:14:20**
  - Destination: aa:bb:cc:00:14:20 _(offset 0, 6 B)_
  - Source: aa:bb:cc:00:19:20 _(offset 6, 6 B)_
  - Type: IPv4 (0x0800) _(offset 12, 2 B)_
- **Internet Protocol Version 4, Src: 100.200.255.2, Dst: 100.200.255.1**
  - 0100 .... = Version: 4 _(offset 14, 1 B)_
  - .... 0101 = Header Length: 20 bytes (5) _(offset 14, 1 B)_
  - Differentiated Services Field: 0xc0 (DSCP: CS6, ECN: Not-ECT) _(offset 15, 1 B)_
    - 1100 00.. = Differentiated Services Codepoint: Class Selector 6 (48) _(offset 15, 1 B)_
    - .... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0) _(offset 15, 1 B)_
  - Total Length: 59 _(offset 16, 2 B)_
  - Identification: 0xb849 (47177) _(offset 18, 2 B)_
  - 010. .... = Flags: 0x2, Don't fragment _(offset 20, 1 B)_
    - 0... .... = Reserved bit: Not set _(offset 20, 1 B)_
    - .1.. .... = Don't fragment: Set _(offset 20, 1 B)_
    - ..0. .... = More fragments: Not set _(offset 20, 1 B)_
  - ...0 0000 0000 0000 = Fragment Offset: 0 _(offset 20, 2 B)_
  - Time to Live: 1 _(offset 22, 1 B)_
  - Protocol: TCP (6) _(offset 23, 1 B)_
  - Header Checksum: 0xf91e [validation disabled] _(offset 24, 2 B)_
  - Source Address: 100.200.255.2 _(offset 26, 4 B)_
  - Destination Address: 100.200.255.1 _(offset 30, 4 B)_
- **Transmission Control Protocol, Src Port: 20076, Dst Port: 179, Seq: 1, Ack: 1, Len: 19**
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
  - Window: 15814 _(offset 48, 2 B)_
  - Window size scaling factor: -1 (unknown) _(offset 48, 2 B)_
  - Checksum: 0x9895 [unverified] _(offset 50, 2 B)_
  - Urgent Pointer: 0 _(offset 52, 2 B)_
  - Timestamps
- **Border Gateway Protocol - KEEPALIVE Message**
  - Marker: ffffffffffffffffffffffffffffffff _(offset 54, 16 B)_
  - Length: 19 _(offset 70, 2 B)_
  - Type: KEEPALIVE Message (4) _(offset 72, 1 B)_

#### #4 BGP KEEPALIVE: HQ1-CORE-R1 -> ISPA-R1

18:10:55.594 (+11.444 s), frame 6, 73 bytes, HQ1-CORE-R1 Et0/2 <-> ISPA-R1 Et0/2

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
  - Identification: 0xc983 (51587) _(offset 18, 2 B)_
  - 010. .... = Flags: 0x2, Don't fragment _(offset 20, 1 B)_
    - 0... .... = Reserved bit: Not set _(offset 20, 1 B)_
    - .1.. .... = Don't fragment: Set _(offset 20, 1 B)_
    - ..0. .... = More fragments: Not set _(offset 20, 1 B)_
  - ...0 0000 0000 0000 = Fragment Offset: 0 _(offset 20, 2 B)_
  - Time to Live: 1 _(offset 22, 1 B)_
  - Protocol: TCP (6) _(offset 23, 1 B)_
  - Header Checksum: 0xe8ac [validation disabled] _(offset 24, 2 B)_
  - Source Address: 100.100.255.2 _(offset 26, 4 B)_
  - Destination Address: 100.100.255.1 _(offset 30, 4 B)_
- **Transmission Control Protocol, Src Port: 36654, Dst Port: 179, Seq: 1, Ack: 1, Len: 19**
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
  - Window: 16232 _(offset 48, 2 B)_
  - Window size scaling factor: -1 (unknown) _(offset 48, 2 B)_
  - Checksum: 0x8a6f [unverified] _(offset 50, 2 B)_
  - Urgent Pointer: 0 _(offset 52, 2 B)_
  - Timestamps
- **Border Gateway Protocol - KEEPALIVE Message**
  - Marker: ffffffffffffffffffffffffffffffff _(offset 54, 16 B)_
  - Length: 19 _(offset 70, 2 B)_
  - Type: KEEPALIVE Message (4) _(offset 72, 1 B)_

#### #5 BGP KEEPALIVE: ISPB-R1 -> HQ1-CORE-R2

18:11:08.944 (+24.794 s), frame 7, 73 bytes, HQ1-CORE-R2 Et0/2 <-> ISPB-R1 Et0/2

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
  - Identification: 0x184b (6219) _(offset 18, 2 B)_
  - 010. .... = Flags: 0x2, Don't fragment _(offset 20, 1 B)_
    - 0... .... = Reserved bit: Not set _(offset 20, 1 B)_
    - .1.. .... = Don't fragment: Set _(offset 20, 1 B)_
    - ..0. .... = More fragments: Not set _(offset 20, 1 B)_
  - ...0 0000 0000 0000 = Fragment Offset: 0 _(offset 20, 2 B)_
  - Time to Live: 1 _(offset 22, 1 B)_
  - Protocol: TCP (6) _(offset 23, 1 B)_
  - Header Checksum: 0x991d [validation disabled] _(offset 24, 2 B)_
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
  - Window: 15985 _(offset 48, 2 B)_
  - Window size scaling factor: -1 (unknown) _(offset 48, 2 B)_
  - Checksum: 0x97d7 [unverified] _(offset 50, 2 B)_
  - Urgent Pointer: 0 _(offset 52, 2 B)_
  - Timestamps
- **Border Gateway Protocol - KEEPALIVE Message**
  - Marker: ffffffffffffffffffffffffffffffff _(offset 54, 16 B)_
  - Length: 19 _(offset 70, 2 B)_
  - Type: KEEPALIVE Message (4) _(offset 72, 1 B)_

#### #6 BGP KEEPALIVE: ISPA-R1 -> HQ1-CORE-R1

18:11:33.451 (+49.301 s), frame 30, 73 bytes, HQ1-CORE-R1 Et0/2 <-> ISPA-R1 Et0/2

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
  - Identification: 0xa1d8 (41432) _(offset 18, 2 B)_
  - 010. .... = Flags: 0x2, Don't fragment _(offset 20, 1 B)_
    - 0... .... = Reserved bit: Not set _(offset 20, 1 B)_
    - .1.. .... = Don't fragment: Set _(offset 20, 1 B)_
    - ..0. .... = More fragments: Not set _(offset 20, 1 B)_
  - ...0 0000 0000 0000 = Fragment Offset: 0 _(offset 20, 2 B)_
  - Time to Live: 1 _(offset 22, 1 B)_
  - Protocol: TCP (6) _(offset 23, 1 B)_
  - Header Checksum: 0x1058 [validation disabled] _(offset 24, 2 B)_
  - Source Address: 100.100.255.1 _(offset 26, 4 B)_
  - Destination Address: 100.100.255.2 _(offset 30, 4 B)_
- **Transmission Control Protocol, Src Port: 179, Dst Port: 36654, Seq: 1, Ack: 20, Len: 19**
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
  - Window: 15628 _(offset 48, 2 B)_
  - Window size scaling factor: -1 (unknown) _(offset 48, 2 B)_
  - Checksum: 0x8cb8 [unverified] _(offset 50, 2 B)_
  - Urgent Pointer: 0 _(offset 52, 2 B)_
  - Timestamps
- **Border Gateway Protocol - KEEPALIVE Message**
  - Marker: ffffffffffffffffffffffffffffffff _(offset 54, 16 B)_
  - Length: 19 _(offset 70, 2 B)_
  - Type: KEEPALIVE Message (4) _(offset 72, 1 B)_

#### #7 ICMP unreachable, admin prohibited: ISPA-R1 -> HQ1-CORE-R1

18:12:39.152 (+115.003 s), frame 79, 70 bytes, HQ1-CORE-R1 Et0/2 <-> ISPA-R1 Et0/2

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
  - Identification: 0x4e30 (20016) _(offset 18, 2 B)_
  - 000. .... = Flags: 0x0 _(offset 20, 1 B)_
    - 0... .... = Reserved bit: Not set _(offset 20, 1 B)_
    - .0.. .... = Don't fragment: Not set _(offset 20, 1 B)_
    - ..0. .... = More fragments: Not set _(offset 20, 1 B)_
  - ...0 0000 0000 0000 = Fragment Offset: 0 _(offset 20, 2 B)_
  - Time to Live: 255 _(offset 22, 1 B)_
  - Protocol: ICMP (1) _(offset 23, 1 B)_
  - Header Checksum: 0xa6c7 [validation disabled] _(offset 24, 2 B)_
  - Source Address: 100.100.255.1 _(offset 26, 4 B)_
  - Destination Address: 100.100.255.2 _(offset 30, 4 B)_
- **Internet Control Message Protocol**
  - Type: 3 (Destination unreachable) _(offset 34, 1 B)_
  - Code: 13 (Communication administratively filtered) _(offset 35, 1 B)_
  - Checksum: 0x80d0 [correct] _(offset 36, 2 B)_
  - Unused: 00000000 _(offset 38, 4 B)_

#### #8 BGP NOTIFICATION: HQ1-CORE-R1 -> ISPA-R1

18:12:53.264 (+129.114 s), frame 89, 75 bytes, HQ1-CORE-R1 Et0/2 <-> ISPA-R1 Et0/2

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
  - Identification: 0xc988 (51592) _(offset 18, 2 B)_
  - 010. .... = Flags: 0x2, Don't fragment _(offset 20, 1 B)_
    - 0... .... = Reserved bit: Not set _(offset 20, 1 B)_
    - .1.. .... = Don't fragment: Set _(offset 20, 1 B)_
    - ..0. .... = More fragments: Not set _(offset 20, 1 B)_
  - ...0 0000 0000 0000 = Fragment Offset: 0 _(offset 20, 2 B)_
  - Time to Live: 1 _(offset 22, 1 B)_
  - Protocol: TCP (6) _(offset 23, 1 B)_
  - Header Checksum: 0xe8a5 [validation disabled] _(offset 24, 2 B)_
  - Source Address: 100.100.255.2 _(offset 26, 4 B)_
  - Destination Address: 100.100.255.1 _(offset 30, 4 B)_
- **Transmission Control Protocol, Src Port: 36654, Dst Port: 179, Seq: 58, Ack: 39, Len: 21**
  - TCP Segment Len: 21
  - Sequence Number: 58    (relative sequence number) _(offset 38, 4 B)_
  - Acknowledgment Number: 39    (relative ack number) _(offset 42, 4 B)_
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
  - Window: 16194 _(offset 48, 2 B)_
  - Window size scaling factor: -1 (unknown) _(offset 48, 2 B)_
  - Checksum: 0x892c [unverified] _(offset 50, 2 B)_
  - Urgent Pointer: 0 _(offset 52, 2 B)_
  - Timestamps
- **Border Gateway Protocol - NOTIFICATION Message**
  - Marker: ffffffffffffffffffffffffffffffff _(offset 54, 16 B)_
  - Length: 21 _(offset 70, 2 B)_
  - Type: NOTIFICATION Message (3) _(offset 72, 1 B)_
  - Major error Code: Cease (6) _(offset 73, 1 B)_
  - Minor error Code (Cease): Administratively Shutdown (2) _(offset 74, 1 B)_

#### #9 TCP FIN (port 179): HQ1-CORE-R1 -> ISPA-R1

18:12:53.265 (+129.115 s), frame 90, 60 bytes, HQ1-CORE-R1 Et0/2 <-> ISPA-R1 Et0/2

Clean TCP close right after a NOTIFICATION.

- **Ethernet II, Src: aa:bb:cc:00:18:20, Dst: aa:bb:cc:00:12:20**
  - Destination: aa:bb:cc:00:12:20 _(offset 0, 6 B)_
  - Source: aa:bb:cc:00:18:20 _(offset 6, 6 B)_
  - Type: IPv4 (0x0800) _(offset 12, 2 B)_
  - Padding: 000000000000 _(offset 54, 6 B)_
- **Internet Protocol Version 4, Src: 100.100.255.2, Dst: 100.100.255.1**
  - 0100 .... = Version: 4 _(offset 14, 1 B)_
  - .... 0101 = Header Length: 20 bytes (5) _(offset 14, 1 B)_
  - Differentiated Services Field: 0xc0 (DSCP: CS6, ECN: Not-ECT) _(offset 15, 1 B)_
    - 1100 00.. = Differentiated Services Codepoint: Class Selector 6 (48) _(offset 15, 1 B)_
    - .... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0) _(offset 15, 1 B)_
  - Total Length: 40 _(offset 16, 2 B)_
  - Identification: 0xc989 (51593) _(offset 18, 2 B)_
  - 010. .... = Flags: 0x2, Don't fragment _(offset 20, 1 B)_
    - 0... .... = Reserved bit: Not set _(offset 20, 1 B)_
    - .1.. .... = Don't fragment: Set _(offset 20, 1 B)_
    - ..0. .... = More fragments: Not set _(offset 20, 1 B)_
  - ...0 0000 0000 0000 = Fragment Offset: 0 _(offset 20, 2 B)_
  - Time to Live: 1 _(offset 22, 1 B)_
  - Protocol: TCP (6) _(offset 23, 1 B)_
  - Header Checksum: 0xe8b9 [validation disabled] _(offset 24, 2 B)_
  - Source Address: 100.100.255.2 _(offset 26, 4 B)_
  - Destination Address: 100.100.255.1 _(offset 30, 4 B)_
- **Transmission Control Protocol, Src Port: 36654, Dst Port: 179, Seq: 79, Ack: 39, Len: 0**
  - TCP Segment Len: 0
  - Sequence Number: 79    (relative sequence number) _(offset 38, 4 B)_
  - Acknowledgment Number: 39    (relative ack number) _(offset 42, 4 B)_
  - 0101 .... = Header Length: 20 bytes (5) _(offset 46, 1 B)_
  - Flags: 0x019 (FIN, PSH, ACK) _(offset 46, 2 B)_
    - 000. .... .... = Reserved: Not set _(offset 46, 1 B)_
    - ...0 .... .... = Accurate ECN: Not set _(offset 46, 1 B)_
    - .... 0... .... = Congestion Window Reduced: Not set _(offset 47, 1 B)_
    - .... .0.. .... = ECN-Echo: Not set _(offset 47, 1 B)_
    - .... ..0. .... = Urgent: Not set _(offset 47, 1 B)_
    - .... ...1 .... = Acknowledgment: Set _(offset 47, 1 B)_
    - .... .... 1... = Push: Set _(offset 47, 1 B)_
    - .... .... .0.. = Reset: Not set _(offset 47, 1 B)_
    - .... .... ..0. = Syn: Not set _(offset 47, 1 B)_
    - .... .... ...1 = Fin: Set _(offset 47, 1 B)_
    - TCP Flags: ·······AP··F _(offset 46, 2 B)_
  - Window: 16194 _(offset 48, 2 B)_
  - Window size scaling factor: -1 (unknown) _(offset 48, 2 B)_
  - Checksum: 0x8e46 [unverified] _(offset 50, 2 B)_
  - Urgent Pointer: 0 _(offset 52, 2 B)_
  - Timestamps

#### #10 BGP UPDATE: ISPB-R1 -> HQ1-CORE-R2

18:12:53.273 (+129.123 s), frame 41, 110 bytes, HQ1-CORE-R2 Et0/2 <-> ISPB-R1 Et0/2

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
  - Identification: 0x184f (6223) _(offset 18, 2 B)_
  - 010. .... = Flags: 0x2, Don't fragment _(offset 20, 1 B)_
    - 0... .... = Reserved bit: Not set _(offset 20, 1 B)_
    - .1.. .... = Don't fragment: Set _(offset 20, 1 B)_
    - ..0. .... = More fragments: Not set _(offset 20, 1 B)_
  - ...0 0000 0000 0000 = Fragment Offset: 0 _(offset 20, 2 B)_
  - Time to Live: 1 _(offset 22, 1 B)_
  - Protocol: TCP (6) _(offset 23, 1 B)_
  - Header Checksum: 0x98f4 [validation disabled] _(offset 24, 2 B)_
  - Source Address: 100.200.255.1 _(offset 26, 4 B)_
  - Destination Address: 100.200.255.2 _(offset 30, 4 B)_
- **Transmission Control Protocol, Src Port: 179, Dst Port: 20076, Seq: 39, Ack: 39, Len: 56**
  - TCP Segment Len: 56
  - Sequence Number: 39    (relative sequence number) _(offset 38, 4 B)_
  - Acknowledgment Number: 39    (relative ack number) _(offset 42, 4 B)_
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
  - Window: 15947 _(offset 48, 2 B)_
  - Window size scaling factor: -1 (unknown) _(offset 48, 2 B)_
  - Checksum: 0x4439 [unverified] _(offset 50, 2 B)_
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

#### #11 TCP SYN (port 179): ISPA-R1 -> HQ1-CORE-R1

18:13:00.571 (+136.421 s), frame 101, 66 bytes, HQ1-CORE-R1 Et0/2 <-> ISPA-R1 Et0/2

A router opening (or re-opening) the BGP transport.

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
  - Total Length: 52 _(offset 16, 2 B)_
  - Identification: 0xe028 (57384) _(offset 18, 2 B)_
  - 010. .... = Flags: 0x2, Don't fragment _(offset 20, 1 B)_
    - 0... .... = Reserved bit: Not set _(offset 20, 1 B)_
    - .1.. .... = Don't fragment: Set _(offset 20, 1 B)_
    - ..0. .... = More fragments: Not set _(offset 20, 1 B)_
  - ...0 0000 0000 0000 = Fragment Offset: 0 _(offset 20, 2 B)_
  - Time to Live: 1 _(offset 22, 1 B)_
  - Protocol: TCP (6) _(offset 23, 1 B)_
  - Header Checksum: 0xd20e [validation disabled] _(offset 24, 2 B)_
  - Source Address: 100.100.255.1 _(offset 26, 4 B)_
  - Destination Address: 100.100.255.2 _(offset 30, 4 B)_
- **Transmission Control Protocol, Src Port: 31178, Dst Port: 179, Seq: 0, Len: 0**
  - TCP Segment Len: 0
  - Sequence Number: 0    (relative sequence number) _(offset 38, 4 B)_
  - Acknowledgment Number: 0 _(offset 42, 4 B)_
  - 1000 .... = Header Length: 32 bytes (8) _(offset 46, 1 B)_
  - Flags: 0x002 (SYN) _(offset 46, 2 B)_
    - 000. .... .... = Reserved: Not set _(offset 46, 1 B)_
    - ...0 .... .... = Accurate ECN: Not set _(offset 46, 1 B)_
    - .... 0... .... = Congestion Window Reduced: Not set _(offset 47, 1 B)_
    - .... .0.. .... = ECN-Echo: Not set _(offset 47, 1 B)_
    - .... ..0. .... = Urgent: Not set _(offset 47, 1 B)_
    - .... ...0 .... = Acknowledgment: Not set _(offset 47, 1 B)_
    - .... .... 0... = Push: Not set _(offset 47, 1 B)_
    - .... .... .0.. = Reset: Not set _(offset 47, 1 B)_
    - .... .... ..1. = Syn: Set _(offset 47, 1 B)_
    - .... .... ...0 = Fin: Not set _(offset 47, 1 B)_
    - TCP Flags: ··········S· _(offset 46, 2 B)_
  - Window: 16384 _(offset 48, 2 B)_
  - Checksum: 0x868a [unverified] _(offset 50, 2 B)_
  - Urgent Pointer: 0 _(offset 52, 2 B)_
  - Options: (12 bytes), Maximum segment size, SACK permitted, No-Operation (NOP), No-Operation (NOP), Window scale, End of Option List (EOL) _(offset 54, 12 B)_
    - TCP Option - Maximum segment size: 1460 bytes _(offset 54, 4 B)_
      - Kind: Maximum Segment Size (2) _(offset 54, 1 B)_
      - Length: 4 _(offset 55, 1 B)_
      - MSS Value: 1460 _(offset 56, 2 B)_
    - TCP Option - SACK permitted _(offset 58, 2 B)_
      - Kind: SACK Permitted (4) _(offset 58, 1 B)_
      - Length: 2 _(offset 59, 1 B)_
    - TCP Option - No-Operation (NOP) _(offset 60, 1 B)_
      - Kind: No-Operation (1) _(offset 60, 1 B)_
    - TCP Option - No-Operation (NOP) _(offset 61, 1 B)_
      - Kind: No-Operation (1) _(offset 61, 1 B)_
    - TCP Option - Window scale: 0 (multiply by 1) _(offset 62, 3 B)_
      - Kind: Window Scale (3) _(offset 62, 1 B)_
      - Length: 3 _(offset 63, 1 B)_
      - Shift count: 0 _(offset 64, 1 B)_
      - Multiplier: 1 _(offset 64, 1 B)_
    - TCP Option - End of Option List (EOL) _(offset 65, 1 B)_
      - Kind: End of Option List (0) _(offset 65, 1 B)_
  - Timestamps

#### #12 TCP RST (port 179): HQ1-CORE-R1 -> ISPA-R1

18:13:00.572 (+136.423 s), frame 102, 60 bytes, HQ1-CORE-R1 Et0/2 <-> ISPA-R1 Et0/2

The other router refusing the connection.

- **Ethernet II, Src: aa:bb:cc:00:18:20, Dst: aa:bb:cc:00:12:20**
  - Destination: aa:bb:cc:00:12:20 _(offset 0, 6 B)_
  - Source: aa:bb:cc:00:18:20 _(offset 6, 6 B)_
  - Type: IPv4 (0x0800) _(offset 12, 2 B)_
  - Padding: 000000000000 _(offset 54, 6 B)_
- **Internet Protocol Version 4, Src: 100.100.255.2, Dst: 100.100.255.1**
  - 0100 .... = Version: 4 _(offset 14, 1 B)_
  - .... 0101 = Header Length: 20 bytes (5) _(offset 14, 1 B)_
  - Differentiated Services Field: 0x00 (DSCP: CS0, ECN: Not-ECT) _(offset 15, 1 B)_
    - 0000 00.. = Differentiated Services Codepoint: Default (0) _(offset 15, 1 B)_
    - .... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0) _(offset 15, 1 B)_
  - Total Length: 40 _(offset 16, 2 B)_
  - Identification: 0x4ba5 (19365) _(offset 18, 2 B)_
  - 000. .... = Flags: 0x0 _(offset 20, 1 B)_
    - 0... .... = Reserved bit: Not set _(offset 20, 1 B)_
    - .0.. .... = Don't fragment: Not set _(offset 20, 1 B)_
    - ..0. .... = More fragments: Not set _(offset 20, 1 B)_
  - ...0 0000 0000 0000 = Fragment Offset: 0 _(offset 20, 2 B)_
  - Time to Live: 255 _(offset 22, 1 B)_
  - Protocol: TCP (6) _(offset 23, 1 B)_
  - Header Checksum: 0xa95d [validation disabled] _(offset 24, 2 B)_
  - Source Address: 100.100.255.2 _(offset 26, 4 B)_
  - Destination Address: 100.100.255.1 _(offset 30, 4 B)_
- **Transmission Control Protocol, Src Port: 179, Dst Port: 31178, Seq: 1, Ack: 1, Len: 0**
  - TCP Segment Len: 0
  - Sequence Number: 1    (relative sequence number) _(offset 38, 4 B)_
  - Acknowledgment Number: 1    (relative ack number) _(offset 42, 4 B)_
  - 0101 .... = Header Length: 20 bytes (5) _(offset 46, 1 B)_
  - Flags: 0x014 (RST, ACK) _(offset 46, 2 B)_
    - 000. .... .... = Reserved: Not set _(offset 46, 1 B)_
    - ...0 .... .... = Accurate ECN: Not set _(offset 46, 1 B)_
    - .... 0... .... = Congestion Window Reduced: Not set _(offset 47, 1 B)_
    - .... .0.. .... = ECN-Echo: Not set _(offset 47, 1 B)_
    - .... ..0. .... = Urgent: Not set _(offset 47, 1 B)_
    - .... ...1 .... = Acknowledgment: Set _(offset 47, 1 B)_
    - .... .... 0... = Push: Not set _(offset 47, 1 B)_
    - .... .... .1.. = Reset: Set _(offset 47, 1 B)_
    - .... .... ..0. = Syn: Not set _(offset 47, 1 B)_
    - .... .... ...0 = Fin: Not set _(offset 47, 1 B)_
    - TCP Flags: ·······A·R·· _(offset 46, 2 B)_
  - Window: 0 _(offset 48, 2 B)_
  - Window size scaling factor: -1 (unknown) _(offset 48, 2 B)_
  - Checksum: 0x0642 [unverified] _(offset 50, 2 B)_
  - Urgent Pointer: 0 _(offset 52, 2 B)_
  - Timestamps

#### #13 BGP UPDATE: ISPB-R1 -> HQ1-CORE-R2

18:13:23.451 (+159.301 s), frame 50, 82 bytes, HQ1-CORE-R2 Et0/2 <-> ISPB-R1 Et0/2

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
  - Identification: 0x1850 (6224) _(offset 18, 2 B)_
  - 010. .... = Flags: 0x2, Don't fragment _(offset 20, 1 B)_
    - 0... .... = Reserved bit: Not set _(offset 20, 1 B)_
    - .1.. .... = Don't fragment: Set _(offset 20, 1 B)_
    - ..0. .... = More fragments: Not set _(offset 20, 1 B)_
  - ...0 0000 0000 0000 = Fragment Offset: 0 _(offset 20, 2 B)_
  - Time to Live: 1 _(offset 22, 1 B)_
  - Protocol: TCP (6) _(offset 23, 1 B)_
  - Header Checksum: 0x990f [validation disabled] _(offset 24, 2 B)_
  - Source Address: 100.200.255.1 _(offset 26, 4 B)_
  - Destination Address: 100.200.255.2 _(offset 30, 4 B)_
- **Transmission Control Protocol, Src Port: 179, Dst Port: 20076, Seq: 95, Ack: 39, Len: 28**
  - TCP Segment Len: 28
  - Sequence Number: 95    (relative sequence number) _(offset 38, 4 B)_
  - Acknowledgment Number: 39    (relative ack number) _(offset 42, 4 B)_
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
  - Window: 15947 _(offset 48, 2 B)_
  - Window size scaling factor: -1 (unknown) _(offset 48, 2 B)_
  - Checksum: 0x6a1a [unverified] _(offset 50, 2 B)_
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

### BGP sessions and messages

2 BGP session(s), 19 BGP message(s): 16 KEEPALIVE, 2 UPDATE, 1 NOTIFICATION.

**BGP sessions**

| Peers | Up when capture started | Messages | Keepalive rhythm | Ended | Reconnect attempts |
|---|---|---|---|---|---|
| ISPA-R1 (100.100.255.1) <-> HQ1-CORE-R1 (100.100.255.2) | yes, no OPEN seen | KEEPALIVE 5, NOTIFICATION 1 | ISPA-R1 every 50.2 s (50-50 s); HQ1-CORE-R1 every 54.8 s (54-55 s) | closed by HQ1-CORE-R1 (100.100.255.2) at 18:12:53.264: Cease / Administrative shutdown | 20 refused |
| ISPB-R1 (100.200.255.1) <-> HQ1-CORE-R2 (100.200.255.2) | yes, no OPEN seen | KEEPALIVE 11, UPDATE 2 | ISPB-R1 every 52.7 s (30-58 s); HQ1-CORE-R2 every 55.3 s (52-58 s) | still up at the end | - |

**UPDATE messages (announce and withdraw)**

| Clock | From -> to | Announces | Withdraws | AS_PATH | NEXT_HOP | Other attributes | Frame |
|---|---|---|---|---|---|---|---|
| 18:12:53.273 | ISPB-R1 (100.200.255.1) -> HQ1-CORE-R2 (100.200.255.2) | 198.51.100.0/25 | - | 65200 65100 65001 | 100.200.255.1 | origin IGP | 41 |
| 18:13:23.451 | ISPB-R1 (100.200.255.1) -> HQ1-CORE-R2 (100.200.255.2) | - | 198.51.100.0/25 | - | - | - | 50 |

**NOTIFICATION messages**

| Clock | From -> to | Reason | Frame |
|---|---|---|---|
| 18:12:53.264 | HQ1-CORE-R1 (100.100.255.2) -> ISPA-R1 (100.100.255.1) | Cease / Administrative shutdown | 89 |

**Every BGP message on the wire**

| Clock | At (s) | From -> to | Message | BGP bytes | Frame |
|---|---|---|---|---|---|
| 18:10:44.948 | 0.80 | HQ1-CORE-R2 (100.200.255.2) -> ISPB-R1 (100.200.255.1) | KEEPALIVE | 19 | 1 |
| 18:10:55.594 | 11.44 | HQ1-CORE-R1 (100.100.255.2) -> ISPA-R1 (100.100.255.1) | KEEPALIVE | 19 | 6 |
| 18:11:08.944 | 24.79 | ISPB-R1 (100.200.255.1) -> HQ1-CORE-R2 (100.200.255.2) | KEEPALIVE | 19 | 7 |
| 18:11:33.451 | 49.30 | ISPA-R1 (100.100.255.1) -> HQ1-CORE-R1 (100.100.255.2) | KEEPALIVE | 19 | 30 |
| 18:11:40.256 | 56.11 | HQ1-CORE-R2 (100.200.255.2) -> ISPB-R1 (100.200.255.1) | KEEPALIVE | 19 | 16 |
| 18:11:50.923 | 66.77 | HQ1-CORE-R1 (100.100.255.2) -> ISPA-R1 (100.100.255.1) | KEEPALIVE | 19 | 44 |
| 18:12:02.197 | 78.05 | ISPB-R1 (100.200.255.1) -> HQ1-CORE-R2 (100.200.255.2) | KEEPALIVE | 19 | 24 |
| 18:12:23.631 | 99.48 | ISPA-R1 (100.100.255.1) -> HQ1-CORE-R1 (100.100.255.2) | KEEPALIVE | 19 | 68 |
| 18:12:37.605 | 113.45 | HQ1-CORE-R2 (100.200.255.2) -> ISPB-R1 (100.200.255.1) | KEEPALIVE | 19 | 34 |
| 18:12:45.201 | 121.05 | HQ1-CORE-R1 (100.100.255.2) -> ISPA-R1 (100.100.255.1) | KEEPALIVE | 19 | 84 |
| 18:12:53.264 | 129.11 | HQ1-CORE-R1 (100.100.255.2) -> ISPA-R1 (100.100.255.1) | NOTIFICATION: Cease / Administrative shutdown | 21 | 89 |
| 18:12:53.273 | 129.12 | ISPB-R1 (100.200.255.1) -> HQ1-CORE-R2 (100.200.255.2) | UPDATE: +1 / -0 prefix(es) | 56 | 41 |
| 18:13:23.451 | 159.30 | ISPB-R1 (100.200.255.1) -> HQ1-CORE-R2 (100.200.255.2) | UPDATE: +0 / -1 prefix(es) | 28 | 50 |
| 18:13:35.982 | 171.83 | HQ1-CORE-R2 (100.200.255.2) -> ISPB-R1 (100.200.255.1) | KEEPALIVE | 19 | 54 |
| 18:14:21.481 | 217.33 | ISPB-R1 (100.200.255.1) -> HQ1-CORE-R2 (100.200.255.2) | KEEPALIVE | 19 | 67 |
| 18:14:28.215 | 224.06 | HQ1-CORE-R2 (100.200.255.2) -> ISPB-R1 (100.200.255.1) | KEEPALIVE | 19 | 70 |
| 18:15:13.710 | 269.56 | ISPB-R1 (100.200.255.1) -> HQ1-CORE-R2 (100.200.255.2) | KEEPALIVE | 19 | 85 |
| 18:15:22.495 | 278.34 | HQ1-CORE-R2 (100.200.255.2) -> ISPB-R1 (100.200.255.1) | KEEPALIVE | 19 | 87 |
| 18:16:09.014 | 324.86 | ISPB-R1 (100.200.255.1) -> HQ1-CORE-R2 (100.200.255.2) | KEEPALIVE | 19 | 102 |

### Probes (IP SLA and other periodic pings)

100.100.255.2 -> 100.200.1.1 every 5.0 s: 23 ok, 44 failed.

**Probe series**

| Source -> target | Interval | Probes | Answered | Failed | Median RTT | Changes |
|---|---|---|---|---|---|---|
| 100.100.255.2 -> 100.200.1.1 | 5.0 s | 67 | 23 | 44 | 2.5 ms | 18:12:39.150 failing (ICMP 3/13 communication administratively prohibited (ACL)) |

### Link and Layer 2

0 link-level event(s). 

**Neighbors announced on this link**

| Protocol | Frames | Device |
|---|---|---|
| LLDP | 33 | HQ1-CORE-R1.almnjoy.lab, ISPA-R1.almnjoy.lab, ISPB-R1.almnjoy.lab |
| CDP | 24 | HQ1-CORE-R1.almnjoy.lab, HQ1-CORE-R2.almnjoy.lab, ISPA-R1.almnjoy.lab, ISPB-R1.almnjoy.lab |

### ICMP

66 pings / 23 replies, 44 unreachable, 0 TTL exceeded.

**Destination unreachable**

| Reason | Count |
|---|---|
| administratively prohibited | 44 |

### Traffic patterns

27 conversation(s), mostly other IP: ICMP on 100.200.1.1, 170 bps, 36% of bytes.

**What the traffic is (grouped by server and port)**

| Server | Service | Looks like | Conversations | Clients | Bytes | Share | Avg rate | Client -> server / back |
|---|---|---|---|---|---|---|---|---|
| 100.200.1.1 | ICMP | Other IP | 1 | 1 | 6.9 KB | 36.0% | 170 bps | 5.1 KB / 1.8 KB |
| 100.200.255.2 | ESP | Other IP | 1 | 1 | 3.8 KB | 19.9% | 102 bps | 1.9 KB / 1.9 KB |
| 100.100.255.2 | ICMP | Keepalive / heartbeat | 1 | 1 | 3.0 KB | 15.8% | 115 bps | 3.0 KB / 0 B |
| 100.100.255.2 | BGP 179 | Polling every ~10 s | 20 | 1 | 2.5 KB | 12.9% | 108 bps | 1.3 KB / 1.2 KB |
| 100.200.255.1 | BGP 179 | Request / response | 2 | 1 | 1.7 KB | 9.1% | 44 bps | 858 B / 917 B |
| 100.100.255.1 | BGP 179 | Request / response | 1 | 1 | 980 B | 5.0% | 67 bps | 534 B / 446 B |
| 34.107.243.93 | HTTPS 443 | Request / response | 1 | 1 | 250 B | 1.3% | 2 kbps | 94 B / 156 B |

**Largest individual conversations**

| Client | Server | Service | Looks like | Packets | Bytes | Lasted | Rate | Filter |
|---|---|---|---|---|---|---|---|---|
| 100.100.255.2: | 100.200.1.1 | ICMP | Other IP | 90 | 6.9 KB | 330.0 s | 170 bps | ip.addr==100.100.255.2 && ip.addr==100.200.1.1 |
| 100.200.255.10: | 100.200.255.2 | ESP | Other IP | 24 | 3.8 KB | 305.8 s | 102 bps | ip.addr==100.200.255.10 && ip.addr==100.200.255.2 |
| 100.100.255.1: | 100.100.255.2 | ICMP | Keepalive / heartbeat | 44 | 3.0 KB | 215.0 s | 115 bps | ip.addr==100.100.255.1 && ip.addr==100.100.255.2 |
| 100.200.255.2:20076 | 100.200.255.1 | BGP 179 | Request / response | 24 | 1.6 KB | 300.2 s | 44 bps | ip.addr==100.200.255.2 && ip.addr==100.200.255.1 |
| 100.100.255.2:36654 | 100.100.255.1 | BGP 179 | Request / response | 15 | 980 B | 117.7 s | 67 bps | ip.addr==100.100.255.2 && ip.addr==100.100.255.1 |
| 198.51.100.10:1025 | 34.107.243.93 | HTTPS 443 | Request / response | 3 | 250 B | 0.0 s | 0 bps | ip.addr==198.51.100.10 && ip.addr==34.107.243.93 |
| 100.200.255.2:20076 | 100.200.255.1 | BGP 179 | Request / response | 2 | 133 B | 0.1 s | 0 bps | ip.addr==100.200.255.2 && ip.addr==100.200.255.1 |
| 100.100.255.1:31178 | 100.100.255.2 | BGP 179 | Polling every ~10 s | 2 | 126 B | 0.0 s | 0 bps | ip.addr==100.100.255.1 && ip.addr==100.100.255.2 |
| 100.100.255.1:37912 | 100.100.255.2 | BGP 179 | Polling every ~10 s | 2 | 126 B | 0.0 s | 0 bps | ip.addr==100.100.255.1 && ip.addr==100.100.255.2 |
| 100.100.255.1:26362 | 100.100.255.2 | BGP 179 | Polling every ~10 s | 2 | 126 B | 0.0 s | 0 bps | ip.addr==100.100.255.1 && ip.addr==100.100.255.2 |
| 100.100.255.1:41521 | 100.100.255.2 | BGP 179 | Polling every ~10 s | 2 | 126 B | 0.0 s | 0 bps | ip.addr==100.100.255.1 && ip.addr==100.100.255.2 |
| 100.100.255.1:54850 | 100.100.255.2 | BGP 179 | Polling every ~10 s | 2 | 126 B | 0.0 s | 0 bps | ip.addr==100.100.255.1 && ip.addr==100.100.255.2 |
| 100.100.255.1:28856 | 100.100.255.2 | BGP 179 | Polling every ~10 s | 2 | 126 B | 0.0 s | 0 bps | ip.addr==100.100.255.1 && ip.addr==100.100.255.2 |
| 100.100.255.1:26248 | 100.100.255.2 | BGP 179 | Polling every ~10 s | 2 | 126 B | 0.0 s | 0 bps | ip.addr==100.100.255.1 && ip.addr==100.100.255.2 |
| 100.100.255.1:46545 | 100.100.255.2 | BGP 179 | Polling every ~10 s | 2 | 126 B | 0.0 s | 0 bps | ip.addr==100.100.255.1 && ip.addr==100.100.255.2 |

### TCP health

24 TCP connections, 0 retransmissions, 20 resets. Handshake RTT median n/a.

**By service (server:port)**

| Service | Conns | Data segs | Retransmits | Retx rate | Dup ACKs | Resets | Worst stall | Handshake p50 |
|---|---|---|---|---|---|---|---|---|
| 100.100.255.2:179 | 20 | 0 | 0 | 0.0% | 0 | 20 | - | n/a |
| 100.200.255.1:179 | 2 | 13 | 0 | 0.0% | 0 | 0 | - | n/a |
| 100.100.255.1:179 | 1 | 6 | 0 | 0.0% | 0 | 0 | - | n/a |
| 34.107.243.93:443 | 1 | 2 | 0 | 0.0% | 0 | 0 | - | n/a |

**Worst connections**

| Stream | Client | Server | Frames | Retx | Dup ACK | RST | Longest stall | Filter |
|---|---|---|---|---|---|---|---|---|
| 0 | 100.100.255.2:36654 | 100.100.255.1:179 | 15 | 0 | 0 | 0 | - | tcp.stream eq 0 |
| 1 | 198.51.100.10:1025 | 34.107.243.93:443 | 3 | 0 | 0 | 0 | - | tcp.stream eq 1 |
| 2 | 100.100.255.1:31178 | 100.100.255.2:179 | 2 | 0 | 0 | 1 by server | - | tcp.stream eq 2 |
| 3 | 100.100.255.1:37912 | 100.100.255.2:179 | 2 | 0 | 0 | 1 by server | - | tcp.stream eq 3 |
| 4 | 100.100.255.1:26362 | 100.100.255.2:179 | 2 | 0 | 0 | 1 by server | - | tcp.stream eq 4 |
| 5 | 100.100.255.1:41521 | 100.100.255.2:179 | 2 | 0 | 0 | 1 by server | - | tcp.stream eq 5 |
| 6 | 100.100.255.1:54850 | 100.100.255.2:179 | 2 | 0 | 0 | 1 by server | - | tcp.stream eq 6 |
| 7 | 100.100.255.1:28856 | 100.100.255.2:179 | 2 | 0 | 0 | 1 by server | - | tcp.stream eq 7 |
| 8 | 100.100.255.1:26248 | 100.100.255.2:179 | 2 | 0 | 0 | 1 by server | - | tcp.stream eq 8 |
| 9 | 100.100.255.1:46545 | 100.100.255.2:179 | 2 | 0 | 0 | 1 by server | - | tcp.stream eq 9 |
| 10 | 100.100.255.1:20004 | 100.100.255.2:179 | 2 | 0 | 0 | 1 by server | - | tcp.stream eq 10 |
| 11 | 100.100.255.1:42399 | 100.100.255.2:179 | 2 | 0 | 0 | 1 by server | - | tcp.stream eq 11 |

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

Largest frame 416 B. SYN MSS 1460-1460.

### Transactions (request to response)

1 request/response exchanges across 1 service(s). Slowest: n/a on stream 1.

**Latency by service**

| Service | Transactions | Server think p50 | Client-felt p50 | Client-felt p95 | Client-felt max | From SYN p50 | No response | App failures |
|---|---|---|---|---|---|---|---|---|
| 34.107.243.93:443 | 1 | n/a | n/a | n/a | n/a | n/a | 1 | 0 |

**Slowest transactions**

| At (s) | Stream | Request | Status | Server think | Client-felt | Resends | Filter |
|---|---|---|---|---|---|---|---|
| 80.03 | 1 | - | - | n/a | n/a | 0 | tcp.stream eq 1 |

## Notes from the engine

- Merged 4 captures onto one clock. Frame numbers in this report are per file; the link label says which file.

## Appendix: all facts (JSON)

```json
{
 "source": "4 captures",
 "kind": "pcap",
 "focus": {
  "src": [],
  "dst": [],
  "ports": [],
  "question": "Break down the individual BGP messages (keepalives, updates, the notification) and the IP SLA pings. Show what we can see in each packet.",
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
  "when": "",
  "when_t": null,
  "display_filter": ""
 },
 "overview": {
  "packets": 368,
  "duration_s": 331.039,
  "bytes": 46272.0,
  "bytes_h": "45.2 KB",
  "start": "2026-11-23 18:10:44 CST",
  "avg_pps": 1.1,
  "focus_packets": 368,
  "tcp_streams": 24,
  "hosts": 14
 },
 "findings": [
  {
   "severity": "warning",
   "category": "bgp",
   "title": "BGP session closed by HQ1-CORE-R1: Cease / Administrative shutdown",
   "detail": "ISPA-R1 (100.100.255.1) <-> HQ1-CORE-R1 (100.100.255.2): HQ1-CORE-R1 (100.100.255.2) sent a NOTIFICATION (Cease / Administrative shutdown) at 18:12:53.264 and closed TCP. Administrative shutdown means the sender's own config shut the neighbor: a person, or a script / EEM applet. ",
   "evidence": "bgp.type == 3 && ip.src == 100.100.255.2",
   "frames": [
    89
   ],
   "metrics": {}
  },
  {
   "severity": "warning",
   "category": "probes",
   "title": "Probe to 100.200.1.1 started failing at 18:12:39.150",
   "detail": "Last answered probe 18:12:34.150; from 18:12:39.150 on: ICMP 3/13 communication administratively prohibited (ACL) from 100.100.255.1. The reporting router is telling you an ACL dropped the probe: the path past it is blocked on purpose. An IP SLA operation counts this as a failure; a track object on it goes down after its delay.",
   "evidence": "icmp && ip.addr == 100.200.1.1 && icmp.type != 8",
   "frames": [
    79
   ],
   "metrics": {}
  },
  {
   "severity": "warning",
   "category": "icmp",
   "title": "43 ping(s) refused with ICMP unreachable",
   "detail": "66 echo requests, 23 replies, 43 answered by an ICMP error instead of a reply. That is a router on the path saying no, not packet loss.",
   "evidence": "icmp.type==3",
   "frames": [],
   "metrics": {}
  },
  {
   "severity": "info",
   "category": "breakdown",
   "title": "13 packets broken down field by field",
   "detail": "Kinds: ICMP echo request, ICMP echo reply, BGP KEEPALIVE, ICMP unreachable, admin prohibited, BGP NOTIFICATION, TCP FIN (port 179), BGP UPDATE, TCP SYN (port 179), TCP RST (port 179).",
   "evidence": "bgp || icmp",
   "frames": [],
   "metrics": {}
  },
  {
   "severity": "info",
   "category": "bgp",
   "title": "20 reconnect attempt(s) refused",
   "detail": "ISPA-R1 (100.100.255.1) kept opening TCP 179 to HQ1-CORE-R1 (100.100.255.2) (18:13:00.571 to 18:16:06.971, every 6-14 s) and every SYN got a RST back. A shut-down or unconfigured neighbor refuses the connection; the other side keeps trying on its connect-retry timer.",
   "evidence": "ip.addr==100.100.255.1 && ip.addr==100.100.255.2 && tcp.port==179 && (tcp.flags.syn == 1 || tcp.flags.reset == 1)",
   "frames": [
    101
   ],
   "metrics": {}
  },
  {
   "severity": "info",
   "category": "bgp",
   "title": "UPDATE ISPB-R1 -> HQ1-CORE-R2: announce 198.51.100.0/25",
   "detail": "At 18:12:53.273, AS_PATH 65200 65100 65001, NEXT_HOP 100.200.255.1.",
   "evidence": "bgp.type == 2 && ip.src == 100.200.255.1",
   "frames": [
    41
   ],
   "metrics": {}
  },
  {
   "severity": "info",
   "category": "bgp",
   "title": "UPDATE ISPB-R1 -> HQ1-CORE-R2: withdraw 198.51.100.0/25",
   "detail": "At 18:13:23.451.",
   "evidence": "bgp.type == 2 && ip.src == 100.200.255.1",
   "frames": [
    50
   ],
   "metrics": {}
  },
  {
   "severity": "info",
   "category": "probes",
   "title": "Periodic probe 100.100.255.2 -> 100.200.1.1 every 5.0 s",
   "detail": "67 echo requests on a steady 5.0 s interval: this is IP SLA icmp-echo (one source, one target, fixed frequency). 23 answered (median 2.5 ms), 44 failed.",
   "evidence": "icmp && ip.addr == 100.100.255.2 && ip.addr == 100.200.1.1",
   "frames": [],
   "metrics": {}
  },
  {
   "severity": "info",
   "category": "probes",
   "title": "14.1 s after the first failed probe: BGP NOTIFICATION 100.100.255.2 -> 100.100.255.1",
   "detail": "First failed probe 18:12:39.150, then BGP NOTIFICATION 100.100.255.2 -> 100.100.255.1 at 18:12:53.264. When a probe drives a track object, the gap is the track's `delay down` plus the time an EEM applet (or the routing process) takes to act.",
   "evidence": "bgp.type == 3",
   "frames": [
    89
   ],
   "metrics": {}
  },
  {
   "severity": "info",
   "category": "flows",
   "title": "27 conversation(s) across 7 service(s)",
   "detail": "27 conversation(s), mostly other IP: ICMP on 100.200.1.1, 170 bps, 36% of bytes. Traffic by pattern: other IP 56%, keepalive / heartbeat 16%, request / response 15%.",
   "evidence": "ip",
   "frames": [],
   "metrics": {}
  },
  {
   "severity": "info",
   "category": "icmp",
   "title": "44 ICMP destination-unreachable message(s)",
   "detail": "Reasons: administratively prohibited (44).",
   "evidence": "icmp.type==3",
   "frames": [
    79,
    83,
    87,
    95,
    99,
    104,
    107,
    113
   ],
   "metrics": {}
  },
  {
   "severity": "info",
   "category": "tcp",
   "title": "20 connection attempt(s) refused with RST",
   "detail": "The server answered the SYN with a RST: it is up and reachable, but nothing accepts on that port (BGP port 179: the neighbor is shut down or not configured on that side, so it refuses the peer's connect-retry).",
   "evidence": "tcp.flags.syn==1 && tcp.flags.ack==0 && tcp.port in {179}",
   "frames": [
    101,
    109,
    114,
    123,
    128,
    137,
    146,
    157
   ],
   "metrics": {}
  },
  {
   "severity": "ok",
   "category": "bgp",
   "title": "ISPA-R1 heard from every 50.2 s",
   "detail": "2 KEEPALIVE(s) on ISPA-R1 (100.100.255.1) <-> HQ1-CORE-R1 (100.100.255.2); gaps between its BGP messages 50.2 to 50.2 s. Any BGP message (KEEPALIVE or UPDATE) restarts the keepalive timer. IOS sends one every third of the hold time (default 60 s of 180) and jitters it a little lower, so 45 to 60 s apart is normal.",
   "evidence": "bgp.type == 4 && ip.src == 100.100.255.1",
   "frames": [],
   "metrics": {}
  },
  {
   "severity": "ok",
   "category": "bgp",
   "title": "HQ1-CORE-R1 heard from every 54.8 s",
   "detail": "3 KEEPALIVE(s) on ISPA-R1 (100.100.255.1) <-> HQ1-CORE-R1 (100.100.255.2); gaps between its BGP messages 54.3 to 55.3 s. Any BGP message (KEEPALIVE or UPDATE) restarts the keepalive timer. IOS sends one every third of the hold time (default 60 s of 180) and jitters it a little lower, so 45 to 60 s apart is normal.",
   "evidence": "bgp.type == 4 && ip.src == 100.100.255.2",
   "frames": [],
   "metrics": {}
  },
  {
   "severity": "ok",
   "category": "bgp",
   "title": "ISPB-R1 heard from every 52.7 s",
   "detail": "5 KEEPALIVE(s) on ISPB-R1 (100.200.255.1) <-> HQ1-CORE-R2 (100.200.255.2); gaps between its BGP messages 30.2 to 58.0 s. Any BGP message (KEEPALIVE or UPDATE) restarts the keepalive timer. IOS sends one every third of the hold time (default 60 s of 180) and jitters it a little lower, so 45 to 60 s apart is normal.",
   "evidence": "bgp.type == 4 && ip.src == 100.200.255.1",
   "frames": [],
   "metrics": {}
  },
  {
   "severity": "ok",
   "category": "bgp",
   "title": "HQ1-CORE-R2 heard from every 55.3 s",
   "detail": "6 KEEPALIVE(s) on ISPB-R1 (100.200.255.1) <-> HQ1-CORE-R2 (100.200.255.2); gaps between its BGP messages 52.2 to 58.4 s. Any BGP message (KEEPALIVE or UPDATE) restarts the keepalive timer. IOS sends one every third of the hold time (default 60 s of 180) and jitters it a little lower, so 45 to 60 s apart is normal.",
   "evidence": "bgp.type == 4 && ip.src == 100.200.255.2",
   "frames": [],
   "metrics": {}
  }
 ],
 "sections": {
  "overview": {
   "summary": "368 frames over 331.0 s (45.2 KB), 14 addresses, 24 TCP connections.",
   "data": {
    "timeline": {
     "x": [
      0.0,
      5.52,
      11.03,
      16.55,
      22.07,
      27.59,
      33.1,
      38.62,
      44.14,
      49.66,
      55.17,
      60.69,
      66.21,
      71.73,
      77.24,
      82.76,
      88.28,
      93.79,
      99.31,
      104.83,
      110.35,
      115.86,
      121.38,
      126.9,
      132.42,
      137.93,
      143.45,
      148.97,
      154.48,
      160.0,
      165.52,
      171.04,
      176.55,
      182.07,
      187.59,
      193.11,
      198.62,
      204.14,
      209.66,
      215.18,
      220.69,
      226.21,
      231.73,
      237.24,
      242.76,
      248.28,
      253.8,
      259.31,
      264.83,
      270.35,
      275.87,
      281.38,
      286.9,
      292.42,
      297.93,
      303.45,
      308.97,
      314.49,
      320.0,
      325.52
     ],
     "all": [
      7,
      5,
      7,
      5,
      8,
      5,
      4,
      2,
      7,
      7,
      7,
      4,
      5,
      7,
      9,
      5,
      4,
      4,
      4,
      9,
      6,
      6,
      6,
      10,
      8,
      4,
      8,
      4,
      10,
      5,
      4,
      9,
      6,
      7,
      4,
      7,
      3,
      7,
      8,
      6,
      8,
      6,
      9,
      4,
      5,
      5,
      5,
      6,
      10,
      4,
      6,
      7,
      8,
      7,
      3,
      6,
      5,
      6,
      10,
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
      1,
      1,
      0,
      1,
      0,
      1,
      1,
      0,
      0,
      1,
      0,
      1,
      1,
      0,
      1,
      1,
      0,
      0,
      1,
      1,
      0,
      1,
      0,
      1,
      0,
      1,
      0,
      1,
      0,
      1,
      1,
      0,
      1,
      0
     ],
     "bin_s": 5.517
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
       257,
       "5.0",
       "330.0"
      ],
      [
       "HQ1-CORE-R2 Et0/2 <-> ISPB-R1 Et0/2",
       "P3-ISPB-link_HQ1-CORE-R2-Et0-2.pcap",
       104,
       "8.6",
       "328.6"
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
       134,
       "36.4%"
      ],
      [
       "LOOP",
       69,
       "18.8%"
      ],
      [
       "TCP",
       63,
       "17.1%"
      ],
      [
       "LLDP",
       33,
       "9.0%"
      ],
      [
       "CDP",
       24,
       "6.5%"
      ],
      [
       "ESP",
       24,
       "6.5%"
      ],
      [
       "BGP",
       19,
       "5.2%"
      ],
      [
       "TLSv1.2",
       2,
       "0.5%"
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
       99,
       "6.4 KB"
      ],
      [
       "100.100.255.2 <-> 100.200.1.1",
       90,
       "6.9 KB"
      ],
      [
       "aa:bb:cc:00:19:20 <-> aa:bb:cc:00:19:20",
       33,
       "1.9 KB"
      ],
      [
       "aa:bb:cc:00:18:20 <-> aa:bb:cc:00:18:20",
       33,
       "1.9 KB"
      ],
      [
       "100.200.255.1 <-> 100.200.255.2",
       26,
       "1.7 KB"
      ],
      [
       "100.200.255.10 <-> 100.200.255.2",
       24,
       "3.8 KB"
      ],
      [
       "01:80:c2:00:00:0e <-> aa:bb:cc:00:12:20",
       11,
       "4.1 KB"
      ],
      [
       "01:80:c2:00:00:0e <-> aa:bb:cc:00:18:20",
       11,
       "4.2 KB"
      ],
      [
       "01:80:c2:00:00:0e <-> aa:bb:cc:00:14:20",
       11,
       "4.1 KB"
      ],
      [
       "01:00:0c:cc:cc:cc <-> aa:bb:cc:00:14:20",
       6,
       "2.4 KB"
      ],
      [
       "01:00:0c:cc:cc:cc <-> aa:bb:cc:00:18:20",
       6,
       "2.4 KB"
      ],
      [
       "01:00:0c:cc:cc:cc <-> aa:bb:cc:00:19:20",
       6,
       "2.4 KB"
      ]
     ]
    }
   ]
  },
  "breakdown": {
   "summary": "13 packets, one of every kind of BGP, ICMP message in the capture, decoded field by field. Click a field to light up its bytes. Rare messages (UPDATE, NOTIFICATION, OPEN) are all shown; routine ones (KEEPALIVE, ping) once per sender.",
   "data": {
    "cards": [
     {
      "n": 1,
      "kind": "ICMP echo request",
      "t": 0.0,
      "clock": "18:10:44.150",
      "from": "HQ1-CORE-R1",
      "to": "ISPA-R1",
      "src": "100.100.255.2",
      "dst": "100.200.1.1",
      "frame": 1,
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
          "text": "Identification: 0x00c2 (194)",
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
          "text": "Header Checksum: 0xf1ca [validation disabled]",
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
          "text": "Checksum: 0xa654 [correct]",
          "pos": 36,
          "size": 2,
          "note": "Checksum over the ICMP message."
         },
         {
          "name": "icmp.ident",
          "text": "Identifier (BE): 169 (0x00a9)",
          "pos": 38,
          "size": 2,
          "note": "Identifier: ties replies to the process that sent the pings (IP SLA uses one per operation)."
         },
         {
          "name": "icmp.ident_le",
          "text": "Identifier (LE): 43264 (0xa900)",
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
            "text": "Data: 000000004c467d7cabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd45ad33ed",
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
      "t": 0.003,
      "clock": "18:10:44.153",
      "from": "ISPA-R1",
      "to": "HQ1-CORE-R1",
      "src": "100.200.1.1",
      "dst": "100.100.255.2",
      "frame": 2,
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
          "text": "Identification: 0x00c2 (194)",
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
          "text": "Header Checksum: 0xf2ca [validation disabled]",
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
          "text": "Checksum: 0xae54 [correct]",
          "pos": 36,
          "size": 2,
          "note": "Checksum over the ICMP message."
         },
         {
          "name": "icmp.ident",
          "text": "Identifier (BE): 169 (0x00a9)",
          "pos": 38,
          "size": 2,
          "note": "Identifier: ties replies to the process that sent the pings (IP SLA uses one per operation)."
         },
         {
          "name": "icmp.ident_le",
          "text": "Identifier (LE): 43264 (0xa900)",
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
            "text": "Data: 000000004c467d7cabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd45ad33ed",
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
      "t": 0.798,
      "clock": "18:10:44.948",
      "from": "HQ1-CORE-R2",
      "to": "ISPB-R1",
      "src": "100.200.255.2",
      "dst": "100.200.255.1",
      "frame": 1,
      "link": "HQ1-CORE-R2 Et0/2 <-> ISPB-R1 Et0/2",
      "len": 73,
      "summary": "Header only: marker, length 19, type 4. Nothing else in it. Its whole job is to reset the peer's hold timer.",
      "layers": [
       {
        "proto": "eth",
        "title": "Ethernet II, Src: aa:bb:cc:00:19:20, Dst: aa:bb:cc:00:14:20",
        "pos": 0,
        "size": 14,
        "note": "Layer 2 frame. Only matters on this one wire: the next hop rewrites both MAC addresses.",
        "fields": [
         {
          "name": "eth.dst",
          "text": "Destination: aa:bb:cc:00:14:20",
          "pos": 0,
          "size": 6,
          "note": "Who on this wire should take the frame."
         },
         {
          "name": "eth.src",
          "text": "Source: aa:bb:cc:00:19:20",
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
        "title": "Internet Protocol Version 4, Src: 100.200.255.2, Dst: 100.200.255.1",
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
          "text": "Identification: 0xb849 (47177)",
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
          "text": "Header Checksum: 0xf91e [validation disabled]",
          "pos": 24,
          "size": 2,
          "note": "Header checksum, recomputed by every router because TTL changes."
         },
         {
          "name": "ip.src",
          "text": "Source Address: 100.200.255.2",
          "pos": 26,
          "size": 4,
          "note": "Original sender."
         },
         {
          "name": "ip.dst",
          "text": "Destination Address: 100.200.255.1",
          "pos": 30,
          "size": 4,
          "note": "Final destination."
         }
        ]
       },
       {
        "proto": "tcp",
        "title": "Transmission Control Protocol, Src Port: 20076, Dst Port: 179, Seq: 1, Ack: 1, Len: 19",
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
          "text": "Window: 15814",
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
          "text": "Checksum: 0x9895 [unverified]",
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
      "t": 11.444,
      "clock": "18:10:55.594",
      "from": "HQ1-CORE-R1",
      "to": "ISPA-R1",
      "src": "100.100.255.2",
      "dst": "100.100.255.1",
      "frame": 6,
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
          "text": "Identification: 0xc983 (51587)",
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
          "text": "Header Checksum: 0xe8ac [validation disabled]",
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
        "title": "Transmission Control Protocol, Src Port: 36654, Dst Port: 179, Seq: 1, Ack: 1, Len: 19",
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
          "text": "Window: 16232",
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
          "text": "Checksum: 0x8a6f [unverified]",
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
      "t": 24.794,
      "clock": "18:11:08.944",
      "from": "ISPB-R1",
      "to": "HQ1-CORE-R2",
      "src": "100.200.255.1",
      "dst": "100.200.255.2",
      "frame": 7,
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
          "text": "Identification: 0x184b (6219)",
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
          "text": "Header Checksum: 0x991d [validation disabled]",
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
          "text": "Window: 15985",
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
          "text": "Checksum: 0x97d7 [unverified]",
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
      "kind": "BGP KEEPALIVE",
      "t": 49.301,
      "clock": "18:11:33.451",
      "from": "ISPA-R1",
      "to": "HQ1-CORE-R1",
      "src": "100.100.255.1",
      "dst": "100.100.255.2",
      "frame": 30,
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
          "text": "Identification: 0xa1d8 (41432)",
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
          "text": "Header Checksum: 0x1058 [validation disabled]",
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
        "title": "Transmission Control Protocol, Src Port: 179, Dst Port: 36654, Seq: 1, Ack: 20, Len: 19",
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
          "text": "Window: 15628",
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
          "text": "Checksum: 0x8cb8 [unverified]",
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
      "n": 7,
      "kind": "ICMP unreachable, admin prohibited",
      "t": 115.003,
      "clock": "18:12:39.152",
      "from": "ISPA-R1",
      "to": "HQ1-CORE-R1",
      "src": "100.100.255.1",
      "dst": "100.100.255.2",
      "frame": 79,
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
          "text": "Identification: 0x4e30 (20016)",
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
          "text": "Header Checksum: 0xa6c7 [validation disabled]",
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
          "text": "Checksum: 0x80d0 [correct]",
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
      "n": 8,
      "kind": "BGP NOTIFICATION",
      "t": 129.114,
      "clock": "18:12:53.264",
      "from": "HQ1-CORE-R1",
      "to": "ISPA-R1",
      "src": "100.100.255.2",
      "dst": "100.100.255.1",
      "frame": 89,
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
          "text": "Identification: 0xc988 (51592)",
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
          "text": "Header Checksum: 0xe8a5 [validation disabled]",
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
        "title": "Transmission Control Protocol, Src Port: 36654, Dst Port: 179, Seq: 58, Ack: 39, Len: 21",
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
          "text": "Sequence Number: 58    (relative sequence number)",
          "pos": 38,
          "size": 4,
          "note": "Sequence number (relative): byte position of this segment's first data byte."
         },
         {
          "name": "tcp.ack",
          "text": "Acknowledgment Number: 39    (relative ack number)",
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
          "text": "Window: 16194",
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
          "text": "Checksum: 0x892c [unverified]",
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
      "n": 9,
      "kind": "TCP FIN (port 179)",
      "t": 129.115,
      "clock": "18:12:53.265",
      "from": "HQ1-CORE-R1",
      "to": "ISPA-R1",
      "src": "100.100.255.2",
      "dst": "100.100.255.1",
      "frame": 90,
      "link": "HQ1-CORE-R1 Et0/2 <-> ISPA-R1 Et0/2",
      "len": 60,
      "summary": "Clean TCP close right after a NOTIFICATION.",
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
         },
         {
          "name": "eth.padding",
          "text": "Padding: 000000000000",
          "pos": 54,
          "size": 6
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
          "text": "Total Length: 40",
          "pos": 16,
          "size": 2,
          "note": "Total IP packet length (header + payload)."
         },
         {
          "name": "ip.id",
          "text": "Identification: 0xc989 (51593)",
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
          "text": "Header Checksum: 0xe8b9 [validation disabled]",
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
        "title": "Transmission Control Protocol, Src Port: 36654, Dst Port: 179, Seq: 79, Ack: 39, Len: 0",
        "pos": 34,
        "size": 20,
        "note": "Transport. BGP rides TCP port 179, so every BGP message is acknowledged, ordered and resent by TCP, not by BGP.",
        "fields": [
         {
          "name": "tcp.len",
          "text": "TCP Segment Len: 0",
          "pos": 34,
          "size": 0,
          "note": "Payload bytes in this segment. 0 = a pure ACK or control segment."
         },
         {
          "name": "tcp.seq",
          "text": "Sequence Number: 79    (relative sequence number)",
          "pos": 38,
          "size": 4,
          "note": "Sequence number (relative): byte position of this segment's first data byte."
         },
         {
          "name": "tcp.ack",
          "text": "Acknowledgment Number: 39    (relative ack number)",
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
          "text": "Flags: 0x019 (FIN, PSH, ACK)",
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
            "text": ".... .... ...1 = Fin: Set",
            "pos": 47,
            "size": 1,
            "note": "FIN is set: closing cleanly."
           },
           {
            "name": "tcp.flags.str",
            "text": "TCP Flags: \u00b7\u00b7\u00b7\u00b7\u00b7\u00b7\u00b7AP\u00b7\u00b7F",
            "pos": 46,
            "size": 2
           }
          ]
         },
         {
          "name": "tcp.window_size_value",
          "text": "Window: 16194",
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
          "text": "Checksum: 0x8e46 [unverified]",
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
       }
      ],
      "focus": "tcp"
     },
     {
      "n": 10,
      "kind": "BGP UPDATE",
      "t": 129.123,
      "clock": "18:12:53.273",
      "from": "ISPB-R1",
      "to": "HQ1-CORE-R2",
      "src": "100.200.255.1",
      "dst": "100.200.255.2",
      "frame": 41,
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
          "text": "Identification: 0x184f (6223)",
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
          "text": "Header Checksum: 0x98f4 [validation disabled]",
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
        "title": "Transmission Control Protocol, Src Port: 179, Dst Port: 20076, Seq: 39, Ack: 39, Len: 56",
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
          "text": "Sequence Number: 39    (relative sequence number)",
          "pos": 38,
          "size": 4,
          "note": "Sequence number (relative): byte position of this segment's first data byte."
         },
         {
          "name": "tcp.ack",
          "text": "Acknowledgment Number: 39    (relative ack number)",
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
          "text": "Window: 15947",
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
          "text": "Checksum: 0x4439 [unverified]",
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
      "n": 11,
      "kind": "TCP SYN (port 179)",
      "t": 136.421,
      "clock": "18:13:00.571",
      "from": "ISPA-R1",
      "to": "HQ1-CORE-R1",
      "src": "100.100.255.1",
      "dst": "100.100.255.2",
      "frame": 101,
      "link": "HQ1-CORE-R1 Et0/2 <-> ISPA-R1 Et0/2",
      "len": 66,
      "summary": "A router opening (or re-opening) the BGP transport.",
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
          "text": "Total Length: 52",
          "pos": 16,
          "size": 2,
          "note": "Total IP packet length (header + payload)."
         },
         {
          "name": "ip.id",
          "text": "Identification: 0xe028 (57384)",
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
          "text": "Header Checksum: 0xd20e [validation disabled]",
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
        "title": "Transmission Control Protocol, Src Port: 31178, Dst Port: 179, Seq: 0, Len: 0",
        "pos": 34,
        "size": 32,
        "note": "Transport. BGP rides TCP port 179, so every BGP message is acknowledged, ordered and resent by TCP, not by BGP.",
        "fields": [
         {
          "name": "tcp.len",
          "text": "TCP Segment Len: 0",
          "pos": 34,
          "size": 0,
          "note": "Payload bytes in this segment. 0 = a pure ACK or control segment."
         },
         {
          "name": "tcp.seq",
          "text": "Sequence Number: 0    (relative sequence number)",
          "pos": 38,
          "size": 4,
          "note": "Sequence number (relative): byte position of this segment's first data byte."
         },
         {
          "name": "tcp.ack",
          "text": "Acknowledgment Number: 0",
          "pos": 42,
          "size": 4,
          "note": "Acknowledgement: the next byte this side expects from the other."
         },
         {
          "name": "tcp.hdr_len",
          "text": "1000 .... = Header Length: 32 bytes (8)",
          "pos": 46,
          "size": 1,
          "note": "TCP header length. 20 = no options; 32 = timestamps; larger on a SYN with MSS / window scale / SACK."
         },
         {
          "name": "tcp.flags",
          "text": "Flags: 0x002 (SYN)",
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
            "text": ".... ...0 .... = Acknowledgment: Not set",
            "pos": 47,
            "size": 1,
            "note": "ACK: the acknowledgement number is valid."
           },
           {
            "name": "tcp.flags.push",
            "text": ".... .... 0... = Push: Not set",
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
            "text": ".... .... ..1. = Syn: Set",
            "pos": 47,
            "size": 1,
            "note": "SYN is set: opening a connection."
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
            "text": "TCP Flags: \u00b7\u00b7\u00b7\u00b7\u00b7\u00b7\u00b7\u00b7\u00b7\u00b7S\u00b7",
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
          "name": "tcp.checksum",
          "text": "Checksum: 0x868a [unverified]",
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
          "name": "tcp.options",
          "text": "Options: (12 bytes), Maximum segment size, SACK permitted, No-Operation (NOP), No-Operation (NOP), Window scale, End of Option List (EOL)",
          "pos": 54,
          "size": 12,
          "note": "Extras. On a SYN: MSS (largest segment), window scale, SACK permitted, timestamps.",
          "children": [
           {
            "name": "tcp.options.mss",
            "text": "TCP Option - Maximum segment size: 1460 bytes",
            "pos": 54,
            "size": 4,
            "children": [
             {
              "name": "tcp.option_kind",
              "text": "Kind: Maximum Segment Size (2)",
              "pos": 54,
              "size": 1
             },
             {
              "name": "tcp.option_len",
              "text": "Length: 4",
              "pos": 55,
              "size": 1
             },
             {
              "name": "tcp.options.mss_val",
              "text": "MSS Value: 1460",
              "pos": 56,
              "size": 2,
              "note": "Maximum segment size this side will accept."
             }
            ]
           },
           {
            "name": "tcp.options.sack_perm",
            "text": "TCP Option - SACK permitted",
            "pos": 58,
            "size": 2,
            "children": [
             {
              "name": "tcp.option_kind",
              "text": "Kind: SACK Permitted (4)",
              "pos": 58,
              "size": 1
             },
             {
              "name": "tcp.option_len",
              "text": "Length: 2",
              "pos": 59,
              "size": 1
             }
            ]
           },
           {
            "name": "tcp.options.nop",
            "text": "TCP Option - No-Operation (NOP)",
            "pos": 60,
            "size": 1,
            "children": [
             {
              "name": "tcp.option_kind",
              "text": "Kind: No-Operation (1)",
              "pos": 60,
              "size": 1
             }
            ]
           },
           {
            "name": "tcp.options.nop",
            "text": "TCP Option - No-Operation (NOP)",
            "pos": 61,
            "size": 1,
            "children": [
             {
              "name": "tcp.option_kind",
              "text": "Kind: No-Operation (1)",
              "pos": 61,
              "size": 1
             }
            ]
           },
           {
            "name": "tcp.options.wscale",
            "text": "TCP Option - Window scale: 0 (multiply by 1)",
            "pos": 62,
            "size": 3,
            "children": [
             {
              "name": "tcp.option_kind",
              "text": "Kind: Window Scale (3)",
              "pos": 62,
              "size": 1
             },
             {
              "name": "tcp.option_len",
              "text": "Length: 3",
              "pos": 63,
              "size": 1
             },
             {
              "name": "tcp.options.wscale.shift",
              "text": "Shift count: 0",
              "pos": 64,
              "size": 1
             },
             {
              "name": "tcp.options.wscale.multiplier",
              "text": "Multiplier: 1",
              "pos": 64,
              "size": 1
             }
            ]
           },
           {
            "name": "tcp.options.eol",
            "text": "TCP Option - End of Option List (EOL)",
            "pos": 65,
            "size": 1,
            "children": [
             {
              "name": "tcp.option_kind",
              "text": "Kind: End of Option List (0)",
              "pos": 65,
              "size": 1
             }
            ]
           }
          ]
         },
         {
          "name": "",
          "text": "Timestamps",
          "pos": 34,
          "size": 0
         }
        ]
       }
      ],
      "focus": "tcp"
     },
     {
      "n": 12,
      "kind": "TCP RST (port 179)",
      "t": 136.423,
      "clock": "18:13:00.572",
      "from": "HQ1-CORE-R1",
      "to": "ISPA-R1",
      "src": "100.100.255.2",
      "dst": "100.100.255.1",
      "frame": 102,
      "link": "HQ1-CORE-R1 Et0/2 <-> ISPA-R1 Et0/2",
      "len": 60,
      "summary": "The other router refusing the connection.",
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
         },
         {
          "name": "eth.padding",
          "text": "Padding: 000000000000",
          "pos": 54,
          "size": 6
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
          "text": "Total Length: 40",
          "pos": 16,
          "size": 2,
          "note": "Total IP packet length (header + payload)."
         },
         {
          "name": "ip.id",
          "text": "Identification: 0x4ba5 (19365)",
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
          "text": "Protocol: TCP (6)",
          "pos": 23,
          "size": 1,
          "note": "What the payload is: 1 ICMP, 6 TCP, 17 UDP, 50 ESP, 89 OSPF, 88 EIGRP."
         },
         {
          "name": "ip.checksum",
          "text": "Header Checksum: 0xa95d [validation disabled]",
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
        "title": "Transmission Control Protocol, Src Port: 179, Dst Port: 31178, Seq: 1, Ack: 1, Len: 0",
        "pos": 34,
        "size": 20,
        "note": "Transport. BGP rides TCP port 179, so every BGP message is acknowledged, ordered and resent by TCP, not by BGP.",
        "fields": [
         {
          "name": "tcp.len",
          "text": "TCP Segment Len: 0",
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
          "text": "Flags: 0x014 (RST, ACK)",
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
            "text": ".... .... 0... = Push: Not set",
            "pos": 47,
            "size": 1,
            "note": "PSH: hand the data to the application now."
           },
           {
            "name": "tcp.flags.reset",
            "text": ".... .... .1.. = Reset: Set",
            "pos": 47,
            "size": 1,
            "note": "RST is set: the connection is refused or aborted."
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
            "text": "TCP Flags: \u00b7\u00b7\u00b7\u00b7\u00b7\u00b7\u00b7A\u00b7R\u00b7\u00b7",
            "pos": 46,
            "size": 2
           }
          ]
         },
         {
          "name": "tcp.window_size_value",
          "text": "Window: 0",
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
          "text": "Checksum: 0x0642 [unverified]",
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
       }
      ],
      "focus": "tcp"
     },
     {
      "n": 13,
      "kind": "BGP UPDATE",
      "t": 159.301,
      "clock": "18:13:23.451",
      "from": "ISPB-R1",
      "to": "HQ1-CORE-R2",
      "src": "100.200.255.1",
      "dst": "100.200.255.2",
      "frame": 50,
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
          "text": "Identification: 0x1850 (6224)",
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
          "text": "Header Checksum: 0x990f [validation disabled]",
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
        "title": "Transmission Control Protocol, Src Port: 179, Dst Port: 20076, Seq: 95, Ack: 39, Len: 28",
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
          "text": "Sequence Number: 95    (relative sequence number)",
          "pos": 38,
          "size": 4,
          "note": "Sequence number (relative): byte position of this segment's first data byte."
         },
         {
          "name": "tcp.ack",
          "text": "Acknowledgment Number: 39    (relative ack number)",
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
          "text": "Window: 15947",
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
          "text": "Checksum: 0x6a1a [unverified]",
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
       "18:10:44.150",
       "ICMP echo request",
       "HQ1-CORE-R1 -> ISPA-R1",
       78,
       1
      ],
      [
       2,
       "18:10:44.153",
       "ICMP echo reply",
       "ISPA-R1 -> HQ1-CORE-R1",
       78,
       2
      ],
      [
       3,
       "18:10:44.948",
       "BGP KEEPALIVE",
       "HQ1-CORE-R2 -> ISPB-R1",
       73,
       1
      ],
      [
       4,
       "18:10:55.594",
       "BGP KEEPALIVE",
       "HQ1-CORE-R1 -> ISPA-R1",
       73,
       6
      ],
      [
       5,
       "18:11:08.944",
       "BGP KEEPALIVE",
       "ISPB-R1 -> HQ1-CORE-R2",
       73,
       7
      ],
      [
       6,
       "18:11:33.451",
       "BGP KEEPALIVE",
       "ISPA-R1 -> HQ1-CORE-R1",
       73,
       30
      ],
      [
       7,
       "18:12:39.152",
       "ICMP unreachable, admin prohibited",
       "ISPA-R1 -> HQ1-CORE-R1",
       70,
       79
      ],
      [
       8,
       "18:12:53.264",
       "BGP NOTIFICATION",
       "HQ1-CORE-R1 -> ISPA-R1",
       75,
       89
      ],
      [
       9,
       "18:12:53.265",
       "TCP FIN (port 179)",
       "HQ1-CORE-R1 -> ISPA-R1",
       60,
       90
      ],
      [
       10,
       "18:12:53.273",
       "BGP UPDATE",
       "ISPB-R1 -> HQ1-CORE-R2",
       110,
       41
      ],
      [
       11,
       "18:13:00.571",
       "TCP SYN (port 179)",
       "ISPA-R1 -> HQ1-CORE-R1",
       66,
       101
      ],
      [
       12,
       "18:13:00.572",
       "TCP RST (port 179)",
       "HQ1-CORE-R1 -> ISPA-R1",
       60,
       102
      ],
      [
       13,
       "18:13:23.451",
       "BGP UPDATE",
       "ISPB-R1 -> HQ1-CORE-R2",
       82,
       50
      ]
     ]
    }
   ]
  },
  "bgp": {
   "summary": "2 BGP session(s), 19 BGP message(s): 16 KEEPALIVE, 2 UPDATE, 1 NOTIFICATION.",
   "data": {
    "names": {
     "100.100.255.2": "HQ1-CORE-R1",
     "100.200.1.1": "ISPA-R1",
     "100.200.255.2": "HQ1-CORE-R2",
     "100.200.255.1": "ISPB-R1",
     "100.100.255.1": "ISPA-R1",
     "100.200.255.10": "ISPB-R1",
     "34.107.243.93": "ISPA-R1",
     "198.51.100.10": "HQ1-CORE-R1"
    },
    "sessions": [
     {
      "pair": "100.100.255.1 <-> 100.100.255.2",
      "a": "100.100.255.1",
      "b": "100.100.255.2",
      "a_name": "ISPA-R1 (100.100.255.1)",
      "b_name": "HQ1-CORE-R1 (100.100.255.2)",
      "counts": {
       "KEEPALIVE": 5,
       "NOTIFICATION": 1
      },
      "keepalive": {
       "100.100.255.1": {
        "n": 2,
        "msgs": 2,
        "median": 50.1805,
        "min": 50.1805,
        "max": 50.1805
       },
       "100.100.255.2": {
        "n": 3,
        "msgs": 3,
        "median": 54.8036,
        "min": 54.2781,
        "max": 55.3292
       }
      },
      "opens": [],
      "notifications": [
       {
        "t": 129.1142,
        "clock": "18:12:53.264",
        "from": "HQ1-CORE-R1 (100.100.255.2)",
        "to": "ISPA-R1 (100.100.255.1)",
        "reason": "Cease / Administrative shutdown",
        "no": 89
       }
      ],
      "updates": [],
      "up_at_start": true,
      "fin": [
       {
        "clock": "18:12:53.265",
        "from": "HQ1-CORE-R1 (100.100.255.2)",
        "t": 129.1153
       },
       {
        "clock": "18:12:53.267",
        "from": "ISPA-R1 (100.100.255.1)",
        "t": 129.1167
       }
      ],
      "connects": [
       {
        "t": 136.4214,
        "clock": "18:13:00.571",
        "from": "ISPA-R1 (100.100.255.1)",
        "to": "HQ1-CORE-R1 (100.100.255.2)",
        "refused": true,
        "no": 101
       },
       {
        "t": 145.6448,
        "clock": "18:13:09.795",
        "from": "ISPA-R1 (100.100.255.1)",
        "to": "HQ1-CORE-R1 (100.100.255.2)",
        "refused": true,
        "no": 109
       },
       {
        "t": 151.7836,
        "clock": "18:13:15.933",
        "from": "ISPA-R1 (100.100.255.1)",
        "to": "HQ1-CORE-R1 (100.100.255.2)",
        "refused": true,
        "no": 114
       },
       {
        "t": 165.0971,
        "clock": "18:13:29.247",
        "from": "ISPA-R1 (100.100.255.1)",
        "to": "HQ1-CORE-R1 (100.100.255.2)",
        "refused": true,
        "no": 123
       },
       {
        "t": 172.2678,
        "clock": "18:13:36.418",
        "from": "ISPA-R1 (100.100.255.1)",
        "to": "HQ1-CORE-R1 (100.100.255.2)",
        "refused": true,
        "no": 128
       },
       {
        "t": 180.4617,
        "clock": "18:13:44.612",
        "from": "ISPA-R1 (100.100.255.1)",
        "to": "HQ1-CORE-R1 (100.100.255.2)",
        "refused": true,
        "no": 137
       },
       {
        "t": 194.7982,
        "clock": "18:13:58.948",
        "from": "ISPA-R1 (100.100.255.1)",
        "to": "HQ1-CORE-R1 (100.100.255.2)",
        "refused": true,
        "no": 146
       },
       {
        "t": 205.0381,
        "clock": "18:14:09.188",
        "from": "ISPA-R1 (100.100.255.1)",
        "to": "HQ1-CORE-R1 (100.100.255.2)",
        "refused": true,
        "no": 157
       },
       {
        "t": 212.2067,
        "clock": "18:14:16.357",
        "from": "ISPA-R1 (100.100.255.1)",
        "to": "HQ1-CORE-R1 (100.100.255.2)",
        "refused": true,
        "no": 162
       },
       {
        "t": 221.4247,
        "clock": "18:14:25.575",
        "from": "ISPA-R1 (100.100.255.1)",
        "to": "HQ1-CORE-R1 (100.100.255.2)",
        "refused": true,
        "no": 169
       },
       {
        "t": 228.5947,
        "clock": "18:14:32.745",
        "from": "ISPA-R1 (100.100.255.1)",
        "to": "HQ1-CORE-R1 (100.100.255.2)",
        "refused": true,
        "no": 174
       },
       {
        "t": 242.9319,
        "clock": "18:14:47.082",
        "from": "ISPA-R1 (100.100.255.1)",
        "to": "HQ1-CORE-R1 (100.100.255.2)",
        "refused": true,
        "no": 187
       },
       {
        "t": 253.1732,
        "clock": "18:14:57.323",
        "from": "ISPA-R1 (100.100.255.1)",
        "to": "HQ1-CORE-R1 (100.100.255.2)",
        "refused": true,
        "no": 194
       },
       {
        "t": 262.3929,
        "clock": "18:15:06.543",
        "from": "ISPA-R1 (100.100.255.1)",
        "to": "HQ1-CORE-R1 (100.100.255.2)",
        "refused": true,
        "no": 201
       },
       {
        "t": 274.6829,
        "clock": "18:15:18.833",
        "from": "ISPA-R1 (100.100.255.1)",
        "to": "HQ1-CORE-R1 (100.100.255.2)",
        "refused": true,
        "no": 210
       },
       {
        "t": 283.9021,
        "clock": "18:15:28.052",
        "from": "ISPA-R1 (100.100.255.1)",
        "to": "HQ1-CORE-R1 (100.100.255.2)",
        "refused": true,
        "no": 217
       },
       {
        "t": 294.1434,
        "clock": "18:15:38.293",
        "from": "ISPA-R1 (100.100.255.1)",
        "to": "HQ1-CORE-R1 (100.100.255.2)",
        "refused": true,
        "no": 227
       },
       {
        "t": 305.4087,
        "clock": "18:15:49.559",
        "from": "ISPA-R1 (100.100.255.1)",
        "to": "HQ1-CORE-R1 (100.100.255.2)",
        "refused": true,
        "no": 237
       },
       {
        "t": 313.6019,
        "clock": "18:15:57.752",
        "from": "ISPA-R1 (100.100.255.1)",
        "to": "HQ1-CORE-R1 (100.100.255.2)",
        "refused": true,
        "no": 242
       },
       {
        "t": 322.821,
        "clock": "18:16:06.971",
        "from": "ISPA-R1 (100.100.255.1)",
        "to": "HQ1-CORE-R1 (100.100.255.2)",
        "refused": true,
        "no": 250
       }
      ]
     },
     {
      "pair": "100.200.255.1 <-> 100.200.255.2",
      "a": "100.200.255.1",
      "b": "100.200.255.2",
      "a_name": "ISPB-R1 (100.200.255.1)",
      "b_name": "HQ1-CORE-R2 (100.200.255.2)",
      "counts": {
       "KEEPALIVE": 11,
       "UPDATE": 2
      },
      "keepalive": {
       "100.200.255.1": {
        "n": 5,
        "msgs": 7,
        "median": 52.7409,
        "min": 30.1784,
        "max": 58.0299
       },
       "100.200.255.2": {
        "n": 6,
        "msgs": 6,
        "median": 55.3078,
        "min": 52.2327,
        "max": 58.3772
       }
      },
      "opens": [],
      "notifications": [],
      "updates": [
       {
        "t": 129.123,
        "clock": "18:12:53.273",
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
        "no": 41
       },
       {
        "t": 159.3015,
        "clock": "18:13:23.451",
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
        "no": 50
       }
      ],
      "up_at_start": true,
      "fin": [],
      "connects": []
     }
    ],
    "messages": [
     {
      "no": 6,
      "epoch": 1795479055.5946,
      "src": "100.100.255.2",
      "dst": "100.100.255.1",
      "sport": "36654",
      "dport": "179",
      "type": "KEEPALIVE",
      "type_n": 4,
      "blen": "19",
      "major": null,
      "minor": null,
      "reason": null,
      "nlri": null,
      "withdrawn": null,
      "as_path": null,
      "next_hop": null,
      "local_pref": null,
      "med": null,
      "origin": null,
      "t": 11.4443,
      "pair": "100.100.255.1 <-> 100.100.255.2"
     },
     {
      "no": 30,
      "epoch": 1795479093.4515,
      "src": "100.100.255.1",
      "dst": "100.100.255.2",
      "sport": "179",
      "dport": "36654",
      "type": "KEEPALIVE",
      "type_n": 4,
      "blen": "19",
      "major": null,
      "minor": null,
      "reason": null,
      "nlri": null,
      "withdrawn": null,
      "as_path": null,
      "next_hop": null,
      "local_pref": null,
      "med": null,
      "origin": null,
      "t": 49.3011,
      "pair": "100.100.255.1 <-> 100.100.255.2"
     },
     {
      "no": 44,
      "epoch": 1795479110.9238,
      "src": "100.100.255.2",
      "dst": "100.100.255.1",
      "sport": "36654",
      "dport": "179",
      "type": "KEEPALIVE",
      "type_n": 4,
      "blen": "19",
      "major": null,
      "minor": null,
      "reason": null,
      "nlri": null,
      "withdrawn": null,
      "as_path": null,
      "next_hop": null,
      "local_pref": null,
      "med": null,
      "origin": null,
      "t": 66.7734,
      "pair": "100.100.255.1 <-> 100.100.255.2"
     },
     {
      "no": 68,
      "epoch": 1795479143.632,
      "src": "100.100.255.1",
      "dst": "100.100.255.2",
      "sport": "179",
      "dport": "36654",
      "type": "KEEPALIVE",
      "type_n": 4,
      "blen": "19",
      "major": null,
      "minor": null,
      "reason": null,
      "nlri": null,
      "withdrawn": null,
      "as_path": null,
      "next_hop": null,
      "local_pref": null,
      "med": null,
      "origin": null,
      "t": 99.4816,
      "pair": "100.100.255.1 <-> 100.100.255.2"
     },
     {
      "no": 84,
      "epoch": 1795479165.2019,
      "src": "100.100.255.2",
      "dst": "100.100.255.1",
      "sport": "36654",
      "dport": "179",
      "type": "KEEPALIVE",
      "type_n": 4,
      "blen": "19",
      "major": null,
      "minor": null,
      "reason": null,
      "nlri": null,
      "withdrawn": null,
      "as_path": null,
      "next_hop": null,
      "local_pref": null,
      "med": null,
      "origin": null,
      "t": 121.0515,
      "pair": "100.100.255.1 <-> 100.100.255.2"
     },
     {
      "no": 89,
      "epoch": 1795479173.2646,
      "src": "100.100.255.2",
      "dst": "100.100.255.1",
      "sport": "36654",
      "dport": "179",
      "type": "NOTIFICATION",
      "type_n": 3,
      "blen": "21",
      "major": 6.0,
      "minor": 2.0,
      "reason": "Cease / Administrative shutdown",
      "nlri": null,
      "withdrawn": null,
      "as_path": null,
      "next_hop": null,
      "local_pref": null,
      "med": null,
      "origin": null,
      "t": 129.1142,
      "pair": "100.100.255.1 <-> 100.100.255.2"
     },
     {
      "no": 7,
      "epoch": 1795479068.9448,
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
      "nlri": null,
      "withdrawn": null,
      "as_path": null,
      "next_hop": null,
      "local_pref": null,
      "med": null,
      "origin": null,
      "t": 24.7944,
      "pair": "100.200.255.1 <-> 100.200.255.2"
     },
     {
      "no": 16,
      "epoch": 1795479100.2566,
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
      "nlri": null,
      "withdrawn": null,
      "as_path": null,
      "next_hop": null,
      "local_pref": null,
      "med": null,
      "origin": null,
      "t": 56.1063,
      "pair": "100.200.255.1 <-> 100.200.255.2"
     },
     {
      "no": 24,
      "epoch": 1795479122.1976,
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
      "nlri": null,
      "withdrawn": null,
      "as_path": null,
      "next_hop": null,
      "local_pref": null,
      "med": null,
      "origin": null,
      "t": 78.0472,
      "pair": "100.200.255.1 <-> 100.200.255.2"
     },
     {
      "no": 34,
      "epoch": 1795479157.6053,
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
      "nlri": null,
      "withdrawn": null,
      "as_path": null,
      "next_hop": null,
      "local_pref": null,
      "med": null,
      "origin": null,
      "t": 113.4549,
      "pair": "100.200.255.1 <-> 100.200.255.2"
     },
     {
      "no": 41,
      "epoch": 1795479173.2734,
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
      "nlri": [
       "198.51.100.0/25"
      ],
      "withdrawn": [],
      "as_path": "65200 65100 65001",
      "next_hop": "100.200.255.1",
      "local_pref": "",
      "med": "",
      "origin": "IGP",
      "t": 129.123,
      "pair": "100.200.255.1 <-> 100.200.255.2"
     },
     {
      "no": 50,
      "epoch": 1795479203.4518,
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
      "nlri": [],
      "withdrawn": [
       "198.51.100.0/25"
      ],
      "as_path": "",
      "next_hop": "",
      "local_pref": "",
      "med": "",
      "origin": "",
      "t": 159.3015,
      "pair": "100.200.255.1 <-> 100.200.255.2"
     },
     {
      "no": 54,
      "epoch": 1795479215.9825,
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
      "nlri": null,
      "withdrawn": null,
      "as_path": null,
      "next_hop": null,
      "local_pref": null,
      "med": null,
      "origin": null,
      "t": 171.8322,
      "pair": "100.200.255.1 <-> 100.200.255.2"
     },
     {
      "no": 67,
      "epoch": 1795479261.4817,
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
      "nlri": null,
      "withdrawn": null,
      "as_path": null,
      "next_hop": null,
      "local_pref": null,
      "med": null,
      "origin": null,
      "t": 217.3314,
      "pair": "100.200.255.1 <-> 100.200.255.2"
     },
     {
      "no": 70,
      "epoch": 1795479268.2152,
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
      "nlri": null,
      "withdrawn": null,
      "as_path": null,
      "next_hop": null,
      "local_pref": null,
      "med": null,
      "origin": null,
      "t": 224.0649,
      "pair": "100.200.255.1 <-> 100.200.255.2"
     },
     {
      "no": 85,
      "epoch": 1795479313.7107,
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
      "nlri": null,
      "withdrawn": null,
      "as_path": null,
      "next_hop": null,
      "local_pref": null,
      "med": null,
      "origin": null,
      "t": 269.5603,
      "pair": "100.200.255.1 <-> 100.200.255.2"
     },
     {
      "no": 87,
      "epoch": 1795479322.4952,
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
      "nlri": null,
      "withdrawn": null,
      "as_path": null,
      "next_hop": null,
      "local_pref": null,
      "med": null,
      "origin": null,
      "t": 278.3448,
      "pair": "100.200.255.1 <-> 100.200.255.2"
     },
     {
      "no": 102,
      "epoch": 1795479369.0143,
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
      "nlri": null,
      "withdrawn": null,
      "as_path": null,
      "next_hop": null,
      "local_pref": null,
      "med": null,
      "origin": null,
      "t": 324.8639,
      "pair": "100.200.255.1 <-> 100.200.255.2"
     },
     {
      "no": 1,
      "epoch": 1795479044.9488,
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
      "nlri": null,
      "withdrawn": null,
      "as_path": null,
      "next_hop": null,
      "local_pref": null,
      "med": null,
      "origin": null,
      "t": 0.7985,
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
       "yes, no OPEN seen",
       "KEEPALIVE 5, NOTIFICATION 1",
       "ISPA-R1 every 50.2 s (50-50 s); HQ1-CORE-R1 every 54.8 s (54-55 s)",
       "closed by HQ1-CORE-R1 (100.100.255.2) at 18:12:53.264: Cease / Administrative shutdown",
       "20 refused"
      ],
      [
       "ISPB-R1 (100.200.255.1) <-> HQ1-CORE-R2 (100.200.255.2)",
       "yes, no OPEN seen",
       "KEEPALIVE 11, UPDATE 2",
       "ISPB-R1 every 52.7 s (30-58 s); HQ1-CORE-R2 every 55.3 s (52-58 s)",
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
       "18:12:53.273",
       "ISPB-R1 (100.200.255.1) -> HQ1-CORE-R2 (100.200.255.2)",
       "198.51.100.0/25",
       "-",
       "65200 65100 65001",
       "100.200.255.1",
       "origin IGP",
       41
      ],
      [
       "18:13:23.451",
       "ISPB-R1 (100.200.255.1) -> HQ1-CORE-R2 (100.200.255.2)",
       "-",
       "198.51.100.0/25",
       "-",
       "-",
       "-",
       50
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
       "18:12:53.264",
       "HQ1-CORE-R1 (100.100.255.2) -> ISPA-R1 (100.100.255.1)",
       "Cease / Administrative shutdown",
       89
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
       "18:10:44.948",
       "0.80",
       "HQ1-CORE-R2 (100.200.255.2) -> ISPB-R1 (100.200.255.1)",
       "KEEPALIVE",
       "19",
       1
      ],
      [
       "18:10:55.594",
       "11.44",
       "HQ1-CORE-R1 (100.100.255.2) -> ISPA-R1 (100.100.255.1)",
       "KEEPALIVE",
       "19",
       6
      ],
      [
       "18:11:08.944",
       "24.79",
       "ISPB-R1 (100.200.255.1) -> HQ1-CORE-R2 (100.200.255.2)",
       "KEEPALIVE",
       "19",
       7
      ],
      [
       "18:11:33.451",
       "49.30",
       "ISPA-R1 (100.100.255.1) -> HQ1-CORE-R1 (100.100.255.2)",
       "KEEPALIVE",
       "19",
       30
      ],
      [
       "18:11:40.256",
       "56.11",
       "HQ1-CORE-R2 (100.200.255.2) -> ISPB-R1 (100.200.255.1)",
       "KEEPALIVE",
       "19",
       16
      ],
      [
       "18:11:50.923",
       "66.77",
       "HQ1-CORE-R1 (100.100.255.2) -> ISPA-R1 (100.100.255.1)",
       "KEEPALIVE",
       "19",
       44
      ],
      [
       "18:12:02.197",
       "78.05",
       "ISPB-R1 (100.200.255.1) -> HQ1-CORE-R2 (100.200.255.2)",
       "KEEPALIVE",
       "19",
       24
      ],
      [
       "18:12:23.631",
       "99.48",
       "ISPA-R1 (100.100.255.1) -> HQ1-CORE-R1 (100.100.255.2)",
       "KEEPALIVE",
       "19",
       68
      ],
      [
       "18:12:37.605",
       "113.45",
       "HQ1-CORE-R2 (100.200.255.2) -> ISPB-R1 (100.200.255.1)",
       "KEEPALIVE",
       "19",
       34
      ],
      [
       "18:12:45.201",
       "121.05",
       "HQ1-CORE-R1 (100.100.255.2) -> ISPA-R1 (100.100.255.1)",
       "KEEPALIVE",
       "19",
       84
      ],
      [
       "18:12:53.264",
       "129.11",
       "HQ1-CORE-R1 (100.100.255.2) -> ISPA-R1 (100.100.255.1)",
       "NOTIFICATION: Cease / Administrative shutdown",
       "21",
       89
      ],
      [
       "18:12:53.273",
       "129.12",
       "ISPB-R1 (100.200.255.1) -> HQ1-CORE-R2 (100.200.255.2)",
       "UPDATE: +1 / -0 prefix(es)",
       "56",
       41
      ],
      [
       "18:13:23.451",
       "159.30",
       "ISPB-R1 (100.200.255.1) -> HQ1-CORE-R2 (100.200.255.2)",
       "UPDATE: +0 / -1 prefix(es)",
       "28",
       50
      ],
      [
       "18:13:35.982",
       "171.83",
       "HQ1-CORE-R2 (100.200.255.2) -> ISPB-R1 (100.200.255.1)",
       "KEEPALIVE",
       "19",
       54
      ],
      [
       "18:14:21.481",
       "217.33",
       "ISPB-R1 (100.200.255.1) -> HQ1-CORE-R2 (100.200.255.2)",
       "KEEPALIVE",
       "19",
       67
      ],
      [
       "18:14:28.215",
       "224.06",
       "HQ1-CORE-R2 (100.200.255.2) -> ISPB-R1 (100.200.255.1)",
       "KEEPALIVE",
       "19",
       70
      ],
      [
       "18:15:13.710",
       "269.56",
       "ISPB-R1 (100.200.255.1) -> HQ1-CORE-R2 (100.200.255.2)",
       "KEEPALIVE",
       "19",
       85
      ],
      [
       "18:15:22.495",
       "278.34",
       "HQ1-CORE-R2 (100.200.255.2) -> ISPB-R1 (100.200.255.1)",
       "KEEPALIVE",
       "19",
       87
      ],
      [
       "18:16:09.014",
       "324.86",
       "ISPB-R1 (100.200.255.1) -> HQ1-CORE-R2 (100.200.255.2)",
       "KEEPALIVE",
       "19",
       102
      ]
     ]
    }
   ]
  },
  "probes": {
   "summary": "100.100.255.2 -> 100.200.1.1 every 5.0 s: 23 ok, 44 failed.",
   "data": {
    "series": [
     {
      "src": "100.100.255.2",
      "dst": "100.200.1.1",
      "interval": 5.0001,
      "transitions": [
       {
        "t": 115.0005,
        "clock": "18:12:39.150",
        "to": "failing",
        "how": "ICMP 3/13 communication administratively prohibited (ACL)",
        "last_ok_clock": "18:12:34.150",
        "no": 78
       }
      ],
      "ok": 23,
      "fail": 44,
      "rtt_ms": 2.465,
      "reaction": {
       "delay_s": 14.1137,
       "what": "BGP NOTIFICATION 100.100.255.2 -> 100.100.255.1",
       "clock": "18:12:53.264"
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
       67,
       23,
       44,
       "2.5 ms",
       "18:12:39.150 failing (ICMP 3/13 communication administratively prohibited (ACL))"
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
      "frames": 33,
      "names": [
       "HQ1-CORE-R1.almnjoy.lab",
       "ISPA-R1.almnjoy.lab",
       "ISPB-R1.almnjoy.lab"
      ]
     },
     {
      "protocol": "CDP",
      "frames": 24,
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
       33,
       "HQ1-CORE-R1.almnjoy.lab, ISPA-R1.almnjoy.lab, ISPB-R1.almnjoy.lab"
      ],
      [
       "CDP",
       24,
       "HQ1-CORE-R1.almnjoy.lab, HQ1-CORE-R2.almnjoy.lab, ISPA-R1.almnjoy.lab, ISPB-R1.almnjoy.lab"
      ]
     ]
    }
   ]
  },
  "icmp": {
   "summary": "66 pings / 23 replies, 44 unreachable, 0 TTL exceeded.",
   "data": {
    "echo_req": 67,
    "echo_rep": 23,
    "unreachable": 44,
    "ttl_exceeded": 0
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
       44
      ]
     ]
    }
   ]
  },
  "flows": {
   "summary": "27 conversation(s), mostly other IP: ICMP on 100.200.1.1, 170 bps, 36% of bytes.",
   "data": {
    "conversations": 27,
    "services": [
     {
      "server": "100.200.1.1",
      "service": "ICMP",
      "pattern": "Other IP",
      "flows": 1,
      "clients": 1,
      "bytes": 7020.0,
      "share_pct": 36.0,
      "rate_bps": 170.1816
     },
     {
      "server": "100.200.255.2",
      "service": "ESP",
      "pattern": "Other IP",
      "flows": 1,
      "clients": 1,
      "bytes": 3888.0,
      "share_pct": 19.9,
      "rate_bps": 101.7075
     },
     {
      "server": "100.100.255.2",
      "service": "ICMP",
      "pattern": "Keepalive / heartbeat",
      "flows": 1,
      "clients": 1,
      "bytes": 3080.0,
      "share_pct": 15.8,
      "rate_bps": 114.6049
     },
     {
      "server": "100.100.255.2",
      "service": "BGP 179",
      "pattern": "Polling every ~10 s",
      "flows": 20,
      "clients": 1,
      "bytes": 2520.0,
      "share_pct": 12.9,
      "rate_bps": 108.1541
     },
     {
      "server": "100.200.255.1",
      "service": "BGP 179",
      "pattern": "Request / response",
      "flows": 2,
      "clients": 1,
      "bytes": 1775.0,
      "share_pct": 9.1,
      "rate_bps": 43.802
     },
     {
      "server": "100.100.255.1",
      "service": "BGP 179",
      "pattern": "Request / response",
      "flows": 1,
      "clients": 1,
      "bytes": 980.0,
      "share_pct": 5.0,
      "rate_bps": 66.6229
     },
     {
      "server": "34.107.243.93",
      "service": "HTTPS 443",
      "pattern": "Request / response",
      "flows": 1,
      "clients": 1,
      "bytes": 250.0,
      "share_pct": 1.3,
      "rate_bps": 2000.0
     }
    ],
    "patterns": {
     "Other IP": 55.9,
     "Keepalive / heartbeat": 15.8,
     "Request / response": 15.4,
     "Polling every ~10 s": 12.9
    },
    "rtp": [],
    "headline": "27 conversation(s), mostly other IP: ICMP on 100.200.1.1, 170 bps, 36% of bytes",
    "points": [
     "Traffic by pattern: other IP 56%, keepalive / heartbeat 16%, request / response 15%.",
     "100.200.1.1 ICMP: other IP, 1 conversation(s), 6.9 KB (36%), 170 bps",
     "100.200.255.2 ESP: other IP, 1 conversation(s), 3.8 KB (20%), 102 bps",
     "100.100.255.2 ICMP: keepalive / heartbeat, 1 conversation(s), 3.0 KB (16%), 115 bps"
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
       "6.9 KB",
       "36.0%",
       "170 bps",
       "5.1 KB / 1.8 KB"
      ],
      [
       "100.200.255.2",
       "ESP",
       "Other IP",
       1,
       1,
       "3.8 KB",
       "19.9%",
       "102 bps",
       "1.9 KB / 1.9 KB"
      ],
      [
       "100.100.255.2",
       "ICMP",
       "Keepalive / heartbeat",
       1,
       1,
       "3.0 KB",
       "15.8%",
       "115 bps",
       "3.0 KB / 0 B"
      ],
      [
       "100.100.255.2",
       "BGP 179",
       "Polling every ~10 s",
       20,
       1,
       "2.5 KB",
       "12.9%",
       "108 bps",
       "1.3 KB / 1.2 KB"
      ],
      [
       "100.200.255.1",
       "BGP 179",
       "Request / response",
       2,
       1,
       "1.7 KB",
       "9.1%",
       "44 bps",
       "858 B / 917 B"
      ],
      [
       "100.100.255.1",
       "BGP 179",
       "Request / response",
       1,
       1,
       "980 B",
       "5.0%",
       "67 bps",
       "534 B / 446 B"
      ],
      [
       "34.107.243.93",
       "HTTPS 443",
       "Request / response",
       1,
       1,
       "250 B",
       "1.3%",
       "2 kbps",
       "94 B / 156 B"
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
       90,
       "6.9 KB",
       "330.0 s",
       "170 bps",
       "ip.addr==100.100.255.2 && ip.addr==100.200.1.1"
      ],
      [
       "100.200.255.10:",
       "100.200.255.2",
       "ESP",
       "Other IP",
       24,
       "3.8 KB",
       "305.8 s",
       "102 bps",
       "ip.addr==100.200.255.10 && ip.addr==100.200.255.2"
      ],
      [
       "100.100.255.1:",
       "100.100.255.2",
       "ICMP",
       "Keepalive / heartbeat",
       44,
       "3.0 KB",
       "215.0 s",
       "115 bps",
       "ip.addr==100.100.255.1 && ip.addr==100.100.255.2"
      ],
      [
       "100.200.255.2:20076",
       "100.200.255.1",
       "BGP 179",
       "Request / response",
       24,
       "1.6 KB",
       "300.2 s",
       "44 bps",
       "ip.addr==100.200.255.2 && ip.addr==100.200.255.1"
      ],
      [
       "100.100.255.2:36654",
       "100.100.255.1",
       "BGP 179",
       "Request / response",
       15,
       "980 B",
       "117.7 s",
       "67 bps",
       "ip.addr==100.100.255.2 && ip.addr==100.100.255.1"
      ],
      [
       "198.51.100.10:1025",
       "34.107.243.93",
       "HTTPS 443",
       "Request / response",
       3,
       "250 B",
       "0.0 s",
       "0 bps",
       "ip.addr==198.51.100.10 && ip.addr==34.107.243.93"
      ],
      [
       "100.200.255.2:20076",
       "100.200.255.1",
       "BGP 179",
       "Request / response",
       2,
       "133 B",
       "0.1 s",
       "0 bps",
       "ip.addr==100.200.255.2 && ip.addr==100.200.255.1"
      ],
      [
       "100.100.255.1:31178",
       "100.100.255.2",
       "BGP 179",
       "Polling every ~10 s",
       2,
       "126 B",
       "0.0 s",
       "0 bps",
       "ip.addr==100.100.255.1 && ip.addr==100.100.255.2"
      ],
      [
       "100.100.255.1:37912",
       "100.100.255.2",
       "BGP 179",
       "Polling every ~10 s",
       2,
       "126 B",
       "0.0 s",
       "0 bps",
       "ip.addr==100.100.255.1 && ip.addr==100.100.255.2"
      ],
      [
       "100.100.255.1:26362",
       "100.100.255.2",
       "BGP 179",
       "Polling every ~10 s",
       2,
       "126 B",
       "0.0 s",
       "0 bps",
       "ip.addr==100.100.255.1 && ip.addr==100.100.255.2"
      ],
      [
       "100.100.255.1:41521",
       "100.100.255.2",
       "BGP 179",
       "Polling every ~10 s",
       2,
       "126 B",
       "0.0 s",
       "0 bps",
       "ip.addr==100.100.255.1 && ip.addr==100.100.255.2"
      ],
      [
       "100.100.255.1:54850",
       "100.100.255.2",
       "BGP 179",
       "Polling every ~10 s",
       2,
       "126 B",
       "0.0 s",
       "0 bps",
       "ip.addr==100.100.255.1 && ip.addr==100.100.255.2"
      ],
      [
       "100.100.255.1:28856",
       "100.100.255.2",
       "BGP 179",
       "Polling every ~10 s",
       2,
       "126 B",
       "0.0 s",
       "0 bps",
       "ip.addr==100.100.255.1 && ip.addr==100.100.255.2"
      ],
      [
       "100.100.255.1:26248",
       "100.100.255.2",
       "BGP 179",
       "Polling every ~10 s",
       2,
       "126 B",
       "0.0 s",
       "0 bps",
       "ip.addr==100.100.255.1 && ip.addr==100.100.255.2"
      ],
      [
       "100.100.255.1:46545",
       "100.100.255.2",
       "BGP 179",
       "Polling every ~10 s",
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
   "summary": "24 TCP connections, 0 retransmissions, 20 resets. Handshake RTT median n/a.",
   "data": {
    "streams": 24,
    "retx": 0,
    "dupack": 0,
    "rst": 20,
    "retx_data": 0,
    "handshake": {
     "n": 0
    },
    "services": [
     {
      "service": "100.100.255.2:179",
      "streams": 20,
      "retx": 0,
      "data_segs": 0,
      "retx_rate": 0.0,
      "rst": 20,
      "worst_stall_s": 0.0
     },
     {
      "service": "100.200.255.1:179",
      "streams": 2,
      "retx": 0,
      "data_segs": 13,
      "retx_rate": 0.0,
      "rst": 0,
      "worst_stall_s": 0.0
     },
     {
      "service": "100.100.255.1:179",
      "streams": 1,
      "retx": 0,
      "data_segs": 6,
      "retx_rate": 0.0,
      "rst": 0,
      "worst_stall_s": 0.0
     },
     {
      "service": "34.107.243.93:443",
      "streams": 1,
      "retx": 0,
      "data_segs": 2,
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
       "100.100.255.2:179",
       20,
       0,
       0,
       "0.0%",
       0,
       20,
       "-",
       "n/a"
      ],
      [
       "100.200.255.1:179",
       2,
       13,
       0,
       "0.0%",
       0,
       0,
       "-",
       "n/a"
      ],
      [
       "100.100.255.1:179",
       1,
       6,
       0,
       "0.0%",
       0,
       0,
       "-",
       "n/a"
      ],
      [
       "34.107.243.93:443",
       1,
       2,
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
       0,
       "100.100.255.2:36654",
       "100.100.255.1:179",
       15,
       0,
       0,
       "0",
       "-",
       "tcp.stream eq 0"
      ],
      [
       1,
       "198.51.100.10:1025",
       "34.107.243.93:443",
       3,
       0,
       0,
       "0",
       "-",
       "tcp.stream eq 1"
      ],
      [
       2,
       "100.100.255.1:31178",
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
       "100.100.255.1:37912",
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
       "100.100.255.1:26362",
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
       "100.100.255.1:41521",
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
       "100.100.255.1:54850",
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
       "100.100.255.1:28856",
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
       "100.100.255.1:26248",
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
       "100.100.255.1:46545",
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
       "100.100.255.1:20004",
       "100.100.255.2:179",
       2,
       0,
       0,
       "1 by server",
       "-",
       "tcp.stream eq 10"
      ],
      [
       11,
       "100.100.255.1:42399",
       "100.100.255.2:179",
       2,
       0,
       0,
       "1 by server",
       "-",
       "tcp.stream eq 11"
      ]
     ]
    }
   ]
  },
  "l2": {
   "summary": "",
   "data": {
    "names": {
     "aa:bb:cc:00:12:20": "ISPA-R1",
     "aa:bb:cc:00:18:20": "HQ1-CORE-R1",
     "aa:bb:cc:00:14:20": "ISPB-R1",
     "aa:bb:cc:00:19:20": "HQ1-CORE-R2"
    },
    "_ports": {
     "aa:bb:cc:00:12:20": "Et0/2",
     "aa:bb:cc:00:18:20": "Et0/2",
     "aa:bb:cc:00:14:20": "Et0/2",
     "aa:bb:cc:00:19:20": "Et0/2"
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
   "summary": "Largest frame 416 B. SYN MSS 1460-1460.",
   "data": {
    "frag_needed": 0,
    "fragments": 0,
    "max_frame": 416,
    "mss_min": 1460.0,
    "mss_max": 1460.0
   },
   "tables": []
  },
  "transactions": {
   "summary": "1 request/response exchanges across 1 service(s). Slowest: n/a on stream 1.",
   "data": {
    "services": [
     {
      "service": "34.107.243.93:443",
      "count": 1,
      "felt": {
       "n": 0
      },
      "think": {
       "n": 0
      },
      "from_syn": {
       "n": 0
      },
      "slow": null,
      "no_response": 1,
      "app_fail": 0,
      "statuses": {
       "(none)": 1
      }
     }
    ],
    "count": 1,
    "ladder_stream": 1
   },
   "tables": [
    {
     "title": "Latency by service",
     "columns": [
      "Service",
      "Transactions",
      "Server think p50",
      "Client-felt p50",
      "Client-felt p95",
      "Client-felt max",
      "From SYN p50",
      "No response",
      "App failures"
     ],
     "rows": [
      [
       "34.107.243.93:443",
       1,
       "n/a",
       "n/a",
       "n/a",
       "n/a",
       "n/a",
       1,
       0
      ]
     ]
    },
    {
     "title": "Slowest transactions",
     "columns": [
      "At (s)",
      "Stream",
      "Request",
      "Status",
      "Server think",
      "Client-felt",
      "Resends",
      "Filter"
     ],
     "rows": [
      [
       "80.03",
       1,
       "-",
       "-",
       "n/a",
       "n/a",
       0,
       "tcp.stream eq 1"
      ]
     ]
    }
   ]
  }
 },
 "warnings": [
  "Merged 4 captures onto one clock. Frame numbers in this report are per file; the link label says which file."
 ],
 "compare": null,
 "verdict": {
  "status": "info",
  "headline": "Packet breakdown: 13 packets, 9 kinds of message (BGP, ICMP)",
  "points": [
   "ISPA-R1 (100.100.255.1) <-> HQ1-CORE-R1 (100.100.255.2): 5 KEEPALIVE, 1 NOTIFICATION; closed by HQ1-CORE-R1 (100.100.255.2) at 18:12:53.264 (Cease / Administrative shutdown)",
   "ISPB-R1 (100.200.255.1) <-> HQ1-CORE-R2 (100.200.255.2): 11 KEEPALIVE, 2 UPDATE; up the whole capture",
   "Probe 100.100.255.2 -> 100.200.1.1 every 5.0 s: 23 answered, 44 failed; first failure 18:12:39.150 (ICMP 3/13 communication administratively prohibited (ACL)); 14.1 s later: BGP NOTIFICATION 100.100.255.2 -> 100.100.255.1",
   "UPDATE 18:12:53.273 ISPB-R1 -> HQ1-CORE-R2: announce 198.51.100.0/25 (AS_PATH 65200 65100 65001)",
   "UPDATE 18:13:23.451 ISPB-R1 -> HQ1-CORE-R2: withdraw 198.51.100.0/25"
  ],
  "cause": "",
  "counts": {
   "critical": 0,
   "warning": 3,
   "ok": 4,
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
