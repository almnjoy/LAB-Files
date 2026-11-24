# CASE-009 · ISP A Is About to Shut the Session (BGP + IP SLA)

**Almnjoy Labs · HQ1 edge · capture pack**: four captures of the HQ edge while ISP A "goes soft". This is a teaching pack: the point is to look at the individual BGP messages and see what each one carries. It is not a troubleshooting puzzle.

HQ (AS 65001) is dual-homed. HQ1-CORE-R1 peers with ISP A (AS 65100) and HQ1-CORE-R2 peers with ISP B (AS 65200). The case's fix adds an IP SLA probe on R1 and an EEM applet. When the probe fails, the applet shuts the ISP A neighbor, so HQ stops depending on a path that is up but passing nothing.

The soft failure is injected with an inbound ACL on ISPA-R1 Et0/2. The link and the BGP session stay up, but traffic through ISP A is dropped.

## The captures

Two links, each tapped from both ends. Both files of a link hold the same frames, a few microseconds apart. The analyzer spots this and merges them, keeping one copy of each frame.

| File | Link | Side |
|---|---|---|
| `P1-ISPA-link_HQ1-CORE-R1-Et0-2.pcap` | HQ1-CORE-R1 Et0/2 <-> ISPA-R1 Et0/2 | HQ side |
| `P2-ISPA-link_ISPA-R1-Et0-2.pcap` | same link | ISP A side |
| `P3-ISPB-link_HQ1-CORE-R2-Et0-2.pcap` | HQ1-CORE-R2 Et0/2 <-> ISPB-R1 Et0/2 | HQ side |
| `P4-ISPB-link_ISPB-R1-Et0-2.pcap` | same link | ISP B side |

You only need one file per link (P1 + P3). Load all four into the analyzer and it shows you the merge (tap skew 3-4 µs, 0 frames seen by only one side).

## What happened (clock in CST)

| Time | Event | Wireshark filter |
|---|---|---|
| until 18:12:34.150 | IP SLA 10 pings 100.200.1.1 from R1 every 5 s, all answered | `icmp.type == 8 && ip.src == 100.100.255.2` |
| 18:12:39.151 | First failed probe. ISPA-R1 answers with ICMP 3/13, *communication administratively prohibited* (the ACL) | `icmp.type == 3 && icmp.code == 13` |
| 18:12:53.264 | R1 sends BGP **NOTIFICATION** Cease / Administrative shutdown to ISPA-R1, 14.1 s after the first failure | `bgp.type == 3` |
| 18:12:53.265 | R1 closes the TCP session (FIN) | `tcp.port == 179 && tcp.flags.fin == 1` |
| 18:12:53.273 | ISPB-R1 sends R2 an **UPDATE**: 198.51.100.0/25, AS_PATH 65200 65100 65001, next hop 100.200.255.1 | `bgp.type == 2 && ip.src == 100.200.255.1` |
| 18:13:23.451 | ISPB-R1 withdraws 198.51.100.0/25 | `bgp.update.withdrawn_routes` |
| 18:13:00.571 to 18:16:06.971 | ISPA-R1 tries to reconnect 20 times. Each SYN to R1's port 179 gets a RST, because R1's neighbor is shut down. | `tcp.flags.syn == 1 && tcp.dstport == 179` |

Probe tally: 23 answered, 44 failed. Keepalives run roughly every 50-55 s on all four speakers (IOS default 60 s, jittered).

**Why 14 s and not 5:** the case's track object has `delay down 10`. The probe has to stay failed for 10 s before the track goes down and EEM fires. The capture shows the first failure, the delay, then the NOTIFICATION.

## Packet by packet: what to look at

The analyzer's breakdown section decodes one example of each kind of message, field by field. Each field has a plain-English note, and clicking it highlights its bytes in the hex dump.

- **KEEPALIVE (19 bytes).** Only the common header: 16 bytes of `ff`, length `00 13`, type `04`. There is no body. Its only job is to reset the peer's hold timer.
- **UPDATE.** Withdrawn-routes length, then the path attributes, then the NLRI. Look at the attribute flags byte (`0x40` = well-known, transitive). Then read the AS_PATH as a sequence of 4-byte AS numbers: leftmost is the neighbor that sent it, rightmost is where the route started.
- **The withdraw.** The same UPDATE layout, except the withdrawn-routes section holds the prefix and there are no attributes.
- **NOTIFICATION.** Header plus two bytes: major `06` (Cease), minor `02` (Administrative shutdown). That is the on-wire form of `neighbor 100.100.255.1 shutdown`, here typed by the EEM applet.
- **FIN, SYN, RST on 179.** BGP is just TCP. After the NOTIFICATION the session closes like any other TCP session. ISP A's connect-retry SYNs then get a RST: R1 is up and reachable, it is just refusing the session.
- **ICMP 3/13.** The error carries the first bytes of the probe that triggered it, so you can match each error to its ping by ICMP ID and sequence.

## What these captures do NOT show

- **No user traffic moving to ISP B.** Only BGP, the probes, CDP/LLDP and a little ESP cross these links in the window. To see the shift, capture the inside path (or the ISP B link) while a host is pinging out.
- **No recovery.** The capture ends with the neighbor still shut. Bringing it back (`no neighbor ... shutdown`, or the up-side EEM) would show a fresh OPEN exchange, with the capability negotiation, hold time and router ID.
- **The failure is not silent.** The lab ACL answers with unreachables, so R1 gets an explicit "no". A real soft failure is usually silent: timeouts, no ICMP. The IP SLA reacts the same way either way.
- **A question to chase in the lab:** why does ISP B announce HQ's own /25 back to R2, with 65001 at the end of the path, right as ISP A's session drops, and withdraw it 30 s later? R2 rejects it on AS_PATH loop prevention (it sees its own AS). Check `show ip bgp 198.51.100.0` on both ISPs before and after.

## Analyzer report

[`analysis/CASE-009-bgp-breakdown.2-links.pdf`](analysis/CASE-009-bgp-breakdown.2-links.pdf) (and the interactive `.html`: click a field to light up its bytes).

The question asked: *"Break down the individual BGP messages (keepalives, updates, the notification) and the IP SLA pings. Show what we can see in each packet."*
