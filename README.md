# LAB-Files

**Packet captures, configs and worked answers from the Almnjoy Labs network lab.**
Every case is a real fault built and broken on Cisco Modeling Labs (the ALMNJOY-ENT enterprise topology), then fixed and captured. Open the pcaps in Wireshark, read the breakdown, check the analyzer report.

> Lab-only data. Every address, hostname and MAC in this repo belongs to a CML lab, not a real network.

## Cases

| Case | Topic | What you get | Folder |
|---|---|---|---|
| **CASE-004** · Cards Time Out at Closing | QoS: classify, mark, LLQ, shape over DMVPN | Final config, before/after pcaps at 3 points, Wireshark profile, analyzer before/after reports | [cases/CASE-004-QoS](cases/CASE-004-QoS/) |
| **CASE-008** · Spanning Tree | MST root move across two port-channels | 4 pcaps (every bundle member), breakdown, analyzer report with the port-role timeline | [cases/CASE-008-STP](cases/CASE-008-STP/) |
| **CASE-009** · ISP A Is About to Shut the Session | eBGP dual-homed edge, IP SLA + EEM soft failover and recovery | 4 pcaps of the full cycle (down, refused reconnects, OPEN + table exchange), before/during/after show commands, Wireshark profile, message-by-message breakdown, analyzer report + AI export | [cases/CASE-009-BGP](cases/CASE-009-BGP/) |

## How every case folder is laid out

```
cases/CASE-0xx-<topic>/
├── README.md      the breakdown: what broke, the fix, what the captures prove
├── pcaps/         the captures (before/after, or one file per capture point)
├── analysis/      Almnjoy Labs Packet Analyzer reports, PDF + self-contained HTML
├── configs/       the config that fixed it (when there is one)
├── img/           charts used in the README
└── wireshark/     a Wireshark profile for the case (when there is one)
```

## Reading the analyzer reports
The reports in `analysis/` come from the Almnjoy Labs Packet Analyzer: tshark does the dissection, the engine computes every number, and every finding carries the Wireshark display filter that reproduces it. Open the `.pdf` to read, or the `.html` in a browser for hover detail. Paste any filter from a report straight into Wireshark against the matching pcap.

## Legacy
[legacy/wireshark-basics](legacy/wireshark-basics/): the original Wireshark samples (duplicate ARP, RADIUS EAP-TLS accept, repeated RADIUS) and the column / filter / profile GIFs.

## License
MIT, see [LICENSE](LICENSE).
