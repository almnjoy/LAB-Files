# AI check: CASE-009 ISP A soft failure (BGP + IP SLA)

How well an outside AI understood this case from the analyzer's **AI export** alone. Template: `templates/ai-check.md`.

## How to run it

1. Fresh chat in the AI (no history, no project).
2. Attach `CASE-009-ai-export.md` (the 2026-11-25 full-process capture) and paste the problem sentence below, nothing else.
3. Paste the answer's key claims here and grade them against the case README.

**Problem sentence given:**
> ISP A's link and BGP session looked up, but traffic through ISP A stopped. Did HQ notice and fail over by itself, how fast, and did it come back cleanly when ISP A healed?

**Known answer** (from the README):
- The inbound ACL on ISPA-R1 refused the IP SLA probes with ICMP 3/13 from 11:11:59.269.
- R1's EEM shut the ISP A neighbor 15.4 s later (NOTIFICATION Cease / Administrative shutdown, track `delay down 10`).
- ISP A's 9 reconnects were refused.
- Probes recovered at 11:13:24.270. After `delay up 30`, R1 reopened the session at 11:14:00.288 (OPEN, KEEPALIVE, BoRR, table, EoRR, End-of-RIB). It was down 105.7 s.
- Bonus: a forwarding loop inside HQ for 198.51.100.10 while ISP A was down (TTL 115 in, TTL-exceeded quoting TTL 1, 9 times).

## ChatGPT · not run yet

| Check | Result |
|---|---|
| Named the right root cause | |
| Quoted at least one display filter from the export | |
| Invented numbers (not in the export) | |
| Said what to capture next | |

**Got right:**

**Missed or got wrong:**

**Engine fixes raised:**

## Claude · not run yet

(same table)
