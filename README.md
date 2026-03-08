# Phishing Alert Triage - SOC L1 Simulation

**Platform:** TryHackMe SOC Simulator  
**Role:** SOC L1 Analyst  
**Severity:** High → Contained (True Positive)  
**Status:** ✅ Resolved — Firewall blocked malicious URL, no compromise

---

## 📋 Project Overview

This project documents a real-world phishing alert triage exercise performed in the TryHackMe SOC Simulator. A High-severity firewall alert was triggered when an internal employee clicked a link in a phishing email impersonating Amazon. The investigation covers the full L1 analyst workflow: alert intake, SIEM investigation in Splunk, OSINT enrichment, victim identification, and case closure.

---

## 🧰 Tools Used

| Tool | Purpose |
|------|---------|
| Splunk Enterprise 8.2.6 | SIEM — log correlation, event timeline, email & firewall analysis |
| VirusTotal | URL reputation analysis |
| urlscan.io | Safe URL rendering and redirect analysis |
| AbuseIPDB | IP reputation check |
| TryDetectThis (Analyst VM) | In-platform URL/IP threat intel |
| TryHackMe Asset Inventory | Victim identification via IP mapping |

---

## 🚨 Alert Details

| Field | Value |
|-------|-------|
| Alert ID | 8816 |
| Alert Name | Access to Blacklisted External URL Blocked by Firewall |
| Severity | High |
| Datasource | Firewall |
| Timestamp | 03/07/2026 16:46:38 |
| Source IP | 10.20.2.17 |
| Destination IP | 67.199.248.11 |
| Destination Port | 80 (HTTP) |
| Protocol | TCP |
| URL | `http://bit.ly/3sHkX3da12340` (defanged: `hxxp://bit[.]ly/3sHkX3da12340`) |
| Firewall Action | **Blocked** |
| Rule Triggered | Blocked Websites |

---

## 🔍 Investigation Methodology

### Step 1 — Alert Intake & Context
Reviewed the firewall alert in the TryHackMe alert queue. Alert indicated a user attempted to access a blacklisted external URL via HTTP (port 80, unencrypted), which was blocked by the firewall.

### Step 2 — URL Analysis in Splunk
Searched Splunk for the malicious URL to confirm the single event and gather surrounding context:

```spl
index=* "http://bit.ly/3sHkX3da12340"
| table _time, host, src_ip, url, user
```

Result: **1 matching event** — firewall block at 16:46:38.

### Step 3 — Victim Identification
Pivoted on the source IP to identify the user and inspect their recent activity:

```spl
index=* SourceIP="10.20.2.17"
| table _time, Action, URL, datasource
```

Cross-referenced `10.20.2.17` against the asset inventory:
- **User:** Hannah Harris
- **Department:** Human Resources
- **Hostname:** win-3457

Prior activity at 16:44 showed a legitimate Google search (`how to set up payroll system for small business`) — confirming normal usage before the phishing event.

### Step 4 — Email Investigation
Searched all email logs associated with Hannah Harris to find the phishing email source:

```spl
index=* sourcetype=* "h.harris@thetrydaily.thm"
| table _time, sender, recipient, subject, content, direction
```

Found inbound phishing email at **16:45:24** — one minute before the firewall alert.

### Step 5 — URL Threat Intelligence
Submitted the URL to three external tools for enrichment:

| Tool | Finding |
|------|---------|
| VirusTotal | 1/95 vendors flagged — **Phishing** (Gridinsoft) |
| urlscan.io | Resolves to `67.199.248.10`, status 404 (link expired/taken down) |
| TryDetectThis | Status: **MALICIOUS** |

The URL is a bit.ly shortlink masking the true destination — a common phishing delivery technique. The 404 response suggests the payload infrastructure was short-lived.

---

## 📧 Phishing Email Analysis

| Field | Value |
|-------|-------|
| Sender | `urgents@amazon.biz` |
| Recipient | `h.harris@thetrydaily.thm` |
| Subject | Your Amazon Package Couldn't Be Delivered – Action Required |
| Direction | Inbound |
| Attachment | None |
| Timestamp | 03/07/2026 16:45:24 |
| Malicious URL in body | `http://bit.ly/3sHkX3da12340` |

**Red Flags Identified:**
- Sender domain `amazon.biz` — spoofing Amazon, not `amazon.com`
- Urgency language ("Action Required", "48 hours" deadline)
- URL shortener (bit.ly) used to obscure true destination
- Unencrypted HTTP link (no HTTPS)
- Delivery failure lure — a common pretext targeting general employees

---

## 📅 Incident Timeline

| Time (03/07/2026) | Event |
|-------------------|-------|
| 16:43:44 | Hannah Harris sends internal email to IT re: onboarding issue (normal) |
| 16:44:16 | Hannah browses Google — payroll setup query (normal activity) |
| 16:45:24 | **Phishing email received** from `urgents@amazon.biz` |
| 16:46:38 | **Hannah clicks malicious link** — firewall blocks connection |
| 16:48:16 | Hannah sends outbound business email (unrelated, benign) |

---

## 🧠 MITRE ATT&CK Mapping

| Technique ID | Technique Name | Observed Behaviour |
|---|---|---|
| T1566.002 | Phishing: Spearphishing Link | Inbound email containing malicious bit.ly URL |
| T1204.001 | User Execution: Malicious Link | Victim clicked the URL — firewall prevented connection |
| T1036 | Masquerading | Sender domain `amazon.biz` spoofing Amazon brand |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTP used for C2/redirect (port 80) |
| T1027 | Obfuscated Files or Information | URL shortener (bit.ly) used to conceal true destination |

---

## ✅ Verdict

**Classification:** True Positive  
**Outcome:** Contained — no compromise  
**Confidence:** High

The evidence confirms Hannah Harris received a phishing email impersonating Amazon and clicked the embedded malicious link. The organisation's firewall successfully blocked the outbound connection before any payload could be delivered. There is no evidence of:
- Successful C2 communication
- Payload download or execution
- Lateral movement
- Data exfiltration

---

## 🛡️ Recommended Actions

1. **Notify victim (Hannah Harris)** — inform her of the phishing attempt, confirm no action is required on her part, provide awareness guidance
2. **Block sender domain** — add `amazon.biz` to the email gateway blocklist
3. **Block malicious URL** — add `hxxp://bit[.]ly/3sHkX3da12340` to the web proxy/firewall blocklist
4. **Block destination IP** — add `67.199.248.11` to the firewall deny list
5. **Scope check** — search for other recipients of the same email across the organisation
6. **Phishing awareness** — flag HR department for targeted phishing awareness training (HR is a high-value target due to access to employee data and financial systems)

---

## 📁 Repository Structure

```
phishing-triage-lab/
├── README.md                          ← This file — full investigation writeup
├── docs/
│   ├── incident-report.md             ← Formal incident report
│   └── mitre-attack-mapping.md        ← Detailed ATT&CK technique breakdown
├── splunk-queries/
│   └── investigation-queries.spl      ← All SPL queries used during triage
└── evidence-notes/
    └── ioc-summary.md                 ← IOC table and threat intel findings
```

---

## 📚 Key Learnings

- **IP-to-user pivoting** in SIEM is a critical first step after alert intake — always map source IPs to the asset inventory
- **Email log correlation** is essential to understand *how* a user was exposed to a malicious URL
- **Multiple OSINT tools** should be used to corroborate findings — a single tool flagging a URL is useful, but two or more creates high confidence
- **Firewall blocks ≠ no investigation needed** — the user still clicked the link; awareness and remediation steps are still required
- **Bit.ly shorteners** in emails are a significant red flag — legitimate organisations rarely use URL shorteners in transactional emails

---

*Lab completed on TryHackMe SOC Simulator | Tools: Splunk, VirusTotal, urlscan.io, AbuseIPDB*
