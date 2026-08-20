# SIEM Log Analysis & Threat Detection — Splunk

## Project Overview

Conducted a security investigation using Splunk SIEM to analyze Windows Server and Apache web server logs for signs of unauthorized activity, account manipulation, and web-based attacks. Identified attack indicators, built custom alerts and dashboards, and documented findings with recommended remediation steps.

---

## Environment

- **Platform:** Splunk Enterprise (local VM instance)
- **Log Sources:** Windows Security Event logs, Apache web server access logs
- **Timeframe Analyzed:** March 17–25, 2020
- **Tools Used:** Splunk SPL (Search Processing Language), Splunk Dashboard Studio, Geolocation mapping

---

## Part 1 — Windows Server Log Analysis

### Objective
Analyze Windows Security Event logs to detect unauthorized account activity, privilege escalation, and policy tampering.

### Key Findings

**Severity Escalation**
- Severity levels increased from 7% to 20% during the attack window
- High-severity events tied to domain policy changes (EventCode 4739) — password minimum length weakened to 6 characters
- Suspicious users: `user_m` and `user_e` made coordinated policy changes within minutes of each other

**Failed Activity**
- Failed activity nearly doubled post-attack — 186 events detected on March 24
- Single failed password reset attempt by `user_a` targeting `user_d` flagged as unauthorized

**Successful Logins**
- Pre-attack: 646 successful logins
- Post-attack: dropped to 280 — indicating disruption or lockout activity
- Primary suspicious users: `user_b` and `user_1` each recorded 8 logins
- Suspicious login spike detected March 25 at 8:00 AM

**Account Deletions**
- 636 accounts deleted within a single hour — major indicator of destructive attack
- EventCode 4726 (user deletions) and 4743 (computer account deletions) both triggered
- `user_l` recorded highest event count (708) — primarily creating and deleting accounts
- `user_a` stood out for heavy activity between 1–2 AM on March 25

**Audit Log Tampering**
- EventCode 1102 detected — audit log was cleared by `user_k`
- Critical indicator of attacker attempting to cover tracks

### Splunk Alerts Configured
| Alert | Threshold |
|-------|-----------|
| Failed Windows Activity | 1 failure/hour (lowered from original threshold) |
| Successful Login Spike | Triggered March 25 8AM |
| Account Deletions | >1 deletion/hour |
| Audit Log Cleared | Any occurrence |

### Suspicious Signatures (EventCodes)
| Signature | EventCode | Count |
|-----------|-----------|-------|
| User account changed | 4738 | High |
| User account created | 4720 | High |
| User account deleted | 4726 | High |
| Domain policy changed | 4739 | 3 (high severity) |
| Audit log cleared | 1102 | 1 |

---

## Part 2 — Apache Web Server Log Analysis

### Objective
Analyze Apache access logs to identify web-based attack indicators, unusual HTTP methods, and suspicious traffic patterns.

### Key Findings

**HTTP Method Analysis**
- 175 GET requests vs. 1 suspicious POST request
- POST targeted `/VSI_Account_logon.php` — the site's login page
- POST returned HTTP 200 (success) — indicating server processed the request
- Referrer was a malformed Google image search URL — indicator of referrer spoofing

**HTTP Response Codes**
- 404 errors detected for specific resources — potential directory probing
- Successful 200 response on POST to login page is the most critical finding
- 304 responses consistent with normal cache behavior

**International Activity**
- Average 44.5 international requests per day
- Traffic originated from: Russia, Romania, Indonesia, Belgium, France, China, Poland
- Peak international activity: 10 PM on March 17 — 22 GET requests from Moscow (IP: 83.149.9.216)
- International alert threshold set at 50 — not triggered; revised recommendation: lower to 20

**HTTP POST Attack Analysis**
- Single POST at 10:05:46 PM on March 17 from IP 50.150.204.184
- URI: `/VSI_Account_logon.php`
- Referrer spoofing confirmed — malformed Google query used as cover
- Alert threshold revised to 1 POST to login endpoint to flag any future attempts

### Splunk Alerts Configured
| Alert | Threshold |
|-------|-----------|
| HTTP POST to login page | 1 (any POST to `/VSI_Account_logon.php`) |
| International activity spike | Revised to 20 requests/hour |
| 404 error volume | >5 per hour per URI |

### Splunk Dashboards Built
- Time chart of HTTP methods over time
- Cluster map with geolocation of client IPs
- URI frequency table
- User activity analysis panel

---

## Summary of Attack Timeline

| Date/Time | Event |
|-----------|-------|
| March 17, 10:05 PM | Suspicious POST to login page from IP 50.150.204.184 |
| March 17, 10 PM | International activity peak — 22 requests from Moscow |
| March 24, 11:59 PM | Mass account creation and deletion — `user_l` (708 events) |
| March 24 | Audit log cleared by `user_k` — evidence tampering |
| March 24 | Domain password policy weakened to length 6 |
| March 25, 1–2 AM | Suspicious `user_a` activity spike |
| March 25, 8 AM | Login volume drop from 646 to 280 — post-attack disruption |

---

## Recommendations

- Lower password policy minimum to 8+ characters (NIST standard)
- Set alert on any audit log clear event (EventCode 1102)
- Flag all POST requests to login endpoints regardless of volume
- Investigate `user_k`, `user_l`, `user_m`, and `user_e` for privilege escalation
- Verify legitimacy of IP 50.150.204.184 and 83.149.9.216
- Implement rate limiting and CAPTCHA on `/VSI_Account_logon.php`

---

## Skills Demonstrated

- Splunk SPL query writing
- SIEM alert configuration and threshold tuning
- Windows Security Event log analysis
- Apache web server log analysis
- Geolocation-based threat detection
- Incident timeline reconstruction
- Dashboard creation for SOC reporting# splunk-siem-log-analysis
Splunk SIEM investigation of Windows Server and Apache web server logs for threat detection and incident response.
