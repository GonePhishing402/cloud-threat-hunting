# Module 00 — Threat Hunt Methodology in the Cloud

## Objective

Establish a structured threat hunting methodology tailored towards cloud environments, specifically Azure and Microsoft Sentinel. Students leave with a repeatable framework for hypothesis-driven hunting.

## Duration

~2 hours (lecture + introductory lab)

## Topics

### 1. The Threat Hunt Loop
- **Hypothesis Formation** — Intelligence-driven, anomaly-driven, situational awareness
- **Data Collection** — Identify required Sentinel tables, validate log coverage
- **Investigation** — KQL query development, entity pivoting, timeline reconstruction
- **Response** — Escalation criteria, containment actions, evidence preservation
- **Feedback** — Convert successful hunts into analytics rules, update threat model

### 2. Cloud-Specific Hunting Considerations
- Identity is the perimeter — Azure AD as the control plane
- Shared responsibility model implications for log visibility
- Log latency and ingestion delays (SigninLogs: ~2 min, AzureActivity: ~5–15 min)
- Multi-tenant and cross-subscription visibility challenges
- Ephemeral resources and just-in-time access patterns

### 3. MITRE ATT&CK Cloud Matrix Mapping
- Map Azure attack surface to ATT&CK tactics:
  - **Initial Access**: Phishing, Valid Accounts, Trusted Relationship
  - **Persistence**: Account Manipulation, Create Account, Implant Container
  - **Privilege Escalation**: Abuse Elevation Control, Valid Accounts
  - **Defense Evasion**: Modify Cloud Compute, Unused Regions
  - **Credential Access**: Steal Application Access Token, Forge Web Credentials
  - **Discovery**: Cloud Infrastructure Discovery, Account Discovery
  - **Lateral Movement**: Use Alternate Authentication Material, Internal Spearphishing
  - **Collection**: Data from Cloud Storage, Email Collection
  - **Exfiltration**: Transfer Data to Cloud Account
  - **Impact**: Resource Hijacking, Data Destruction
- Map each tactic to Sentinel data sources and tables

### 4. KQL Foundations for Threat Hunting
- Essential operators: `where`, `project`, `summarize`, `join`, `extend`, `parse`
- Time-based analysis: `bin()`, `ago()`, `between()`
- Entity pivoting: correlating across UserPrincipalName, IPAddress, ResourceId
- Statistical baselines: `percentile()`, `stdev()`, `series_decompose_anomalies()`

### 5. Sentinel Hunting Features
- Hunting queries blade
- Bookmarks and investigation graph
- Livestream
- Notebooks integration
- Watchlists for IOC management

## CTFd Challenges

| # | Title | Difficulty | Description |
|---|---|---|---|
| 1 | Orient to Sentinel | Easy | Navigate to the Hunting blade and identify the number of built-in hunting queries for Initial Access |
| 2 | First KQL Hunt | Easy | Write a KQL query to find all sign-in events from a specific IP address in the last 24 hours |
| 3 | Hypothesis Builder | Medium | Given a threat intel report, formulate a hunt hypothesis and identify which Sentinel tables are needed |

## References

- [MITRE ATT&CK Cloud Matrix](https://attack.mitre.org/matrices/enterprise/cloud/)
- [Microsoft Sentinel Hunting Documentation](https://learn.microsoft.com/en-us/azure/sentinel/hunting)
- [KQL Quick Reference](https://learn.microsoft.com/en-us/azure/data-explorer/kql-quick-reference)

## Instructor Notes

- This module sets the tone for the entire engagement — emphasize that hunting is a discipline, not a tool feature
- Spend time on hypothesis formation; students tend to jump straight to queries
- Use the KQL section as a leveling exercise — identify students who need more support
- Tie the MITRE mapping back to the specific modules they'll cover later
