# Instructor Guide — Cloud Threat Hunting VBD

## Engagement Overview

| Item | Detail |
|---|---|
| **Duration** | 5 days (full) / 3 days (core) |
| **Format** | Instructor-led, hands-on labs, CTFd challenges |
| **Class Size** | 8–16 students (optimal for team exercises) |
| **Prerequisites** | Basic KQL, Azure portal navigation, SOC analyst experience |

## Delivery Schedule

### 5-Day Full Curriculum

| Day | Morning (4 hrs) | Afternoon (4 hrs) |
|---|---|---|
| **Day 1** | Module 00: Threat Hunt Methodology | Module 07: Logging Enablement + Lab Setup |
| **Day 2** | Module 01: Phishing (Lecture + Playbooks) | Module 01: Phishing (CTFd Challenges) |
| **Day 3** | Module 02: Token Abuse | Module 03: Logic App Abuse |
| **Day 4** | Module 04: Storage & Key Vault | Module 05: Persistence (MI & SP) |
| **Day 5** | Module 06: Hardening Capstone (Group Exercise) | Capstone Presentations + Wrap-up |

### 3-Day Core Curriculum

| Day | Morning (4 hrs) | Afternoon (4 hrs) |
|---|---|---|
| **Day 1** | Module 00: Methodology + Module 07: Logging | Module 01: Phishing |
| **Day 2** | Module 02: Token Abuse | Module 04: Storage & Key Vault |
| **Day 3** | Module 05: Persistence | Module 06: Hardening Capstone (Condensed) |

> In the 3-day format, Module 03 (Logic App Abuse) is provided as self-study material.

## Per-Module Delivery Template

Each module follows a consistent structure. Timing for a half-day module (~3 hours):

| Segment | Duration | Activity |
|---|---|---|
| Threat Brief | 30 min | Slide deck: Attack narrative, MITRE mapping, real-world examples |
| Live Demo | 20 min | Instructor walks through hunt playbook in Sentinel |
| Guided Lab | 45 min | Students follow playbook, execute KQL queries, investigate findings |
| CTFd Challenges | 60 min | Independent/team challenges (Easy → Hard) |
| Hardening Discussion | 15 min | Review hardening controls, Conditional Access policies |
| Q&A / Debrief | 10 min | Address questions, preview next module |

## Lab Environment Setup

### Pre-Engagement (1 week before)

1. Deploy lab workspace: `az deployment group create --template-file infrastructure/lab-environment.bicep`
2. Ingest emulated data for ALL modules:
   ```powershell
   Get-ChildItem modules/*/emulated-data | ForEach-Object {
       .\infrastructure\Invoke-DataIngestion.ps1 -ModulePath $_.FullName -WorkspaceId $WS_ID -WorkspaceKey $WS_KEY
   }
   ```
3. Deploy the Sentinel Workbook: Import `sentinel-workbook/workbook-template.json`
4. Verify all data is queryable: Run the validation query from Module 07
5. Set up CTFd instance and import challenge sets from each module's `ctfd-challenges/challenges.json`
6. Update CTFd flags with environment-specific values based on the ingested data

### During Engagement

- Ensure all students have **Sentinel Reader** role on the lab workspace
- CTFd should be accessible via browser (provide URL on Day 1)
- Huntability app should be deployed and accessible for Module 06

### Post-Engagement

- Export CTFd scoreboard for customer report
- Leave Sentinel Workbook deployed in customer workspace (if applicable)
- Provide Huntability app URL or deployment guide
- Share Git repo access for reference material

## CTFd Administration

### Scoring Model
- **Easy challenges**: 100–150 points
- **Medium challenges**: 200 points
- **Hard challenges**: 300–400 points
- **Hints**: Cost 25–100 points (deducted from challenge value)
- **Leaderboard**: Display throughout engagement for motivation

### Flag Management
Flags in `challenges.json` marked `PLACEHOLDER` must be updated with environment-specific values after data ingestion. Generate correct answers by running the hunt playbooks against the ingested data.

### Manual Grading
Challenges marked `"type": "manual"` (e.g., "Build the Detection" in Module 01) require instructor review. Evaluate based on:
- Query correctness (does it detect the attack?)
- False positive consideration (does it explain tuning?)
- Completeness (does it include relevant fields?)

## Demo Scripts

### Module 01 Live Demo: AiTM Detection
```
1. Open Sentinel > Logs
2. Run: SigninLogs | where TimeGenerated > ago(7d) | where ResultType == 0 | where AuthenticationRequirement == "multiFactorAuthentication" | take 10
3. "These are successful MFA sign-ins. Now let's look for the session replay..."
4. Run the AiTM detection query from the hunt playbook
5. Point out: same SessionId, different IP, different UserAgent, 2-minute gap
6. "This is what AiTM looks like in log data. The MFA was valid — the attacker stole the cookie AFTER MFA."
```

### Module 04 Live Demo: Key Vault Enumeration
```
1. Open Sentinel > Logs
2. Run: AzureDiagnostics | where ResourceProvider == "MICROSOFT.KEYVAULT" | take 10
3. "Here's what normal Key Vault access looks like — usually a service principal reading one secret."
4. Run the enumeration detection query from the hunt playbook
5. Point out: SecretList followed by rapid SecretGet for multiple secrets, from a user account
6. "Users don't normally bulk-read secrets. This is an attacker enumerating the vault."
```

## Common Student Questions

**Q: Why can't we just write analytics rules for everything instead of hunting?**
A: Analytics rules detect *known* patterns. Hunting finds *unknown* or *novel* attack variations. Both are needed — hunts often become analytics rules after validation.

**Q: How do we handle the ingestion cost of all these logs?**
A: Module 07 covers this. Key strategies: Basic Logs tier for high-volume tables, commitment tiers, DCR filtering. The cost of NOT having logs is the inability to detect breaches.

**Q: Should we hunt in real-time or on a schedule?**
A: Scheduled hunts (weekly/bi-weekly) are most sustainable. Use trigger-based hunts when a new threat intel report is relevant to your environment.

**Q: What if we don't have Sentinel?**
A: The methodology applies to any SIEM. The specific KQL queries are Sentinel-native, but the hunt logic, data requirements, and hardening guidance are universal.

## Instructor Preparation Checklist

- [ ] Lab workspace deployed and verified
- [ ] All emulated data ingested and queryable
- [ ] CTFd instance running with challenges imported
- [ ] Flags updated with correct environment-specific values
- [ ] Sentinel Workbook deployed
- [ ] Huntability app accessible
- [ ] Student accounts provisioned with Sentinel Reader role
- [ ] Slide decks reviewed and customized for customer context
- [ ] Printed/digital student guides prepared
- [ ] Backup KQL queries tested (in case of Sentinel latency)
