# Cloud Threat Hunting — Azure / Microsoft Sentinel

A modular, hands-on threat hunting training built for the Azure stack. Students learn to detect, investigate, and harden against real-world cloud attack techniques using Microsoft Sentinel and emulated log data.

## Offering Summary

| Aspect | Detail |
|---|---|
| **Delivery Format** | Instructor-led, hands-on labs with CTF challenges |
| **Duration** | 2 days (core) + optional Day 3 (environment hardening) |
| **Platform** | Microsoft Sentinel, Log Analytics, Azure Monitor |
| **Audience** | SOC analysts, threat hunters, cloud security engineers |
| **Prerequisites** | Basic KQL, Azure portal familiarity |

### Day 1

| Time | Activity |
|---|---|
| Morning | **Module 00** — Threat Hunt Methodology: hunt loop, KQL foundations, table footprinting, correlation fields |
| Late Morning | **Module 00 DEMO** |
| Midday | **Module 01** — Phishing: illicit consent grants, AiTM, device code phishing |
| Early Afternoon | **Module 01 CTF** |
| Mid Afternoon | **Module 02** — Token Abuse: FOCI token farming, PRT theft, OAuth refresh token replay |
| Late Afternoon | **Module 02 CTF** |
| End of Day | **Module 03** — Logic App Abuse: RBAC workflow edits, trigger URL harvest, managed identity exfiltration |
| Wrap-up | **Module 03 CTF** |

### Day 2

| Time | Activity |
|---|---|
| Morning | **Module 04** — Storage Abuse: storage key extraction, SAS token abuse, data plane log correlation |
| Late Morning | **Module 04 CTF** |
| Midday | **Module 05** — Persistence via Identities: PFX escalation, backdoor service principals, managed identity abuse |
| Early Afternoon | **Module 05 CTF** |
| Mid Afternoon | **Module 06** — Key Vault Abuse: secret enumeration, RBAC policy manipulation, data vs. control plane detection |
| Late Afternoon | **Module 06 CTF** |
| End of Day | **Module 07 / 08** — Container Apps & Azure Web Apps: RBAC abuse, web shell deployment, managed identity pivot |
| Wrap-up | **Module 07/08 CTF** |

### Day 3 (Optional) — Environment Hardening & Logging Enablement

An optional third day focused on deploying the course tooling into the customer's own Azure environment and remediating gaps found during the hunt exercises.

| Time | Activity |
|---|---|
| Morning | Deploy the **Huntability App** — score the environment's current hunt readiness across all attack categories covered in Days 1–2 |
| Late Morning | Review Huntability output — identify logging gaps (missing diagnostic settings, unconfigured data connectors, tables with no retention) |
| Midday | Enable logging coverage — configure diagnostic settings, connect data connectors, validate table ingestion |
| Early Afternoon | Deploy the **Sentinel Threat Hunting Workbook** — validate workbook queries populate with live data |
| Mid Afternoon | Re-run Huntability to confirm coverage improvements; document residual gaps and remediation owners |
| Late Afternoon | Debrief — review findings, prioritize remaining hardening work, hand off action items |

## Modules

| # | Module | Focus |
|---|---|---|
| 00 | [Threat Hunt Methodology](modules/00-methodology/) | Hunt loop, MITRE ATT&CK Cloud, hypothesis-driven hunting in Azure |
| 01 | [Phishing](modules/01-phishing/) | Illicit consent grants, AiTM, device code phishing |
| 02 | [Token Abuse](modules/02-token-abuse/) | OAuth/refresh token replay, PRT abuse, FOCI token farming, cross-table M365 exfiltration |
| 03 | [Logic App Abuse](modules/03-logic-app-abuse/) | RBAC workflow edits, trigger URL harvest, managed identity exfiltration, persistence via timer triggers |
| 04 | [Storage Abuse](modules/04-storage/) | Storage key extraction, SAS token abuse, management vs. data plane log correlation |
| 05 | [Persistence — Identities](modules/05-persistence-identities/) | Service principals, federated identity credentials, managed identity backdoors |
| 06 | [Key Vault Abuse](modules/06-keyvault/) | Secret/key enumeration, RBAC policy manipulation, data vs. control plane detection |
| 07 | [Container Apps](modules/07-container-apps/) | Azure RBAC abuse, container exec, runtime threat detection with Defender for Containers |
| 08 | [Azure Web Apps](modules/08-azure-webapps/) | Web shell deployment, App Service config abuse, managed identity pivot, Defender for App Service |

## Deliverables

- **CTF Challenges** — Progressive, flag-based challenges per module in each module's `ctfd-challenges/` folder (modules 01–02)
- **Emulated Data** — Pre-built JSON log sets per module in each module's `emulated-data/` folder (modules 01–05), ingestible into a Sentinel workspace
- **Sentinel Workbook** — Interactive hunting workbook deployable to any Sentinel workspace ([template](sentinel-workbook/workbook-template.json))
- **Delivery Guides** — Instructor and student run-of-show documents ([delivery-guides/](delivery-guides/))

## Repository Structure

```
cloud-threat-hunting/
├── README.md
├── modules/
│   ├── 00-methodology/
│   │   └── README.md
│   ├── 01-phishing/
│   │   ├── README.md, Attack.md, Defend.md, Mitigate.md
│   │   ├── ctfd-challenges/challenges.json
│   │   └── emulated-data/phishing-logs.json
│   ├── 02-token-abuse/
│   │   ├── README.md, Attack.md, Defend.md, Mitigate.md
│   │   ├── ctfd-challenges/challenges.md
│   │   └── emulated-data/token-abuse-logs.json
│   ├── 03-logic-app-abuse/
│   │   ├── README.md, Attack.md, Defend.md, Mitigate.md
│   │   └── emulated-data/logic-app-logs.json
│   ├── 04-storage/
│   │   ├── README.md, Attack.md, Defend.md, Mitigate.md
│   │   └── emulated-data/storage-keyvault-logs.json
│   ├── 05-persistence-identities/
│   │   ├── README.md, Attack.md, Defend.md, Mitigate.md
│   │   └── emulated-data/persistence-logs.json
│   ├── 06-keyvault/
│   │   ├── README.md, Attack.md, Defend.md, Mitigate.md
│   │   └── (emulated data TBD)
│   ├── 07-container-apps/
│   │   ├── README.md, Attack.md, Defend.md, Mitigate.md
│   │   └── (emulated data TBD)
│   └── 08-azure-webapps/
│       ├── README.md, Attack.md, Defend.md, Mitigate.md
│       └── (emulated data TBD)
├── sentinel-workbook/
│   ├── README.md
│   └── workbook-template.json
└── delivery-guides/
    ├── instructor-guide.md
    └── student-guide.md
```

## Getting Started

### Lab Setup

1. Clone the repo and open a module folder.

2. Ingest emulated data for the target module into your Sentinel workspace using the Log Analytics Data Collector API or the Azure Monitor HTTP Data Collector.

3. Deploy the Sentinel Workbook:
   ```bash
   az deployment group create \
     --resource-group <rg-name> \
     --template-file sentinel-workbook/workbook-template.json
   ```

4. Load the module's `ctfd-challenges/` content into your CTFd instance and run queries against the ingested data.

## Contributing

Each module follows a consistent structure: `README.md`, `Attack.md`, `Defend.md`, `Mitigate.md`, `ctfd-challenges/`, and `emulated-data/`. See [delivery-guides/instructor-guide.md](delivery-guides/instructor-guide.md) for content standards and authoring guidelines.

## License

Internal use only. Do not distribute outside the organization.
