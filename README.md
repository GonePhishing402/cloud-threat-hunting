# Cloud Threat Hunting — Azure / Microsoft Sentinel

A modular, hands-on threat hunting training built for the Azure stack. Students learn to detect, investigate, and harden against real-world cloud attack techniques using Microsoft Sentinel and emulated log data.

## Offering Summary

| Aspect | Detail |
|---|---|
| **Delivery Format** | Instructor-led, hands-on labs with CTF challenges |
| **Duration** | 3-day (core) or 5-day (full curriculum + capstone) |
| **Platform** | Microsoft Sentinel, Log Analytics, Azure Static Web Apps |
| **Audience** | SOC analysts, threat hunters, cloud security engineers |
| **Prerequisites** | Basic KQL, Azure portal familiarity |

## Modules

| # | Module | Focus |
|---|---|---|
| 00 | [Threat Hunt Methodology](modules/00-methodology/) | Hunt loop, MITRE ATT&CK Cloud, cloud-specific considerations |
| 01 | [Phishing](modules/01-phishing/) | Illicit consent grants, AiTM, device code phishing |
| 02 | [Token Abuse](modules/02-token-abuse/) | OAuth/refresh token replay, PRT abuse, FOCI token farming, cross-table M365 exfil |
| 03 | [Logic App Abuse](modules/03-logic-app-abuse/) | RBAC workflow edits, trigger URL harvest, managed identity exfiltration |
| 04 | [Storage & Key Vault](modules/04-storage-keyvault/) | Shared key abuse, SAS token misuse, blob data exfiltration, Key Vault RBAC abuse |
| 05 | [Persistence — Identities](modules/05-persistence-identities/) | Service principals, federated identity credentials, managed identities |
| 06 | [Hardening Capstone](modules/06-hardening-capstone/) | End-to-end hardening review across all attack surfaces |
| 07 | [Logging Enablement](modules/07-logging-enablement/) | Sentinel table coverage, diagnostic settings, log gap remediation |

## Deliverables

- **Sentinel Workbook** — Interactive hunting workbook deployed to the lab Sentinel workspace ([template](sentinel-workbook/))
- **Huntability App** — Azure Static Web App for self-assessing hunt readiness per attack category ([source](huntability-app/))
- **CTF Challenges** — Progressive, flag-based challenges per module; each module has a `ctfd-challenges/` folder with a `challenges.md` file
- **Emulated Data** — Pre-built JSON log sets per module, importable into Sentinel or queryable offline from the `emulated-data/` folder

## Repository Structure

```
cloud-threat-hunting/
├── modules/
│   ├── 00-methodology/
│   │   ├── README.md
│   │   └── ctfd-challenges/
│   │       └── challenges.json
│   ├── 01-phishing/
│   │   ├── README.md
│   │   ├── Attack.md
│   │   ├── Defend.md
│   │   ├── Mitigate.md
│   │   ├── ctfd-challenges/
│   │   │   └── challenges.json
│   │   └── emulated-data/
│   │       └── phishing-logs.json
│   ├── 02-token-abuse/
│   │   ├── README.md
│   │   ├── Attack.md
│   │   ├── Defend.md
│   │   ├── Mitigate.md
│   │   ├── ctfd-challenges/
│   │   │   └── challenges.md
│   │   └── emulated-data/
│   │       └── token-abuse-logs.json
│   ├── 03-logic-app-abuse/
│   │   ├── README.md
│   │   ├── Attack.md
│   │   ├── Defend.md
│   │   ├── Mitigate.md
│   │   └── emulated-data/
│   │       └── logic-app-logs.json
│   ├── 04-storage-keyvault/
│   │   ├── README.md
│   │   └── emulated-data/
│   │       └── storage-keyvault-logs.json
│   ├── 05-persistence-identities/
│   │   ├── README.md
│   │   └── emulated-data/
│   │       └── persistence-logs.json
│   ├── 06-hardening-capstone/
│   │   └── README.md
│   └── 07-logging-enablement/
│       └── README.md
├── sentinel-workbook/
│   ├── README.md
│   └── workbook-template.json
├── huntability-app/
│   ├── README.md
│   ├── public/
│   └── src/
├── infrastructure/
│   ├── lab-environment.bicep
│   └── Invoke-DataIngestion.ps1
└── delivery-guides/
    ├── instructor-guide.md
    └── student-guide.md
```

## Getting Started

### Lab Environment Setup

1. Deploy the lab Sentinel workspace:
   ```bash
   az deployment group create \
     --resource-group <rg-name> \
     --template-file infrastructure/lab-environment.bicep \
     --parameters workspaceName=<name>
   ```

2. Ingest emulated data for the target module:
   ```powershell
   .\infrastructure\Invoke-DataIngestion.ps1 -ModulePath modules/02-token-abuse/emulated-data -WorkspaceId <id> -WorkspaceKey <key>
   ```

3. Deploy the Sentinel Workbook:
   ```bash
   az deployment group create \
     --resource-group <rg-name> \
     --template-file sentinel-workbook/workbook-template.json
   ```

4. Open the module's `ctfd-challenges/challenges.md` and load the flags into your CTFd instance.

## Contributing

Each module follows a consistent structure. See [delivery-guides/instructor-guide.md](delivery-guides/instructor-guide.md) for content standards and authoring guidelines.

## License

Internal use only. Do not distribute outside the organization.
