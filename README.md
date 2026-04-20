# Cloud Threat Hunting VBD — Azure / Microsoft Sentinel

A modular, hands-on threat hunting training built for the Azure stack. Customers learn to detect, investigate, and harden against real-world cloud attack techniques using Microsoft Sentinel and emulated log data.

## Offering Summary

| Aspect | Detail |
|---|---|
| **Delivery Format** | Instructor-led, hands-on labs with CTFd challenges |
| **Duration** | 3-day (core) or 5-day (full curriculum + capstone) |
| **Platform** | Microsoft Sentinel, Log Analytics, Azure Static Web Apps |
| **Audience** | SOC analysts, threat hunters, cloud security engineers |
| **Prerequisites** | Basic KQL, Azure portal familiarity |

## Modules

| # | Module | Focus |
|---|---|---|
| 00 | [Threat Hunt Methodology](modules/00-methodology/) | Hunt loop, MITRE ATT&CK Cloud, cloud-specific considerations |
| 01 | [Phishing](modules/01-phishing/) | Illicit consent grants, AiTM, device code phishing |
| 02 | [Token Abuse](modules/02-token-abuse/) | OAuth/refresh token replay, PRT abuse, token extraction |
| 03 | [Logic App Abuse](modules/03-logic-app-abuse/) | Exfiltration, privilege escalation via managed identities, persistence |
| 04 | [Storage](modules/04-storage/) | Shared key abuse, SAS token misuse, blob data exfiltration |
| 05 | [Persistence](modules/05-persistence-identities/) | Service principals, federated identity credentials, managed identities |
| 08 | [Key Vault](modules/08-keyvault/) | Secret/key enumeration, policy abuse, suspicious access patterns |

## Deliverables

- **Sentinel Workbook** — Interactive hunting workbook deployed to the customer's Sentinel workspace ([template](sentinel-workbook/))
- **Huntability App** — Azure Static Web App for self-assessing hunt readiness per attack category ([source](huntability-app/))
- **CTFd Challenges** — 3–5 flags per module, progressive difficulty, leaderboard-enabled
- **Emulated Data** — Pre-built JSON log sets per module, importable into Sentinel or queryable offline

## Repository Structure

```
cloud-threat-hunting-vbd/
├── modules/
│   ├── 00-methodology/
│   ├── 01-phishing/
│   ├── 02-token-abuse/
│   ├── 03-logic-app-abuse/
│   ├── 04-storage/
│   ├── 05-persistence-identities/
│   └── 08-keyvault/
├── sentinel-workbook/
├── huntability-app/
├── infrastructure/
└── delivery-guides/
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
   .\infrastructure\Invoke-DataIngestion.ps1 -ModulePath modules/01-phishing/emulated-data -WorkspaceId <id> -WorkspaceKey <key>
   ```

3. Deploy the Sentinel Workbook:
   ```bash
   az deployment group create \
     --resource-group <rg-name> \
     --template-file sentinel-workbook/workbook-template.json
   ```

4. Launch CTFd and import the challenge set for the module.

### Exercise Augmentation

This VBD is designed to follow an Exercise (attack emulation) engagement:

- **Exercise** → "Here's what an attacker did in your environment"
- **Threat Hunting VBD** → "Here's how you find it yourselves"

Recommended: Exercise Week 1 → VBD Week 2, or VBD delivered 2–4 weeks post-Exercise.

## Contributing

Each module follows a consistent structure. See [delivery-guides/instructor-guide.md](delivery-guides/instructor-guide.md) for content standards and authoring guidelines.

## License

Internal use only. Do not distribute outside the organization.
