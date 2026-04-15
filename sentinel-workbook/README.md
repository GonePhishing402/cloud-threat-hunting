# Sentinel Workbook — Cloud Threat Hunting

## Overview

This workbook provides interactive hunting views aligned to each VBD module. Deploy it to the customer's Sentinel workspace as a post-engagement deliverable.

## Deployment

### Azure CLI
```bash
az deployment group create \
  --resource-group <rg-name> \
  --template-file workbook-deploy.bicep \
  --parameters workspaceName=<sentinel-workspace-name>
```

### Manual
1. Open Microsoft Sentinel > Workbooks > Add workbook
2. Switch to Advanced Editor
3. Paste the contents of `workbook-template.json`
4. Save

## Tabs

| Tab | Content |
|---|---|
| **Overview** | Event volume timeline across all data sources |
| **Phishing** | Consent grants, device code sign-ins, AiTM indicators |
| **Token Abuse** | Multi-IP token usage, anomalous refresh patterns |
| **Logic Apps** | Logic App operations, creation/modification events |
| **Storage & KV** | Storage key listings, Key Vault access events |
| **Persistence** | SP credential changes, federated identity credentials, app role assignments |
| **Log Coverage** | Which tables are actively receiving data vs. expected tables |

## Parameters

- **Time Range**: Scope all queries to a specific window
- **User Filter**: Narrow to a specific UserPrincipalName
- **IP Filter**: Narrow to a specific IP address

## Customization

The workbook is designed to be extended. Add new query tiles by editing the JSON template and adding new items to the `items` array.
