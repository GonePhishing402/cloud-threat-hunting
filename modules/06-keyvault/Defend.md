# Defend: Module 06 — Azure Key Vault Detection

This guide focuses on detecting Key Vault abuse using the **`AzureDiagnostics`** table in Microsoft Sentinel / Log Analytics and **Microsoft Defender for Key Vault** alerts. The `AzureDiagnostics` table captures every data plane operation against the vault — making it the primary hunt surface for secret enumeration, RBAC escalation, and exfiltration patterns.

---

## Enabling Key Vault Diagnostic Logging

Key Vault audit logs must be routed to a Log Analytics workspace before they appear in `AzureDiagnostics`. Enable via Diagnostic Settings:

1. **Azure Portal** → Key Vault → **Monitoring** → **Diagnostic settings** → **Add diagnostic setting**
2. Select log category: **`audit`** (or `allLogs`)
3. Destination: **Send to Log Analytics workspace**

```bash
# Enable via Azure CLI
az monitor diagnostic-settings create \
  --name "kv-audit-to-sentinel" \
  --resource /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.KeyVault/vaults/<vault> \
  --workspace /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.OperationalInsights/workspaces/<workspace> \
  --logs '[{"category":"audit","enabled":true}]'
```

Reference: [Azure Key Vault logging](https://learn.microsoft.com/azure/key-vault/general/logging)

---

## `AzureDiagnostics` — Key Vault Filter and Key Fields

When Key Vault logs are streamed to a Log Analytics workspace they land in the **`AzureDiagnostics`** table alongside logs from other Azure resources. Always scope queries to Key Vault with:

```kusto
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.KEYVAULT"
```

### Key Fields for Key Vault Investigation

| Field | Type | Why It Matters |
|---|---|---|
| `ResourceProvider` | string | Filter value: `"MICROSOFT.KEYVAULT"` — scopes to Key Vault rows only |
| `ResourceType` | string | `"VAULTS"` — distinguishes vault ops from managed HSM |
| `Resource` | string | The **vault name** (uppercased) — use to scope to a specific vault |
| `OperationName` | string | **Primary hunt field** — the data plane operation performed. Format is `ObjectVerb`: `SecretGet`, `SecretList`, `KeyGet`, `VaultPut`, `SecretBackup`. Full reference below. |
| `ResultType` | string | `"Success"` or `"Failed"` — failed operations at volume may indicate reconnaissance or lockout attempts |
| `ResultSignature` | string | HTTP status code: `200` (success), `401` (unauthorized), `403` (forbidden), `404` (not found) |
| `CallerIpAddress` | string | IP address of the caller — compare against known service infrastructure IPs; TOR/VPN exit nodes will appear here |
| `identity_claim_oid_g` | string | **Object ID** of the calling identity (Entra ID object ID for users and service principals) — use to pivot to Entra sign-in logs |
| `identity_claim_upn_s` | string | **UPN** of the calling user — populated for interactive user access |
| `identity_claim_appid_g` | string | **Application (client) ID** of the calling app/service principal — key for identifying which application accessed the vault |
| `requestUri_s` | string | The full REST API URI — reveals the specific secret or key name targeted (e.g., `https://<vault>.vault.azure.net/secrets/<name>/`) |
| `id_s` | string | Resource URI of the object returned (e.g., the secret URI) — confirms which object was successfully retrieved |
| `httpStatusCode_d` | long | Numeric HTTP response code — useful when `ResultSignature` is not populated |
| `TimeGenerated` | datetime | UTC timestamp of the operation |
| `CorrelationId` | string | Client-supplied GUID for correlating a sequence of related operations (e.g., a script's session) |
| `DurationMs` | long | Processing time in milliseconds — very short duration across many operations may indicate automated tooling |
| `clientInfo_s` | string | User-agent string of the calling client — `azure-cli/...`, `python-requests/...`, `PostmanRuntime` are common attacker tooling signatures |

### `OperationName` Values — Attacker-Relevant Operations

| OperationName | Attack Relevance |
|---|---|
| `SecretList` | Reconnaissance — attacker enumerating all secret names in the vault |
| `SecretGet` | Exfiltration — reading the value of a specific secret |
| `SecretBackup` | Bulk exfiltration — saves encrypted secret blob for offline recovery |
| `SecretSet` | Persistence / tampering — writing a new or modified secret |
| `SecretDelete` / `SecretPurge` | Destruction / anti-forensics |
| `KeyList` | Key enumeration |
| `KeyGet` | Key metadata retrieval |
| `KeySign` / `KeyDecrypt` | Crypto abuse — signing malicious content or decrypting data using the vault key |
| `VaultPut` | Control plane change — may signal policy manipulation to grant new access |
| `CertificateGet` | Certificate theft |
| `CertificateList` | Certificate enumeration |

Reference: [Key Vault logging — operationName reference](https://learn.microsoft.com/azure/key-vault/general/logging#interpret-your-key-vault-logs)

---

## KQL Detection Queries

### Query 1 — Secret Dump Pattern: SecretList Followed by SecretGet

The canonical attacker sequence. Lists secrets then retrieves values. Aggregates per caller within a 10-minute window.

```kusto
let ListEvents = AzureDiagnostics
    | where ResourceProvider == "MICROSOFT.KEYVAULT"
    | where OperationName == "SecretList"
    | where ResultType == "Success"
    | project ListTime = TimeGenerated, Vault = Resource,
              CallerOid = identity_claim_oid_g,
              CallerUpn = identity_claim_upn_s,
              AppId = identity_claim_appid_g,
              CallerIp = CallerIpAddress;

AzureDiagnostics
| where ResourceProvider == "MICROSOFT.KEYVAULT"
| where OperationName == "SecretGet"
| where ResultType == "Success"
| project GetTime = TimeGenerated, Vault = Resource,
          CallerOid = identity_claim_oid_g,
          SecretUri = requestUri_s,
          CallerIp = CallerIpAddress
| join kind=inner ListEvents on CallerOid, Vault
| where GetTime > ListTime and GetTime < ListTime + 10m
| summarize
    SecretGetCount = count(),
    Secrets = make_set(SecretUri),
    FirstGet = min(GetTime),
    LastGet = max(GetTime)
    by CallerOid, CallerUpn, AppId, Vault, CallerIp, ListTime
| where SecretGetCount >= 2
| order by ListTime desc
```

---

### Query 2 — High Volume of Secret Get Operations (Volume Anomaly)

Detects any caller retrieving an abnormally high number of secrets within an hour — consistent with automated credential harvesting.

```kusto
AzureDiagnostics
| where TimeGenerated > ago(24h)
| where ResourceProvider == "MICROSOFT.KEYVAULT"
| where OperationName == "SecretGet"
| where ResultType == "Success"
| summarize
    SecretGetCount = count(),
    SecretUris = make_set(requestUri_s),
    Vaults = make_set(Resource),
    IPs = make_set(CallerIpAddress),
    ClientInfos = make_set(clientInfo_s)
    by identity_claim_oid_g, identity_claim_upn_s, identity_claim_appid_g,
       bin(TimeGenerated, 1h)
| where SecretGetCount > 10
| order by SecretGetCount desc
```

---

### Query 3 — VaultPut (Policy Change) Followed by SecretGet

Detects the pattern where an attacker modifies vault configuration (`VaultPut`) — either to add themselves to an access policy or to change RBAC settings — and then immediately reads secrets.

```kusto
let PolicyChanges = AzureDiagnostics
    | where ResourceProvider == "MICROSOFT.KEYVAULT"
    | where OperationName == "VaultPut"
    | where ResultType == "Success"
    | project ChangeTime = TimeGenerated, Vault = Resource,
              CallerOid = identity_claim_oid_g,
              CallerUpn = identity_claim_upn_s,
              CallerIp = CallerIpAddress;

AzureDiagnostics
| where ResourceProvider == "MICROSOFT.KEYVAULT"
| where OperationName in ("SecretGet", "SecretList", "KeyGet")
| where ResultType == "Success"
| project AccessTime = TimeGenerated, Vault = Resource,
          CallerOid = identity_claim_oid_g,
          Operation = OperationName,
          SecretUri = requestUri_s,
          CallerIp = CallerIpAddress
| join kind=inner PolicyChanges on CallerOid, Vault
| where AccessTime > ChangeTime and AccessTime < ChangeTime + 30m
| project ChangeTime, AccessTime, Vault, CallerOid, CallerUpn = CallerUpn,
          Operation, SecretUri, CallerIp
| order by ChangeTime desc
```

---

### Query 4 — Access from Unexpected Caller IP or New Client

Surfaces callers accessing a vault from an IP or user-agent not seen in the prior 14 days for that vault. Useful for identifying compromised service principals being replayed from attacker infrastructure.

```kusto
let Lookback = 14d;
let Recent = 1d;

let HistoricalCallers = AzureDiagnostics
    | where TimeGenerated between (ago(Lookback) .. ago(Recent))
    | where ResourceProvider == "MICROSOFT.KEYVAULT"
    | where ResultType == "Success"
    | distinct Resource, identity_claim_oid_g, CallerIpAddress;

AzureDiagnostics
| where TimeGenerated > ago(Recent)
| where ResourceProvider == "MICROSOFT.KEYVAULT"
| where ResultType == "Success"
| where OperationName in ("SecretGet", "SecretList", "KeyGet", "CertificateGet")
| join kind=leftanti HistoricalCallers
    on $left.Resource == $right.Resource,
       $left.identity_claim_oid_g == $right.identity_claim_oid_g,
       $left.CallerIpAddress == $right.CallerIpAddress
| project TimeGenerated, Resource, OperationName,
          identity_claim_oid_g, identity_claim_upn_s,
          identity_claim_appid_g, CallerIpAddress, clientInfo_s, requestUri_s
| order by TimeGenerated desc
```

---

### Query 5 — Failed Access Attempts (Access Denied Reconnaissance)

Repeated `403 Forbidden` or `401 Unauthorized` responses can indicate an attacker probing for a vault they don't yet have permissions to, or a stolen token that was successfully invalidated.

```kusto
AzureDiagnostics
| where TimeGenerated > ago(24h)
| where ResourceProvider == "MICROSOFT.KEYVAULT"
| where ResultType == "Failed"
| where httpStatusCode_d in (401, 403)
| summarize
    FailureCount = count(),
    Operations = make_set(OperationName),
    Vaults = make_set(Resource),
    IPs = make_set(CallerIpAddress)
    by identity_claim_oid_g, identity_claim_upn_s,
       identity_claim_appid_g, bin(TimeGenerated, 1h)
| where FailureCount > 5
| order by FailureCount desc
```

---

### Query 6 — SecretBackup Operations (Bulk Exfiltration Signal)

`SecretBackup` and `KeyBackup` are rarely used in normal operations and are high-fidelity signals for bulk credential exfiltration.

```kusto
AzureDiagnostics
| where TimeGenerated > ago(30d)
| where ResourceProvider == "MICROSOFT.KEYVAULT"
| where OperationName in ("SecretBackup", "KeyBackup", "CertificateBackup")
| where ResultType == "Success"
| project TimeGenerated, Resource, OperationName,
          identity_claim_oid_g, identity_claim_upn_s,
          identity_claim_appid_g, CallerIpAddress,
          clientInfo_s, requestUri_s
| order by TimeGenerated desc
```

---

## Microsoft Defender for Key Vault

**Defender for Key Vault** is a Microsoft Defender for Cloud plan that provides Azure-native behavioral analytics and threat intelligence for Key Vault data plane activity. It detects unusual and potentially harmful access patterns **without requiring custom queries** — using machine learning baselines and Microsoft Threat Intelligence.

### Enablement

1. **Microsoft Defender for Cloud** → **Environment settings** → Select subscription → **Defender plans** → Enable **Key Vault**
2. Alerts appear in: **Defender for Cloud** → **Security alerts**, and on the vault's **Security** page

### Alert Reference

| Alert ID | Description | MITRE Tactic | Severity |
|---|---|---|---|
| `KV_ListGetAnomaly` | **Suspicious secret listing and query** — `SecretList` followed by `SecretGet` for a user/principal that doesn't normally perform this pattern | Credential Access | Medium |
| `KV_PutGetAnomaly` | **Suspicious policy change and secret query** — `VaultPut` (policy change) followed by `SecretGet` | Credential Access | Medium |
| `KV_OperationVolumeAnomaly` | **High volume of operations** — anomalous number of Key Vault operations by a single identity | Credential Access | Medium |
| `KV_UserAnomaly` | **Unusual user accessed a key vault** — user that doesn't normally access this vault | Credential Access | Medium |
| `KV_AppAnomaly` | **Unusual application accessed a key vault** — service principal not normally seen accessing this vault | Credential Access | Medium |
| `KV_UserAppAnomaly` | **Unusual user-application pair accessed a key vault** — the combination of user + app is anomalous | Credential Access | Medium |
| `KV_AccountVolumeAnomaly` | **User accessed high volume of key vaults** — single principal accessing many vaults | Credential Access | Medium |
| `KV_SuspiciousIPAccess` | **Access from a suspicious IP** — Microsoft Threat Intelligence flagged the source IP | Credential Access | Medium |
| `KV_TORAccess` | **Access from a TOR exit node** — attacker anonymizing traffic | Credential Access | Medium |
| `KV_UnusualAccessSuspiciousIP` | **Unusual access from suspicious IP** — non-Microsoft IP combined with anomalous access pattern | Credential Access | Medium |
| `KV_OperationPatternAnomaly` | **Unusual operation pattern** — the sequence and type of operations is anomalous | Credential Access | Medium |
| `KV_UserAccessDeniedAnomaly` | **Unusual access denied — unusual user denied** | Initial Access, Discovery | Low |
| `KV_AccountVolumeAccessDeniedAnomaly` | **Unusual access denied — high-volume vault access denied** | Discovery | Low |
| `KV_SuspiciousIPAccessDenied` | **Denied access from suspicious IP** | Credential Access | Low |

Reference: [Alerts for Azure Key Vault](https://learn.microsoft.com/azure/defender-for-cloud/alerts-azure-key-vault)

### Responding to Defender for Key Vault Alerts

When a Defender for Key Vault alert fires:

1. **Identify the source** — Note the `Object ID` and `User Principal Name or IP` in the alert. Check if the traffic originated within your tenant.
2. **Do not dismiss based on familiarity** — even if you recognize the app or user, verify the activity was legitimate by contacting the owner. Stolen credentials appear as known identities.
3. **Investigate the scope** — Open the vault's **Security** page, select the alert, review the list of secrets accessed and timestamps. Cross-reference with `AzureDiagnostics` using the caller's IP and Object ID.
4. **Rotate affected secrets** — Any secret confirmed or suspected as accessed should be rotated immediately.
5. **Restrict access** — Enable the Key Vault firewall, remove suspicious RBAC assignments, or disable the compromised identity.

Reference: [Respond to Microsoft Defender for Key Vault alerts](https://learn.microsoft.com/azure/defender-for-cloud/defender-for-key-vault-introduction#respond-to-microsoft-defender-for-key-vault-alerts)

---

## Correlating with AzureActivity (Control Plane RBAC Changes)

New RBAC role assignments on a vault are **control plane events** — they appear in `AzureActivity`, not `AzureDiagnostics`. Always check for RBAC escalation alongside data plane logs:

```kusto
AzureActivity
| where TimeGenerated > ago(7d)
| where OperationNameValue has "roleAssignments/write"
| where ResourceProviderValue == "Microsoft.KeyVault"
    or ResourceId has "/vaults/"
| project TimeGenerated, Caller, OperationNameValue,
          ResourceId, ActivityStatusValue, Properties
| order by TimeGenerated desc
```

---

## Microsoft Learn References

- [Azure Key Vault logging — field reference and operationName values](https://learn.microsoft.com/azure/key-vault/general/logging)
- [AzureDiagnostics table reference](https://learn.microsoft.com/azure/azure-monitor/reference/tables/azurediagnostics)
- [Monitor Key Vault with Azure Monitor](https://learn.microsoft.com/azure/key-vault/general/monitor-key-vault)
- [Microsoft Defender for Key Vault — overview](https://learn.microsoft.com/azure/defender-for-cloud/defender-for-key-vault-introduction)
- [Alerts for Azure Key Vault (full alert reference)](https://learn.microsoft.com/azure/defender-for-cloud/alerts-azure-key-vault)
- [Respond to Defender for Key Vault alerts](https://learn.microsoft.com/azure/defender-for-cloud/defender-for-key-vault-introduction#respond-to-microsoft-defender-for-key-vault-alerts)
- [Azure Key Vault access model — RBAC guide](https://learn.microsoft.com/azure/key-vault/general/rbac-guide)
- [Secure your Azure Key Vault](https://learn.microsoft.com/azure/key-vault/general/secure-key-vault)
- [Azure Monitor log queries for Key Vault](https://learn.microsoft.com/azure/key-vault/general/monitor-key-vault#analyzing-logs)

## Network Security
- Disable public network access and use **Private Endpoints** — [Private Link](https://learn.microsoft.com/azure/key-vault/general/private-link-service)
- Enable the **Key Vault firewall** and restrict to known IP ranges / virtual networks
- Consider Network Security Perimeter for PaaS isolation — [Network security](https://learn.microsoft.com/azure/key-vault/general/network-security)

## Data Protection
- Enable **soft delete** (7–90 day retention) and **purge protection** — [Soft delete overview](https://learn.microsoft.com/azure/key-vault/general/soft-delete-overview)
- Configure **autorotation** for keys, secrets, and certificates — [Key autorotation](https://learn.microsoft.com/azure/key-vault/keys/how-to-configure-key-rotation)
- Use one Key Vault per application, region, and environment to minimize blast radius

## Logging & Threat Detection
- Enable **audit logging** via Diagnostic Settings (category: `AuditEvent` / `allLogs`) — [Key Vault logging](https://learn.microsoft.com/azure/key-vault/general/logging)
- Enable **Microsoft Defender for Key Vault** — [Defender for Key Vault](https://learn.microsoft.com/azure/defender-for-cloud/defender-for-key-vault-introduction)
- Set up **log alerts** for critical events (access failures, secret deletions) — [Monitoring and alerting](https://learn.microsoft.com/azure/key-vault/general/alert)
- Integrate with **Event Grid** for near-real-time notifications on key/secret/cert changes

## Log Analytics Tables

| Table | Purpose |
|---|---|
| `AZKVAuditLogs` | Key Vault data-plane audit operations (recommended) |
| `AzureDiagnostics` | Multi-resource table; filter by `ResourceProvider == "MICROSOFT.KEYVAULT"` |
| `AzureActivity` | Management-plane operations (RBAC changes, vault creation/deletion) |

## Compliance & Governance
- Use **Azure Policy** to enforce diagnostic settings and secure configuration at scale — [Policy built-ins](https://learn.microsoft.com/azure/key-vault/policy-reference)
- Audit key expiration dates and rotation compliance via built-in policy definitions

## Microsoft Learn References
- [Secure your Azure Key Vault](https://learn.microsoft.com/azure/key-vault/general/secure-key-vault)
- [Azure Key Vault security baseline](https://learn.microsoft.com/security/benchmark/azure/baselines/key-vault-security-baseline)
- [Best practices for protecting secrets](https://learn.microsoft.com/azure/security/fundamentals/secrets-best-practices)