# Module 06 — Key Vault Threat Hunting CTF Challenges

> **Data source:** `modules/06-keyvault/emulated-data/` — ingest `AzureDiagnostics.json` and `SecurityAlert.json` into their matching ADX tables.  
> **Tables used:** `AzureDiagnostics`, `SecurityAlert`  
> **Total points available:** 1,300

---

## Scenario Background

NorthStar Technologies' production Key Vault, `kv-northstar-prod`, logs all operations to `AzureDiagnostics` via the `AzureKeyVault` diagnostic category. During the same window as the storage exfiltration, a service principal account performed rapid enumeration and bulk reads of production secrets — including database credentials, payment API keys, and an Azure AD client secret. Your job is to reconstruct the full attack sequence and correlate Defender for Key Vault alerts back to the raw vault audit trail.

---

### K-1 | Vault Recon
**Category:** `06-keyvault` | **Points:** 100 | **Difficulty:** 🟢 Easy

**Narrative:**  
Key Vault audit events land in `AzureDiagnostics` with `ResourceType == "VAULTS"`. Before an attacker reads any secrets, they typically call `VaultGet` to confirm the vault is accessible and gather its configuration. Find the identity behind that first call.

**Question:**  
Query `AzureDiagnostics` for Key Vault events (`ResourceType == "VAULTS"`, `Category == "AuditEvent"`). Find the `identity_claim_upn_s` value — the UPN of the **suspicious** calling identity. Submit it as your flag.

**KQL starting point:**
```kql
AzureDiagnostics
| where ResourceType == "VAULTS"
| where Category == "AuditEvent"
| summarize by identity_claim_upn_s, CallerIPAddress, identity_claim_oid_g
```

**Hint 1** (25 pts): Multiple service accounts appear in the logs alongside legitimate pipeline identities. The suspicious identity authenticates from a non-RFC1918, external IP address — use the `CallerIPAddress` column alongside `identity_claim_upn_s` to identify the attacker. The UPN is a service account in the `northstartech.com` domain.

**Flag:** `FLAG{svc-automation@northstartech.com}`

---

### K-2 | The Attacker's First Move
**Category:** `06-keyvault` | **Points:** 150 | **Difficulty:** 🟢 Easy

**Narrative:**  
Attackers who have compromised a service principal credential typically perform a vault-level read before targeting individual secrets. This single request confirms the vault exists and is accessible — and it shows up in the audit log before any `SecretGet` operations.

**Question:**  
Filter `AzureDiagnostics` to Key Vault audit events and sort ascending by `TimeGenerated`. What is the `OperationName` of the **first** recorded action? Submit it as your flag.

**KQL starting point:**
```kql
AzureDiagnostics
| where ResourceType == "VAULTS"
| where Category == "AuditEvent"
| order by TimeGenerated asc
| project TimeGenerated, OperationName, CallerIPAddress, ResultType
```

**Hint 1** (25 pts): The first operation reads vault-level metadata, not an individual secret. Its name reflects reading the vault object itself.

**Flag:** `FLAG{VaultGet}`

---

### K-3 | Secret Sweep
**Category:** `06-keyvault` | **Points:** 150 | **Difficulty:** 🟢 Easy

**Narrative:**  
After confirming vault access, the attacker enumerated all secret names with a `SecretList` call, then fetched each one individually using `SecretGet`. Counting those reads gives you the exact number of secrets exposed.

**Question:**  
Query `AzureDiagnostics` for `OperationName == "SecretGet"` on the `VAULTS` resource type. How many `SecretGet` operations were successfully performed? Submit the count as your flag.

**KQL starting point:**
```kql
AzureDiagnostics
| where ResourceType == "VAULTS"
| where OperationName == "SecretGet"
| where ResultType == "Success"
| count
```

**Hint 1** (25 pts): Each row is one secret read. Count all rows where `ResultType == "Success"`.

**Flag:** `FLAG{5}`

---

### K-4 | Identity Behind the Token
**Category:** `06-keyvault` | **Points:** 200 | **Difficulty:** 🟡 Medium

**Narrative:**  
When hunting compromised service principals, the Object ID (OID) is a more reliable identifier than the UPN — it cannot be renamed or aliased. Extracting the OID from the vault audit log gives you a stable pivot point for correlating activity across Azure AD, storage logs, and other telemetry.

**Question:**  
Extract the `identity_claim_oid_g` (Object ID GUID) of the **attacker's** calling identity from the Key Vault audit events. Submit the full GUID as your flag.

**KQL starting point:**
```kql
AzureDiagnostics
| where ResourceType == "VAULTS"
| where Category == "AuditEvent"
| summarize by identity_claim_oid_g, CallerIPAddress, identity_claim_upn_s
```

**Hint 1** (50 pts): Multiple Object IDs are present across service accounts. Correlate to the external attacker IP identified in K-1 to isolate the correct OID. The attacker's GUID begins with `3bc4`.

**Flag:** `FLAG{3bc4dd12-7f9a-4e8b-b0c3-2a6d5f8c9e1b}`

---

### K-5 | Last Secret Out the Door
**Category:** `06-keyvault` | **Points:** 200 | **Difficulty:** 🟡 Medium

**Narrative:**  
The last secret accessed before the session ended is often the highest-value target — an attacker who maintained access long enough to reach it likely took everything above it too. Parse the secret name out of the `id_s` URI field from the final `SecretGet` event.

**Question:**  
Filter `AzureDiagnostics` to `OperationName == "SecretGet"`, sort descending by `TimeGenerated`, and extract the secret name from `id_s`. The URI format is `https://<vault>.vault.azure.net/secrets/<name>/current`. Submit the secret name as your flag.

**KQL starting point:**
```kql
AzureDiagnostics
| where ResourceType == "VAULTS"
| where OperationName == "SecretGet"
| order by TimeGenerated desc
| extend SecretName = tostring(split(id_s, "/")[-2])
| project TimeGenerated, SecretName, id_s
| take 1
```

**Hint 1** (50 pts): Split `id_s` on `/` and take the second-to-last element. The secret name suggests it could be used to access a secondary storage resource.

**Flag:** `FLAG{backup-storage-access-key}`

---

### K-6 | Defender's Verdict
**Category:** `06-keyvault` | **Points:** 200 | **Difficulty:** 🟡 Medium

**Narrative:**  
Microsoft Defender for Key Vault fired two alerts during this incident. A complete investigation requires correlating `SecurityAlert` events back to the underlying `AzureDiagnostics` audit trail — linking the detection to the raw telemetry that triggered it. This join is how you confirm alert accuracy and close the loop in an IR timeline.

**Question:**  
Query `SecurityAlert` filtered to `ProviderName contains "Key Vault"`. Join it against `AzureDiagnostics` using the vault resource path — `ResourceId` in `SecurityAlert` should match `_ResourceId` in `AzureDiagnostics`. Return the `AlertName` and `AlertSeverity` for both alerts. How many distinct alerts fired? Submit the count as your flag.

**KQL starting point:**
```kql
let KVAlerts = SecurityAlert
    | where ProviderName has "Key Vault"
    | project AlertName, AlertSeverity, AlertType, ResourceId, StartTime, EndTime;
let KVDiag = AzureDiagnostics
    | where ResourceType == "VAULTS"
    | summarize by _ResourceId;
KVAlerts
| join kind=inner KVDiag on $left.ResourceId == $right._ResourceId
| project AlertName, AlertSeverity, AlertType, StartTime, EndTime
```

**Hint 1** (50 pts): Both alerts target the same vault. After the join, count the rows or `dcount(AlertName)` to get the alert count. There are fewer than three.

**Flag:** `FLAG{2}`

---

### K-7 | How Fast Was the Sweep?
**Category:** `06-keyvault` | **Points:** 300 | **Difficulty:** 🔴 Hard

**Narrative:**  
Security alert metadata often contains pre-computed analytics that aren't easily derived from raw logs alone. The Defender for Key Vault alert embeds the time window (in seconds) over which the suspicious secret reads occurred — a key metric for distinguishing automated tooling from manual access. Extract it by parsing the `ExtendedProperties` JSON.

**Question:**  
Query `SecurityAlert` for the High severity Defender for Key Vault alert. Parse `ExtendedProperties` and extract the `Time window (seconds)` value. Submit it as your flag.

**KQL starting point:**
```kql
SecurityAlert
| where ProviderName has "Key Vault"
| where AlertSeverity == "High"
| extend Props = parse_json(ExtendedProperties)
| project AlertName,
          TimeWindowSec    = Props["Time window (seconds)"],
          SecretsAccessed  = Props["Number of secrets accessed"],
          AccessedNames    = Props["Accessed secrets"]
```

**Hint 1** (75 pts): Use `parse_json()` on `ExtendedProperties`, then access the key with bracket notation. The result is a two-digit number. You can verify it by comparing `max(TimeGenerated) - min(TimeGenerated)` across the `SecretGet` events in `AzureDiagnostics`.

**Hint 2** (100 pts): Manually calculate: the `SecretList` fired at `14:40:28` and the last `SecretGet` was at `14:41:14`. The difference in seconds matches the value stored in the alert.

**Flag:** `FLAG{46}`
