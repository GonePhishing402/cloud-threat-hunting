## Slide 1: Azure Key Vault Abuse

Module 06 — Secret Enumeration, RBAC Exploitation, and Data Plane Detection

**Speaker Notes:**
Welcome to Module 06. Key Vault is one of the highest-value targets in Azure — it stores secrets, certificates, keys, and connection strings that unlock access to other services. Attackers who gain Key Vault access can extract credentials that enable lateral movement across the entire environment. The detection challenge is the control plane vs. data plane split — AzureActivity captures RBAC changes, but AzureDiagnostics captures the actual secret reads.

## Slide 2: Agenda

- Module Objective and MITRE ATT&CK Mapping
- Key Vault Attack Surface: Control Plane vs. Data Plane
- RBAC Roles Attackers Abuse
- Attack Pattern: SecretList to SecretGet
- Enabling Key Vault Diagnostic Logging
- KQL Detection Queries
- Defender for Key Vault Alerts
- Incident Response
- Hardening Controls

**Speaker Notes:**
This module follows the same two-plane pattern as Module 04 (Storage). Key Vault has a control plane (manage vault configuration, RBAC) and a data plane (read secrets, keys, certificates). An attacker needs both: control plane access to enumerate vaults and check permissions, then data plane access to read the actual secrets. The detection queries focus on AzureDiagnostics for data plane operations, particularly the SecretList followed by SecretGet pattern that indicates secret enumeration and extraction.

## Slide 3: Objective and MITRE Mapping

!layout: Title and Content

**Objective:** Hunt for unauthorized Key Vault access, secret enumeration and extraction, and RBAC policy manipulation. Detect the SecretList-to-SecretGet pattern and volume anomalies.

| Technique | ID | Tactic |
|---|---|---|
| Unsecured Credentials | T1552 | Credential Access |
| Valid Accounts: Cloud Accounts | T1078.004 | Persistence, Defense Evasion |
| Account Manipulation | T1098 | Persistence |
| Exfiltration Over Web Service | T1567 | Exfiltration |
| Steal Application Access Token | T1528 | Credential Access |

**Speaker Notes:**
Key Vault abuse maps to five MITRE techniques. T1552 covers the credential extraction — reading secrets and certificates. T1078.004 covers using stolen identities to access the vault. T1098 covers RBAC manipulation to grant or escalate Key Vault access. T1528 covers certificate theft, which enables service principal authentication as we learned in Module 05.

## Slide 4: Control Plane vs. Data Plane

!layout: Title and Content

**Control Plane (AzureActivity):**
- List Key Vaults in a subscription
- Manage RBAC role assignments on vaults
- Create/delete vaults and access policies
- Always logged — no additional configuration needed

**Data Plane (AzureDiagnostics):**
- Read secrets: SecretGet, SecretList
- Read keys: KeySign, KeyDecrypt, KeyGet
- Read certificates: CertificateGet
- Requires diagnostic logging enabled per vault

**The attack pattern:** Control plane access to find and scope vaults, then data plane access to extract secrets.

**Two access models:** RBAC-based (recommended) and legacy Access Policies (vault-level)

**Speaker Notes:**
Just like Storage, Key Vault has two planes. The control plane tells you who has access and how they got it. The data plane tells you what they actually read. Without diagnostic logging, you can see that someone was granted Key Vault Secrets User but NOT that they read 50 secrets in 2 minutes. The two access models — RBAC and Access Policies — determine how permissions are granted. RBAC is the modern approach and is auditable in AzureActivity. Legacy Access Policies are harder to monitor. Encourage students to migrate to RBAC-based access if they haven't already.

## Slide 5: RBAC Roles Attackers Abuse

!layout: Title and Content

| Role | Data Plane Access | Attack Value |
|---|---|---|
| Key Vault Administrator | Full (secrets, keys, certificates) | Complete vault control |
| Key Vault Secrets Officer | Read/write/delete secrets | Full secret extraction |
| Key Vault Secrets User | Read secrets only | Secret extraction (most common target) |
| Key Vault Crypto Officer | Key operations (sign, decrypt, encrypt) | Cryptographic key abuse |
| Key Vault Certificate User | Read certificates | Certificate theft for SP auth |
| Key Vault Reader | List vaults and metadata only | Reconnaissance — no secret access |
| Contributor | Control plane only | Can modify RBAC but NOT read secrets directly |

**Key insight:** Contributor can grant themselves Key Vault Secrets User, then read all secrets. Control plane access enables data plane escalation.

**Speaker Notes:**
This table shows the RBAC hierarchy. The critical insight is that Contributor — one of the most commonly assigned roles — doesn't have direct data plane access, but can grant it to themselves by creating a role assignment. This is a common escalation path: an attacker with Contributor creates a role assignment granting themselves Key Vault Secrets User, then reads all secrets. The detection for this is a roleAssignments/write in AzureActivity followed by SecretGet operations in AzureDiagnostics.

## Slide 6: Attack Pattern — Secret Enumeration and Extraction

!layout: Title and Content

**Typical attacker sequence:**
- Enumerate Key Vaults: `az keyvault list`
- Check own permissions: `az role assignment list --assignee <self>`
- List all secrets in vault: SecretList operation
- Read each secret value: SecretGet for each secret
- Export certificates as PFX for lateral movement

**High-signal indicators:**
| Indicator | Source | Severity |
|---|---|---|
| SecretList followed by multiple SecretGet within minutes | AzureDiagnostics | High |
| User account performing SecretGet (not service principal) | AzureDiagnostics | High |
| SecretGet from IP not in vault's allowed network | AzureDiagnostics | High |
| roleAssignments/write on Key Vault scope | AzureActivity | High |
| SecretBackup operation | AzureDiagnostics | Critical |

**Speaker Notes:**
The SecretList-to-SecretGet pattern is the signature of Key Vault enumeration. A legitimate application typically reads one or two specific secrets it needs. An attacker lists all secrets first, then reads each one. SecretBackup is the most critical operation — it exports the secret in a portable format. If you see SecretBackup in your logs, investigate immediately. User accounts performing SecretGet are also suspicious — most secret access should come from service principals or managed identities in production.

## Slide 7: KQL — Secret Dump Pattern Detection

!layout: Title and Content

```kql
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.KEYVAULT"
| where TimeGenerated > ago(7d)
| where OperationName in (
    "SecretList", "SecretGet", "SecretBackup")
| where ResultType == "Success"
| summarize
    Operations = make_set(OperationName),
    OpCount = count(),
    SecretNames = make_set(id_s),
    IPs = make_set(CallerIPAddress)
    by identity_claim_upn_s,
    Resource, bin(TimeGenerated, 15m)
| where OpCount > 5
    and Operations has "SecretList"
    and Operations has "SecretGet"
| order by OpCount desc
```

**What this detects:** SecretList followed by multiple SecretGet operations within 15 minutes — the signature pattern of secret enumeration and extraction.

**Speaker Notes:**
This is the primary Key Vault abuse detection query. It aggregates secret operations by user and vault in 15-minute windows. The filter requires both SecretList AND SecretGet in the same window — this eliminates normal application access patterns that typically just perform SecretGet for known secrets. The OpCount > 5 threshold is conservative — adjust based on your environment. The identity_claim_upn_s field shows the user, and the CallerIPAddress shows the source. SecretNames shows which secrets were accessed.

## Slide 8: KQL — Volume Anomaly and Unexpected Caller Detection

!layout: Title and Content

**Volume anomaly (baseline comparison):**
```kql
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.KEYVAULT"
| where TimeGenerated > ago(24h)
| where OperationName == "SecretGet"
| where ResultType == "Success"
| summarize DailyCount = count()
    by identity_claim_upn_s, Resource
| join kind=leftanti (
    AzureDiagnostics
    | where ResourceProvider == "MICROSOFT.KEYVAULT"
    | where TimeGenerated between(ago(30d)..ago(1d))
    | where OperationName == "SecretGet"
    | summarize by identity_claim_upn_s, Resource
) on identity_claim_upn_s, Resource
| order by DailyCount desc
```

**What this detects:** Users or SPs accessing Key Vault secrets for the first time in the last 24 hours compared to a 30-day baseline.

**Speaker Notes:**
This query uses a leftanti join to find callers who accessed secrets today but never in the previous 30 days. These are first-time callers and the highest-priority triage targets. In a well-managed environment, the set of identities accessing each vault is relatively stable. A new identity appearing is either a legitimate deployment change or an attacker. The DailyCount shows how aggressively the new caller is reading secrets.

## Slide 9: KQL — RBAC Escalation to Secret Access

!layout: Title and Content

```kql
AzureActivity
| where TimeGenerated > ago(7d)
| where OperationNameValue ==
    "Microsoft.Authorization/roleAssignments/write"
| where ActivityStatusValue == "Success"
| where _ResourceId has "Microsoft.KeyVault"
| project TimeGenerated, Caller, CallerIpAddress,
          _ResourceId
| order by TimeGenerated desc
```

**Correlate with subsequent secret access:**
```kql
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.KEYVAULT"
| where TimeGenerated > ago(7d)
| where OperationName == "SecretGet"
| where ResultType == "Success"
| project TimeGenerated, identity_claim_upn_s,
          CallerIPAddress, Resource, id_s
| order by TimeGenerated desc
```

**Pattern:** RBAC grant followed by secret access from the same identity = privilege escalation.

**Speaker Notes:**
This two-query pattern detects the escalation path: an attacker grants themselves Key Vault data plane access (roleAssignments/write), then reads secrets (SecretGet). Run both queries and correlate the Caller from AzureActivity with the identity_claim_upn_s from AzureDiagnostics. If the same identity appears in both within a short window, you've confirmed a privilege escalation attack. This is one of the most reliable detection patterns for Key Vault abuse.

## Slide 10: Defender for Key Vault Alerts

!layout: Title and Content

| Alert | Severity | What It Detects |
|---|---|---|
| Access from suspicious IP | High | Key Vault access from known malicious IPs |
| Unusual secret listing | Medium | Anomalous SecretList patterns |
| Suspicious secret access volume | High | Bulk secret reads in short window |
| Access policy change | Medium | Vault access policy modification |
| Unusual application accessing vault | Medium | First-time application access |
| Access from Tor exit node | High | Key Vault access via Tor anonymization |
| Suspicious operation pattern | High | Combination of list + get + export operations |

**Enable Defender for Key Vault** for automated detection — covers patterns that are difficult to detect with static KQL rules alone.

**Speaker Notes:**
Defender for Key Vault provides ML-based anomaly detection on top of your KQL hunting queries. The "unusual secret listing" and "suspicious secret access volume" alerts specifically target the enumeration patterns we've been discussing. Enable Defender for Key Vault at the subscription level. The alerts feed into Defender for Cloud and can trigger Sentinel incidents.

## Slide 11: Incident Response and Hardening

!layout: Title and Content

**Immediate Response:**
- Identify the compromised identity and revoke its access
- Rotate all secrets in affected vault(s)
- Review vault access policies and RBAC assignments
- Check for SecretBackup operations (portable secret export)
- Rotate downstream credentials (connection strings, API keys stored as secrets)

**Hardening Controls:**
| Control | What It Prevents |
|---|---|
| RBAC-based access (not Access Policies) | Granular, auditable permission management |
| Private endpoints + firewall | Network-level vault isolation |
| Purge protection + soft delete | Prevents permanent secret destruction |
| Diagnostic logging enabled | Ensures data plane visibility |
| Defender for Key Vault | Automated anomaly detection |
| Managed identities for secret access | Eliminates credential-based vault access |
| Secret rotation automation | Limits exposure window |

**Speaker Notes:**
The most critical response action is rotating all secrets in the affected vault. If an attacker read your secrets, assume they've been exfiltrated and treat them as compromised. Rotate everything: database connection strings, API keys, certificates, and any downstream credentials. For hardening, RBAC-based access is mandatory — it provides granular permissions that are auditable in AzureActivity. Private endpoints eliminate network-level exposure. Managed identities for secret access eliminate the need for service principal credentials to access the vault.

## Slide 12: Key Takeaways and References

!layout: Title and Content

- Key Vault has control plane (AzureActivity) and data plane (AzureDiagnostics) — both must be monitored
- SecretList followed by SecretGet is the signature pattern of secret enumeration
- First-time callers accessing secrets are the highest-priority anomaly signal
- Contributor can escalate to Key Vault data plane access via RBAC self-assignment
- Rotate ALL secrets after a confirmed vault compromise — assume everything was read

**References:**
| Resource | Link |
|---|---|
| Key Vault Security Overview | learn.microsoft.com/azure/key-vault/general/security-features |
| Key Vault Monitoring | learn.microsoft.com/azure/key-vault/general/monitor-key-vault |
| Defender for Key Vault | learn.microsoft.com/azure/defender-for-cloud/defender-for-key-vault-introduction |
| AzureDiagnostics Schema | learn.microsoft.com/azure/azure-monitor/reference/tables/azurediagnostics |
| Key Vault Best Practices | learn.microsoft.com/azure/key-vault/general/best-practices |

**Speaker Notes:**
Module 06 builds directly on Module 05 — the service principal credentials stored in Key Vault are exactly what attackers extracted using the persistence techniques we covered. Encourage students to verify diagnostic logging is enabled on all production Key Vaults. Module 07 moves to Container Apps — where attackers use exec access and managed identity tokens for lateral movement.
