# Defend — Module 05 (Persistence via Identities)

Detection for the three persistence techniques in this module relies primarily on two Entra ID log sources: **`AADServicePrincipalSignInLogs`** (signs of a service principal authenticating) and **`AuditLogs`** (signs of an SP being created, or credentials being added).

---

## Key Tables

### `AADServicePrincipalSignInLogs`

Logs every non-interactive sign-in performed by a Service Principal or Managed Identity. This is the primary table for detecting **credential use** — catching a backdoor SP authenticating, a stolen certificate being replayed, or a managed identity token being used from an unexpected IP.

> Reference: [AADServicePrincipalSignInLogs schema — Microsoft Learn](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadserviceprincipalsigninlogs)

| Field | Type | Hunting Relevance |
|---|---|---|
| `ServicePrincipalId` | string | Object ID of the SP that signed in |
| `ServicePrincipalName` | string | Display name — watch for newly created / unfamiliar SPs |
| `AppId` | string | Application (client) ID |
| `IPAddress` | string | Source IP — pivot here for geo anomalies or datacenter vs. residential |
| `Location` | string | Country/region of sign-in |
| `LocationDetails` | string | City, state — flag sign-ins from unexpected regions |
| `ResultType` | string | `0` = success; non-zero = failure code |
| `ResultDescription` | string | Human-readable failure reason |
| `ClientCredentialType` | string | `clientCertificate`, `clientSecret`, `federatedIdentityCredential` — pivot on `clientCertificate` to detect PFX use |
| `ServicePrincipalCredentialKeyId` | string | Key ID of the credential used — correlate against known-good credential IDs |
| `ServicePrincipalCredentialThumbprint` | string | Certificate thumbprint used for auth — fingerprint the certificate found on disk |
| `ResourceDisplayName` | string | Resource the SP authenticated against (e.g., `Windows Azure Service Management API`, `Microsoft Graph`) |
| `FederatedCredentialId` | string | Populated when federated credential was used — flag unfamiliar issuer subjects |
| `UniqueTokenIdentifier` | string | Track token replay across AADServicePrincipalSignInLogs and downstream resource logs |
| `CorrelationId` | string | Tie this sign-in to downstream `AzureActivity` operations |
| `TimeGenerated` | datetime | All time-based analysis |

---

### `AuditLogs`

Records all control-plane operations on identities: creating app registrations, adding credentials, assigning roles, modifying permissions. This is the primary table for detecting **SP creation and credential staging** before the SP is ever used.

> Reference: [AuditLogs schema — Microsoft Learn](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/auditlogs)

| Field | Type | Hunting Relevance |
|---|---|---|
| `ActivityDisplayName` | string | Operation name — key values: `Add application`, `Add service principal`, `Add service principal credentials`, `Update application – Certificates and secrets management` |
| `AADOperationType` | string | `Add`, `Update`, `Delete` |
| `InitiatedBy` | dynamic | Who performed the operation — contains nested `user.userPrincipalName` or `app.displayName` |
| `TargetResources` | dynamic | What was modified — contains SP/app displayName, objectId, and modified properties |
| `Result` | string | `success` or `failure` |
| `LoggedByService` | string | `Core Directory` for most SP operations |
| `CorrelationId` | string | Optional client-set GUID — can tie audit events to a broader session |
| `ActivityDateTime` | datetime | Timestamp of the operation |
| `Identity` | string | Identity string from the token that made the request |

---

## Detection Queries

### 1 — New Service Principal Registrations

Detects new app registrations and service principal creation events. Focus on operations initiated by non-service-account users or applications.

```kusto
AuditLogs
| where ActivityDisplayName in (
    "Add application",
    "Add service principal"
  )
| where Result == "success"
| extend InitiatedByUser = tostring(parse_json(tostring(InitiatedBy)).user.userPrincipalName)
| extend InitiatedByApp  = tostring(parse_json(tostring(InitiatedBy)).app.displayName)
| extend TargetName      = tostring(parse_json(tostring(TargetResources))[0].displayName)
| extend TargetObjectId  = tostring(parse_json(tostring(TargetResources))[0].id)
| project ActivityDateTime, ActivityDisplayName,
          InitiatedByUser, InitiatedByApp,
          TargetName, TargetObjectId, CorrelationId
| sort by ActivityDateTime desc
```

**Triage signal:** A human user (not an automated provisioning pipeline) creating a new app registration with a generic / infrastructure-sounding name.

---

### 2 — Credential Additions to Service Principals

Detects when a certificate or client secret is added to an existing or newly created service principal.

```kusto
AuditLogs
| where ActivityDisplayName in (
    "Add service principal credentials",
    "Update application – Certificates and secrets management"
  )
| where Result == "success"
| extend InitiatedByUser = tostring(parse_json(tostring(InitiatedBy)).user.userPrincipalName)
| extend InitiatedByApp  = tostring(parse_json(tostring(InitiatedBy)).app.displayName)
| extend TargetName      = tostring(parse_json(tostring(TargetResources))[0].displayName)
| extend TargetObjectId  = tostring(parse_json(tostring(TargetResources))[0].id)
| extend ModifiedProps   = tostring(parse_json(tostring(TargetResources))[0].modifiedProperties)
| project ActivityDateTime, ActivityDisplayName,
          InitiatedByUser, InitiatedByApp,
          TargetName, TargetObjectId, ModifiedProps, CorrelationId
| sort by ActivityDateTime desc
```

**Triage signal:** Credentials added to an SP that was just created in the same session (same `CorrelationId` or within minutes) — classic backdoor staging sequence.

---

### 3 — Correlate SP Creation to First Sign-In

Chain the audit event (SP created) to the first sign-in from that SP within a hunting window. A backdoor SP authenticating soon after creation is a strong indicator.

```kusto
let newSPs = AuditLogs
| where ActivityDisplayName == "Add application"
| where Result == "success"
| extend AppId = tostring(parse_json(tostring(TargetResources))[0].id)
| extend SPName = tostring(parse_json(tostring(TargetResources))[0].displayName)
| project CreatedAt = ActivityDateTime, AppId, SPName;

AADServicePrincipalSignInLogs
| where ResultType == "0"  // successful sign-in only
| join kind=inner newSPs on $left.ServicePrincipalId == $right.AppId
| where TimeGenerated between (CreatedAt .. (CreatedAt + 48h))
| project TimeGenerated, SPName, ServicePrincipalId, IPAddress,
          Location, ClientCredentialType,
          ServicePrincipalCredentialThumbprint,
          ResourceDisplayName, CreatedAt
| sort by TimeGenerated asc
```

---

### 4 — Certificate-Based Sign-Ins from Unexpected Locations

Targets PFX/certificate credential use — especially from IPs that do not match known CI/CD infrastructure.

```kusto
AADServicePrincipalSignInLogs
| where ClientCredentialType == "clientCertificate"
| where ResultType == "0"
| summarize
    SignInCount  = count(),
    Locations    = make_set(Location),
    IPs          = make_set(IPAddress),
    Resources    = make_set(ResourceDisplayName),
    Thumbprints  = make_set(ServicePrincipalCredentialThumbprint)
    by ServicePrincipalName, ServicePrincipalId, bin(TimeGenerated, 1h)
| where array_length(Locations) > 1  // same SP signing in from multiple countries
   or array_length(IPs) > 2
| sort by TimeGenerated desc
```

To hunt for a **specific certificate thumbprint** found during forensics:

```kusto
let suspectThumbprint = "AABBCCDDEEFF1122334455667788990011223344";

AADServicePrincipalSignInLogs
| where ServicePrincipalCredentialThumbprint == suspectThumbprint
| project TimeGenerated, ServicePrincipalName, ServicePrincipalId,
          IPAddress, Location, ResourceDisplayName,
          ResultType, ResultDescription, UniqueTokenIdentifier
| sort by TimeGenerated asc
```

---

### 5 — Managed Identity Sign-Ins from Unexpected IPs

System-assigned managed identity tokens are acquired from the **local** runtime endpoint (`IDENTITY_ENDPOINT`) and should always originate from within Azure infrastructure IPs. A managed identity authenticating from a residential, Tor exit, or non-Azure IP indicates token theft and replay.

```kusto
AADServicePrincipalSignInLogs
| where AppId in (
    // Enumerate known managed identity client IDs from your environment, or:
    AADServicePrincipalSignInLogs
    | where ResourceDisplayName contains "Azure"
    | summarize by AppId  // rough filter; tune per environment
  )
| where ResultType == "0"
// Azure datacenter IP ranges will have AutonomousSystemNumber set to Microsoft ASNs
// Flag anything without a Microsoft-owned ASN or clearly residential
| where AutonomousSystemNumber !startswith "8075"   // Microsoft AS8075
      and AutonomousSystemNumber !startswith "8068"  // Microsoft AS8068
| project TimeGenerated, ServicePrincipalName, ServicePrincipalId,
          IPAddress, Location, AutonomousSystemNumber,
          ResourceDisplayName, UniqueTokenIdentifier
| sort by TimeGenerated desc
```

> **Note:** Tune the ASN filter to your environment. The primary Microsoft ASN is AS8075. You can also flag any IP outside known Azure IP ranges published at https://www.microsoft.com/en-us/download/details.aspx?id=56519.

---

### 6 — Role Assignment to Newly Created Service Principals

Detects role assignments targeting SPs that were created within the last 48 hours — a key step in backdoor SP operationalization.

```kusto
let recentSPs = AuditLogs
| where ActivityDisplayName == "Add application"
| where Result == "success"
| extend SPName = tostring(parse_json(tostring(TargetResources))[0].displayName)
| extend AppObjId = tostring(parse_json(tostring(TargetResources))[0].id)
| project CreatedAt = ActivityDateTime, SPName, AppObjId;

AzureActivity
| where OperationNameValue == "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE"
| where ActivityStatus == "Succeeded"
| extend AssigneePrincipalId = tostring(parse_json(tostring(Properties)).requestbody)
| join kind=inner recentSPs on $left.Caller == $right.AppObjId
    or tostring(Properties) contains AppObjId
| project TimeGenerated, Caller, OperationNameValue,
          ResourceGroup, SPName, CreatedAt, CorrelationId
| sort by TimeGenerated desc
```

---

## Detection Coverage Map

| Attack Technique | Primary Table | Key Fields | Query Above |
|---|---|---|---|
| PFX certificate used to authenticate | `AADServicePrincipalSignInLogs` | `ClientCredentialType`, `ServicePrincipalCredentialThumbprint` | #4 |
| Backdoor SP created | `AuditLogs` | `ActivityDisplayName`, `InitiatedBy`, `TargetResources` | #1 |
| Credential added to SP | `AuditLogs` | `ActivityDisplayName` = "Add service principal credentials" | #2 |
| Backdoor SP first use after creation | Both | `CorrelationId` join, `CreatedAt` + `TimeGenerated` delta | #3 |
| Role assigned to new SP | `AuditLogs` + `AzureActivity` | `ROLEASSIGNMENTS/WRITE` + new SP object ID | #6 |
| Managed identity token replayed off-host | `AADServicePrincipalSignInLogs` | `IPAddress`, `AutonomousSystemNumber` | #5 |

---

## References

| Resource | URL |
|---|---|
| AADServicePrincipalSignInLogs schema | https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadserviceprincipalsigninlogs |
| AuditLogs schema | https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/auditlogs |
| Workload identity risk detections (Entra ID Protection) | https://learn.microsoft.com/en-us/entra/id-protection/concept-workload-identity-risk |
| Securing service principals | https://learn.microsoft.com/en-us/entra/architecture/service-accounts-principal |
| App Service managed identity REST endpoint | https://learn.microsoft.com/en-us/azure/app-service/overview-managed-identity#rest-endpoint-reference |
