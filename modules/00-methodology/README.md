# Module 00 — Threat Hunt Methodology

## What Is Threat Hunting?

Threat hunting is the proactive, human-led process of searching through data to detect adversarial activity that has evaded automated detections. Unlike alert-driven response, hunting starts with a **hypothesis** — a testable prediction about how an attacker might behave in your environment — and then queries the data to prove or disprove it.

Effective hunters:
- Assume compromise and work to find evidence of it
- Follow the data, not just the alerts
- Build institutional knowledge from every hunt (successful or not)
- Convert confirmed findings into durable analytics rules

---

## The Hunt Loop

```
Hypothesis → Data Collection → Investigation → Finding → Feedback
     ↑                                                        |
     └────────────────────────────────────────────────────────┘
```

| Phase | Description |
|---|---|
| **Hypothesis** | Form a testable prediction grounded in threat intel, MITRE ATT&CK, or environmental anomaly |
| **Data Collection** | Identify which Sentinel tables hold relevant evidence; validate log coverage |
| **Investigation** | Write KQL queries, pivot on entities, reconstruct timelines |
| **Finding** | Document confirmed malicious or suspicious activity; escalate if needed |
| **Feedback** | Promote confirmed hunts to analytics rules; update threat model |

---

## Starting Point: Find a User's Footprint Across All Tables

When you receive a lead — a username, an IP, an email address — the first step is to determine which log tables contain activity for that indicator. Rather than querying each table individually, use the `search` operator to scan across the entire workspace at once.

### Discover which tables contain a user's activity

```kusto
search "jsmith@contoso.com"
| summarize count() by $table
| sort by count_ desc
```

> `$table` is a special built-in column that returns the name of the table each result came from. See [search operator — Microsoft Learn](https://learn.microsoft.com/en-us/kusto/query/search-operator?view=microsoft-sentinel).

This gives you a ranked list of every table with log entries mentioning that value. Use it to scope the rest of your hunt — focus your query effort on tables that actually have a footprint.

**Example output:**

| $table | count_ |
|---|---|
| SigninLogs | 47 |
| AzureActivity | 12 |
| MicrosoftGraphActivityLogs | 9 |
| CloudAppEvents | 5 |
| AADNonInteractiveUserSignInLogs | 3 |

### Search across a time window

```kusto
search in (SigninLogs, AzureActivity, CloudAppEvents) "jsmith@contoso.com"
| where TimeGenerated > ago(7d)
| summarize count() by $table, bin(TimeGenerated, 1h)
| sort by TimeGenerated asc
```

Scoping the `search` to specific tables once you have a footprint list improves performance and narrows the volume of results.

> Reference: [Threat hunting in Microsoft Sentinel — useful operators](https://learn.microsoft.com/en-us/azure/sentinel/hunting#useful-operators-and-functions)

---

## Drilling Into Tables

Once you know which tables hold the user's activity, pull the relevant records from each one and review them for suspicious patterns.

### Sign-in events

```kusto
SigninLogs
| where UserPrincipalName == "jsmith@contoso.com"
| where TimeGenerated > ago(7d)
| project TimeGenerated, IPAddress, Location, AppDisplayName,
          AuthenticationRequirement, ResultType, ResultDescription,
          ConditionalAccessStatus, UniqueTokenIdentifier, CorrelationId
| sort by TimeGenerated asc
```

### Azure control plane actions

```kusto
AzureActivity
| where Caller == "jsmith@contoso.com"
| where TimeGenerated > ago(7d)
| project TimeGenerated, OperationNameValue, ResourceGroup,
          ResourceId, ActivityStatus, CorrelationId
| sort by TimeGenerated asc
```

### Graph API calls (token abuse, data access)

```kusto
MicrosoftGraphActivityLogs
| where UserPrincipalName == "jsmith@contoso.com"
| where TimeGenerated > ago(7d)
| project TimeGenerated, RequestUri, ResponseStatusCode,
          IPAddress, UniqueTokenIdentifier
| sort by TimeGenerated asc
```

---

## Correlating Activity Using Key Fields

The power of multi-table hunting comes from joining events together through shared identifiers. The following fields are the most commonly used correlation anchors across Microsoft Sentinel data sources.

---

### `CorrelationId`

**Tables:** `SigninLogs`, `AADNonInteractiveUserSignInLogs`, `AzureActivity`

`CorrelationId` ties together all internal service calls that were initiated by a single authentication or Azure Resource Manager operation. In `AzureActivity` it groups the sub-operations of a single ARM request under one GUID. In `SigninLogs` it is set by the client at the start of an authentication attempt.

**Use it when:** You want to link an Azure resource operation (e.g., a Key Vault secret read) back to the sign-in that established the session, or to pull all sub-operations of a single ARM action.

```kusto
// Find the sign-in that corresponds to a suspicious AzureActivity event
let suspiciousCorrelationId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx";

AzureActivity
| where CorrelationId == suspiciousCorrelationId
| project TimeGenerated, OperationNameValue, Caller, ResourceId, ActivityStatus

| union (
    SigninLogs
    | where CorrelationId == suspiciousCorrelationId
    | project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, ResultType
)

| sort by TimeGenerated asc
```

> Reference: [AzureActivity table schema — CorrelationId](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/azureactivity#columns) — *"Events that share a correlationId belong to the same uber action."*

---

### `UniqueTokenIdentifier`

**Tables:** `SigninLogs`, `AADNonInteractiveUserSignInLogs`, `MicrosoftGraphActivityLogs`

`UniqueTokenIdentifier` is a base64-encoded identifier that tracks a specific issued token as it is redeemed at a resource provider. This is the primary field for detecting **token theft and replay** — if the same token value appears authenticating from two different IPs, or in Graph / resource activity after an anomalous sign-in, that is a strong indicator of access token theft.

**Use it when:** You see a suspicious sign-in or Graph API activity and want to confirm whether the same token was used across multiple requests or from unexpected locations.

```kusto
// Identify all activity tied to a specific access token
let tokenId = "BASE64ENCODEDVALUE==";

SigninLogs
| where UniqueTokenIdentifier == tokenId
| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName

| union (
    AADNonInteractiveUserSignInLogs
    | where UniqueTokenIdentifier == tokenId
    | project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName
)

| union (
    MicrosoftGraphActivityLogs
    | where UniqueTokenIdentifier == tokenId
    | project TimeGenerated, RequestUri, ResponseStatusCode, IPAddress
)

| sort by TimeGenerated asc
```

> Reference: [SigninLogs table schema — UniqueTokenIdentifier](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs#columns) — *"A unique base64 encoded request identifier used to track tokens issued by Azure AD as they are redeemed at resource providers."*

---

### `NetworkMessageId`

**Tables:** `EmailEvents`, `EmailUrlInfo`, `EmailAttachmentInfo`, `EmailPostDeliveryEvents`

`NetworkMessageId` is the Microsoft 365 internal identifier for a single email message. It is consistent across all tables that reference that message, making it the join key for email timeline reconstruction — delivery, URL clicks, attachment detonation, and post-delivery actions (e.g., ZAP).

**Use it when:** Investigating a phishing chain, you need to see everything that happened to or from a specific message: where it was delivered, which URLs it contained, what attachments were analyzed, and whether it was remediated after delivery.

```kusto
// Reconstruct the full timeline for a suspicious email
let msgId = "<insert NetworkMessageId>";

EmailEvents
| where NetworkMessageId == msgId
| project TimeGenerated, Subject, SenderFromAddress, RecipientEmailAddress,
          DeliveryAction, DeliveryLocation, ThreatTypes

| union (
    EmailUrlInfo
    | where NetworkMessageId == msgId
    | project TimeGenerated = ingestion_time(), Url, UrlCount
)

| union (
    EmailPostDeliveryEvents
    | where NetworkMessageId == msgId
    | project TimeGenerated, Action, ActionType, ActionResult, DeliveryLocation
)

| sort by TimeGenerated asc
```

> Reference: [EmailEvents table schema — NetworkMessageId](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/emailevents#columns) — *"Unique identifier for the email, generated by Office 365."*
>
> Also see: [Queries for the EmailUrlInfo table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/queries/emailurlinfo)

---

## Putting It Together: End-to-End Hunt Pattern

A complete hunt typically chains all three techniques:

1. **Surface footprint** — `search "indicator" | summarize by $table`
2. **Pull per-table records** — targeted queries per table with time filter
3. **Correlate** — join across tables using `CorrelationId`, `UniqueTokenIdentifier`, or `NetworkMessageId`

```kusto
// Step 1 — find all tables with this user's activity
search "jsmith@contoso.com"
| where TimeGenerated > ago(14d)
| summarize count() by $table
| sort by count_ desc
```

```kusto
// Step 2 — pull sign-in and Graph activity
let user = "jsmith@contoso.com";
let window = 14d;

SigninLogs
| where TimeGenerated > ago(window)
| where UserPrincipalName == user
| project TimeGenerated, IPAddress, Location, AppDisplayName,
          ResultType, UniqueTokenIdentifier, CorrelationId

| union (
    MicrosoftGraphActivityLogs
    | where TimeGenerated > ago(window)
    | where UserPrincipalName == user
    | project TimeGenerated, RequestUri, ResponseStatusCode,
              IPAddress, UniqueTokenIdentifier
)
| sort by TimeGenerated asc
```

```kusto
// Step 3 — pivot on a suspicious token to confirm replay
let suspiciousToken = "BASE64ENCODEDVALUE==";

SigninLogs
| where UniqueTokenIdentifier == suspiciousToken
| project TimeGenerated, UserPrincipalName, IPAddress, Location

| union (
    MicrosoftGraphActivityLogs
    | where UniqueTokenIdentifier == suspiciousToken
    | project TimeGenerated, RequestUri, IPAddress
)
| sort by TimeGenerated asc
```

---

## References

| Resource | URL |
|---|---|
| Threat hunting in Microsoft Sentinel | https://learn.microsoft.com/en-us/azure/sentinel/hunting |
| KQL `search` operator | https://learn.microsoft.com/en-us/kusto/query/search-operator?view=microsoft-sentinel |
| KQL `summarize` operator | https://learn.microsoft.com/en-us/kusto/query/summarize-operator?view=microsoft-sentinel |
| Common KQL tasks for Microsoft Sentinel | https://learn.microsoft.com/en-us/kusto/query/tutorials/common-tasks-microsoft-sentinel |
| SigninLogs table schema | https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs |
| AzureActivity table schema | https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/azureactivity |
| EmailEvents table schema | https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/emailevents |
| EmailUrlInfo query examples | https://learn.microsoft.com/en-us/azure/azure-monitor/reference/queries/emailurlinfo |
| MITRE ATT&CK Cloud Matrix | https://attack.mitre.org/matrices/enterprise/cloud/ |
