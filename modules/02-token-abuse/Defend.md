# Defend: Module 02 — Cloud Token Abuse Detection

## Overview

Token theft and FOCI replay attacks are nearly invisible in interactive sign-in logs because the attacker **never triggers an interactive authentication**. The primary detection surface is the **`AADNonInteractiveUserSignInLogs`** table in Microsoft Sentinel / Log Analytics. This table captures every token refresh, silent re-authentication, and background Graph/Exchange sign-in — precisely where stolen refresh token abuse appears.

---

## `AADNonInteractiveUserSignInLogs` — Detection Foundation

**What it captures:** Sign-ins done on behalf of a user by a client app using a cached token, refresh token, or silent auth flow. Device or client uses a token or code to authenticate or access a resource. The user is not prompted.

Reference: [What are the identity logs you can stream to an endpoint?](https://learn.microsoft.com/entra/identity/monitoring-health/concept-diagnostic-settings-logs-options#activity-log-options)

### Key Fields for Token Abuse Detection

| Field | Type | Why It Matters |
|---|---|---|
| `ResourceDisplayName` | string | The resource the token was presented to — e.g., `"Microsoft Graph"`, `"Office 365 Exchange Online"`, `"Azure Resource Manager"`, `"Windows Azure Service Management API"`. A single victim account appearing across multiple resources in seconds indicates FOCI pivoting. |
| `AppDisplayName` | string | The client app that initiated the sign-in — e.g., `"Azure CLI"`, `"Microsoft Office"`, `"Graph Explorer"`. An unexpected app (e.g., Azure CLI authenticating a user who only uses browser apps) is a strong signal. |
| `ClientAppUsed` | string | Category of client: `"Browser"`, `"Native App"`, `"Mobile Apps and Desktop clients"`, `"Older Clients"`. GraphSpy using Python HTTP libraries may appear as `"Other clients"` or `"Native App"`. |
| `AuthenticationProtocol` | string | The grant type: `oAuth2`, `ropc`, `deviceCode`. Normal browser sessions show `oAuth2`. |
| `IncomingTokenType` | string | **Critical field.** The type of token used to initiate the sign-in: `primaryRefreshToken`, `refreshToken`, `saml20Assertion`. A value of `refreshToken` means a previously issued refresh token was replayed — not a fresh authentication. |
| `SignInEventTypes` | string | Classifies the sign-in event: `"interactive"`, `"refreshToken"`, `"managedIdentity"`, `"continuousAccessEvaluation"`. A value of `"refreshToken"` confirms non-interactive refresh token usage — the attacker's primary mechanism. |
| `UserAgent` | string | The HTTP User-Agent string. Legitimate Azure CLI sends `python-requests/<version>`. GraphSpy also uses Python HTTP libraries. Mismatches between the `AppDisplayName` and the `UserAgent` are strong anomaly signals. |
| `IPAddress` | string | Attacker IP. In FOCI replay, the IP will differ from the victim's normal IP since the attack is run from a separate machine. |
| `LocationDetails` | string | Geographic details of the sign-in. Cross-country token replay is detectable here. |
| `RiskLevelDuringSignIn` | string | Entra ID Protection risk score at sign-in time: `none`, `low`, `medium`, `high`. |
| `RiskEventTypes_V2` | string | Named risk detections associated with this sign-in: `anomalousToken`, `unfamiliarFeatures`, `investigationsThreatIntelligence`. `anomalousToken` is triggered by Entra ID Protection when token characteristics are atypical. |
| `IsRisky` | bool | `true` if any risk detection is associated with the sign-in event. |
| `TokenProtectionStatusDetails` | string | Whether the token is cryptographically bound to the device (via Token Protection CA policy). Unbound tokens from Token Protection-enabled policies appear anomalous here. |
| `UserPrincipalName` | string | Account that owns the token. |
| `UserDisplayName` | string | Display name for correlation with other logs. |
| `CorrelationId` | string | Sign-in trail identifier for linking events across tables. |
| `CreatedDateTime` | datetime | Sign-in timestamp for timeline analysis. |

---

## KQL Detection Queries

### Query 1 — Detect Token Refresh Events Targeting Microsoft Graph

Flags non-interactive sign-ins where a refresh token (`IncomingTokenType = refreshToken`) is used to access Microsoft Graph — the primary GraphSpy target.

```kusto
AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(24h)
| where IncomingTokenType == "refreshToken"
| where ResourceDisplayName has_any ("Microsoft Graph", "Office 365 Exchange Online", "Azure Resource Manager")
| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName,
          ClientAppUsed, ResourceDisplayName, IncomingTokenType,
          SignInEventTypes, UserAgent, RiskLevelDuringSignIn, ResultType
| order by TimeGenerated desc
```

---

### Query 2 — FOCI Pivoting Detection (Multi-Resource Token Replay)

A single account accessing multiple distinct resources rapidly through non-interactive sign-ins is a key FOCI indicator. This query looks for accounts that authenticate non-interactively to 3 or more distinct resources within a 15-minute window.

```kusto
AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(24h)
| where IncomingTokenType == "refreshToken"
| where ResultType == 0  // Successful sign-ins only
| summarize
    ResourceCount = dcount(ResourceDisplayName),
    Resources = make_set(ResourceDisplayName),
    AppNames = make_set(AppDisplayName),
    IPs = make_set(IPAddress),
    UserAgents = make_set(UserAgent),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by UserPrincipalName, bin(TimeGenerated, 15m)
| where ResourceCount >= 3
| order by FirstSeen desc
```

---

### Query 3 — App ID / UserAgent Mismatch (GraphSpy / Tooling Detection)

Detects cases where the `AppDisplayName` (e.g., Azure CLI) is used from a `UserAgent` inconsistent with legitimate Azure CLI traffic. Legitimate `az cli` uses `python-requests`; GraphSpy and other token replay tools may show different patterns or no user agent.

```kusto
AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(24h)
| where IncomingTokenType == "refreshToken"
| where AppDisplayName has_any ("Azure CLI", "Microsoft Azure PowerShell", "Microsoft Office")
| where isnotempty(UserAgent)
| extend IsSuspiciousAgent = case(
    AppDisplayName == "Azure CLI" and UserAgent !startswith "python-requests", true,
    UserAgent has_any ("GraphSpy", "curl", "Postman", "Mozilla/4.0"), true,
    false
  )
| where IsSuspiciousAgent == true
| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName,
          UserAgent, ResourceDisplayName, SignInEventTypes, ResultType
| order by TimeGenerated desc
```

---

### Query 4 — Anomalous Token Risk Detections in Non-Interactive Logs

Surfaces non-interactive sign-ins where Entra ID Protection has flagged the event with `anomalousToken`, `unfamiliarFeatures`, or similar risk detections.

```kusto
AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(48h)
| where IsRisky == true
    or RiskLevelDuringSignIn in ("medium", "high")
    or RiskEventTypes_V2 has_any ("anomalousToken", "unfamiliarFeatures", "investigationsThreatIntelligence")
| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName,
          ResourceDisplayName, IncomingTokenType, SignInEventTypes,
          RiskLevelDuringSignIn, RiskEventTypes_V2, ResultType
| order by TimeGenerated desc
```

---

### Query 5 — Non-Interactive PowerShell and Graph API Access Baseline

Builds a baseline of known non-interactive Graph and PowerShell activity per user to identify new / unexpected access patterns.

```kusto
// Shows all non-interactive Graph and PowerShell resource access per user
// Use to identify unfamiliar AppDisplayName or ResourceDisplayName for a user
AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(7d)
| where ResourceDisplayName has_any (
    "Microsoft Graph",
    "Office 365 Exchange Online",
    "Windows Azure Service Management API",
    "Azure Resource Manager",
    "Microsoft 365 Management APIs"
  )
| where ResultType == 0
| summarize
    SignInCount = count(),
    UniqueIPs = dcount(IPAddress),
    UniqueApps = dcount(AppDisplayName),
    AppList = make_set(AppDisplayName),
    ResourceList = make_set(ResourceDisplayName),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
  by UserPrincipalName
| order by UniqueApps desc
```

---

## Entra ID Protection — Relevant Detections

| Detection Name | Trigger | Relevance |
|---|---|---|
| **Anomalous Token** | Atypical token characteristics; token used from unfamiliar location | Fires on token replay attacks |
| **Unfamiliar Sign-in Properties** | Sign-in properties don't match history | Fires when attacker IP/UAG differs from victim baseline |
| **Unfamiliar Sign-in** | Non-interactive sign-in from unexpected context | Explicitly highlighted in the Token Theft Playbook as a key indicator |
| **Attacker in the Middle** | Correlated with AiTM proxy signals | Relevant when browser theft follows AiTM session |

Reference: [Token theft playbook — Investigation triggers](https://learn.microsoft.com/security/operations/token-theft-playbook#requirements)

---

## Correlating Across Tables

After identifying a suspicious non-interactive sign-in, pivot to:

```kusto
// Confirm downstream activity in CloudAppEvents after the suspicious sign-in
CloudAppEvents
| where AccountUpn == "<suspect-UPN>"
| where Timestamp > datetime(<suspicious-signin-time>)
| project Timestamp, AccountUpn, ActionType, Application, IPAddress, City, CountryCode, RawEventData
| order by Timestamp asc
```

```kusto
// Check interactive sign-ins from the same account for comparison
SigninLogs
| where UserPrincipalName == "<suspect-UPN>"
| where TimeGenerated > ago(7d)
| summarize
    min(TimeGenerated), max(TimeGenerated)
    by IPAddress, AppDisplayName, ResourceDisplayName
```

---

## Microsoft Learn References

- [AADNonInteractiveUserSignInLogs table schema](https://learn.microsoft.com/azure/azure-monitor/reference/tables/aadnoninteractiveusersigninlogs)
- [Non-interactive user sign-ins (concept)](https://learn.microsoft.com/entra/identity/monitoring-health/concept-noninteractive-sign-ins)
- [What are the identity logs you can stream to an endpoint?](https://learn.microsoft.com/entra/identity/monitoring-health/concept-diagnostic-settings-logs-options)
- [Token theft playbook — Investigation triggers](https://learn.microsoft.com/security/operations/token-theft-playbook)
- [Protecting tokens in Microsoft Entra — Detect and mitigate](https://learn.microsoft.com/entra/identity/devices/protecting-tokens-microsoft-entra-id#token-theft---detect-and-mitigate)
- [Risk detections reference — Anomalous Token](https://learn.microsoft.com/entra/id-protection/concept-identity-protection-risks)
