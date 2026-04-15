# Module 02 — Token Abuse in Azure

## Objective

Hunt for token theft and replay attacks in Azure AD. Students learn how OAuth tokens, refresh tokens, and Primary Refresh Tokens (PRTs) are abused to maintain persistent access without re-authenticating.

## Duration

~3 hours (lecture + hands-on labs)

## MITRE ATT&CK Mapping

| Technique | ID | Tactic |
|---|---|---|
| Steal Application Access Token | T1528 | Credential Access |
| Use Alternate Authentication Material | T1550 | Lateral Movement |
| Valid Accounts: Cloud Accounts | T1078.004 | Defense Evasion, Persistence |

## Sentinel Tables

- `SigninLogs` — Token issuance events
- `AADNonInteractiveUserSignInLogs` — Token refresh and silent sign-in events
- `AzureActivity` — Resource access using stolen tokens
- `MicrosoftGraphActivityLogs` — Graph API calls made with tokens (if enabled)

## Attack Narratives

### 1. OAuth/Refresh Token Replay

**Attack Flow:**
1. Attacker compromises endpoint or intercepts token (MITM, malware, memory dump)
2. Extracts access token and/or refresh token from browser cache, token cache files, or process memory
3. Replays token from attacker infrastructure to access cloud resources
4. Refresh token provides long-lived access (up to 90 days) without re-authentication

**Key Indicators:**
- Same user token used from drastically different IPs within short time window
- Non-interactive sign-ins from IPs that don't match the original token issuance IP
- Token refresh events from unusual user agents or OS platforms
- Resource access patterns inconsistent with user's role

### 2. Primary Refresh Token (PRT) Abuse

**Attack Flow:**
1. Attacker with local admin on Azure AD joined/registered device extracts PRT
2. Tools: ROADtools, AADInternals, Mimikatz (CloudAP plugin)
3. PRT used to request access tokens for any resource the user has access to
4. Can generate PRT cookies to bypass device compliance checks

**Key Indicators:**
- Sign-in events with `deviceTrustType` claims that don't match the actual device
- Token requests for resources the user has never accessed before
- PRT-based sign-ins from network locations inconsistent with the device's normal location
- Multiple resource access in rapid succession (token farming)

### 3. Access Token Extraction from Compromised Hosts

**Attack Flow:**
1. Attacker compromises workstation with access to Azure CLI, PowerShell Az module, or browser
2. Extracts cached tokens from `~/.azure/`, `TokenCache.dat`, browser LocalStorage
3. Uses tokens from external infrastructure

**Key Indicators:**
- Azure CLI / PowerShell sign-ins from IPs not associated with the corporate network
- Sudden spike in Graph API calls from a user account
- Token used for Azure management plane operations from unusual locations

## Hunt Playbooks

### Playbook 1: Detect Token Replay (IP Mismatch)
```kql
let TimeWindow = 10m;
SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType == 0
| project IssuanceTime = TimeGenerated, UserPrincipalName, IssuanceIP = IPAddress, AppDisplayName
| join kind=inner (
    AADNonInteractiveUserSignInLogs
    | where TimeGenerated > ago(7d)
    | where ResultType == 0
    | project UseTime = TimeGenerated, UserPrincipalName, UseIP = IPAddress, ResourceDisplayName
) on UserPrincipalName
| where UseTime between (IssuanceTime .. (IssuanceTime + TimeWindow))
| where IssuanceIP != UseIP
| extend IPPair = strcat(IssuanceIP, " -> ", UseIP)
| summarize Count = count(), Resources = make_set(ResourceDisplayName) by UserPrincipalName, IPPair
| where Count > 3
| order by Count desc
```

### Playbook 2: Anomalous Token Refresh Patterns
```kql
AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(7d)
| where ResultType == 0
| summarize 
    RefreshCount = count(),
    DistinctIPs = dcount(IPAddress),
    DistinctApps = dcount(AppDisplayName),
    IPs = make_set(IPAddress, 10),
    UserAgents = make_set(UserAgent, 5)
    by UserPrincipalName, bin(TimeGenerated, 1h)
| where DistinctIPs > 3 or RefreshCount > 50
| order by RefreshCount desc
```

### Playbook 3: Azure CLI/PowerShell from Unusual Locations
```kql
SigninLogs
| where TimeGenerated > ago(7d)
| where AppDisplayName in ("Azure CLI", "Azure PowerShell", "Microsoft Azure PowerShell")
| where ResultType == 0
| extend City = tostring(LocationDetails.city)
| extend Country = tostring(LocationDetails.countryOrRegion)
| summarize 
    SignInCount = count(),
    IPs = make_set(IPAddress),
    Locations = make_set(strcat(City, ", ", Country))
    by UserPrincipalName
| order by SignInCount desc
```

## CTFd Challenges

| # | Title | Difficulty | Description |
|---|---|---|---|
| 1 | Token Traveler | Easy | Identify a user whose access token was used from two different countries within 5 minutes |
| 2 | Refresh Frenzy | Medium | Find the user with an anomalous refresh token pattern indicating token theft |
| 3 | CLI Hijack | Medium | Detect Azure CLI usage from a non-corporate IP after token extraction |
| 4 | PRT Pirate | Hard | Identify a PRT abuse scenario and trace all resources accessed |
| 5 | Token Timeline | Hard | Build a complete token abuse timeline from initial theft to final resource access |

## Hardening

### Controls
- **Continuous Access Evaluation (CAE)**: Near-real-time token revocation on IP change or risk detection
- **Token Lifetime Policies**: Reduce access token lifetime; enforce re-authentication frequency
- **Conditional Access — Require Compliant Device**: Prevents token use from non-managed devices
- **Conditional Access — Named Locations**: Restrict token use to known corporate IPs
- **Credential Guard**: Protect PRT on Windows endpoints
- **Regular Token Cache Cleanup**: Automate clearing of `~/.azure/` and browser token caches on shared systems

### Sentinel Analytics Rule
```kql
// Token Replay Detection - Same user, different IP within 10 minutes
let TimeWindow = 10m;
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType == 0
| project T1 = TimeGenerated, UPN = UserPrincipalName, IP1 = IPAddress
| join kind=inner (
    AADNonInteractiveUserSignInLogs
    | where TimeGenerated > ago(1h)
    | where ResultType == 0
    | project T2 = TimeGenerated, UPN = UserPrincipalName, IP2 = IPAddress
) on UPN
| where T2 between (T1 .. (T1 + TimeWindow))
| where IP1 != IP2
| distinct UPN, IP1, IP2, T1, T2
```
