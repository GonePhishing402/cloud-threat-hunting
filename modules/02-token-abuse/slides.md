## Slide 1: Cloud Token Abuse

Module 02 — Token Theft, Replay, and FOCI Exploitation

**Speaker Notes:**
Welcome to Module 02. In the previous module we learned how phishing techniques steal tokens and sessions. In this module, we go deeper into what happens after tokens are stolen. We'll cover how attackers extract tokens from browsers, replay refresh tokens across services using the Family of Client IDs mechanism, and use tools like GraphSpy to enumerate and exfiltrate data. The detection surface here is AADNonInteractiveUserSignInLogs — the table that captures every silent token refresh, which is exactly where stolen token usage appears.

## Slide 2: Agenda

- Module Objective and MITRE ATT&CK Mapping
- Token Types: Access, Refresh, and PRT
- Browser Token Theft — Extraction Techniques
- FOCI Token Exchange — Cross-Service Pivoting
- GraphSpy — Post-Authentication Enumeration
- AADNonInteractiveUserSignInLogs — Detection Foundation
- KQL Detection Queries
- High-Signal Indicators of Compromise
- Incident Response and Token Revocation
- Continuous Access Evaluation (CAE)
- Hardening Controls

**Speaker Notes:**
We'll start with the fundamentals — understanding the three token types and why refresh tokens are the primary target. Then we'll walk through two attack techniques: browser-based token theft and FOCI token exchange with GraphSpy. The detection section focuses on AADNonInteractiveUserSignInLogs, which is the single most important table for token abuse hunting. We'll finish with incident response, emphasizing the critical role of Continuous Access Evaluation in making token revocation effective in near-real-time.

## Slide 3: Objective and MITRE Mapping

!layout: Title and Content

**Objective:** Hunt for token theft and replay attacks in Entra ID. Learn how OAuth tokens, refresh tokens, and Primary Refresh Tokens are abused to maintain persistent access without re-authenticating.

| Technique | ID | Tactic |
|---|---|---|
| Steal Application Access Token | T1528 | Credential Access |
| Use Alternate Authentication Material | T1550.001 | Lateral Movement |
| Valid Accounts: Cloud Accounts | T1078.004 | Defense Evasion, Persistence |
| Cloud Service Discovery | T1526 | Discovery |
| Email Collection | T1114.002 | Collection |

**Speaker Notes:**
Token abuse maps to five MITRE techniques. T1528 is the theft itself — extracting tokens from browser storage or memory. T1550.001 is the replay — using stolen tokens to authenticate as the victim. T1078.004 covers the attacker operating as a valid cloud account. T1526 and T1114.002 describe what the attacker does post-access: discovering tenant resources and collecting email. The key distinction from Module 01 is that token abuse is a post-authentication technique — the initial access has already occurred.

## Slide 4: Token Types — What Attackers Target

!layout: Title and Content

| Token Type | Lifetime | Revocable | Red Team Value |
|---|---|---|---|
| Access Token | 60-90 minutes | Only if CAE-capable | Short-lived; authorizes API calls directly |
| Refresh Token | 90 days (rolling) | Yes | Long-lived; acquires new access tokens without re-auth |
| Primary Refresh Token (PRT) | 90 days | Yes | Device-bound; issues tokens for all first-party apps |

**Key insight:** A stolen refresh token is far more dangerous than a stolen access token — it enables persistent access for up to 90 days and can be used to acquire tokens for any in-scope resource without user interaction.

**Speaker Notes:**
Understanding the token hierarchy is critical. Access tokens are short-lived and limited to a single resource — stealing one gives the attacker 60-90 minutes of access. Refresh tokens are the real prize — they last up to 90 days on a rolling window and can be exchanged for new access tokens targeting any resource the user has access to. PRTs are the most powerful — they're device-bound and can issue tokens for all Microsoft first-party applications. In this module, we focus primarily on refresh token theft and replay via FOCI, as this is the most common and impactful attack pattern.

## Slide 5: Key Tables for This Module

!layout: Title and Content

| Table | What It Captures | Module Use |
|---|---|---|
| AADNonInteractiveUserSignInLogs | Token refresh, silent sign-ins, background auth | Primary detection surface for token replay |
| SigninLogs | Interactive sign-in events | Baseline comparison and initial token issuance |
| MicrosoftGraphActivityLogs | Graph API calls made with tokens | Attacker's post-access activity |
| AzureActivity | Azure resource management operations | Stolen token used for control plane actions |
| CloudAppEvents | App-level events (mail, files, Teams) | Downstream impact assessment |

**Speaker Notes:**
AADNonInteractiveUserSignInLogs is the star table for this module. Token theft and FOCI replay attacks are nearly invisible in interactive sign-in logs because the attacker never triggers an interactive authentication. Every token refresh, every silent re-auth, every background sign-in appears in the non-interactive logs. SigninLogs provides the baseline — what does normal activity look like for this user? MicrosoftGraphActivityLogs shows what the attacker accessed with the stolen token. CloudAppEvents captures the downstream impact — emails read, files downloaded, Teams messages accessed.

## Slide 6: Browser Token Theft — How It Works

!layout: Title and Content

Single-page applications and browser-based Microsoft apps cache tokens locally in the browser using MSAL.js. An attacker with brief access to a browser session can extract these tokens in seconds.

**Token cache locations:**
- localStorage / sessionStorage / IndexedDB
- MSAL.js keys follow predictable patterns: `msal.<client-id>.<tenant-id>.refreshtoken-<hash>`
- Network tab captures live Authorization: Bearer headers

**Attack prerequisites:**
- Physical access to unlocked workstation, or remote browser session access, or XSS execution
- No credential knowledge required — tokens are already cached
- No malware needed

**Speaker Notes:**
This is a low-barrier attack. An attacker who gets 30 seconds of physical access to an unlocked workstation can open browser dev tools, navigate to localStorage, and extract both access and refresh tokens. They don't need to know the user's password. The tokens are cached by MSAL.js in a predictable format. The refresh token is in the secret field of the refreshtoken cache entry. They can also capture tokens live from the Network tab by filtering for Authorization headers on outbound Graph API requests. This is why workstation security and screen lock policies matter.

## Slide 7: FOCI Token Exchange — Cross-Service Pivoting

!layout: Title and Content

**Family of Client IDs (FOCI):** A set of trusted Microsoft first-party applications that share refresh tokens. Steal one refresh token and get access tokens for any Microsoft service the victim can access.

| App Name | Client ID |
|---|---|
| Azure CLI | 04b07795-8ddb-461a-bbee-02f9e1bf7b46 |
| Microsoft Azure PowerShell | 1950a258-227b-4e31-a9cf-717495945fc2 |
| Microsoft Office | d3590ed6-52b3-4102-aeff-aad2292ab01c |
| Graph Command Line Tools | 14d82eec-204b-4c2f-b7e8-296a70dab67e |
| Teams Web Client | 5e3ce6c0-2b1f-4285-8d4b-75ee78787346 |

**How it works:** Attacker sends stolen refresh token to /oauth2/v2.0/token with a DIFFERENT FOCI sibling client_id — gets back new access + refresh tokens for the requested scope, no user interaction required.

**Speaker Notes:**
FOCI is a design feature, not a vulnerability. Microsoft intentionally shares refresh tokens across trusted first-party apps for user convenience — you authenticate once and all Microsoft apps work seamlessly. But attackers abuse this by stealing a token issued for one app (like the browser) and exchanging it via a different client ID (like Azure CLI). This gives them access to any resource the user is authorized for — Graph, Exchange, SharePoint, Azure Resource Manager — all from a single stolen refresh token. The FOCI client ID table here shows the most commonly abused apps. Azure CLI is the most popular because it has broad default scopes.

## Slide 8: GraphSpy — Post-Authentication Enumeration

!layout: Title and Content

**GraphSpy** is an open-source tool that provides a point-and-click interface for Microsoft Graph API operations post-authentication. It accepts a stolen token and automates:

- User, group, and application enumeration
- Mailbox reading, calendar access, Teams messages
- File download from OneDrive and SharePoint
- Search queries across the tenant
- Automatic token refresh via FOCI to maintain persistent access

**Full attack chain:**
- Victim authenticates to M365 portal
- Attacker extracts refresh token from browser localStorage
- Attacker uses FOCI exchange (Azure CLI client ID) to get Graph access token
- GraphSpy loaded with token — auto-refreshes as tokens expire
- Attacker enumerates users, reads mail, downloads files
- Pivots to Exchange, SharePoint, Azure ARM via additional FOCI exchanges

**Speaker Notes:**
GraphSpy is a real tool used by both red teams and actual threat actors. It abstracts the complexity of token manipulation and Graph API interaction into a simple web UI. The key detection implication is that GraphSpy generates a burst of Graph API requests across multiple resource types in rapid succession — a pattern that's very different from normal user activity. It also uses Python HTTP libraries, which creates a UserAgent mismatch when the token was originally issued to a browser-based app. We'll see how to detect this pattern in the KQL queries.

## Slide 9: High-Signal Indicators of Compromise

!layout: Title and Content

| Indicator | What It Means |
|---|---|
| IncomingTokenType = refreshToken in non-interactive logs | Token replay — attacker reusing a stolen refresh token |
| AppDisplayName = Azure CLI with unusual UserAgent | FOCI exchange — CLI app ID used from non-CLI tooling |
| ResourceDisplayName changes rapidly for same user | FOCI pivoting across services (Graph, Exchange, Azure) |
| Multiple resources accessed in minutes via same token | GraphSpy-style enumeration across resources |
| RiskEventTypes includes anomalousToken | Entra ID Protection detecting token replay anomalies |
| Non-interactive sign-in from IP with no prior interactive sign-in | Attacker IP not in victim's sign-in history |
| UserAgent mismatch with AppDisplayName | Tool-based replay (GraphSpy, curl, Postman) |

**Speaker Notes:**
These are the indicators you'll be hunting for in the lab. The most reliable signal is the combination of IncomingTokenType = refreshToken with an IP address that has never appeared in the user's interactive sign-in history. FOCI pivoting is detected by a single user authenticating to 3 or more distinct resources within a short window. The UserAgent mismatch is a tool-specific signal — legitimate Azure CLI uses python-requests, but GraphSpy and other tools use different HTTP libraries. Each of these indicators alone is suspicious; in combination, they're near-definitive for token abuse.

## Slide 10: AADNonInteractiveUserSignInLogs — Key Fields

!layout: Title and Content

| Field | Why It Matters |
|---|---|
| IncomingTokenType | "refreshToken" = replay; "primaryRefreshToken" = PRT abuse |
| SignInEventTypes | "refreshToken" confirms non-interactive refresh usage |
| AppDisplayName | Client app that initiated sign-in — mismatch indicates tooling |
| ClientAppUsed | Category: "Browser", "Native App", "Other clients" |
| ResourceDisplayName | Target resource — rapid changes indicate FOCI pivoting |
| UserAgent | HTTP User-Agent — mismatches reveal replay tools |
| IPAddress | Attacker IP — differs from victim's normal IP |
| RiskEventTypes_V2 | anomalousToken, unfamiliarFeatures |
| TokenProtectionStatusDetails | Unbound token from Token Protection-enabled policy |

**Speaker Notes:**
This slide is your field reference card for investigating token abuse. IncomingTokenType is the single most important field — if it shows refreshToken, you know a previously issued refresh token was replayed rather than a fresh authentication occurring. SignInEventTypes confirms this. AppDisplayName combined with UserAgent reveals tool-based attacks — if AppDisplayName says "Azure CLI" but UserAgent doesn't show python-requests, that's a tool impersonating the Azure CLI client ID. TokenProtectionStatusDetails is a newer field that shows whether the token was cryptographically bound to the device — unbound tokens from policies that require binding are anomalous.

## Slide 11: KQL — Detect Refresh Token Replay

!layout: Title and Content

```kql
AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(24h)
| where IncomingTokenType == "refreshToken"
| where ResourceDisplayName has_any (
    "Microsoft Graph",
    "Office 365 Exchange Online",
    "Azure Resource Manager"
  )
| project TimeGenerated, UserPrincipalName,
          IPAddress, AppDisplayName,
          ClientAppUsed, ResourceDisplayName,
          IncomingTokenType, SignInEventTypes,
          UserAgent, RiskLevelDuringSignIn
| order by TimeGenerated desc
```

**What this finds:** Refresh token usage targeting Graph, Exchange, and ARM — the three primary resources attackers target after token theft.

**Speaker Notes:**
This is your primary hunting query for token abuse. It filters for refresh token usage targeting the three most valuable resources. In a normal environment, you'll see legitimate refresh token activity — but look for anomalies: unusual IPs, unexpected AppDisplayNames, or UserAgents that don't match the app. The volume of results will be high in a busy tenant, so use this as a starting point and then narrow with additional filters. In the lab, we'll filter this further by specific users or IPs identified through other signals.

## Slide 12: KQL — FOCI Pivoting Detection

!layout: Title and Content

A single account accessing 3+ distinct resources via refresh tokens within 15 minutes is a strong FOCI indicator.

```kql
AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(24h)
| where IncomingTokenType == "refreshToken"
| where ResultType == 0
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

**Speaker Notes:**
This is the FOCI-specific detection query. Normal user activity typically targets one or two resources in a 15-minute window — your browser refreshes tokens for Graph and maybe Exchange. An attacker using FOCI exchanges will hit Graph, Exchange, SharePoint, Azure Resource Manager, and other resources in rapid succession. The ResourceCount >= 3 threshold is conservative — in real attacks, you'll often see 4 or 5 distinct resources. The make_set aggregations give you the full picture: which resources, which apps, which IPs, which user agents. This is ideal for an analytics rule with a 15-minute window.

## Slide 13: KQL — App/UserAgent Mismatch Detection

!layout: Title and Content

Detects tooling like GraphSpy by finding mismatches between AppDisplayName and UserAgent.

```kql
AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(24h)
| where IncomingTokenType == "refreshToken"
| where AppDisplayName has_any (
    "Azure CLI",
    "Microsoft Azure PowerShell",
    "Microsoft Office"
  )
| where isnotempty(UserAgent)
| extend IsSuspiciousAgent = case(
    AppDisplayName == "Azure CLI"
        and UserAgent !startswith "python-requests",
        true,
    UserAgent has_any (
        "GraphSpy", "curl", "Postman", "Mozilla/4.0"
    ), true,
    false
  )
| where IsSuspiciousAgent == true
| project TimeGenerated, UserPrincipalName,
          IPAddress, AppDisplayName, UserAgent,
          ResourceDisplayName, ResultType
| order by TimeGenerated desc
```

**Speaker Notes:**
This query is highly specific to tool-based attacks. Legitimate Azure CLI uses the python-requests library and will have a UserAgent starting with "python-requests/". If someone is using the Azure CLI client ID but sending requests with curl, Postman, or a Python library other than requests, they're likely using a replay tool. GraphSpy's own UserAgent string will sometimes appear directly. Mozilla/4.0 is a legacy user agent string sometimes used by older tools. This query has a very low false positive rate because it's matching specific tool signatures.

## Slide 14: KQL — Anomalous Token Risk Detections

!layout: Title and Content

```kql
AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(48h)
| where IsRisky == true
    or RiskLevelDuringSignIn in ("medium", "high")
    or RiskEventTypes_V2 has_any (
        "anomalousToken",
        "unfamiliarFeatures",
        "investigationsThreatIntelligence"
    )
| project TimeGenerated, UserPrincipalName,
          IPAddress, AppDisplayName,
          ResourceDisplayName, IncomingTokenType,
          RiskLevelDuringSignIn, RiskEventTypes_V2
| order by TimeGenerated desc
```

**Key risk types:**
- **anomalousToken** — Token characteristics don't match normal patterns (Entra ID P2)
- **unfamiliarFeatures** — Sign-in properties don't match user's history
- **investigationsThreatIntelligence** — IP matches known threat actor infrastructure

**Speaker Notes:**
This query leverages Entra ID Protection's machine learning detections. The anomalousToken risk type is the most relevant for token abuse — it fires when the token's characteristics (issuing device, network, timing) don't match the user's established pattern. This requires Entra ID P2 licensing. The 48-hour window is wider than usual because risk detections can be retroactively applied. If your organization doesn't have P2, you'll need to rely on the manual detection patterns from the previous queries — IP mismatches, FOCI pivoting, and UserAgent mismatches.

## Slide 15: KQL — Token Replay Detection (IP Mismatch)

!layout: Title and Content

```kql
let TimeWindow = 10m;
SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType == 0
| project IssuanceTime = TimeGenerated,
          UserPrincipalName,
          IssuanceIP = IPAddress,
          AppDisplayName
| join kind=inner (
    AADNonInteractiveUserSignInLogs
    | where TimeGenerated > ago(7d)
    | where ResultType == 0
    | project UseTime = TimeGenerated,
              UserPrincipalName,
              UseIP = IPAddress,
              ResourceDisplayName
) on UserPrincipalName
| where UseTime between
    (IssuanceTime .. (IssuanceTime + TimeWindow))
| where IssuanceIP != UseIP
| summarize Count = count(),
    Resources = make_set(ResourceDisplayName)
    by UserPrincipalName,
    strcat(IssuanceIP, " -> ", UseIP)
| where Count > 3
| order by Count desc
```

**Speaker Notes:**
This is the definitive token replay detection query from the module playbooks. It joins interactive sign-ins (where the token was issued) with non-interactive sign-ins (where the token was used) and looks for IP mismatches within a 10-minute window. If a user authenticates from their office IP and within 10 minutes the resulting token is used from a completely different IP, that's token theft. The Count > 3 threshold reduces noise from legitimate VPN switches. The Resources aggregation shows which services the attacker accessed. This query is suitable for conversion to a near-real-time analytics rule with a 1-hour window.

## Slide 16: Incident Response — Token Revocation

!layout: Title and Content

**Step 1 — Revoke refresh tokens (critical):**

```powershell
Connect-MgGraph -Scopes "User.ReadWrite.All"
Invoke-MgInvalidateUserRefreshToken -UserId <UPN>
```

This blocks the attacker from obtaining new access tokens. Next refresh attempt returns error AADSTS50173.

**Step 2 — Block sign-in if confirmed compromised:**

```powershell
Update-MgUser -UserId <UPN> -AccountEnabled $false
```

**The problem:** Access tokens already in the attacker's possession remain valid for up to 90 minutes — unless CAE is in place.

**Speaker Notes:**
Revoking refresh tokens is always the first step. This immediately prevents the attacker from using FOCI or direct refresh to get new access tokens. But there's a critical gap: any access tokens the attacker already holds continue to work until they expire. A 60-90 minute window where the attacker still has access is unacceptable for high-impact compromises. This is where Continuous Access Evaluation becomes essential — it closes this gap by pushing revocation signals to resource providers in near-real-time. We'll cover CAE on the next slide.

## Slide 17: Continuous Access Evaluation (CAE)

!layout: Title and Content

CAE allows Entra ID to push revocation signals to resource providers in near-real-time. When a revocation event occurs, the resource provider rejects the token immediately — without waiting for expiry.

**CAE revocation triggers:**
- User account is disabled or deleted
- User password is changed or reset
- Admin revokes all refresh tokens (Invoke-MgInvalidateUserRefreshToken)
- Entra ID Protection elevates user to high risk
- Token exported to untrusted network (location-based CAE)

**CAE-capable resources (near-real-time revocation):**
- Microsoft Graph, Exchange Online, SharePoint, Teams

**Non-CAE resources (tokens valid until expiry):**
- Third-party APIs, non-CAE-integrated apps

**Speaker Notes:**
CAE is the most important defensive control for token abuse. Without CAE, revoking a refresh token only prevents future token issuance — the attacker's existing access tokens are valid for up to 90 minutes. With CAE, calling Invoke-MgInvalidateUserRefreshToken triggers a revocation event that is pushed to Graph, Exchange, SharePoint, and Teams within seconds. The attacker's access tokens are rejected immediately. CAE should be enabled for all users — it's available with Entra ID P1 and higher. Verify CAE is working by checking the SignInEventTypes field for "continuousAccessEvaluation" entries after a revocation.

## Slide 18: Hardening Controls

!layout: Title and Content

| Control | What It Prevents |
|---|---|
| Continuous Access Evaluation (CAE) | Closes the access token validity gap after revocation |
| Token Protection (CA preview) | Cryptographically binds tokens to the issuing device |
| Conditional Access: Require Compliant Device | Prevents token use from non-managed devices |
| Conditional Access: Named Locations | Restricts token use to known corporate IPs |
| Credential Guard (Windows) | Protects PRT on Windows endpoints |
| Token Lifetime Policies | Reduce access token lifetime; enforce re-auth frequency |
| Disable FOCI Apps | Block first-party apps not needed in your environment |

**Speaker Notes:**
These controls layer to create defense-in-depth against token abuse. CAE is the most impactful — it makes token revocation effective in near-real-time. Token Protection is the next evolution — it cryptographically binds the token to the device, making stolen tokens unusable on other devices. This is currently in preview but will be the definitive control when GA. Compliant device requirements and named locations add additional constraints. For organizations with high-value targets, consider reducing access token lifetimes and disabling FOCI apps that aren't needed. In the lab, students will verify which of these controls are active in the training environment.

## Slide 19: Post-Incident Investigation

!layout: Title and Content

**Identify what the attacker accessed:**

```kql
AADNonInteractiveUserSignInLogs
| where UserPrincipalName == "<affected-UPN>"
| where IncomingTokenType == "refreshToken"
| where ResultType == 0
| distinct IPAddress, UserAgent,
    AppDisplayName, ResourceDisplayName
```

**Distinguish attacker IPs from legitimate IPs:**

```kql
SigninLogs
| where UserPrincipalName == "<affected-UPN>"
| where TimeGenerated > ago(7d)
| summarize min(TimeGenerated), max(TimeGenerated)
    by IPAddress, AppDisplayName,
    ResourceDisplayName
```

**Recovery:** Force password reset, re-enable account, force MFA re-registration, verify no attacker-registered MFA methods.

**Speaker Notes:**
The investigation phase determines the blast radius. The first query shows all resources the attacker accessed using the stolen refresh token — the distinct clause deduplicates to show unique access patterns. Compare the IPAddress values from non-interactive logs against the user's known interactive sign-in IPs. Any IP that appears in non-interactive logs but never in interactive sign-ins is likely the attacker. After containment and investigation, force a password reset and MFA re-registration. Check the user's authentication methods for any attacker-registered devices or phone numbers, just like we did in Module 01 for AiTM.

## Slide 20: Key Takeaways

!layout: Title and Content

- Refresh tokens are the primary target — they provide up to 90 days of persistent access
- FOCI allows one stolen refresh token to access ANY Microsoft service the user can reach
- AADNonInteractiveUserSignInLogs is the primary detection surface for token abuse
- Look for: IP mismatches, FOCI pivoting (3+ resources in 15 min), UserAgent mismatches
- Revoking refresh tokens stops future issuance, but CAE is required for immediate access token revocation
- Token Protection (preview) will cryptographically bind tokens to devices — the definitive future control

**What comes next:** Module 03 — Logic App Abuse (RBAC exploitation, trigger URL harvesting, managed identity exfiltration)

**Speaker Notes:**
Summarize the three key skills from this module: understanding the token hierarchy, detecting refresh token abuse in non-interactive sign-in logs, and the critical importance of CAE for effective incident response. The FOCI mechanism is a design feature that attackers exploit — understanding which client IDs participate in FOCI helps you detect cross-service pivoting. Encourage students to run the lab playbooks and practice the IP mismatch and FOCI detection queries. Module 03 shifts from identity-layer attacks to Azure resource-layer attacks with Logic Apps.

## Slide 21: References

!layout: Title and Content

| Resource | Link |
|---|---|
| Token Theft Playbook | learn.microsoft.com/security/operations/token-theft-playbook |
| Understanding Tokens in Entra ID | learn.microsoft.com/entra/identity/devices/concept-tokens-microsoft-entra-id |
| Protecting Tokens in Entra ID | learn.microsoft.com/entra/identity/devices/protecting-tokens-microsoft-entra-id |
| Token Protection in Conditional Access | learn.microsoft.com/entra/identity/conditional-access/concept-token-protection |
| Continuous Access Evaluation | learn.microsoft.com/entra/identity/conditional-access/concept-continuous-access-evaluation |
| Revoke User Access in Entra ID | learn.microsoft.com/entra/identity/users/users-revoke-access |
| AADNonInteractiveUserSignInLogs Schema | learn.microsoft.com/azure/azure-monitor/reference/tables/aadnoninteractiveusersigninlogs |
| Entra ID Protection Risk Detections | learn.microsoft.com/entra/id-protection/concept-identity-protection-risks |

**Speaker Notes:**
The Token Theft Playbook from Microsoft Security is the authoritative reference for token abuse investigation. The Protecting Tokens documentation covers all defensive controls including CAE and Token Protection. The AADNonInteractiveUserSignInLogs schema reference is essential for understanding all available fields in the primary detection table. Encourage students to review the CAE documentation and verify it's enabled in their production environments.
