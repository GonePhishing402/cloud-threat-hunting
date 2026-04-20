# Mitigate: Module 02 — Cloud Token Abuse Incident Response

This playbook addresses the two primary token abuse scenarios from this module: **browser-based token theft** and **FOCI refresh token replay with GraphSpy**. The core challenge in token abuse IR is that revoking a refresh token stops future token issuance, but **access tokens already in the attacker's hand remain valid until they expire** — unless Continuous Access Evaluation (CAE) is in place.

---

## Phase 1 — Immediate Containment

### Step 1: Revoke Refresh Tokens

Revoking refresh tokens is the primary containment action. This immediately blocks the attacker from obtaining new access tokens via FOCI or direct refresh.

```powershell
# Revoke all refresh tokens and sign-in sessions for the affected user
Connect-MgGraph -Scopes "User.ReadWrite.All"
Invoke-MgInvalidateUserRefreshToken -UserId <UPN>

# Verify: The user will receive error 50173 on next token refresh attempt
# "Your password or access key has been updated. Sign in again."
```

Via **Entra ID admin center** (https://entra.microsoft.com):
1. **Identity** > **Users** > [affected user] > **Revoke sessions**

> **What this does:** Marks all existing refresh tokens and session cookies as invalid. The attacker's next `grant_type=refresh_token` request will return `AADSTS50173: The provided grant has expired`.

Reference: [Revoke user access in Microsoft Entra ID](https://learn.microsoft.com/entra/identity/users/users-revoke-access)

---

### Step 2: Contain Access Tokens with Continuous Access Evaluation (CAE)

**The problem:** Access tokens are **not revoked** by `Invoke-MgInvalidateUserRefreshToken`. An access token already in the attacker's possession is valid for its remaining lifetime (up to 90 minutes). Without CAE, you cannot stop the attacker from using a token they already hold.

**CAE solves this.** Continuous Access Evaluation allows Microsoft Entra to push revocation signals to CAE-capable resource providers (Microsoft Graph, Exchange Online, SharePoint, Teams) in **near real-time**. When a revocation event occurs, the resource provider rejects the token immediately — without waiting for it to expire.

**Events that trigger CAE enforcement in near real-time:**
1. User account is disabled or deleted
2. User password is changed or reset
3. **Administrator explicitly revokes all refresh tokens** (`Invoke-MgInvalidateUserRefreshToken`) → triggers CAE revocation
4. Microsoft Entra ID Protection elevates user to high risk
5. Token export to untrusted network (location-based CAE)

```
CAE-Capable Resources (tokens revoked in near real-time):
  Microsoft Graph
  Exchange Online
  SharePoint Online / OneDrive
  Microsoft Teams
  
Non-CAE Resources (tokens remain valid until expiry after revocation):
  Third-party APIs
  Non-CAE-integrated apps
```

> When `Invoke-MgInvalidateUserRefreshToken` is called, a CAE revocation event fires. Any resource provider that has integrated CAE will reject the attacker's access token within seconds — even if it hasn't expired.

Reference: [Continuous Access Evaluation — User revocation event flow](https://learn.microsoft.com/entra/identity/conditional-access/concept-continuous-access-evaluation#example-flow-diagrams)

Reference: [Revoke user access — Using CAE](https://learn.microsoft.com/entra/identity/users/users-revoke-access#best-practices)

---

### Step 3: Block Sign-In (if compromise confirmed)

```powershell
# Hard block the user account if compromise is confirmed
Update-MgUser -UserId <UPN> -AccountEnabled $false
```

This triggers an additional CAE event — disabling the account causes immediate revocation at CAE-capable resource providers.

---

## Phase 2 — Investigation

### Identify Accessed Resources

Use the non-interactive sign-in logs to determine what the attacker accessed and when:

```kusto
// What did the attacker access with the stolen token?
AADNonInteractiveUserSignInLogs
| where UserPrincipalName == "<affected-UPN>"
| where TimeGenerated between (datetime(<start>) .. datetime(<end>))
| where IncomingTokenType == "refreshToken"
| project TimeGenerated, AppDisplayName, ResourceDisplayName,
          IPAddress, UserAgent, SignInEventTypes, ResultType
| order by TimeGenerated asc
```

```kusto
// Downstream activity via CloudAppEvents
CloudAppEvents
| where AccountUpn == "<affected-UPN>"
| where Timestamp > datetime(<start>)
| project Timestamp, Application, ActionType, IPAddress, ObjectName, RawEventData
| order by Timestamp asc
```

### Identify Attacker IP / Infrastructure

```kusto
// All IPs that used the victim's token in non-interactive sign-ins
AADNonInteractiveUserSignInLogs
| where UserPrincipalName == "<affected-UPN>"
| where IncomingTokenType == "refreshToken"
| where ResultType == 0
| distinct IPAddress, UserAgent, AppDisplayName, ResourceDisplayName
```

Compare against `SigninLogs` for the same user to distinguish legitimate vs. attacker IPs.

---

## Phase 3 — Recovery

### Force Password Reset

After revoking sessions, force the user to reset their password on next sign-in. This also triggers a CAE event and invalidates any remaining session state:

```powershell
Update-MgUser -UserId <UPN> -PasswordProfile @{ForceChangePasswordNextSignIn = $true}

# Re-enable if previously disabled
Update-MgUser -UserId <UPN> -AccountEnabled $true
```

### Re-register MFA

Verify the attacker did not register a new MFA factor or device:

1. **Entra ID** > **Users** > [user] > **Authentication methods** — remove unrecognized methods
2. **Entra ID** > **Users** > [user] > **Registered devices** — remove unrecognized devices

---

## Phase 4 — Hardening

### Deploy Token Protection in Conditional Access

Token Protection cryptographically **binds tokens to the device** that authenticated. A token stolen from one device cannot be replayed from another — this directly defeats browser-based FOCI replay attacks.

```
Conditional Access Policy:
- Name: "Require Token Protection — Graph and Exchange"
- Target: All users (or start with privileged accounts)
- Target apps: Microsoft Graph, Office 365 Exchange Online
- Session control: Token protection — Enabled
- Platform: Windows (Generally Available); iOS/macOS in Preview

Note: Token Protection currently supports native applications only.
Browser-based applications are NOT yet supported.
```

Reference: [Token Protection in Conditional Access](https://learn.microsoft.com/entra/identity/conditional-access/concept-token-protection)

### Verify CAE Is Active in Your Environment

CAE is enabled by default for Microsoft 365 apps and Microsoft Graph. Verify your Conditional Access policies and sign-in events include CAE-enforced sessions:

```kusto
// Look for CAE-evaluated sign-ins
AADNonInteractiveUserSignInLogs
| where SignInEventTypes has "continuousAccessEvaluation"
| summarize count() by UserPrincipalName, ResourceDisplayName, bin(TimeGenerated, 1d)
```

If `continuousAccessEvaluation` events are absent, check Conditional Access policies and ensure CAE is not disabled for any targeted resources.

Reference: [Secure applications with CAE](https://learn.microsoft.com/security/zero-trust/develop/secure-with-cae)

### Disable Unused FOCI-Capable Apps

If Azure CLI, Azure PowerShell, or other FOCI-member apps are not used by most of your users, block them with Conditional Access:

```
Conditional Access Policy:
- Name: "Block Azure CLI — Non-Privileged Users"
- Target: All users EXCEPT admins/developers group
- Target apps: Azure Command Line Interface (04b07795-8ddb-461a-bbee-02f9e1bf7b46)
- Grant: Block access
```

### Risk-Based Conditional Access for High-Risk Sign-ins

Ensure Entra ID Protection policies are set to block or challenge at **high** user risk and **medium** sign-in risk. This causes CAE to revoke sessions when `anomalousToken` or `unfamiliarFeatures` fires:

1. **Entra ID** > **Security** > **Identity Protection** > **Sign-in risk policy** → Set to Medium+ → Require MFA
2. **Entra ID** > **Security** > **Identity Protection** > **User risk policy** → Set to High → Block or require password change

Reference: [Configure risk-based Conditional Access (Identity Protection)](https://learn.microsoft.com/entra/id-protection/howto-identity-protection-configure-risk-policies)

---

## Verification Checklist

| Check | Query / Action |
|---|---|
| No new successful refresh token sign-ins from attacker IP | `AADNonInteractiveUserSignInLogs` — filter by attacker IP, `IncomingTokenType == "refreshToken"`, `ResultType == 0` |
| Error 50173 on attacker's subsequent attempts | `ResultDescription has "50173"` in sign-in logs |
| CAE revocation confirmed on resource servers | `SignInEventTypes has "continuousAccessEvaluation"` with `ResultType != 0` for suspect user |
| User risk has returned to `none` or `low` | Entra ID Protection — Risky Users dashboard |
| No unrecognized MFA methods or devices | Authentication methods + Registered devices reviewed |

---

## Microsoft Learn References

- [Revoke user access in Microsoft Entra ID](https://learn.microsoft.com/entra/identity/users/users-revoke-access)
- [Revoke-MgUserSignInSession (PowerShell)](https://learn.microsoft.com/powershell/module/microsoft.graph.users.actions/revoke-mgusersigninsession)
- [Invoke-MgInvalidateUserRefreshToken (PowerShell)](https://learn.microsoft.com/graph/api/user-invalidateallrefreshtokens)
- [Continuous Access Evaluation — Overview](https://learn.microsoft.com/entra/identity/conditional-access/concept-continuous-access-evaluation)
- [Continuous Access Evaluation — Example flow diagrams](https://learn.microsoft.com/entra/identity/conditional-access/concept-continuous-access-evaluation#example-flow-diagrams)
- [Secure applications with Continuous Access Evaluation](https://learn.microsoft.com/security/zero-trust/develop/secure-with-cae)
- [Token Protection in Conditional Access](https://learn.microsoft.com/entra/identity/conditional-access/concept-token-protection)
- [Protecting tokens in Microsoft Entra — Token theft detect and mitigate](https://learn.microsoft.com/entra/identity/devices/protecting-tokens-microsoft-entra-id#token-theft---detect-and-mitigate)
- [Token theft playbook](https://learn.microsoft.com/security/operations/token-theft-playbook)
- [Configure risk-based Conditional Access policies](https://learn.microsoft.com/entra/id-protection/howto-identity-protection-configure-risk-policies)
- [Understanding tokens — Summary and revocability](https://learn.microsoft.com/entra/identity/devices/concept-tokens-microsoft-entra-id#summary-of-the-kinds-of-tokens)
