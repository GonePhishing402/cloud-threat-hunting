# Mitigate: Module 01 — Cloud Identity Phishing Incident Response

This playbook follows the **NIST SP 800-61** incident response lifecycle. It covers specific containment and recovery steps for each of the three phishing techniques: **device code phishing**, **AiTM session cookie theft**, and **illicit consent grant**.

---

## Phase 1 — Preparation

### Prerequisites

- **Entra ID Identity Protection** enabled (P2 license) — required for `AnomalousToken` and `AttackerInTheMiddle` risk detections
- **Microsoft Defender for Office 365 Plan 2** — required for Threat Explorer, AIR, and campaign correlation
- **Audit logging** enabled in Microsoft Purview (mailbox auditing + activity auditing)
- **Conditional Access policies** reviewed for device code flow restrictions and MFA enforcement
- **Admin consent workflow** enabled in Entra ID — require admin approval for all third-party apps

### Baseline Controls to Validate Before Incident

| Control | Recommendation |
|---|---|
| **Device code flow** | Block via Conditional Access Authentication Flows policy for all users without a documented exception |
| **User consent** | Restrict to verified publishers with low-risk permissions only; require admin consent for all others |
| **MFA strength** | Enforce phishing-resistant methods (FIDO2 / passkeys / certificate-based) for privileged accounts |
| **Entra ID Protection** | Enable sign-in risk and user risk policies set to block at **high** risk |
| **Safe Links** | Ensure policies are enabled for all users with click-time URL rewriting and time-of-click protection |

---

## Phase 2 — Detection & Analysis

### Triage Checklist

For any suspected phishing-related compromise:

- [ ] Identify which technique was used (device code / AiTM / consent grant)
- [ ] Enumerate affected user accounts from sign-in logs, risk detections, or alerts
- [ ] Determine the time window of initial access (first anomalous sign-in or consent event)
- [ ] Identify resources accessed: mailbox, SharePoint, OneDrive, Azure management
- [ ] Check for persistence actions: new MFA factors, new inbox rules, new OAuth apps, new federated credentials
- [ ] Determine if BEC (Business Email Compromise) follow-on occurred: payment intercept, forwarding rules, impersonation emails sent

### Key Queries (from Defend.md — run during triage)

```kusto
// Quick: recent high-risk sign-ins
AADSignInEventsBeta
| where Timestamp > ago(24h)
| where RiskLevelDuringSignIn in ("high", "medium")
| project Timestamp, AccountUpn, IPAddress, Country, RiskLevelDuringSignIn, DetectedRiskTypes, AuthenticationProtocol
| order by Timestamp desc
```

```kusto
// Quick: recent consent grants
CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType == "Consent to application"
| project Timestamp, AccountUpn, IPAddress, RawEventData
| order by Timestamp desc
```

```kusto
// Quick: inbox rules created after sign-in
CloudAppEvents
| where Timestamp > ago(24h)
| where ActionType in ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules")
| project Timestamp, AccountUpn, ActionType, IPAddress, RawEventData
| order by Timestamp desc
```

---

## Phase 3 — Containment

### For Device Code Phishing

```powershell
# 1. Revoke all refresh tokens for the affected user (block ongoing session use)
Connect-MgGraph -Scopes "User.ReadWrite.All"
Invoke-MgInvalidateUserRefreshToken -UserId <UPN>

# 2. Set user risk to HIGH to trigger risk-based Conditional Access block
# (Portal: Entra ID > Identity Protection > Risky users > select user > Confirm user compromised)

# 3. Block sign-in entirely if the user account is confirmed compromised
Update-MgUser -UserId <UPN> -AccountEnabled $false
```

```bash
# Via Azure CLI
az ad user update --id <UPN> --account-enabled false
```

**Conditional Access emergency block:**
- Navigate to **Entra ID** > **Security** > **Conditional Access**
- Create a policy targeting the affected user(s): block all cloud apps, all platforms, all locations

### For AiTM Session Cookie Theft

```powershell
# 1. Revoke all sessions and refresh tokens
Invoke-MgInvalidateUserRefreshToken -UserId <UPN>

# 2. Revoke active sessions via Entra portal
# Entra ID > Users > [affected user] > Revoke sessions

# 3. If new MFA factors were registered by the attacker, remove them
# Entra ID > Users > [user] > Authentication methods > remove unfamiliar methods

# 4. Disable the user account pending investigation
Update-MgUser -UserId <UPN> -AccountEnabled $false

# 5. Remove attacker-created inbox rules
Connect-ExchangeOnline
Get-InboxRule -Mailbox <UPN> | Where-Object {$_.Enabled -eq $true} | Format-List Name,Description,ForwardTo,DeleteMessage
Remove-InboxRule -Mailbox <UPN> -Identity "<RuleName>"
```

**Check for and remove attacker-registered credentials:**
1. Navigate to **Entra ID** > **Users** > [user] > **Authentication methods**
2. Remove any unrecognized phone numbers, authenticator apps, or FIDO2 keys registered during or after the attack window
3. Navigate to **Entra ID** > **Users** > [user] > **Registered devices** — remove unrecognized devices

### For Illicit Consent Grant

```powershell
# 1. Revoke the OAuth consent grant (delegated permission)
Connect-MgGraph -Scopes "Directory.ReadWrite.All"
# Find the grant
$grants = Get-MgOauth2PermissionGrant -Filter "principalId eq '<user-object-id>'"
$grants | Select-Object Id, ClientId, Scope

# Remove the specific grant
Remove-MgOauth2PermissionGrant -OAuth2PermissionGrantId <grant-id>

# 2. Remove application role assignment (for app-only/admin-consented grants)
Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId <sp-object-id>
Remove-MgServicePrincipalAppRoleAssignment -ServicePrincipalId <sp-object-id> -AppRoleAssignmentId <assignment-id>

# 3. Disable the malicious application (do NOT delete — prevents re-consent if deleted)
Update-MgApplication -ApplicationId <app-id> -SignInAudience "AzureADMyOrg"
# Then disable via portal: Entra ID > Enterprise Applications > [app] > Properties > Enabled for sign-in: No
```

Via the **Microsoft Entra admin center** (https://entra.microsoft.com):
1. **Identity** > **Users** > **All users** > [affected user] > **Applications**
2. Select the malicious application > **Remove**

---

## Phase 4 — Eradication & Recovery

### Token Revocation Verification

After revoking tokens, verify the attacker can no longer access resources:

```powershell
# Check current refresh token validity (via sign-in logs — new sign-in attempts should show error 50173 after revocation)
# Error 50173 = "User account password or refresh token has been updated"
Get-MgAuditLogSignIn -Filter "userPrincipalName eq '<UPN>'" | 
  Select-Object CreatedDateTime, ErrorCode, Status | 
  Sort-Object CreatedDateTime -Descending | 
  Select-Object -First 20
```

### Re-enable User After Remediation

```powershell
# Force password reset on next sign-in
Update-MgUser -UserId <UPN> -PasswordProfile @{ForceChangePasswordNextSignIn = $true}

# Re-enable account
Update-MgUser -UserId <UPN> -AccountEnabled $true

# Force re-registration of MFA methods
# Portal: Entra ID > Users > [user] > Authentication methods > Require re-register MFA
```

### Hardening After Each Technique

#### Device Code Phishing Hardening

```
Conditional Access Policy:
- Name: "Block Device Code Flow — Corporate Users"
- Target: All users (exclude break-glass)
- Authentication flows: Device code flow — BLOCK
- Reference: https://learn.microsoft.com/entra/identity/conditional-access/concept-authentication-flows
```

#### AiTM Hardening

- Deploy **phishing-resistant MFA** (FIDO2 passkeys or certificate-based authentication) for all users — eliminates the post-auth cookie as a viable steal target
- Enable **Entra ID Protection** risk-based Conditional Access: sign-in risk ≥ Medium → MFA; User risk = High → block
- Enable **Continuous Access Evaluation (CAE)** — revokes sessions in near-real-time when high user risk is detected
- Configure **Token Protection** in Conditional Access (preview) — binds tokens to the device that authenticated

#### Illicit Consent Grant Hardening

```
User Consent Settings (Entra ID > Enterprise Apps > Consent and permissions):
- "Users can consent to apps accessing company data on their behalf" → Disabled
  OR
- Restrict to verified publishers with low-risk permissions

Admin Consent Workflow:
- Enable admin consent workflow so users can request approval
- Assign consent reviewers (Security team)
- Reference: https://learn.microsoft.com/entra/identity/enterprise-apps/configure-user-consent
```

---

## Phase 5 — Post-Incident Activity

### Checklist

| Action | Notes |
|---|---|
| Scope all affected accounts | Check for lateral movement from the initial compromised identity |
| Review BEC-related actions | Invoice/payment discussions read, forwarding rules, external emails sent |
| Audit all OAuth consent grants | Run Get-AzureADPSPermissions.ps1 for all users post-incident |
| Validate alert coverage | Confirm AnomalousToken, AiTM, and Consent alerts are firing in your environment |
| Update Conditional Access | Block device code flow; enforce phishing-resistant MFA for privileged users |
| Notify affected users | Advise users what was accessed and actions taken |
| Document IOCs | AiTM proxy domains, malicious app client IDs, attacker IP addresses — add to Tenant Allow/Block List |

### Lessons-Learned Document

Capture within 72 hours:
1. Which technique was used and how it was initially detected
2. Time from first malicious event to detection (dwell time)
3. Resources accessed by the attacker
4. Whether BEC or downstream lateral movement occurred
5. Controls that failed or were not in place
6. Conditional Access policy gaps identified

---

## Microsoft Learn References

- [Phishing Investigation Playbook](https://learn.microsoft.com/security/operations/incident-response-playbook-phishing)
- [Token Theft Playbook](https://learn.microsoft.com/security/operations/token-theft-playbook)
- [App Consent Grant Investigation Playbook](https://learn.microsoft.com/security/operations/incident-response-playbook-app-consent)
- [Detect and Remediate Illicit Consent Grants](https://learn.microsoft.com/defender-office-365/detect-and-remediate-illicit-consent-grants)
- [Remove-MgOauth2PermissionGrant (PowerShell)](https://learn.microsoft.com/powershell/module/microsoft.graph.identity.signins/remove-mgoauth2permissiongrant)
- [Remove-MgServicePrincipalAppRoleAssignment (PowerShell)](https://learn.microsoft.com/powershell/module/microsoft.graph.applications/remove-mgserviceprincipalapproleassignment)
- [Protecting Tokens in Microsoft Entra — Detect and Mitigate](https://learn.microsoft.com/entra/identity/devices/protecting-tokens-microsoft-entra-id)
- [Configure Restricted User Consent Settings](https://learn.microsoft.com/entra/identity/enterprise-apps/configure-user-consent)
- [Conditional Access — Authentication Flows (Device Code)](https://learn.microsoft.com/entra/identity/conditional-access/concept-authentication-flows)
- [Configure Risk-Based Conditional Access Policies (Identity Protection)](https://learn.microsoft.com/entra/id-protection/howto-identity-protection-configure-risk-policies)
- [Plan a Phishing-Resistant Passwordless Authentication Deployment](https://learn.microsoft.com/entra/identity/authentication/how-to-plan-prerequisites-phishing-resistant-passwordless-authentication)
- [NIST SP 800-61 Computer Security Incident Handling Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf)
