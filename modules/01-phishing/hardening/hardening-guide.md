# Phishing Hardening Guide

## Illicit Consent Grant Prevention

### 1. Restrict User Consent
Configure the consent policy so users cannot consent to apps on their own — require admin approval.

**Azure Portal:** Azure AD > Enterprise Applications > Consent and Permissions
- Set "User consent for applications" to **Do not allow user consent**
- Enable **Admin consent workflow** so users can request access

**Conditional Access Policy:**
- Require admin consent for apps requesting high-risk permissions
- Block consent for apps from unverified publishers

### 2. App Governance
- Enable Microsoft Defender for Cloud Apps app governance
- Create policies to alert on:
  - Apps with high-privilege Graph API permissions
  - Apps registered outside the tenant accessing organizational data
  - Unused apps with broad permissions

### 3. Regular Consent Audit
```kql
// Monthly audit of all active consent grants
AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName == "Consent to application"
| extend AppName = tostring(TargetResources[0].displayName)
| extend ConsentedBy = tostring(InitiatedBy.user.userPrincipalName)
| summarize ConsentCount = count() by AppName, ConsentedBy
| order by ConsentCount desc
```

---

## AiTM Prevention

### 1. Continuous Access Evaluation (CAE)
CAE enables near-instant token revocation when risk conditions change. When a token is replayed from a new IP, CAE can revoke it.

**Enable:** Azure AD > Security > Conditional Access > Session > Customize continuous access evaluation

### 2. Token Protection (Preview)
Token binding ties tokens to the device where they were issued. A stolen session cookie cannot be replayed from another device.

**Enable:** Conditional Access policy > Session controls > Require token protection

### 3. Phishing-Resistant MFA
- **FIDO2 security keys**: Hardware-bound, phishing-resistant
- **Windows Hello for Business**: TPM-bound, device-specific
- **Certificate-based authentication**: PKI-backed

**Conditional Access Policy:**
- Require phishing-resistant MFA strength for all cloud application access
- Target privileged users first, then expand

### 4. Compliant Device Requirement
```
Conditional Access > Grant > Require device to be marked as compliant
```
This prevents token replay from non-enrolled devices because the attacker's proxy won't have a compliant device to present.

---

## Device Code Flow Prevention

### 1. Block Device Code Flow via Conditional Access
If your organization doesn't use device code authentication for legitimate IoT/CLI scenarios:

**Conditional Access Policy:**
- Conditions: Client apps > Other clients
- Target: All users (or start with high-value accounts)
- Grant: Block access

### 2. Restrict Device Code to Specific Users/Groups
If some users legitimately need device code flow:
- Create a security group for authorized device code users
- Conditional Access: Block "Other clients" for all users EXCEPT the authorized group

### 3. Monitor and Alert
```kql
// Sentinel Analytics Rule: Device Code Authentication from Non-Baseline Users
let BaselineUsers = SigninLogs
    | where TimeGenerated between (ago(30d) .. ago(1d))
    | where AuthenticationProtocol == "deviceCode"
    | distinct UserPrincipalName;
SigninLogs
| where TimeGenerated > ago(1h)
| where AuthenticationProtocol == "deviceCode"
| where UserPrincipalName !in (BaselineUsers)
| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, Location = LocationDetails
```

---

## Cross-Cutting Recommendations

| Control | Illicit Consent | AiTM | Device Code |
|---|:---:|:---:|:---:|
| Admin consent workflow | ✅ | | |
| CAE | | ✅ | ✅ |
| Token protection | | ✅ | |
| Phishing-resistant MFA | ✅ | ✅ | ✅ |
| Compliant device requirement | | ✅ | ✅ |
| Block device code flow | | | ✅ |
| App governance | ✅ | | |
| Named locations / IP fencing | | ✅ | ✅ |

## Sentinel Analytics Rules

Deploy the following analytics rules from the `sentinel-workbook/` directory:
1. `Illicit-Consent-Grant-Detection.yaml`
2. `AiTM-Session-Replay-Detection.yaml`
3. `Device-Code-Anomaly-Detection.yaml`
