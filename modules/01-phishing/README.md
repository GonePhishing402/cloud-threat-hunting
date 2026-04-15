# Module 01 — Phishing: Illicit Consent, AiTM, and Device Code

## Objective

Hunt for three cloud-native phishing attack patterns in Azure AD sign-in and audit data. Students learn to distinguish between traditional credential phishing and cloud-specific techniques that bypass MFA.

## Duration

~3 hours (lecture + hands-on labs)

## MITRE ATT&CK Mapping

| Technique | ID | Tactic |
|---|---|---|
| Phishing | T1566 | Initial Access |
| Steal Application Access Token | T1528 | Credential Access |
| Forge Web Credentials | T1606 | Credential Access |
| Valid Accounts: Cloud Accounts | T1078.004 | Initial Access, Persistence |

## Sentinel Tables

- `SigninLogs` — Interactive and non-interactive sign-in events
- `AADNonInteractiveUserSignInLogs` — Non-interactive sign-ins (token refresh, SSO)
- `AuditLogs` — Directory changes including app consent grants
- `OfficeActivity` — Post-compromise activity in M365

## Attack Narratives

### 1. Illicit Consent Grant

**Attack Flow:**
1. Attacker registers a malicious multi-tenant Azure AD application
2. Crafts a phishing email with an OAuth consent URL
3. Victim clicks link and grants permissions (Mail.Read, Files.ReadWrite.All, etc.)
4. Attacker uses granted permissions to access victim's data via Graph API

**Key Indicators:**
- `AuditLogs` where `OperationName == "Consent to application"` with high-privilege scopes
- Applications with `OAuth2PermissionGrants` targeting `Mail.Read`, `Files.ReadWrite.All`, `User.ReadWrite.All`
- Consent granted to apps registered outside the tenant
- Unusual `AppDisplayName` values or recently created apps

### 2. Adversary-in-the-Middle (AiTM)

**Attack Flow:**
1. Attacker deploys reverse proxy (Evilginx, EvilNoVNC, etc.) mimicking Azure AD login
2. Victim authenticates through proxy — attacker captures session cookie post-MFA
3. Attacker replays session cookie from a different IP/location
4. MFA is bypassed because the session is already authenticated

**Key Indicators:**
- `SigninLogs` showing successful MFA, then immediate sign-in from different IP
- Token claim anomalies: `SessionId` reuse across different IPs/user agents
- Impossible travel patterns (sign-in from two distant locations within minutes)
- `UserAgent` string mismatches between initial auth and subsequent token use
- Sign-in from known proxy infrastructure IPs

### 3. Device Code Phishing

**Attack Flow:**
1. Attacker initiates device code flow (typically for IoT/CLI devices)
2. Crafts phishing email asking victim to enter the device code at `microsoft.com/devicelogin`
3. Victim enters the code, authenticating the attacker's session
4. Attacker receives access/refresh tokens

**Key Indicators:**
- `SigninLogs` where `AuthenticationProtocol == "deviceCode"`
- Device code sign-ins from users who don't typically use CLI tools or IoT devices
- Subsequent non-interactive sign-ins using refresh tokens from unusual IPs
- Resource access patterns inconsistent with the user's normal behavior

## Hunt Playbooks

See [hunt-playbooks/](hunt-playbooks/) for step-by-step KQL queries and investigation procedures.

## CTFd Challenges

| # | Title | Difficulty | Description |
|---|---|---|---|
| 1 | Consent Granted | Easy | Identify which application received an illicit consent grant |
| 2 | The Proxy in the Middle | Medium | Find the AiTM session replay and identify the attacker's IP |
| 3 | Enter the Code | Medium | Detect the device code phishing and trace the attacker's subsequent access |
| 4 | Full Chain | Hard | Reconstruct the complete attack timeline across all three phishing techniques |
| 5 | Build the Detection | Hard | Write a Sentinel analytics rule to detect one of the three phishing patterns |

## Hardening Recommendations

See [hardening/](hardening/) for detailed hardening guidance.

### Quick Reference
- **Illicit Consent**: Admin consent workflow, restrict user consent to verified publishers, app governance policies
- **AiTM**: Continuous Access Evaluation (CAE), token protection (token binding), compliant device requirement via Conditional Access
- **Device Code**: Block or restrict device code flow via Conditional Access, monitor and alert on device code authentications
- **Cross-cutting**: Phishing-resistant MFA (FIDO2, Windows Hello), Conditional Access - require compliant device for all cloud app access

## Instructor Notes

- AiTM is the highest-impact technique — spend extra time here as it bypasses MFA
- Device code phishing is often underestimated; emphasize that many orgs don't even know this flow exists
- Use the illicit consent scenario to teach Graph API permission scoping — it has direct hardening value
- The "Full Chain" CTFd challenge ties all three together and previews the investigation skills needed for later modules
