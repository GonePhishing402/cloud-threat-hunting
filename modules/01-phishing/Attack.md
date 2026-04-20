# Attack: Module 01 — Cloud Identity Phishing

Modern cloud identity phishing bypasses traditional password theft. Attackers target **tokens, sessions, and OAuth consent** — meaning MFA alone is not a sufficient defense. This module covers three primary techniques used against Microsoft 365 and Entra ID environments.

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Phishing | T1566 | Delivering lures to initiate device code, AiTM, or consent flows |
| Steal Application Access Token | T1528 | Capturing access tokens via device code polling or AiTM session theft |
| Adversary-in-the-Middle | T1557 | Proxying authentication to steal session cookies and bypass MFA |
| Forge Web Credentials: Web Cookies | T1606.001 | Replaying captured session cookies from AiTM proxy |
| Valid Accounts: Cloud Accounts | T1078.004 | Using stolen tokens to authenticate as the victim |
| Phishing for Information: Spearphishing Link | T1598.003 | Crafting targeted lures pointing to device code or AiTM pages |

---

## Technique 1 — Device Code Phishing

### How It Works

The [OAuth 2.0 Device Authorization Grant flow](https://learn.microsoft.com/entra/identity-platform/v2-oauth2-device-code) is designed for input-constrained devices (smart TVs, IoT). An attacker **abuses this flow** by initiating it themselves, then social engineering the victim into completing authentication:

1. **Attacker** sends a POST request to `/oauth2/v2.0/devicecode` for the target tenant, requesting high-privilege scopes (e.g., `Mail.Read`, `Files.ReadWrite.All`)
2. **Azure AD** returns a `device_code` (for the attacker), a short `user_code`, and a `verification_uri` (`https://microsoft.com/devicelogin`)
3. **Attacker** crafts a lure email/message telling the victim: *"Your device session has expired — go to microsoft.com/devicelogin and enter code XXXXXXXX"*
4. **Victim** navigates to the legitimate Microsoft URL, signs in with their credentials and MFA
5. **Attacker** is polling the `/token` endpoint with the `device_code` — as soon as the victim completes authentication, the attacker receives a fully valid **access token and refresh token**
6. The **refresh token** can persist for up to 90 days; the attacker has durable access to M365 resources with no further victim interaction

```
POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/devicecode
Content-Type: application/x-www-form-urlencoded

client_id=<public_app_client_id>&scope=https://graph.microsoft.com/.default

# Azure AD responds with:
# user_code: "ABCDE1234"
# verification_uri: "https://microsoft.com/devicelogin"
# device_code: "<long_opaque_string>"
# expires_in: 900
```

```
# Attacker polls until victim completes auth:
POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:device_code
&client_id=<public_app_client_id>
&device_code=<device_code_from_step_1>
```

### Why It Bypasses MFA

The victim completes MFA **during the device code entry flow**. The resulting tokens are legitimate — Entra ID has no way to know the device code was initiated by an attacker unless specific Conditional Access controls are enforced.

### Attack Prerequisites

- A valid `client_id` of any Microsoft first-party or public app (e.g., Microsoft Teams, Azure CLI)
- Victim must be reachable via email, Teams, LinkedIn, or other social channel
- No malware or implant required

### Key Indicators

- Sign-in logs showing `AuthenticationProtocol == "deviceCode"` for users who never use device-constrained auth
- Sign-in from a user at one IP with a nearly simultaneous token use from a completely different IP
- Refresh token lifetimes being used to access resources for days/weeks after the initial code entry

---

## Technique 2 — AiTM Phishing with Evilginx (Session Cookie Theft)

### How It Works

[Adversary-in-the-Middle (AiTM) phishing](https://learn.microsoft.com/entra/identity/devices/protecting-tokens-microsoft-entra-id) deploys a **reverse proxy** between the victim and a legitimate Microsoft sign-in page. The proxy transparently relays all traffic — including the MFA challenge — while **capturing the session cookie** issued after successful authentication.

**Evilginx** is a popular open-source framework used for this attack. It uses custom "phishlets" configured for targets like Microsoft 365, Okta, and Google.

**Attack flow:**

1. **Attacker** registers a convincing domain (e.g., `login-microsoftonline.attacker.com`) and starts an Evilginx instance
2. **Victim** receives a phishing email with a link to the attacker's proxy domain
3. **Victim** enters credentials and completes MFA — all transparently proxied to the real `login.microsoftonline.com`
4. **Microsoft** issues a legitimate session cookie (`ESTSAUTH`, `ESTSAUTHPERSISTENT`) to the victim's browser
5. **Evilginx** intercepts this cookie before it reaches the victim's browser
6. **Attacker** imports the captured cookie into their own browser — they are now authenticated as the victim **without needing the password or MFA factor**

```
Victim → [attacker proxy domain] → Microsoft login (real)
         [proxy captures session cookie mid-transit]
          ↓
Attacker uses cookie → Authenticated as victim
```

### Why It Bypasses MFA

AiTM does not steal the password or the MFA factor. It steals the **post-authentication session token** which Microsoft issued after MFA was successfully completed. Standard MFA provides no protection because from Microsoft's perspective, the authentication was valid.

### What Attackers Do Post-Compromise

- **Business Email Compromise (BEC)** — read mail, create inbox rules to intercept conversations, redirect payments
- **Data exfiltration** — download files from SharePoint/OneDrive
- **Lateral movement** — pivot using the stolen identity to access connected apps
- **Persistence** — register a new MFA factor or add federated credentials to resist remediation

### Key Indicators

- `AnomalousToken` or `AttackerInTheMiddle` risk detections in Entra ID Protection
- `Stolen session cookie was used` alert in Microsoft Defender XDR
- `Impossible travel` or `Activity from infrequent country` in Defender for Cloud Apps
- New MFA credential registrations shortly after sign-in from an unfamiliar location
- New inbox rules created immediately after sign-in (forward, delete, mark-as-read)

---

## Technique 3 — Illicit Consent Grant

### How It Works

An [illicit consent grant attack](https://learn.microsoft.com/defender-office-365/detect-and-remediate-illicit-consent-grants) abuses the **Microsoft Entra ID OAuth consent framework**. Rather than stealing credentials, the attacker tricks a user into granting a **malicious registered application** permission to their data.

1. **Attacker** registers a multi-tenant application in their own Entra ID tenant
2. The app is configured to request high-privilege delegated permissions: e.g., `Mail.ReadWrite`, `Files.ReadWrite.All`, `Contacts.ReadWrite`, `offline_access`
3. **Victims** receive phishing emails containing an OAuth authorization link:
   `https://login.microsoftonline.com/common/oauth2/authorize?client_id=<attacker_app>&response_type=code&scope=Mail.ReadWrite...`
4. **Victim** clicks, is shown a legitimate Microsoft consent prompt, and clicks **Accept**
5. **Attacker** exchanges the authorization code for an **access token + refresh token** with the granted scopes
6. The app now has **persistent, delegated access** to all victim data covered by the consented scopes — no password reset or MFA revocation removes this access

### Why Standard Remediation Fails

Resetting passwords and revoking sessions **does not remove OAuth consent grants**. The malicious app retains its authorization until an admin explicitly revokes the grant. This gives attackers a persistent foothold that survives forced password resets and MFA re-enrollment.

### Dangerous Permission Combos to Watch

| Permission | Risk |
|---|---|
| `Mail.ReadWrite` + `offline_access` | Persistent email read/write with non-expiring refresh tokens |
| `Files.ReadWrite.All` | Full read/write on SharePoint and OneDrive |
| `Contacts.ReadWrite` | Harvest contact data for phishing expansion |
| `User.ReadWrite.All` | Modify other users' profiles and credentials (app-only pattern) |
| `AllPrincipals` (admin consent) | Tenant-wide access to all user data |

### Inventory Script

```powershell
# Download Get-AzureADPSPermissions.ps1 from GitHub (psignoret/Get-AzureADPSPermissions)
# Then run:
Connect-MgGraph -Scopes "Directory.Read.All"
.\Get-AzureADPSPermissions.ps1 | Export-Csv -Path "Permissions.csv" -NoTypeInformation

# Review:
# Column G (ConsentType) == "AllPrincipals" → tenant-wide admin consent → HIGH RISK
# Column F (Permission) contains "ReadWrite" or "All" → review carefully
# Column C (ClientDisplayName) with misspelled or vague names → suspicious
```

### Key Indicators

- Audit log events: `Consent to application` with `IsAdminConsent == True` from unexpected users
- New OAuth apps with `AllPrincipals` scope in Permissions.csv output
- Mail forwarding or download activity by an application principal (not user sign-in)
- App-only sign-ins from the malicious application appearing in sign-in logs

---

## Microsoft Learn References

- [Microsoft identity platform — OAuth 2.0 Device Authorization Grant](https://learn.microsoft.com/entra/identity-platform/v2-oauth2-device-code)
- [Protecting Tokens in Microsoft Entra (AiTM, Device Code, Token Theft)](https://learn.microsoft.com/entra/identity/devices/protecting-tokens-microsoft-entra-id)
- [Understanding Tokens in Microsoft Entra ID](https://learn.microsoft.com/entra/identity/devices/concept-tokens-microsoft-entra-id)
- [Detect and Remediate Illicit Consent Grants in Microsoft 365](https://learn.microsoft.com/defender-office-365/detect-and-remediate-illicit-consent-grants)
- [App Consent Grant Investigation Playbook](https://learn.microsoft.com/security/operations/incident-response-playbook-app-consent)
- [Alert Grading for Session Cookie Theft (AiTM)](https://learn.microsoft.com/defender-xdr/session-cookie-theft-alert)
- [Token Theft Playbook](https://learn.microsoft.com/security/operations/token-theft-playbook)
- [Conditional Access Authentication Flows — Device Code](https://learn.microsoft.com/entra/identity/conditional-access/concept-authentication-flows#device-code-flow)
- [2024 Microsoft Digital Defense Report](https://aka.ms/mddr)
