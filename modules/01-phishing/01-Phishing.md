## Slide 1: Cloud Identity Phishing

Module 01 — Illicit Consent, AiTM, and Device Code Phishing

**Speaker Notes:**
Welcome to Module 01. Modern cloud identity phishing bypasses traditional password theft. Attackers target tokens, sessions, and OAuth consent — meaning MFA alone is not a sufficient defense. This module covers three primary techniques used against Microsoft 365 and Entra ID environments: device code phishing, adversary-in-the-middle (AiTM), and illicit consent grants. We'll learn how each attack works, how to detect it in Sentinel and Defender XDR, and how to respond.

## Slide 2: Agenda

- Module Objective and MITRE ATT&CK Mapping
- Three Cloud Phishing Techniques Overview
- Device Code Phishing — Attack, Detect, Respond
- AiTM Session Cookie Theft — Attack, Detect, Respond
- Illicit Consent Grant — Attack, Detect, Respond
- Email-Layer Detection with Defender for Office 365
- Full Phishing Kill Chain KQL
- Recommended Alert Rules
- Hardening and Post-Incident Checklist
- References

**Speaker Notes:**
This module is structured around three distinct attack techniques. For each one, we'll follow the same pattern: understand the attack mechanics, learn the detection queries, and walk through the incident response steps. Then we'll cover email-layer detection using the Defender for Office 365 tables — EmailEvents, EmailUrlInfo, and UrlClickEvents. We'll finish with hardening recommendations and a post-incident checklist that applies to all three techniques.

## Slide 3: Module Objective and MITRE Mapping

!layout: Title and Content

**Objective:** Hunt for three cloud-native phishing attack patterns in Entra ID sign-in and audit data. Distinguish between traditional credential phishing and cloud-specific techniques that bypass MFA.

| Technique | ID | Tactic |
|---|---|---|
| Phishing | T1566 | Initial Access |
| Steal Application Access Token | T1528 | Credential Access |
| Adversary-in-the-Middle | T1557 | Credential Access |
| Forge Web Credentials: Web Cookies | T1606.001 | Credential Access |
| Valid Accounts: Cloud Accounts | T1078.004 | Initial Access, Persistence |
| Phishing for Information: Spearphishing Link | T1598.003 | Reconnaissance |

**Speaker Notes:**
This module maps to six MITRE ATT&CK techniques. The critical insight is that all three techniques bypass MFA — they don't steal the password, they steal the token or session that was issued after MFA completed. T1528 (Steal Application Access Token) applies to both device code phishing and illicit consent grants. T1557 and T1606.001 are specific to AiTM attacks where session cookies are intercepted and replayed. T1078.004 covers the attacker's use of stolen tokens to authenticate as the victim.

## Slide 4: Three Cloud Phishing Techniques

!layout: Title and Content

| Technique | What Attacker Steals | MFA Bypassed? | Persistence Mechanism |
|---|---|---|---|
| Device Code Phishing | Access token + refresh token | Yes — victim completes MFA during device code entry | Refresh token persists up to 90 days |
| AiTM (Evilginx) | Session cookie post-MFA | Yes — cookie captured after MFA completes | Session cookie + BEC inbox rules |
| Illicit Consent Grant | OAuth delegated permissions | N/A — no credentials stolen | OAuth grant survives password reset |

**Key insight:** Password resets and MFA re-enrollment do NOT remediate illicit consent grants. The malicious app retains its authorization until an admin explicitly revokes the OAuth grant.

**Speaker Notes:**
This comparison table is essential. Each technique has a different theft target and persistence model. Device code phishing gives the attacker durable refresh tokens. AiTM gives them a session cookie and typically leads to BEC. Illicit consent grants are the most persistent — they survive password resets, MFA changes, and session revocations because the authorization is at the application level, not the user session level. Ask the class: which technique do they think is most common in their environment? Most will say AiTM — it's the dominant technique according to the 2024 Microsoft Digital Defense Report.

## Slide 5: Key Tables for This Module

!layout: Title and Content

| Table | What It Captures | Module Use |
|---|---|---|
| SigninLogs / AADSignInEventsBeta | Interactive sign-ins, device code flows, risk detections | Device code and AiTM detection |
| AADNonInteractiveUserSignInLogs | Token refresh, SSO, silent sign-ins | Token replay after device code phishing |
| AuditLogs / CloudAppEvents | Consent grants, inbox rules, app registrations | Illicit consent and BEC detection |
| EmailEvents | Inbound/outbound email with threat verdicts | Phishing email identification |
| EmailUrlInfo | URLs extracted from emails | OAuth consent and device code lure URLs |
| UrlClickEvents | Safe Links click events | User click-through to phishing pages |

**Speaker Notes:**
This module uses more tables than any other because phishing spans identity, email, and application layers. AADSignInEventsBeta is the Advanced Hunting equivalent of SigninLogs with additional fields like AuthenticationProtocol and DetectedRiskTypes. CloudAppEvents captures application-level events like consent grants and inbox rule creation. The email tables — EmailEvents, EmailUrlInfo, and UrlClickEvents — are specific to Defender for Office 365 Advanced Hunting. All email tables are joined using NetworkMessageId, which we covered in Module 00.

## Slide 6: Device Code Phishing — How It Works

!layout: Title and Content

The OAuth 2.0 Device Authorization Grant flow is designed for input-constrained devices (smart TVs, IoT). Attackers abuse this flow by initiating it themselves, then social engineering the victim into completing authentication.

**Attack Flow:**
- Attacker sends POST to /oauth2/v2.0/devicecode requesting high-privilege scopes
- Azure AD returns a device_code (for attacker) and a user_code (for victim)
- Attacker sends phishing lure: "Go to microsoft.com/devicelogin and enter code ABCDE1234"
- Victim navigates to the legitimate Microsoft URL, signs in with credentials and MFA
- Attacker polls the /token endpoint — when victim completes auth, attacker gets access + refresh tokens
- Refresh token persists up to 90 days with no further victim interaction

**Speaker Notes:**
The key deception is that the victim is on a legitimate Microsoft URL — microsoft.com/devicelogin is real. The victim completes real MFA. From Microsoft's perspective, the authentication was valid. The attacker doesn't need malware or a proxy — just a valid client ID of any Microsoft first-party or public app like Azure CLI or Microsoft Teams. This is why it's so effective and why many organizations don't even know this flow exists. Walk through the attack flow slowly and emphasize that the attacker never touches the victim's device.

## Slide 7: Device Code Phishing — Key Indicators

!layout: Title and Content

**Red Flags in Sign-In Logs:**
- AuthenticationProtocol == "deviceCode" for users who never use CLI/IoT devices
- Sign-in from user at one IP, then immediate token use from a completely different IP
- Refresh token lifetimes used to access resources for days or weeks after initial code entry
- Resource access patterns inconsistent with the user's normal behavior

**Attack Prerequisites:**
- A valid client_id of any Microsoft first-party or public app (Azure CLI, Teams, etc.)
- Victim reachable via email, Teams, LinkedIn, or other social channel
- No malware or implant required — entirely social engineering

**Speaker Notes:**
The most reliable detection signal is AuthenticationProtocol == "deviceCode" in the sign-in logs. Most corporate users never use device code flow — it's designed for headless devices. If you see a finance team member or executive authenticating via device code, that's immediately suspicious. The IP mismatch between initial auth and subsequent token use is the second signal — the victim enters the code from their corporate network, but the attacker redeems the token from their own infrastructure. We'll look at both detection queries next.

## Slide 8: KQL — Detect Device Code Sign-Ins

!layout: Title and Content

```kql
AADSignInEventsBeta
| where Timestamp > ago(7d)
| where AuthenticationProtocol == "deviceCode"
| project Timestamp, AccountUpn, IPAddress, Country,
          DeviceName, RiskLevelDuringSignIn, ErrorCode
| order by Timestamp desc
```

**What to investigate:**
- Does this user normally use device code flow?
- Is the IPAddress from expected corporate ranges?
- Is the Country where the user typically operates?
- Did RiskLevelDuringSignIn flag anything?

**Speaker Notes:**
This is your primary detection query for device code phishing. Run this weekly as a scheduled hunt. In most corporate environments, the result set should be very small or zero. Any result warrants investigation. The DeviceName field helps distinguish legitimate device code usage (managed IoT devices will have a known device name) from phishing (typically null or unknown device). Demo this query in the lab environment and show students what a legitimate vs. suspicious result looks like.

## Slide 9: KQL — Device Code IP Mismatch Detection

!layout: Title and Content

```kql
let DeviceCodeSignIns = AADSignInEventsBeta
| where AuthenticationProtocol == "deviceCode"
| project AccountUpn, SignInIP = IPAddress,
          SignInTime = Timestamp, SessionId;

AADSignInEventsBeta
| where Timestamp > ago(7d)
| join kind=inner DeviceCodeSignIns on AccountUpn
| where IPAddress != SignInIP
| where Timestamp > SignInTime
    and Timestamp < SignInTime + 1h
| project SignInTime, Timestamp, AccountUpn,
          SignInIP, AccessIP = IPAddress, SessionId
| order by SignInTime desc
```

**Speaker Notes:**
This is the correlation query that confirms device code phishing. It finds cases where a user completed device code authentication from one IP, then the resulting token was used from a different IP within one hour. The SignInIP is where the victim entered the code. The AccessIP is where the attacker used the stolen token. If these are different — especially different countries — you have a confirmed device code phishing event. This query is highly specific and low false-positive.

## Slide 10: AiTM Phishing — How It Works

!layout: Title and Content

Adversary-in-the-Middle phishing deploys a reverse proxy between the victim and the real Microsoft sign-in page. The proxy transparently relays all traffic — including MFA — while capturing the session cookie issued after successful authentication.

**Attack Flow:**
- Attacker registers convincing domain (e.g., login-microsoftonline.attacker.com) and deploys Evilginx
- Victim receives phishing email with link to attacker's proxy domain
- Victim enters credentials and completes MFA — all proxied to real login.microsoftonline.com
- Microsoft issues session cookie (ESTSAUTH) to the victim's browser
- Evilginx intercepts the cookie before it reaches the victim
- Attacker imports cookie into their own browser — authenticated as victim without password or MFA

**Speaker Notes:**
AiTM is the highest-impact phishing technique and the most common in the wild today. Evilginx is the most popular open-source framework for this. The critical point is that MFA provides NO protection because the attacker steals the post-authentication session token, not the password or MFA factor. From Microsoft's perspective, the authentication was completely valid. The attacker's browser session is indistinguishable from the victim's except for the IP address. This is why phishing-resistant MFA like FIDO2 passkeys and certificate-based authentication are essential — they bind to the device and domain, preventing proxy-based theft.

## Slide 11: AiTM — Post-Compromise Actions

!layout: Title and Content

Once an attacker has a stolen session cookie, typical follow-on actions include:

**Business Email Compromise (BEC):**
- Read mail, search for payment discussions and invoice threads
- Create inbox rules to intercept conversations (forward, delete, mark-as-read)
- Send impersonation emails from the victim's mailbox to redirect payments

**Persistence and Lateral Movement:**
- Register a new MFA factor (phone number or authenticator app) to resist remediation
- Add federated credentials to the victim's account
- Download files from SharePoint and OneDrive
- Pivot to connected apps using the stolen identity

**Speaker Notes:**
BEC is the most financially impactful follow-on to AiTM. Attackers look for active invoice or payment threads, create inbox rules to hide their activity from the victim, and then send emails redirecting payments to attacker-controlled accounts. The inbox rule creation is a critical detection signal — we have a KQL query for that. MFA factor registration by the attacker is also common and is how they maintain access even after the session cookie expires. Emphasize to students that AiTM is not the end goal — it's the initial access that enables BEC, data theft, and lateral movement.

## Slide 12: AiTM — Key Indicators and Built-In Alerts

!layout: Title and Content

| Alert | Source | What It Detects |
|---|---|---|
| Stolen session cookie was used | Defender XDR | Session cookie replayed from different IP |
| Authentication request from AiTM phishing page | Defender XDR | Sign-in from known AiTM infrastructure |
| AnomalousToken | Entra ID Protection | Anomalous token characteristics detected |
| AttackerInTheMiddle | Entra ID Protection | ML detection of AiTM session hijack pattern |
| Impossible travel | Defender for Cloud Apps | Same user from distant locations in short window |
| User clicked through to malicious URL | Defender for Office 365 | User overrode Safe Links warning |

**Speaker Notes:**
These are all built-in alerts you should have enabled. The most important are AnomalousToken and AttackerInTheMiddle from Entra ID Protection — these require P2 licensing. The "Stolen session cookie was used" alert from Defender XDR is high-confidence and should always trigger investigation. Impossible travel from Defender for Cloud Apps catches the geographic anomaly when the attacker replays the cookie from a different location. The Safe Links click-through alert catches the phishing email click, which is earlier in the kill chain. Make sure students validate all these alerts are enabled in their environment.

## Slide 13: KQL — AiTM Risk Detections

!layout: Title and Content

```kql
AADSignInEventsBeta
| where Timestamp > ago(7d)
| where RiskLevelDuringSignIn in ("high", "medium")
| where DetectedRiskTypes has_any (
    "anomalousToken",
    "attackerInTheMiddle",
    "unfamiliarFeatures"
  )
| project Timestamp, AccountUpn, IPAddress, Country,
          RiskLevelDuringSignIn, DetectedRiskTypes,
          DeviceName
| order by Timestamp desc
```

**Key risk types for AiTM:**
- anomalousToken — token characteristics don't match normal patterns
- attackerInTheMiddle — ML model detected proxy-based session hijack
- unfamiliarFeatures — sign-in from unusual device, location, or app

**Speaker Notes:**
This query surfaces sign-ins flagged by Entra ID Protection's machine learning models. DetectedRiskTypes is the field that contains the specific risk type. For AiTM, the three most relevant are anomalousToken, attackerInTheMiddle, and unfamiliarFeatures. These detections require Entra ID Protection P2 licensing. If your environment doesn't have P2, you'll need to rely on the manual detection patterns like IP mismatch and impossible travel, which we'll cover in the lab. Run this query in the demo environment and show the results.

## Slide 14: KQL — Phishing Click to Sign-In Correlation

!layout: Title and Content

```kql
let PhishClicks = UrlClickEvents
| where ThreatTypes has "Phish"
| project ClickTime = Timestamp, AccountUpn,
          PhishUrl = Url, NetworkMessageId;

AADSignInEventsBeta
| where Timestamp > ago(7d)
| join kind=inner PhishClicks on AccountUpn
| where Timestamp > ClickTime
    and Timestamp < ClickTime + 30m
| project ClickTime, SignInTime = Timestamp,
          AccountUpn, PhishUrl,
          SignInIP = IPAddress,
          RiskLevelDuringSignIn
| order by ClickTime desc
```

**What this reveals:** Users who clicked a phishing link AND then had a sign-in event within 30 minutes — the AiTM kill chain in action.

**Speaker Notes:**
This is one of the most powerful correlation queries in this module. It joins the email layer (UrlClickEvents — when did the user click the phishing link?) with the identity layer (AADSignInEventsBeta — when did a sign-in occur?). If a user clicked a phishing URL and then had a sign-in within 30 minutes, they likely authenticated through the AiTM proxy. The PhishUrl shows which domain they visited, and SignInIP shows where the subsequent sign-in came from. If SignInIP doesn't match the user's normal IP, the attacker likely has the session cookie. This query is the bridge between email detection and identity compromise.

## Slide 15: KQL — BEC Inbox Rule Detection

!layout: Title and Content

```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType in (
    "New-InboxRule",
    "Set-InboxRule",
    "UpdateInboxRules"
  )
| extend RawData = parse_json(RawEventData)
| project Timestamp, AccountUpn, ActionType,
          IPAddress, RawData
| order by Timestamp desc
```

**Why this matters:** Inbox rule creation is the most common BEC follow-on after AiTM. Attackers create rules to:
- Forward emails to external addresses (data exfiltration)
- Delete incoming replies (hide their activity from the victim)
- Mark messages as read (prevent the victim from noticing new activity)

**Speaker Notes:**
After an attacker compromises an account via AiTM, the first thing they typically do is create inbox rules to control the victim's mailbox. The most dangerous rules forward emails to external addresses or delete specific messages. Check the RawEventData for the rule parameters — look for ForwardTo with external domains, or DeleteMessage set to true. This query should be run as part of any AiTM investigation. If you find inbox rules created from an unfamiliar IP shortly after a risky sign-in, you've confirmed BEC activity. In the lab, we'll look at real inbox rule creation events and parse the rule parameters.

## Slide 16: Illicit Consent Grant — How It Works

!layout: Title and Content

An illicit consent grant attack abuses the Entra ID OAuth consent framework. Rather than stealing credentials, the attacker tricks a user into granting a malicious application permission to their data.

**Attack Flow:**
- Attacker registers a multi-tenant app in their own Entra ID tenant
- App is configured to request high-privilege delegated permissions (Mail.ReadWrite, Files.ReadWrite.All, offline_access)
- Victim receives phishing email with an OAuth authorization link
- Victim clicks, sees a legitimate Microsoft consent prompt, and clicks Accept
- Attacker exchanges the authorization code for access + refresh tokens
- App has persistent, delegated access to all victim data covered by the consented scopes

**Speaker Notes:**
Illicit consent grants are the most persistent of the three techniques. The consent URL points to a legitimate Microsoft domain — login.microsoftonline.com/common/oauth2/authorize — which makes it hard for users to recognize as phishing. The consent prompt looks legitimate because it IS legitimate — Microsoft is genuinely asking the user to approve the permissions. The critical remediation point is that resetting passwords and revoking sessions does NOT remove the consent grant. An admin must explicitly revoke the OAuth permission grant. This is a common oversight in incident response.

## Slide 17: Dangerous Permission Combinations

!layout: Title and Content

| Permission | Risk |
|---|---|
| Mail.ReadWrite + offline_access | Persistent email read/write with non-expiring refresh tokens |
| Files.ReadWrite.All | Full read/write on SharePoint and OneDrive |
| Contacts.ReadWrite | Harvest contact data for phishing expansion |
| User.ReadWrite.All | Modify other users' profiles and credentials (app-only) |
| AllPrincipals (admin consent) | Tenant-wide access to all user data |

**Key detection signal:** AuditLogs where OperationName == "Consent to application" with IsAdminConsent == True from unexpected users, or high-privilege scopes granted to unfamiliar applications.

**Speaker Notes:**
Mail.ReadWrite combined with offline_access is the most common dangerous combination — it gives the attacker persistent access to read and modify emails. offline_access means the refresh token doesn't expire, so the attacker maintains access indefinitely until the grant is revoked. Files.ReadWrite.All gives full access to SharePoint and OneDrive. AllPrincipals scope means admin consent was granted for the entire tenant, not just one user. If you find this in your audit logs from a non-admin user, it's a strong indicator of privilege escalation. The inventory script mentioned in the Attack module — Get-AzureADPSPermissions.ps1 — should be run periodically to audit all consent grants in your tenant.

## Slide 18: KQL — Detect OAuth Consent Grants

!layout: Title and Content

```kql
CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType == "Consent to application"
| extend AppName = tostring(
    RawEventData.ExtendedProperties[0].Value
  )
| project Timestamp, AccountUpn, AppName,
          IPAddress, RawEventData
| order by Timestamp desc
```

**What to investigate:**
- Is the application recognized and approved by your organization?
- Was consent granted from an expected IP and location?
- What scopes were granted (check RawEventData)?
- Is this the first time this app received consent in the tenant?

**Speaker Notes:**
This query surfaces all consent grant events in the last 30 days. The extended time window is important because consent grant attacks often have a long dwell time — the attacker may wait days or weeks before actively abusing the permissions. The AppName from RawEventData tells you which application received the consent. Cross-reference this against your approved app inventory. Any unfamiliar app name warrants immediate investigation. Also check the IPAddress — if consent was granted from an IP that doesn't match the user's normal location, it may have been granted via a phishing link.

## Slide 19: KQL — Detect App-Based Mail Access

!layout: Title and Content

```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType == "MailItemsAccessed"
| where isnotempty(ApplicationId)
| project Timestamp, AccountUpn, ApplicationId,
          ActionType, IPAddress
| order by Timestamp desc
```

**Why this matters:** After a consent grant, the attacker accesses email through the malicious application, not through a user sign-in. This query finds mail access by application principals — the footprint of an active consent grant attack.

**Speaker Notes:**
This is a subtle but critical detection pattern. Normal email access happens through the user's browser or Outlook client. After an illicit consent grant, the attacker reads email through the malicious application's API access. The ApplicationId field being populated indicates it was an app-based access, not a user-interactive session. If you see MailItemsAccessed with an ApplicationId that doesn't match Microsoft Outlook, Exchange Online, or another legitimate mail client, investigate immediately. In the lab, you'll see the difference between user-interactive mail access and application-based access.

## Slide 20: Email Detection — Table Overview

!layout: Title and Content

Microsoft Defender for Office 365 provides deep email-layer detection:

| Table | What It Contains | Key Use |
|---|---|---|
| EmailEvents | Every inbound/outbound email — sender, recipient, delivery action, threat verdict | Primary phishing hunt table |
| EmailUrlInfo | All URLs extracted from email bodies, attachments, and QR codes | Hunt for phishing and consent grant URLs |
| EmailAttachmentInfo | Attachment metadata — filename, file type, SHA256, threat verdict | HTML smuggling and malicious attachment detection |
| UrlClickEvents | Safe Links click events — every URL a user clicks from email, Teams, or Office | Confirm user interaction with phishing links |

**Correlation Key:** NetworkMessageId joins all four tables.

**Speaker Notes:**
These tables are from the Defender for Office 365 Advanced Hunting schema. They provide visibility into the email delivery pipeline that Sentinel tables don't have. EmailEvents is your starting point — it shows what was delivered, what was blocked, and what verdict was applied. EmailUrlInfo extracts every URL including those embedded in QR codes. UrlClickEvents is the confirmation layer — it shows whether a user actually clicked a phishing link. The join key across all tables is NetworkMessageId, which we learned in Module 00.

## Slide 21: KQL — Phishing Delivered to Inbox

!layout: Title and Content

```kql
EmailEvents
| where Timestamp > ago(7d)
| where ThreatTypes has "Phish"
| where DeliveryAction == "Delivered"
| where DeliveryLocation == "Inbox/Folder"
| project Timestamp, NetworkMessageId,
          SenderFromAddress, SenderFromDomain,
          RecipientEmailAddress, Subject,
          DetectionMethods, ConfidenceLevel,
          UrlCount, AttachmentCount,
          LatestDeliveryAction
| order by Timestamp desc
```

**This is your most actionable starting point:** Phishing-verdicted email that reached the inbox — not blocked, not junked — the user likely saw it.

**Speaker Notes:**
This query finds the gap in your defenses — phishing emails that were correctly classified but still delivered to the inbox. DeliveryAction == "Delivered" with DeliveryLocation == "Inbox/Folder" means the user has the email in front of them. Check LatestDeliveryAction to see if ZAP moved it after initial delivery. The UrlCount and AttachmentCount fields tell you whether to pivot to EmailUrlInfo or EmailAttachmentInfo for additional context. DetectionMethods shows which detection technology flagged it. This query should be run weekly as a minimum hunting cadence.

## Slide 22: KQL — Full Phishing Kill Chain

!layout: Title and Content

Three-table join: Email delivery, URL extraction, and user click — correlated via NetworkMessageId.

```kql
EmailEvents
| where Timestamp > ago(7d)
| where ThreatTypes has "Phish"
| where DeliveryAction == "Delivered"
| project NetworkMessageId, SenderFromAddress,
          RecipientEmailAddress, Subject,
          DeliveryLocation, EmailTimestamp = Timestamp
| join kind=inner (
    EmailUrlInfo
    | project NetworkMessageId, ExtractedUrl = Url,
              UrlDomain, UrlLocation
  ) on NetworkMessageId
| join kind=inner (
    UrlClickEvents
    | project NetworkMessageId, AccountUpn,
              ClickedUrl = Url, IsClickedThrough,
              ClickTimestamp = Timestamp, IPAddress
  ) on NetworkMessageId
| project EmailTimestamp, ClickTimestamp,
          RecipientEmailAddress, SenderFromAddress,
          Subject, ExtractedUrl, UrlDomain,
          IsClickedThrough, IPAddress
| order by EmailTimestamp desc
```

**Speaker Notes:**
This is the most complete phishing detection query in the module. It reconstructs the full kill chain: the email arrived, the URL was extracted and analyzed, and the user clicked it. The IsClickedThrough field is the highest severity signal — it means the user clicked past a Safe Links warning. This query gives you everything you need to start an incident: who received the email, who sent it, what URL it contained, whether the user clicked, and from which IP. In the lab, students will run this query and trace a complete phishing attack from email delivery to user interaction.

## Slide 23: KQL — QR Code Phishing Detection

!layout: Title and Content

QR code phishing bypasses text-based URL scanning. The URL is embedded in an image, not in email text.

```kql
EmailUrlInfo
| where Timestamp > ago(7d)
| where UrlLocation == "QRCode"
| join kind=inner (
    EmailEvents
    | where DeliveryAction == "Delivered"
    | project NetworkMessageId, RecipientEmailAddress,
              SenderFromAddress, Subject, Timestamp
  ) on NetworkMessageId
| project Timestamp, RecipientEmailAddress,
          SenderFromAddress, Subject,
          Url, UrlDomain, UrlLocation,
          NetworkMessageId
| order by Timestamp desc
```

**Why QR codes matter:** Users scan with personal devices (outside corporate protection), bypassing Safe Links and endpoint security entirely.

**Speaker Notes:**
QR code phishing — sometimes called "quishing" — is a rapidly growing technique. The URL is encoded in a QR code image in the email body. Users scan with their personal phone camera, which takes them to the phishing page outside of any corporate security controls. The UrlLocation == "QRCode" filter in EmailUrlInfo is a relatively new capability in Defender for Office 365. If you find delivered emails with QR code URLs, these are high priority because users who scan them are completely unprotected by Safe Links.

## Slide 24: KQL — OAuth and Device Code Email Lures

!layout: Title and Content

Find emails that contain URLs matching OAuth consent or device login endpoints — the lure phase for consent grant and device code attacks.

```kql
EmailUrlInfo
| where Timestamp > ago(7d)
| where Url has_any (
    "microsoft.com/devicelogin",
    "login.microsoftonline.com/common/oauth2/authorize",
    "response_type=code",
    "client_id="
  )
| join kind=inner (
    EmailEvents
    | where DeliveryAction == "Delivered"
    | project NetworkMessageId, RecipientEmailAddress,
              SenderFromAddress, Subject,
              ThreatTypes, Timestamp
  ) on NetworkMessageId
| project Timestamp, RecipientEmailAddress,
          SenderFromAddress, Subject, Url,
          UrlDomain, ThreatTypes
| order by Timestamp desc
```

**Speaker Notes:**
This query catches the phishing email BEFORE the user acts on it. It looks for delivered emails containing URLs that point to OAuth consent endpoints or the device login page. These are the lure emails for device code phishing and illicit consent grant attacks. The URL patterns are specific: microsoft.com/devicelogin for device code, and login.microsoftonline.com with oauth2/authorize and client_id for consent grants. If you find these, immediately check whether any recipients clicked through using UrlClickEvents. This query can also be converted into an analytics rule for continuous monitoring.

## Slide 25: Recommended Alert Rules

!layout: Title and Content

| Alert Condition | Source | Severity |
|---|---|---|
| Device code sign-in for corporate user | AADSignInEventsBeta: AuthenticationProtocol == "deviceCode" | High |
| AiTM session cookie reuse | Built-in: "Stolen session cookie was used" | High |
| Risk detection: AnomalousToken | Entra ID Protection: anomalousToken risk event | High |
| Safe Links click-through to phishing | UrlClickEvents: IsClickedThrough == true, ThreatTypes has "Phish" | High |
| OAuth consent to new app | CloudAppEvents: ActionType == "Consent to application" for first-seen app | High |
| Admin consent granted | AuditLogs: Consent to application where IsAdminConsent == True from non-GA | High |
| New inbox rule from app principal | CloudAppEvents: ActionType contains "InboxRule" from app sign-in | High |

**Speaker Notes:**
These seven alert rules cover all three attack techniques. Every one should be configured as at minimum a High severity analytics rule or NRT rule in Sentinel. The device code sign-in alert should fire on any occurrence since most corporate users never use device code flow. The AiTM alerts leverage built-in detections from Entra ID Protection and Defender XDR. The consent grant and inbox rule alerts cover the persistence and BEC phases. Walk students through how to create at least one of these as an analytics rule in the lab.

## Slide 26: Incident Response — Device Code Phishing

!layout: Title and Content

**Immediate Containment:**
- Revoke all refresh tokens: `Invoke-MgInvalidateUserRefreshToken -UserId <UPN>`
- Set user risk to HIGH in Entra ID Protection (triggers risk-based CA block)
- Block sign-in if confirmed compromised: `Update-MgUser -UserId <UPN> -AccountEnabled $false`

**Investigation:**
- Identify resources accessed after the device code sign-in (Graph API, email, files)
- Check for lateral movement from the compromised identity
- Review AADNonInteractiveUserSignInLogs for token refresh activity from attacker IP

**Recovery:**
- Force password reset on next sign-in
- Re-enable account after investigation complete
- Force MFA re-registration

**Speaker Notes:**
The most critical immediate action is revoking refresh tokens. Device code phishing gives the attacker a long-lived refresh token that can persist for 90 days. Disabling the account and revoking tokens cuts off the attacker's access immediately. Setting the user risk to HIGH in Entra ID Protection triggers any risk-based Conditional Access policies, which provides additional protection if you have policies configured for high-risk sign-ins. After containment, investigate what the attacker accessed — check MicrosoftGraphActivityLogs and CloudAppEvents for the attacker's IP.

## Slide 27: Incident Response — AiTM Session Cookie Theft

!layout: Title and Content

**Immediate Containment:**
- Revoke all sessions and refresh tokens
- Check for and remove attacker-registered MFA methods (Entra ID > Users > Authentication methods)
- Remove attacker-created inbox rules: `Get-InboxRule -Mailbox <UPN>` then `Remove-InboxRule`
- Disable account pending investigation

**Check for BEC Activity:**
- Review forwarding rules and inbox rules created after the compromise
- Check for emails sent from the victim's mailbox to external recipients
- Review payment-related conversations for manipulation

**Key Remediation Difference:** Unlike device code phishing, AiTM often requires cleaning up BEC artifacts (inbox rules, sent emails, modified contacts).

**Speaker Notes:**
AiTM remediation is more complex than device code because of the BEC follow-on activity. You must check for attacker-registered MFA methods — the attacker may have added a phone number or authenticator app during the session. Inbox rules are critical — the attacker may have created rules to forward all incoming email to an external address, or to delete messages from specific senders. Use Get-InboxRule to enumerate all rules and look for anything created during or after the attack window. Also check Registered Devices in Entra ID — the attacker may have registered their device to maintain access.

## Slide 28: Incident Response — Illicit Consent Grant

!layout: Title and Content

**Immediate Containment:**
- Revoke the OAuth consent grant (do NOT just reset the password):

```powershell
$grants = Get-MgOauth2PermissionGrant `
    -Filter "principalId eq '<user-object-id>'"
Remove-MgOauth2PermissionGrant `
    -OAuth2PermissionGrantId <grant-id>
```

- Remove application role assignments for app-only grants
- Disable the malicious application (do NOT delete — prevents re-consent if deleted)

**Critical Point:** Password resets and session revocations do NOT remove OAuth consent grants. The grant must be explicitly revoked by an admin.

**Speaker Notes:**
This is the most important remediation point in the entire module. Many incident responders will reset the password, revoke sessions, and close the incident — but the consent grant is still active. The attacker's application still has delegated access to the victim's data. You must explicitly revoke the OAuth permission grant using Remove-MgOauth2PermissionGrant. Do NOT delete the malicious application — disabling it is sufficient. If you delete it, the attacker can re-register it with the same client ID and the consent grant may be re-established. Disable the app via Entra admin center: Enterprise Applications > Properties > Enabled for sign-in: No.

## Slide 29: Hardening — Device Code Flow

!layout: Title and Content

**Conditional Access Policy:**
- Name: "Block Device Code Flow — Corporate Users"
- Target: All users (exclude break-glass accounts)
- Authentication flows: Device code flow — BLOCK
- Reference: Conditional Access Authentication Flows policy

**Why this works:** If device code flow is blocked by policy, the attacker's POST to /oauth2/v2.0/devicecode returns an error — the attack fails at step 1.

**Residual Risk:** Users with legitimate device code flow needs (IoT devices, CLI tools) need a documented exception. Monitor exceptions closely.

**Speaker Notes:**
This is the single most effective control against device code phishing. If you block the device code flow at the Conditional Access level, the attack is completely prevented — the attacker can't even initiate the flow. The Conditional Access Authentication Flows policy was introduced specifically to address this threat. For organizations that need device code flow for legitimate purposes (Azure CLI, IoT devices), create a narrowly scoped exception and monitor it. Ask students: has anyone configured this policy in their environment? Walk through the configuration in the Entra admin center.

## Slide 30: Hardening — AiTM and Consent Grants

!layout: Title and Content

**AiTM Hardening:**
- Deploy phishing-resistant MFA (FIDO2 passkeys, certificate-based auth) — binds to device and domain
- Enable Continuous Access Evaluation (CAE) — revokes sessions in near-real-time
- Enable Token Protection in Conditional Access (preview) — binds tokens to the device
- Enable Entra ID Protection risk-based CA: sign-in risk >= Medium requires MFA, User risk = High blocks

**Consent Grant Hardening:**
- Disable user consent or restrict to verified publishers with low-risk permissions
- Enable admin consent workflow — require admin approval for all third-party apps
- Assign consent reviewers from the security team
- Run periodic consent grant audits with Get-AzureADPSPermissions.ps1

**Speaker Notes:**
For AiTM, phishing-resistant MFA is the definitive control. FIDO2 passkeys and certificate-based authentication bind the authentication to the specific device and domain — they cannot be proxied through an AiTM reverse proxy. CAE and Token Protection provide additional layers. For consent grants, the most effective control is disabling user consent entirely and requiring admin approval for all third-party apps. This eliminates the attack vector completely. Organizations that can't disable user consent should restrict it to verified publishers with low-risk permissions only.

## Slide 31: Post-Incident Checklist

!layout: Title and Content

| Action | Notes |
|---|---|
| Scope all affected accounts | Check for lateral movement from the initial compromised identity |
| Review BEC-related actions | Invoice discussions read, forwarding rules, external emails sent |
| Audit all OAuth consent grants | Run Get-AzureADPSPermissions.ps1 for all users post-incident |
| Validate alert coverage | Confirm AnomalousToken, AiTM, and Consent alerts are firing |
| Update Conditional Access | Block device code flow; enforce phishing-resistant MFA |
| Notify affected users | Advise users what was accessed and actions taken |
| Document IOCs | AiTM proxy domains, malicious app client IDs, attacker IPs |

**Lessons Learned (capture within 72 hours):** Which technique was used, dwell time from first event to detection, resources accessed, controls that failed, CA policy gaps identified.

**Speaker Notes:**
This checklist should be completed for every phishing compromise. The most commonly missed step is auditing all OAuth consent grants — not just the affected user, but tenant-wide. The attacker may have phished multiple users in the same campaign. Document the IOCs — AiTM proxy domains should be added to your Tenant Allow/Block List, and malicious app client IDs should be blocked at the app governance level. The lessons-learned document should be completed within 72 hours while the details are fresh. This feeds back into the hunt loop — confirmed findings become analytics rules and hardening improvements.

## Slide 32: References

!layout: Title and Content

| Resource | Link |
|---|---|
| Phishing Investigation Playbook | learn.microsoft.com/security/operations/incident-response-playbook-phishing |
| Token Theft Playbook | learn.microsoft.com/security/operations/token-theft-playbook |
| App Consent Grant Investigation | learn.microsoft.com/security/operations/incident-response-playbook-app-consent |
| Detect Illicit Consent Grants | learn.microsoft.com/defender-office-365/detect-and-remediate-illicit-consent-grants |
| Protecting Tokens in Entra ID | learn.microsoft.com/entra/identity/devices/protecting-tokens-microsoft-entra-id |
| OAuth 2.0 Device Authorization Grant | learn.microsoft.com/entra/identity-platform/v2-oauth2-device-code |
| CA Authentication Flows (Device Code) | learn.microsoft.com/entra/identity/conditional-access/concept-authentication-flows |
| Alert Grading for AiTM Cookie Theft | learn.microsoft.com/defender-xdr/session-cookie-theft-alert |
| Entra ID Protection Risk Detections | learn.microsoft.com/entra/id-protection/concept-identity-protection-risks |
| 2024 Microsoft Digital Defense Report | aka.ms/mddr |

**Speaker Notes:**
These are the official Microsoft resources for deep reference. The three investigation playbooks — Phishing, Token Theft, and App Consent Grant — are the gold standard for incident response procedures. The Conditional Access Authentication Flows documentation shows exactly how to block device code flow. Encourage students to bookmark these and review them before running the lab exercises.
