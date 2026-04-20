# Defend: Module 01 — Cloud Identity Phishing Detection

This guide focuses on detecting device code phishing, AiTM session cookie theft, and illicit consent grant attacks using **Microsoft Defender for Office 365** telemetry, **Advanced Hunting** in Microsoft Defender XDR, and **Entra ID** sign-in/audit logs.

---

## 1. Defender for Office 365 Telemetry Overview

Microsoft Defender for Office 365 provides multiple detection layers for phishing that feeds into Microsoft Defender XDR:

| Signal Layer | What It Covers |
|---|---|
| **Safe Links** | URL click-time analysis — detects and blocks phishing URLs at click |
| **Threat Explorer** | Near real-time view of all email with phishing verdicts, URL clicks, and delivery actions |
| **Real-time Detections** | Plan 1 equivalent of Threat Explorer |
| **Email Entity Page** | Full message analysis — headers, URLs, attachments, and detection details |
| **Campaign Views** | Groups related phishing messages into attack campaigns for broad analysis |
| **AIR (Automated Investigation)** | Auto-investigates alerts and surfaces affected users, messages, and URLs |

### Key Log Tables (Advanced Hunting)

| Table | Description |
|---|---|
| `EmailEvents` | All inbound/outbound email — sender, recipient, subject, delivery action, detection technology |
| `EmailUrlInfo` | URLs extracted from email messages |
| `EmailPostDeliveryEvents` | Post-delivery actions (ZAP, manual remediation) |
| `UrlClickEvents` | Safe Links URL clicks — user, URL, click verdict, click-through status |
| `CloudAppEvents` | App-level events including OAuth consent grants, inbox rule creation, and file access |
| `AADSignInEventsBeta` | Entra ID sign-in log — authentication protocol, IP, device, risk level, error codes |
| `IdentityLogonEvents` | Identity-sourced logon events (Defender for Identity) |
| `AlertInfo` / `AlertEvidence` | Correlated alerts and attached evidence entities |

---

## 2. Detecting Device Code Phishing

### What to Look For

- Sign-ins using `AuthenticationProtocol == "deviceCode"` from users who do not operate headless/IoT devices
- Access token used from a different IP/country than where the device code was entered
- Sudden M365 access (email reads, file downloads) immediately after a device code sign-in the user did not initiate

### Advanced Hunting — Device Code Sign-Ins

```kusto
// Detect device code flow sign-ins in Entra sign-in logs
AADSignInEventsBeta
| where Timestamp > ago(7d)
| where AuthenticationProtocol == "deviceCode"
| project Timestamp, AccountUpn, IPAddress, Country, DeviceName, RiskLevelDuringSignIn, ErrorCode
| order by Timestamp desc
```

```kusto
// Correlate device code sign-ins with subsequent resource access from a different IP
let DeviceCodeSignIns = AADSignInEventsBeta
| where AuthenticationProtocol == "deviceCode"
| project AccountUpn, SignInIP = IPAddress, SignInTime = Timestamp, SessionId;

AADSignInEventsBeta
| where Timestamp > ago(7d)
| join kind=inner DeviceCodeSignIns on AccountUpn
| where IPAddress != SignInIP
| where Timestamp > SignInTime and Timestamp < SignInTime + 1h
| project SignInTime, Timestamp, AccountUpn, SignInIP, AccessIP = IPAddress, SessionId
| order by SignInTime desc
```

```kusto
// Look for email/file activity immediately following a device code sign-in
let DeviceCodeUsers = AADSignInEventsBeta
| where AuthenticationProtocol == "deviceCode"
| distinct AccountUpn;

CloudAppEvents
| where Timestamp > ago(7d)
| where AccountObjectId in (DeviceCodeUsers) or AccountUpn in (DeviceCodeUsers)
| where ActionType in ("MailItemsAccessed", "FileDownloaded", "FileSyncDownloadedFull")
| project Timestamp, AccountUpn, ActionType, ObjectName, IPAddress
| order by Timestamp desc
```

### Threat Explorer — Device Code Phishing Lures

Navigate to **Microsoft Defender portal** > **Email & collaboration** > **Explorer** > **Phish** view:

1. Filter by **Detection technology** = `URL reputation` or `Advanced filter`
2. Look for messages with subject lines containing phrases like "device session", "sign in required", "microsoft.com/devicelogin", or code-like strings (e.g., "BDXLQ")
3. Review **Safe Links click verdicts** for links pointing to `microsoft.com/devicelogin` or similar Microsoft auth pages that were used as lures

---

## 3. Detecting AiTM Session Cookie Theft (Evilginx)

### Built-in Alerts to Enable and Monitor

| Alert | Source | Description |
|---|---|---|
| **Stolen session cookie was used** | Defender XDR / Cloud Apps | Session cookie replayed from a different IP — high confidence AiTM indicator |
| **Authentication request from AiTM-related phishing page** | Defender XDR | Sign-in originated from a known AiTM phishing infrastructure |
| **AnomalousToken** | Entra ID Protection | Anomalous token characteristics detected (atypical claims, unusual origin) |
| **AttackerInTheMiddle** | Entra ID Protection | Machine learning detection of AiTM session hijack pattern |
| **Impossible travel** | Defender for Cloud Apps | Same user authenticated from two geographically distant locations in a short window |
| **A potentially malicious URL click was detected** | Defender for Office 365 | Safe Links detected and blocked a phishing URL click |
| **A user clicked through to a potentially malicious URL** | Defender for Office 365 | User overrode Safe Links warning and navigated to phishing page |

### Advanced Hunting — Session Cookie Replay Detection

```kusto
// Find sign-ins flagged as Anomalous Token or AiTM by Entra ID Protection
AADSignInEventsBeta
| where Timestamp > ago(7d)
| where RiskLevelDuringSignIn in ("high", "medium")
| where DetectedRiskTypes has_any ("anomalousToken", "attackerInTheMiddle", "unfamiliarFeatures")
| project Timestamp, AccountUpn, IPAddress, Country, RiskLevelDuringSignIn, DetectedRiskTypes, DeviceName
| order by Timestamp desc
```

```kusto
// Detect URL clicks to known phishing URLs that bypassed Safe Links (click-through)
UrlClickEvents
| where Timestamp > ago(7d)
| where ThreatTypes has "Phish"
| where ActionType == "ClickAllowed" or IsClickedThrough == true
| project Timestamp, AccountUpn, Url, ActionType, IsClickedThrough, NetworkMessageId, IPAddress
| order by Timestamp desc
```

```kusto
// Correlate phishing click event with follow-on sign-in (AiTM kill chain)
let PhishClicks = UrlClickEvents
| where ThreatTypes has "Phish"
| project ClickTime = Timestamp, AccountUpn, PhishUrl = Url, NetworkMessageId;

AADSignInEventsBeta
| where Timestamp > ago(7d)
| join kind=inner PhishClicks on AccountUpn
| where Timestamp > ClickTime and Timestamp < ClickTime + 30m
| project ClickTime, SignInTime = Timestamp, AccountUpn, PhishUrl, SignInIP = IPAddress, RiskLevelDuringSignIn
| order by ClickTime desc
```

```kusto
// Detect inbox rule creation shortly after sign-in — common BEC follow-on after AiTM
CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType in ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules")
| extend RawData = parse_json(RawEventData)
| project Timestamp, AccountUpn, ActionType, IPAddress, RawData
| order by Timestamp desc
```

### Threat Explorer — AiTM Phishing URLs

1. Open **Threat Explorer** > **Phish** view
2. Filter by **Click verdict** = `Blocked` or `Blocked overridden`
3. Filter by **Detection technology** = `URL detonation` or `URL reputation`
4. Review the **top URLs** tab for AiTM proxy domains (typically impersonate Microsoft login pages with slight domain variations)
5. For confirmed phishing messages, select **Take action** > **Trigger investigation** to start AIR

---

## 4. Detecting Illicit Consent Grant

### Audit Log — Consent to Application Events

1. Navigate to **Microsoft Defender portal** > **Audit** (https://security.microsoft.com/auditlogsearch)
2. Set date range to last 90 days
3. Under **Activities**, search for: `Consent to application`
4. Review results for:
   - `IsAdminConsent == True` from non-admin users (delegated admin consent abuse)
   - Unfamiliar application display names
   - High-privilege scopes: `Mail.ReadWrite`, `Files.ReadWrite.All`, `offline_access`, `User.ReadWrite.All`

### Advanced Hunting — OAuth Consent and App Activity

```kusto
// Find OAuth consent grant events in CloudAppEvents
CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType == "Consent to application"
| extend AppName = tostring(RawEventData.ExtendedProperties[0].Value)
| project Timestamp, AccountUpn, AppName, IPAddress, RawEventData
| order by Timestamp desc
```

```kusto
// Detect mail access by application (non-user) principal — may indicate consent abuse
CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType == "MailItemsAccessed"
| where isnotempty(ApplicationId)
| project Timestamp, AccountUpn, ApplicationId, ApplicationDisplayName = tostring(RawEventData.AppAccessContext), ActionType, IPAddress
| order by Timestamp desc
```

```kusto
// Find sign-ins by application using delegated permissions (app + user combo)
AADSignInEventsBeta
| where Timestamp > ago(7d)
| where isnotempty(ApplicationId)
| where AuthenticationRequirement == "singleFactorAuthentication"
| where ResourceDisplayName has_any ("Microsoft Graph", "Office 365 SharePoint Online", "Microsoft 365")
| project Timestamp, AccountUpn, ApplicationDisplayName, ApplicationId, IPAddress, ResourceDisplayName
| order by Timestamp desc
```

```kusto
// Look for new application registrations or service principal creations (control plane)
CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType in ("Add application", "Add service principal", "Add OAuth2PermissionGrant")
| project Timestamp, AccountUpn, ActionType, IPAddress, RawEventData
| order by Timestamp desc
```

### Threat Explorer — Phishing Emails Delivering Consent URLs

1. Open **Threat Explorer** > **Phish** view
2. Filter by **URL domain** for known attacker infrastructure or `login.microsoftonline.com` with suspicious query parameters
3. Look for emails with links containing `oauth2/authorize`, `response_type=code`, and unfamiliar `client_id` values
4. Cross-reference the `client_id` against your tenant's registered app inventory in Entra ID

---

## 5. Recommended Alert Rules

| Alert | Condition | Severity |
|---|---|---|
| Device code sign-in for corporate user | `AADSignInEventsBeta` where `AuthenticationProtocol == "deviceCode"` for managed users | High |
| AiTM session cookie reuse | `Stolen session cookie was used` alert (built-in Defender XDR) | High |
| Risk detection: AnomalousToken | Entra ID Protection risk event `anomalousToken` | High |
| Safe Links click-through to phish | `UrlClickEvents` where `ThreatTypes has "Phish"` and `IsClickedThrough == true` | Medium |
| OAuth consent to new app | `CloudAppEvents` where `ActionType == "Consent to application"` for first-seen app | High |
| Admin consent granted | Audit log `Consent to application` where `IsAdminConsent == True` from non-GA | High |
| New inbox rule from app principal | `CloudAppEvents` where `ActionType contains "InboxRule"` from app sign-in | High |

---

## 6. Microsoft Learn References

- [Threat Explorer and Real-time Detections in Defender for Office 365](https://learn.microsoft.com/defender-office-365/threat-explorer-threat-hunting)
- [Email Security with Threat Explorer — URL Click Verdict Data](https://learn.microsoft.com/defender-office-365/threat-explorer-email-security)
- [About Threat Explorer and Real-time Detections](https://learn.microsoft.com/defender-office-365/threat-explorer-real-time-detections-about)
- [UrlClickEvents Table — Advanced Hunting Reference](https://learn.microsoft.com/defender-xdr/advanced-hunting-urlclickevents-table)
- [Hunt for Threats Across Devices, Emails, Apps, and Identities](https://learn.microsoft.com/defender-xdr/advanced-hunting-query-emails-devices)
- [Alert Grading for Session Cookie Theft (AiTM)](https://learn.microsoft.com/defender-xdr/session-cookie-theft-alert)
- [Token Theft Playbook](https://learn.microsoft.com/security/operations/token-theft-playbook)
- [Phishing Investigation Playbook](https://learn.microsoft.com/security/operations/incident-response-playbook-phishing)
- [Detect and Remediate Illicit Consent Grants in Microsoft 365](https://learn.microsoft.com/defender-office-365/detect-and-remediate-illicit-consent-grants)
- [Protecting Tokens in Microsoft Entra — Detect and Mitigate](https://learn.microsoft.com/entra/identity/devices/protecting-tokens-microsoft-entra-id)
- [Entra ID Protection Risk Detections](https://learn.microsoft.com/entra/id-protection/concept-identity-protection-risks)
- [Defender for Office 365 Threat Management Alert Policies](https://learn.microsoft.com/defender-xdr/alert-policies#threat-management-alert-policies)
