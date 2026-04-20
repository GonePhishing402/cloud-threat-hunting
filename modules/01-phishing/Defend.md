# Defend: Module 01 — Cloud Identity Phishing Detection

This guide focuses on detecting device code phishing, AiTM session cookie theft, and illicit consent grant attacks using the **Microsoft Defender for Office 365 Advanced Hunting** tables: `EmailEvents`, `EmailUrlInfo`, `EmailAttachmentInfo`, and `UrlClickEvents`. The **`NetworkMessageId`** field is the primary key for correlating events across all four tables.

---

## Table Overview

| Table | What It Contains | Key Use |
|---|---|---|
| `EmailEvents` | Every inbound/outbound email — sender, recipient, delivery action, threat verdict | Primary email hunt table; pivots to all others via `NetworkMessageId` |
| `EmailUrlInfo` | All URLs extracted from email bodies and attachments | Hunt for phishing domains and QR code URLs before the user clicks |
| `EmailAttachmentInfo` | Attachment metadata including filename, file type, SHA256, and threat verdict | Hunt for malicious attachment lures (HTML smuggling, .lnk files) |
| `UrlClickEvents` | Safe Links click events — every URL a user clicks from email, Teams, or Office apps | Confirm whether a user actually clicked a phishing link; check `IsClickedThrough` |

---

## Correlation Key: `NetworkMessageId`

`NetworkMessageId` is the **Microsoft 365-generated unique identifier** for each email message. It is present in all four tables and is the correct join key for correlating email metadata, URL extraction, attachment metadata, and click events for the same message.

> **Note:** `NetworkMessageId` is distinct from `InternetMessageId` (the public RFC 5322 `Message-ID` set by the sending server). Always use `NetworkMessageId` for joins within the Advanced Hunting schema.

Reference: [EmailEvents table — Advanced Hunting schema](https://learn.microsoft.com/microsoft-365/security/defender/advanced-hunting-emailevents-table)

---

## `EmailEvents` — Key Fields

| Field | Type | Why It Matters for Phishing |
|---|---|---|
| `NetworkMessageId` | string | **Primary correlation key** — links to `EmailUrlInfo`, `EmailAttachmentInfo`, and `UrlClickEvents` |
| `SenderFromAddress` | string | The visible FROM address — commonly spoofed; compare against `SenderMailFromAddress` for mismatch (display name spoofing) |
| `SenderMailFromAddress` | string | The MAIL FROM / envelope sender (Return-Path) — used for SPF evaluation; often differs from `SenderFromAddress` in phishing |
| `SenderFromDomain` | string | Sender domain shown to the user — look for lookalike domains (e.g., `micros0ft.com`, `microsoft-support.net`) |
| `SenderIPv4` | string | IP of the last mail relay — compare against sender domain's MX/SPF records for mismatch |
| `RecipientEmailAddress` | string | Target user — correlate with privileged account list (admins, finance, C-suite) |
| `Subject` | string | Phishing lure text — search for urgency keywords, invoice subjects, "device code" lures |
| `DeliveryAction` | string | `Delivered`, `Junked`, `Blocked`, or `Replaced` — filter to `Delivered` to find what reached the inbox |
| `DeliveryLocation` | string | Where the message was placed: `Inbox/Folder`, `Junk`, `Quarantine`, `Deleted items` — `Inbox/Folder` means the user likely saw it |
| `ThreatTypes` | string | Pipeline verdict: `Phish`, `Malware`, `Spam`, `None` — primary filter for phishing hunts |
| `DetectionMethods` | string | What caught it: `URL reputation`, `URL detonation`, `Advanced filter`, `Anti-phish`, `Spoof intelligence`, `DMARC`, `General filter` |
| `ConfidenceLevel` | string | For phishing: `High` or `Low` confidence. For spam: Spam Confidence Level (SCL) numeric |
| `AuthenticationDetails` | string | JSON of DMARC, DKIM, SPF, and CompAuth results — a failed `compauth` with a delivered verdict is a high-signal indicator |
| `AttachmentCount` | int | Messages with attachments — pivot to `EmailAttachmentInfo` on `NetworkMessageId` |
| `UrlCount` | int | Messages with URLs — pivot to `EmailUrlInfo` on `NetworkMessageId` |
| `EmailActionPolicy` | string | Which policy made the final verdict: `Anti-phishing user impersonation`, `Anti-phishing spoof`, `Safe Attachments`, etc. |
| `LatestDeliveryLocation` | string | Most recent known location post-ZAP or admin remediation — different from original `DeliveryLocation` if ZAP moved the message |
| `LatestDeliveryAction` | string | Last action taken: may show `ZAP` moved a delivered phishing message to Junk after initial delivery |
| `EmailClusterId` | long | Groups similar phishing messages by content heuristics — useful for correlating a phishing campaign |

---

## `EmailUrlInfo` — Key Fields

| Field | Type | Why It Matters for Phishing |
|---|---|---|
| `NetworkMessageId` | string | **Join key** back to `EmailEvents` and forward to `UrlClickEvents` |
| `Url` | string | Full URL extracted from the email — look for device login pages, OAuth consent URLs, AiTM domains |
| `UrlDomain` | string | Domain portion only — useful for aggregating by domain across a campaign |
| `UrlLocation` | string | Where in the email the URL appeared: `Body`, `Subject`, `Attachment`, `QRCode` — **`QRCode` identifies phishing QR codes** |
| `ReportId` | string | Event identifier — use with `Timestamp` for deduplication |

Reference: [EmailUrlInfo table — Advanced Hunting schema](https://learn.microsoft.com/microsoft-365/security/defender/advanced-hunting-emailurlinfo-table)

---

## `EmailAttachmentInfo` — Key Fields

| Field | Type | Why It Matters for Phishing |
|---|---|---|
| `NetworkMessageId` | string | **Join key** back to `EmailEvents` |
| `FileName` | string | Attachment name — look for `.html` (HTML smuggling), `.lnk`, `.pdf`, `.htm` files used as phishing lures |
| `FileType` | string | File extension — filter for `.html`, `.htm`, `.lnk`, `.iso` |
| `SHA256` | string | File hash — cross-reference against threat intelligence or VirusTotal |
| `ThreatTypes` | string | Attachment verdict: `Phish`, `Malware`, `None` |
| `DetectionMethods` | string | How the attachment was caught: `Safe Attachments detonation`, `Malware reputation` |
| `SenderFromAddress` | string | Sender corroboration — matches `EmailEvents` for same message |
| `RecipientEmailAddress` | string | Target user |

Reference: [EmailAttachmentInfo table — Advanced Hunting schema](https://learn.microsoft.com/microsoft-365/security/defender/advanced-hunting-emailattachmentinfo-table)

---

## `UrlClickEvents` — Key Fields

| Field | Type | Why It Matters for Phishing |
|---|---|---|
| `NetworkMessageId` | string | **Join key** back to `EmailEvents` and `EmailUrlInfo` — links the click to the original email |
| `Url` | string | The full URL clicked — may differ from the URL in `EmailUrlInfo` if redirects occurred |
| `UrlChain` | string | Full redirect chain — AiTM proxies and multi-hop phishing chains appear here |
| `AccountUpn` | string | UPN of the user who clicked — correlate with identity logs |
| `ActionType` | string | `ClickAllowed` (Safe Links permitted), `ClickBlocked` (Safe Links blocked), or `TenantPolicyBlocked` |
| `IsClickedThrough` | bool | `true` = user clicked "Continue anyway" past a Safe Links warning — **highest severity signal** |
| `ThreatTypes` | string | Verdict at click time: `Phish`, `Malware` — this is evaluated at the moment of click, not mail delivery |
| `DetectionMethods` | string | What flagged the URL at click time: `URL reputation`, `URL detonation` |
| `IPAddress` | string | IP from which the user clicked — can differ from mail client IP if mobile or VPN |
| `Workload` | string | Where the click originated: `Email`, `Office`, `Teams` |
| `ReportId` | string | Consistent ID for the same click event — use to correlate click-through follow-ups |

Reference: [UrlClickEvents table — Advanced Hunting schema](https://learn.microsoft.com/microsoft-365/security/defender/advanced-hunting-urlclickevents-table)

---

## KQL Detection Queries

### Query 1 — Phishing Emails Delivered to Inbox

Finds phishing-verdicted email that was **delivered** to the inbox (not blocked) — the most actionable starting point.

```kusto
EmailEvents
| where Timestamp > ago(7d)
| where ThreatTypes has "Phish"
| where DeliveryAction == "Delivered"
| where DeliveryLocation == "Inbox/Folder"
| project Timestamp, NetworkMessageId, SenderFromAddress, SenderFromDomain,
          SenderIPv4, RecipientEmailAddress, Subject, DetectionMethods,
          ConfidenceLevel, UrlCount, AttachmentCount, LatestDeliveryAction
| order by Timestamp desc
```

---

### Query 2 — Enrich Delivered Phish with URLs (EmailEvents + EmailUrlInfo via NetworkMessageId)

Joins delivered phishing emails to their extracted URLs. Surfaces the actual phishing domain the user was exposed to.

```kusto
EmailEvents
| where Timestamp > ago(7d)
| where ThreatTypes has "Phish"
| where DeliveryAction == "Delivered"
| join kind=inner (
    EmailUrlInfo
    | project NetworkMessageId, Url, UrlDomain, UrlLocation
  ) on NetworkMessageId
| project Timestamp, NetworkMessageId, RecipientEmailAddress, SenderFromAddress,
          Subject, Url, UrlDomain, UrlLocation, DetectionMethods
| order by Timestamp desc
```

---

### Query 3 — QR Code Phishing Detection (EmailUrlInfo UrlLocation = QRCode)

QR code phishing bypasses text-based URL scanning. This query finds emails where a URL was embedded in a QR code image.

```kusto
EmailUrlInfo
| where Timestamp > ago(7d)
| where UrlLocation == "QRCode"
| join kind=inner (
    EmailEvents
    | where DeliveryAction == "Delivered"
    | project NetworkMessageId, RecipientEmailAddress, SenderFromAddress, Subject, Timestamp
  ) on NetworkMessageId
| project Timestamp, RecipientEmailAddress, SenderFromAddress, Subject,
          Url, UrlDomain, UrlLocation, NetworkMessageId
| order by Timestamp desc
```

---

### Query 4 — Users Who Clicked Through a Phishing Link (UrlClickEvents)

Surfaces users who clicked **past** a Safe Links warning. These users have navigated to the phishing page and are high-priority for IR triage.

```kusto
UrlClickEvents
| where Timestamp > ago(7d)
| where ThreatTypes has "Phish"
| where IsClickedThrough == true
| project Timestamp, AccountUpn, Url, UrlChain, ActionType,
          IPAddress, Workload, NetworkMessageId, ReportId
| order by Timestamp desc
```

---

### Query 5 — Full Phishing Kill Chain: Email → URL → Click (Three-Table Join)

Correlates the original email (`EmailEvents`), the extracted URL (`EmailUrlInfo`), and the user's click event (`UrlClickEvents`) into a single row per click — using `NetworkMessageId` as the binding key across all three tables.

```kusto
EmailEvents
| where Timestamp > ago(7d)
| where ThreatTypes has "Phish"
| where DeliveryAction == "Delivered"
| project NetworkMessageId, SenderFromAddress, RecipientEmailAddress,
          Subject, DeliveryLocation, EmailTimestamp = Timestamp
| join kind=inner (
    EmailUrlInfo
    | project NetworkMessageId, ExtractedUrl = Url, UrlDomain, UrlLocation
  ) on NetworkMessageId
| join kind=inner (
    UrlClickEvents
    | project NetworkMessageId, AccountUpn, ClickedUrl = Url, UrlChain,
              ActionType, IsClickedThrough, ClickTimestamp = Timestamp,
              IPAddress, Workload
  ) on NetworkMessageId
| project EmailTimestamp, ClickTimestamp, RecipientEmailAddress, AccountUpn,
          SenderFromAddress, Subject, ExtractedUrl, ClickedUrl, UrlDomain,
          UrlLocation, UrlChain, ActionType, IsClickedThrough,
          DeliveryLocation, IPAddress, Workload, NetworkMessageId
| order by EmailTimestamp desc
```

---

### Query 6 — Phishing with Malicious Attachments (EmailEvents + EmailAttachmentInfo)

Finds phishing-verdicted emails with attachments, enriched with attachment metadata. Focus on HTML files (HTML smuggling lures) and unusual extensions.

```kusto
EmailEvents
| where Timestamp > ago(7d)
| where ThreatTypes has "Phish"
| where AttachmentCount > 0
| join kind=inner (
    EmailAttachmentInfo
    | project NetworkMessageId, FileName, FileType, SHA256, ThreatTypes,
              DetectionMethods
  ) on NetworkMessageId
| project Timestamp, NetworkMessageId, RecipientEmailAddress, SenderFromAddress,
          Subject, FileName, FileType, SHA256,
          AttachmentThreatTypes = ThreatTypes1, AttachmentDetection = DetectionMethods1
| order by Timestamp desc
```

---

### Query 7 — Authentication Failures on Phishing Emails (CompAuth / DMARC Fails)

Finds emails that failed composite authentication (`compauth=fail`) but were still delivered — a signal for spoofed sender addresses.

```kusto
EmailEvents
| where Timestamp > ago(7d)
| where DeliveryAction == "Delivered"
| where AuthenticationDetails has "compauth=fail"
| project Timestamp, NetworkMessageId, SenderFromAddress, SenderMailFromAddress,
          SenderFromDomain, RecipientEmailAddress, Subject, ThreatTypes,
          AuthenticationDetails, DetectionMethods
| order by Timestamp desc
```

---

### Query 8 — Suspicious OAuth / Device Code Phishing Email Lures

Finds emails delivered to the inbox that contain URLs matching OAuth consent or device login endpoints — the lure phase for illicit consent and device code attacks.

```kusto
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
    | project NetworkMessageId, RecipientEmailAddress, SenderFromAddress,
              Subject, ThreatTypes, Timestamp
  ) on NetworkMessageId
| project Timestamp, RecipientEmailAddress, SenderFromAddress, Subject,
          Url, UrlDomain, ThreatTypes, NetworkMessageId
| order by Timestamp desc
```

---

## Recommended Alert Tuning

| Alert Condition | Table + Filter | Severity |
|---|---|---|
| Phishing delivered to inbox | `EmailEvents` — `ThreatTypes has "Phish"` + `DeliveryAction == "Delivered"` | High |
| User clicked through Safe Links warning | `UrlClickEvents` — `IsClickedThrough == true` + `ThreatTypes has "Phish"` | High |
| QR code phishing URL in delivered email | `EmailUrlInfo` — `UrlLocation == "QRCode"` + join to `EmailEvents` delivered | High |
| OAuth/device code lure URL delivered | `EmailUrlInfo` — URL contains `devicelogin` or `oauth2/authorize` | High |
| CompAuth fail delivered to inbox | `EmailEvents` — `AuthenticationDetails has "compauth=fail"` + delivered | Medium |
| Malicious attachment delivered | `EmailAttachmentInfo` — `ThreatTypes has "Phish"` or `"Malware"` | High |

---

## Microsoft Learn References

- [EmailEvents table — Advanced Hunting schema](https://learn.microsoft.com/microsoft-365/security/defender/advanced-hunting-emailevents-table)
- [EmailUrlInfo table — Advanced Hunting schema](https://learn.microsoft.com/microsoft-365/security/defender/advanced-hunting-emailurlinfo-table)
- [EmailAttachmentInfo table — Advanced Hunting schema](https://learn.microsoft.com/microsoft-365/security/defender/advanced-hunting-emailattachmentinfo-table)
- [UrlClickEvents table — Advanced Hunting schema](https://learn.microsoft.com/microsoft-365/security/defender/advanced-hunting-urlclickevents-table)
- [Hunt for threats in emails — Advanced Hunting](https://learn.microsoft.com/microsoft-365/security/defender/advanced-hunting-query-emails-devices)
- [Threat Explorer and Real-time Detections](https://learn.microsoft.com/defender-office-365/threat-explorer-threat-hunting)
- [Safe Links in Defender for Office 365](https://learn.microsoft.com/defender-office-365/safe-links-about)
- [Advanced Hunting schema tables reference](https://learn.microsoft.com/microsoft-365/security/defender/advanced-hunting-schema-tables)

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
