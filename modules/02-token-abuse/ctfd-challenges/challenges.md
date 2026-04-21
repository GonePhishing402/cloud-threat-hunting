# Module 02 — Token Abuse CTF Challenges

> **Lab setup:** See [lab-setup.md](lab-setup.md) for instructions on creating a free ADX cluster and ingesting the emulated data.  
> **Data source:** `modules/02-token-abuse/emulated-data/` — one JSON file per table (ingest each into its matching ADX table per the setup guide).  
> **Tables used:** `SigninLogs`, `AADNonInteractiveUserSignInLogs`, `AzureActivity`, `MicrosoftGraphActivityLogs`, `CloudAppEvents`  
> **Total points available:** 2,050

---

## Scenario Background

Your SOC received an alert: two users in the `celestialtrident-enc2.mscyberlab.com` tenant show unusual non-interactive sign-in patterns. One appears to involve stolen Azure CLI tokens being replayed from Eastern Europe. The other shows a device-registered workstation whose tokens are being consumed from a Microsoft Azure datacenter IP — a strong indicator of a Primary Refresh Token (PRT) theft and off-device replay.

Work through the challenges below in order. Each challenge builds on the previous one. Flags are in `FLAG{value}` format.

---

## Challenge Track A — Azure CLI Token Theft (`mgarcia`)

---

### A-1 | Where Did the Clone Go?
**Category:** `02-token-abuse` | **Points:** 100 | **Difficulty:** 🟢 Easy

**Narrative:**  
`mgarcia@contoso.com` authenticated normally with MFA at 08:28 UTC on March 12. Minutes later, the same user's tokens appeared somewhere in Eastern Europe. The attacker is using a refresh token obtained via FOCI (Family of Client IDs) to silently generate new access tokens for cloud resources.

**Question:**  
Query `AADNonInteractiveUserSignInLogs` and find the attacker's IP address — the one that is NOT `mgarcia`'s corporate IP. Submit that IP as your flag.

**KQL starting point:**
```kql
AADNonInteractiveUserSignInLogs
| where UserPrincipalName == "mgarcia@contoso.com"
| where ResultType == 0
| project TimeGenerated, IPAddress, LocationDetails, AppDisplayName, IncomingTokenType
| order by TimeGenerated asc
```

**Hint 1** (25 pts): Compare IPAddress across `SigninLogs` (MFA event) and `AADNonInteractiveUserSignInLogs` (token replay). The legitimate sign-in originated from Dallas, TX.

**Flag:** `FLAG{185.220.101.34}`

---

### A-2 | FOCI Token Farm
**Category:** `02-token-abuse` | **Points:** 150 | **Difficulty:** 🟢 Easy

**Narrative:**  
After replaying the initial refresh token, the attacker didn't stop at one resource. Azure CLI tokens belong to the "Family of Client IDs" (FOCI) — a single refresh token can be redeemed for access tokens to any Microsoft first-party app. The attacker used this to silently acquire tokens for multiple cloud services within seconds.

**Question:**  
Using `AADNonInteractiveUserSignInLogs`, count how many **distinct** Azure resources the attacker farmed tokens for within the 45-second window between `2026-03-12T08:36:00Z` and `2026-03-12T08:36:45Z`. Submit that count as your flag.

**KQL starting point:**
```kql
AADNonInteractiveUserSignInLogs
| where UserPrincipalName == "mgarcia@contoso.com"
| where IPAddress == "<attacker-ip-from-A1>"
| where TimeGenerated between(datetime(2026-03-12T08:36:00Z) .. datetime(2026-03-12T08:36:45Z))
| summarize dcount(ResourceDisplayName)
```

**Hint 1** (25 pts): Fill in the attacker IP you found in A-1. Run the query and look at the `dcount` result.

**Flag:** `FLAG{3}`

---

### A-3 | First Move on the Control Plane
**Category:** `02-token-abuse` | **Points:** 200 | **Difficulty:** 🟡 Medium

**Narrative:**  
Once the attacker had a valid Azure Resource Manager token, they moved to the Azure management plane. The first thing most attackers do after stealing cloud tokens is enumerate what the victim has access to. Find that first enumeration action.

**Question:**  
Query `AzureActivity` for `mgarcia@contoso.com` coming from the attacker IP. What is the `OperationName` of the **first** Azure management action performed? Submit the full operation name as your flag.

**KQL starting point:**
```kql
AzureActivity
| where Caller == "mgarcia@contoso.com"
| where CallerIpAddress == "<attacker-ip-from-A1>"
| project TimeGenerated, OperationName, CallerIpAddress, ActivityStatus
| order by TimeGenerated asc
| take 1
```

**Hint 1** (50 pts): The first operation is a `read` operation against the subscriptions endpoint — standard reconnaissance to understand what the compromised identity can reach.

**Flag:** `FLAG{Microsoft.Resources/subscriptions/read}`

---

### A-4 | Attack Duration (mgarcia)
**Category:** `02-token-abuse` | **Points:** 200 | **Difficulty:** 🟡 Medium

**Narrative:**  
You've identified what the attacker did. Now calculate how long `mgarcia`'s token was actively abused — from the first token replay success to the last recorded attacker action in AzureActivity.

**Question:**  
Using a union of `AADNonInteractiveUserSignInLogs` and `AzureActivity`, find the duration in **whole minutes** between the attacker's first successful non-interactive sign-in (`08:33:15Z`) and the last `AzureActivity` event from the attacker IP. Submit the rounded minute count as your flag.

**KQL starting point:**
```kql
let attacker_ip = "<attacker-ip-from-A1>";
let first_event = todatetime("2026-03-12T08:33:15Z");
AzureActivity
| where CallerIpAddress == attacker_ip
| where Caller == "mgarcia@contoso.com"
| summarize LastEvent = max(TimeGenerated)
| extend DurationMinutes = toint((LastEvent - first_event) / 1m)
| project DurationMinutes
```

**Hint 1** (50 pts): The AzureActivity events are the last attacker actions. Compare `max(TimeGenerated)` against the first non-interactive sign-in at `08:33:15Z`.

**Flag:** `FLAG{3}`

---

## Challenge Track B — PRT Theft and M365 Exfiltration (`alex.nguyen`)

---

### B-1 | Ghost in the Datacenter
**Category:** `02-token-abuse` | **Points:** 100 | **Difficulty:** 🟢 Easy

**Narrative:**  
`alex.nguyen` authenticated normally from Seattle at 16:45 UTC. Sixteen minutes later, that user's Primary Refresh Token was being replayed — but from an IP that belongs to Microsoft Azure's datacenter range in Virginia. End users don't sign in from Azure datacenter IPs. This is the fingerprint of a tool running on an attacker-controlled Azure VM.

**Question:**  
Query `AADNonInteractiveUserSignInLogs` for `alex.nguyen@celestialtrident-enc2.mscyberlab.com` and find the attacker's source IP address. Submit it as your flag.

**KQL starting point:**
```kql
AADNonInteractiveUserSignInLogs
| where UserPrincipalName == "alex.nguyen@celestialtrident-enc2.mscyberlab.com"
| where ResultType == 0
| project TimeGenerated, IPAddress, LocationDetails, IncomingTokenType, ResourceDisplayName
| order by TimeGenerated asc
```

**Hint 1** (25 pts): The legitimate sign-in came from `72.21.210.29` (Seattle). The attacker IP appears only in the non-interactive logs and resolves to an Azure datacenter city in Virginia.

**Flag:** `FLAG{20.124.65.190}`

---

### B-2 | Dual Token Technique
**Category:** `02-token-abuse` | **Points:** 150 | **Difficulty:** 🟢 Easy

**Narrative:**  
During the successful access window, the attacker used two different token types (`refreshToken` and `primaryRefreshToken`) to access Microsoft 365 resources. One of those token types was used specifically to gain access to **Microsoft Exchange Online Protection** — a higher-value target that normally only accepts PRT-derived tokens from device-bound sessions.

**Question:**  
Query `AADNonInteractiveUserSignInLogs` for `alex.nguyen` with `ResultType == 0` and find what `IncomingTokenType` was used to access `Microsoft Exchange Online Protection`. Submit the value as your flag.

**KQL starting point:**
```kql
AADNonInteractiveUserSignInLogs
| where UserPrincipalName == "alex.nguyen@celestialtrident-enc2.mscyberlab.com"
| where ResultType == 0
| where ResourceDisplayName == "Microsoft Exchange Online Protection"
| project TimeGenerated, IncomingTokenType, ResourceDisplayName, IPAddress
```

**Hint 1** (25 pts): There are only two successful sign-in events — one per resource. One used a regular `refreshToken`, the other used something more powerful that is tied to the device.

**Flag:** `FLAG{primaryRefreshToken}`

---

### B-3 | Geolocation Mismatch
**Category:** `02-token-abuse` | **Points:** 150 | **Difficulty:** 🟢 Easy

**Narrative:**  
A key hunting signal for token replay attacks is a **geolocation mismatch** between the legitimate sign-in and the token replay. The user authenticated from the west coast; the token was replayed from a different city entirely.

**Question:**  
Using `AADNonInteractiveUserSignInLogs`, find the `city` field inside `LocationDetails` for the attacker's successful events. What city is the attacker's IP geo-mapped to? Submit the city name as your flag.

**KQL starting point:**
```kql
AADNonInteractiveUserSignInLogs
| where UserPrincipalName == "alex.nguyen@celestialtrident-enc2.mscyberlab.com"
| where ResultType == 0
| extend City = tostring(parse_json(LocationDetails).city)
| project TimeGenerated, IPAddress, City
```

**Hint 1** (25 pts): The location is a well-known Microsoft datacenter city in Virginia that appears frequently in Azure infrastructure lookups on threat intel platforms.

**Flag:** `FLAG{Boydton}`

---

### B-4 | Inbox Raider
**Category:** `02-token-abuse` | **Points:** 200 | **Difficulty:** 🟡 Medium

**Narrative:**  
After gaining an Exchange token, the attacker immediately began accessing mailbox contents. The `CloudAppEvents` table captures `MailItemsAccessed` audit events — these log how many items were touched and which folders. Investigators use this to understand the scope of mail exposure.

**Question:**  
Query `CloudAppEvents` for `alex.nguyen`, filter for `ActionType == "MailItemsAccessed"`, and extract the `OperationCount` from `RawEventData`. How many mail items were accessed in the bulk sync operation? Submit that count as your flag.

**KQL starting point:**
```kql
CloudAppEvents
| where AccountUpn == "alex.nguyen@celestialtrident-enc2.mscyberlab.com"
| where ActionType == "MailItemsAccessed"
| extend RawData = parse_json(RawEventData)
| project TimeGenerated, IPAddress, OperationCount = RawData.OperationCount, Folders = RawData.Folders
```

**Hint 1** (50 pts): Look at the `RawEventData` field — it contains a nested JSON object. Use `parse_json()` and then access the `OperationCount` property to get the item count.

**Hint 2** (75 pts): The sync event shows multiple folders being accessed simultaneously. The `OperationCount` is a two-digit number.

**Flag:** `FLAG{42}`

---

### B-5 | Keyword Recon
**Category:** `02-token-abuse` | **Points:** 200 | **Difficulty:** 🟡 Medium

**Narrative:**  
After reviewing the inbox, the attacker ran a targeted mailbox search — a strong indicator of intentional data gathering rather than opportunistic access. The search term reveals exactly what the attacker was looking for.

**Question:**  
Query `CloudAppEvents` for `alex.nguyen` and filter for `ActionType == "SearchQueryInitiatedExchange"`. What search string did the attacker use? Submit the exact query text as your flag.

**KQL starting point:**
```kql
CloudAppEvents
| where AccountUpn == "alex.nguyen@celestialtrident-enc2.mscyberlab.com"
| where ActionType == "SearchQueryInitiatedExchange"
| extend RawData = parse_json(RawEventData)
| project TimeGenerated, SearchQuery = RawData.QueryText, ResultCount = RawData.ResultCount
```

**Hint 1** (50 pts): The `QueryText` field is nested inside `RawEventData`. Parse the JSON and look at `QueryText`. The search term is three words that indicate the attacker's interest in HR or financial data.

**Flag:** `FLAG{salary review confidential}`

---

### B-6 | The Crown Jewels
**Category:** `02-token-abuse` | **Points:** 250 | **Difficulty:** 🟡 Medium

**Narrative:**  
After reading emails, the attacker pivoted to SharePoint to find structured data files. The `CloudAppEvents` table captures file download events from SharePoint Online via the `FileDownloaded` action type. One specific file download represents the primary data exfiltration event.

**Question:**  
Query `CloudAppEvents` for `alex.nguyen` and the `FileDownloaded` action type. What is the full filename (including extension) of the downloaded file? Submit it as your flag.

**KQL starting point:**
```kql
CloudAppEvents
| where AccountUpn == "alex.nguyen@celestialtrident-enc2.mscyberlab.com"
| where ActionType == "FileDownloaded"
| extend RawData = parse_json(RawEventData)
| project TimeGenerated, FileName = RawData.SourceFileName, Site = RawData.SiteUrl, IPAddress
```

**Hint 1** (50 pts): The file is on a SharePoint site called `HRDocuments`. The filename includes the current year, the word "Compensation", and lists all employees. It's an Excel spreadsheet.

**Flag:** `FLAG{2026_Compensation_Plan_ALL_EMPLOYEES.xlsx}`

---

### B-7 | Graph API Pivot
**Category:** `02-token-abuse` | **Points:** 300 | **Difficulty:** 🔴 Hard

**Narrative:**  
The `MicrosoftGraphActivityLogs` table records individual REST API calls made using Graph tokens. Each entry contains a `SignInActivityId` field that links back to the specific token issuance event in `AADNonInteractiveUserSignInLogs` — this is the cross-table correlation that proves the attacker's Graph calls used the stolen token.

**Question:**  
Find the `CorrelationId` from `AADNonInteractiveUserSignInLogs` for the **first** successful sign-in by `alex.nguyen` from the attacker IP. Then confirm it matches the `SignInActivityId` in `MicrosoftGraphActivityLogs`. Submit the shared GUID as your flag.

**KQL starting point:**
```kql
// Step 1: Find the CorrelationId of the successful non-interactive sign-in
AADNonInteractiveUserSignInLogs
| where UserPrincipalName == "alex.nguyen@celestialtrident-enc2.mscyberlab.com"
| where ResultType == 0
| where IPAddress == "<attacker-ip-from-B1>"
| project TimeGenerated, CorrelationId, ResourceDisplayName
| order by TimeGenerated asc

// Step 2: Confirm in MicrosoftGraphActivityLogs
MicrosoftGraphActivityLogs
| where UserId == "<userId-from-step1>"
| project TimeGenerated, SignInActivityId, RequestUri, ResponseStatusCode
```

**Hint 1** (75 pts): The `CorrelationId` in `AADNonInteractiveUserSignInLogs` and the `SignInActivityId` in `MicrosoftGraphActivityLogs` are the same GUID — this is by design, so defenders can trace a Graph API call back to its token issuance event.

**Hint 2** (100 pts): There is only one successful non-interactive sign-in before the revocation errors begin. Its `CorrelationId` starts with `b2c3d4e5`.

**Flag:** `FLAG{b2c3d4e5-f6a7-2b3c-4d5e-6f7a8b9c0d1e}`

---

### B-8 | Revocation Storm
**Category:** `02-token-abuse` | **Points:** 200 | **Difficulty:** 🟡 Medium

**Narrative:**  
After the SOC revoked `alex.nguyen`'s session, the attacker's stolen tokens began generating authentication failures. All failures share the same error code — a specific Entra ID sign-in error that indicates a **revoked grant**. Recognizing this error code is critical: a burst of this code for the same user across multiple apps is a near-certain indicator that token revocation is in progress and an attacker is still attempting access.

**Question:**  
Query `AADNonInteractiveUserSignInLogs` for `alex.nguyen` with `ResultType != 0` (failures only). What is the `ResultType` (error code) shared by all the failed attempts? Submit just the numeric code as your flag.

**KQL starting point:**
```kql
AADNonInteractiveUserSignInLogs
| where UserPrincipalName == "alex.nguyen@celestialtrident-enc2.mscyberlab.com"
| where ResultType != 0
| summarize Count = count() by ResultType, ResultDescription
```

**Hint 1** (25 pts): This error code means "the grant was revoked" — it typically means an admin ran `Revoke-AzureADUserAllRefreshToken` or revoked sessions from the Entra ID portal. All failures should share the same 5-digit code.

**Flag:** `FLAG{50173}`

---

### B-9 | Session Stalker
**Category:** `02-token-abuse` | **Points:** 300 | **Difficulty:** 🔴 Hard

**Narrative:**  
The attacker's tool maintained a persistent handle to the stolen session across all token requests — both successful and failed. This `SessionId` appears in every non-interactive sign-in log entry for `alex.nguyen` from the attacker IP, and it's different from the session established during the legitimate sign-in. Identifying this value allows you to scope the full blast radius of the compromise.

**Question:**  
Query `AADNonInteractiveUserSignInLogs` for all events from the attacker IP for `alex.nguyen`. What `SessionId` appears consistently across **all** of them (both successful and failed)? Submit it as your flag.

**KQL starting point:**
```kql
AADNonInteractiveUserSignInLogs
| where UserPrincipalName == "alex.nguyen@celestialtrident-enc2.mscyberlab.com"
| where IPAddress == "<attacker-ip-from-B1>"
| summarize EventCount = count() by SessionId
| order by EventCount desc
```

**Hint 1** (75 pts): The attacker's tool used the same session handle for all requests. There should be one `SessionId` that appears in ALL non-interactive sign-in events from the attacker IP — both before and after the revocation.

**Flag:** `FLAG{1a4c7b9e-d528-4f0a-b3e6-82c9f1a05347}`

---

## Capstone Challenges

---

### C-1 | Full Attack Timeline (alex.nguyen)
**Category:** `02-token-abuse` | **Points:** 300 | **Difficulty:** 🔴 Hard

**Narrative:**  
Build a complete timeline of the `alex.nguyen` attack. The clock starts when the first token replay succeeds and ends when the attacker makes their last authentication attempt.

**Question:**  
Using `AADNonInteractiveUserSignInLogs`, calculate the number of **whole minutes** between the attacker's **first successful** non-interactive sign-in for `alex.nguyen` and the attacker's **last failed** attempt. Submit the rounded minute count as your flag.

**KQL starting point:**
```kql
AADNonInteractiveUserSignInLogs
| where UserPrincipalName == "alex.nguyen@celestialtrident-enc2.mscyberlab.com"
| where IPAddress == "<attacker-ip-from-B1>"
| summarize FirstSuccess = minif(TimeGenerated, ResultType == 0),
            LastAttempt  = max(TimeGenerated)
| extend DurationMinutes = toint((LastAttempt - FirstSuccess) / 1m)
| project FirstSuccess, LastAttempt, DurationMinutes
```

**Hint 1** (75 pts): The first success is the earliest `ResultType == 0` event. The last attempt is `max(TimeGenerated)` across all events from the attacker IP, including the 50173 failures.

**Flag:** `FLAG{20}`

---

### C-2 | Cross-Table Hunt — Prove the Exfiltration
**Category:** `02-token-abuse` | **Points:** 350 | **Difficulty:** 🔴 Hard

**Narrative:**  
Build a single KQL query that joins `AADNonInteractiveUserSignInLogs` (token issuance) → `MicrosoftGraphActivityLogs` (Graph API calls) → `CloudAppEvents` (file access) to tell the complete story of how a stolen PRT became a file exfiltration event. The join keys are `UserId` / `AccountObjectId` to tie the user across tables, and `SignInActivityId` to tie the Graph activity back to the token event.

**Question:**  
Using a join or union across all three tables, identify the full `RequestUri` of the **first** Graph API call the attacker made after obtaining the token. Submit the full URI path (no hostname, no query parameters) as your flag.

**KQL starting point:**
```kql
// Join non-interactive sign-in to Graph activity logs
AADNonInteractiveUserSignInLogs
| where UserPrincipalName == "alex.nguyen@celestialtrident-enc2.mscyberlab.com"
| where ResultType == 0
| project TokenCorrelationId = CorrelationId, TokenTime = TimeGenerated, UserId
| join kind=inner (
    MicrosoftGraphActivityLogs
    | project SignInActivityId, RequestUri, GraphTime = TimeGenerated, UserId
) on $left.TokenCorrelationId == $right.SignInActivityId
| project TokenTime, GraphTime, RequestUri, UserId
| order by GraphTime asc
| take 1
```

**Hint 1** (75 pts): The first Graph call was to retrieve a list of email messages. The path follows the Microsoft Graph v1.0 `/me/messages` pattern. Strip the hostname (`https://graph.microsoft.com`) and any query parameters (everything after `?`) from the `RequestUri`.

**Hint 2** (100 pts): The answer is a path-only string starting with `/v1.0/me/`.

**Flag:** `FLAG{/v1.0/me/messages}`

---

### C-3 | Build the Detection Rule
**Category:** `02-token-abuse` | **Points:** 400 | **Difficulty:** 🔴 Hard (Manually Graded)

**Narrative:**  
You've investigated both token theft scenarios. Now write a Microsoft Sentinel **scheduled analytics rule** (KQL query) that would detect the `alex.nguyen` style attack — a PRT replay from a non-corporate IP that succeeds, followed by a burst of 50173 errors after session revocation. Your rule must:

1. Identify users with **both** successful (`ResultType == 0`) and failed (`ResultType == 50173`) non-interactive sign-ins from the same IP in a 30-minute window
2. Surface the user, attacker IP, count of 50173 failures, and resources targeted
3. Exclude known service account UPNs and `@microsoft.com` callers
4. Include at least one comment explaining the detection logic

**Question:**  
Submit your completed KQL query to the instructor. If approved, the instructor will provide the flag.

**Acceptance criteria:**
- Query returns results when run against the emulated dataset
- False positive rate is documented
- All four required output columns are present

**Hint 1** (50 pts): Use a `let` block to define the 30-minute window. Summarize successful and failed events separately, then `join` them on `UserPrincipalName` and `IPAddress`.

**Flag:** Manually issued by instructor upon query review.

---

## Scoring Summary

| ID | Challenge | Points | Difficulty |
|---|---|---|---|
| A-1 | Where Did the Clone Go? | 100 | 🟢 Easy |
| A-2 | FOCI Token Farm | 150 | 🟢 Easy |
| A-3 | First Move on the Control Plane | 200 | 🟡 Medium |
| A-4 | Attack Duration (mgarcia) | 200 | 🟡 Medium |
| B-1 | Ghost in the Datacenter | 100 | 🟢 Easy |
| B-2 | Dual Token Technique | 150 | 🟢 Easy |
| B-3 | Geolocation Mismatch | 150 | 🟢 Easy |
| B-4 | Inbox Raider | 200 | 🟡 Medium |
| B-5 | Keyword Recon | 200 | 🟡 Medium |
| B-6 | The Crown Jewels | 250 | 🟡 Medium |
| B-7 | Graph API Pivot | 300 | 🔴 Hard |
| B-8 | Revocation Storm | 200 | 🟡 Medium |
| B-9 | Session Stalker | 300 | 🔴 Hard |
| C-1 | Full Attack Timeline | 300 | 🔴 Hard |
| C-2 | Cross-Table Hunt | 350 | 🔴 Hard |
| C-3 | Build the Detection Rule | 400 | 🔴 Hard |
| **Total** | | **3,350** | |

---

## Instructor Flag Reference

> ⚠️ **INSTRUCTOR USE ONLY** — Do not distribute to students.

| Challenge | Flag |
|---|---|
| A-1 | `FLAG{185.220.101.34}` |
| A-2 | `FLAG{3}` |
| A-3 | `FLAG{Microsoft.Resources/subscriptions/read}` |
| A-4 | `FLAG{3}` |
| B-1 | `FLAG{20.124.65.190}` |
| B-2 | `FLAG{primaryRefreshToken}` |
| B-3 | `FLAG{Boydton}` |
| B-4 | `FLAG{42}` |
| B-5 | `FLAG{salary review confidential}` |
| B-6 | `FLAG{2026_Compensation_Plan_ALL_EMPLOYEES.xlsx}` |
| B-7 | `FLAG{b2c3d4e5-f6a7-2b3c-4d5e-6f7a8b9c0d1e}` |
| B-8 | `FLAG{50173}` |
| B-9 | `FLAG{1a4c7b9e-d528-4f0a-b3e6-82c9f1a05347}` |
| C-1 | `FLAG{20}` |
| C-2 | `FLAG{/v1.0/me/messages}` |
| C-3 | Manually graded |
