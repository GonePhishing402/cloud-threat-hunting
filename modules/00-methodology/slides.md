## Slide 1: Cloud Threat Hunting: Methodology

Module 00 — Threat Hunt Methodology

**Speaker Notes:**
Welcome to Module 00 — the foundation for everything we'll do in this course. This module establishes the threat hunting mindset, introduces the core KQL techniques, and walks through the key Sentinel tables and correlation fields you'll use across every module.

## Slide 2: Agenda

- What Is Threat Hunting?
- Reactive vs. Proactive Security
- The Threat Hunt Loop
- Forming a Strong Hypothesis
- Key Sentinel Tables for Cloud Hunting
- Finding a User's Footprint Across Tables
- Drilling Into Tables
- Correlating Activity with Key Fields
- End-to-End Hunt Pattern
- Key Takeaways and Course Preview

**Speaker Notes:**
We'll start with the fundamentals — what hunting is, why it matters, and how it differs from alert-driven response. Then we'll move into hands-on KQL technique: footprint discovery, per-table drilldowns, and cross-table correlation using three critical fields. By the end of this module you'll have a repeatable hunt pattern you can apply to every module that follows.

## Slide 3: What Is Threat Hunting?

!layout: Title and Content

Threat hunting is the proactive, human-led process of searching through data to detect adversarial activity that has evaded automated detections.

**What makes an effective hunter:**
- Assume compromise and work to find evidence of it
- Follow the data, not just the alerts
- Build institutional knowledge from every hunt — successful or not
- Convert confirmed findings into durable analytics rules

**Speaker Notes:**
Hunting isn't about replacing your SIEM alerts — it's about finding what they miss. Analytics rules detect known patterns. Hunting finds unknown or novel attack variations. Both are necessary. Every successful hunt should end with either a confirmed finding or a new analytics rule that closes the gap. Even unsuccessful hunts refine your threat model by eliminating hypotheses.

## Slide 4: Reactive vs. Proactive Security

!layout: Title and Content

**Reactive (Alert-Driven):**
- Responds to SIEM alerts and incidents after they fire
- Limited to known signatures and detection rules
- Attacker has already achieved their objective before you start investigating

**Proactive (Threat Hunting):**
- Starts with a hypothesis before any alert fires
- Searches for behaviors and anomalies, not just signatures
- Finds novel attack variations and zero-day techniques
- Runs on a cadence — weekly or bi-weekly hunts are most sustainable

**Key Insight:** Waiting on detections is not enough. Proactive hunting provides early insight into events that might confirm a compromise is in process, or reveals weak areas in your environment.

**Speaker Notes:**
This is from Microsoft's own guidance: "Waiting on detections isn't enough. Take proactive action by running threat-hunting queries related to the data you're ingesting into your workspace at least once a week." Hunting is what finds the attacker who slipped past your analytics rules. Scheduled hunts on a weekly or bi-weekly cadence are the most sustainable model for SOC teams. Trigger-based hunts happen when new threat intel is relevant to your environment. Ask the class: how many run scheduled hunts today versus only responding to alerts?

## Slide 5: The Threat Hunt Loop

!layout: Title and Content

| Phase | What You Do |
|---|---|
| Hypothesis | Form a testable prediction grounded in threat intel, MITRE ATT&CK, or an environmental anomaly |
| Data Collection | Identify which Sentinel tables hold relevant evidence and validate log coverage |
| Investigation | Write KQL queries, pivot on entities, reconstruct timelines |
| Finding | Document confirmed malicious or suspicious activity and escalate if needed |
| Feedback | Promote confirmed hunts to analytics rules and update the threat model |

**Speaker Notes:**
This five-phase loop is the backbone of everything we do in this course. Every module follows this pattern: we start with a hypothesis about a specific attack technique, identify the tables that contain evidence, investigate with KQL, document findings, and convert them to detection rules. The loop is circular because every hunt's feedback becomes input for the next hypothesis. Even a hunt that finds nothing is valuable — it eliminates a hypothesis and refines your understanding of the data.

## Slide 6: Forming a Strong Hypothesis

!layout: Title and Content

**A good hypothesis is testable, specific, and grounded:**

**Strong hypotheses:**
- "An attacker who phished user credentials is using a stolen refresh token to access Graph API from a foreign IP"
- "A compromised service principal is enumerating Key Vault secrets outside business hours"
- "A Logic App's managed identity was reassigned elevated roles after a new contributor was added"

**Weak hypotheses:**
- "Something bad is happening in our environment"
- "There might be a phishing attack"
- "Check all the logs for anomalies"

**Sources for hypotheses:** MITRE ATT&CK Cloud Matrix, threat intelligence reports, anomalies in your environment, red team findings, incident post-mortems

**Speaker Notes:**
Hypothesis quality determines hunt quality. A vague hypothesis like "check for anomalies" leads to unfocused queries and wasted time. A strong hypothesis names the technique, the asset or user, and the reason you suspect it. The MITRE ATT&CK Cloud Matrix is your best starting point — it maps specific techniques to data sources. Throughout this course, each module starts with specific hypotheses tied to MITRE techniques. Encourage students to practice writing hypotheses before executing queries.

## Slide 7: Key Sentinel Tables for Cloud Hunting

!layout: Title and Content

| Table | What It Contains |
|---|---|
| SigninLogs | Interactive sign-in events (user logins, MFA challenges) |
| AADNonInteractiveUserSignInLogs | Token refresh, SSO, silent sign-ins |
| AADServicePrincipalSignInLogs | Service principal authentications |
| AADManagedIdentitySignInLogs | Managed identity authentications |
| AuditLogs | Entra ID directory changes (user, app, role modifications) |
| AzureActivity | Azure resource management operations (control plane) |
| StorageBlobLogs | Blob storage data plane access |
| AzureDiagnostics | Key Vault, Logic App, and other resource diagnostic logs |
| MicrosoftGraphActivityLogs | Microsoft Graph API calls |
| OfficeActivity | Microsoft 365 events (SharePoint, Exchange, Teams) |

**Speaker Notes:**
This is your cheat sheet for the entire course. Every module targets a subset of these tables. SigninLogs captures interactive logins. AADNonInteractiveUserSignInLogs is where you find token refresh events — critical for detecting token theft in Module 02. AADServicePrincipalSignInLogs and AADManagedIdentitySignInLogs are essential for Modules 05 through 08 where we investigate service principal and managed identity abuse. AzureActivity covers the Azure control plane — any resource creation, deletion, or modification. AzureDiagnostics is the catch-all for resource-specific logs like Key Vault and Logic Apps. Encourage students to keep this table handy throughout the training.

## Slide 8: Starting Point — Find the Footprint

!layout: Title and Content

When you receive a lead — a username, an IP, an email address — the first step is to determine which log tables contain activity for that indicator.

**Why this matters:**
- Querying each table individually is slow and incomplete
- The KQL `search` operator scans across the entire workspace at once
- Result: a ranked list of every table with log entries mentioning that value
- Use this to scope the rest of your hunt to tables that actually have a footprint

**Performance tip:** The `search` operator scans all tables and is expensive on large workspaces. Once you have a footprint list, immediately scope to specific tables.

**Speaker Notes:**
This is the single most important starting technique in threat hunting. When someone gives you a UPN, an IP, or any indicator, your first query should always be a cross-table search. This tells you where to focus. Don't waste time writing per-table queries for tables that have zero records for your indicator. The search operator returns a special column called $table that tells you which table each result came from. After the initial search, narrow your scope immediately — search is expensive at scale.

## Slide 9: KQL — Cross-Table Footprint Discovery

!layout: Title and Content

```kql
search "jsmith@contoso.com"
| summarize count() by $table
| sort by count_ desc
```

**Example output:**

| $table | count_ |
|---|---|
| SigninLogs | 47 |
| AzureActivity | 12 |
| MicrosoftGraphActivityLogs | 9 |
| CloudAppEvents | 5 |
| AADNonInteractiveUserSignInLogs | 3 |

**Speaker Notes:**
Walk through this query live in Sentinel. The $table column is a built-in KQL column that returns the source table name. This output tells us jsmith has the most activity in SigninLogs (47 entries), followed by AzureActivity (12 control plane operations), and Graph API calls (9). The AADNonInteractiveUserSignInLogs entries are token refreshes — if we suspect token theft, that's where we'll look next. This footprint scan takes seconds and saves hours of unfocused investigation.

## Slide 10: KQL — Scoped Search with Time Window

!layout: Title and Content

Once you have a footprint list, scope your search to specific tables and a time window for better performance:

```kql
search in (SigninLogs, AzureActivity, CloudAppEvents)
    "jsmith@contoso.com"
| where TimeGenerated > ago(7d)
| summarize count() by $table, bin(TimeGenerated, 1h)
| sort by TimeGenerated asc
```

**Why scope matters:**
- Reduces query cost and execution time
- Narrows results to the investigation window
- The `bin()` function groups results into time buckets for timeline analysis

**Speaker Notes:**
After the initial broad search, always scope down. This query targets only three tables over the last 7 days and bins results by hour. This gives you a timeline view — you can see when activity spiked. If you see a burst of AzureActivity at 2 AM followed by Graph API calls, that's a pattern worth investigating. This is the transition from footprint discovery to timeline reconstruction.

## Slide 11: Drilling Into Tables — Sign-In Events

!layout: Title and Content

Pull the relevant records from each table and review them for suspicious patterns.

```kql
SigninLogs
| where UserPrincipalName == "jsmith@contoso.com"
| where TimeGenerated > ago(7d)
| project TimeGenerated, IPAddress, Location, AppDisplayName,
          AuthenticationRequirement, ResultType, ResultDescription,
          ConditionalAccessStatus, UniqueTokenIdentifier, CorrelationId
| sort by TimeGenerated asc
```

**Key fields to examine:**
- **IPAddress / Location** — Is the user signing in from expected locations?
- **ResultType** — 0 = success; other values indicate failures
- **AuthenticationRequirement** — Was MFA required and satisfied?
- **UniqueTokenIdentifier** — Links this sign-in to downstream token usage

**Speaker Notes:**
This is your bread-and-butter sign-in investigation query. Project only the fields you need — it keeps results clean and fast. ResultType is critical: 0 means success, anything else is a failure with a specific error code. Look for patterns like successful sign-ins from unusual IPs, or MFA satisfied followed by activity from a different IP (which suggests AiTM or token theft). The UniqueTokenIdentifier field is how you'll track this token into other tables — we'll cover that in the correlation section.

## Slide 12: Drilling Into Tables — Control Plane and Graph API

!layout: Title and Content

```kql
AzureActivity
| where Caller == "jsmith@contoso.com"
| where TimeGenerated > ago(7d)
| project TimeGenerated, OperationNameValue, ResourceGroup,
          ResourceId, ActivityStatus, CorrelationId
| sort by TimeGenerated asc
```

```kql
MicrosoftGraphActivityLogs
| where UserPrincipalName == "jsmith@contoso.com"
| where TimeGenerated > ago(7d)
| project TimeGenerated, RequestUri, ResponseStatusCode,
          IPAddress, UniqueTokenIdentifier
| sort by TimeGenerated asc
```

**Speaker Notes:**
AzureActivity captures every Azure control plane operation — resource creation, deletion, role assignments, key listings. The OperationNameValue field tells you exactly what action was performed. CorrelationId groups all sub-operations of a single ARM request. MicrosoftGraphActivityLogs captures Graph API calls — reading users, accessing mail, modifying directory objects. The RequestUri shows exactly what endpoint was called. Both tables share correlation fields with SigninLogs, which is how we connect authentication to downstream actions.

## Slide 13: Correlating Activity — Overview

!layout: Title and Content

The power of multi-table hunting comes from joining events together through shared identifiers. These three fields are the most commonly used correlation anchors.

| Correlation Field | Tables | Use Case |
|---|---|---|
| CorrelationId | SigninLogs, AADNonInteractiveUserSignInLogs, AzureActivity | Link Azure resource operations back to the sign-in that established the session |
| UniqueTokenIdentifier | SigninLogs, AADNonInteractiveUserSignInLogs, MicrosoftGraphActivityLogs | Detect token theft and replay — track a specific token across services |
| NetworkMessageId | EmailEvents, EmailUrlInfo, EmailAttachmentInfo, EmailPostDeliveryEvents | Reconstruct the full timeline of a phishing email |

**Speaker Notes:**
This is the most important slide in this module. These three fields are how you connect the dots across tables. CorrelationId is set by the client and groups ARM sub-operations. UniqueTokenIdentifier is server-generated and tracks a specific issued token — this is your primary indicator for token theft. NetworkMessageId is the Office 365 message identifier that ties together email delivery, URL analysis, attachment detonation, and post-delivery actions like ZAP. Master these three fields and you can correlate any cloud attack chain.

## Slide 14: CorrelationId — Linking Sign-Ins to Resource Actions

!layout: Title and Content

**What it is:** A GUID that ties together all internal service calls initiated by a single authentication or ARM operation. Events that share a CorrelationId belong to the same uber action.

**Use it when:** You want to link an Azure resource operation (e.g., a Key Vault secret read) back to the sign-in that established the session, or to pull all sub-operations of a single ARM action.

**Present in:** SigninLogs, AADNonInteractiveUserSignInLogs, AzureActivity

**Speaker Notes:**
CorrelationId is your bridge between identity and infrastructure. When an attacker authenticates and then performs Azure operations, the CorrelationId connects those two events. In AzureActivity, it groups sub-operations — for example, creating a resource might involve multiple API calls that all share one CorrelationId. Note that CorrelationId is client-initiated, so a sophisticated attacker could potentially vary it across sessions. That's why we also use UniqueTokenIdentifier, which is server-generated and harder to manipulate.

## Slide 15: KQL — CorrelationId Pivot

!layout: Title and Content

```kql
let suspiciousCorrelationId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx";

AzureActivity
| where CorrelationId == suspiciousCorrelationId
| project TimeGenerated, OperationNameValue, Caller,
          ResourceId, ActivityStatus

| union (
    SigninLogs
    | where CorrelationId == suspiciousCorrelationId
    | project TimeGenerated, UserPrincipalName, IPAddress,
              AppDisplayName, ResultType
)

| sort by TimeGenerated asc
```

**Speaker Notes:**
This is the pattern you'll use repeatedly: take a CorrelationId from a suspicious AzureActivity event and union it with SigninLogs to find the corresponding authentication. The union operator combines results from multiple tables into a single timeline sorted by TimeGenerated. This shows you exactly who authenticated, from where, using which app, and what resource operations they performed — all in one query. Demo this live by picking a CorrelationId from an AzureActivity result and running this pivot.

## Slide 16: UniqueTokenIdentifier — Detecting Token Theft

!layout: Title and Content

**What it is:** A base64-encoded identifier that tracks a specific issued token as it is redeemed at a resource provider.

**Why it matters for hunting:** If the same token appears authenticating from two different IPs, or in Graph API activity after an anomalous sign-in, that is a strong indicator of access token theft and replay.

**Present in:** SigninLogs, AADNonInteractiveUserSignInLogs, MicrosoftGraphActivityLogs

**Key detection pattern:** Same UniqueTokenIdentifier + different IPAddress = potential token theft

**Speaker Notes:**
UniqueTokenIdentifier is your most powerful tool for detecting token theft. Unlike CorrelationId which is client-set, this field is generated server-side by Azure AD when a token is issued. It follows that token everywhere it's redeemed. If you see the same UniqueTokenIdentifier appearing from the user's normal IP and then from an attacker's IP, you've found a stolen token. This is the foundation of Module 02 (Token Abuse). We'll use this field extensively to track stolen refresh tokens and detect FOCI token farming.

## Slide 17: KQL — Token Tracking Across Tables

!layout: Title and Content

```kql
let tokenId = "BASE64ENCODEDVALUE==";

SigninLogs
| where UniqueTokenIdentifier == tokenId
| project TimeGenerated, UserPrincipalName, IPAddress,
          Location, AppDisplayName

| union (
    AADNonInteractiveUserSignInLogs
    | where UniqueTokenIdentifier == tokenId
    | project TimeGenerated, UserPrincipalName, IPAddress,
              Location, AppDisplayName
)

| union (
    MicrosoftGraphActivityLogs
    | where UniqueTokenIdentifier == tokenId
    | project TimeGenerated, RequestUri, ResponseStatusCode,
              IPAddress
)

| sort by TimeGenerated asc
```

**Speaker Notes:**
This three-table union is the definitive token tracking query. It shows every place a specific token was used: interactive sign-ins, silent token refreshes, and Graph API calls. If the IPAddress column shows two different IPs for the same token, you've confirmed token theft. The MicrosoftGraphActivityLogs results show exactly what the attacker accessed with that stolen token — were they reading emails, enumerating users, or modifying directory objects? This query reconstructs the complete attack timeline from a single token identifier.

## Slide 18: NetworkMessageId — Email Timeline Reconstruction

!layout: Title and Content

**What it is:** The Microsoft 365 internal identifier for a single email message, consistent across all tables that reference that message.

**Use it when:** Investigating a phishing chain — you need to see everything that happened to a specific message: delivery, URLs, attachments, and post-delivery remediation.

**Present in:** EmailEvents, EmailUrlInfo, EmailAttachmentInfo, EmailPostDeliveryEvents

**Speaker Notes:**
NetworkMessageId is the email equivalent of UniqueTokenIdentifier — it's the join key that connects everything about a single email message. In Module 01 (Phishing), we'll use this field extensively to reconstruct phishing kill chains: who received the email, what URLs it contained, whether anyone clicked them, what attachments were analyzed, and whether ZAP remediated the message after delivery. This field is what turns individual log entries into a complete phishing narrative.

## Slide 19: KQL — Email Timeline Reconstruction

!layout: Title and Content

```kql
let msgId = "<insert NetworkMessageId>";

EmailEvents
| where NetworkMessageId == msgId
| project TimeGenerated, Subject, SenderFromAddress,
          RecipientEmailAddress, DeliveryAction,
          DeliveryLocation, ThreatTypes

| union (
    EmailUrlInfo
    | where NetworkMessageId == msgId
    | project TimeGenerated = ingestion_time(), Url, UrlCount
)

| union (
    EmailPostDeliveryEvents
    | where NetworkMessageId == msgId
    | project TimeGenerated, Action, ActionType,
              ActionResult, DeliveryLocation
)

| sort by TimeGenerated asc
```

**Speaker Notes:**
Walk through this query step by step. The EmailEvents portion shows who sent the email, who received it, and what happened on delivery. DeliveryAction tells you if it was delivered, blocked, or quarantined. The EmailUrlInfo union adds all URLs contained in the message. The EmailPostDeliveryEvents union shows post-delivery actions like ZAP (Zero-hour Auto Purge) removals. Together, this gives you the complete lifecycle of a phishing email in one query. We'll build on this heavily in Module 01.

## Slide 20: End-to-End Hunt Pattern

!layout: Title and Content

A complete hunt chains all three techniques:

**Step 1 — Surface the footprint:**
- `search "indicator" | summarize by $table`
- Identifies which tables contain evidence

**Step 2 — Pull per-table records:**
- Targeted queries per table with time filter and key field projection
- Review for suspicious patterns (unusual IPs, off-hours activity, failed operations)

**Step 3 — Correlate across tables:**
- Join events using CorrelationId, UniqueTokenIdentifier, or NetworkMessageId
- Reconstruct the full attack timeline from authentication to action

**Speaker Notes:**
This three-step pattern is your hunting workflow for every module in this course. Step 1 is always quick — 30 seconds to find where the data lives. Step 2 is where you spend most of your time — examining individual table records for anomalies. Step 3 is where you connect the dots and prove (or disprove) your hypothesis. If Step 3 confirms your hypothesis, you have a finding. If not, refine your hypothesis and loop back. This pattern works whether you're hunting phishing, token abuse, Key Vault exfiltration, or any other cloud attack technique.

## Slide 21: Key Takeaways

!layout: Title and Content

- Threat hunting is proactive, hypothesis-driven, and complementary to alert-based detection
- Always start with a cross-table footprint scan before deep-diving into individual tables
- Three correlation fields connect cloud attack chains: CorrelationId, UniqueTokenIdentifier, NetworkMessageId
- The hunt loop — Hypothesis, Data Collection, Investigation, Finding, Feedback — applies to every module
- Convert confirmed findings into analytics rules to close detection gaps permanently

**What comes next:**
- Module 01: Phishing — device code phishing, AiTM attacks, illicit consent grants
- Module 02: Token Abuse — refresh token replay, PRT abuse, FOCI token farming
- Modules 03-08: Logic Apps, Storage, Persistence, Key Vault, Container Apps, Web Apps

**Speaker Notes:**
Summarize the three key skills from this module: footprint discovery with the search operator, per-table drilldowns with targeted KQL, and cross-table correlation with the three key fields. Every module that follows will use this same pattern applied to different attack techniques and Sentinel tables. Encourage students to practice these queries in the lab environment before moving to Module 01. Remind them that the Student Guide has a KQL Quick Reference and Sentinel Tables Reference they can use throughout the training.

## Slide 22: References

!layout: Title and Content

| Resource | Link |
|---|---|
| Threat Hunting in Microsoft Sentinel | learn.microsoft.com/azure/sentinel/hunting |
| KQL search operator | learn.microsoft.com/kusto/query/search-operator |
| KQL summarize operator | learn.microsoft.com/kusto/query/summarize-operator |
| SigninLogs table schema | learn.microsoft.com/azure/azure-monitor/reference/tables/signinlogs |
| AzureActivity table schema | learn.microsoft.com/azure/azure-monitor/reference/tables/azureactivity |
| EmailEvents table schema | learn.microsoft.com/azure/azure-monitor/reference/tables/emailevents |
| MITRE ATT&CK Cloud Matrix | attack.mitre.org/matrices/enterprise/cloud/ |
| SC-200 Threat Hunting Learning Path | learn.microsoft.com/training/paths/sc-200-perform-threat-hunting-azure-sentinel/ |

**Speaker Notes:**
These are all official Microsoft Learn resources that students can reference after the training. The SC-200 learning path is particularly valuable for anyone pursuing the Microsoft Security Operations Analyst certification. The MITRE ATT&CK Cloud Matrix should be bookmarked — it's the primary source for forming hypotheses throughout the rest of this course.
