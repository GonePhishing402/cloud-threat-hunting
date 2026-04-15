# Student Guide — Cloud Threat Hunting VBD

## Welcome

This training teaches you to proactively hunt for cloud threats in Azure using Microsoft Sentinel. You'll investigate real attack patterns, execute KQL hunt queries, and build hardening recommendations — all through hands-on labs.

## Lab Access

| Resource | URL |
|---|---|
| Microsoft Sentinel | `https://portal.azure.com/#view/Microsoft_Azure_Security_Insights` |
| CTFd Challenges | *Provided by instructor* |
| Huntability App | *Provided by instructor* |

**Your lab credentials and workspace details will be provided on Day 1.**

## How This Training Works

1. **Threat Brief** — Instructor presents the attack technique with real-world examples
2. **Live Demo** — Watch the hunt in action in Sentinel
3. **Guided Lab** — Follow the hunt playbook and run the queries yourself
4. **CTFd Challenges** — Solve challenges independently or in teams
5. **Hardening** — Discuss how to prevent and detect the attack going forward

## KQL Quick Reference

### Essential Operators

```kql
// Filter rows
TableName | where ColumnName == "value"
TableName | where TimeGenerated > ago(7d)
TableName | where ColumnName has "partial"
TableName | where ColumnName in ("val1", "val2")

// Select columns
| project TimeGenerated, UserPrincipalName, IPAddress

// Add calculated columns
| extend City = tostring(LocationDetails.city)

// Aggregate
| summarize count() by UserPrincipalName
| summarize dcount(IPAddress) by UserPrincipalName

// Sort
| order by TimeGenerated desc

// Limit
| take 100

// Join tables
Table1 | join kind=inner (Table2) on CommonColumn

// Union tables
union Table1, Table2
```

### Time Functions
```kql
ago(7d)                    // 7 days ago
ago(1h)                    // 1 hour ago
between(ago(7d) .. now())  // Last 7 days
bin(TimeGenerated, 1h)     // Group into 1-hour buckets
datetime_diff('minute', T2, T1)  // Minutes between two times
```

### String Functions
```kql
has           // Contains substring (case-insensitive, word boundary)
contains      // Contains substring (case-insensitive)
startswith    // Starts with
matches regex // Regex match
strcat(A, B)  // Concatenate strings
split(S, "/") // Split string
tostring(X)   // Convert to string
parse_json(X) // Parse JSON string
```

### Aggregations
```kql
count()                    // Count rows
dcount(Column)             // Distinct count
make_set(Column)           // Distinct values as array
make_set(Column, 10)       // Limit to 10 values
sum(Column)                // Sum numeric values
avg(Column)                // Average
min(Column) / max(Column)  // Min / Max
```

## Sentinel Tables Reference

| Table | What It Contains |
|---|---|
| `SigninLogs` | Interactive sign-in events (user logins) |
| `AADNonInteractiveUserSignInLogs` | Token refresh, SSO, silent sign-ins |
| `AADServicePrincipalSignInLogs` | Service principal authentications |
| `AADManagedIdentitySignInLogs` | Managed identity authentications |
| `AuditLogs` | Azure AD directory changes (user/app/role modifications) |
| `AzureActivity` | Azure resource management operations |
| `StorageBlobLogs` | Blob storage data plane access |
| `AzureDiagnostics` | Key Vault, Logic App, and other resource diagnostic logs |
| `OfficeActivity` | Microsoft 365 events (SharePoint, Exchange, Teams) |
| `MicrosoftGraphActivityLogs` | Microsoft Graph API calls |

## Threat Hunt Methodology — Quick Card

```
┌─────────────────────────────────────────────────┐
│           THREAT HUNT LOOP                       │
│                                                   │
│  1. HYPOTHESIS                                    │
│     "I suspect [technique] is targeting           │
│      [asset/user] because [intel/anomaly]"        │
│                                                   │
│  2. DATA COLLECTION                               │
│     Which Sentinel tables do I need?              │
│     Are those logs enabled and current?            │
│                                                   │
│  3. INVESTIGATION                                 │
│     Execute KQL queries                           │
│     Pivot on entities (user, IP, resource)         │
│     Build a timeline                              │
│                                                   │
│  4. RESPONSE                                      │
│     Escalate if confirmed                         │
│     Contain if active                             │
│     Preserve evidence                             │
│                                                   │
│  5. FEEDBACK                                      │
│     Convert to analytics rule if repeatable       │
│     Update threat model                           │
│     Share findings with team                      │
└─────────────────────────────────────────────────┘
```

## MITRE ATT&CK Cloud Techniques Covered

| Module | Techniques |
|---|---|
| 01 - Phishing | T1566, T1528, T1606, T1078.004 |
| 02 - Token Abuse | T1528, T1550, T1078.004 |
| 03 - Logic Apps | T1648, T1020, T1548, T1053 |
| 04 - Storage/KV | T1552, T1530, T1098, T1567 |
| 05 - Persistence | T1098.001, T1136.003, T1078.004, T1199 |

## CTFd Tips

- **Start with Easy challenges** to build confidence and orient to the data
- **Use hints strategically** — they cost points but save time
- **Read the challenge description carefully** — the flag format is specified
- **Work as a team** on Hard challenges — divide investigation tasks
- **Ask the instructor** if you're stuck for >15 minutes on a single challenge

## Post-Training Resources

- [MITRE ATT&CK Cloud Matrix](https://attack.mitre.org/matrices/enterprise/cloud/)
- [Microsoft Sentinel Hunting](https://learn.microsoft.com/en-us/azure/sentinel/hunting)
- [KQL Quick Reference](https://learn.microsoft.com/en-us/azure/data-explorer/kql-quick-reference)
- [Azure AD Security Operations Guide](https://learn.microsoft.com/en-us/azure/active-directory/fundamentals/security-operations-introduction)
- [Microsoft Cloud Security Benchmark](https://learn.microsoft.com/en-us/security/benchmark/azure/)
