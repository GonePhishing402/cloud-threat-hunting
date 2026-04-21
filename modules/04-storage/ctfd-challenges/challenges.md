# Module 04 — Storage Blob Threat Hunting CTF Challenges

> **Data source:** `modules/04-storage/emulated-data/` — ingest `StorageBlobLogs.json` and `SecurityAlert.json` into their matching ADX tables.  
> **Tables used:** `StorageBlobLogs`, `SecurityAlert`  
> **Total points available:** 1,300

---

## Scenario Background

Your SOC has been asked to investigate unusual activity against the `stcorpanalyticsprod` storage account owned by NorthStar Technologies. A series of blob read operations occurred outside business hours, targeting sensitive files across HR, Legal, Security, and IT containers. The activity was performed using a service principal account that should only perform automated pipeline reads — not bulk enumeration across multiple sensitive directories.

Dig into the logs and determine what was taken, how, and from where.

---

### S-1 | First Light
**Category:** `04-storage` | **Points:** 100 | **Difficulty:** 🟢 Easy

**Narrative:**  
Before a threat hunt, you need to orient yourself. Start by identifying who was active on the storage account. Something will stand out — a caller IP that doesn't match the account's normal access patterns.

**Question:**  
Query `StorageBlobLogs` for all events against the `stcorpanalyticsprod` account and summarize unique `CallerIpAddress` values. One IP accounts for the majority of activity and belongs to external infrastructure. Submit that IP as your flag.

**KQL starting point:**
```kql
StorageBlobLogs
| where AccountName == "stcorpanalyticsprod"
| summarize EventCount = count() by CallerIpAddress
| order by EventCount desc
```

**Hint 1** (25 pts): The suspicious IP is a /24 block commonly associated with hosting providers. It is not a private RFC1918 address.

**Flag:** `FLAG{91.229.50.103}`

---

### S-2 | The Opening Move
**Category:** `04-storage` | **Points:** 150 | **Difficulty:** 🟢 Easy

**Narrative:**  
Attackers targeting storage accounts typically begin with a reconnaissance operation to understand the structure of the account before downloading blobs. Find the very first operation the suspicious IP executed on the storage account — this tells you how they mapped the environment.

**Question:**  
Filter `StorageBlobLogs` to the suspicious IP found in S-1 and sort by `TimeGenerated` ascending. What is the `OperationName` of the **first** operation recorded? Submit it as your flag.

**KQL starting point:**
```kql
StorageBlobLogs
| where AccountName == "stcorpanalyticsprod"
| where CallerIpAddress == "<ip-from-S1>"
| order by TimeGenerated asc
| project TimeGenerated, OperationName, ObjectKey, AuthenticationType
```

**Hint 1** (25 pts): The first operation reveals the account-level structure before the attacker drilled into any specific container. The operation name starts with "List".

**Flag:** `FLAG{ListContainers}`

---

### S-3 | The Haul
**Category:** `04-storage` | **Points:** 150 | **Difficulty:** 🟢 Easy

**Narrative:**  
After enumerating containers, the attacker moved to downloading individual blobs. Knowing the exact count of files pulled helps scope the blast radius of the incident.

**Question:**  
Count the number of **distinct** blob objects downloaded (`OperationName == "GetBlob"`) by the attacker IP using OAuth authentication. Submit the count as your flag.

**KQL starting point:**
```kql
StorageBlobLogs
| where CallerIpAddress == "<ip-from-S1>"
| where OperationName == "GetBlob"
| where AuthenticationType == "OAuth"
| summarize dcount(ObjectKey)
```

**Hint 1** (25 pts): Each blob is a unique file path. The distinct count reflects the number of unique files pulled — not individual HTTP requests.

**Flag:** `FLAG{5}`

---

### S-4 | Crown Jewel
**Category:** `04-storage` | **Points:** 200 | **Difficulty:** 🟡 Medium

**Narrative:**  
Not all files are equal. Triage which blob represented the largest single data transfer — this is typically where an attacker spent the most bandwidth and is the highest-priority exfiltration artifact to recover or revoke access to.

**Question:**  
Query `StorageBlobLogs` for `GetBlob` operations from the attacker IP. Parse the filename out of `ObjectKey` and return the file with the highest `ResponseBodySize`. Submit the filename (not the full path) as your flag.

**KQL starting point:**
```kql
StorageBlobLogs
| where CallerIpAddress == "<ip-from-S1>"
| where OperationName == "GetBlob"
| extend FileName = tostring(split(ObjectKey, "/")[-1])
| project TimeGenerated, FileName, ResponseBodySize
| order by ResponseBodySize desc
| take 1
```

**Hint 1** (50 pts): The largest file is an archive containing structured HR documents. Its extension is `.zip`.

**Flag:** `FLAG{employee_contracts.zip}`

---

### S-5 | Second Stage
**Category:** `04-storage` | **Points:** 200 | **Difficulty:** 🟡 Medium

**Narrative:**  
Eight minutes after the initial OAuth-based access ended, a second source IP reached the same storage account and re-downloaded the highest-value blob from S-4. This time the access was authenticated differently — suggesting the attacker generated a credential artifact during the first wave and handed it to a separate system for staged exfiltration.

**Question:**  
Query `StorageBlobLogs` for all `GetBlob` events where `AuthenticationType == "SAS"`. What is the `CallerIpAddress` of this second-stage access? Submit it as your flag.

**KQL starting point:**
```kql
StorageBlobLogs
| where AccountName == "stcorpanalyticsprod"
| where OperationName == "GetBlob"
| where AuthenticationType == "SAS"
| project TimeGenerated, CallerIpAddress, ObjectKey, ResponseBodySize, UserAgentHeader
```

**Hint 1** (50 pts): The SAS-based download uses a different SDK user agent than the OAuth-based access, suggesting it ran on a different machine. The IP is in a Netherlands hosting range.

**Flag:** `FLAG{5.188.62.14}`

---

### S-6 | Defender Sees It Too
**Category:** `04-storage` | **Points:** 200 | **Difficulty:** 🟡 Medium

**Narrative:**  
Microsoft Defender for Storage fired alerts during this incident. Instead of only hunting raw telemetry, a skilled analyst correlates `SecurityAlert` events back to `StorageBlobLogs` to understand which attacker actions triggered detection — and equally important, which ones did not.

**Question:**  
Query `SecurityAlert` and filter by `ProviderName == "Microsoft Defender for Storage"`. Join it with `StorageBlobLogs` on `AccountName` matching `CompromisedEntity`. Return the `AlertName` and `AlertSeverity` of the alert that fired specifically due to the SAS-based access from the second IP. Submit the `AlertSeverity` value as your flag.

**KQL starting point:**
```kql
let StorageAlerts = SecurityAlert
    | where ProviderName == "Microsoft Defender for Storage"
    | extend Props = parse_json(ExtendedProperties)
    | project AlertName, AlertSeverity, AlertType, CompromisedEntity,
              AlertIP = tostring(Props["IP address"]),
              AuthType = tostring(Props["Authentication type"]);
StorageAlerts
| where AuthType == "SAS"
| project AlertName, AlertSeverity, AlertType, AlertIP
```

**Hint 1** (50 pts): Two alerts fired. You want the one scoped to SAS authentication, not the bulk-extraction alert. Check the `ExtendedProperties` JSON for the `Authentication type` field.

**Flag:** `FLAG{Medium}`

---

### S-7 | Quantify the Damage
**Category:** `04-storage` | **Points:** 300 | **Difficulty:** 🔴 Hard

**Narrative:**  
The `SecurityAlert` from Defender for Storage embeds structured metadata in the `ExtendedProperties` field, including the total volume of data read. This is useful when the raw telemetry contains partial records or when you need a pre-computed summary for an IR report. Your job is to extract it.

**Question:**  
Query `SecurityAlert` for the High severity Defender for Storage alert. Parse the `ExtendedProperties` JSON field and extract the `Total accessed data (bytes)` value. Submit the byte count as your flag.

**KQL starting point:**
```kql
SecurityAlert
| where ProviderName == "Microsoft Defender for Storage"
| where AlertSeverity == "High"
| extend Props = parse_json(ExtendedProperties)
| project AlertName,
          TotalBytes = Props["Total accessed data (bytes)"],
          BlobCount  = Props["Number of accessed blobs"],
          AccessedPaths = Props["Accessed blob paths"]
```

**Hint 1** (75 pts): `ExtendedProperties` is a JSON string. Use `parse_json()` to deserialize it, then reference the key with bracket notation: `Props["Total accessed data (bytes)"]`. The result is a nine-digit number.

**Hint 2** (100 pts): Sum the `ResponseBodySize` values from the five OAuth `GetBlob` events in `StorageBlobLogs` and compare — the numbers should match.

**Flag:** `FLAG{167704532}`
