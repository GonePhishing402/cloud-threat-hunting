# Defend - Module 03 (Logic App Abuse)

## Primary Detection Surface: AzureActivity

Logic App management operations (creating, editing, deleting workflows; assigning RBAC; retrieving trigger URLs) are recorded in the **AzureActivity** table in Log Analytics. This table captures the Azure control plane — every call that goes through Azure Resource Manager.

### Key AzureActivity Fields for Logic App Hunting

| Field | Description | Example Value |
|---|---|---|
| `TimeGenerated` | UTC timestamp of the operation | `2024-03-15T14:22:10Z` |
| `OperationName` | The resource provider action performed | `Microsoft.Logic/workflows/write` |
| `ResourceId` | Full ARM resource ID of the affected Logic App | `/subscriptions/.../workflows/my-workflow` |
| `ResourceGroup` | Resource group containing the Logic App | `rg-finance-automation` |
| `SubscriptionId` | Azure subscription | `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` |
| `Caller` | UPN or service principal ID that made the call | `jsmith@contoso.com` |
| `CallerIpAddress` | Source IP of the call | `203.0.113.45` |
| `ActivityStatus` | Outcome of the operation | `Succeeded`, `Failed`, `Started` |
| `ActivityStatusValue` | Normalized status string | `Success` |
| `Level` | Severity level of the event | `Informational`, `Warning`, `Error` |
| `Properties` | JSON blob with additional detail; contains `statusCode`, `serviceRequestId`, `eventCategory` | `{"statusCode":"OK", ...}` |
| `Authorization` | JSON blob with the `action`, `scope`, and `evidence` fields from the RBAC check | `{"action":"Microsoft.Logic/workflows/write","scope":"/subscriptions/..."}` |
| `HTTPRequest` | HTTP method and URI of the ARM API call | `{"method":"PUT","clientRequestId":"..."}` |

### High-Value OperationName Values

| OperationName | Meaning | Threat Signal |
|---|---|---|
| `Microsoft.Logic/workflows/write` | Workflow definition created or updated | Attacker editing workflow JSON |
| `Microsoft.Logic/workflows/delete` | Workflow deleted | Covering tracks / disruption |
| `Microsoft.Logic/workflows/triggers/listCallbackUrl/action` | Trigger SAS URL retrieved | Attacker harvesting trigger URL |
| `Microsoft.Logic/workflows/run/action` | Manual workflow run initiated | Adversary-triggered execution |
| `Microsoft.Authorization/roleAssignments/write` | RBAC assignment added on Logic App scope | Privilege escalation / persistence |
| `Microsoft.Authorization/roleAssignments/delete` | RBAC assignment removed | Covering tracks |

---

## KQL Detection Queries

### 1. Detect All Workflow Write Operations (Baseline)

```kql
AzureActivity
| where TimeGenerated > ago(30d)
| where OperationName == "Microsoft.Logic/workflows/write"
| where ActivityStatus == "Succeeded"
| project TimeGenerated, Caller, CallerIpAddress, ResourceId, ResourceGroup, SubscriptionId
| order by TimeGenerated desc
```

**What to look for:** Any `Caller` that is not a known automation service principal. Interactive user accounts editing workflows are a high-priority lead.

---

### 2. Detect Trigger URL Retrieval (SAS Callback URL Harvest)

```kql
AzureActivity
| where TimeGenerated > ago(30d)
| where OperationName has "listCallbackUrl"
| where ActivityStatus == "Succeeded"
| project TimeGenerated, Caller, CallerIpAddress, ResourceId, ResourceGroup
| order by TimeGenerated desc
```

**What to look for:** Any identity retrieving trigger SAS URLs for workflows they did not create, especially from unusual IP addresses or at unusual times.

---

### 3. Detect RBAC Changes Scoped to Logic App Resources

```kql
AzureActivity
| where TimeGenerated > ago(30d)
| where OperationName == "Microsoft.Authorization/roleAssignments/write"
| where ActivityStatus == "Succeeded"
| where ResourceId has "Microsoft.Logic/workflows"
| extend AuthJson = parse_json(Authorization)
| project TimeGenerated, Caller, CallerIpAddress, ResourceId,
    RoleAction = AuthJson.action,
    Scope = AuthJson.scope
| order by TimeGenerated desc
```

**What to look for:** New role assignments on Logic App resources — especially granting Logic App Contributor or Contributor to identities outside the expected DevOps team.

---

### 4. First-Time Callers Editing Workflows (Anomaly Detection)

```kql
let known_editors = AzureActivity
| where TimeGenerated between(ago(90d) .. ago(30d))
| where OperationName == "Microsoft.Logic/workflows/write"
| where ActivityStatus == "Succeeded"
| summarize by Caller;
AzureActivity
| where TimeGenerated > ago(30d)
| where OperationName == "Microsoft.Logic/workflows/write"
| where ActivityStatus == "Succeeded"
| where Caller !in (known_editors)
| project TimeGenerated, Caller, CallerIpAddress, ResourceId, ResourceGroup
| order by TimeGenerated desc
```

**What to look for:** Identities editing workflows for the first time in the last 30 days that had no prior history. These are the highest-priority triage targets.

---

### 5. Full Logic App Suspicious Activity Summary

```kql
AzureActivity
| where TimeGenerated > ago(7d)
| where ResourceProvider == "MICROSOFT.LOGIC"
    or OperationName has "Microsoft.Authorization/roleAssignments"
| where ActivityStatus == "Succeeded"
| summarize Operations = make_set(OperationName), Count = count()
    by Caller, CallerIpAddress, ResourceGroup, bin(TimeGenerated, 1h)
| order by Count desc
```

**What to look for:** A single `Caller` performing multiple operation types (workflow write + trigger URL retrieval + RBAC write) within a short window — this pattern strongly indicates an adversary enumerating and abusing Logic Apps.

---

## Investigation Workflow

1. **Start with query #4** (first-time callers) to find unexpected identities.
2. **Pivot to query #1** to review all recent workflow edits by that identity.
3. **Check query #2** to determine if the same identity retrieved trigger SAS URLs.
4. **Run query #3** to check for RBAC changes that granted that identity access.
5. **Review the workflow definition** in the Azure portal to inspect the run history and action definitions for external HTTP endpoints.

---

## Microsoft Learn References

- Monitoring data reference for Azure Logic Apps (AzureActivity columns): https://learn.microsoft.com/azure/logic-apps/monitor-logic-apps-reference#azure-monitor-logs-tables
- AzureActivity table schema: https://learn.microsoft.com/azure/azure-monitor/reference/tables/AzureActivity
- View activity logs for Azure RBAC changes: https://learn.microsoft.com/azure/role-based-access-control/change-history-report
- Microsoft.Logic resource provider operations: https://learn.microsoft.com/azure/role-based-access-control/permissions/integration#microsoftlogic
