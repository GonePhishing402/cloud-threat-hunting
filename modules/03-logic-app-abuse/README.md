# Module 03 — Logic App Abuse in Azure

## Objective

Hunt for malicious use of Azure Logic Apps including data exfiltration via connectors, privilege escalation through managed identity-backed Logic Apps, and persistence via timer triggers.

## Duration

~3 hours (lecture + hands-on labs)

## MITRE ATT&CK Mapping

| Technique | ID | Tactic |
|---|---|---|
| Serverless Execution | T1648 | Execution |
| Automated Exfiltration | T1020 | Exfiltration |
| Abuse Elevation Control Mechanism | T1548 | Privilege Escalation |
| Scheduled Task/Job | T1053 | Persistence |

## Sentinel Tables

- `AzureActivity` — Logic App creation, modification, run triggers
- `AzureDiagnostics` — Logic App run history, action details (requires diagnostic settings)
- `AuditLogs` — Managed identity assignment to Logic Apps
- `SigninLogs` — Managed identity sign-in events

## Attack Narratives

### 1. Data Exfiltration via Logic App Connectors

**Attack Flow:**
1. Attacker with Contributor access creates or modifies a Logic App
2. Configures connectors: HTTP (external webhook), Outlook (email with attachments), Blob Storage (copy to external account)
3. Logic App reads sensitive data from internal systems and sends it externally
4. Trigger can be recurrence (timer) for continuous exfil

**Key Indicators:**
- Logic App creation/modification by unexpected users
- HTTP connector actions pointing to external IPs/domains
- Outlook connector sending emails with attachments to external recipients
- Blob Storage connector writing to unfamiliar storage accounts
- High-frequency timer triggers (every 5 min, hourly)

### 2. Privilege Escalation via Managed Identity

**Attack Flow:**
1. Attacker assigns a system-assigned or user-assigned managed identity to a Logic App
2. The managed identity has elevated RBAC roles (Contributor, Key Vault Secrets Officer, etc.)
3. Logic App actions execute with the managed identity's permissions
4. Attacker effectively escalates from Logic App Contributor to whatever the MI can access

**Key Indicators:**
- Managed identity assignment to Logic Apps by non-admin users
- Logic App making API calls to resources beyond its expected scope
- Managed identity sign-ins with `ServicePrincipalId` matching a Logic App's identity
- MI accessing Key Vault secrets, modifying RBAC, or reading sensitive data

### 3. Persistence via Timer Triggers

**Attack Flow:**
1. Attacker creates a Logic App with a recurrence trigger (e.g., every 6 hours)
2. Logic App performs reconnaissance, exfiltration, or maintains C2
3. Even if the attacker loses access, the Logic App continues executing
4. Logic App can re-establish access by creating new credentials or exfiltrating tokens

**Key Indicators:**
- Net-new Logic Apps with recurrence triggers created during non-business hours
- Logic Apps with no associated change management record
- Logic Apps running successfully with no human interaction for extended periods
- Logic App outputs containing tokens, secrets, or large data volumes

## Hunt Playbooks

### Playbook 1: Detect Suspicious Logic App Creation/Modification
```kql
AzureActivity
| where TimeGenerated > ago(7d)
| where OperationNameValue has_any (
    "Microsoft.Logic/workflows/write",
    "Microsoft.Logic/workflows/run/action",
    "Microsoft.Logic/workflows/triggers/run/action"
)
| where ActivityStatusValue == "Success"
| extend Creator = Caller
| project TimeGenerated, Creator, CallerIpAddress, OperationNameValue, ResourceGroup, 
    ResourceId = _ResourceId, Properties = Properties_d
| order by TimeGenerated desc
```

### Playbook 2: Identify Logic Apps with External HTTP Connections
```kql
AzureDiagnostics
| where TimeGenerated > ago(7d)
| where ResourceProvider == "MICROSOFT.LOGIC"
| where Category == "WorkflowRuntime"
| where status_s == "Succeeded"
| where resource_actionName_s has "HTTP"
| extend TargetUri = tostring(parse_json(resource_triggerOutput_s).uri)
| where TargetUri !has "management.azure.com" and TargetUri !has "graph.microsoft.com"
| project TimeGenerated, resource_workflowName_s, resource_actionName_s, TargetUri, resource_runId_s
```

### Playbook 3: Logic Apps with Managed Identity Sign-ins
```kql
let LogicAppMIs = AzureActivity
    | where OperationNameValue == "Microsoft.Logic/workflows/write"
    | extend ResourceId = _ResourceId
    | distinct ResourceId;
AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(7d)
| where ResourceDisplayName != ""
| where AppDisplayName == "Logic Apps"
| project TimeGenerated, ServicePrincipalId = UserId, ResourceDisplayName, IPAddress, ResultType
| order by TimeGenerated desc
```

### Playbook 4: High-Frequency Timer Triggers
```kql
AzureActivity
| where TimeGenerated > ago(7d)
| where OperationNameValue == "Microsoft.Logic/workflows/triggers/run/action"
| summarize RunCount = count(), FirstRun = min(TimeGenerated), LastRun = max(TimeGenerated) 
    by _ResourceId, Caller
| extend AvgIntervalMinutes = datetime_diff('minute', LastRun, FirstRun) / toreal(RunCount)
| where AvgIntervalMinutes < 60 and RunCount > 10
| order by RunCount desc
```

## CTFd Challenges

| # | Title | Difficulty | Description |
|---|---|---|---|
| 1 | App Factory | Easy | Identify the Logic App that was created by an unexpected user |
| 2 | Dial Home | Medium | Find the Logic App making HTTP calls to an external IP |
| 3 | Identity Theft | Medium | Detect the Logic App abusing a managed identity to access Key Vault |
| 4 | Tick Tock | Hard | Find the persistence Logic App with a timer trigger and determine what data it exfiltrates |
| 5 | Kill the Chain | Hard | Trace the full attack: Logic App creation → MI escalation → exfiltration |

## Hardening

- **Restrict Logic App connector types** using Azure Policy (deny HTTP connector, restrict to approved connectors)
- **RBAC scoping**: Separate Logic App Contributor from Managed Identity Operator — don't let the same user create Logic Apps AND assign MIs
- **Network isolation**: Deploy Logic Apps in ISE (Integration Service Environment) or use VNet integration
- **Diagnostic logging**: Enable WorkflowRuntime diagnostic logs to Log Analytics
- **Run history monitoring**: Alert on Logic Apps with high run frequency or external connections
- **Disable unused Logic Apps**: Implement lifecycle management — disable Logic Apps that haven't been modified/reviewed in 90 days
