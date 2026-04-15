# Module 05 — Persistence with Managed Identities and Service Principals

## Objective

Hunt for attacker persistence via Azure AD service principals, federated identity credentials, and managed identity abuse. Students learn how attackers establish long-term access that survives credential resets and user account remediation.

## Duration

~3 hours (lecture + hands-on labs)

## MITRE ATT&CK Mapping

| Technique | ID | Tactic |
|---|---|---|
| Account Manipulation: Additional Cloud Credentials | T1098.001 | Persistence |
| Create Account: Cloud Account | T1136.003 | Persistence |
| Valid Accounts: Cloud Accounts | T1078.004 | Defense Evasion, Persistence |
| Trusted Relationship | T1199 | Initial Access |

## Sentinel Tables

- `AuditLogs` — SP creation, credential changes, app role assignments, federated identity credentials
- `AADNonInteractiveUserSignInLogs` / `AADServicePrincipalSignInLogs` — SP authentication events
- `AzureActivity` — Managed identity operations (assignment, usage)
- `AzureADManagedIdentitySignInLogs` — MI sign-in events (if enabled)

## Attack Narratives

### 1. Service Principal Credential Addition (Backdoor)

**Attack Flow:**
1. Attacker with Application Administrator or Owner role on an existing SP
2. Adds a new client secret or certificate credential to the SP
3. SP retains its existing RBAC roles and API permissions
4. Attacker authenticates as the SP from any location — no MFA, no Conditional Access (by default)

**Key Indicators:**
- `AuditLogs` where `OperationName == "Add service principal credentials"` from unexpected admins
- Credential additions outside of change management windows
- New credentials with unusually long expiry (>1 year)
- SP sign-ins from new IPs after credential addition

### 2. Federated Identity Credential Abuse

**Attack Flow:**
1. Attacker adds a federated identity credential to an Azure AD application
2. Links external identity provider (GitHub Actions, AWS, attacker-controlled IdP)
3. External IdP can now request tokens as the Azure AD application
4. No client secret needed — identity federation provides token exchange

**Key Indicators:**
- `AuditLogs` where `OperationName == "Add federated identity credential"`
- Federated credentials pointing to unexpected issuers (attacker's GitHub repo, unknown AWS accounts)
- SP sign-ins with `AuthenticationProtocol == "federatedIdentity"` from new issuers
- Federation to external organizations not in approved vendor list

### 3. Managed Identity Assignment to Attacker Resources

**Attack Flow:**
1. Attacker creates a new Azure resource (VM, Logic App, Function App) in a compromised subscription
2. Assigns a user-assigned managed identity with elevated RBAC roles
3. Managed identity provides credential-free access to Azure resources
4. Identity persists even if the attacker's user account is disabled

**Key Indicators:**
- User-assigned managed identity creation by non-Infrastructure users
- MI assignment to newly created resources (especially VMs, Logic Apps in unexpected RGs)
- MI RBAC role assignments granting Contributor, Owner, or Key Vault access
- MI sign-in events from resources that shouldn't need those permissions

### 4. App Role Assignment Escalation

**Attack Flow:**
1. Attacker assigns high-privilege Microsoft Graph app roles to a SP
2. Roles like `RoleManagement.ReadWrite.Directory`, `Application.ReadWrite.All`, `Mail.ReadWrite`
3. SP can now manage directory roles, create more apps, or read all email
4. App roles on SPs don't require user consent — admin-granted

**Key Indicators:**
- `AuditLogs` where `OperationName == "Add app role assignment to service principal"`
- High-privilege Graph roles assigned to SPs that previously had none
- Role assignments by users who aren't Global Admins or Application Admins
- SPs with both directory and data access roles (unusual combination)

## Hunt Playbooks

### Playbook 1: Detect New SP Credentials
```kql
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName has_any ("Add service principal credentials", "Update application – Certificates and secrets management")
| extend Actor = tostring(InitiatedBy.user.userPrincipalName)
| extend SPName = tostring(TargetResources[0].displayName)
| extend SPId = tostring(TargetResources[0].id)
| extend KeyType = tostring(TargetResources[0].modifiedProperties[0].displayName)
| project TimeGenerated, Actor, SPName, SPId, KeyType, CorrelationId
| order by TimeGenerated desc
```

### Playbook 2: Detect Federated Identity Credentials
```kql
AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName has "federated identity credential"
| extend Actor = tostring(InitiatedBy.user.userPrincipalName)
| extend AppName = tostring(TargetResources[0].displayName)
| extend FedDetails = tostring(TargetResources[0].modifiedProperties)
| project TimeGenerated, Actor, AppName, FedDetails, CorrelationId
| order by TimeGenerated desc
```

### Playbook 3: New Managed Identity Assignments
```kql
AzureActivity
| where TimeGenerated > ago(7d)
| where OperationNameValue has_any (
    "Microsoft.ManagedIdentity/userAssignedIdentities/write",
    "Microsoft.Compute/virtualMachines/write",
    "Microsoft.Logic/workflows/write"
)
| where Properties_d has "identity" and Properties_d has "UserAssigned"
| project TimeGenerated, Caller, CallerIpAddress, OperationNameValue, _ResourceId
| order by TimeGenerated desc
```

### Playbook 4: High-Privilege App Role Assignments
```kql
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName == "Add app role assignment to service principal"
| extend Actor = tostring(InitiatedBy.user.userPrincipalName)
| extend SPName = tostring(TargetResources[0].displayName)
| extend RoleDetails = tostring(TargetResources[0].modifiedProperties)
| where RoleDetails has_any ("RoleManagement", "Application.ReadWrite", "Directory.ReadWrite", "Mail.ReadWrite", "Sites.ReadWrite")
| project TimeGenerated, Actor, SPName, RoleDetails
| order by TimeGenerated desc
```

### Playbook 5: SP Sign-ins After Credential Changes
```kql
let CredentialChanges = AuditLogs
    | where TimeGenerated > ago(7d)
    | where OperationName has "service principal credentials"
    | extend SPId = tostring(TargetResources[0].id)
    | project ChangeTime = TimeGenerated, SPId;
AADServicePrincipalSignInLogs
| where TimeGenerated > ago(7d)
| where ResultType == 0
| join kind=inner (CredentialChanges) on $left.ServicePrincipalId == $right.SPId
| where TimeGenerated > ChangeTime
| project TimeGenerated, ServicePrincipalName, ServicePrincipalId, IPAddress, ResourceDisplayName, ChangeTime
| order by TimeGenerated desc
```

## CTFd Challenges

| # | Title | Difficulty | Description |
|---|---|---|---|
| 1 | New Keys | Easy | Identify the service principal that received new credentials from an unexpected user |
| 2 | Federal Agent | Medium | Find the federated identity credential and identify the external issuer |
| 3 | Identity Farm | Medium | Detect the managed identity assigned to an attacker-created resource and list its RBAC roles |
| 4 | Role Escalation | Hard | Trace the app role assignment escalation and identify what data the SP accessed |
| 5 | Persistence Map | Hard | Map all persistence mechanisms established by the attacker across SPs, MIs, and federated credentials |

## Hardening

- **PIM for Service Principals**: Use Privileged Identity Management for workload identities where available
- **Credential Expiration Policies**: Enforce maximum secret lifetime (e.g., 6 months); alert on certificates expiring >1 year out
- **Require Admin Consent for App Role Assignments**: Prevent self-service app role grants
- **Audit Federated Identity Credentials**: Maintain an approved list of external issuers; alert on new federation
- **Managed Identity RBAC Review**: Quarterly review of all MI role assignments; remove unnecessary access
- **Conditional Access for Workload Identities**: Apply CA policies to service principals (Preview)
- **Monitor SP Sign-ins**: Enable and alert on AADServicePrincipalSignInLogs
- **Owner/Contributor Alerting**: Alert when any user is added as Owner of an application or SP
