# Phishing Hunt Playbooks

## Playbook 1: Illicit Consent Grant Detection

### Hypothesis
An attacker has phished a user into granting OAuth permissions to a malicious application, which is now accessing organizational data via Graph API.

### Step 1 — Identify Recent Consent Grants
```kql
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName == "Consent to application"
| extend AppName = tostring(TargetResources[0].displayName)
| extend ConsentedBy = tostring(InitiatedBy.user.userPrincipalName)
| extend Permissions = tostring(TargetResources[0].modifiedProperties)
| project TimeGenerated, ConsentedBy, AppName, Permissions, CorrelationId
| order by TimeGenerated desc
```

### Step 2 — Identify High-Risk Permissions
```kql
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName == "Consent to application"
| extend Permissions = tostring(TargetResources[0].modifiedProperties)
| where Permissions has_any ("Mail.Read", "Mail.ReadWrite", "Files.ReadWrite.All", "User.ReadWrite.All", "Directory.ReadWrite.All", "Mail.Send")
| extend AppName = tostring(TargetResources[0].displayName)
| extend ConsentedBy = tostring(InitiatedBy.user.userPrincipalName)
| project TimeGenerated, ConsentedBy, AppName, Permissions
```

### Step 3 — Check if the App is External
```kql
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName == "Consent to application"
| extend AppId = tostring(TargetResources[0].id)
| extend AppName = tostring(TargetResources[0].displayName)
| extend HomeTenantId = tostring(AdditionalDetails[0].value)
| where HomeTenantId != AADTenantId
| project TimeGenerated, AppName, AppId, HomeTenantId
```

### Step 4 — Correlate with Sign-in Activity
```kql
let SuspiciousApps = 
    AuditLogs
    | where TimeGenerated > ago(7d)
    | where OperationName == "Consent to application"
    | extend AppId = tostring(TargetResources[0].id)
    | distinct AppId;
AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(7d)
| where AppId in (SuspiciousApps)
| summarize AccessCount = count(), DistinctUsers = dcount(UserPrincipalName), DistinctIPs = dcount(IPAddress) by AppId, AppDisplayName
| order by AccessCount desc
```

---

## Playbook 2: AiTM Session Replay Detection

### Hypothesis
An attacker deployed a reverse proxy to capture a user's session cookie post-MFA, and is replaying it from a different location.

### Step 1 — Find Successful MFA Followed by Anomalous Token Use
```kql
let TimeWindow = 30m;
SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType == 0
| where AuthenticationRequirement == "multiFactorAuthentication"
| project MFATime = TimeGenerated, UserPrincipalName, MFA_IP = IPAddress, MFA_UserAgent = UserAgent, SessionId = CorrelationId
| join kind=inner (
    AADNonInteractiveUserSignInLogs
    | where TimeGenerated > ago(7d)
    | where ResultType == 0
    | project TokenTime = TimeGenerated, UserPrincipalName, Token_IP = IPAddress, Token_UserAgent = UserAgent
) on UserPrincipalName
| where TokenTime between (MFATime .. (MFATime + TimeWindow))
| where MFA_IP != Token_IP
| project MFATime, TokenTime, UserPrincipalName, MFA_IP, Token_IP, MFA_UserAgent, Token_UserAgent
```

### Step 2 — Detect Impossible Travel
```kql
SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType == 0
| project TimeGenerated, UserPrincipalName, IPAddress, Location = strcat(LocationDetails.city, ", ", LocationDetails.countryOrRegion)
| order by UserPrincipalName, TimeGenerated asc
| serialize
| extend PrevTime = prev(TimeGenerated, 1), PrevLocation = prev(Location, 1), PrevUser = prev(UserPrincipalName, 1)
| where UserPrincipalName == PrevUser
| extend TimeDiffMinutes = datetime_diff('minute', TimeGenerated, PrevTime)
| where TimeDiffMinutes < 60 and Location != PrevLocation and PrevLocation != ""
| project TimeGenerated, UserPrincipalName, Location, PrevLocation, TimeDiffMinutes, IPAddress
```

### Step 3 — Identify Session Cookie Replay Indicators
```kql
SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType == 0
| extend DeviceDetail_Browser = tostring(DeviceDetail.browser)
| extend DeviceDetail_OS = tostring(DeviceDetail.operatingSystem)
| summarize 
    DistinctIPs = dcount(IPAddress),
    IPs = make_set(IPAddress),
    DistinctLocations = dcount(strcat(LocationDetails.city, LocationDetails.countryOrRegion)),
    SignInCount = count()
    by UserPrincipalName, DeviceDetail_Browser, DeviceDetail_OS, bin(TimeGenerated, 1h)
| where DistinctIPs > 2
| order by DistinctIPs desc
```

---

## Playbook 3: Device Code Phishing Detection

### Hypothesis
An attacker tricked a user into entering a device code at microsoft.com/devicelogin, granting the attacker authenticated access.

### Step 1 — Identify Device Code Sign-ins
```kql
SigninLogs
| where TimeGenerated > ago(7d)
| where AuthenticationProtocol == "deviceCode"
| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, ResourceDisplayName, UserAgent, DeviceDetail, Location = LocationDetails
| order by TimeGenerated desc
```

### Step 2 — Baseline Normal Device Code Usage
```kql
SigninLogs
| where TimeGenerated > ago(30d)
| where AuthenticationProtocol == "deviceCode"
| summarize 
    DeviceCodeCount = count(),
    DistinctDays = dcount(format_datetime(TimeGenerated, 'yyyy-MM-dd')),
    Apps = make_set(AppDisplayName)
    by UserPrincipalName
| order by DeviceCodeCount desc
```

### Step 3 — Detect Anomalous Device Code Sign-ins
```kql
let NormalDeviceCodeUsers = 
    SigninLogs
    | where TimeGenerated between (ago(30d) .. ago(7d))
    | where AuthenticationProtocol == "deviceCode"
    | distinct UserPrincipalName;
SigninLogs
| where TimeGenerated > ago(7d)
| where AuthenticationProtocol == "deviceCode"
| where UserPrincipalName !in (NormalDeviceCodeUsers)
| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, UserAgent
| order by TimeGenerated desc
```

### Step 4 — Trace Post-Compromise Activity
```kql
let CompromisedUser = "PLACEHOLDER_UPN";
let CompromiseTime = datetime(2026-01-01T00:00:00Z);
union SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated between (CompromiseTime .. (CompromiseTime + 24h))
| where UserPrincipalName == CompromisedUser
| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, ResourceDisplayName, AuthenticationProtocol, UserAgent
| order by TimeGenerated asc
```
