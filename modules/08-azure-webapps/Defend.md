# Defend: Azure Web Apps — Diagnostic Settings & Investigation

A guide for configuring Azure App Service diagnostic logging to a Log Analytics Workspace and investigating suspicious activity using KQL.

---

## 1. Enable Diagnostic Logging

### Azure Portal

1. Navigate to your **App Service** in the [Azure Portal](https://portal.azure.com)
2. Select **Monitoring** > **App Service logs**
3. Enable the following:
   - **Application logging** — set to **File System** (or **Blob** for long-term retention)
   - **Web server logging** — set to **File System** or **Storage**
   - **Detailed error messages** — **On**
   - **Failed request tracing** — **On**
4. Select **Save**

### Azure CLI

```bash
# Create a Log Analytics Workspace (if one doesn't exist)
az monitor log-analytics workspace create \
  --resource-group <resource-group> \
  --workspace-name <workspace-name>

# Get the resource IDs
resourceID=$(az webapp show -g <resource-group> -n <app-name> --query id --output tsv)
workspaceID=$(az monitor log-analytics workspace show -g <resource-group> --workspace-name <workspace-name> --query id --output tsv)

# Create diagnostic setting to send all logs to Log Analytics
az monitor diagnostic-settings create \
  --name "AppServiceDiagnostics" \
  --resource "$resourceID" \
  --workspace "$workspaceID" \
  --logs '[
    {"category": "AppServiceHTTPLogs", "enabled": true},
    {"category": "AppServiceConsoleLogs", "enabled": true},
    {"category": "AppServiceAppLogs", "enabled": true},
    {"category": "AppServiceAuditLogs", "enabled": true},
    {"category": "AppServiceIPSecAuditLogs", "enabled": true},
    {"category": "AppServicePlatformLogs", "enabled": true},
    {"category": "AppServiceFileAuditLogs", "enabled": true},
    {"category": "AppServiceAntivirusScanAuditLogs", "enabled": true}
  ]'
```

### PowerShell

```powershell
# Create diagnostic setting
$resourceId = (Get-AzWebApp -ResourceGroupName <resource-group> -Name <app-name>).Id
$workspaceId = (Get-AzOperationalInsightsWorkspace -ResourceGroupName <resource-group> -Name <workspace-name>).ResourceId

Set-AzDiagnosticSetting -ResourceId $resourceId -WorkspaceId $workspaceId -Enabled $true -Name "AppServiceDiagnostics"
```

---

## 2. Log Analytics Tables for App Service

Once diagnostic settings are configured, logs flow into the following tables in your Log Analytics Workspace:

| Table | Description | Availability |
|---|---|---|
| `AppServiceHTTPLogs` | Web server HTTP request logs (method, URI, status code, client IP, user agent) | Windows, Linux, Containers |
| `AppServiceConsoleLogs` | Standard output and standard error from the application | Java SE, Tomcat, Linux, Containers |
| `AppServiceAppLogs` | Application-level logs (traces, errors, warnings) | ASP.NET, Java SE, Tomcat |
| `AppServiceAuditLogs` | Login activity via FTP and Kudu | Windows, Linux, Containers |
| `AppServiceFileAuditLogs` | File changes made to site content (**Premium tier and above**) | Windows, Windows Containers |
| `AppServiceIPSecAuditLogs` | Requests evaluated against IP restriction rules | Windows, Linux, Containers |
| `AppServicePlatformLogs` | Container operation logs (start, stop, pull) | Linux, Containers |
| `AppServiceAntivirusScanAuditLogs` | Antivirus scan logs via Microsoft Defender for Cloud (**Premium tier**) | Windows, Linux, Containers |
| `AppServiceAuthenticationLogs` | Authentication and authorization events | Windows, Linux, Containers |
| `AzureActivity` | Subscription-level control plane operations (create, delete, restart, config changes) | All |

---

## 3. Investigation Queries (KQL)

### Detect Suspicious HTTP Requests

```kusto
// Requests returning 500+ errors — may indicate exploitation attempts
AppServiceHTTPLogs
| where ScStatus >= 500
| project TimeGenerated, CsMethod, CsUriStem, ScStatus, CIp, CsHost, UserAgent
| order by TimeGenerated desc
```

### Identify Command Injection Attempts

```kusto
// Look for common OS command injection patterns in URI stem and query string.
// ScStatus >= 500 is intentionally excluded — successful injections typically return 200.
// URL-encoded variants (%24(, %7C, %60) are included to catch evasion attempts.
AppServiceHTTPLogs
| where TimeGenerated > ago(7d)
| where CsUriStem has_any (
    "cmd", "exec", "system",
    "eval", "subprocess",
    "cmd.exe", "powershell", "whoami",
    "/bin/sh", "/bin/bash"
  )
  or CsUriQuery has_any (
    "$(", "%24(", "%;", "|", "%7C", "`", "%60",
    "../", "etc/passwd", "cmd.exe", "whoami",
    "powershell", "/bin/sh"
  )
| project TimeGenerated, CsHost, CsMethod,
    CsUriStem, CsUriQuery, ScStatus,
    CIp, UserAgent, TimeTaken
| order by TimeGenerated desc
```

### Monitor Console Output for Suspicious Activity

```kusto
// Look for evidence of RCE in console logs
AppServiceConsoleLogs
| where ResultDescription has_any ("uid=", "root", "id=", "whoami", "IDENTITY_ENDPOINT", "MSI_SECRET", "access_token")
| project TimeGenerated, Host, ResultDescription
| order by TimeGenerated desc
```

### Correlate HTTP 500 Errors with Console Logs

```kusto
// Join HTTP errors with console output to find exploitation artifacts
let myHttp = AppServiceHTTPLogs
| where ScStatus == 500
| project TimeGen=substring(TimeGenerated, 0, 19), CsUriStem, ScStatus, CIp;

let myConsole = AppServiceConsoleLogs
| project TimeGen=substring(TimeGenerated, 0, 19), ResultDescription;

myHttp
| join myConsole on TimeGen
| project TimeGen, CsUriStem, ScStatus, CIp, ResultDescription
```

### Detect FTP/Kudu Login Activity

```kusto
// Monitor for unauthorized access via FTP or Kudu (SCM)
AppServiceAuditLogs
| project TimeGenerated, User, UserAddress, Protocol, ResourceName
| order by TimeGenerated desc
```

### Detect File Changes (Premium Tier)

```kusto
// Monitor file modifications — may indicate webshell deployment
AppServiceFileAuditLogs
| where OperationName == "Write" or OperationName == "Create"
| project TimeGenerated, OperationName, Path, Process, UserDisplayName
| order by TimeGenerated desc
```

### Detect Requests Blocked by IP Restrictions

```kusto
// Check IP security rule evaluations
AppServiceIPSecAuditLogs
| where Result == "Denied"
| project TimeGenerated, CIp, CsHost, Details, Result
| summarize Count=count() by CIp, Details
| order by Count desc
```

### Monitor Managed Identity Token Requests (via Console Logs)

```kusto
// Look for token requests to the managed identity endpoint — may indicate token theft
AppServiceConsoleLogs
| where ResultDescription has_any ("IDENTITY_ENDPOINT", "169.254.169.254", "metadata/identity", "oauth2/token", "vault.azure.net", "management.azure.com", "graph.microsoft.com")
| project TimeGenerated, Host, ResultDescription
| order by TimeGenerated desc
```

### Monitor App Configuration Changes (Activity Log)

```kusto
// Track control plane operations on the web app
AzureActivity
| where ResourceProvider == "Microsoft.Web"
| where OperationNameValue has_any ("Microsoft.Web/sites/write", "Microsoft.Web/sites/delete", "Microsoft.Web/sites/config/write", "Microsoft.Web/sites/publishxml/action")
| project TimeGenerated, OperationNameValue, Caller, CallerIpAddress, ActivityStatusValue
| order by TimeGenerated desc
```

### Summary: Log Severity Over Time

```kusto
// Bar chart of app log severities over time
AppServiceAppLogs
| summarize count() by CustomLevel, bin(TimeGenerated, 1h), _ResourceId
| render barchart
```

---

## 4. Alert Rules to Configure

| Alert | Table | Condition |
|---|---|---|
| High rate of 500 errors | `AppServiceHTTPLogs` | `ScStatus >= 500` count > threshold in 5 min |
| Command injection patterns in URIs | `AppServiceHTTPLogs` | URI contains `$(`, `` ` ``, `&&`, `\|` |
| FTP/Kudu login from unknown IP | `AppServiceAuditLogs` | `UserAddress` not in allowed list |
| File modifications outside deployments | `AppServiceFileAuditLogs` | `Write` or `Create` operations outside deploy windows |
| Managed identity token scraping | `AppServiceConsoleLogs` | Output contains `IDENTITY_ENDPOINT`, `oauth2/token` |
| IP restriction denials spike | `AppServiceIPSecAuditLogs` | `Result == "Denied"` count > threshold |

---

## 5. Microsoft Defender for Cloud — App Service Protection

### Overview

**Microsoft Defender for App Service** is a cloud-native workload protection plan within Microsoft Defender for Cloud that detects attacks targeting applications running on Azure App Service. It monitors:

- The VM instance running your App Service and its management interface
- Requests and responses sent to/from your App Service apps
- Underlying sandboxes and VMs
- App Service internal logs

### Enable Defender for App Service

#### Azure Portal

1. Open **Microsoft Defender for Cloud** in the Azure Portal
2. Navigate to **Environment Settings** > select your subscription
3. Under **Defender plans**, enable **App Service**
4. Select **Save**

#### Azure CLI

```bash
az security pricing create --name AppServices --tier Standard
```

### Threat Detection by MITRE ATT&CK Tactic

| MITRE Tactic | What Defender Detects |
|---|---|
| **Pre-attack** | Vulnerability scanner execution (Nessus, Qualys, etc.) probing for weaknesses |
| **Initial Access** | Connections from known malicious IPs to FTP interface; exploitation of known vulnerabilities |
| **Execution** | High-privilege command attempts; Linux commands on Windows App Service; fileless attacks; crypto mining tools |
| **Persistence** | Web shell deployment and invocation |
| **Command & Control** | Communication with suspicious or known malicious domains |

### Key Defender for App Service Alerts

| Alert Name | Severity | Description |
|---|---|---|
| Attempt to run Linux commands on a Windows App Service | Medium | Detected attempt to run Linux commands on a Windows-based App Service |
| Phishing content hosted on Azure Webapps | Medium | URL used in phishing attack found on the App Service website |
| An attempt to run high privilege command detected | Medium | Suspicious process detected attempting to run elevated commands |
| Web shell detected | High | Potential malicious web shell detected on the App Service |
| Suspicious download using Certutil detected | Medium | Download of suspicious files by certutil.exe |
| Known malicious IP connected to FTP interface | High | Connection from a known malicious IP to the App Service FTP endpoint |
| Dangling DNS record detected | High | DNS entry points to a decommissioned App Service — subdomain takeover risk |
| Vulnerability scanner detected | Medium | Known vulnerability scanner (e.g., Nessus, Qualys) targeting the App Service |
| Digital currency mining detected | High | Crypto mining activity detected on the App Service host |
| Suspicious PHP execution detected | Medium | Suspicious PHP execution indicating a possible web shell or malicious code |
| Raw data download detected | Medium | App Service process performed an unusual raw data download |

> **Full alerts list:** [Alerts for Azure App Service](https://learn.microsoft.com/azure/defender-for-cloud/alerts-azure-app-service)

### Simulating an App Service Alert (Testing)

To validate that Defender is working:

1. Create or use an existing App Service website
2. Wait 24 hours for it to register with Defender for Cloud (or use an existing site)
3. Browse to: `https://<app-name>.azurewebsites.net/This_Will_Generate_ASC_Alert`
4. An alert should appear within 2–4 hours

### Responding to Alerts

1. View alerts: **Defender for Cloud** > **Security alerts**
2. Investigate the alert details, affected resource, and MITRE tactic mapping
3. Follow the remediation steps provided
4. Export alerts to SIEM, email, or Logic Apps via **Continuous Export**

---

## 6. Microsoft Learn References

| # | Reference | What It Covers |
|---|---|---|
| 1 | [AppServiceHTTPLogs table schema — Azure Monitor Reference](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/appservicehttplogs) | Authoritative column definitions for `AppServiceHTTPLogs`, including `CsUriStem`, `CsUriQuery`, `ScStatus`, `CIp`, `UserAgent`, and `TimeTaken`. Required for writing accurate KQL against HTTP request logs. |
| 2 | [Azure App Service monitoring data reference](https://learn.microsoft.com/en-us/azure/app-service/monitor-app-service-reference) | Full reference for all App Service resource log categories (`AppServiceHTTPLogs`, `AppServiceConsoleLogs`, `AppServiceAuditLogs`, `AppServiceFileAuditLogs`, `AppServiceIPSecAuditLogs`, `AppServiceAntivirusScanAuditLogs`, etc.), their supported platforms (Windows/Linux/Containers), and the Log Analytics tables they populate. |
| 3 | [Monitor Azure App Service](https://learn.microsoft.com/en-us/azure/app-service/monitor-app-service) | Explains how to configure diagnostic settings to route App Service logs into a Log Analytics Workspace, recommended KQL query patterns for `AppServiceHTTPLogs` and `AppServiceConsoleLogs`, and how to correlate HTTP 500 errors with console output. |
| 4 | [Microsoft Defender for App Service — Overview](https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-app-service-introduction) | Covers what Defender for App Service detects (MITRE ATT&CK: Pre-attack through C2), how it uses internal App Service logs and infrastructure telemetry, dangling DNS detection, and prerequisites for enabling the plan on a subscription. |
