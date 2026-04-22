## Slide 1: Azure Web Apps Abuse

Module 08 — Remote Code Execution, Managed Identity Exploitation, and Web Shell Detection

**Speaker Notes:**
Welcome to Module 08, the final module. Azure Web Apps (App Service) are fully managed PaaS for web applications. The attack surface spans the application layer (RCE via command injection) and the Azure control plane (managed identity abuse, deployment credential theft). Detection relies on AppServiceHTTPLogs, ConsoleLogs, and AppServiceFileAuditLogs — a rich set of tables that provides visibility into HTTP requests, console output, and file system changes.

## Slide 2: Agenda

- Module Objective and MITRE ATT&CK Mapping
- Web App Attack Surface
- Attack Techniques: RCE, Token Theft, Web Shells
- Critical Environment Variables
- Managed Identity Token Theft
- Enabling Diagnostic Logging
- KQL Detection Queries
- Defender for App Service
- Incident Response (NIST Phases)
- Hardening Controls

**Speaker Notes:**
This module covers the full web app attack chain: fingerprinting and reconnaissance, remote code execution through command injection, environment variable extraction, managed identity token theft, and web shell deployment. The detection tables are comprehensive — AppServiceHTTPLogs captures every HTTP request, ConsoleLogs captures application console output, and FileAuditLogs captures file system modifications. We'll focus on detection queries that identify RCE patterns, suspicious HTTP responses, and managed identity token requests.

## Slide 3: Objective and MITRE Mapping

!layout: Title and Content

**Objective:** Hunt for Azure Web App exploitation including remote code execution, managed identity token theft, authentication token forgery, and web shell deployment.

| Technique | ID | Tactic |
|---|---|---|
| Active Scanning: Vulnerability Scanning | T1595.002 | Reconnaissance |
| Exploit Public-Facing Application | T1190 | Initial Access |
| Command and Scripting Interpreter | T1059 | Execution |
| Unsecured Credentials | T1552.001 | Credential Access |
| Steal Application Access Token | T1528 | Credential Access |
| Valid Accounts: Cloud Accounts | T1078.004 | Persistence |
| Cloud Service Discovery | T1526 | Discovery |
| Server Software Component: Web Shell | T1505.003 | Persistence |

**Speaker Notes:**
Web Apps map to eight MITRE techniques. The attack typically starts with T1595.002 (fingerprinting the app) and T1190 (exploiting a vulnerability for initial code execution). From there, T1059 enables command execution, T1552.001 extracts credentials from environment variables, T1528 steals managed identity tokens, and T1505.003 establishes persistence via web shells. This is one of the most complete attack chains in the course.

## Slide 4: Web App Attack Surface

!layout: Title and Content

**Application layer attacks:**
- Command injection via unsanitized user input (exec(), system(), shell_exec())
- Web shell deployment via Kudu/SCM console or FTP
- Source code disclosure through misconfigured deployment

**Vulnerable functions by language:**

| Language | Dangerous Functions |
|---|---|
| PHP | exec(), system(), shell_exec(), passthru() |
| Python | os.system(), subprocess.call() |
| Node.js | child_process.exec(), child_process.spawn() |
| .NET | Process.Start(), System.Diagnostics.Process |

**Azure platform attacks:**
- Managed identity token theft via IDENTITY_ENDPOINT
- Environment variable extraction (connection strings, subscription IDs)
- Authentication token forgery using WEBSITE_AUTH_SIGNING_KEY

**Speaker Notes:**
The attack surface has two layers: application vulnerabilities (code-level) and Azure platform exploitation. An attacker who achieves RCE through a command injection vulnerability can then access the Azure platform layer — environment variables contain subscription IDs, connection strings, and the managed identity endpoint. The managed identity is the pivot point for lateral movement, just like in Modules 05 and 07. Web shell deployment provides persistent access that survives application redeployments if placed in the right directory.

## Slide 5: Critical Environment Variables

!layout: Title and Content

| Variable | Red Team Value |
|---|---|
| WEBSITE_OWNER_NAME | Subscription ID and resource group |
| WEBSITE_RESOURCE_GROUP | Maps app to resource group |
| IDENTITY_ENDPOINT | URL to local managed identity token service |
| IDENTITY_HEADER | Header value for managed identity token requests |
| WEBSITE_AUTH_SIGNING_KEY | Can forge authentication tokens |
| WEBSITE_AUTH_ENCRYPTION_KEY | Can decrypt authentication data |
| SQLCONNSTR_* | SQL Server connection strings |
| CUSTOMCONNSTR_* | Custom backend connection strings |

**After RCE, attacker runs:** `env` or `printenv` to dump all environment variables — this provides the roadmap for lateral movement.

**Speaker Notes:**
These environment variables are available to any code running in the App Service sandbox. After achieving command injection, the attacker's first command is typically env or printenv to dump the full environment. IDENTITY_ENDPOINT and IDENTITY_HEADER are the keys to managed identity token theft. WEBSITE_AUTH_SIGNING_KEY allows forging authentication tokens, effectively bypassing App Service Authentication. Connection string variables expose database credentials. Emphasize to students that securing the application code is the first line of defense — if RCE is prevented, none of these variables are accessible.

## Slide 6: Managed Identity Token Theft

!layout: Title and Content

**From inside a compromised Web App, the attacker requests managed identity tokens for any Azure resource:**

ARM (Azure management): `resource=https://management.azure.com/`
Graph API: `resource=https://graph.microsoft.com/`
Key Vault: `resource=https://vault.azure.net/`
Storage: `resource=https://storage.azure.com/`

**Request format:**
- `curl "${IDENTITY_ENDPOINT}?resource=https://management.azure.com/&api-version=2019-08-01" -H "X-IDENTITY-HEADER: ${IDENTITY_HEADER}"`

**Detection:** Monitor AADManagedIdentitySignInLogs for sign-ins from unexpected IPs or targeting unexpected resources.

**Speaker Notes:**
This is the same managed identity token theft pattern from Module 05, but in the Web App context. The attacker queries the local IDENTITY_ENDPOINT with different resource URLs to get tokens for ARM, Graph, Key Vault, and Storage. Each token request generates a managed identity sign-in event. If the Web App's managed identity has Contributor on the subscription or Key Vault Secrets User, the attacker inherits those permissions. In the lab, students will see the managed identity sign-in events generated by token theft and correlate them with the original RCE activity.

## Slide 7: Log Tables for Web App Detection

!layout: Title and Content

| Table | What It Captures |
|---|---|
| AppServiceHTTPLogs | Every HTTP request — URI, status code, user agent, response time |
| AppServiceConsoleLogs | Application console output (stdout/stderr) |
| AppServiceAppLogs | Application-level logging (framework logs) |
| AppServiceAuditLogs | Kudu/SCM and FTP access events |
| AppServiceFileAuditLogs | File system changes (create, modify, delete) |
| AppServiceIPSecAuditLogs | IP restriction rule matches |
| AppServicePlatformLogs | Platform-level events (scaling, deployment) |
| AzureActivity | Control plane operations |

**Enable all diagnostic categories** to ensure comprehensive visibility.

**Speaker Notes:**
Web Apps have the richest logging of any Azure service. AppServiceHTTPLogs is the primary table — it captures every HTTP request with response codes, which is how we detect RCE (500 errors with injection patterns). ConsoleLogs captures the output of command execution. FileAuditLogs captures web shell deployment. AuditLogs captures Kudu and FTP access. All these categories must be enabled via diagnostic settings. Without them, you're blind to both the initial exploitation and the follow-on activity.

## Slide 8: KQL — Detect Command Injection (RCE)

!layout: Title and Content

```kql
AppServiceHTTPLogs
| where TimeGenerated > ago(7d)
| where ScStatus >= 500
| where CsUriStem has_any (
    "cmd", "exec", "system",
    "eval", "subprocess"
  )
    or CsUriQuery has_any (
    "$(", "%;", "|", "`",
    "../", "etc/passwd"
  )
| project TimeGenerated, CsHost, CsMethod,
          CsUriStem, CsUriQuery, ScStatus,
          CIp, CsUserAgent, TimeTaken
| order by TimeGenerated desc
```

**What this detects:** HTTP requests with command injection patterns that triggered server errors — likely exploitation attempts.

**Speaker Notes:**
This query catches the initial exploitation. Command injection patterns in URI stems or query strings combined with 500-series status codes indicate the application is processing malicious input. The patterns include shell metacharacters ($(), %;, pipe, backtick), path traversal (../), and direct command references (cmd, exec, system). CIp is the attacker's IP address. CsUserAgent may reveal automated scanning tools. In the lab, students will see these patterns in the HTTP logs and trace them to console output showing command execution.

## Slide 9: KQL — Console Output and HTTP Correlation

!layout: Title and Content

**Detect RCE output in console logs:**
```kql
AppServiceConsoleLogs
| where TimeGenerated > ago(7d)
| where ResultDescription has_any (
    "uid=", "root:", "/bin/sh",
    "IDENTITY_ENDPOINT", "WEBSITE_OWNER",
    "BEGIN CERTIFICATE", "access_token"
  )
| project TimeGenerated, Host,
          ResultDescription
| order by TimeGenerated desc
```

**Detect managed identity token requests:**
```kql
AppServiceHTTPLogs
| where TimeGenerated > ago(7d)
| where CsUriStem has "identity"
    or CsUriQuery has "identity"
| where ScStatus == 200
| project TimeGenerated, CsHost, CsUriStem,
          CsUriQuery, CIp, ScStatus
| order by TimeGenerated desc
```

**Speaker Notes:**
The first query catches command execution output in console logs — uid= and /bin/sh indicate the attacker ran shell commands, IDENTITY_ENDPOINT shows they discovered the managed identity, and access_token shows they successfully stole a token. The second query detects the HTTP request to the managed identity endpoint from within the app. Correlate the timestamps between HTTP logs and console logs to reconstruct the attack timeline: the injection request, the command execution output, and the managed identity token theft.

## Slide 10: KQL — File Changes and FTP/Kudu Access

!layout: Title and Content

**Detect file system changes (web shell deployment):**
```kql
AppServiceFileAuditLogs
| where TimeGenerated > ago(7d)
| where Category == "AppServiceFileAuditLogs"
| project TimeGenerated, OperationName,
          Result, Description
| order by TimeGenerated desc
```

**Detect FTP and Kudu/SCM access:**
```kql
AppServiceAuditLogs
| where TimeGenerated > ago(7d)
| project TimeGenerated, UserAddress,
          UserDisplayName, Protocol,
          ResourceId
| order by TimeGenerated desc
```

**What to investigate:** New files in wwwroot (web shells), FTP access from unexpected IPs, Kudu console access outside deployment windows.

**Speaker Notes:**
FileAuditLogs captures every file creation, modification, and deletion in the app's file system. Web shells — malicious PHP, ASPX, or JSP files — will appear as new file creation events. Correlate the file creation timestamp with the RCE event to confirm web shell deployment. AuditLogs captures FTP and Kudu access — Kudu is the deployment console available at yourapp.scm.azurewebsites.net. Kudu access outside of CI/CD deployment windows is suspicious. FTP access from IPs outside your deployment infrastructure warrants immediate investigation.

## Slide 11: Defender for App Service

!layout: Title and Content

| Alert Category | MITRE Tactic | Examples |
|---|---|---|
| Reconnaissance | Initial Access | Scanning, fingerprinting, version detection |
| Vulnerability exploitation | Execution | Command injection, path traversal, RFI/LFI |
| Web shell detection | Persistence | Known web shell files in wwwroot |
| Suspicious process execution | Execution | Unexpected processes launched by the web app |
| Token theft indicators | Credential Access | Managed identity endpoint access patterns |
| Data exfiltration | Exfiltration | Unusual outbound data volume |
| Dangling DNS | Initial Access | Subdomain takeover vulnerability detected |

**Enable Defender for App Service** for automated detection across all attack phases.

**Speaker Notes:**
Defender for App Service provides comprehensive detection from reconnaissance through exfiltration. The web shell detection is particularly valuable — it identifies known malicious files deployed to the application. The dangling DNS alert detects subdomain takeover vulnerabilities where a custom domain points to a deprovisioned App Service. Enable Defender for App Service at the subscription level and ensure alerts are connected to Sentinel for correlation with other modules.

## Slide 12: Incident Response

!layout: Title and Content

**Containment:**
- Stop the app: `az webapp stop --name <app> --resource-group <rg>`
- Apply IP restrictions to block attacker IP immediately
- Revoke managed identity role assignments to prevent lateral movement
- Revoke deployment credentials (FTP, Kudu)

**Eradication:**
- Remove web shells from wwwroot and all file locations
- Rotate all connection strings and app settings
- Rotate managed identity credentials
- Redeploy from known-good deployment package
- Assign new managed identity if existing one was compromised

**Hardening:**
- Input validation and parameterized queries in application code
- WAF (Web Application Firewall) in front of all public apps
- Private endpoints for App Service
- Disable FTP; restrict Kudu access to VNet
- Managed identity with least-privilege RBAC

**Speaker Notes:**
Stopping the app is the fastest containment action. IP restrictions provide a more surgical approach if you can identify the attacker's IP from HTTP logs. Revoking managed identity role assignments cuts off lateral movement. In eradication, remove ALL files that weren't part of the original deployment — check all directories, not just wwwroot. Redeploy from source control or a known-good package rather than trying to clean the existing deployment. For hardening, WAF is the most impactful control for preventing the initial RCE — it blocks common injection patterns before they reach the application.

## Slide 13: Key Takeaways and References

!layout: Title and Content

- Web Apps have the richest logging of any Azure service — enable all diagnostic categories
- Command injection patterns in HTTP logs combined with 500 errors indicate active exploitation
- Managed identity token theft from Web Apps follows the same pattern as Container Apps and Logic Apps
- Web shells in FileAuditLogs confirm persistent access
- WAF is the most effective control for preventing initial RCE

**References:**
| Resource | Link |
|---|---|
| App Service Security | learn.microsoft.com/azure/app-service/overview-security |
| Defender for App Service | learn.microsoft.com/azure/defender-for-cloud/defender-for-app-service-introduction |
| App Service Diagnostics | learn.microsoft.com/azure/app-service/troubleshoot-diagnostic-logs |
| AppServiceHTTPLogs Schema | learn.microsoft.com/azure/azure-monitor/reference/tables/appservicehttplogs |
| Web Application Firewall | learn.microsoft.com/azure/web-application-firewall/overview |

**Speaker Notes:**
Module 08 completes the course. We've covered the full cloud threat hunting landscape: methodology, phishing, token abuse, Logic Apps, storage, persistence, Key Vault, Container Apps, and Web Apps. The patterns are consistent across all modules: hypothesis-driven hunting, per-table KQL investigation, cross-table correlation, and the hunt loop. Encourage students to take the detection queries and analytics rules from each module back to their environments. Every confirmed finding should become a durable analytics rule.
