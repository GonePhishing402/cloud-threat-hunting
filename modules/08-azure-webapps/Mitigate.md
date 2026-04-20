# Mitigate: Azure Web Apps — Incident Response Playbook

This playbook follows the **NIST SP 800-61** incident response lifecycle: **Preparation → Detection & Analysis → Containment → Eradication & Recovery → Post-Incident Activity**.

---

## Phase 1 — Preparation

### Prerequisites

- **Diagnostic logging** enabled and sending to Log Analytics (all `AppService*` log categories)
- **Microsoft Defender for App Service** enabled on the subscription
- **Microsoft Sentinel** connected to the Log Analytics workspace (optional — for automated playbooks)
- App Service running on **Premium tier or above** for `AppServiceFileAuditLogs`
- RBAC enforced — KuduPublish and FTP credentials restricted to authorized users only
- **Managed identity** role assignments reviewed and scoped to principle of least privilege

### Runbooks to Prepare

| Runbook | Purpose |
|---|---|
| Stop the web app | Immediately halt execution of a compromised app |
| Rotate connection strings | Invalidate exfiltrated database credentials |
| Remove/rotate managed identity | Block downstream Azure resource access |
| Remove web shell | Delete discovered web shell files from `wwwroot` |
| Re-deploy from clean package | Restore app from a known-good build artifact |

---

## Phase 2 — Detection & Analysis

### Investigate in Microsoft Defender for Cloud

1. Navigate to **Microsoft Defender for Cloud** > **Security alerts**
2. Filter by **Resource type**: `App Service`
3. Review alert severity, MITRE tactic mapping, and affected resource details
4. Click **View full details** to see the evidence, process tree, and recommended remediation steps

### Investigate in Microsoft Defender XDR

1. Navigate to [Microsoft Defender XDR](https://security.microsoft.com) > **Incidents & Alerts**
2. Filter by **Product name**: `Microsoft Defender for Cloud`
3. Open the incident — examine the incident graph for:
   - App Service entities and related process execution chains
   - Web shell invocation behaviors
   - Managed identity token requests to IMDS
   - Outbound connections to suspicious domains (C2 indicators)
4. Use the **Timeline** view on the affected resource to see all behaviors chronologically

### KQL Investigation Queries — Log Analytics

```kusto
// Identify command injection patterns in HTTP URIs
AppServiceHTTPLogs
| where CsUriStem has_any ("$(", "%24(", "`", "whoami", "/etc/passwd", "cmd.exe", "powershell")
| project TimeGenerated, CsMethod, CsUriStem, ScStatus, CIp, UserAgent
| order by TimeGenerated desc
```

```kusto
// Check console logs for RCE evidence (env variable disclosure, token theft)
AppServiceConsoleLogs
| where ResultDescription has_any ("uid=", "IDENTITY_ENDPOINT", "access_token", "oauth2/token", "MSI_SECRET")
| project TimeGenerated, Host, ResultDescription
| order by TimeGenerated desc
```

```kusto
// Web shell — look for Create/Write operations to wwwroot
AppServiceFileAuditLogs
| where OperationName in ("Write", "Create")
| where Path has "wwwroot"
| project TimeGenerated, OperationName, Path, Process, UserDisplayName
| order by TimeGenerated desc
```

```kusto
// FTP/Kudu login activity from unexpected IPs
AppServiceAuditLogs
| project TimeGenerated, User, UserAddress, Protocol, ResourceName
| order by TimeGenerated desc
```

```kusto
// Control plane changes (app stops, config writes, deployment)
AzureActivity
| where ResourceProvider == "Microsoft.Web"
| where OperationNameValue has_any ("Microsoft.Web/sites/write", "Microsoft.Web/sites/config/write", "Microsoft.Web/sites/stop/action", "Microsoft.Web/sites/publishxml/action")
| project TimeGenerated, OperationNameValue, Caller, CallerIpAddress, ActivityStatusValue
| order by TimeGenerated desc
```

```kusto
// Managed identity token requests via console output
AppServiceConsoleLogs
| where ResultDescription has_any ("169.254.169.254", "metadata/identity", "vault.azure.net", "management.azure.com", "graph.microsoft.com")
| project TimeGenerated, Host, ResultDescription
| order by TimeGenerated desc
```

---

## Phase 3 — Containment

### Option A — Stop the Web App

Immediately halt the app to prevent active exploitation:

```bash
# Stop the web app
az webapp stop --name <app-name> --resource-group <resource-group>

# Verify the app is stopped
az webapp show --name <app-name> --resource-group <resource-group> --query state
```

```powershell
Stop-AzWebApp -Name <app-name> -ResourceGroupName <resource-group>
```

### Option B — Block Source IP via Access Restrictions

If the exploit is coming from a known IP, add an IP restriction rule to block it without stopping the app:

```bash
# Add a deny rule for the attacking IP
az webapp config access-restriction add \
  --name <app-name> \
  --resource-group <resource-group> \
  --rule-name "BlockAttacker" \
  --action Deny \
  --ip-address <attacker-ip>/32 \
  --priority 100
```

### Option C — Revoke Managed Identity Role Assignments

If managed identity tokens were stolen, immediately remove the identity's role assignments to block downstream access:

```bash
# List role assignments for the managed identity
az role assignment list \
  --assignee <managed-identity-object-id> \
  --output table

# Remove a specific role assignment
az role assignment delete \
  --assignee <managed-identity-object-id> \
  --role "<role-name>" \
  --scope <scope>
```

### Option D — Revoke Deployment Credentials

If FTP or Kudu credentials were compromised:

```bash
# Reset the publishing credentials for the web app
az webapp deployment user set \
  --user-name <new-username> \
  --password <new-strong-password>
```

### Option E — Automated Containment via Sentinel Playbook

If Microsoft Sentinel is configured, trigger a playbook to:
1. Stop the web app via Azure Resource Manager API
2. Send an alert notification to the security team
3. Create an incident ticket and begin the approval workflow for recovery

Reference: [Sentinel Playbooks — Tutorial: Respond to Threats](https://learn.microsoft.com/azure/sentinel/tutorial-respond-threats-playbook)

---

## Phase 4 — Eradication & Recovery

### Remove Web Shell

```bash
# Use Kudu REST API to delete a suspicious file
# List files in wwwroot
curl -u "<username>:<password>" \
  "https://<app-name>.scm.azurewebsites.net/api/vfs/site/wwwroot/"

# Delete the web shell file
curl -u "<username>:<password>" -X DELETE \
  "https://<app-name>.scm.azurewebsites.net/api/vfs/site/wwwroot/<webshell.php>"
```

### Rotate Connection Strings

```bash
# Update a connection string in the App Service configuration
az webapp config connection-string set \
  --name <app-name> \
  --resource-group <resource-group> \
  --connection-string-type SQLAzure \
  --settings "MyDb=<new-connection-string>"
```

### Rotate App Settings (Secrets in Environment Variables)

```bash
# Update a compromised app setting
az webapp config appsettings set \
  --name <app-name> \
  --resource-group <resource-group> \
  --settings "MY_SECRET=<new-value>"
```

### Redeploy from a Known-Good Build Artifact

```bash
# Deploy a clean ZIP package
az webapp deploy \
  --name <app-name> \
  --resource-group <resource-group> \
  --src-path <path-to-clean.zip> \
  --type zip

# Restart the app after deployment
az webapp restart --name <app-name> --resource-group <resource-group>
```

### Assign a New Managed Identity (if old one was compromised)

```bash
# Disable the current system-assigned managed identity
az webapp identity remove \
  --name <app-name> \
  --resource-group <resource-group> \
  --identities [system]

# Re-enable to generate a new identity with new credentials
az webapp identity assign \
  --name <app-name> \
  --resource-group <resource-group>

# Re-apply required role assignments to the new identity
az role assignment create \
  --assignee <new-managed-identity-object-id> \
  --role "<role-name>" \
  --scope <scope>
```

---

## Phase 5 — Post-Incident Activity

### Hardening Checklist

| Control | Action |
|---|---|
| **Input validation** | Sanitize all user inputs; avoid passing user data to shell commands (`exec`, `system`, `Popen`) |
| **Secrets management** | Move all secrets to Azure Key Vault; remove hardcoded values and environment variable secrets |
| **Managed identity** | Apply least-privilege role assignments; remove unused identities |
| **Authentication keys** | Rotate `WEBSITE_AUTH_SIGNING_KEY` and `WEBSITE_AUTH_ENCRYPTION_KEY` after any suspected compromise |
| **FTP/Kudu access** | Disable FTP if not required (`az webapp config set --ftps-state Disabled`); restrict Kudu to Azure IP ranges |
| **IP restrictions** | Implement access restrictions for SCM (Kudu) endpoint — allow only CI/CD service IPs |
| **Network isolation** | Deploy in a VNet-integrated environment; restrict outbound egress to allow-listed endpoints |
| **Logging** | Verify all `AppService*` log categories are enabled in diagnostic settings |
| **File audit logs** | Upgrade to Premium tier to enable `AppServiceFileAuditLogs` for web shell detection |
| **Defender for App Service** | Ensure Defender plan is set to **Standard** on the subscription |
| **Subdomain takeover** | Audit DNS records for decommissioned apps; remove dangling CNAMEs immediately |
| **HTTPS only** | Enforce HTTPS-only (`az webapp update --https-only true`) |

### Lessons-Learned Document

Capture the following within 72 hours:
1. Timeline of events (first indicator → containment → recovery)
2. MITRE ATT&CK techniques observed
3. How the initial access was achieved (injectable parameter, FTP, Kudu, CI/CD)
4. Data potentially exfiltrated (env vars, connection strings, managed identity tokens)
5. Gaps in logging or detection (what was missed and why)
6. Changes made to hardening controls
7. Updated runbooks and playbooks for future response

---

## Microsoft Learn References
- [Incident Response Overview for Azure](https://learn.microsoft.com/azure/security/fundamentals/incident-response-overview)
- [Defender for App Service Overview](https://learn.microsoft.com/azure/defender-for-cloud/defender-for-app-service-introduction)
- [Alerts for Azure App Service](https://learn.microsoft.com/azure/defender-for-cloud/alerts-azure-app-service)
- [Manage and Respond to Security Alerts](https://learn.microsoft.com/azure/defender-for-cloud/manage-respond-alerts)
- [Tutorial: Respond to Threats with Sentinel Playbooks](https://learn.microsoft.com/azure/sentinel/tutorial-respond-threats-playbook)
- [Azure Automation Overview](https://learn.microsoft.com/azure/automation/overview)
- [Secure Your Azure App Service Deployment](https://learn.microsoft.com/azure/app-service/overview-security)
- [Configure Access Restrictions for App Service](https://learn.microsoft.com/azure/app-service/app-service-ip-restrictions)
- [Managed Identities for App Service](https://learn.microsoft.com/azure/app-service/overview-managed-identity)
- [Prevent Dangling DNS Entries and Subdomain Takeover](https://learn.microsoft.com/azure/security/fundamentals/subdomain-takeover)
- [NIST SP 800-61 Computer Security Incident Handling Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf)
