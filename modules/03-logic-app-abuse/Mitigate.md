# Mitigate - Module 03 (Logic App Abuse)

## Immediate Incident Response Steps

1. **Disable the compromised workflow** to stop any active exfiltration or adversary-triggered runs:
   ```bash
   az logic workflow update \
     --resource-group <rg-name> \
     --name <workflow-name> \
     --state Disabled
   ```

2. **Revoke unauthorized RBAC assignments** on the Logic App and its resource group:
   ```bash
   az role assignment delete \
     --assignee <attacker-principal-id> \
     --role "Logic App Contributor" \
     --scope /subscriptions/<sub>/resourceGroups/<rg>
   ```

3. **Invalidate all existing trigger SAS URLs** by deleting and recreating the trigger (the new trigger will have a new `sig=` token; any exfiltrated URLs become invalid):
   ```bash
   # For Consumption Logic Apps, delete the trigger via portal or ARM
   # Then re-save the workflow definition to regenerate the trigger
   az logic workflow update \
     --resource-group <rg-name> \
     --name <workflow-name> \
     --definition @clean-workflow.json
   ```

4. **Review run history** in the Azure portal to determine scope of exfiltration — specifically the inputs and outputs of each action in affected runs.

5. **Rotate any secrets** referenced by the workflow (connection strings, API keys, storage account keys) that may have been exposed.

---

## Hardening: Store Secrets in Azure Key Vault

### Why This Matters

Hardcoded connection strings and API keys in workflow definitions are exposed in the JSON definition, visible in run history, and persist after a workflow clone or ARM template export. Storing secrets in **Azure Key Vault** and referencing them from Logic App parameters eliminates the secret from the workflow definition entirely.

### How to Reference Key Vault Secrets from Logic App Parameters

**Step 1 — Create a parameter in your Logic App** (in the workflow parameters tab or ARM template):

```json
"$parameters": {
  "ApiKey": {
    "defaultValue": "",
    "type": "SecureString"
  }
}
```

**Step 2 — Link the parameter to a Key Vault secret** in the Logic App resource configuration. In the ARM template, use the `@Microsoft.KeyVault()` expression in the parameters section:

```json
"parameters": {
  "ApiKey": {
    "value": "@Microsoft.KeyVault(SecretUri=https://<vault-name>.vault.azure.net/secrets/<secret-name>/)"
  }
}
```

**Step 3 — Reference the parameter in workflow actions** instead of hardcoding:

```json
"inputs": {
  "headers": {
    "Authorization": "Bearer @{parameters('ApiKey')}"
  }
}
```

**Step 4 — Grant the Logic App's managed identity** `Key Vault Secrets User` on the vault (not full Contributor). This is the minimum permission needed to read secret values:

```bash
az role assignment create \
  --assignee <logic-app-managed-identity-principal-id> \
  --role "Key Vault Secrets User" \
  --scope /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.KeyVault/vaults/<vault-name>
```

> Do **not** grant `Key Vault Contributor` — this allows the managed identity to modify vault access policies and escalate.

---

## Hardening: Enable Secure Inputs and Outputs

### Why This Matters

By default, Logic App **run history** shows the full inputs and outputs of every action. If a workflow retrieves a Key Vault secret, queries a database, or processes PII, those values are visible to anyone with read access to the Logic App resource — including attackers who have read-only RBAC. Enabling **Secure Inputs** and **Secure Outputs** replaces the content in run history with `[Content is obfuscated]`.

### How to Enable via Portal

1. Open the Logic App workflow in the **designer**.
2. Click the action or trigger whose data you want to protect.
3. Click the **ellipsis (...)** menu → **Settings**.
4. Under the **Security** section, toggle **Secure Inputs** and/or **Secure Outputs** to **On**.
5. Save the workflow.

### How to Enable via ARM Template / Workflow JSON

Add the `runtimeConfiguration` property to the action or trigger definition:

```json
"Retrieve_Secret": {
  "type": "ApiConnection",
  "inputs": {
    "host": {"connection": {"name": "@parameters('$connections')['keyvault']['connectionId']"}},
    "method": "get",
    "path": "/secrets/MyApiKey/value"
  },
  "runtimeConfiguration": {
    "secureData": {
      "properties": ["inputs", "outputs"]
    }
  }
}
```

### Which Actions Should Always Have Secure Inputs/Outputs Enabled

| Action Type | Enable Secure Inputs | Enable Secure Outputs |
|---|---|---|
| HTTP action calling internal APIs with bearer tokens | ✅ | ✅ |
| Key Vault connector (Get Secret) | N/A | ✅ (hides secret value in history) |
| Parse JSON / Compose with PII fields | ✅ | ✅ |
| Send Email / Teams message with sensitive body | N/A | ✅ |
| Initialize Variable with secrets | ✅ | ✅ |

---

## Hardening: Additional Controls

### Least-Privilege RBAC

- Assign **Logic App Operator** (not Contributor) to users who only need to enable/disable or trigger runs.
- Reserve **Logic App Contributor** for the DevOps pipeline service principal that deploys workflows, not for individuals.
- Use **Azure Resource Lock** on production Logic Apps to prevent accidental modification or deletion:
  ```bash
  az lock create \
    --name "protect-production-workflow" \
    --resource-group <rg-name> \
    --resource-name <workflow-name> \
    --resource-type Microsoft.Logic/workflows \
    --lock-type CanNotDelete
  ```

### Trigger URL Access Restriction

Restrict which IP addresses can invoke HTTP-triggered workflows by configuring allowed inbound IP ranges:

1. In the Azure portal, open the Logic App → **Settings** → **Workflow settings**.
2. Under **Access control configuration**, set **Allowed inbound IP addresses** to only the expected caller IP ranges.
3. For production integrations, prefer **managed identity** or **service-to-service authentication** over SAS-signed callback URLs.

### Managed Identity > Connection Strings

Always prefer **system-assigned or user-assigned managed identity** for connector authentication. Managed identity tokens are short-lived, never stored in workflow definitions, and automatically rotated. Replace any connector that uses stored credentials (username/password or API key) with a managed identity equivalent.

---

## Verification Checklist Post-Incident

- [ ] Disabled workflow shows no new runs in run history.
- [ ] All unauthorized RBAC assignments on Logic App and resource group are removed.
- [ ] Trigger SAS URLs have been regenerated; old URLs return 403.
- [ ] All secrets referenced by the workflow have been rotated in Key Vault.
- [ ] Secure Inputs / Secure Outputs are enabled on all sensitive actions.
- [ ] AzureActivity alerts fire on the next `Microsoft.Logic/workflows/write` event.

---

## Microsoft Learn References

- Secure access and data for workflows (Key Vault parameters, secure inputs/outputs, IP restrictions): https://learn.microsoft.com/azure/logic-apps/logic-apps-securing-a-logic-app
- Secure data in run history by using obfuscation: https://learn.microsoft.com/azure/logic-apps/logic-apps-securing-a-logic-app#secure-data-in-run-history-by-using-obfuscation
- Secure inputs and outputs in the designer: https://learn.microsoft.com/azure/logic-apps/logic-apps-securing-a-logic-app#secure-inputs-and-outputs-in-the-designer
- Authenticate with managed identity: https://learn.microsoft.com/azure/logic-apps/authenticate-with-managed-identity
- Key Vault overview: https://learn.microsoft.com/azure/key-vault/general/overview
- Azure Logic Apps built-in RBAC roles: https://learn.microsoft.com/azure/role-based-access-control/built-in-roles#logic-app-contributor
