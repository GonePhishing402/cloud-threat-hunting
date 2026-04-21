# Module 06 — Key Vault Hunt CTF : Lab Setup (ADX)

This guide walks you through creating a free Azure Data Explorer (ADX) cluster, creating the two tables used in this module, and ingesting the emulated log data directly from GitHub. Once complete, you can run all CTF challenge queries against the live ADX database.

---

## Prerequisites

- A Microsoft account (personal or work/school)
- A browser — no local tooling required

---

## Step 1 — Create a Free ADX Cluster

1. Go to **https://dataexplorer.azure.com**
2. Sign in with your Microsoft account
3. In the left panel, click **+ Create cluster**
4. Select **Free cluster (no Azure subscription required)**
5. Give the cluster any name (e.g., `cloudhunt`)
6. Click **Create**

> The free cluster provisions in ~30 seconds. It supports up to 100 GB of data and all standard KQL query capabilities.

---

## Step 2 — Create a Database

1. Once the cluster is ready, click **+ Add database**
2. Name it `KeyVaultHunt`
3. Click **Create**

---

## Step 3 — Create the Tables

Open the query editor, make sure `KeyVaultHunt` is selected as the active database, then run the following commands **one at a time** (select each block and press **Run**).

### AzureDiagnostics

> Key Vault audit events land in `AzureDiagnostics` with `ResourceType == "VAULTS"` and `Category == "AuditEvent"`. The Key Vault-specific fields use the `_s`, `_g`, and `_b` suffix conventions that the Azure Diagnostics pipeline appends.

```kusto
.create-merge table AzureDiagnostics (
    TimeGenerated:datetime, Type:string,
    ResourceProvider:string, ResourceType:string,
    Resource:string, ResourceGroup:string,
    _ResourceId:string, SubscriptionId:string,
    Category:string, OperationName:string,
    ResultType:string, ResultSignature:string,
    DurationMs:long, CallerIPAddress:string,
    CorrelationId:string, Level:string,
    identity_claim_oid_g:guid, identity_claim_appid_g:guid,
    identity_claim_upn_s:string, requestUri_s:string,
    id_s:string, isAccessPolicyMatch_b:bool,
    TenantId:string
)
```

### SecurityAlert

```kusto
.create-merge table SecurityAlert (
    TimeGenerated:datetime, Type:string,
    AlertName:string, AlertSeverity:string,
    AlertType:string, CompromisedEntity:string,
    ConfidenceLevel:string, Description:string,
    DisplayName:string, EndTime:datetime,
    StartTime:datetime, Entities:string,
    ExtendedProperties:string, IsIncident:bool,
    ProductComponentName:string, ProductName:string,
    ProviderName:string, RemediationSteps:string,
    ResourceId:string, Status:string,
    SubTechniques:string, SystemAlertId:string,
    Tactics:string, Techniques:string,
    VendorName:string, VendorOriginalId:string,
    WorkspaceResourceGroup:string, WorkspaceSubscriptionId:string
)
```

---

## Step 4 — Ingest the Emulated Data

Run each ingest command individually. Wait for the previous one to show **Completed** before running the next.

```kusto
.ingest into table AzureDiagnostics
  ('https://raw.githubusercontent.com/GonePhishing402/cloud-threat-hunting/main/modules/06-keyvault/emulated-data/AzureDiagnostics.json')
  with (format='multijson')
```

```kusto
.ingest into table SecurityAlert
  ('https://raw.githubusercontent.com/GonePhishing402/cloud-threat-hunting/main/modules/06-keyvault/emulated-data/SecurityAlert.json')
  with (format='multijson')
```

---

## Step 5 — Verify the Data

Run this row-count check to confirm all records loaded correctly:

```kusto
union
  (AzureDiagnostics | count | extend Table="AzureDiagnostics"),
  (SecurityAlert    | count | extend Table="SecurityAlert")
| project Table, Count
```

Expected output:

| Table | Count |
|---|---|
| AzureDiagnostics | 7 |
| SecurityAlert | 2 |

If any count is 0, re-run the corresponding `.ingest` command from Step 4.

---

## Step 6 — Start the CTF

Open [challenges.md](challenges.md) and work through the challenges using your ADX database as the data source.

All KQL starting points in `challenges.md` are written for ADX and will run as-is against the `KeyVaultHunt` database.

---

## Troubleshooting

| Issue | Fix |
|---|---|
| `.ingest` returns an error about permissions | Make sure you are querying the correct database (`KeyVaultHunt`) and that you created the table first in Step 3 |
| Table exists but returns 0 rows after ingest | Ingestion on the free cluster can take up to 60 seconds — wait and re-run the count query |
| `.create-merge table` fails with "column type mismatch" | The table already exists with a different schema — run `.drop table <TableName>` then re-run the create command |
| `_ResourceId` column name causes a parse error | ADX treats leading underscores as valid — use backtick quoting if needed: `` [`_ResourceId`] `` |
| `parse_json()` returns null on `ExtendedProperties` | The field is stored as a JSON string — make sure you call `parse_json()` before accessing nested keys with bracket notation |
| `identity_claim_oid_g` returns empty | This field is a `guid` type — compare with `tostring()` if joining against a string field from another table |
