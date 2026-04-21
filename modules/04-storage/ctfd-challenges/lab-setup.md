# Module 04 — Storage Blob Hunt CTF : Lab Setup (ADX)

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
2. Name it `StorageHunt`
3. Click **Create**

---

## Step 3 — Create the Tables

Open the query editor, make sure `StorageHunt` is selected as the active database, then run the following commands **one at a time** (select each block and press **Run**).

### StorageBlobLogs

```kusto
.create-merge table StorageBlobLogs (
    TimeGenerated:datetime, Type:string,
    AccountName:string, AuthenticationType:string,
    CallerIpAddress:string, Category:string,
    ClientRequestId:string, CorrelationId:string,
    DurationMs:long, ObjectKey:string,
    OperationName:string, OperationVersion:string,
    Protocol:string, RequestBodySize:long,
    RequesterObjectId:string, RequesterUpn:string,
    ResponseBodySize:long, ServerLatencyMs:long,
    ServiceType:string, StatusCode:int,
    StatusText:string, TenantId:string,
    TlsVersion:string, Uri:string,
    UserAgentHeader:string
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
.ingest into table StorageBlobLogs
  ('https://raw.githubusercontent.com/GonePhishing402/cloud-threat-hunting/main/modules/04-storage/emulated-data/StorageBlobLogs.json')
  with (format='multijson')
```

```kusto
.ingest into table SecurityAlert
  ('https://raw.githubusercontent.com/GonePhishing402/cloud-threat-hunting/main/modules/04-storage/emulated-data/SecurityAlert.json')
  with (format='multijson')
```

---

## Step 5 — Verify the Data

Run this row-count check to confirm all records loaded correctly:

```kusto
union
  (StorageBlobLogs | count | extend Table="StorageBlobLogs"),
  (SecurityAlert   | count | extend Table="SecurityAlert")
| project Table, Count
```

Expected output:

| Table | Count |
|---|---|
| StorageBlobLogs | 20 |
| SecurityAlert | 4 |

If any count is 0, re-run the corresponding `.ingest` command from Step 4.

---

## Step 6 — Start the CTF

Open [challenges.md](challenges.md) and work through the challenges using your ADX database as the data source.

All KQL starting points in `challenges.md` are written for ADX and will run as-is against the `StorageHunt` database.

---

## Troubleshooting

| Issue | Fix |
|---|---|
| `.ingest` returns an error about permissions | Make sure you are querying the correct database (`StorageHunt`) and that you created the table first in Step 3 |
| Table exists but returns 0 rows after ingest | Ingestion on the free cluster can take up to 60 seconds — wait and re-run the count query |
| `.create-merge table` fails with "column type mismatch" | The table already exists with a different schema — run `.drop table <TableName>` then re-run the create command |
| `parse_json()` returns null on `ExtendedProperties` | The field is stored as a JSON string — make sure you call `parse_json()` before accessing nested keys with bracket notation |
