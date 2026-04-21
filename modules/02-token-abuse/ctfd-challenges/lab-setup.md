# Module 02 — Token Abuse CTF : Lab Setup (ADX)

This guide walks you through creating a free Azure Data Explorer (ADX) cluster, creating the five tables used in this module, and ingesting the emulated log data directly from GitHub. Once complete, you can run all CTF challenge queries against the live ADX database.

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
2. Name it `TokenAbuseHunt`
3. Click **Create**

---

## Step 3 — Create the Tables

Open the query editor, make sure `TokenAbuseHunt` is selected as the active database, then run the following commands **one at a time** (select each block and press **Run**).

### SigninLogs

```kusto
.create-merge table SigninLogs (
    TimeGenerated:datetime, Type:string, TenantId:string,
    UserPrincipalName:string, UserDisplayName:string, UserId:string,
    AppDisplayName:string, AppId:string,
    ResourceDisplayName:string, ResourceIdentity:string,
    IPAddress:string, IsInteractive:bool,
    ResultType:int, ResultDescription:string,
    AuthenticationRequirement:string, AuthenticationProtocol:string,
    ClientAppUsed:string, UserAgent:string,
    DeviceDetail:dynamic, LocationDetails:dynamic,
    ConditionalAccessStatus:string, MfaDetail:dynamic,
    SessionId:string, CorrelationId:string,
    UniqueTokenIdentifier:string, IncomingTokenType:string
)
```

### AADNonInteractiveUserSignInLogs

```kusto
.create-merge table AADNonInteractiveUserSignInLogs (
    TimeGenerated:datetime, Type:string, TenantId:string,
    UserPrincipalName:string, UserDisplayName:string, UserId:string,
    AppDisplayName:string, AppId:string,
    ResourceDisplayName:string, ResourceIdentity:string,
    IPAddress:string, IsInteractive:bool,
    ResultType:int, ResultDescription:string,
    AuthenticationRequirement:string, AuthenticationProtocol:string,
    ClientAppUsed:string, UserAgent:string,
    DeviceDetail:dynamic, LocationDetails:dynamic,
    ConditionalAccessStatus:string,
    SessionId:string, CorrelationId:string,
    UniqueTokenIdentifier:string, IncomingTokenType:string
)
```

### AzureActivity

```kusto
.create-merge table AzureActivity (
    TimeGenerated:datetime, Type:string, TenantId:string,
    SubscriptionId:string, Caller:string,
    OperationName:string, OperationNameValue:string,
    ResourceGroup:string, ResourceId:string,
    ActivityStatus:string, ActivityStatusValue:string,
    CategoryValue:string, CorrelationId:string,
    Properties:dynamic, HTTPRequest:dynamic
)
```

### MicrosoftGraphActivityLogs

```kusto
.create-merge table MicrosoftGraphActivityLogs (
    TimeGenerated:datetime, Type:string, TenantId:string,
    UserId:string, UserPrincipalName:string,
    AppId:string, IPAddress:string,
    RequestUri:string, RequestMethod:string,
    ResponseStatusCode:int, ResponseSizeBytes:int,
    DurationMs:int, UniqueTokenIdentifier:string,
    CorrelationId:string, UserAgent:string,
    Roles:dynamic, Scopes:dynamic
)
```

### CloudAppEvents

```kusto
.create-merge table CloudAppEvents (
    TimeGenerated:datetime, Type:string, TenantId:string,
    AccountObjectId:string, AccountDisplayName:string,
    AccountId:string, IPAddress:string,
    Application:string, ActionType:string,
    ObjectType:string, ObjectName:string, ObjectId:string,
    ActivityObjects:dynamic, RawEventData:dynamic,
    ReportId:string
)
```

---

## Step 4 — Ingest the Emulated Data

Run each ingest command individually. Wait for the previous one to show **Completed** before running the next.

```kusto
.ingest into table SigninLogs
  ('https://raw.githubusercontent.com/GonePhishing402/cloud-threat-hunting/main/modules/02-token-abuse/emulated-data/SigninLogs.json')
  with (format='multijson')
```

```kusto
.ingest into table AADNonInteractiveUserSignInLogs
  ('https://raw.githubusercontent.com/GonePhishing402/cloud-threat-hunting/main/modules/02-token-abuse/emulated-data/AADNonInteractiveUserSignInLogs.json')
  with (format='multijson')
```

```kusto
.ingest into table AzureActivity
  ('https://raw.githubusercontent.com/GonePhishing402/cloud-threat-hunting/main/modules/02-token-abuse/emulated-data/AzureActivity.json')
  with (format='multijson')
```

```kusto
.ingest into table MicrosoftGraphActivityLogs
  ('https://raw.githubusercontent.com/GonePhishing402/cloud-threat-hunting/main/modules/02-token-abuse/emulated-data/MicrosoftGraphActivityLogs.json')
  with (format='multijson')
```

```kusto
.ingest into table CloudAppEvents
  ('https://raw.githubusercontent.com/GonePhishing402/cloud-threat-hunting/main/modules/02-token-abuse/emulated-data/CloudAppEvents.json')
  with (format='multijson')
```

---

## Step 5 — Verify the Data

Run these row-count checks to confirm all records loaded correctly:

```kusto
union
  (SigninLogs | count | extend Table="SigninLogs"),
  (AADNonInteractiveUserSignInLogs | count | extend Table="AADNonInteractiveUserSignInLogs"),
  (AzureActivity | count | extend Table="AzureActivity"),
  (MicrosoftGraphActivityLogs | count | extend Table="MicrosoftGraphActivityLogs"),
  (CloudAppEvents | count | extend Table="CloudAppEvents")
| project Table, Count
```

Expected output:

| Table | Count |
|---|---|
| SigninLogs | 2 |
| AADNonInteractiveUserSignInLogs | 16 |
| AzureActivity | 2 |
| MicrosoftGraphActivityLogs | 2 |
| CloudAppEvents | 5 |

If any count is 0, re-run the corresponding `.ingest` command from Step 4.

---

## Step 6 — Start the CTF

Open [challenges.md](challenges.md) and work through the challenges using your ADX database as the data source.

All KQL starting points in `challenges.md` are written for ADX and will run as-is against the `TokenAbuseHunt` database.

---

## Troubleshooting

| Issue | Fix |
|---|---|
| `.ingest` returns an error about permissions | Make sure you are querying the correct database (`TokenAbuseHunt`) and that you created the table first in Step 3 |
| Table exists but returns 0 rows after ingest | Ingestion on the free cluster can take up to 60 seconds — wait and re-run the count query |
| `.create-merge table` fails with "column type mismatch" | The table already exists with a different schema — run `.drop table <TableName>` then re-run the create command |
| Query returns "semantic error: unknown column" | The JSON field is nested under a `dynamic` column — use `tostring(d.FieldName)` or `toint(d.FieldName)` to extract it |
