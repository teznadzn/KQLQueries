# Intune Device Enrollment Information

## Query Description
This query retrieves and correlates Intune enrollment logs and device information, summarizing the latest data based on the time range provided, and reorders the output to show when each device was last enrolled, its name, and the associated user principal name (UPN).

## Sentinel
```KQL
let Hostname = "";
let Timerange = ""; // 15m, 5h, 7d, etc
IntuneOperationalLogs
| where TimeGenerated >= ago(Timerange)
| where OperationName == "Enrollment"
| extend EnrollmentTimeUTC = tostring(parse_json(Properties).EnrollmentTimeUTC)
| extend EnrollmentType = tostring(parse_json(Properties).EnrollmentType)
| extend FailureCategory = tostring(parse_json(Properties).FailureCategory)
| extend DeviceId = tostring(parse_json(Properties).IntuneDeviceId)
| extend IntuneUserId = tostring(parse_json(Properties).IntuneUserId)
| extend OS = tostring(parse_json(Properties).Os)
| join kind=leftouter (
    IntuneDevices
    | where TimeGenerated >= ago(Timerange)
    | summarize arg_max(TimeGenerated, *) by DeviceName
    | project TimeGenerated, DeviceName, LastContact, OS, Model, DeviceState, JoinType, DeviceId
) on DeviceId
| join kind=leftouter (
    IdentityInfo
    | where TimeGenerated >= ago(Timerange)
    | extend IntuneUserId = AccountObjectId
    | summarize arg_max(TimeGenerated, *) by IntuneUserId
    | project UPN = AccountUPN, IntuneUserId
) on IntuneUserId
| where DeviceName =~ "Hostname"
| project-away DeviceId1, OS1, IntuneUserId1, Type, Properties, Category, TimeGenerated1, SourceSystem
| project-reorder TimeGenerated, DeviceName, UPN
```
