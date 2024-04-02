# Host Logon Triage Queries

## Query Description
These queries provide various security event analyses focused on logon activities, such as tracking daily logins to identify anomalies, sign-ins to specific hosts, failed and successful logon attempts, logins at unusual times, logins from multiple devices, account lockout incidents, and overall login attempts by users.

## Sentinel

### Checks Logins per day
```KQL
let Hostname = "";
let Timerange = ""; // 15m, 5h, 7d, etc
SecurityEvent
| where TimeGenerated >= ago(Timerange)
| where EventID == 4624
and Computer contains Hostname
// Uncomment below line to check elevated token 
// and ElevatedToken contains "1842" 
and TimeGenerated >= ago(TimePeriod)
| summarize ElevatedLogins = count() by bin(TimeGenerated, 1d), Computer
```

### Window Signins to host
```KQL
let Hostname = "";
let Timerange = ""; // 15m, 5h, 7d, etc
SecurityEvent
| where TimeGenerated >= ago(Timerange)
| where EventID in (4624, 4625) 
| where Computer =~ Hostname  
| summarize count() by Account, AccountType, LogonType, IpAddress, WorkstationName, Status
| order by count_ desc
```

### Failed Logon Events
```KQL
let Hostname = "";
let Timerange = ""; // 15m, 5h, 7d, etc
DeviceLogonEvents
| where TimeGenerated >= ago(Timerange)
| where DeviceName == Hostname
| where ActionType == "LogonFailed"
| project TimeGenerated, DeviceName, AccountName, FailureReason
```

### Successful Logon Events
```KQL
let Hostname = "";
let Timerange = ""; // 15m, 5h, 7d, etc
DeviceLogonEvents
| where TimeGenerated >= ago(Timerange)
| where DeviceName == Hostname
| where ActionType == "LogonSucceeded"
| project TimeGenerated, DeviceName, AccountName
```

### Unusual Login Times
```KQL
let Hostname = "";
let Timerange = ""; // 15m, 5h, 7d, etc
DeviceLogonEvents
| where TimeGenerated >= ago(Timerange)
| where DeviceName == Hostname
| extend HourOfDay = hourofday(TimeGenerated)
| where HourOfDay < 6 or HourOfDay > 18 // Adjust hours according to your organization's typical work hours
| project TimeGenerated, DeviceName, AccountName, HourOfDay
```

### Detect Logins from Multiple Devices
```KQL
let Timerange = ""; // 15m, 5h, 7d, etc
DeviceLogonEvents
| where TimeGenerated >= ago(Timerange)
| where ActionType == "LogonSucceeded"
| summarize DeviceCount = dcount(DeviceName) by AccountName
| where DeviceCount > 1
| project AccountName, DeviceCount
```

### Account Lockout Detection
```KQL
let Hostname = "";
let Timerange = ""; // 15m, 5h, 7d, etc
DeviceLogonEvents
| where TimeGenerated >= ago(Timerange)
| where DeviceName == Hostname
| where ActionType == "AccountLockout"
| project TimeGenerated, DeviceName, AccountName
```

### Login Attempts by User
```KQL
let Hostname = "";
let Timerange = ""; // 15m, 5h, 7d, etc
DeviceLogonEvents
| where TimeGenerated >= ago(Timerange)
| where DeviceName == Hostname
| summarize AttemptCount = count() by AccountName, ActionType
| order by AttemptCount desc
| project AccountName, ActionType, AttemptCount
```
