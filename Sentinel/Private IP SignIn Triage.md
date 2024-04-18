# Private IP SignIn Triage

## Query Description
This set of queries provides an analysis of user and computer access within a network, focusing on logon events from a specified private IP address. It can help identify the most common users and computers, events from associated hosts, identify specific logon events, and track both successful and unsuccessful logons. Additionally, it can highlight unusual logon times which may indicate off-hours access or potential security threats.

## Sentinel

### Summarize most common users and computers associated
```KQL
let PrivateIP = "";
let Timerange = ""; // 15m, 5h, 7d, etc
SecurityEvent
| where TimeGenerated >= ago(Timerange)
| where EventID == 4624 // An account was successfully logged on
| where IpAddress == ip_PrivateIP
| summarize UserHostLogonCount = count() by TargetUserName, Computer
| top 5 by UserHostLogonCount desc
```

### SignInLogs Events from Associated Host
```KQL
let PrivateIP = "";
let Timerange = ""; // 15m, 5h, 7d, etc
let DeviceNameFromIP = Heartbeat
| where ComputerPrivateIPs contains PrivateIP 
| extend DeviceName = tostring(split(Computer, ".")[0])
| summarize by DeviceName; 
SigninLogs
| where TimeGenerated >= ago(Timerange)
| where ResultType == "0"
| extend DeviceName = tostring(DeviceDetail.displayName)
| join kind=inner DeviceNameFromIP on DeviceName 
| extend city_ = tostring(LocationDetails.city)
| extend state_ = tostring(LocationDetails.state)
| extend countryOrRegion_ = tostring(LocationDetails.countryOrRegion)
| extend fullLocation = strcat(
    iff(isempty(city_), '', strcat(city_, ', ')), 
    iff(isempty(state_), '', strcat(state_, ', ')), 
    countryOrRegion_)
| project TimeGenerated, DeviceName, UserPrincipalName, UserDisplayName, fullLocation, AppDisplayName, IPAddress, UserAgent
```

### Identify Logon Events from a Private IP
```KQL
let Timerange = ""; // e.g., "30d"
let PrivateIP = ""; // e.g., "192.168.1.100"
DeviceLogonEvents
| where TimeGenerated >= ago(Timerange)
| where RemoteIP == PrivateIP
| project TimeGenerated, DeviceName, AccountName, LogonType, RemoteIP
```

### Count of Logon Failures by User from a Private IP
```KQL
let Timerange = ""; // e.g., "7d"
let PrivateIP = ""; // e.g., "10.0.0.5"
DeviceLogonEvents
| where TimeGenerated >= ago(Timerange)
| where RemoteIP == PrivateIP and ResultType != 0 // Adjust based on your success codes
| summarize FailureCount = count() by AccountName
| order by FailureCount desc
| project AccountName, FailureCount
```

### Successful Logons from a Private IP
```KQL
let Timerange = ""; // e.g., "14d"
let PrivateIP = ""; // e.g., "172.16.0.4"
DeviceLogonEvents
| where TimeGenerated >= ago(Timerange)
| where RemoteIP == PrivateIP and ResultType == 0 // Ensure this matches your environment's success code
| project TimeGenerated, DeviceName, AccountName, LogonType, RemoteIP
```

### Logon Types for Accesses from a Private IP
```KQL
let Timerange = ""; // e.g., "7d"
let PrivateIP = ""; // e.g., "10.1.2.3"
DeviceLogonEvents
| where TimeGenerated >= ago(Timerange)
| where RemoteIP == PrivateIP
| summarize CountByLogonType = count() by LogonType
| order by CountByLogonType desc
| project LogonType, CountByLogonType
```

### Unusual Logon Times from a Private IP
```KQL
let Timerange = ""; // e.g., "1d"
let PrivateIP = ""; // e.g., "192.168.1.254"
DeviceLogonEvents
| where TimeGenerated >= ago(Timerange)
| where RemoteIP == PrivateIP
| extend HourOfDay = HourOfDay(TimeGenerated)
| where HourOfDay < 6 or HourOfDay > 18 // Adjust according to typical business hours
| project TimeGenerated, DeviceName, AccountName, LogonType, HourOfDay
```
