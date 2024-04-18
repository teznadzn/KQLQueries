# Public IP Process Activity Triage Queries

## Query Description
This collection of queries is designed to analyze network and process activity associated with a specified public IP address. The queries help to list processes communicating with the IP, identify unique processes initiating connections, analyze the frequency of process activity over time, and detect high-volume data transfers. This information is vital for security and network traffic analysis, allowing for a better understanding of system interactions with external IPs.

## Sentinel

### List Processes Communicating with a Public IP
```KQL
let Timerange = ""; // e.g., "24h"
let PublicIP = ""; // e.g., "93.184.216.34"
DeviceNetworkEvents
| where TimeGenerated >= ago(Timerange)
| where RemoteIP == PublicIP
| project DeviceName, TimeGenerated, RemoteIP, RemotePort, LocalIP, LocalPort, ProcessId
| join kind=inner (
    DeviceProcessEvents
    | where TimeGenerated >= ago(Timerange)
    ) on $left.ProcessId == $right.ProcessId
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, RemoteIP, RemotePort
```

### Unique Processes Initiating Connections to a Public IP
```KQL
let Timerange = ""; // e.g., "7d"
let PublicIP = ""; // e.g., "93.184.216.34"
DeviceNetworkEvents
| where TimeGenerated >= ago(Timerange)
| where RemoteIP == PublicIP
| summarize by ProcessId
| join kind=inner (
    DeviceProcessEvents
    | where TimeGenerated >= ago(Timerange)
    ) on ProcessId
| summarize UniqueProcesses = dcount(FileName) by DeviceName
| project DeviceName, UniqueProcesses
```

### Frequency of Process Activity to a Public IP by Hour
```KQL
let Timerange = ""; // e.g., "48h"
let PublicIP = ""; // e.g., "93.184.216.34"
DeviceNetworkEvents
| where TimeGenerated >= ago(Timerange)
| where RemoteIP == PublicIP
| summarize Count = count() by bin(TimeGenerated, 1h), ProcessId
| join kind=inner (
    DeviceProcessEvents
    | where TimeGenerated >= ago(Timerange)
    ) on ProcessId
| summarize CountPerHour = sum(Count) by bin(TimeGenerated, 1h), FileName
| project TimeGenerated, FileName, CountPerHour
| order by TimeGenerated asc, CountPerHour desc
```

### Detect Processes with High Volume Data Transfers to a Public IP
```KQL
let Timerange = ""; // e.g., "30d"
let PublicIP = ""; // e.g., "93.184.216.34"
DeviceNetworkEvents
| where TimeGenerated >= ago(Timerange)
| where RemoteIP == PublicIP
| summarize TotalBytes = sum(BytesSent) by ProcessId
| where TotalBytes > 1000000 // Filter for significant data transfer, adjust threshold as needed
| join kind=inner (
    DeviceProcessEvents
    | where TimeGenerated >= ago(Timerange)
    ) on ProcessId
| project FileName, TotalBytes
| order by TotalBytes desc
```
