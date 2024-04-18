# Public IP Network Activity Triage Queries

## Query Description
This series of queries is designed to analyze network connections related to a specific public IP. It helps identify the volume of outbound and inbound traffic, RDP activity, connection attempts by protocol, actions by type, time distribution of connections, and devices with frequent connections to the IP. It also includes investigation of specific port activity and correlation of IP connections with process executions, useful for security analysis and monitoring network behavior.

## Sentinel

### Look into network connections
```KQL
let Timerange = ""; // e.g., "24h"
let PublicIP = ""; // e.g., "8.8.8.8"
DeviceNetworkEvents
| where TimeGenerated >= ago(Timerange)
| where RemoteIP == PublicIP
| project TimeGenerated, DeviceName, Action, RemoteIP, RemotePort, LocalIP, LocalPort, Protocol
```

### Query for RDP activity in Windows Event Logs relating to IP
```KQL
let PublicIP = ""; 
let Timerange = ""; // 15m, 5h, 7d, etc 
SecurityEvent
| where TimeGenerated >= ago(Timerange)
| search "PublicIP"
| where EventID in ("1149", "21", "22", "24", "40", "4779", "39", "9009") 
    or (EventID in ("4624", "4625", "4634") and LogonType == "10")
| project TimeGenerated, Account, Computer, Activity, IpAddress, ProcessId, SubjectAccount, TargetUserName
| order by TimeGenerated desc
```

### Outbound Traffic Volume to Public IP
```KQL
let Timerange = ""; // e.g., "7d"
let PublicIP = ""; // e.g., "8.8.8.8"
DeviceNetworkEvents
| where TimeGenerated >= ago(Timerange)
| where RemoteIP == PublicIP
| summarize TotalBytesSent = sum(BytesSent) by DeviceName
| order by TotalBytesSent desc
| project DeviceName, TotalBytesSent
```

### Unique Devices Connecting to Public IP
```KQL
let Timerange = ""; // e.g., "30d"
let PublicIP = ""; // e.g., "8.8.8.8"
DeviceNetworkEvents
| where TimeGenerated >= ago(Timerange)
| where RemoteIP == PublicIP
| summarize DeviceCount = dcount(DeviceName) by RemoteIP
| project RemoteIP, DeviceCount
```

### Count of Connection Attempts by Protocol
```KQL
let Timerange = ""; // e.g., "1d"
let PublicIP = ""; // e.g., "8.8.8.8"
DeviceNetworkEvents
| where TimeGenerated >= ago(Timerange)
| where RemoteIP == PublicIP
| summarize AttemptsCount = count() by Protocol
| order by AttemptsCount desc
| project Protocol, AttemptsCount
```

### Network Events by Action Type to Public IP
```KQL
let Timerange = ""; // e.g., "1h"
let PublicIP = ""; // e.g., "8.8.8.8"
DeviceNetworkEvents
| where TimeGenerated >= ago(Timerange)
| where RemoteIP == PublicIP
| summarize EventCount = count() by ActionType
| order by EventCount desc
| project ActionType, EventCount
```

### Investigate 443/80 Port Activity
```KQL
let Timerange = ""; // e.g., "24h"
let PublicIP = ""; // e.g., "8.8.8.8"
DeviceNetworkEvents
| where TimeGenerated >= ago(Timerange)
| where RemoteIP == PublicIP and RemotePort in (80, 443) // Add or modify ports as necessary
| project TimeGenerated, DeviceName, RemotePort, Protocol, Action, RemoteUrl
```

### Inbound Traffic from Public IP
```KQL
let Timerange = ""; // e.g., "7d"
let PublicIP = ""; // e.g., "8.8.8.8"
DeviceNetworkEvents
| where TimeGenerated >= ago(Timerange)
| where LocalIP == PublicIP
| summarize TrafficVolume = sum(BytesReceived) by DeviceName
| order by TrafficVolume desc
| project DeviceName, TrafficVolume
```

### Time Distribution of Connections to Public IP
```KQL
let Timerange = ""; // e.g., "24h"
let PublicIP = ""; // e.g., "8.8.8.8"
DeviceNetworkEvents
| where TimeGenerated >= ago(Timerange)
| where RemoteIP == PublicIP
| summarize ConnectionCount = count() by bin(TimeGenerated, 1h) // Adjust binning as needed
| order by TimeGenerated asc
| project TimeGenerated, ConnectionCount
```

### Devices with Most Frequent Connections to Public IP
```KQL
let Timerange = ""; // e.g., "30d"
let PublicIP = ""; // e.g., "8.8.8.8"
DeviceNetworkEvents
| where TimeGenerated >= ago(Timerange)
| where RemoteIP == PublicIP
| summarize ConnectionCount = count() by DeviceName
| order by ConnectionCount desc
| project DeviceName, ConnectionCount
```

### Analyze Bytes Transferred Over Time to Public IP
```KQL
let Timerange = ""; // e.g., "1d"
let PublicIP = ""; // e.g., "8.8.8.8"
DeviceNetworkEvents
| where TimeGenerated >= ago(Timerange)
| where RemoteIP == PublicIP
| summarize BytesSentTotal = sum(BytesSent), BytesReceivedTotal = sum(BytesReceived) by bin(TimeGenerated, 1h)
| order by TimeGenerated asc
| project TimeGenerated, BytesSentTotal, BytesReceivedTotal
```

### Correlate Public IP Connections with Process Executions
```KQL
let Timerange = ""; // e.g., "48h"
let PublicIP = ""; // e.g., "8.8.8.8"
DeviceNetworkEvents
| where TimeGenerated >= ago(Timerange)
| where RemoteIP == PublicIP
| project DeviceId, DeviceName, TimeGenerated, RemoteIP, RemotePort
| join kind=inner (
    DeviceProcessEvents
    | where TimeGenerated >= ago(Timerange)
    ) on DeviceId, $left.TimeGenerated == $right.TimeGenerated
| project DeviceName, ProcessName = FileName, ProcessCommandLine, RemoteIP, RemotePort, TimeGenerated
```

### Detect First-Time Connections to Public IP
```KQL
let Timerange = ""; // e.g., "90d"
let PublicIP = ""; // e.g., "8.8.8.8"
DeviceNetworkEvents
| where TimeGenerated >= ago(Timerange)
| where RemoteIP == PublicIP
| summarize FirstConnectionTime = min(TimeGenerated) by DeviceName
| where FirstConnectionTime >= ago(Timerange)
| project DeviceName, FirstConnectionTime
```
