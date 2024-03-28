# Host Network Triage Queries

## Queries Description
This collection of queries is designed to provide detailed insights into network activity on specific hosts. It includes the analysis of inbound and outbound connections, identification of high volume data transfers, detection of repeated connections to the same remote IPs, and more. The goal is to help in detecting potential security threats, unusual network activities, and optimizing network performance.

## Sentinel

### List Network Connections
```KQL
let Timerange = ""; // 15m, 5h, 7d, etc
let Hostname = ""; // Hostname goes here
DeviceNetworkEvents
| where TimeGenerated >= ago(Timerange)
| where DeviceName == Hostname
| project TimeGenerated, DeviceName, Action, RemoteIP, RemotePort, LocalIP, LocalPort, Protocol
```

### List outbound connections to uncommon ports
```KQL
let Timerange = ""; // 15m, 5h, 7d, etc
let Hostname = ""; // Hostname goes here
DeviceNetworkEvents
| where TimeGenerated >= ago(Timerange)
| where DeviceName == Hostname and RemotePort !in (80, 443, 22, 21, 25)
| project TimeGenerated, DeviceName, RemoteIP, RemotePort, Protocol
```

### Summarize network activity by protocol
```KQL
let Timerange = ""; // 15m, 5h, 7d, etc
let Hostname = ""; // Hostname goes here
DeviceNetworkEvents
| where TimeGenerated >= ago(Timerange)
| where DeviceName == Hostname
| summarize count() by Protocol
| project Protocol, Count = count_
```

### List Network Connections with High Volume Data Transfer
```KQL
let Timerange = ""; // 15m, 5h, 7d, etc
let Hostname = ""; // Hostname goes here
DeviceNetworkEvents
| where TimeGenerated >= ago(Timerange)
| where DeviceName == Hostname
| where BytesSent + BytesReceived > 1000000 // Adjust threshold as needed
| project TimeGenerated, DeviceName, RemoteIP, LocalIP, BytesSent, BytesReceived, Protocol
```

### Identify Repeated Connections to the Same Remote IP
```KQL
let Timerange = ""; // 15m, 5h, 7d, etc
let Hostname = ""; // Hostname goes here
DeviceNetworkEvents
| where TimeGenerated >= ago(Timerange)
| where DeviceName == Hostname
| summarize CountConnections = count() by RemoteIP
| where CountConnections > 5 // Adjust threshold as needed
| project RemoteIP, CountConnections
```

### Detect Connections to Non-Standard HTTP/HTTPS Ports
```KQL
let Timerange = ""; // 15m, 5h, 7d, etc
let Hostname = ""; // Hostname goes here
DeviceNetworkEvents
| where TimeGenerated >= ago(Timerange)
| where DeviceName == Hostname and Protocol in ("HTTP", "HTTPS") and RemotePort !in (80, 443)
| project TimeGenerated, DeviceName, RemoteIP, RemotePort, Protocol
```

### Look for Large Data Transfers
```KQL
let Timerange = ""; // e.g., "1d"
let Hostname = ""; // e.g., "server01"
DeviceNetworkEvents
| where TimeGenerated >= ago(Timerange)
| where DeviceName == Hostname
| where BytesSent > 10000000 // Adjust threshold as needed
| project TimeGenerated, DeviceName, RemoteIP, BytesSent, Protocol
```

### Look for Unusual Network Connections
```KQL
let Timerange = ""; // 15m, 5h, 7d, etc
let Hostname = ""; // Hostname goes here
DeviceNetworkEvents
| where TimeGenerated >= ago(Timerange)
| where DeviceName == Hostname
| summarize CountConnections = count() by RemotePort
| where CountConnections < 5 // Threshold for rarity, adjust as needed
| project RemotePort, CountConnections
```

### Detect VPN and Remote Desktop Usage
```KQL
let Timerange = ""; // 15m, 5h, 7d, etc
let Hostname = ""; // Hostname goes here
DeviceNetworkEvents
| where TimeGenerated >= ago(Timerange)
| where DeviceName == Hostname
| where RemotePort in (3389, 1723) // RDP and PPTP VPN ports, adjust as needed
| project TimeGenerated, DeviceName, RemoteIP, RemotePort, Protocol
```

### Detect Anomalous Protocol Usage
```KQL
let Timerange = ""; // 15m, 5h, 7d, etc
let Hostname = ""; // Hostname goes here
DeviceNetworkEvents
| where TimeGenerated >= ago(Timerange)
| where DeviceName == Hostname
| where Protocol !in ("TCP", "UDP", "") // Adjust based on expected protocols
| project TimeGenerated, DeviceName, RemoteIP, Protocol
```

### Cross-Table Analysis for Process and Network Activity
```KQL
let Timerange = ""; // 15m, 5h, 7d, etc
let Hostname = ""; // Hostname goes here
DeviceNetworkEvents
| where TimeGenerated >= ago(Timerange)
| where DeviceName == Hostname
| join kind=inner (
    DeviceProcessEvents 
    | where TimeGenerated >= ago(Timerange) 
    and DeviceName == Hostname) on $left.DeviceId == $right.DeviceId, $left.ProcessId == $right.ProcessId
| project TimeGenerated, DeviceName, RemoteIP, RemotePort
```
