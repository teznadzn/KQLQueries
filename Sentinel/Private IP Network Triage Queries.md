# Private IP Network Triage Queries

## Query Description
This set of queries is targeted at monitoring network activity related to a specified private IP address. It covers a range of scenarios from basic activity logs to advanced threat intelligence matching. These queries can be useful for identifying large data transfers, analyzing uncommon protocols used, and detecting potential threats from untrusted sources.

## Sentinel

### Looks for network activity to or from the Private IP
```KQL
let Timerange = ""; // 15m, 5h, 7d, etc
let PrivateIP = "";
DeviceNetworkEvents
| where TimeGenerated >= ago(Timerange)
| where RemoteIP == PrivateIP or LocalIP == PrivateIP
| project TimeGenerated, DeviceName, LocalIP, RemoteIP, RemotePort, Protocol, Action
```

### Large Data Transfers Involving a Private IP
```KQL
let Timerange = ""; // 15m, 5h, 7d, etc
let PrivateIP = "";
DeviceNetworkEvents
| where TimeGenerated >= ago(Timerange)
| where RemoteIP == PrivateIP or LocalIP == PrivateIP
| where BytesSent > 1000000 or BytesReceived > 1000000 // Adjust thresholds as needed
| project TimeGenerated, DeviceName, LocalIP, RemoteIP, BytesSent, BytesReceived, Protocol
```

### Unusual Protocols for a Private IP
```KQL
let Timerange = ""; // 15m, 5h, 7d, etc
let PrivateIP = "";
DeviceNetworkEvents
| where TimeGenerated >= ago(Timerange)
| where RemoteIP == PrivateIP or LocalIP == PrivateIP
| where Protocol !in ("TCP", "UDP", "") // Add or remove protocols as per your environment
| project TimeGenerated, DeviceName, LocalIP, RemoteIP, Protocol
```

### Inbound Connections from Untrusted Sources to a Private IP
```KQL
let Timerange = ""; // 15m, 5h, 7d, etc
let PrivateIP = ""; 
DeviceNetworkEvents
| where TimeGenerated >= ago(Timerange)
| where LocalIP == PrivateIP and ActionType == "InboundConnection"
| project TimeGenerated, DeviceName, LocalIP, RemoteIP, Protocol, Action
```

### TI Lookup check
```KQL
let Timerange = ""; // 15m, 5h, 7d, etc
let PrivateIP = ""; 
DeviceNetworkEvents
| where TimeGenerated >= ago(Timerange)
| where RemoteIP == PrivateIP or LocalIP == PrivateIP
| join kind=inner (
    ThreatIntelligenceIndicator
    | where TimeGenerated >= ago(Timerange)
    | where IndicatorType == "IP"
    | project MaliciousIP = NetworkDestinationIPv4
) on $left.RemoteIP == $right.MaliciousIP
| project TimeGenerated, DeviceName, LocalIP, RemoteIP, Protocol, ThreatConfidence
```
