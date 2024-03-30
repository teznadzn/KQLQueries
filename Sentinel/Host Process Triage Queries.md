# Host Process Triage Queries

## Query Description
These queries collectively enhance security monitoring by identifying unusual process behaviors, network activities, and potential threats across Windows devices, including the tracking of process hierarchies, detection of risky executions, and monitoring of uncommon application activities.

## Sentinel

### Query for child, parent, and sibling processes of a process
```KQL
let Process = ""; // Looking for process file name, process.exe (case sensitive)
let PID = ""; // Looking for specific PID
let OriginalProcess = DeviceProcessEvents
| where FileName == Process and ProcessId == PID
| extend Hierarchy = "TargetProcess",
         ParentProcessFileName = InitiatingProcessFileName,
         ParentProcessPID = InitiatingProcessId
| project TimeGenerated, Hierarchy, FileName, FolderPath, FileSize, ProcessCommandLine, ParentProcessFileName, ParentProcessPID;
let ChildProcess = DeviceProcessEvents
| where InitiatingProcessFileName == Process and InitiatingProcessId == PID
| extend Hierarchy = "ChildProcess"
| project TimeGenerated, Hierarchy, FileName, FolderPath, FileSize, ProcessCommandLine;
let ParentProcessFileName = toscalar(OriginalProcess | project ParentProcessFileName | limit 1);
let ParentProcessPID = toscalar(OriginalProcess | project ParentProcessPID | limit 1);
let ParentProcess = DeviceProcessEvents
| where FileName == ParentProcessFileName and ProcessId == ParentProcessPID
| extend Hierarchy = "ParentProcess"
| project TimeGenerated, Hierarchy, FileName, FolderPath, FileSize, ProcessCommandLine;
// New query to find Sibling Processes - those initiated by the same parent as the original process
let SiblingProcesses = DeviceProcessEvents
| where InitiatingProcessFileName == ParentProcessFileName and InitiatingProcessId == ParentProcessPID
    and not(FileName == Process and ProcessId == PID) // Exclude the original process itself
| extend Hierarchy = "SiblingProcess"
| project TimeGenerated, Hierarchy, FileName, FolderPath, FileSize, ProcessCommandLine;
union OriginalProcess, ChildProcess, ParentProcess, SiblingProcesses
| project-away ParentProcessFileName, ParentProcessPID
| order by TimeGenerated desc
```

### Detect Process Spawning cmd.exe or powershell.exe
```KQL
| let Timerange = ""; // 15m, 5h, 7d, etc
| let Hostname = "";
DeviceProcessEvents
| where TimeGenerated >= ago(Timerange)
| where DeviceName == Hostname
| where FileName has_any("cmd.exe", "powershell.exe")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
```

### Find Processes with Network Activity
```KQL
| let Timerange = ""; // 15m, 5h, 7d, etc
| let Hostname = "";
DeviceNetworkEvents
| where TimeGenerated >= ago(Timerange)
| join kind=inner (DeviceProcessEvents | where DeviceName == Hostname) on DeviceId
| project TimeGenerated, DeviceName, ProcessCommandLine, RemoteIP, RemotePort
```

### List Processes Running from Uncommon Locations
```KQL
| let Timerange = ""; // 15m, 5h, 7d, etc
| let Hostname = "";
DeviceProcessEvents
| where TimeGenerated >= ago(Timerange)
| where DeviceName == Hostname
| where FolderPath !startswith_any("/windows/", "/program files/")
| project TimeGenerated, DeviceName, FileName, FolderPath
```

### Detect Execution from Temp Directory
```KQL
| let Timerange = ""; // 15m, 5h, 7d, etc
| let Hostname = "";
DeviceProcessEvents
| where TimeGenerated >= ago(Timerange)
| where DeviceName == Hostname
| where FolderPath contains "\\temp\\"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, FolderPath
```

### Identify Processes with no Parent Process
```KQL
| let Timerange = ""; // 15m, 5h, 7d, etc
| let Hostname = "";
DeviceProcessEvents
| where TimeGenerated >= ago(Timerange)
| where DeviceName == Hostname
| where InitiatingProcessFileName == ""
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
```

### Monitor for Batch Scripts Execution
```KQL
| let Timerange = ""; // 15m, 5h, 7d, etc
| let Hostname = "";
DeviceProcessEvents
| where TimeGenerated >= ago(Timerange)
| where DeviceName == Hostname
| where FileName endswith ".bat"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
```

### Detect Script Execution via Microsoft Office Applications
```KQL
| let Timerange = ""; // 15m, 5h, 7d, etc
| let Hostname = "";
DeviceProcessEvents
| where TimeGenerated >= ago(Timerange)
| where DeviceName == Hostname
| where FileName has_any("winword.exe", "excel.exe", "onenote.exe") and ProcessCommandLine contains "script"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
```

### Monitor for SSH Client Usage
```KQL
| let Timerange = ""; // 15m, 5h, 7d, etc
| let Hostname = "";
DeviceProcessEvents
| where TimeGenerated >= ago(Timerange)
| where DeviceName == Hostname
| where FileName == "ssh.exe"
| project TimeGenerated, DeviceName, ProcessCommandLine
```

### Detect Processes with Self-Deletion Commands
```KQL
| let Timerange = ""; // 15m, 5h, 7d, etc
| let Hostname = "";
DeviceProcessEvents
| where TimeGenerated >= ago(Timerange)
| where DeviceName == Hostname
| where ProcessCommandLine contains "cmd.exe /c del"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
```
