# Related Processes via DeviceProcessEvents

## Query Description
The query searches for a specific process by name and ID, identifies its child processes and the parent process, and then finds sibling processes (those initiated by the same parent, excluding the original process), finally presenting the combined results in descending order of creation time. Useful in environments without Defender access.

## Sentinel
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
