# Windows RDP Logon Sessions

## Query Description
This query sifts through Windows event logs, zeroing in on logon sessions associated with Remote Desktop Protocol (RDP) activities. It calculates the duration of each session and assesses whether any session was initiated with elevated privileges.

## Sentinel
```KQL
let AllEvents = SecurityEvent 
    | where EventID in (4624, 4634, 4672) 
    | where LogonType in ("2", "10", "11", "12") 
    | extend LogonId = coalesce(TargetLogonId, SubjectLogonId) 
    | join kind=leftouter ( 
        SecurityEvent 
        | where EventID == "4672" 
        | project EventID, LogonId = SubjectLogonId 
    ) on LogonId 
    | extend EventType = case(EventID1 == 4672, "SpecialLogon", EventID == 4624, "Logon", EventID == 4634, "Logoff", "Other") 
    | project TimeGenerated, Account, LogonId, EventType, Computer, LogonType; 
AllEvents 
| summarize 
    MinTime=min(TimeGenerated), 
    MaxTime=max(TimeGenerated), 
    SpecialLogonOccurred=any(EventType == "SpecialLogon") 
    by LogonId, Account, Computer, LogonType 
| extend SessionLengthSeconds = datetime_diff('second', MaxTime, MinTime) 
| extend Days = toint(SessionLengthSeconds / 86400) 
| extend Hours = toint((SessionLengthSeconds % 86400) / 3600) 
| extend Minutes = toint((SessionLengthSeconds % 3600) / 60) 
| extend Seconds = SessionLengthSeconds % 60 
| extend SessionLengthFormatted = strcat( 
                                      tostring(Days), 
                                      "d:", 
                                      iff(Hours < 10, strcat("0", tostring(Hours)), tostring(Hours)), 
                                      "h:", 
                                      iff(Minutes < 10, strcat("0", tostring(Minutes)), tostring(Minutes)), 
                                      "m:", 
                                      iff(Seconds < 10, strcat("0", tostring(Seconds)), tostring(Seconds)), 
                                      "s" 
                                  ) 
| where SessionLengthSeconds > 1 // Filter out any short sessions 
| project 
    Account, 
    SessionStart = MinTime, 
    SessionEnd = MaxTime, 
    SessionLengthFormatted, 
    SpecialLogonOccurred, 
    Computer, 
    LogonType, 
    LogonId 
```
