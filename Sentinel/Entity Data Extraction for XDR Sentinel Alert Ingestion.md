# Entity Data Extraction for XDR Sentinel Alert Ingestion

## Query Descriptions and KQL Queries

### Extract MDE Detection Alert Entities for Email Escalation
This query extracts detailed entity information from Microsoft Defender for Endpoint (MDE) detection alerts. It structures each entity into a separate event to facilitate the escalation process via email. 

```KQL
let ReferenceSystemAlertId = dynamic([PasteHere]);
SecurityIncident
| where parse_json(tostring(AdditionalData.alertProductNames))[0] == "Microsoft Defender Advanced Threat Protection"
| summarize arg_max(CreatedTime, *) by IncidentNumber
| project IncidentNumber, AlertIds 
| mv-expand AlertIds to typeof(string)
| join kind=inner SecurityAlert on $left.AlertIds == $right.SystemAlertId
| where SystemAlertId in (ReferenceSystemAlertId)
| summarize arg_max(TimeGenerated, *) by SystemAlertId
| mv-expand todynamic(Entities)
| evaluate bag_unpack(Entities, 'Entity_')
| extend Entity_ImageFileName = tostring(column_ifexists("Entity_ImageFile.Name", "")),
          Entity_ParentProcessName = tostring(column_ifexists("Entity_ParentProcess.ImageFile", "{}")),
          Entity_ParentProcessId = tostring(column_ifexists("Entity_ParentProcess.ProcessId", "")),
          Entity_Directory = tostring(column_ifexists("Entity_Directory", ""))
| extend Entity_ParentProcessName = tostring(parse_json(Entity_ParentProcessName).Name),
          Entity_FileHashes = todynamic(column_ifexists("Entity_FileHashes", dynamic([])))
| mv-expand Entity_FileHashes
| extend HashAlgorithm = tostring(Entity_FileHashes.Algorithm), 
          HashValue = tostring(Entity_FileHashes.Value)
| extend SHA1 = iif(HashAlgorithm == "SHA1", HashValue, ""),
          SHA256 = iif(HashAlgorithm == "SHA256", HashValue, ""),
          MD5 = iif(HashAlgorithm == "MD5", HashValue, "")
| extend ATP_InvestigationState = tostring(parse_json(ExtendedProperties).["MicrosoftDefenderAtp.InvestigationState"])
| extend LoggedOnUsers = parse_json(Entity_LoggedOnUsers)[0].AccountName
| summarize SHA1 = max(column_ifexists("SHA1", "")), 
            SHA256 = max(column_ifexists("SHA256", "")), 
            MD5 = max(column_ifexists("MD5", "")) 
            by IncidentNumber, AlertIds, TimeGenerated, AlertName, CompromisedEntity, 
            Entity_Name = column_ifexists("Entity_Name", ""), 
            Entity_Directory, Entity_HostName = column_ifexists("Entity_HostName", ""), 
            Entity_FQDN = column_ifexists("Entity_FQDN", ""), 
            Entity_LastExternalIpAddress = column_ifexists("Entity_LastExternalIpAddress", ""), 
            Entity_LastIpAddress = column_ifexists("Entity_LastIpAddress", ""), 
            Entity_LastSeen = column_ifexists("Entity_LastSeen", ""), 
            Entity_OnboardingStatus = column_ifexists("Entity_OnboardingStatus", ""), 
            Entity_OSFamily = column_ifexists("Entity_OSFamily", ""), 
            Entity_OSVersion = column_ifexists("Entity_OSVersion", ""), 
            LoggedOnUsers = tostring((column_ifexists(tostring("LoggedOnUsers"), ""))), 
            Entity_RiskScore = column_ifexists("Entity_RiskScore", ""), 
            Entity_Sid = column_ifexists("Entity_Sid", ""), 
            Entity_UserPrincipalName = column_ifexists("Entity_UserPrincipalName", ""), 
            Entity_CommandLine = column_ifexists("Entity_CommandLine", ""), 
            Entity_ImageFileName, 
            Entity_ProcessId = column_ifexists("Entity_ProcessId", ""), 
            Entity_ParentProcessName, 
            Entity_ParentProcessId, 
            ATP_InvestigationState
| extend TimeGenerated = TimeGenerated, AlertName = AlertName, CompromisedEntity = CompromisedEntity, ATP_InvestigationState = ATP_InvestigationState, Name = Entity_Name, 
          Directory = Entity_Directory, SHA1 = SHA1, SHA256 = SHA256, MD5 = MD5, HostName = Entity_HostName, FQDN = Entity_FQDN, LastExternalIpAddress = Entity_LastExternalIpAddress, 
          LastIpAddress = Entity_LastIpAddress, LastSeen = Entity_LastSeen, OnboardingStatus = Entity_OnboardingStatus, OSFamily = Entity_OSFamily, 
          OSVersion = Entity_OSVersion, LoggedOnUsers = LoggedOnUsers, RiskScore = Entity_RiskScore, Sid = Entity_Sid, 
          UserPrincipalName = Entity_UserPrincipalName, CommandLine = Entity_CommandLine, ImageFileName = Entity_ImageFileName, 
          ProcessId = Entity_ProcessId, ParentProcessName = Entity_ParentProcessName, ParentProcessId = Entity_ParentProcessId
| project TimeGenerated, AlertName, CompromisedEntity, ATP_InvestigationState, Name, 
          Directory, SHA1, SHA256, MD5, HostName, FQDN, LastExternalIpAddress, 
          LastIpAddress, LastSeen, OnboardingStatus, OSFamily, 
          OSVersion, LoggedOnUsers, RiskScore, Sid, 
          UserPrincipalName, CommandLine, ImageFileName, 
          ProcessId, ParentProcessName, ParentProcessId
```


### Extract Defender for DLP Alert Entities for Email Escalation
This query is tailored to extract information from Defender for Data Loss Prevention (DLP) alerts, arranging each alert entity into separate events for easy inclusion in emails.

```KQL
let ReferenceSystemAlertId = dynamic([PasteHere]);
let Alerts = SecurityIncident
| summarize arg_max(CreatedTime, *) by IncidentNumber
| project IncidentNumber, AlertIds 
| mv-expand AlertIds to typeof(string)
| join kind=inner SecurityAlert on $left.AlertIds == $right.SystemAlertId
| where SystemAlertId in(ReferenceSystemAlertId)
| summarize arg_max(TimeGenerated, *) by SystemAlertId
| mv-expand todynamic(Entities)
| evaluate bag_unpack(Entities, 'Entity_')
| extend Sender = tostring(column_ifexists("Entity_P1Sender", "")),
    Recipient  = tostring(column_ifexists("Entity_Recipient", "")),
    Subject = tostring(column_ifexists("Entity_Subject", "")),
    ReceivedDate = tostring(column_ifexists("Entity_ReceivedDate", "")),
    FileName = tostring(column_ifexists("Entity_Name", "")),
    UserPrincipalName = tostring(column_ifexists("Entity_UserPrincipalName", ""))
| summarize arg_max(TimeGenerated, *) by TimeGenerated, Sender, Recipient, Subject, FileName, UserPrincipalName, ReceivedDate, AlertName, AlertSeverity, SystemAlertId;
Alerts
| join kind=inner (Alerts) on TimeGenerated
| distinct TimeGenerated, AlertName, Sender, Recipient, Subject, FileName1
| where (Subject != "") and (Sender != "") and (Recipient != "") and (FileName1 != "")
```

### Extract Defender for O365 Alert Entities for Email Escalation
Specifically focusing on Defender for Office 365 alerts, this query separates each alert entity into individual events to simplify the process of including them in escalation emails.

```KQL
let ReferenceSystemAlertId = dynamic([PasteHere]);
let Alerts = SecurityIncident 
| summarize arg_max(CreatedTime, *) by IncidentNumber 
| project IncidentNumber, AlertIds  
| mv-expand AlertIds to typeof(string) 
| join kind=inner SecurityAlert on $left.AlertIds == $right.SystemAlertId 
| where SystemAlertId in(ReferenceSystemAlertId) 
| summarize arg_max(TimeGenerated, *) by SystemAlertId 
| mv-expand todynamic(Entities) 
| evaluate bag_unpack(Entities, 'Entity_') 
| extend URL = tostring(column_ifexists("Entity_Url", "")), 
    URLs = tostring(column_ifexists("Entity_Urls", "")),
    Sender1  = tostring(column_ifexists("Entity_P1Sender", "")), 
    Sender2 = tostring(column_ifexists("Entity_P2Sender", "")), 
    SenderDisplayName = tostring(column_ifexists("Entity_P2SenderDisplayName", "")), 
    Recipient = tostring(column_ifexists("Entity_Recipient", "")), 
    SenderIP = tostring(column_ifexists("Entity_SenderIP", "")),
    Subject = tostring(column_ifexists("Entity_Subject", "")),
    UserPrincipalName = tostring(column_ifexists("Entity_UserPrincipalName", "")),
    DeliveryAction = tostring(column_ifexists("Entity_DeliveryAction", "")),
    DeliveryLocation = tostring(column_ifexists("Entity_DeliveryLocation", "")),
    NetworkMessageId = tostring(column_ifexists("Entity_NetworkMessageId", ""))
| summarize arg_max(TimeGenerated, *) by TimeGenerated, Sender1, Sender2, SenderDisplayName, SenderIP, Recipient, Subject, URLs, URL, UserPrincipalName, DeliveryAction, DeliveryLocation, NetworkMessageId, SystemAlertId; 
Alerts 
| join kind=inner (Alerts) on TimeGenerated 
| distinct TimeGenerated, Sender1, Sender2, SenderDisplayName, SenderIP, Recipient, Subject, URLs, URL, DeliveryAction, DeliveryLocation, SystemAlertId, NetworkMessageId
| where SenderDisplayName != ""
```

