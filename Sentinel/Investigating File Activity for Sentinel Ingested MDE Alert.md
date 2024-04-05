# Investigating File Activity for Sentinel Ingested MDE Alert

## Query Description
This query is designed to extract and consolidate file activity from different logs within Microsoft Defender for Endpoint logs in Azure Sentinel. It aggregates details about files, network events, and process events associated with security alerts to aid in incident analysis and response.

You will need to replace the 'PasteHere' string in the first line with all SystemAlertId values from the Sentinel incident from MDE you are investigating.

## Sentinel
```KQL
let ReferenceSystemAlertId = dynamic(["PasteHere"]);
let FileSet = SecurityIncident
	| where parse_json(tostring(AdditionalData.alertProductNames))[0] == "Microsoft Defender Advanced Threat Protection"
	| summarize arg_max(CreatedTime, *) by IncidentNumber
	| project IncidentNumber, AlertIds 
	| mv-expand AlertIds to typeof(string)
	| join kind=inner SecurityAlert on $left.AlertIds == $right.SystemAlertId
	| where SystemAlertId in (ReferenceSystemAlertId)
	| summarize arg_max(TimeGenerated, *) by SystemAlertId
	| mv-expand todynamic(Entities)
	| evaluate bag_unpack(Entities, 'Entity_')
	| extend Name = Entity_Name
	| distinct Name;
let LinkList = DeviceFileEvents
	| where FileName in (FileSet)
	| where FileOriginUrl != ""
	| distinct FileOriginUrl
	| extend FileOriginUrl2 = tostring(extract("^(?:https?:\\/\\/)?([^\\/]+)", 1, FileOriginUrl))
	| project FileOriginUrls = pack_array(FileOriginUrl, FileOriginUrl2)
	| mv-expand FileOriginUrl = FileOriginUrls to typeof(string)
	| project FileOriginUrl;
let CompromisedEntityList = SecurityIncident
	| where parse_json(tostring(AdditionalData.alertProductNames))[0] == "Microsoft Defender Advanced Threat Protection"
	| summarize arg_max(CreatedTime, *) by IncidentNumber
	| project IncidentNumber, AlertIds 
	| mv-expand AlertIds to typeof(string)
	| join kind=inner SecurityAlert on $left.AlertIds == $right.SystemAlertId
	| where SystemAlertId in (ReferenceSystemAlertId)
	| summarize arg_max(TimeGenerated, *) by SystemAlertId
	| distinct CompromisedEntity;
let Query1 = DeviceNetworkEvents
	| where RemoteUrl in (LinkList)
	| project TimeGenerated, DeviceName, RemoteUrl, ActionType, RemoteIP, RemotePort, LocalIP, LocalPort, Protocol;
let Query2 = DeviceFileEvents
	| where FileName in (FileSet)
	| project TimeGenerated, FileName, ActionType, FolderPath, FileOriginUrl, FileOriginReferrerUrl, FileOriginIP, FileSize, InitiatingProcessAccountName, InitiatingProcessFolderPath, SHA256, PreviousFileName, PreviousFolderPath;
let OriginalAlert = SecurityAlert
	| summarize arg_max(TimeGenerated, *) by SystemAlertId 
	| where SystemAlertId in(ReferenceSystemAlertId);
let Query3 = DeviceEvents
	| where RemoteUrl in (LinkList)
	| extend Experience = tostring(AdditionalFields.Experience)
	| project TimeGenerated, ActionType, Experience, DeviceName, RemoteUrl, InitiatingProcessFileName, InitiatingProcessAccountName;
let Query4 = DeviceProcessEvents
	| where FileName in (FileSet) and DeviceName in (CompromisedEntityList)
	| project TimeGenerated, DeviceName, ActionType, FileName, FolderPath, FileSize, ProcessCommandLine, MD5, InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName;
union isfuzzy=true Query1, Query2, Query3, Query4, OriginalAlert
```
