# Email Sign In Triage Queries

## Query Description
This suite of queries offers comprehensive insights into user sign-on activities, aiming to monitor and analyze user access across various metrics. The queries facilitate the tracking of sign-on locations, devices used for access, both successful and failed sign-on attempts, and the variety of application usage. 

## Sentinel

### Summarize sign-on location for user
```KQL
let UserEmail = "";
let Timerange = ""; // 15m, 5h, 7d, etc
SigninLogs
| where TimeGenerated >= ago(Timerange)
| where UserPrincipalName =~ UserEmail
| extend succeeded_ = tostring(parse_json(AuthenticationDetails)[0].succeeded)
| extend city_ = tostring(LocationDetails.city)
| extend state_ = tostring(LocationDetails.state)
| extend countryOrRegion_ = tostring(LocationDetails.countryOrRegion)
| extend fullLocation = strcat(
    iff(isempty(city_), '', strcat(city_, ', ')), 
    iff(isempty(state_), '', strcat(state_, ', ')), 
    countryOrRegion_
)
| where succeeded_ == "true"
| summarize count() by fullLocation, IPAddress
```

### Determine hosts the user has signed into
```KQL
let UserEmail = "";
let Timerange = ""; // 15m, 5h, 7d, etc
SigninLogs
| where TimeGenerated >= ago(Timerange)
| where UserPrincipalName =~ UserEmail
| extend DeviceName = tostring(DeviceDetail.displayName)
| extend DeviceOS = tostring(DeviceDetail.operatingSystem)
| summarize HostsSignedInto = dcount(DeviceName) by DeviceName, DeviceOS, UserPrincipalName
| project UserPrincipalName, DeviceName, DeviceOS, HostsSignedInto
| sort by HostsSignedInto desc
| project-away HostsSignedInto
```

### Failed sign-on attempts

```KQL
let UserEmail = "";
let Timerange = ""; // 15m, 5h, 7d, etc
SigninLogs
| where TimeGenerated >= ago(Timerange)
| where UserPrincipalName = UserEmail 
| extend authenticationMethod_ = tostring(parse_json(AuthenticationDetails)[0].authenticationMethod)
| extend authenticationStepResultDetail_ = tostring(parse_json(AuthenticationDetails)[0].authenticationStepResultDetail)
| extend succeeded_ = tostring(parse_json(AuthenticationDetails)[0].succeeded)
| extend DeviceName = tostring(DeviceDetail.displayName)
| extend DeviceTrustType = tostring(DeviceDetail.trustType)
| extend operatingSystem_ = tostring(DeviceDetail.operatingSystem)
| extend city_ = tostring(LocationDetails.city)
| extend state_ = tostring(LocationDetails.state)
| extend countryOrRegion_ = tostring(LocationDetails.countryOrRegion)
| extend fullLocation = strcat(
    iff(isempty(city_), '', strcat(city_, ', ')), 
    iff(isempty(state_), '', strcat(state_, ', ')), 
    countryOrRegion_
)
| where succeeded_ == "false"
| project TimeGenerated, IPAddress, ResultDescription, SourceSystem, AppDisplayName, authenticationMethod_, authenticationStepResultDetail_, succeeded_, ConditionalAccessStatus, DeviceName, DeviceTrustType, operatingSystem_, fullLocation, UserAgent, UserType
| order by TimeGenerated desc
```

### Successful sign-on attempts
```KQL
let UserEmail = "";
let Timerange = ""; // 15m, 5h, 7d, etc
SigninLogs
| where TimeGenerated >= ago(Timerange)
| where UserPrincipalName = UserEmail 
| extend authenticationMethod_ = tostring(parse_json(AuthenticationDetails)[0].authenticationMethod)
| extend authenticationStepResultDetail_ = tostring(parse_json(AuthenticationDetails)[0].authenticationStepResultDetail)
| extend succeeded_ = tostring(parse_json(AuthenticationDetails)[0].succeeded)
| extend DeviceName = tostring(DeviceDetail.displayName)
| extend DeviceTrustType = tostring(DeviceDetail.trustType)
| extend operatingSystem_ = tostring(DeviceDetail.operatingSystem)
| extend city_ = tostring(LocationDetails.city)
| extend state_ = tostring(LocationDetails.state)
| extend countryOrRegion_ = tostring(LocationDetails.countryOrRegion)
| extend fullLocation = strcat(
    iff(isempty(city_), '', strcat(city_, ', ')), 
    iff(isempty(state_), '', strcat(state_, ', ')), 
    countryOrRegion_
)
| where (ResultType in ("0", "Success")) or (succeeded_ == "true")
| project TimeGenerated, IPAddress, ResultDescription, SourceSystem, AppDisplayName, authenticationMethod_, authenticationStepResultDetail_, succeeded_, ConditionalAccessStatus, DeviceName, DeviceTrustType, operatingSystem_, fullLocation, UserAgent, UserType
| order by TimeGenerated desc
```

### Sign-On Activity for Multiple Applications
```KQL
let UserEmail = "";
let Timerange = ""; // 15m, 5h, 7d, etc
SigninLogs
| where TimeGenerated >= ago(Timerange)
| where Identity =~ UserEmail
| summarize Applications = dcount(Application) by Identity
| project Identity, Applications
```
