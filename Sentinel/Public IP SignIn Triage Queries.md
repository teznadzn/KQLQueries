# Public IP SignIn Triage Queries

## Query Description
This collection of queries is designed to analyze various activities associated with specific IP addresses. It helps in identifying the most common users and associated computers, Azure activity, sign-in information, geolocation mapping of sign-ins, sign-on attempts over time, and applications accessed from a given IP. Additionally, it provides insights into sign-on attempts by device type, correlates sign-on locations with users, identifies high-risk sign-ons, and determines the frequency of sign-on methods used from a specific IP.

## Sentinel
### Azure Activity relating to IP
```KQL
let PublicIP = ""; 
let Timerange = ""; // 15m, 5h, 7d, etc 
AzureActivity
| where TimeGenerated >= ago(Timerange)
| search "PublicIP"
| extend ActionPath = tostring(parse_json(Properties).message)
| extend SourceResource = tostring(parse_json(Properties).resource)
| extend AuthroizedRole = tostring(parse_json(tostring(parse_json(Authorization).evidence)).role)
| project TimeGenerated, CallerIpAddress, ActivityStatusValue, ResourceGroup, ActionPath, SourceResource, AuthroizedRole
| order by TimeGenerated desc
```

### Pull relevant information for recent signin information to EntraAD
```KQL
let PublicIP = ""; 
let Timerange = ""; // 15m, 5h, 7d, etc 
SigninLogs
| where TimeGenerated >= ago(Timerange)
| where IPAddress == "PublicIP"
| extend city_ = tostring(LocationDetails.city), 
        state_ = tostring(LocationDetails.state), 
        countryOrRegion_ = tostring(LocationDetails.countryOrRegion),
        OS = tostring(DeviceDetail.operatingSystem),
        DeviceName = tostring(DeviceDetail.displayName)
| extend DeviceName = tostring(DeviceDetail.displayName)
| project TimeGenerated, ResultType, ResultDescription, city_, state_, countryOrRegion_,
        UserPrincipalName, 
        ResourceDisplayName, 
        DeviceName,
        OS,
        ConditionalAccessStatus,
        TokenIssuerType
| order by TimeGenerated desc
```

### Map Signin Location from IP
```KQL
let PublicIP = ""; 
let Timerange = ""; // 15m, 5h, 7d, etc 
SigninLogs
| where TimeGenerated >= ago(Timerange)
| where IPAddress == "PublicIP"
| extend Geo = parse_json(tostring(parse_json(LocationDetails)['geoCoordinates']))
| extend Latitude = toreal((tostring(parse_json(Geo)['latitude'])))
| extend Longitude = toreal(parse_json(tostring(parse_json(Geo)['longitude'])))
| summarize Count = count() by Longitude, Latitude, IPAddress
| project Longitude, Latitude, Count, IPAddress
| render scatterchart with (kind=map)
```

### Sign-On Attempts Over Time from a Public IP
```KQL
let Timerange = ""; // e.g., "1h"
let PublicIP = ""; // e.g., "8.8.8.8"
SigninLogs
| where TimeGenerated >= ago(Timerange)
| where IPAddress == PublicIP
| summarize AttemptCount = count() by bin(TimeGenerated, 10m) // Adjust bin as needed
| project TimeGenerated, AttemptCount
```

### Applications Accessed from a Public IP
```KQL
let Timerange = ""; // e.g., "24h"
let PublicIP = ""; // e.g., "8.8.8.8"
SigninLogs
| where TimeGenerated >= ago(Timerange)
| where IPAddress == PublicIP
| summarize AppCount = count() by AppDisplayName
| order by AppCount desc
| project AppDisplayName, AppCount
```

### Sign-On Attempts by Device Type from a Public IP
```KQL
let Timerange = ""; // e.g., "1d"
let PublicIP = ""; // e.g., "8.8.8.8"
SigninLogs
| where TimeGenerated >= ago(Timerange)
| where IPAddress == PublicIP
| summarize AttemptCount = count() by DeviceDetail
| order by AttemptCount desc
| project DeviceDetail, AttemptCount
```

### Correlate Sign-On Locations with Users from a Public IP
```KQL
let Timerange = ""; // e.g., "30d"
let PublicIP = ""; // e.g., "8.8.8.8"
SigninLogs
| where TimeGenerated >= ago(Timerange)
| where IPAddress == PublicIP
| summarize Locations = make_set(Location) by UserPrincipalName
| project UserPrincipalName, Locations
```

### Identifying High-Risk Sign-Ons from a Public IP
```KQL
let Timerange = ""; // e.g., "7d"
let PublicIP = ""; // e.g., "8.8.8.8"
SigninLogs
| where TimeGenerated >= ago(Timerange)
| where IPAddress == PublicIP
| where RiskLevel != "none" // Adjust based on your log structure and available fields
| project TimeGenerated, UserPrincipalName, RiskLevel, IPAddress
```

### Frequency of Sign-On Methods Used from a Public IP
```KQL
let Timerange = ""; // e.g., "30d"
let PublicIP = ""; // e.g., "8.8.8.8"
SigninLogs
| where TimeGenerated >= ago(Timerange)
| where IPAddress == PublicIP
| summarize MethodCount = count() by AuthenticationMethod
| order by MethodCount desc
| project AuthenticationMethod, MethodCount
```
