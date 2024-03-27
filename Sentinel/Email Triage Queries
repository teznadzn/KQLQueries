# Email Triage Queries

## Query Description
These queries are designed to analyze email activities, focusing on email interactions, attachments, URLs, frequent contacts, potential security threats, and delivery failures for a specific user over chosen periods.

## Sentinel

### Emails received by user
```KQL
let UserEmail = "";
let Timerange = ""; // 15m, 5h, 7d, etc
EmailEvents
| where TimeGenerated >= ago(Timerange)
| where RecipientEmailAddress =~ UserEmail
| project TimeGenerated, SenderFromAddress, Subject, AttachmentCount, UrlCount, DeliveryAction, EmailDirection, EmailLanguage
| order by TimeGenerated desc
```

### Emails sent by user
```KQL
let UserEmail = "";
let Timerange = ""; // 15m, 5h, 7d, etc
EmailEvents
| where TimeGenerated >= ago(Timerange)
| where SenderFromAddress =~ UserEmail
| project TimeGenerated, SenderFromAddress, Subject, AttachmentCount, UrlCount, DeliveryAction, EmailDirection, EmailLanguage
| order by TimeGenerated desc
```

### Attachment Info in sent/received emails
```KQL
let UserEmail = "";
let Timerange = ""; // 15m, 5h, 7d, etc
EmailAttachmentInfo
| where TimeGenerated >= ago(Timerange) 
| where SenderFromAddress =~ UserEmail or RecipientEmailAddress =~ UserEmail
| project TimeGenerated, FileName, FileType, RecipientEmailAddress, SenderFromAddress, SHA256, FileSize
| order by TimeGenerated desc
```
### URL Info in sent/received emails
```KQL
let UserEmail = "";
let Timerange = ""; // 15m, 5h, 7d, etc
EmailUrlInfo
| where TimeGenerated >= ago(Timerange)
| join kind=inner (
    EmailEvents
    | project SenderFromAddress, RecipientEmailAddress, NetworkMessageId
) on NetworkMessageId
| where SenderFromAddress =~ UserEmail or RecipientEmailAddress =~ UserEmail
| project TimeGenerated, Url, UrlLocation, Domain = UrlDomain, Sender = SenderFromAddress, Recipient = RecipientEmailAddress
| order by TimeGenerated desc
```
### User's most frequent correspondents
```KQL
let UserEmail = "";
let Timerange = ""; // 15m, 5h, 7d, etc
EmailEvents
| where TimeGenerated >= ago(Timerange)
| where SenderMailFromAddress =~ UserEmail or RecipientEmailAddress =~ UserEmail
| extend CorrespondentEmail = iif(SenderMailFromAddress == Email, RecipientEmailAddress, SenderMailFromAddress)
| summarize CorrespondenceCount = count() by CorrespondentEmail
| order by CorrespondenceCount desc
| project CorrespondentEmail, CorrespondenceCount
```
### Potential phishing email detection
```KQL
let UserEmail = "";
let Timerange = ""; // 15m, 5h, 7d, etc
EmailEvents
| where TimeGenerated >= ago(Timerange)
| where RecipientEmailAddress =~ UserEmail
| where Subject has_any("password", "reset", "urgent", "immediate action required") or SenderMailFromAddress !contains Email.split("@")[1] // Adjust based on common phishing indicators
| project TimeGenerated, SenderMailFromAddress, Subject, URLCount
```
### Failed email deliveries
```KQL
let UserEmail = "";
let Timerange = ""; // 15m, 5h, 7d, etc
EmailEvents
| where TimeGenerated >= ago(Timerange)
| where SenderMailFromAddress =~ UserEmail and DeliveryAction == "Fail"
| summarize FailedCount = count() by Subject, RecipientEmailAddress
| order by FailedCount desc
| project Subject, RecipientEmailAddress, FailedCount
```
