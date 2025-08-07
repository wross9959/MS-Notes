1
```
SigninLogs
| where TimeGenerated between (datetime({{AlertTime}}) - 1h) .. (datetime({{AlertTime}}) + 1h)
| where UserPrincipalName has "{{AlertUser}}"
| project TimeGenerated, UserPrincipalName, IPAddress, Location, DeviceDetail, OperatingSystem, Browser, UserAgent, AuthenticationDetails

```

4
```
SigninLogs
| where UserPrincipalName has "{{AlertUser}}"
| project TimeGenerated, AuthenticationDetails

```

5
```
SigninLogs
| where UserPrincipalName has "{{AlertUser}}"
| sort by TimeGenerated desc
| project TimeGenerated, Location, IPAddress, DeviceDetail, UserAgent
```

6
```
SecurityEvent
| where Account contains "{{AlertUser}}"
| where EventID in (4728, 4729, 4732, 4733, 4740, 4756, 4757, 4768, 4769, 4771)
| project TimeGenerated, EventID, Account, TargetUserName, SubjectUserName, Computer

```

---

2
```
SigninLogs
| where TimeGenerated >= ago(3d)
| where UserPrincipalName == "{{user_upn}}"
| project TimeGenerated, Location, UserAgent, AppDisplayName, DeviceDetail, IPAddress, ResultType
| sort by TimeGenerated asc

```

4
```
SigninLogs
| where UserPrincipalName == "{{user_upn}}"
| project TimeGenerated, AuthenticationDetails, TokenIssuerType, TokenStatus

```

5
```
SecurityEvent
| where Account == "{{user_upn}}"
| where EventID in (4720, 4728, 4732, 4756)  // Group or privilege changes

```

6
```
SigninLogs
| where UserPrincipalName == "{{user_upn}}"
| project TimeGenerated, AuthenticationDetails, MFAResult, MFADetails

```

8
```
SigninLogs
| where TimeGenerated between (ago(30d) .. ago(2d))
| where UserPrincipalName == "{{user_upn}}"
| summarize by Location, IPAddress, DeviceDetail

```


