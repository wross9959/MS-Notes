2.
SigninLogs
| where TimeGenerated > ago(72h)
| where UserPrincipalName == "<user_upn>"
| project TimeGenerated, Location, UserAgent, AppDisplayName, DeviceDetail, IPAddress, ResultType
| sort by TimeGenerated asc

dataset = xdr_data
| filter event_type == "AUTH"
| filter actor_user == "<user_upn>"
| fields event_timestamp, source_location_country, user_agent, application_name, source_ip, result
| sort event_timestamp asc

4.
SigninLogs
| where UserPrincipalName == "<user_upn>"
| project TimeGenerated, AuthenticationDetails, TokenIssuerType, TokenStatus

dataset = xdr_data
| filter actor_user == "<user_upn>"
| filter event_type == "AUTH"
| filter token_type == "RefreshToken" or token_reuse == true
| fields token_type, region, reuse_detected

5.
SecurityEvent
| where Account == "<user_upn>"
| where EventID in (4720, 4728, 4732, 4756) // Group/privilege changes

dataset = audit_logs
| filter actor_user == "<user_upn>"
| filter activity_type in ("RoleAssigned", "RBACModified", "MFAChanged")
| fields activity_type, target_user, modified_fields


8
SigninLogs
| where TimeGenerated between (ago(30d)..ago(2d))
| where UserPrincipalName == "<user_upn>"
| summarize by Location, IPAddress, DeviceDetail

dataset = xdr_data
| filter actor_user == "<user_upn>"
| filter event_timestamp between now() - 30d and now() - 2d
| summarize by source_ip, source_location_country, os_type, browser


