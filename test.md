SigninLogs
| where TimeGenerated between (datetime({{AlertTime}}) - 1h) .. datetime({{AlertTime}} + 1h)
| where UserPrincipalName has "{{AlertUser}}"
| project TimeGenerated, UserPrincipalName, IPAddress, Location, DeviceDetail, OperatingSystem, Browser, UserAgent, AuthenticationDetails



dataset = xdr_data
| filter event_type == "AUTH"
| filter actor_user == "{{AlertUser}}"
| filter timestamp between relative_time(now(), -1h) and relative_time(now(), 1h)
| fields timestamp, actor_user, src_ip, src_location, device_os, device_model, user_agent, auth_method


2. 
SigninLogs
| where UserPrincipalName has "{{AlertUser}}"
| summarize LoginCount = count() by IPAddress, Location
| order by LoginCount asc


dataset = xdr_data
| filter event_type == "AUTH"
| filter actor_user == "{{AlertUser}}"
| stats count() as login_count by src_ip, src_location
| sort login_count asc

3. 
SigninLogs
| where IPAddress in~ ('{{SuspiciousIP}}')
| extend ThreatIntel = parse_json(ThreatDetectionDetails)
| project IPAddress, ThreatIntel

dataset = xdr_data
| filter src_ip == "{{SuspiciousIP}}"
| fields src_ip, src_location, is_tor_exit_node, is_known_vpn, tags


4. 
SigninLogs
| where UserPrincipalName has "{{AlertUser}}"
| project TimeGenerated, AuthenticationDetails


dataset = auth_method
| filter user == "{{AlertUser}}"
| filter timestamp between relative_time(now(), -1h) and now()
| fields user, method, mfa_status, mfa_type, mfa_result


5.
SigninLogs
| where UserPrincipalName has "{{AlertUser}}"
| summarize by IPAddress, DeviceDetail, Location, TimeGenerated

dataset = xdr_data
| filter event_type == "AUTH"
| filter actor_user == "{{AlertUser}}"
| stats count() by src_ip, src_location, device_model


6.
SecurityEvent
| where Account contains "{{AlertUser}}"
| where EventID in (4728, 4729, 4732, 4733, 4740, 4756, 4757, 4768, 4769, 4771)
| project TimeGenerated, EventID, Account, TargetUserName, SubjectUserName, Computer

dataset = xdr_data
| filter actor_user == "{{AlertUser}}"
| filter event_sub_type in ("user_permissions_modified", "password_reset", "role_assignment", "token_issued")
| fields timestamp, actor_user, event_sub_type, src_ip, resource_name

