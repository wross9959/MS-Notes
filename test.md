2
```
dataset = xdr_data
| filter event_type == "AUTH"
| filter actor_user == "{{AlertUser}}"
| filter event_timestamp between relative_time(now(), -1h) and now()
| fields event_timestamp, actor_user, src_ip, src_location_country, device_os, device_model, user_agent, auth_method, result
| sort event_timestamp desc


```

4

```
dataset = auth_method
| filter user == "{{AlertUser}}"
| filter timestamp between relative_time(now(), -1h) and now()
| fields timestamp, user, method, mfa_status, mfa_type, mfa_result
| sort timestamp desc


```

6

```
dataset = xdr_data
| filter actor_user == "{{AlertUser}}"
| filter event_sub_type in ("user_permissions_modified", "password_reset", "role_assignment", "token_issued")
| filter event_timestamp between relative_time(now(), -1h) and now()
| fields event_timestamp, event_sub_type, actor_user, src_ip, resource_name
| sort event_timestamp desc

```

2
```
dataset = xdr_data
| filter event_type == "AUTH"
| filter actor_user == "{{AlertUser}}"
| filter event_timestamp between relative_time(now(), -1h) and now()
| fields src_ip, src_location_country, src_location_city, source_location_latitude, source_location_longitude
| dedup src_ip

```

4
```
dataset = auth_method
| filter user == "{{AlertUser}}"
| filter timestamp between relative_time(now(), -7d) and now()
| fields timestamp, user, method, mfa_status, mfa_type, mfa_result
| sort timestamp desc

```

5
```
dataset = xdr_data
| filter event_type == "AUTH"
| filter actor_user == "{{AlertUser}}"
| filter event_timestamp between relative_time(now(), -7d) and now()
| fields event_timestamp, src_ip, src_location_country, device_os, device_model, user_agent, result
| sort event_timestamp desc

```


8
```
dataset = xdr_data
| filter event_type == "AUTH"
| filter actor_user == "{{AlertUser}}"
| filter event_timestamp between relative_time(now(), -30d) and relative_time(now(), -2d)
| summarize count() by src_ip, src_location_country, device_os, device_model, user_agent


```
