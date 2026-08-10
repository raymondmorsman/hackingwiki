---
title: Nice queries for Crowdstrike Falcon
description: 
published: true
date: 2026-08-10T08:22:01.716Z
tags: 
editor: markdown
dateCreated: 2026-08-10T08:18:27.016Z
---

# Nice queries

Find who uses a computer in the Falcon Logging:

> 
	#event_simpleName=/UserLogon.*/ ComputerName="**COMPUTERNAME**"
| case {
    #event_simpleName="UserLogon" | LogonOutcome:="Success";
    #event_simpleName="UserLogonFailed2" | LogonOutcome:="Failed";
    * | LogonOutcome:="Unknown";
  }
| $falcon/helper:enrich(field=LogonType)
| LoginTime:=@timestamp
| formatTime(format="%Y-%m-%d %H:%M:%S", field=LoginTime, as=LoginTime)
| default(field=RemoteAddressIP4, value="N/A")
| table([LoginTime, UserName, LogonOutcome, LogonType, RemoteAddressIP4])