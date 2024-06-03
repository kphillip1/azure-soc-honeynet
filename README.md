
# Building a SOC + Honeynet in Azure (Live Traffic)
![image](https://github.com/kphillip1/azure-soc-honeynet/assets/165929885/ca6ef315-dcbf-4176-b90f-c46a6bbf0459)

<h2>Video Demonstration</h2>

- ### [YouTube: How To Build a SOC + Honeynet in Azure](https://youtu.be/mOjbD7FkUUI)

[![How To Build a SOC + Honeynet in Azure](https://img.youtube.com/vi/mOjbD7FkUUI/0.jpg)](https://www.youtube.com/watch?v=mOjbD7FkUUI)


## Introduction

In this project, I build a mini honeynet in Azure and ingest logs from various resources into a Log Analytics Workspace, which is then used by Microsoft Sentinel to build attack maps, trigger alerts, and create incidents. I measured some security metrics in the insecure environment for 24 hours, applied security controls to harden the environment, measured metrics for another 24 hours, and then shared the results below. The metrics we will collect are:

- SecurityEvent (Windows Event Logs)
- Syslog (Linux Event Logs)
- SecurityAlert (Log Analytics Alerts Triggered)
- SecurityIncident (Incidents created by Sentinel)
- AzureNetworkAnalytics_CL (Malicious Flows allowed into our honeynet)

## Architecture Before Hardening / Security Controls
![image](https://github.com/kphillip1/azure-soc-honeynet/assets/165929885/efa182b3-afe3-46d6-b431-84fe61c1daff)


## Architecture After Hardening / Security Controls
![image](https://github.com/kphillip1/azure-soc-honeynet/assets/165929885/bda2d085-3471-4d51-8373-404e5dbd3371)


The architecture of the mini honeynet in Azure consists of the following components:

- Virtual Network (VNet)
- Network Security Group (NSG)
- Virtual Machines (2 windows, 1 linux)
- Log Analytics Workspace
- Azure Key Vault
- Azure Storage Account
- Microsoft Sentinel


## Attack Maps Before Hardening / Security Controls
<img width="735" alt="Capture1" src="https://github.com/kphillip1/azure-soc-honeynet/assets/165929885/6201e7a7-6e1e-4759-bca5-c820e125190c">
<br><br>
<img width="593" alt="Capture2" src="https://github.com/kphillip1/azure-soc-honeynet/assets/165929885/ccefa380-5948-4dd6-b52c-f303648fb68e">
<br><br>
<img width="598" alt="Capture3" src="https://github.com/kphillip1/azure-soc-honeynet/assets/165929885/3406fac0-c152-4684-bc3a-236ff35a9eb4">
<br><br>

## Metrics Before Hardening / Security Controls

The following table shows the metrics we measured in our insecure environment for 24 hours:
<br>
| Start Time 2024-04-13 13:53:48
<br>
| Stop Time 2024-04-14 13:53:48

| Metric                   | Count
| ------------------------ | -----
| SecurityEvent            | 7671
| Syslog                   | 833
| SecurityAlert            | 4
| SecurityIncident         | 59
| AzureNetworkAnalytics_CL | 620

## Attack Maps After Hardening / Security Controls

<img width="231" alt="noresults" src="https://github.com/kphillip1/azure-soc-honeynet/assets/165929885/031e52cf-266f-40de-a1b1-d8ff313aa746">
<br><br>

```All map queries actually returned no results due to no instances of malicious activity for the 24 hour period after hardening.```

## Metrics After Hardening / Security Controls

The following table shows the metrics we measured in our environment for another 24 hours, but after we have applied security controls:
<br>
| Start Time 2024-04-15 11:50:28
<br>
| Stop Time 2024-04-16 11:50:28

| Metric                   | Count
| ------------------------ | -----
| SecurityEvent            | 3894
| Syslog                   | 6
| SecurityAlert            | 0
| SecurityIncident         | 0
| AzureNetworkAnalytics_CL | 0

![image](https://github.com/kphillip1/azure-soc-honeynet/assets/165929885/3d5a9f41-fd9f-4e0c-bfa1-85da4b249939)


## Summary

In this project, a mini honeynet was constructed in Microsoft Azure and the logs were pushed into a Log Analytics Workspace for analysis. Microsoft Sentinel was also employed to trigger alerts and create incidents based on the ingested logs. Additionally, metrics were measured in the insecure environment before security controls were applied, and then again after implementing security measures. The number of security events and incidents were drastically reduced after the security controls were applied, demonstrating their effectiveness.

It is worth noting that if the resources within the network were heavily utilized by regular users, it is likely that more security events and alerts may have been generated within the 24-hour period following the implementation of the security controls.


## KQL Queries

| Metric                                       | Query                                                                                                                                            |
|----------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------|
| Start/Stop Time                              | range x from 1 to 1 step 1<br>\| project StartTime = ago(24h), StopTime = now()                                                                  |
| Security Events (Windows VMs)                | SecurityEvent<br>\| where TimeGenerated>= ago(24h)<br>\| count                                                                                   |
| Syslog (Linux VMs)                           | Syslog<br>\| where TimeGenerated >= ago(24h)<br>\| count                                                                                         |
| SecurityAlert (Microsoft Defender for Cloud) | Security Alert<br>\| where DisplayName !startswith "CUSTOM" and DisplayName !startswith "TEST"<br>\| where TimeGenerated >= ago(24h)<br>\| count |
| Security Incident (Sentinel Incidents)       | SecurityIncident<br>\| where TimeGenerated >= ago(24h)<br>\| count                                                                               |
| NSG Inbound Malicious Flows Allowed          | AzureNetworkAnalytics_CL<br>\| where FlowType_s == "MaliciousFlow" and AllowedInFlows_d > 0<br>\| where TimeGenerated >= ago(24h)<br>\| count    |
