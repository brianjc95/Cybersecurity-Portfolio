# Windows Server Health Monitor

## Project Overview

This project is a PowerShell-based Windows Server health monitoring tool developed in a virtualized Active Directory lab environment (`companyx.local`).

The script monitors critical server resources, Windows services, event logs, and network connectivity to identify potential system issues. It generates an overall server health status and automatically exports a detailed event log report in CSV format and a full health report in TXT format.

The project was developed iteratively through four versions, with each version introducing additional monitoring and reporting capabilities.

## Features

### System Resource Monitoring
- Monitors CPU utilization using Windows Management Instrumentation (WMI/CIM).
- Calculates physical memory utilization.
- Monitors local fixed-disk usage.
- Applies warning and critical thresholds to resource utilization.

### Windows Service Monitoring
- Checks the status of six critical Active Directory services:
  - Active Directory Domain Services (NTDS)
  - DNS Server
  - Netlogon
  - Kerberos Key Distribution Center (KDC)
  - Active Directory Web Services (ADWS)
  - Windows Time (W32Time)
- Identifies stopped or missing required services.

### Event Log Monitoring
- Reviews the Windows System and Application event logs.
- Searches for critical and error-level events within the previous 24 hours.
- Captures event IDs, timestamps, sources, severity levels, and messages.
- Exports detailed event information to CSV.

### Network Connectivity Monitoring
- Discovers and tests the server's default gateway.
- Tests external IP connectivity.
- Verifies external DNS resolution.
- Checks Active Directory LDAP DNS service records.

### Reporting and Health Classification
- Calculates an overall server health status.
- Classifies components as HEALTHY, WARNING, REVIEW, CRITICAL, or NOT FOUND.
- Displays component health counts.
- Generates timestamped TXT and CSV reports.

## Lab Environment

The project was developed and tested in a virtualized Windows Server environment configured with an Active Directory domain.

| Component | Configuration |
|---|---|
| Server | Windows Server |
| Hostname | DC01 |
| Active Directory Domain | companyx.local |
| Server IP Address | 192.168.1.204 |
| Default Gateway | 192.168.1.1 |
| DNS Server | 192.168.1.204 |
| Virtualization | Oracle VirtualBox |

## Tools and Technologies

- **PowerShell 5.1** – Automation and monitoring scripts.
- **Windows Server** – Server operating system and Active Directory environment.
- **Active Directory Domain Services** – Domain services and infrastructure monitoring.
- **WMI/CIM** – System resource information.
- **Windows Event Viewer** – System and application event monitoring.
- **Windows Networking Cmdlets** – Gateway, DNS, and network connectivity checks.
- **CSV and TXT Reporting** – Automated health report generation.

## Development History

The project was developed through four iterations, with each version introducing additional monitoring and reporting capabilities.

| Version | Features Added |
|---|---|
| V1 | CPU, memory, and disk utilization monitoring with warning and critical thresholds. |
| V2 | Added monitoring for six critical Windows Active Directory services. |
| V3 | Added System and Application event log monitoring, including detailed CSV exports. |
| V4 | Added network connectivity checks, DNS validation, overall health classification, component summaries, and automated TXT health reports. |

### Key Improvements
- Expanded monitoring from basic system resources to multiple areas of server health.
- Added service-state validation for critical domain controller services.
- Implemented event log collection and severity reporting.
- Added network and Active Directory DNS connectivity validation.
- Developed automated reporting to make monitoring results easier to review and troubleshoot.

- ## Testing and Validation

The monitoring script was executed and validated within the `companyx.local` lab environment.

### Successful Tests

- Verified CPU, memory, and disk utilization reporting.
- Tested resource health thresholds using simulated values.
- Confirmed all six required Active Directory services were detected and running.
- Tested service health classification for running, stopped, and missing services.
- Verified System and Application event log collection.
- Confirmed detailed event information was exported to CSV.
- Successfully tested gateway connectivity using ICMP.
- Verified external IP connectivity to `8.8.8.8`.
- Confirmed external DNS resolution using `google.com`.
- Verified Active Directory LDAP service record discovery.
- Tested overall health classification with HEALTHY, WARNING, REVIEW, CRITICAL, and NOT FOUND statuses.
- Confirmed timestamped TXT and CSV reports were generated successfully.

### Sample Test Results

| Component | Result |
|---|---|
| CPU | HEALTHY |
| Memory | HEALTHY |
| Disk C: | HEALTHY |
| Active Directory Services | HEALTHY |
| Network Connectivity | HEALTHY |
| External DNS | HEALTHY |
| AD DNS Discovery | HEALTHY |
| System Event Log | REVIEW |
| Application Event Log | REVIEW |

**Overall Server Status: REVIEW**

The REVIEW status was expected because the System and Application event logs contained error-level or critical events during the monitoring period.

## Limitations and Future Improvements

The current version was developed for a single Windows Server domain controller within a home lab environment.

Potential future improvements include:

- Support monitoring multiple remote Windows servers.
- Make network adapter and DNS server discovery more flexible.
- Add configurable monitoring thresholds.
- Improve event log filtering to identify recurring or high-priority issues.
- Add email notifications when critical conditions are detected.
- Implement scheduled execution using Windows Task Scheduler.
- Expand reporting with historical health data and trend analysis.

## Project Status

**Version 4.0 – Complete**

The current version successfully monitors server resources, Active Directory services, Windows event logs, and network connectivity while generating automated health reports.
