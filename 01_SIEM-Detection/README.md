# Artifact 2: SIEM Deployment and Detection with Wazuh

A Wazuh SIEM deployed from scratch in an isolated VirtualBox home lab, then used to detect and attribute real attacks against monitored endpoints. The work is split into two units; open whichever matches what you want to see.

## Reports

**Unit 1: SSH brute-force detection (Linux)** &rarr; [Artifact-2-Unit1-SSH-Detection.md](Artifact-2-Unit1-SSH-Detection.md) ([PDF](pdf/Artifact-2-SIEM-Detection.pdf))
Stands up the Wazuh all-in-one SIEM (indexer, manager, dashboard), builds an isolated lab network, enrolls a Linux agent, and detects and attributes an SSH brute-force (MITRE T1110).

**Unit 2: Windows endpoint detection (Sysmon and RDP brute-force)** &rarr; [Artifact-2-Unit2-Windows-Detection.md](Artifact-2-Unit2-Windows-Detection.md)
Extends the SIEM to a Windows 11 endpoint, adds Sysmon telemetry, and detects an RDP brute-force from the Windows Security log (event 4625, rules 60122 and 60204).

## How this folder is organized

- `images/` holds the evidence screenshots the reports reference.
- `pdf/` holds downloadable PDF versions of the reports.

## At a glance

- **Platform:** Wazuh 4.14.7 all-in-one on Ubuntu Server 24.04.4; monitored Ubuntu and Windows 11 endpoints; Parrot attacker; isolated VirtualBox NAT Network.
- **Frameworks:** CIS Controls v8, NIST SP 800-53 Rev. 5, MITRE ATT&CK.
- **Analyst:** Brandon Cunningham (Google Cybersecurity Certificate).
