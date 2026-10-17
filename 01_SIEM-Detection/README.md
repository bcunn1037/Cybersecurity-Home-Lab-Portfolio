# Artifact 2: SIEM Deployment and Detection with Wazuh

A Wazuh SIEM deployed from scratch in an isolated VirtualBox home lab, then used to detect, attribute, and respond to real attacks against monitored endpoints.
## Reports

**Unit 1: SSH brute-force detection (Linux)** &rarr; [Artifact-2-Unit1-SSH-Detection.md](Artifact-2-Unit1-SSH-Detection.md) ([PDF](pdf/Artifact-2-SIEM-Detection.pdf))
Stands up the Wazuh all-in-one SIEM (indexer, manager, dashboard), builds an isolated lab network, enrolls a Linux agent, and detects and attributes an SSH brute-force (MITRE T1110).

**Unit 2: Windows endpoint detection (Sysmon and RDP brute-force)** &rarr; [Artifact-2-Unit2-Windows-Detection.md](Artifact-2-Unit2-Windows-Detection.md)
Extends the SIEM to a Windows 11 endpoint, adds Sysmon telemetry, and detects an RDP brute-force from the Windows Security log (event 4625, rules 60122 and 60204).

**Unit 3: Active response and Windows hardening** &rarr; [Artifact-2-Unit3-ActiveResponse-Hardening.md](Artifact-2-Unit3-ActiveResponse-Hardening.md)
Closes the loop on the RDP brute-force: adds automated containment (Wazuh active response auto-blocks the attacker at the Windows Firewall), diagnoses and remediates a Wazuh 4.14.7 active-response bug by upgrading the agent to 4.14.9, and hardens the endpoint with an account lockout policy and RDP Network Level Authentication.

## How this folder is organized

- `images/` holds t