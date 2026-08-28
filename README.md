# Cybersecurity Home-Lab Portfolio

**Brandon Cunningham** | Aspiring SOC / blue-team analyst | Google Cybersecurity Certificate

I am a career-changer building a documented cybersecurity home lab to demonstrate hands-on defensive security skills. Each project in this repository is a self-contained lab: I build the environment, apply and test real security controls, and write it up the way a security or GRC team would expect, with the defensive (blue-team) angle first.

**Links:** [LinkedIn](https://www.linkedin.com/in/brandon-cunningham456) | [GitHub](https://github.com/bcunn1037) | [Email](mailto:bcunningham456@proton.me)

---

## How to read these projects

Every artifact follows the same discipline, so a non-technical recruiter and a technical reviewer can both follow it:

- **Scope first:** what the project does and, just as important, what it deliberately does not do.
- **Each control as a short story:** the risk, the change I made, and how I verified it worked.
- **Framework tags:** every control is mapped to recognized standards (CIS Controls v8, NIST SP 800-53 Rev. 5, and MITRE ATT&CK).
- **Controls deliberately not applied:** the judgment calls, documented with the same rigor as the work I did.

---

## Artifacts

| # | Project | Focus | Frameworks | Status |
|---|---------|-------|------------|--------|
| 1 | [Parrot Workstation Hardening](00_parrot-hardening) | Host hardening measured with Lynis: firewall, DNS resilience, patching, least-privilege file permissions | CIS, NIST 800-53 | Published |
| 2 | SIEM Deployment & Detection (Wazuh) | Stand up a SIEM and detect, then attribute, an SSH brute-force attack | CIS, NIST 800-53, MITRE ATT&CK | In progress |
| 3 | Active Directory Hardening | Windows domain hardening and attack detection | CIS, NIST 800-53, MITRE ATT&CK | Planned |
| 4 | Cloud Security | Cloud misconfiguration identification and remediation | CIS, NIST 800-53 | Planned |
| 5 | Vulnerability Management | Scanning, prioritization, and a remediation workflow | NIST 800-53, MITRE ATT&CK | Planned |

Only published projects are linked. In-progress and planned projects will be linked as they go live.

---

## Frameworks referenced

- **CIS Controls v8:** a prioritized set of safeguards for cyber defense.
- **NIST SP 800-53 Rev. 5:** the control catalog widely used across GRC and compliance work.
- **MITRE ATT&CK:** a knowledge base of real-world attacker techniques, used to tag what each detection actually catches.

---

## A note on evidence handling

Only polished reports, their supporting screenshots, and PDF copies are published here. Raw journals, working notes, and any lab credentials are deliberately kept private and out of this public repository, which is itself a small demonstration of good data-handling discipline.
