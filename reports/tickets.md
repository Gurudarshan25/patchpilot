# PatchPilot tickets - week 1

| Ticket | System | CVE | Priority | Hours | Exploited (KEV) | Ransomware | Opens attack path |
|---|---|---|---|---|---|---|---|
| PP-001 | Domain controller (Active Directory) | CVE-2021-34527 | P1 | 2 | Yes | Yes | Yes |
| PP-002 | Edge firewall (Palo Alto) | CVE-2024-3400 | P1 | 2 | Yes | Yes | Yes |
| PP-003 | Message queue (ActiveMQ) | CVE-2023-46604 | P1 | 3 | Yes | Yes | Yes |
| PP-004 | Partner file transfer (MOVEit) | CVE-2023-34362 | P1 | 3 | Yes | Yes | Yes |
| PP-005 | Remote access VPN (Citrix NetScaler) | CVE-2023-4966 | P1 | 3 | Yes | Yes | Yes |
| PP-006 | Remote access VPN (Citrix NetScaler) | CVE-2023-6549 | P1 | 1 | Yes | No | Yes |
| PP-007 | Remote access VPN (Citrix NetScaler) | CVE-2024-6387 | P2 | 1 | No | No | Yes |
| PP-008 | Remote access VPN (Citrix NetScaler) | CVE-2023-6548 | P1 | 1 | Yes | No | Yes |
| PP-009 | Mail server (Exchange) | CVE-2021-26855 | P1 | 4 | Yes | Yes | Yes |

## PP-001: [P1] Install update, disable spooler on Domain controller (Active Directory) (CVE-2021-34527)

**Deadline:** fix within 48 hours  |  **Effort:** 2 h  |  **Risk score:** 100/100

**Why it matters:** This vulnerability affects the Domain Controller (Active Directory) system, which is a critical component of the network infrastructure. If exploited, it could lead to remote code execution with SYSTEM privileges, allowing attackers to install malware, view, change, or delete data, and create new accounts with full user rights.

**Attacker scenario:** An attacker could exploit this vulnerability to gain full control over the Domain Controller, potentially leading to the compromise of the entire network and the theft of sensitive data. The attacker could also use this as a stepping stone to further compromise other systems.

**Fix steps:**
1. Install the security update for the Print Spooler service.
2. Disable the Print Spooler service to prevent unauthorized use.
3. Restart the affected system to apply the changes.
4. Verify that the Print Spooler service is disabled.
5. Test the system to ensure it functions as expected after the fix.

**Verify:** Verify that the Print Spooler service is disabled and the system is functioning correctly after the update and disable steps.

## PP-002: [P1] Apply vendor hotfix on Edge firewall (Palo Alto) (CVE-2024-3400)

**Deadline:** fix within 48 hours  |  **Effort:** 2 h  |  **Risk score:** 100/100

**Why it matters:** This vulnerability allows an unauthenticated attacker to execute arbitrary code with root privileges on the Edge firewall, which could enable them to compromise the system and gain control over sensitive data or infrastructure.

**Attacker scenario:** An attacker could exploit this vulnerability to execute commands with root privileges, potentially allowing them to steal sensitive data, modify system configurations, or even take full control of the firewall.

**Fix steps:**
1. Apply the vendor-provided hotfix to the Edge firewall.
2. Restart the firewall to ensure the fix is applied.
3. Verify that the firewall is running the latest PAN-OS version.
4. Check the firewall logs for any suspicious activity.
5. Test the firewall's functionality to ensure it is operating as expected.

**Verify:** Verify that the firewall is running the latest PAN-OS version and monitor the logs for any suspicious activity.

## PP-003: [P1] Upgrade ActiveMQ on Message queue (ActiveMQ) (CVE-2023-46604)

**Deadline:** fix within 48 hours  |  **Effort:** 3 h  |  **Risk score:** 96.0/100

**Why it matters:** CVE-2023-46604 affects the Message queue (ActiveMQ) system, mq-01, which is internet-facing and a crown jewel. The vulnerability allows remote attackers to execute arbitrary shell commands, posing a significant risk to the system's security and integrity.

**Attacker scenario:** An attacker could exploit this vulnerability to run arbitrary shell commands on the system, potentially gaining full control over the ActiveMQ instance and compromising the system's security.

**Fix steps:**
1. Upgrade ActiveMQ to version 5.15.16, 5.16.7, 5.17.6, or 5.18.3
2. Restart the ActiveMQ service to apply the changes
3. Verify that the ActiveMQ version is updated to the recommended version

**Verify:** Verify that the ActiveMQ version is updated to the recommended version 5.15.16, 5.16.7, 5.17.6, or 5.18.3 and that the service is restarted.

## PP-004: [P1] Apply vendor patch on Partner file transfer (MOVEit) (CVE-2023-34362)

**Deadline:** fix within 48 hours  |  **Effort:** 3 h  |  **Risk score:** 100/100

**Why it matters:** This vulnerability allows an attacker to gain unauthorized access to the MOVEit Transfer database, which contains sensitive information for this system. The vulnerability could lead to data theft or further exploitation of the system.

**Attacker scenario:** An attacker could exploit this vulnerability to retrieve sensitive data from the database, such as credentials and configuration settings, which could be used for further attacks or data exfiltration.

**Fix steps:**
1. Apply the vendor patch provided by MOVEit.
2. Restart the MOVEit Transfer service to ensure the patch is applied.
3. Verify that the system is secure by checking for any remaining vulnerabilities.
4. Ensure that all users are trained on secure practices to prevent future incidents.
5. Monitor the system for any suspicious activity post-remediation.

**Verify:** Verify that the system is secure by checking for any remaining vulnerabilities and ensuring that the service is running without issues.

## PP-005: [P1] Apply vendor patch, kill sessions on Remote access VPN (Citrix NetScaler) (CVE-2023-4966)

**Deadline:** fix within 48 hours  |  **Effort:** 3 h  |  **Risk score:** 100/100

**Why it matters:** CVE-2023-4966 affects the Remote access VPN system (system_id: vpn-gw), which is internet-facing and used by ransomware. This vulnerability allows sensitive information disclosure and opens attack paths to crown jewels, making it critical to secure immediately.

**Attacker scenario:** An attacker could exploit this vulnerability to disclose sensitive information and gain unauthorized access to crown jewels, potentially leading to data breaches and ransomware attacks.

**Fix steps:**
1. Apply the vendor patch provided for CVE-2023-4966.
2. Kill all sessions associated with the affected system.
3. Ensure all security measures are in place to prevent unauthorized access.
4. Restart the affected system to apply the patch.
5. Monitor the system for any signs of unauthorized activity.

**Verify:** Verify that no sensitive information is disclosed and all sessions have been terminated by checking logs and session management tools.

## PP-006: [P1] Apply vendor update on Remote access VPN (Citrix NetScaler) (CVE-2023-6549)

**Deadline:** fix within 48 hours  |  **Effort:** 1 h  |  **Risk score:** 100/100

**Why it matters:** This CVE impacts the Remote access VPN (Citrix NetScaler) system, which is internet-facing and considered a crown jewel. The vulnerability allows for Denial of Service and Out-Of-Bounds Memory Read attacks, which could lead to unauthorized access and data breaches.

**Attacker scenario:** An attacker could exploit this vulnerability to cause a Denial of Service, rendering the system unavailable. Additionally, an attacker might be able to read sensitive data stored in memory, compromising the confidentiality of the system.

**Fix steps:**
1. Apply the vendor-provided update to the NetScaler ADC and NetScaler Gateway.
2. Ensure all systems are patched within the 48-hour deadline.
3. Restart the affected systems to apply the update.
4. Monitor the systems for any signs of the vulnerability being exploited.
5. Verify the fix by checking for the presence of the update in the system logs.

**Verify:** Verify the presence of the vendor update in the system logs to ensure the fix was applied successfully.

## PP-007: [P2] Upgrade OpenSSH on Remote access VPN (Citrix NetScaler) (CVE-2024-6387)

**Deadline:** fix within 7 days  |  **Effort:** 1 h  |  **Risk score:** 96.2/100

**Why it matters:** CVE-2024-6387 affects the Remote access VPN (Citrix NetScaler) system, which is internet-facing and critical to the organization's security posture. The race condition vulnerability in OpenSSH's server (sshd) allows an attacker to potentially exploit authentication failures, compromising the system's integrity and confidentiality.

**Attacker scenario:** An attacker could exploit this vulnerability by sending a crafted signal to the sshd process, causing it to handle signals in an unsafe manner. This could lead to unauthorized access or denial of service, as the system might fail to authenticate users within the specified time frame.

**Fix steps:**
1. Upgrade the OpenSSH server to the latest version.
2. Apply any available security patches and updates.
3. Restart the OpenSSH server service to ensure the new version is in use.
4. Verify that the OpenSSH version is up to date.
5. Test the system to ensure it continues to function as expected.

**Verify:** Verify that the OpenSSH version is up to date and that the system is functioning correctly after the upgrade.

## PP-008: [P1] Apply vendor update on Remote access VPN (Citrix NetScaler) (CVE-2023-6548)

**Deadline:** fix within 48 hours  |  **Effort:** 1 h  |  **Risk score:** 96.0/100

**Why it matters:** This vulnerability allows an attacker to execute arbitrary code with low privileges on the management interface of the Citrix NetScaler VPN gateway, which is critical for this system as it opens a direct path to the management interface and can be exploited to gain unauthorized control over the system.

**Attacker scenario:** An attacker with access to the NetScaler's management interface could exploit this vulnerability to execute malicious code, potentially leading to unauthorized access to sensitive data or system takeover, compromising the integrity and confidentiality of the system.

**Fix steps:**
1. Apply the latest vendor update to the NetScaler gateway.
2. Ensure all patches are applied and the system is rebooted.
3. Verify that the management interface is secure and only accessible to authorized personnel.
4. Monitor the system for any suspicious activity after the update.
5. Restart the NetScaler gateway service to apply the update.

**Verify:** Verify that the management interface is secure and only accessible to authorized personnel after the update.

## PP-009: [P1] Install Exchange security update on Mail server (Exchange) (CVE-2021-26855)

**Deadline:** fix within 48 hours  |  **Effort:** 4 h  |  **Risk score:** 100/100

**Why it matters:** CVE-2021-26855 affects the Mail server (mail-01) which is internet-facing and a crown jewel system. This vulnerability allows attackers to execute arbitrary code, which could lead to full control of the system and potential data exfiltration.

**Attacker scenario:** An attacker could exploit this vulnerability to gain full control over the Mail server (mail-01), allowing them to read, modify, or delete any email and associated data, as well as execute arbitrary code with SYSTEM privileges.

**Fix steps:**
1. Install the Exchange security update
2. Restart the Exchange Server service
3. Verify that the update is installed
4. Restart the affected services
5. Test the system for any issues

**Verify:** Verify that the Exchange security update is installed and the system is functioning as expected