# Second Vector 

## SOC Incident Report

**Incident 87241:** A low-severity anonymous sign-in alert against a finance user was investigated and confirmed as an identity compromise involving business email compromise, mailbox persistence, cloud automation abuse, and targeted data theft.

---

## 1. Administrative & Metadata Summary

| Field                 | Details                                                   |
| --------------------- | --------------------------------------------------------- |
| Incident ID           | 87241                                                     |
| Hunt Name             | Second Vector                                             |
| Hunt Type             | Active Hunt — Microsoft Sentinel                          |
| Tier                  | T2                                                        |
| Analyst               | Nehal Patel                                               |
| Organisation          | LOG(N) Pacific                                            |
| Platform              | Microsoft Sentinel|
| Telemetry Source      | Microsoft 365 / Entra ID  / Defender XDR                                      |
| Investigation Window  | 2026-06-11 03:00 UTC to 2026-06-11 13:00 UTC              |
| Initial Severity      | Low                                                       |
| Final Severity        | High                                                      |
| Classification        | Confirmed Identity Compromise / Business Email Compromise |
| Status                | True Positive                                             |
| Primary Affected User | [m.smith@lognpacific.org](mailto:m.smith@lognpacific.org) |
| Primary Suspicious IP | 103.69.224.136                                            |
---
## 2. Executive Summary

Incident 87241 began as a low-severity anonymous sign-in alert against a finance user, **[m.smith@lognpacific.org](mailto:m.smith@lognpacific.org)**. Further investigation confirmed that the activity was not benign and represented a true identity compromise.

The attacker used the compromised account to access Microsoft 365 services, perform mailbox and directory reconnaissance, create suspicious mailbox rules, send a fraudulent banking update request, and download a small number of targeted files.

Although no malware or endpoint outage was observed, the incident was escalated to **High severity** because it involved business email compromise, mailbox persistence, cloud automation abuse, and potential exposure of sensitive credentials.

## 3. Hunt Scope

This hunt was performed in the **law-cyber-range** Microsoft Sentinel workspace and focused on Microsoft 365, Entra ID, Defender XDR, mailbox activity, cloud application activity, and Microsoft Graph activity.

The investigation started from **Defender XDR Incident 87241** and was expanded into Sentinel using KQL to correlate identity, email, mailbox, file, and cloud automation activity.

### In-Scope Data Sources

| Table                      | Purpose                                                                                         |
| -------------------------- | ----------------------------------------------------------------------------------------------- |
| SigninLogs                 | Entra ID sign-ins, authentication results, MFA, source IPs, apps, and Conditional Access status |
| AuditLogs                  | Entra ID directory and identity-object changes                                                  |
| CloudAppEvents             | Cloud app activity, file operations, mailbox activity, and service actions                      |
| OfficeActivity             | Microsoft 365 audit events, mailbox rules, and user activity                                    |
| MicrosoftGraphActivityLogs | Microsoft Graph API requests and programmatic tenant activity                                   |
| EmailEvents                | Defender for Office 365 mail flow, sent and received messages                                   |
| IdentityLogonEvents        | Defender for Identity account logon activity                                                    |
| BehaviorAnalytics          | UEBA signals and anomaly-based identity behavior                                                |

## 4. Incident Timeline

All timestamps are in **UTC**.

| Time             | Event                                                                                                      |
| ---------------- | ---------------------------------------------------------------------------------------------------------- |
| 2026-06-11 03:15 | Suspicious sign-in activity observed from `103.69.224.136`.                                                |
| 2026-06-11 03:28 | Mailbox rule **Invoice Processing** created to move messages from `j.reynolds@lognpacific.org` to Archive. |
| 2026-06-11 03:32 | Mailbox rule **Backup Copy** created to forward selected mail to `merovingian1337@proton.me`.              |
| 2026-06-11 03:37 | Three files were downloaded from the compromised user’s cloud storage.                                     |
| 2026-06-11 03:39 | File `yomark.pdf` was accessed but not downloaded.                                                         |
| 2026-06-11 03:41 | Entra ID Protection generated an anonymous IP risk event for Mark Smith.                                   |
| 2026-06-11 03:45 | Graph activity showed group membership enumeration using `/me/memberOf`.                                   |
| 2026-06-11 03:48 | Attacker accessed **Microsoft Flow Portal**.                                                               |
| 2026-06-11 03:51 | Successful sign-in recorded using `singleFactorAuthentication`.                                            |
| 2026-06-11 04:13 | Fraudulent email sent: **Updated Banking Details - Pacific IT Monthly**.                                   |
| 2026-06-11 04:17 | Same request was reinforced through **Microsoft Teams**.                                                   |
| 2026-06-11 12:40 | Reply from `j.reynolds@lognpacific.org` was received by the compromised mailbox.                           |
| 2026-06-11 12:41 | Microsoft Graph forward action fired through Power Automate / Microsoft Flow.                              |

## 5. Flag Analysis

### Flag 1 – Compromised Principal

**Objective:** Identify the account involved in the incident.
**Hypothesis:** The anonymous sign-in alert was tied to a specific finance user.

**KQL Query Used:**

```kql
SigninLogs
| where TimeGenerated between (datetime(2026-06-11 03:00:00) .. datetime(2026-06-11 13:00:00))
| where IPAddress == "103.69.224.136"
| where UserPrincipalName contains "smith"
| project TimeGenerated,UserPrincipalName
```

**Evidence Collected:** `m.smith@lognpacific.org`
**Final Finding:** The compromised principal was `m.smith@lognpacific.org`.

---

### Flag 2 – Flagged Source IP

**Objective:** Identify the source IP address of the flagged sign-in.
**Hypothesis:** The sign-in came from an unusual or anonymized external IP.

**KQL Query Used:**

```kql
SigninLogs
| where TimeGenerated between (datetime(2026-06-11 03:00:00) .. datetime(2026-06-11 13:00:00))
| where IPAddress == "103.69.224.136"
| where UserPrincipalName contains "smith"
| project TimeGenerated,UserPrincipalName,IPAddress
```

**Evidence Collected:** `103.69.224.136`
**Final Finding:** The flagged sign-in originated from `103.69.224.136`.

---

### Flag 3 – Client Operating System

**Objective:** Identify the client OS used during the suspicious sign-in.
**Hypothesis:** The attacker used a non-corporate or unmanaged device.

**KQL Query Used:**

```kql
SigninLogs
| where TimeGenerated between (datetime(2026-06-11 03:00:00) .. datetime(2026-06-11 13:00:00))
| where IPAddress == "103.69.224.136"
| where UserPrincipalName contains "smith"
| project TimeGenerated,UserPrincipalName,DeviceDetail
```

**Evidence Collected:** `Linux`, `Chrome 149.0.0`, unmanaged and non-compliant device.
**Final Finding:** The suspicious session used a Linux client.

---

### Flag 4 – Stored Detection Type

**Objective:** Identify the exact risk detection type stored by Entra ID.
**Hypothesis:** The alert was generated due to anonymized IP activity.

**KQL Query Used:**

```kql
AADUserRiskEvents
| where UserDisplayName contains "smith"
| where TimeGenerated between (datetime(2026-06-11 03:00:00) .. datetime(2026-06-11 13:00:00))
| project TimeGenerated,UserDisplayName,RiskEventType
```

**Evidence Collected:** `anonymizedIPAddress`
**Final Finding:** The stored detection type was `anonymizedIPAddress`.

---

### Flag 5 – Risk Verdict Review

**Objective:** Determine how the user’s risk detections were classified.
**Hypothesis:** Multiple detections may have been dismissed despite suspicious behavior.

**KQL Query Used:**

```kql
AADUserRiskEvents
| where UserDisplayName contains "smith"
| where TimeGenerated between (datetime(2026-06-11 03:00:00) .. datetime(2026-06-11 13:00:00))
| summarize count() by RiskState
```

**Evidence Collected:** `dismissed`, count `5`
**Final Finding:** Most risk detections ended in the `dismissed` state.

---

### Flag 6 – Live Account Exposure

**Objective:** Confirm the account status from the Defender XDR incident asset view.
**Hypothesis:** The account may still have been active during investigation.

**Query / Method Used:**

```text
Microsoft Defender Portal → Incidents & Alerts → Incidents → Select Incident 87241 → Assets → Users
```

**Evidence Collected:** Account status reviewed in Defender XDR.
**Final Finding:** The account status was verified from the Defender XDR incident asset record.

---

### Flag 7 – MFA Bypass Condition

**Objective:** Determine how the session succeeded despite MFA expectations.
**Hypothesis:** The session may have succeeded without MFA being enforced.

**KQL Query Used:**

```kql
SigninLogs
| where IPAddress == "103.69.224.136"
| where TimeGenerated between (datetime(2026-06-11 03:00:00) .. datetime(2026-06-11 13:00:00))
| where ResultType == 0
| project TimeGenerated,UserDisplayName,AuthenticationRequirement
```

**Evidence Collected:** `singleFactorAuthentication`
**Final Finding:** The suspicious session succeeded using single-factor authentication.

---

### Flag 8 – First Application Surface

**Objective:** Identify the app involved when the suspicious address interacted with Microsoft 365.
**Hypothesis:** One application allowed access while other attempts were blocked.

**KQL Query Used:**

```kql
SigninLogs
| where IPAddress == "103.69.224.136"
| where TimeGenerated between (datetime(2026-06-11 03:00:00) .. datetime(2026-06-11 13:00:00))
| where ResultType != 0
| order by TimeGenerated asc
| project TimeGenerated, ResultType, AppDisplayName
```

**Evidence Collected:** `One Outlook Web`
**Final Finding:** The application surface identified was `One Outlook Web`.

---

### Flag 9 – Failed Attempts Before Entry

**Objective:** Count bad-password failures before successful access.
**Hypothesis:** The attacker attempted credentials before gaining access.

**KQL Query Used:**

```kql
SigninLogs
| where TimeGenerated between (datetime(2026-06-11 00:00:00) .. datetime(2026-06-11 13:00:00))
| where IPAddress == "103.69.224.136"
| where Identity contains "smith"
| where ResultType == 50126
| order by TimeGenerated asc
| count
```

**Evidence Collected:** `2` bad-password failures.
**Final Finding:** There were 2 bad-password failures before successful activity.

---

### Flag 10 – Application Blast Radius

**Objective:** Count how many distinct apps the session accessed.
**Hypothesis:** One compromised session reached multiple Microsoft 365 services.

**KQL Query Used:**

```kql
SigninLogs
| where IPAddress == "103.69.224.136"
| where Identity contains "smith"
| where TimeGenerated between (datetime(2026-06-11 03:00:00) .. datetime(2026-06-11 13:00:00))
| where ResultType == 0
| distinct AppDisplayName
| count
```

**Evidence Collected:** `7` distinct applications.
**Final Finding:** The session accessed 7 distinct apps.

---

### Flag 11 – Session Correlation Identifier

**Objective:** Identify the session ID tying sign-in and later activity together.
**Hypothesis:** The activity belonged to one continuous attacker session.

**KQL Query Used:**

```kql
SigninLogs
| where IPAddress == "103.69.224.136"
| where Identity contains "smith"
| where TimeGenerated between (datetime(2026-06-11 03:00:00) .. datetime(2026-06-11 13:00:00))
| where ResultType == 0
| project TimeGenerated,SessionId,UserDisplayName
```

**Evidence Collected:** `005d431a-380b-1f5e-e554-16d5010dc28e`
**Final Finding:** The session identifier was `005d431a-380b-1f5e-e554-16d5010dc28e`.

---

### Flag 12 – MFA Posture Profiling

**Objective:** Identify the Graph report resource queried by the attacker.
**Hypothesis:** The attacker checked the victim’s MFA or authentication registration posture.

**KQL Query Used:**

```kql
MicrosoftGraphActivityLogs
| where TimeGenerated between (datetime(2026-06-11 03:00:00) .. datetime(2026-06-11 13:00:00))
| where RequestUri has "/reports/"
| project TimeGenerated, RequestUri
| order by TimeGenerated asc
```

**Evidence Collected:** `userRegistrationDetails`
**Final Finding:** The attacker queried `userRegistrationDetails`.

---

### Flag 13 – Group Enumeration

**Objective:** Identify the Graph request used to enumerate group membership.
**Hypothesis:** The attacker checked what groups the compromised user belonged to.

**KQL Query Used:**

```kql
MicrosoftGraphActivityLogs
| where TimeGenerated between (datetime(2026-06-11 03:00:00) .. datetime(2026-06-11 13:00:00))
| where RequestUri endswith "memberof"
| project TimeGenerated, RequestUri
| order by TimeGenerated asc
```

**Evidence Collected:** `/me/memberOf`
**Final Finding:** The attacker enumerated group membership using `/me/memberOf`.

---

### Flag 14 – Fraudulent Email Request

**Objective:** Identify the fraudulent payment-related email.
**Hypothesis:** The attacker used the compromised mailbox to redirect payment information.

**KQL Query Used:**

```kql
EmailEvents
| where TimeGenerated between (datetime(2026-06-11 03:00:00) .. datetime(2026-06-11 13:00:00))
| where SenderDisplayName contains "smith"
| where Subject has_any ("bank", "payment", "invoice", "details", "update", "account")
| project TimeGenerated, SenderFromAddress, RecipientEmailAddress, Subject
| order by TimeGenerated asc
```

**Evidence Collected:** `Updated Banking Details - Pacific IT Monthly`
**Final Finding:** The fraudulent email subject was `Updated Banking Details - Pacific IT Monthly`.

---

### Flag 15 – Mined Payment Thread

**Objective:** Identify the older thread used for payment-process reconnaissance.
**Hypothesis:** The attacker read historical finance mail to make the fraud believable.

**KQL Query Used:**

```kql
EmailEvents
| where TimeGenerated between (datetime(2026-01-11 03:00:00) .. datetime(2026-06-11 13:00:00))
| where SenderDisplayName contains "smith"
| where Subject has_any ("bank", "payment", "invoice", "details", "update", "account")
| project TimeGenerated, SenderFromAddress, RecipientEmailAddress, Subject
| order by TimeGenerated asc
```

**Evidence Collected:** `Re: Q1 Vendor Payment Schedule - Review Required`
**Final Finding:** The attacker mined the older payment thread `Re: Q1 Vendor Payment Schedule - Review Required`.

---

### Flag 16 – Fraud Target

**Objective:** Identify who received the fraudulent request.
**Hypothesis:** The attacker targeted an internal payment or approval contact.

**KQL Query Used:**

```kql
EmailEvents
| where TimeGenerated between (datetime(2026-06-11 03:00:00) .. datetime(2026-06-11 13:00:00))
| where Subject == "Updated Banking Details - Pacific IT Monthly"
| where SenderFromAddress contains "smith"
| project TimeGenerated, SenderFromAddress, RecipientEmailAddress, Subject
| order by TimeGenerated asc
```

**Evidence Collected:** `j.reynolds@lognpacific.org`
**Final Finding:** The fraud target was `j.reynolds@lognpacific.org`.

---

### Flag 17 – Second Communication Channel

**Objective:** Identify the second service used to reinforce the fraud.
**Hypothesis:** The attacker used another trusted channel besides email.

**KQL Query Used:**

```kql
CloudAppEvents
| where TimeGenerated between (datetime(2026-06-11 03:00:00) .. datetime(2026-06-11 13:00:00))
| where AccountDisplayName contains "smith"
| where ActionType contains "sent"
| project TimeGenerated, ActionType, Application
```

**Evidence Collected:** `Microsoft Teams`
**Final Finding:** The attacker reinforced the request through Microsoft Teams.

---

### Flag 18 – Concealment Mailbox Rule

**Objective:** Identify the mailbox rule used to hide replies.
**Hypothesis:** The attacker created a rule to move suspicious replies out of view.

**KQL Query Used:**

```kql
OfficeActivity
| where TimeGenerated between (datetime(2026-06-11 03:00:00) .. datetime(2026-06-11 13:00:00))
| where UserId contains "smith"
| where Operation contains "rule"
| project TimeGenerated,Operation,Parameters
```

**Evidence Collected:** Rule name `Invoice Processing`; messages from `j.reynolds@lognpacific.org` moved to `Archive`.
**Final Finding:** The concealment rule was named `Invoice Processing`.

---

### Flag 19 – Reason for Moving Instead of Deleting

**Objective:** Explain why the attacker moved mail instead of deleting it.
**Hypothesis:** Moving mail is quieter and less suspicious than deleting it.

**Query / Method Used:**

```text
Analyst review of mailbox rule parameters from OfficeActivity.
```

**Evidence Collected:** Mail was moved to the normal-looking `Archive` folder.
**Final Finding:** Moving mail avoided suspicion while hiding replies from the user’s inbox.

---

### Flag 20 – External Forwarding Rule

**Objective:** Identify the external destination used by the second mailbox rule.
**Hypothesis:** The attacker created a forwarding rule for selected inbound mail.

**KQL Query Used:**

```kql
OfficeActivity
| where TimeGenerated between (datetime(2026-06-11 03:00:00) .. datetime(2026-06-11 13:00:00))
| where UserId contains "smith"
| where Operation contains "rule"
| project TimeGenerated,Operation,Parameters
```

**Evidence Collected:** `merovingian1337@proton.me`
**Final Finding:** Selected mail was forwarded externally to `merovingian1337@proton.me`.

---

### Flag 21 – Purpose of Targeted Rules

**Objective:** Explain why both mailbox rules targeted the same sender.
**Hypothesis:** The rules were designed to suppress replies from the fraud target.

**Query / Method Used:**

```text
Analyst correlation between the fraud recipient in EmailEvents and mailbox rule parameters in OfficeActivity.
```

**Evidence Collected:** Both rules targeted mail from `j.reynolds@lognpacific.org`.
**Final Finding:** The rules were created to hide finance replies that could expose the fake payment request.

---

### Flag 22 – Exfiltration Operation

**Objective:** Identify the operation showing data was taken out.
**Hypothesis:** The attacker downloaded files instead of only viewing them.

**KQL Query Used:**

```kql
CloudAppEvents
| where TimeGenerated between (datetime(2026-06-11 03:00:00) .. datetime(2026-06-11 13:00:00))
| where AccountDisplayName contains "smith"
| where ActionType contains "download"
| project TimeGenerated,AccountDisplayName,ActionType
| order by TimeGenerated asc
```

**Evidence Collected:** `FileDownloaded`
**Final Finding:** The exfiltration operation was `FileDownloaded`, showing files were copied out rather than only accessed.

---

### Flag 23 – Volume of Files Taken

**Objective:** Count the number of files downloaded during the session.
**Hypothesis:** The attacker performed targeted theft rather than bulk exfiltration.

**KQL Query Used:**

```kql
CloudAppEvents
| where TimeGenerated between (datetime(2026-06-11 03:00:00) .. datetime(2026-06-11 13:00:00))
| where AccountDisplayName contains "smith"
| where ActionType contains "download"
| project TimeGenerated,AccountDisplayName,ActionType
| order by TimeGenerated asc
```

**Evidence Collected:** `3` file download events.
**Final Finding:** The attacker downloaded 3 files, indicating a small and targeted pull rather than mass exfiltration.

---

### Flag 24 – Credential Document

**Objective:** Identify the downloaded file that widened the incident scope.
**Hypothesis:** One downloaded file contained credentials or access information.

**KQL Query Used:**

```kql
CloudAppEvents
| where TimeGenerated between (datetime(2026-06-11 03:00:00) .. datetime(2026-06-11 13:00:00))
| where AccountDisplayName contains "smith"
| where ActionType contains "download"
| project TimeGenerated,AccountDisplayName,ActionType,ObjectName
| order by TimeGenerated asc
```

**Evidence Collected:** `VPN-Access-Credentials.txt`
**Final Finding:** The attacker downloaded `VPN-Access-Credentials.txt`.

---

### Flag 25 – Credential Vault Pointer

**Objective:** Identify the accessed file that pointed toward a credential store.
**Hypothesis:** The attacker opened a file that may guide access to additional secrets.

**KQL Query Used:**

```kql
CloudAppEvents
| where TimeGenerated between (datetime(2026-06-11 03:00:00) .. datetime(2026-06-11 13:00:00))
| where AccountDisplayName contains "smith"
| where ActionType contains "access"
| project TimeGenerated,AccountDisplayName,ActionType,ObjectName
| order by TimeGenerated asc
```

**Evidence Collected:** `yomark.pdf`
**Final Finding:** The attacker accessed `yomark.pdf` but did not download it.

---

### Flag 26 – MFA Satisfaction Count

**Objective:** Determine whether MFA was actually satisfied during the session.
**Hypothesis:** The VPN explanation is false if MFA was never satisfied.

**KQL Query Used:**

```kql
SigninLogs
| where TimeGenerated between (datetime(2026-06-11 03:00:00) .. datetime(2026-06-11 13:00:00))
| where UserPrincipalName contains "smith"
| where AuthenticationRequirement contains "multi"
| where ResultSignature contains "SUCCESS"
| summarize count() by AuthenticationRequirement
```

**Evidence Collected:** `0` successful MFA satisfactions.
**Final Finding:** MFA was satisfied 0 times, disproving the benign VPN explanation.

---

### Flag 27 – Suspicious Automation Surface

**Objective:** Identify the app used to build or trigger automation.
**Hypothesis:** The attacker accessed an app not normally used by a finance user.

**KQL Query Used:**

```kql
SigninLogs
| where TimeGenerated between (datetime(2026-06-11 03:00:00) .. datetime(2026-06-11 13:00:00))
| where UserPrincipalName contains "smith"
| distinct AppDisplayName
```

**Evidence Collected:** `Microsoft Flow Portal`
**Final Finding:** The attacker accessed Microsoft Flow Portal.

---

### Flag 28 – Table Recording the Forward Trigger

**Objective:** Identify where the real forward trigger was recorded.
**Hypothesis:** The forward was caused by a Graph/API action, not a normal user action.

**KQL Query Used:**

```kql
MicrosoftGraphActivityLogs
| where RequestUri has_any ("forward", "createForward", "sendMail")
| where TimeGenerated between (datetime(2026-06-11T03:00:00Z) .. datetime(2026-06-11T13:00:00Z))
| project TimeGenerated, RequestUri, IPAddress
| order by TimeGenerated asc
```

**Evidence Collected:** `MicrosoftGraphActivityLogs`
**Final Finding:** The forward trigger was recorded in `MicrosoftGraphActivityLogs`.

---

### Flag 29 – Forwarding Sequence

**Objective:** Compare the mail event and Graph API forward event.
**Hypothesis:** The mail arrived first, then automation forwarded it.

**KQL Query Used:**

```kql
// 1. Graph API operations
MicrosoftGraphActivityLogs
| where RequestUri has_any ("forward", "createForward", "sendMail")
| where TimeGenerated between (datetime(2026-06-11T03:00:00Z) .. datetime(2026-06-11T13:00:00Z))
| project TimeGenerated, RequestUri, IPAddress
| order by TimeGenerated asc

// 2. Mail events
EmailEvents
| where RecipientEmailAddress =~ "m.smith@lognpacific.org"
| where SenderFromAddress contains "reynolds"
| where TimeGenerated between (datetime(2026-06-11T03:00:00Z) .. datetime(2026-06-11T13:00:00Z))
| where Subject contains "banking"
| project TimeGenerated, RecipientEmailAddress, SenderFromAddress, Subject
```

**Evidence Collected:** Mail event at `12:40:49 UTC`; Graph forward call at `12:41:09 UTC`.
**Final Finding:** The mail event came first, followed by the Graph forward call.

---

### Flag 30 – Forward Source IP

**Objective:** Identify the IP address that triggered the forward call.
**Hypothesis:** The forward came from cloud automation, not the original attacker IP.

**KQL Query Used:**

```kql
MicrosoftGraphActivityLogs
| where RequestUri has_any ("forward", "createForward", "sendMail")
| where TimeGenerated between (datetime(2026-06-11T03:00:00Z) .. datetime(2026-06-11T13:00:00Z))
| project TimeGenerated, RequestUri, IPAddress
| order by TimeGenerated asc
```

**Evidence Collected:** `20.150.129.194`
**Final Finding:** The forward call came from `20.150.129.194`.

---

### Flag 31 – Automation App Identity

**Objective:** Identify the app ID used in the forward call.
**Hypothesis:** A Microsoft cloud automation app identity signed the request.

**KQL Query Used:**

```kql
MicrosoftGraphActivityLogs
| where RequestUri has_any ("forward", "createForward", "sendMail")
| where TimeGenerated between (datetime(2026-06-11T03:00:00Z) .. datetime(2026-06-11T13:00:00Z))
| project TimeGenerated, RequestUri, IPAddress, AppId
| order by TimeGenerated asc
```

**Evidence Collected:** `7ab7862c-4c57-491e-8a45-d52a7e023983`
**Final Finding:** The app ID was `7ab7862c-4c57-491e-8a45-d52a7e023983`.

---

### Flag 32 – Abused Cloud Service

**Objective:** Name the Microsoft 365 service abused to forward mail.
**Hypothesis:** Power Automate / Microsoft Flow was used for persistence or automation.

**KQL Query Used:**

```kql
MicrosoftGraphActivityLogs
| where RequestUri has_any ("forward", "createForward", "sendMail")
| where TimeGenerated between (datetime(2026-06-11T03:00:00Z) .. datetime(2026-06-11T13:00:00Z))
| project TimeGenerated, RequestUri, IPAddress, AppId, UserAgent
| order by TimeGenerated asc
```

**Evidence Collected:** `azure-logic-apps/1.0`, `microsoft-flow/1.0`
**Final Finding:** The abused service was Power Automate / Microsoft Flow.

---

### Flag 33 – Actor IP Across Log Sources

**Objective:** Count how many distinct in-scope log sources contained the actor IP.
**Hypothesis:** The same IP appeared across multiple telemetry sources, linking activity to one actor.

**KQL Query Used:**

```kql
SigninLogs
| where TimeGenerated between (datetime(2026-06-10) .. datetime(2026-06-20 23:59:59))
| where IPAddress == "103.69.224.136"
| take 1

AADUserRiskEvents
| where TimeGenerated between (datetime(2026-06-10) .. datetime(2026-06-20 23:59:59))
| where tostring(IpAddress) == "103.69.224.136"
| take 1 

SecurityAlert
| where TimeGenerated between (datetime(2026-06-10) .. datetime(2026-06-20 23:59:59))
| where tostring(Entities) has "103.69.224.136"
      or tostring(CompromisedEntity) has "103.69.224.136"
| take 1

OfficeActivity
| where TimeGenerated between (datetime(2026-06-10) .. datetime(2026-06-20 23:59:59))
| where tostring(ClientIP) == "103.69.224.136"
| take 1

EmailEvents
| where TimeGenerated between (datetime(2026-06-10) .. datetime(2026-06-20 23:59:59))
| where tostring(SenderIPv4) == "103.69.224.136"
| take 1

CloudAppEvents
| where TimeGenerated between (datetime(2026-06-10) .. datetime(2026-06-20 23:59:59))
| where tostring(IPAddress) == "103.69.224.136"
| take 1

MicrosoftGraphActivityLogs
| where TimeGenerated between (datetime(2026-06-10) .. datetime(2026-06-20 23:59:59))
| where tostring(IPAddress) == "103.69.224.136"
| take 1
```

**Evidence Collected:** `7` distinct log sources.
**Final Finding:** The actor IP appeared in 7 distinct in-scope log sources.

---

### Flag 34 – First Containment Action

**Objective:** Identify the first action required before deleting rules or flows.
**Hypothesis:** The attacker could return if active sessions remain valid.

**Query / Method Used:**

```text
Incident response decision based on active session and token persistence risk.
```

**Evidence Collected:** Existing sessions and refresh tokens can survive simple cleanup.
**Final Finding:** Revoke active sessions first.

---

### Flag 35 – Flow Removal Location

**Objective:** Identify where the malicious flow should be removed.
**Hypothesis:** Sentinel and Exchange rules do not manage Power Automate flows.

**Query / Method Used:**

```text
Power Platform Admin Center review.
```

**Evidence Collected:** Power Automate flows are managed through the Power Platform Admin Center.
**Final Finding:** The flow should be removed from the Power Platform Admin Center.

---

### Flag 36 – Conditional Access Failure

**Objective:** Determine what Conditional Access did during the suspicious sign-ins.
**Hypothesis:** A foreign single-factor sign-in should have been blocked or challenged.

**Query / Method Used:**

```text
SigninLogs were reviewed for Conditional Access results on the suspicious sign-ins.
```

**Evidence Collected:** `notApplied`
**Final Finding:** Conditional Access did not apply, which allowed the suspicious single-factor sign-in.

---

### Flag 37 – Why Password Reset Alone Is Not Enough

**Objective:** Explain why password reset alone would not fully contain the attacker.
**Hypothesis:** Active sessions or refresh tokens may remain valid after a password reset.

**Query / Method Used:**

```text
Incident response decision based on session and refresh token behavior.
```

**Evidence Collected:** Existing sessions can remain valid unless revoked.
**Final Finding:** Revoke sessions first to invalidate refresh tokens, then reset the password.


## 6. Indicators of Compromise (IoCs)

The following indicators were identified during the investigation and used to correlate the suspicious activity across Microsoft 365, Entra ID, mailbox, Graph, and cloud app logs.

| Indicator Type              | Indicator                                          | Description                                                                       |
| --------------------------- | -------------------------------------------------- | --------------------------------------------------------------------------------- |
| Compromised User            | `m.smith@lognpacific.org`                          | Finance user account involved in the incident                                     |
| User Display Name           | `Mark Smith`                                       | Display name of the affected account                                              |
| Suspicious Source IP        | `103.69.224.136`                                   | Primary IP address used during the suspicious sign-in activity                    |
| Automation Source IP        | `20.150.129.194`                                   | IP address associated with the Graph forward action                               |
| External Forwarding Address | `merovingian1337@proton.me`                        | External email address used in the mailbox forwarding rule                        |
| Fraud Target                | `j.reynolds@lognpacific.org`                       | Internal recipient of the fraudulent payment request                              |
| Session ID                  | `005d431a-380b-1f5e-e554-16d5010dc28e`             | Session identifier linked to the suspicious sign-in                               |
| App ID                      | `7ab7862c-4c57-491e-8a45-d52a7e023983`             | App identity associated with the Graph forward activity                           |
| Mailbox Rule                | `Invoice Processing`                               | Rule used to move selected mail to Archive                                        |
| Mailbox Rule                | `Backup Copy`                                      | Rule used to forward selected mail externally                                     |
| Fraud Email Subject         | `Updated Banking Details - Pacific IT Monthly`     | Subject line of the fraudulent payment redirection email                          |
| Mined Email Thread          | `Re: Q1 Vendor Payment Schedule - Review Required` | Older finance thread used for payment-process reconnaissance                      |
| Downloaded File             | `VPN-Access-Credentials.txt`                       | Credential-related file downloaded during the session                             |
| Accessed File               | `yomark.pdf`                                       | File accessed during the session, likely used for additional credential discovery |
| Suspicious App              | `Microsoft Flow Portal`                            | Automation platform accessed during the suspicious session                        |
| Abused Service              | `Power Automate / Microsoft Flow`                  | Service used to trigger automated mail forwarding                                 |
| User Agent                  | `azure-logic-apps/1.0`, `microsoft-flow/1.0`       | User-agent values linked to automated Graph forwarding activity                   |

### IoC Summary

The strongest indicators in this case were the suspicious IP `103.69.224.136`, the compromised account `m.smith@lognpacific.org`, the external forwarding address `merovingian1337@proton.me`, and the Power Automate activity linked to the Graph forward call. These indicators connected the sign-in activity, mailbox persistence, fraud attempt, data theft, and automation-based forwarding into one confirmed compromise.

## 7. MITRE ATT&CK Mapping by Flag

| Flag    | Finding                                                          | ATT&CK Tactic                         | Technique ID          | Technique Name                              | Mapping Reason                                                                                        |
| ------- | ---------------------------------------------------------------- | ------------------------------------- | --------------------- | ------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| Flag 1  | Compromised principal identified as `m.smith@lognpacific.org`    | Initial Access / Defense Evasion      | T1078.004             | Valid Accounts: Cloud Accounts              | The attacker used a legitimate Microsoft 365 cloud account.                                           |
| Flag 2  | Suspicious source IP `103.69.224.136`                            | Initial Access / Defense Evasion      | T1078.004             | Valid Accounts: Cloud Accounts              | The IP was tied to successful use of the compromised cloud account.                                   |
| Flag 3  | Client OS identified as Linux                                    | Supporting Evidence                   | N/A                   | Contextual Telemetry                        | The OS helped profile the suspicious session but is not a standalone ATT&CK technique.                |
| Flag 4  | Detection type was `anonymizedIPAddress`                         | Defense Evasion                       | T1090                 | Proxy                                       | The sign-in came from an anonymized source, suggesting use of proxy/VPN-style infrastructure.         |
| Flag 5  | Risk state was mostly `dismissed`                                | Supporting Evidence                   | N/A                   | Detection Verdict Review                    | This shows a detection/process gap, not a direct attacker technique.                                  |
| Flag 6  | Account exposure checked in Defender XDR                         | Supporting Evidence                   | N/A                   | Asset Status Review                         | This was used to validate live exposure, not map attacker behavior.                                   |
| Flag 7  | Session succeeded with `singleFactorAuthentication`              | Initial Access                        | T1078.004             | Valid Accounts: Cloud Accounts              | The attacker authenticated successfully using the compromised cloud account without MFA satisfaction. |
| Flag 8  | Application surface identified as `One Outlook Web`              | Initial Access                        | T1078.004             | Valid Accounts: Cloud Accounts              | The attacker accessed Microsoft 365 through a legitimate application surface.                         |
| Flag 9  | Two bad-password failures before entry                           | Credential Access                     | T1110.001             | Brute Force: Password Guessing              | Failed password attempts suggest credential guessing or attempted account access.                     |
| Flag 10 | Session accessed 7 distinct apps                                 | Defense Evasion / Persistence         | T1078.004             | Valid Accounts: Cloud Accounts              | The same valid cloud account was used across multiple Microsoft 365 apps.                             |
| Flag 11 | Session ID linked sign-in and later activity                     | Supporting Evidence                   | N/A                   | Session Correlation                         | The session ID linked attacker activity but is not itself a technique.                                |
| Flag 12 | Queried `userRegistrationDetails`                                | Discovery                             | T1087.004             | Account Discovery: Cloud Account            | The attacker profiled cloud account authentication/MFA posture.                                       |
| Flag 13 | Queried `/me/memberOf`                                           | Discovery                             | T1069.003             | Permission Groups Discovery: Cloud Groups   | The attacker enumerated the victim’s cloud group membership.                                          |
| Flag 14 | Fraud email sent: `Updated Banking Details - Pacific IT Monthly` | Lateral Movement / Social Engineering | T1534                 | Internal Spearphishing                      | The compromised account was used to send a trusted internal fraudulent request.                       |
| Flag 15 | Older payment thread was mined                                   | Collection                            | T1114.002             | Remote Email Collection                     | The attacker reviewed historical mailbox content to understand payment processes.                     |
| Flag 16 | Fraud target identified as `j.reynolds@lognpacific.org`          | Lateral Movement / Social Engineering | T1534                 | Internal Spearphishing                      | The attacker targeted an internal user from the compromised account.                                  |
| Flag 17 | Request reinforced through Microsoft Teams                       | Social Engineering                    | T1684.001             | Social Engineering: Impersonation           | The attacker impersonated the compromised finance user through a second communication channel.        |
| Flag 18 | Mailbox rule `Invoice Processing` created                        | Defense Evasion                       | T1564.008             | Hide Artifacts: Email Hiding Rules          | The rule moved replies to Archive to hide them from the user.                                         |
| Flag 19 | Mail was moved instead of deleted                                | Defense Evasion                       | T1564.008             | Hide Artifacts: Email Hiding Rules          | Moving mail to a normal folder reduced suspicion while hiding evidence.                               |
| Flag 20 | Rule forwarded mail to `merovingian1337@proton.me`               | Collection / Persistence              | T1114.003             | Email Collection: Email Forwarding Rule     | A mailbox rule was created to forward selected mail outside the organization.                         |
| Flag 21 | Both rules targeted `j.reynolds@lognpacific.org`                 | Defense Evasion / Collection          | T1564.008 / T1114.003 | Email Hiding Rules / Email Forwarding Rule  | The rules suppressed and forwarded replies that could expose the fraud.                               |
| Flag 22 | Operation identified as `FileDownloaded`                         | Collection                            | T1530                 | Data from Cloud Storage                     | The attacker downloaded files from the user’s cloud storage.                                          |
| Flag 23 | Three files downloaded                                           | Collection                            | T1530                 | Data from Cloud Storage                     | A small number of targeted files were pulled from cloud storage.                                      |
| Flag 24 | `VPN-Access-Credentials.txt` downloaded                          | Credential Access                     | T1552.001             | Unsecured Credentials: Credentials In Files | The downloaded file appeared to contain credential or access information.                             |
| Flag 25 | `yomark.pdf` accessed as possible vault pointer                  | Credential Access                     | T1552.001             | Unsecured Credentials: Credentials In Files | The accessed file may have pointed to additional credential material.                                 |
| Flag 26 | MFA satisfied 0 times                                            | Supporting Evidence                   | T1078.004             | Valid Accounts: Cloud Accounts              | This disproved benign VPN use and supported valid account compromise.                                 |
| Flag 27 | Microsoft Flow Portal accessed                                   | Persistence / Exfiltration            | T1020                 | Automated Exfiltration                      | The attacker accessed an automation platform later tied to mail forwarding.                           |
| Flag 28 | Forward trigger found in `MicrosoftGraphActivityLogs`            | Exfiltration                          | T1020                 | Automated Exfiltration                      | The forward was triggered programmatically through Graph activity.                                    |
| Flag 29 | Mail event occurred before Graph forward call                    | Exfiltration                          | T1020                 | Automated Exfiltration                      | The sequence showed automation forwarded mail after it arrived.                                       |
| Flag 30 | Forward source IP was `20.150.129.194`                           | Exfiltration                          | T1567                 | Exfiltration Over Web Service               | The forward came from cloud service infrastructure rather than the original sign-in IP.               |
| Flag 31 | App ID identified as `7ab7862c-4c57-491e-8a45-d52a7e023983`      | Exfiltration / Persistence            | T1020                 | Automated Exfiltration                      | The Graph forward call was signed by an app identity linked to automation.                            |
| Flag 32 | Abused service identified as Power Automate / Microsoft Flow     | Exfiltration / Persistence            | T1020                 | Automated Exfiltration                      | Power Automate was used to trigger forwarding without the user being actively online.                 |
| Flag 33 | Actor IP appeared across 7 log sources                           | Supporting Evidence                   | N/A                   | Cross-Source Correlation                    | This linked activity across telemetry sources but is not an ATT&CK technique.                         |
| Flag 34 | First containment action: revoke active sessions                 | Response Action                       | N/A                   | Containment                                 | This is a defensive response step, not attacker behavior.                                             |
| Flag 35 | Malicious flow removed from Power Platform Admin Center          | Response Action                       | N/A                   | Eradication                                 | This identifies where to remove the abused automation.                                                |
| Flag 36 | Conditional Access result was `notApplied`                       | Supporting Evidence                   | T1078.004             | Valid Accounts: Cloud Accounts              | The control gap allowed the valid cloud account session to succeed.                                   |
| Flag 37 | Revoke sessions before password reset                            | Response Action                       | N/A                   | Containment                                 | Active tokens/sessions must be invalidated before password reset is considered effective.             |

### ATT&CK Summary

The attacker primarily relied on valid cloud account abuse instead of malware. After gaining access to `m.smith@lognpacific.org`, the actor performed account and group discovery, reviewed mailbox content, created mailbox rules for hiding and forwarding mail, attempted internal payment fraud, downloaded targeted cloud files, and abused Power Automate / Microsoft Flow to continue forwarding mail through automation.

The strongest ATT&CK techniques observed were:

* **T1078.004 — Valid Accounts: Cloud Accounts**
* **T1110.001 — Brute Force: Password Guessing**
* **T1087.004 — Account Discovery: Cloud Account**
* **T1069.003 — Permission Groups Discovery: Cloud Groups**
* **T1114.002 — Remote Email Collection**
* **T1114.003 — Email Forwarding Rule**
* **T1564.008 — Email Hiding Rules**
* **T1530 — Data from Cloud Storage**
* **T1552.001 — Credentials In Files**
* **T1020 — Automated Exfiltration**
* **T1567 — Exfiltration Over Web Service**
* **T1534 — Internal Spearphishing**
* **T1684.001 — Social Engineering: Impersonation**
  
## 8. Recommendations

* Revoke active sessions for the compromised user before resetting the password.
* Remove malicious mailbox rules such as `Invoice Processing` and `Backup Copy`.
* Delete unauthorized Power Automate / Microsoft Flow workflows from Power Platform Admin Center.
* Block or monitor suspicious IPs, including `103.69.224.136` and `20.150.129.194`.
* Investigate external forwarding to `merovingian1337@proton.me`.
* Disable unapproved external email forwarding across the tenant.
* Rotate any credentials exposed in `VPN-Access-Credentials.txt`.
* Enforce Conditional Access for finance users, unmanaged devices, anonymized IPs, and single-factor sign-ins.
* Audit Graph `/forward`, mailbox rule creation, and Power Automate activity for similar behavior.
* Require out-of-band verification for all banking detail or payment changes.





