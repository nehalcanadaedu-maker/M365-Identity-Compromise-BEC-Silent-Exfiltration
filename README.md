Absolutely — here is a **clean, GitHub‑ready Markdown block** with **time ranges added for every flag**, matching the structure you requested:

✔ Objective  
✔ Hypothesis  
✔ Query Used  
✔ **Time Range** (new)

You can paste this directly into your README.

---

# 📌 **FLAG 1 — Initial Sign‑In Source**

### **Objective**  
Identify the first successful sign‑in associated with the suspicious activity.

### **Hypothesis**  
The attacker’s initial foothold will appear as the earliest successful login from the flagged IP.

### **Time Range**  
`2026‑06‑11 03:00 → 2026‑06‑11 13:00 UTC`

### **Query Used**
```kql
SigninLogs
| where TimeGenerated between (datetime(2026-06-11 03:00:00) .. datetime(2026-06-11 13:00:00))
| where IPAddress == "103.69.224.136"
| where Identity contains "smith"
| where ResultType == 0
| order by TimeGenerated asc
```

---

# 📌 **FLAG 2 — Source IP Identification**

### **Objective**  
Determine the IP address associated with the suspicious sign‑in.

### **Hypothesis**  
The flagged sign‑in originates from a non‑trusted, external IP not associated with the user’s normal behavior.

### **Time Range**  
`2026‑06‑11 03:00 → 2026‑06‑11 13:00 UTC`

### **Query Used**
```kql
SigninLogs
| where TimeGenerated between (datetime(2026-06-11 03:00:00) .. datetime(2026-06-11 13:00:00))
| where Identity contains "smith"
| project TimeGenerated, IPAddress, ResultType
```

---

# 📌 **FLAG 3 — Detection Type (Risk Telemetry)**

### **Objective**  
Identify the detection type stored in risk telemetry for the incident.

### **Hypothesis**  
The risk detection type will reveal whether the login was flagged due to unfamiliar location, impossible travel, or atypical behavior.

### **Time Range**  
`All available risk events (no time filter required)`

### **Query Used**
```kql
IdentityRiskEvents
| where UserPrincipalName contains "smith"
| project DetectionType
```

---

# 📌 **FLAG 4 — Risk State Aggregation**

### **Objective**  
Aggregate all risk detections for the user and determine the most common risk state.

### **Hypothesis**  
Multiple detections will share a common state (e.g., “atRisk”, “remediated”, “dismissed”).

### **Time Range**  
`All available risk events (no time filter required)`

### **Query Used**
```kql
IdentityRiskEvents
| where UserPrincipalName contains "smith"
| summarize count() by RiskState
```

---

# 📌 **FLAG 5 — First Successful App**

### **Objective**  
Identify which application was used for the first successful sign‑in.

### **Hypothesis**  
The attacker will target a high‑value app first, such as Outlook Web.

### **Time Range**  
`2026‑06‑11 03:00 → 2026‑06‑11 13:00 UTC`

### **Query Used**
```kql
SigninLogs
| where TimeGenerated between (datetime(2026-06-11 03:00:00) .. datetime(2026-06-11 13:00:00))
| where IPAddress == "103.69.224.136"
| where Identity contains "smith"
| where ResultType == 0
| order by TimeGenerated asc
| take 1
| project AppDisplayName
```

---

# 📌 **FLAG 6 — Investigation Time Window**

### **Objective**  
Determine the correct time window for analyzing the attacker’s activity.

### **Hypothesis**  
All malicious activity will fall between the first success and the end of the session.

### **Time Range**  
`2026‑06‑11 03:00 → 2026‑06‑11 13:00 UTC`

### **Query Used**
```kql
SigninLogs
| where IPAddress == "103.69.224.136"
| where Identity contains "smith"
| project TimeGenerated
| order by TimeGenerated asc
```

---

# 📌 **FLAG 7 — Successful Sign‑Ins in Window**

### **Objective**  
List all successful sign‑ins within the investigation window.

### **Hypothesis**  
The attacker reused the same session token to access multiple apps without MFA prompts.

### **Time Range**  
`2026‑06‑11 03:00 → 2026‑06‑11 13:00 UTC`

### **Query Used**
```kql
SigninLogs
| where TimeGenerated between (datetime(2026-06-11 03:00:00) .. datetime(2026-06-11 13:00:00))
| where IPAddress == "103.69.224.136"
| where Identity contains "smith"
| where ResultType == 0
```

---

# 📌 **FLAG 8 — Bad Password Attempts Before Entry**

### **Objective**  
Count the number of bad‑password failures before the first successful login.

### **Hypothesis**  
The attacker attempted multiple incorrect passwords before gaining access.

### **Time Range**  
`Expanded backward: 2026‑06‑11 00:00 → 2026‑06‑11 03:00 UTC`

### **Query Used**
```kql
SigninLogs
| where TimeGenerated between (datetime(2026-06-11 00:00:00) .. datetime(2026-06-11 03:00:00))
| where IPAddress == "103.69.224.136"
| where Identity contains "smith"
| where ResultType == 50126
| count
```

---

# 📌 **FLAG 9 — Blast Radius (Distinct Apps)**

### **Objective**  
Determine how many distinct apps the attacker accessed using the same session token.

### **Hypothesis**  
The attacker pivoted laterally across multiple M365 apps without re‑authentication.

### **Time Range**  
`2026‑06‑11 03:00 → 2026‑06‑11 13:00 UTC`

### **Query Used**
```kql
SigninLogs
| where TimeGenerated between (datetime(2026-06-11 03:00:00) .. datetime(2026-06-11 13:00:00))
| where IPAddress == "103.69.224.136"
| where Identity contains "smith"
| where ResultType == 0
| summarize dcount(AppDisplayName)
```

---

# 📌 **FLAG 10 — First Success Timestamp**

### **Objective**  
Capture the timestamp of the first successful login to anchor the session timeline.

### **Hypothesis**  
All subsequent malicious activity will occur after this timestamp.

### **Time Range**  
`2026‑06‑11 03:00 → 2026‑06‑11 13:00 UTC`

### **Query Used**
```kql
SigninLogs
| where TimeGenerated between (datetime(2026-06-11 03:00:00) .. datetime(2026-06-11 13:00:00))
| where IPAddress == "103.69.224.136"
| where Identity contains "smith"
| where ResultType == 0
| order by TimeGenerated asc
| take 1
| project TimeGenerated
```

---

# 📌 **FLAG 11 — Session Correlation (SessionId)**

### **Objective**  
Identify the session identifier shared between the sign‑in and later activity.

### **Hypothesis**  
A single SessionId will appear in both SigninLogs and AuditLogs, proving continuous attacker activity.

### **Time Range**  
`2026‑06‑11 03:00 → 2026‑06‑11 13:00 UTC`

### **Query Used — Sign‑In**
```kql
SigninLogs
| where TimeGenerated between (datetime(2026-06-11 03:00:00) .. datetime(2026-06-11 13:00:00))
| where IPAddress == "103.69.224.136"
| where Identity contains "smith"
| where ResultType == 0
| project TimeGenerated, AppDisplayName, SessionId
```

### **Query Used — Audit Activity**
```kql
AuditLogs
| where TimeGenerated between (datetime(2026-06-11 03:00:00) .. datetime(2026-06-11 13:00:00))
| where Identity contains "smith"
| project TimeGenerated, OperationName, SessionId
```

---

If you want, I can now:

✔ Add Flags 12–20  
✔ Build the entire README from top to bottom  
✔ Add repo folder structure  
✔ Add MITRE ATT&CK mapping  
✔ Add diagrams (Mermaid)  

Just say **“continue”**.
