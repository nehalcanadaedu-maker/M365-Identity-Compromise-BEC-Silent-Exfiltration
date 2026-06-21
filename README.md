---

# 🧭 **LIVEHunt 08 — SECOND VECTOR: M365 Identity Compromise**  
---

# 📌 **Q01 — The Compromised Principal**

### **Objective**  
Identify which user account was compromised.

### **Hypothesis**  
The principal with suspicious sign‑ins from the attacker IP is the compromised identity.

<img width="1913" height="965" alt="image" src="https://github.com/user-attachments/assets/c59f5215-c8e5-459d-8be6-bcec9cae5efa" />

---

# 📌 **Q02 — The Flagged Source**

### **Objective**  
Identify the IP address associated with the suspicious login.

### **Hypothesis**  
The attacker originates from a non‑trusted foreign IP.

<img width="1906" height="957" alt="image" src="https://github.com/user-attachments/assets/f32fd8b6-a8ac-46e2-bf64-cc7e070c0d0b" />

---

# 📌 **Q03 — The Client OS**

### **Objective**  
Determine the OS used during the suspicious login.

### **Hypothesis**  
The attacker’s OS will differ from the user’s normal baseline.

<img width="1913" height="967" alt="image" src="https://github.com/user-attachments/assets/fe344532-a698-4496-a31b-ab696a4476ed" />


---

# 📌 **Q04 — The Stored Detection Type**

### **Objective**  
Identify the *raw backend detection type* stored in Entra ID Identity Protection telemetry for this incident.

### **Hypothesis**  
The portal shows a friendly label (e.g., *Anonymous IP address*), but the underlying telemetry stores a **tokenized detection type**. Retrieving this value reveals the exact machine‑level reason the risk event was generated.

---

If you want, I can rewrite **Q01–Q11** in this exact clean style or continue with **Q05 next**.
<img width="1915" height="971" alt="Screenshot 2026-06-20 201234" src="https://github.com/user-attachments/assets/9dcfa434-2dc5-4744-904f-94ec0b3d1e3d" />


---

# 📌 **Q05 — Audit the Verdict**

### **Objective**  
Determine the final disposition (verdict) of all risk detections associated with the compromised user.

### **Hypothesis**  
The user has multiple risk detections, and aggregating them by **RiskState** will reveal the most common outcome (e.g., *atRisk*, *remediated*, *dismissed*).

<img width="1917" height="873" alt="Screenshot 2026-06-20 201510" src="https://github.com/user-attachments/assets/9d4471da-d96c-4dc5-b141-0a06d380bd8e" />

---

# 📌 **Q06 — Live Exposure**

### **Objective**  
Identify the first successful sign‑in from the attacker.

### **Hypothesis**  
The earliest successful login marks the start of the attacker’s session.

### **Time Range**  
`2026‑06‑11 03:00 → 2026‑06‑11 13:00 UTC`

### **Query Used**
```kql
SigninLogs
| where TimeGenerated between (datetime(2026-06-11 03:00:00) .. datetime(2026-06-11 13:00:00))
| where IPAddress == "103.69.224.136"
| where ResultType == 0
| order by TimeGenerated asc
| take 1
```

---

# 📌 **Q07 — How the Session Beat MFA**

### **Objective**  
Identify how the attacker bypassed MFA.

### **Hypothesis**  
The attacker reused a valid session token that did not require MFA re‑authentication.

### **Time Range**  
`2026‑06‑11 03:00 → 2026‑06‑11 13:00 UTC`

### **Query Used**
```kql
SigninLogs
| where TimeGenerated between (datetime(2026-06-11 03:00:00) .. datetime(2026-06-11 13:00:00))
| where IPAddress == "103.69.224.136"
| project AuthenticationRequirement
```

---

# 📌 **Q08 — The Control Surface That Let Them In**

### **Objective**  
Identify the app used for the first successful login.

### **Hypothesis**  
The attacker targeted Outlook Web first.

### **Time Range**  
`2026‑06‑11 03:00 → 2026‑06‑11 13:00 UTC`

### **Query Used**
```kql
SigninLogs
| where TimeGenerated between (datetime(2026-06-11 03:00:00) .. datetime(2026-06-11 13:00:00))
| where IPAddress == "103.69.224.136"
| where ResultType == 0
| order by TimeGenerated asc
| take 1
| project AppDisplayName
```

---

# 📌 **Q09 — Failed Attempts Before Entry**

### **Objective**  
Count bad‑password failures before the first successful login.

### **Hypothesis**  
The attacker attempted multiple incorrect passwords before gaining access.

### **Time Range**  
`2026‑06‑11 00:00 → 2026‑06‑11 03:00 UTC` (expanded backward)

### **Query Used**
```kql
SigninLogs
| where TimeGenerated between (datetime(2026-06-11 00:00:00) .. datetime(2026-06-11 03:00:00))
| where IPAddress == "103.69.224.136"
| where ResultType == 50126
| count
```

---

# 📌 **Q10 — Blast Radius of One Token**

### **Objective**  
Count how many distinct apps the attacker accessed using the same session token.

### **Hypothesis**  
The attacker pivoted across multiple M365 apps without MFA re‑prompt.

### **Time Range**  
`2026‑06‑11 03:00 → 2026‑06‑11 13:00 UTC`

### **Query Used**
```kql
SigninLogs
| where TimeGenerated between (datetime(2026-06-11 03:00:00) .. datetime(2026-06-11 13:00:00))
| where IPAddress == "103.69.224.136"
| where ResultType == 0
| summarize dcount(AppDisplayName)
```

---

# 📌 **Q11 — One Continuous Session**

### **Objective**  
Identify the session identifier shared between the sign‑in and later activity.

### **Hypothesis**  
A single **SessionId** GUID ties the attacker’s initial login to all subsequent activity.

### **Time Range**  
`2026‑06‑11 03:00 → 2026‑06‑11 13:00 UTC`

### **Query Used — Sign‑In**
```kql
SigninLogs
| where TimeGenerated between (datetime(2026-06-11 03:00:00) .. datetime(2026-06-11 13:00:00))
| where IPAddress == "103.69.224.136"
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

If you want, I can now generate:

✔ Q12–Q20  
✔ Full README.md  
✔ Repo folder structure  
✔ MITRE ATT&CK mapping  
✔ Mermaid diagrams  

Just say **continue**.
