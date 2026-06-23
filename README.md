---

# M365 Identity Compromise
---

# 📌 **Q01 — The Compromised Principal**

### **Objective**  
Identify which user account was compromised.

### **Hypothesis**  
The principal with suspicious sign‑ins from the attacker IP is the compromised identity.

<img width="927" height="396" alt="image" src="https://github.com/user-attachments/assets/7edbce94-c2ae-4cbc-84d4-15493520b1de" />

---

# 📌 **Q02 — The Flagged Source**

### **Objective**  
Identify the IP address associated with the suspicious login.

### **Hypothesis**  
The attacker originates from a non‑trusted foreign IP.

<img width="1092" height="628" alt="image" src="https://github.com/user-attachments/assets/31097e5b-d038-465f-8a32-616508525cf7" />

---

# 📌 **Q03 — The Client OS**

### **Objective**  
Determine the OS used during the suspicious login.

### **Hypothesis**  
The attacker’s OS will differ from the user’s normal baseline.

<img width="1241" height="695" alt="image" src="https://github.com/user-attachments/assets/12990d13-ae67-4832-8d45-92b2aeb363eb" />


---

# 📌 **Q04 — The Stored Detection Type**

### **Objective**  
Identify the *raw backend detection type* stored in Entra ID Identity Protection telemetry for this incident.

### **Hypothesis**  
The portal shows a friendly label (e.g., *Anonymous IP address*), but the underlying telemetry stores a **tokenized detection type**. Retrieving this value reveals the exact machine‑level reason the risk event was generated.

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
Determine the current status of the compromised account by checking the asset record inside the incident.

### **Hypothesis**  
The account status (e.g., *enabled*, *disabled*) will reveal whether the user was still active at the time of compromise, helping confirm whether the attacker operated under a valid, unblocked identity.

<img width="1912" height="872" alt="Screenshot 2026-06-20 201927" src="https://github.com/user-attachments/assets/792c3748-978c-4541-a6b8-6c7775025076" />


---

Here you go — **Q07 written cleanly in the same style as your README**, with only the **Objective** and **Hypothesis**, matching the IR Lead prompt.

---

# 📌 **Q07 — How the Session Beat MFA**

### **Objective**  
Identify the specific authentication field in the successful sign‑in logs that explains why MFA was not required, despite the tenant enforcing MFA.

### **Hypothesis**  
The attacker’s session was allowed because the authentication requirement was downgraded (e.g., **single‑factor authentication**) due to token reuse or a policy gap, and this value is stored as a single backend token in the sign‑in logs.

<img width="1915" height="976" alt="Screenshot 2026-06-20 202420" src="https://github.com/user-attachments/assets/f3acbb06-f164-476a-a133-24e46b502489" />

---

# 📌 **Q08 — The Control Surface That Let Them In**  

### **Objective**  
Identify which application allowed the attacker’s **first successful sign‑in** after multiple failed attempts from the same IP address.

### **Hypothesis**  
By ordering all sign‑ins from the attacker IP chronologically, the earliest **ResultType == 0** event will reveal the exact application (AppDisplayName) that granted access, exposing the control surface that enabled the compromise.

<img width="1918" height="975" alt="Screenshot 2026-06-20 204935" src="https://github.com/user-attachments/assets/4741da49-e194-49c8-9571-7c1a57e1bbce" />


---

# 📌 **Q09 — Failed Attempts Before Entry**

### **Objective**  
Count bad‑password failures before the first successful login.

### **Hypothesis**  
The attacker attempted multiple incorrect passwords before gaining access.

<img width="1912" height="970" alt="Screenshot 2026-06-20 210634" src="https://github.com/user-attachments/assets/c9ac1f73-7cde-49c2-9d64-f9194cd85235" />

---

# 📌 **Q10 — Blast Radius of One Token**

### **Objective**  
Count how many distinct apps the attacker accessed using the same session token.

### **Hypothesis**  
The attacker pivoted across multiple M365 apps without MFA re‑prompt.

<img width="1906" height="967" alt="Screenshot 2026-06-20 211059" src="https://github.com/user-attachments/assets/7167f0f6-60b2-45fb-8188-3c1b2782aa4b" />


---

# 📌 **Q11 — One Continuous Session**

### **Objective**  
Identify the session identifier shared between the sign‑in and later activity.

### **Hypothesis**  
A single **SessionId** GUID ties the attacker’s initial login to all subsequent activity.

<img width="1913" height="971" alt="Screenshot 2026-06-20 212151" src="https://github.com/user-attachments/assets/f547752f-74d5-4999-998a-804e9a85f8e9" />

---

Here you go, Nehal — **Q12 written in the exact same style as your README**, with only the **Objective** and **Hypothesis**, matching the IR Lead prompt precisely.

---

# 📌 **Q12 — MFA‑Posture Profiling**  

### **Objective**  
Identify which **Microsoft Graph Reports API resource** the attacker queried to profile the user’s MFA and authentication posture early in the session.

### **Hypothesis**  
The attacker executed a Graph **reports** call to gather intelligence on the user’s MFA configuration, sign‑in methods, or authentication strength. The specific **resource path** queried will reveal what aspect of the user’s identity posture they were profiling.

<img width="1911" height="971" alt="image" src="https://github.com/user-attachments/assets/2c52f000-bbe6-4105-a5d3-84e28be4ea06" />

---
Here you go Nehal — **Q13 fully formatted for GitHub**, matching the exact style you’ve been using, with **Objective**, **Hypothesis**, and the **final answer**.

---

# **Q13 — Group Enumeration**

### **Objective**  
Identify whether the attacker queried Microsoft Graph to enumerate the victim’s own group memberships, which would reveal what permissions or roles the compromised account has.

### **Hypothesis**  
If the attacker is profiling the victim’s access level, there should be a Graph API request that lists the groups or directory roles the victim belongs to — typically via the `/me/memberOf` endpoint.

<img width="1910" height="961" alt="image" src="https://github.com/user-attachments/assets/85d42263-07f9-40b9-b382-045d501edc6e" />

---

# **Q14 — The Fraudulent Request**

### **Objective**  
Identify the internal fraudulent email sent from the compromised mailbox by extracting the **exact subject line** used to redirect a legitimate payment.

### **Hypothesis**  
If the attacker attempted to manipulate internal financial processes, the mailbox logs will contain an outbound internal email with a subject line referencing updated banking, payment changes, or invoice redirection — revealing the attacker’s intent and confirming fraudulent activity.

<img width="1086" height="617" alt="image" src="https://github.com/user-attachments/assets/af0e589c-f1ff-4786-b86d-b6ca574fbd72" />
---





