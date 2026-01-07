# 🇦🇺 Wattle-Guard: APP 8 & SOCI Compliance Validator

**Automated Vendor Sovereignty Auditing for Australian Financial Institutions.**

### 🛑 The Problem
Under the **Privacy Act 1988 (Cth)** and **APP 8 (Cross-border disclosure)**, Australian entities are liable if an overseas vendor mishandles personal data. With the new 2024 penalty regime ($50M or 30% turnover), "blindly trusting" US/EU vendors is no longer a viable strategy.

### 🛡️ The Solution
**Wattle-Guard** is a Python-based forensic tool designed for **Compliance Officers** and **Risk Architects**. It automates the technical due diligence required to onboard external vendors.

### Core Capabilities
1.  **Sovereignty Detection:** Instantly resolves physical server jurisdiction to flag non-Australian hosting (SOCI Act triggers).
2.  **APP 11 Security Verification:** Validates encryption standards in transit.
3.  **Jurisdictional Risk Scoring:** Automatically flags "High Risk" zones (e.g., US Cloud Act) vs "Safe Zones" (GDPR/NZ).

### How to Run
```bash
python wattle_guard.py

---



### ⚠️ Legal Disclaimer
**Wattle-Guard is a technical forensic tool, not legal advice.** While this tool assists with APP 8 and SOCI Act due diligence, it does not guarantee compliance. Users should consult with their own legal counsel regarding specific cross-border data transfer obligations under the Privacy Legislation Amendment (Enforcement and Other Measures) Act 2022.
