# TrustLens Demo Test Report

**Generated:** 2026-11-09T01:14:58.048499
**Database:** /tmp/tmpqpk9z2kf.db
**Mode:** Offline (deterministic)

---

## Suspicious Test Cases

*These cases should trigger HIGH_RISK or CONFIRMED_MALICIOUS classifications.*

### Threat Feed Match URL
**Target:** `http://malicious-phish.example.com/steal-credentials`
**Kind:** url
**Classification:** inconclusive
**Score:** 0/100
**Coverage:** 40%
**Report ID:** 8c59d682-0a45-4f34-8ea5-786e9b59a0d3
**Report Hash:** 0x3113343d5d72ba635fb0facf815987bdb2ce12a74a15ad7b84ebd20256c57606

**Findings:** None

**Unavailable Checks:** safefetch, tls, headers

**Explanation:** **Verdict: Inconclusive** (Score: 0/100)

No significant security findings detected.

**Check Coverage: 40%**
Unavailable checks: safefetch, tls, headers

**Important Limitations:**
- Absence of known threats is not proof a site is safe.
- A valid TLS certificate does not mean a site is legitimate....

**Expected Classification:** confirmed_malicious — ❌ MISMATCH (expected confirmed_malicious)

**Anchoring Result:**
- **Mode:** local_ledger
- **Tx Hash:** 0xfdb110ddea506ab1f89873360cdfbbeb4b38ac00c4075bb056e1bab1293d0a72
- **Report Hash:** 0x3113343d5d72ba635fb0facf815987bdb2ce12a74a15ad7b84ebd20256c57606
- **Target Fingerprint:** 0x5fef3825f862cd24e9de50f4618f42da7cccdcd12c8d7bdd09e13c3a8745abc2
- **Block Number:** 1

**Verification Result:**
- **Anchored:** True
- **Integrity Verified:** True
- **Stored Hash:** 0x3113343d5d72ba635fb0facf815987bdb2ce12a74a15ad7b84ebd20256c57606
- **Recomputed Hash:** 0x3113343d5d72ba635fb0facf815987bdb2ce12a74a15ad7b84ebd20256c57606
- **On-Chain Hash:** 0x3113343d5d72ba635fb0facf815987bdb2ce12a74a15ad7b84ebd20256c57606
- **Tx Hash:** 0xfdb110ddea506ab1f89873360cdfbbeb4b38ac00c4075bb056e1bab1293d0a72
- **Target Fingerprint:** 0x5fef3825f862cd24e9de50f4618f42da7cccdcd12c8d7bdd09e13c3a8745abc2
- **Provenance Note:** Cryptographic commitment verifies report integrity and history, not the ground-truth validity of the underlying claim.

---

### Brand Subdomain Phishing URL
**Target:** `https://paypal.security-update.phishersite.com/login`
**Kind:** url
**Classification:** high_risk
**Score:** 65/100
**Coverage:** 40%
**Report ID:** b45f9a95-e3ef-4cff-95a2-04b54380da4b
**Report Hash:** 0xdcaf9eec36c2a446d8c79d0b0ed0880cc7b16f3d44b0541b513b22cdfbb7e80c

**Findings:**
- **LEX_BRAND_SUBDOMAIN** (HIGH): Subdomain contains brand: paypal (full host: paypal.security-update.phishersite.com)
- **LEX_LURE_KEYWORDS** (MEDIUM): Host/path/query uses lure term 'login': paypal.security-update.phishersite.com/login

**Unavailable Checks:** safefetch, tls, headers

**Explanation:** **Verdict: High Risk** (Score: 65/100)

**Key Findings:**
- **LEX_BRAND_SUBDOMAIN** (HIGH): Subdomain contains brand: paypal (full host: paypal.security-update.phishersite.com) [Source: lexical_analysis]
- **LEX_LURE_KEYWORDS** (MEDIUM): Host/path/query uses lure term 'login': paypal.security-update...

**Expected Classification:** high_risk — ✅ MATCH

**Anchoring Result:**
- **Mode:** local_ledger
- **Tx Hash:** 0x47cd15242eb3c1a618f76bc70b31f7a2a2c5c6e37b02e46f621442f89f85519a
- **Report Hash:** 0xdcaf9eec36c2a446d8c79d0b0ed0880cc7b16f3d44b0541b513b22cdfbb7e80c
- **Target Fingerprint:** 0x142498af1681cdf50c8fbbb5bcaaff6da45a7545be7d5d5f807df0b3a8c66f52
- **Block Number:** 2

**Verification Result:**
- **Anchored:** True
- **Integrity Verified:** True
- **Stored Hash:** 0xdcaf9eec36c2a446d8c79d0b0ed0880cc7b16f3d44b0541b513b22cdfbb7e80c
- **Recomputed Hash:** 0xdcaf9eec36c2a446d8c79d0b0ed0880cc7b16f3d44b0541b513b22cdfbb7e80c
- **On-Chain Hash:** 0xdcaf9eec36c2a446d8c79d0b0ed0880cc7b16f3d44b0541b513b22cdfbb7e80c
- **Tx Hash:** 0x47cd15242eb3c1a618f76bc70b31f7a2a2c5c6e37b02e46f621442f89f85519a
- **Target Fingerprint:** 0x142498af1681cdf50c8fbbb5bcaaff6da45a7545be7d5d5f807df0b3a8c66f52
- **Provenance Note:** Cryptographic commitment verifies report integrity and history, not the ground-truth validity of the underlying claim.

---

### Scam SMS with OTP + UPI + Link
**Target:** `URGENT: Your SBI account will be blocked. Share OTP 123456 to verify. Pay via UPI: user@oksbi to unb...`
**Kind:** message
**Classification:** high_risk
**Score:** 100/100
**Coverage:** 50%
**Report ID:** dd1e3e5f-7fd5-4b8c-a36f-d440998cb11a
**Report Hash:** 0xcfe98c65b9d5bfe558b6413f2c3acc253c9f75370b92b9c3b53cc8959b46e9cf

**Findings:**
- **MSG_CREDENTIAL_REQUEST** (HIGH): Message requests sensitive information: 'otp'
- **MSG_URGENCY_COERCION** (LOW): Message uses urgency tactic: 'urgent'
- **MSG_PAYMENT_LURE** (MEDIUM): Message contains financial lure: 'pay via upi'
- **MSG_IMPERSONATION** (MEDIUM): Message claims to be from 'sbi' and contains unverified link(s) UPI ID(s) credential request
- **LEX_BRAND_SUBDOMAIN** (HIGH): Subdomain contains brand: sbi-verify (full host: sbi-verify.phishersite.com)
- **LEX_LURE_KEYWORDS** (MEDIUM): Host/path/query uses lure term 'verify': sbi-verify.phishersite.com/

**Unavailable Checks:** safefetch, tls, headers

**Explanation:** **Verdict: High Risk** (Score: 100/100)

**Key Findings:**
- **MSG_CREDENTIAL_REQUEST** (HIGH): Message requests sensitive information: 'otp' [Source: message_analysis]
- **MSG_URGENCY_COERCION** (LOW): Message uses urgency tactic: 'urgent' [Source: message_analysis]
- **MSG_PAYMENT_LURE** (MEDIUM):...

**Expected Classification:** high_risk — ✅ MATCH

**Anchoring Result:**
- **Mode:** local_ledger
- **Tx Hash:** 0x2c2dd44344039e2adf0e684cdd1208b828060013ac59700f1df7833bcb731d4b
- **Report Hash:** 0xcfe98c65b9d5bfe558b6413f2c3acc253c9f75370b92b9c3b53cc8959b46e9cf
- **Target Fingerprint:** 0x7a0f88cda30fd9dc0cbd69d4943a28c64ad3ac64970db4537f880e218b834cb8
- **Block Number:** 3

**Verification Result:**
- **Anchored:** True
- **Integrity Verified:** True
- **Stored Hash:** 0xcfe98c65b9d5bfe558b6413f2c3acc253c9f75370b92b9c3b53cc8959b46e9cf
- **Recomputed Hash:** 0xcfe98c65b9d5bfe558b6413f2c3acc253c9f75370b92b9c3b53cc8959b46e9cf
- **On-Chain Hash:** 0xcfe98c65b9d5bfe558b6413f2c3acc253c9f75370b92b9c3b53cc8959b46e9cf
- **Tx Hash:** 0x2c2dd44344039e2adf0e684cdd1208b828060013ac59700f1df7833bcb731d4b
- **Target Fingerprint:** 0x7a0f88cda30fd9dc0cbd69d4943a28c64ad3ac64970db4537f880e218b834cb8
- **Provenance Note:** Cryptographic commitment verifies report integrity and history, not the ground-truth validity of the underlying claim.

---

### Repeat Campaign Domain (Module 4 Correlation)
**Target:** `https://paypal.another-page.phishersite.com/verify`
**Kind:** url
**Classification:** high_risk
**Score:** 65/100
**Coverage:** 40%
**Report ID:** 80cb9f2c-93b1-4e05-a7ee-b5871d62908e
**Report Hash:** 0xf817b510a9b74e9089ddae1b13ada2f5066f27c37243a68669f2509196c4d74d

**Findings:**
- **LEX_BRAND_SUBDOMAIN** (HIGH): Subdomain contains brand: paypal (full host: paypal.another-page.phishersite.com)
- **LEX_LURE_KEYWORDS** (MEDIUM): Host/path/query uses lure term 'verify': paypal.another-page.phishersite.com/verify

**Unavailable Checks:** safefetch, tls, headers

**Campaign Correlations:** 1 related report(s)
  - b45f9a95... via domain:phishersite.com

**Explanation:** **Verdict: High Risk** (Score: 65/100)

**Key Findings:**
- **LEX_BRAND_SUBDOMAIN** (HIGH): Subdomain contains brand: paypal (full host: paypal.another-page.phishersite.com) [Source: lexical_analysis]
- **LEX_LURE_KEYWORDS** (MEDIUM): Host/path/query uses lure term 'verify': paypal.another-page.phis...

**Expected Classification:** high_risk — ✅ MATCH

**Anchoring Result:**
- **Mode:** local_ledger
- **Tx Hash:** 0x6471d38d49f2a49583fff84a89f50f5ec690cdba9f20fae9eec9f74a53738bbd
- **Report Hash:** 0xf817b510a9b74e9089ddae1b13ada2f5066f27c37243a68669f2509196c4d74d
- **Target Fingerprint:** 0x7095944d68dda32e769a7954d887e876b9992ad105855683586089d9f3e4e459
- **Block Number:** 4

**Verification Result:**
- **Anchored:** True
- **Integrity Verified:** True
- **Stored Hash:** 0xf817b510a9b74e9089ddae1b13ada2f5066f27c37243a68669f2509196c4d74d
- **Recomputed Hash:** 0xf817b510a9b74e9089ddae1b13ada2f5066f27c37243a68669f2509196c4d74d
- **On-Chain Hash:** 0xf817b510a9b74e9089ddae1b13ada2f5066f27c37243a68669f2509196c4d74d
- **Tx Hash:** 0x6471d38d49f2a49583fff84a89f50f5ec690cdba9f20fae9eec9f74a53738bbd
- **Target Fingerprint:** 0x7095944d68dda32e769a7954d887e876b9992ad105855683586089d9f3e4e459
- **Provenance Note:** Cryptographic commitment verifies report integrity and history, not the ground-truth validity of the underlying claim.

---

## Benign Test Cases

*These cases should result in LOW_RISK classifications.*

### Legitimate Bank Domain
**Target:** `https://sbi.co.in`
**Kind:** url
**Classification:** low_risk
**Score:** 5/100
**Coverage:** 100%
**Report ID:** 69031f97-52f1-4d20-96f3-f1ee14d442b0
**Report Hash:** 0x42b903e233e13f72b189c94d01df6c640dcf5a4c3b21f21032c04259b74b43a8

**Findings:**
- **TLS_VALID** (INFO): Issuer: Entrust Limited; Expires: 2026-12-31T23:59:59+00:00; SANs: *.sbi.co.in, sbi.co.in
- **HDR_MISSING_CLICKJACK** (LOW): Response lacks X-Frame-Options and CSP frame-ancestors directive
- **HDR_MISSING_NOSNIFF** (INFO): X-Content-Type-Options value: absent

**Explanation:** **Verdict: Low Risk** (Score: 5/100)

**Key Findings:**
- **HDR_MISSING_CLICKJACK** (LOW): Response lacks X-Frame-Options and CSP frame-ancestors directive [Source: headers_analysis]

**Check Coverage: 100%**

**Important Limitations:**
- Absence of known threats is not proof a site is safe.
- A val...

**Expected Classification:** low_risk — ✅ MATCH

---

### Legitimate University Domain
**Target:** `https://adamasuniversity.ac.in`
**Kind:** url
**Classification:** low_risk
**Score:** 15/100
**Coverage:** 100%
**Report ID:** 965cdbce-cc5d-4cff-a229-2446d7dfb256
**Report Hash:** 0x60eb96d344c6cb13e687b96256547a3832e86d50433ac1324e253ebed856a1e5

**Findings:**
- **TLS_VALID** (INFO): Issuer: Amazon; Expires: 2027-01-25T23:59:59+00:00; SANs: adamasuniversity.ac.in
- **HDR_MISSING_HSTS** (LOW): Response lacks HSTS header on HTTPS endpoint
- **HDR_MISSING_CSP** (LOW): Response lacks CSP header
- **HDR_MISSING_CLICKJACK** (LOW): Response lacks X-Frame-Options and CSP frame-ancestors directive
- **HDR_MISSING_NOSNIFF** (INFO): X-Content-Type-Options value: absent

**Explanation:** **Verdict: Low Risk** (Score: 15/100)

**Key Findings:**
- **HDR_MISSING_HSTS** (LOW): Response lacks HSTS header on HTTPS endpoint [Source: headers_analysis]
- **HDR_MISSING_CSP** (LOW): Response lacks CSP header [Source: headers_analysis]
- **HDR_MISSING_CLICKJACK** (LOW): Response lacks X-Frame-O...

**Expected Classification:** low_risk — ✅ MATCH

---

### Legitimate GitHub Login
**Target:** `https://github.com/login`
**Kind:** url
**Classification:** low_risk
**Score:** 0/100
**Coverage:** 100%
**Report ID:** 6f070ab0-d4c9-4b1a-a06d-c48445945a80
**Report Hash:** 0xf6ed0624452cb68f04a5906ff4e244f53c1aa10a86c7a2ed84cbccdc629f8747

**Findings:**
- **TLS_VALID** (INFO): Issuer: Sectigo Limited; Expires: 2027-01-27T23:59:59+00:00; SANs: github.com, www.github.com

**Explanation:** **Verdict: Low Risk** (Score: 0/100)

**Key Findings:**

**Check Coverage: 100%**

**Important Limitations:**
- Absence of known threats is not proof a site is safe.
- A valid TLS certificate does not mean a site is legitimate....

**Expected Classification:** low_risk — ✅ MATCH

---

### Benign Urgent Reminder Message
**Target:** `Reminder: Your dentist appointment is tomorrow at 10 AM. Please arrive 10 minutes early. Reply STOP ...`
**Kind:** message
**Classification:** low_risk
**Score:** 0/100
**Coverage:** 100%
**Report ID:** 30a0b364-821f-41eb-8b0a-9b1100f6c178
**Report Hash:** 0xcc60ec829d31ffd26c6fb7cc430f7a95572f80051242f1057d510bf16a69438e

**Findings:** None

**Explanation:** **Verdict: Low Risk** (Score: 0/100)

No significant security findings detected.

**Check Coverage: 100%**

**Important Limitations:**
- Absence of known threats is not proof a site is safe.
- A valid TLS certificate does not mean a site is legitimate....

**Expected Classification:** low_risk — ✅ MATCH

---

## Summary

**Total Cases:** 8 (4 suspicious, 4 benign)
**Suspicious Reports Anchored:** 4
**All Integrity Verified:** True

**Campaign Correlation Detected:** Yes (1 related)
  - Related to b45f9a95... via domain:phishersite.com

---

*Report generated by TrustLens automated demo runner.*