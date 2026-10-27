# ISO/IEC 27090 AI Security Readiness Scanner

A free, browser-based self-assessment that shows **where your enterprise stands on AI security** and **what it takes to align with ISO/IEC 27090**, sequenced into a **30-day remediation plan**.

**Live tool:** https://cybersmeashish.github.io/cybernonics_tools/iso27090-ai-security-scanner/

## What it does
- **54 controls** across 10 domains: governance, threat modelling and validation, secure AI engineering, AI supply chain, data protection, development-environment protection, zero trust, runtime defences, monitoring, and oversight
- Coverage of all **12 ISO/IEC 27090 AI threats** plus 3 Annex B attacks (data poisoning, evasion, membership inference, model exfiltration and inversion, prompt and output injection, and others)
- Maturity scoring from 0 to 4 per control, with readiness by domain, threat, priority and phase
- A **gap report** grouped into a week-by-week **30-day plan**, with owners and the audit evidence each control needs
- Mappings to **ISO/IEC 27002:2022, ISO/IEC 42001 and NIST SP 800-53** (indicative)
- Export to CSV, save and load an assessment as JSON, print to PDF
- An [Excel version](assets/ISO27090_AI_Security_Scanner.xlsx) for offline or workshop use

## Privacy
Everything runs client-side. There is no backend, no analytics and no data collection. Scores are kept in your browser's localStorage only.

## How to score
| Score | Meaning |
|---|---|
| 0 | Not in place |
| 1 | Ad hoc |
| 2 | Partial |
| 3 | Implemented: the target for full alignment |
| 4 | Managed and continuously improved |

Controls you haven't scored count as gaps. N/A controls are excluded.

## Important notes
- ISO/IEC 27090 is **guidance, not a certifiable standard**. Certification runs through ISO/IEC 27001 (information security) and ISO/IEC 42001 (AI management). Feed the AI treatments into your 27001 risk treatment plan and Statement of Applicability.
- The controls are paraphrased from practitioner analysis of ISO/IEC DIS 27090 (April 2025 draft). The first edition was reportedly published on 14 October 2026, so verify against it. No ISO text is reproduced.
- This is an independent tool, not affiliated with or endorsed by ISO or IEC.

## Author
**Ashish Srivastava**, Principal Architect, AI Security & Governance · Part of [cybernonics_tools](https://github.com/cybersmeashish/cybernonics_tools)
