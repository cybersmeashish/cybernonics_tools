# EU AI Act Compliance Scanner

A free, browser-based self-assessment for the **EU AI Act**, the world's first comprehensive, binding AI law. It classifies each AI system into a **risk tier**, identifies the obligations that apply to your **role**, scores your readiness, and produces a **gap report ordered by legal deadline**.

**Live tool:** https://cybersmeashish.github.io/cybernonics_tools/eu-ai-act-compliance-scanner/

Up to date with **Regulation (EU) 2024/1689 as amended by the Digital Omnibus on AI, Regulation (EU) 2026/1744** (in force since 27 July 2026).

## What it checks
- **Risk tier per AI system**
  - **Unacceptable:** all 10 Article 5 prohibitions, including the new bans on non-consensual intimate imagery (NCII) and CSAM that apply from 2 Dec 2026
  - **High:** Annex I product-safety route, all 8 Annex III areas, the Art. 6(3) exemption test and the profiling override
  - **Limited:** Art. 50 transparency triggers
  - **Minimal**
  - **GPAI model / systemic risk** flag
- **User disclosure duties:** chatbot "you are talking to AI" notices, machine-readable marking of synthetic content, deepfake and AI-generated text labelling, emotion-recognition notices
- **High-risk pipelines:** risk management, data governance, Annex IV documentation, **automatic logging (Art. 12)** and log retention, **human oversight by design (Art. 14)** and competent deployer oversight (Art. 26), accuracy, robustness and cybersecurity, QMS, conformity assessment, CE marking, EU database registration, post-market monitoring, serious incident reporting, FRIA, right to explanation
- **Value chain:** importer and distributor checks, and when you become a provider (Art. 25)
- **GPAI models:** Art. 53 to 55 duties
- **57 obligations in total.** Only the ones relevant to your systems and roles are shown.

## Deadlines it tracks
| Date | What applies |
|---|---|
| 2 Feb 2025 | Original 8 prohibitions; AI literacy |
| 2 Aug 2025 | GPAI model obligations |
| 2 Aug 2026 | General application; Art. 50 transparency; enforcement |
| 2 Dec 2026 | New NCII and CSAM bans; content marking for generative systems already on the market |
| 2 Aug 2027 | GPAI models placed on the market before 2 Aug 2025 |
| 2 Dec 2027 | High-risk: Annex III use cases |
| 2 Aug 2028 | High-risk: Annex I regulated products |

## Privacy
Everything runs client-side. There is no backend, no analytics and no data collection.

## Disclaimer
This is an independent practitioner tool, not affiliated with or endorsed by the European Union, the European Commission or the AI Office. The obligations are paraphrased summaries. **Not legal advice.** Check the official text on EUR-Lex and the Commission's AI Act Service Desk.

## Author
**Ashish Srivastava**, Principal Architect, AI Security & Governance · Part of [cybernonics_tools](https://github.com/cybersmeashish/cybernonics_tools) · Companion tool: [ISO/IEC 27090 AI Security Scanner](../iso27090-ai-security-scanner/)
