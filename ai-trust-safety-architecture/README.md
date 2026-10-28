# AI Trust & Safety Enterprise Architecture · MITRE ATLAS Mapping

An interactive enterprise reference architecture for **AI trust & safety**: 9 layers and 41 components. Every component is mapped to **MITRE ATLAS** (v5.6.0, all 101 techniques, 16 tactics and 35 mitigations), **ISO/IEC 23894:2023**, **ISO/IEC TR 24028:2020**, the **OWASP Top 10 for LLM Applications 2025** and **NIST AI RMF**. A built-in coverage assessment shows which adversary techniques you are exposed to.

**Live:** https://cybersmeashish.github.io/cybernonics_tools/ai-trust-safety-architecture/

## What's on the page
1. **Layered reference architecture** across three planes:
   - **Control plane:** Governance & policy; Supply chain & MLOps
   - **Data plane:** Identity & edge → Input trust → Agents & orchestration ⇄ Models / Data & RAG → Output trust & content safety
   - **Assurance plane:** Observability, trust & safety operations and response
2. **Reference diagrams**
   - Runtime request flow and trust boundaries
   - Trust & safety operations loop (signals → detect → decide → enforce → review → appeal → report → improve)
   - Three attack chains mapped to ATLAS, showing where the architecture breaks each one (indirect prompt injection to agent exfiltration, model extraction to evasion, deepfake-enabled fraud)
   - ISO/IEC 23894 risk process → components
   - AI lifecycle → controls
   - ISO/IEC TR 24028 trustworthiness characteristics × layers
3. **MITRE ATLAS matrix** with technique-to-component mappings. Official links come from ATLAS mitigations; practitioner links cover techniques where ATLAS lists no mitigation. Includes search, layer highlighting and CSV export.
4. **Coverage assessment.** Score each component to get your ATLAS coverage %, coverage by tactic, the "next best controls" to implement, and an exposure report (CSV, JSON, print).
5. **Standards crosswalk:** ISO/IEC 23894, TR 24028, 42001, 27090, EU AI Act, NIST AI RMF, MITRE ATLAS, OWASP LLM Top 10.

## Notes
- The ISO mappings are paraphrased practitioner interpretations. No ISO text is reproduced.
- MITRE ATLAS™ data comes from [mitre-atlas/atlas-data](https://github.com/mitre-atlas/atlas-data) v5.6.0, © The MITRE Corporation, used under its published licence. This tool is not affiliated with or endorsed by MITRE, ISO, IEC or OWASP.
- Everything runs in your browser. No data is collected.

## Author
**Ashish Srivastava**, Principal Architect, AI Security & Governance · Part of [cybernonics_tools](https://github.com/cybersmeashish/cybernonics_tools)
