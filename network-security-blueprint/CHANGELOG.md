# Changelog

## [1.1.0] — 2026-10-28
### Added
- **NIST SP 800-53 Rev. 5** mapping: 49 controls/enhancements across 12 families (AC, AU, CM, CP, IA, MA, PL, RA, SA, SC, SI, SR).
- **MITRE ATT&CK** mapping: 43 techniques/sub-techniques across 11 Enterprise tactics plus ATT&CK for ICS (T0822, T0883, T0886).
- ATT&CK techniques addressed are shown on each reference architecture and in the remediation roadmap.
- Framework metadata (`abbr`, `pre`, `gl`, `unit`) so the UI, CSV export and validator handle any number of frameworks.
### Changed
- Natural sort handles control enhancements, e.g. `SC-7(5)`.
- Rows group by framework order (CSF function, ATT&CK tactic).

## [1.0.0] — 2026-10-28
### Added
- Blueprint: scope, 8 design principles, 7-layer defense model, cryptographic baseline, governance KPIs.
- 6 interactive reference architectures: Perimeter/DMZ, Campus & Branch, Data Center + OOB, Hybrid Cloud (AWS), ZTNA/SASE, OT/ICS (Purdue).
- 60-control gap assessment across 10 domains, with severity-weighted scoring, maturity levels (L1–L5), architecture scoping, CSV/JSON export/import and print.
- Risk-ranked 30/90/180-day remediation roadmap.
- Cisco IOS/IOS-XE hardening baseline generator (all controls, or gaps only).
- NIST CSF 2.0, CIS Controls v8 and ISO/IEC 27001:2022 Annex A cross-mapping with live coverage.
- Light/dark theme, deep links (`#ga`, `#fm`, …), `?sample=1` demo mode.
- CI validation, GitHub Pages deployment, single-file offline build.
