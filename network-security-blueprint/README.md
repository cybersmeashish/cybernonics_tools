# 🛡️ Enterprise Network Security Blueprint

**An interactive, client-side tool for designing, assessing and hardening enterprise networks.**
It has six reference architectures, a 60-control gap assessment, a risk-ranked remediation roadmap, a Cisco IOS hardening generator, and live cross-mapping to **NIST CSF 2.0**, **CIS Controls v8**, **ISO/IEC 27001:2022**, **NIST SP 800-53 Rev. 5** and **MITRE ATT&CK**.

The baseline is the public **NSA *Network Infrastructure Security Guide*** (v1.2, Oct 2023), extended with Zero Trust, cloud and OT controls.

**[▶ Live demo](https://cybersmeashish.github.io/cybernonics_tools/network-security-blueprint/)** · [Demo with sample data](https://cybersmeashish.github.io/cybernonics_tools/network-security-blueprint/?sample=1#ga) · [Single-file download](https://cybersmeashish.github.io/cybernonics_tools/network-security-blueprint/dist/network-security-blueprint.html)

> Part of [cybernonics_tools](https://github.com/cybersmeashish/cybernonics_tools).

<!-- Add a screenshot: docs/screenshot.png -->

---

## Features

| Tab | What it does |
|---|---|
| **1 · Blueprint** | Scope, 8 design principles, 7-layer defense model mapped to NSA sections, cryptographic baseline (CNSSP 15 / NIST SP 800-52r2), governance KPIs |
| **2 · Reference Architectures** | 6 interactive diagrams with design decisions, threats mitigated and mapped controls. One click scopes the assessment to that architecture |
| **3 · Gap Assessment** | 60 controls × 10 domains. Severity-weighted posture score, L1–L5 maturity, radar and gap charts, evidence notes, CSV/JSON export/import, print report |
| **4 · Remediation Roadmap** | Open gaps ranked by risk and phased into 0–30 / 31–90 / 91–180 days |
| **5 · Hardening Baseline** | Generates a Cisco IOS/IOS-XE config template from the NSA sample commands, for all controls or gaps only |
| **6 · Framework Mapping** | Live coverage for NIST CSF 2.0 (23 subcategories), CIS v8 (49 safeguards), ISO 27001:2022 Annex A (29 controls), NIST SP 800-53 r5 (49 controls) and MITRE ATT&CK (43 techniques, Enterprise + ICS), plus a full control matrix |

### Reference architectures
`RA1` Enterprise Perimeter & DMZ (dual-vendor) · `RA2` Campus & Branch (802.1X, SD-WAN) · `RA3` Data Center & OOB management · `RA4` Hybrid Cloud: AWS hub-and-spoke with centralized inspection · `RA5` Zero Trust remote access (ZTNA/SASE) · `RA6` OT/ICS Purdue segmentation with IDMZ

### Privacy by design
- 100% static: no backend, no accounts, no telemetry.
- Answers are saved only in your browser's `localStorage`. Export and import JSON to move them between machines.
- A strict Content-Security-Policy is applied. The only third-party resource is Chart.js from jsDelivr.

---

## Quick start

```bash
git clone https://github.com/cybersmeashish/cybernonics_tools.git
cd cybernonics_tools/network-security-blueprint
python3 -m http.server 8080        # or: npm run serve
# open http://localhost:8080
```

You can also open `index.html` directly, or use the single-file edition in `dist/`.

| Command | Purpose |
|---|---|
| `node scripts/validate.js` | Checks integrity: IDs, domains, severities, architecture refs, framework codes |
| `node scripts/build-standalone.js` | Builds `dist/network-security-blueprint.html` (one file) |

No `npm install` is needed. The scripts use Node built-ins only (Node ≥ 18).

---

## GitHub Pages

The repo-level workflow `.github/workflows/pages.yml` deploys this tool. Every push to `main` validates each tool, builds its single-file edition and publishes the repo to Pages.

Demo: **https://cybersmeashish.github.io/cybernonics_tools/network-security-blueprint/**

One-time setup: **Settings → Pages → Build and deployment → Source: GitHub Actions**.

---

## Using the tool

1. Review the **Blueprint** and choose the **Reference Architecture** that matches your environment.
2. Click **Assess against this architecture**, or assess the whole enterprise.
3. Set each control to *Implemented*, *Partial*, *Not implemented* or *N/A*, and add evidence notes.
4. Open the **Roadmap** for the prioritized plan and **Framework Mapping** for CSF, CIS and ISO coverage.
5. Generate a **Hardening Baseline** for your gaps. **Export CSV** for an evidence register, or **Save JSON** to resume later.

Deep links: `#bp` `#ra` `#ga` `#rm` `#hb` `#fm`. Add `?sample=1` to load demo data into an empty assessment.

Scoring details are in [docs/methodology.md](docs/methodology.md).

---

## Project structure

```
.
├── index.html                  # Page shell
├── assets/
│   ├── css/styles.css          # Theme tokens (light/dark) + layout
│   └── js/
│       ├── theme.js            # Applies saved/preferred theme before paint
│       ├── data.js             # Domains, 60 controls, 6 reference architectures
│       ├── frameworks.js       # NIST CSF 2.0 / CIS v8 / ISO 27001 titles + mappings
│       └── app.js              # UI, scoring, roadmap, generator, charts
├── examples/sample-assessment.json
├── scripts/validate.js · build-standalone.js
├── docs/methodology.md
├── dist/                       # Single-file build (generated)
└── .github/                    # Pages workflow, issue & PR templates
```

Extending the controls, architectures or frameworks is covered in [CONTRIBUTING.md](CONTRIBUTING.md).

---

## Roadmap ideas
- Multi-vendor hardening syntax (Palo Alto, Fortinet, Juniper, Arista)
- Regional regulatory overlays (e.g., CERT-In, RBI, SEBI CSCRF, DPDP, NIS2, DORA)
- Before/after comparison of two saved assessments

## Disclaimer
This is an independent community project. It is **not affiliated with or endorsed by NSA, NIST, CIS, ISO or MITRE**. Framework mappings are indicative architect mappings, not official crosswalks, and are not compliance evidence by themselves. Generated configurations are templates: validate them in a lab before production. Treat completed assessments as **confidential**. See [NOTICE.md](NOTICE.md) and [SECURITY.md](SECURITY.md).

## License
[MIT](LICENSE). Third-party notices are in [NOTICE.md](NOTICE.md).
