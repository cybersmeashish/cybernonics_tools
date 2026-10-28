# Security policy

This is a static, client-side tool: no backend, no accounts, no telemetry, and no
network calls other than loading Chart.js from jsDelivr. Assessment data is stored only in your
browser's `localStorage` and in files you export yourself.

**Handling assessment data:** a completed assessment describes your organisation's security weaknesses.
Treat exported CSV/JSON files as **confidential**. Do not commit real assessments to a public fork.

**Generated configurations** are templates. Replace every `<PLACEHOLDER>`, never paste real secrets
into issues or PRs, and validate in a lab before production.

**Reporting a vulnerability** (e.g. XSS in the tool): please use GitHub's *Private vulnerability
reporting* (Security → Advisories) rather than a public issue.
