#!/usr/bin/env node
/* Data-integrity checks for the control catalogue, architectures and framework mappings.
   Usage: node scripts/validate.js   (exit code 1 on any error) */
'use strict';
const path = require('path');
const ROOT = process.env.NSBP_ROOT || path.resolve(__dirname, '..');
const { DOMAINS, SEVW, ALL, CONTROLS, RAS } = require(path.join(ROOT, 'assets/js/data.js'));
const { FW, XMAP } = require(path.join(ROOT, 'assets/js/frameworks.js'));

const errors = [], warn = [];
const domIds = new Set(DOMAINS.map(d => d.id));
const raIds = new Set(RAS.map(r => r.id));
const seen = new Set();

for (const c of CONTROLS) {
  if (seen.has(c.id)) errors.push(`Duplicate control id ${c.id}`);
  seen.add(c.id);
  if (!domIds.has(c.d)) errors.push(`${c.id}: unknown domain "${c.d}"`);
  if (!(c.sev in SEVW)) errors.push(`${c.id}: invalid severity "${c.sev}"`);
  if (!c.t || !c.fix) errors.push(`${c.id}: missing title or remediation text`);
  if (c.ras !== ALL) {
    if (!Array.isArray(c.ras) || !c.ras.length) errors.push(`${c.id}: ras must be '*' or a non-empty array`);
    else c.ras.forEach(r => { if (!raIds.has(r)) errors.push(`${c.id}: unknown architecture "${r}"`); });
  }
  if (c.cmd && /\bpassword\s+\S+$/m.test(c.cmd) && !/<[A-Z_#0-9]+>/.test(c.cmd)) warn.push(`${c.id}: command block may contain a literal secret`);
}
for (const r of RAS) {
  r.ctl.forEach(id => { if (!seen.has(id)) errors.push(`${r.id}: references unknown control ${id}`); });
  if (!r.tiers || !r.tiers.length) errors.push(`${r.id}: no tiers defined`);
  r.tiers.forEach(t => t[1].forEach(n => { if (!/^[snima]\|/.test(n)) errors.push(`${r.id}: node "${n}" needs a type prefix s|n|i|m|a`); }));
}
const fwKeys = Object.keys(FW);
for (const id of seen) if (!XMAP[id]) errors.push(`${id}: missing framework mapping in XMAP`);
for (const [id, m] of Object.entries(XMAP)) {
  if (!seen.has(id)) errors.push(`XMAP: unknown control ${id}`);
  if (!Array.isArray(m) || m.length !== fwKeys.length) { errors.push(`XMAP ${id}: must have ${fwKeys.length} arrays (${fwKeys.join(', ')})`); continue; }
  m.forEach((codes, i) => codes.forEach(code => {
    if (!FW[fwKeys[i]].t[code]) errors.push(`XMAP ${id}: ${fwKeys[i]} code "${code}" has no title in FW.${fwKeys[i]}.t`);
  }));
}
for (const k of fwKeys) for (const f of ['name','abbr','gl','unit']) if (FW[k][f] == null) errors.push(`FW.${k}: missing "${f}"`);
for (const code of Object.keys(FW.ATK ? FW.ATK.t : {})) if (FW.ATK.grp(code) === '99') errors.push(`ATT&CK ${code}: no tactic assigned in ATK_TAC`);
const counts = fwKeys.map(k => `${k}=${Object.keys(FW[k].t).length}`).join(' ');
warn.forEach(x => console.warn('WARN  ' + x));
if (errors.length) { errors.forEach(x => console.error('ERROR ' + x)); console.error(`\n${errors.length} error(s).`); process.exit(1); }
console.log(`OK  ${CONTROLS.length} controls · ${DOMAINS.length} domains · ${RAS.length} architectures · framework requirements: ${counts}`);
