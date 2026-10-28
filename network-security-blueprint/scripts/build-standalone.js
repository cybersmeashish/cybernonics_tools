#!/usr/bin/env node
/* Builds dist/network-security-blueprint.html — a single self-contained file
   (CSS + app JS inlined; Chart.js still loaded from jsDelivr). Usage: node scripts/build-standalone.js */
'use strict';
const fs = require('fs'), path = require('path');
const ROOT = process.env.NSBP_ROOT || path.resolve(__dirname, '..');
const read = p => fs.readFileSync(path.join(ROOT, p), 'utf8');
let html = read('index.html');
html = html.replace('<link rel="stylesheet" href="assets/css/styles.css">', () => `<style>\n${read('assets/css/styles.css')}</style>`);
html = html.replace(/<script src="(assets\/js\/[\w-]+\.js)"><\/script>/g, (_, p) => `<script>\n${read(p).replace(/<\/script/gi, '<\\/script')}</script>`);
// inline scripts need 'unsafe-inline' in the single-file build
html = html.replace("script-src 'self' https://cdn.jsdelivr.net", "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net");
fs.mkdirSync(path.join(ROOT, 'dist'), { recursive: true });
const out = path.join(ROOT, 'dist', 'network-security-blueprint.html');
fs.writeFileSync(out, html);
console.log(`Built ${path.relative(ROOT, out)} (${(html.length / 1024).toFixed(1)} KB)`);
