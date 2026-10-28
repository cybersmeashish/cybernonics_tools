# Contributing

Contributions are welcome, especially new controls, reference architectures, framework-mapping
corrections, and vendor syntax for the hardening generator.

## Ground rules
1. **Cite a source.** Every control needs an NSA guide section (`ref: '7.3'`) or `Ext` plus a rationale in the PR.
2. **Keep it static.** No build step, no framework, and no new runtime dependencies without discussion.
3. **Run the validator** before you push: `node scripts/validate.js`.

## Data model (in `assets/js/`)
| File | What lives there |
|---|---|
| `data.js` | `DOMAINS`, `CONTROLS` (built with `C(id, domain, title, ref, severity, architectures, fix, commands)`) and `RAS` (reference architectures) |
| `frameworks.js` | `FW` (framework requirement titles) and `XMAP` (control → `[CSF[], CIS[], ISO[]]`) |
| `app.js` | Rendering, scoring, roadmap, hardening generator and UI |

### Add a control
```js
C('R10','MGT','Control statement','7.x','High',ALL /* or ['RA1','RA3'] */,
  'Remediation guidance.', 'optional\nCisco IOS\ncommands')
```
Then add `R10:[[...CSF],[...CIS],[...ISO]]` to `XMAP`, and add a title to `FW.*.t` for any requirement code that's new.

### Add a reference architecture
Append to `RAS`: `tiers` is an ordered list of `[label, ['type|Node label', ...]]`, where the type is
`s` security · `n` network · `i` identity · `m` management/monitoring · `a` asset. List the relevant control IDs in `ctl`,
and add the RA id to each relevant control's `ras` array.

### Add a framework
Add a key to `FW` with `name`, `grp` (code → group), `gn` (group names in display order), `t` (code → title) and the display fields `abbr`, `pre`, `gl` and `unit`. Push one more array onto every `XMAP` entry, in the same order as the `FW` keys, and add an `<option>` to the framework `<select>` in `index.html`. The UI, CSV export and validator pick it up automatically.
