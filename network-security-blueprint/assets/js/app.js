/*! Enterprise Network Security Blueprint | MIT License | https://github.com/ */
/* Application logic: rendering, scoring, roadmap, hardening generator, framework view. */
/* ===================== STATE ===================== */
const KEY='nsbp_state_v1';
let state={org:'',scope:'ALL',ans:{}};
try{const s=localStorage.getItem(KEY);if(s)state=Object.assign(state,JSON.parse(s));}catch(e){}
function save(){try{localStorage.setItem(KEY,JSON.stringify(state));}catch(e){}}
const SV={impl:1,partial:0.5,none:0};
const SL={'':'— Not assessed —',impl:'Implemented',partial:'Partial',none:'Not implemented',na:'N/A'};
function applicable(c){return state.scope==='ALL'||c.ras===ALL||c.ras.includes(state.scope);}
function st(id){return (state.ans[id]&&state.ans[id].s)||'';}
function esc(s){return String(s).replace(/[&<>"]/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[m]));}
function level(p){if(p==null)return 'Not assessed';if(p<40)return 'L1 · Initial';if(p<60)return 'L2 · Developing';if(p<80)return 'L3 · Defined';if(p<95)return 'L4 · Managed';return 'L5 · Optimized';}

/* ===================== TABS ===================== */
const tabs=document.querySelectorAll('#tabs button');
function showTab(t){tabs.forEach(b=>b.classList.toggle('on',b.dataset.t===t));document.querySelectorAll('.panel').forEach(p=>p.classList.toggle('on',p.id==='p-'+t));if(t==='ga'){renderCharts();}if(t==='rm')renderRoadmap();if(t==='hb')renderHB();if(t==='fm')renderFM();try{history.replaceState(null,'','#'+t);}catch(e){}window.scrollTo(0,0);}
tabs.forEach(b=>b.onclick=()=>showTab(b.dataset.t));

/* ===================== REFERENCE ARCHITECTURES ===================== */
function wrap(t,max){const w=t.split(' ');const L=[];let cur='';w.forEach(x=>{if((cur+' '+x).trim().length>max&&cur){L.push(cur);cur=x;}else cur=(cur+' '+x).trim();});if(cur)L.push(cur);return L.slice(0,3);}
function drawRA(ra){
 const W=980,LW=150,TH=74,G=16,top=6;const H=top+ra.tiers.length*(TH+G)-G+6;
 let s=`<svg viewBox="0 0 ${W} ${H}" width="100%" role="img" aria-label="${esc(ra.name)} diagram" style="max-height:${H}px">`;
 s+=`<defs><marker id="ah" markerWidth="8" markerHeight="8" refX="4" refY="4" orient="auto"><path d="M0,0 L8,4 L0,8 z" class="arrh"/></marker></defs>`;
 const avail=W-LW-16;
 ra.tiers.forEach((t,i)=>{
  const y=top+i*(TH+G);
  s+=`<rect class="band" x="0" y="${y}" width="${W}" height="${TH}" rx="10"/>`;
  wrap(t[0],16).forEach((ln,k)=>{s+=`<text class="tl" x="14" y="${y+TH/2-4+k*14}">${esc(ln)}</text>`;});
  const n=t[1].length,gap=10;const bw=Math.min(200,(avail-(n-1)*gap)/n);const tot=n*bw+(n-1)*gap;const x0=LW+(avail-tot)/2;
  t[1].forEach((nd,j)=>{const [ty,lab]=nd.split('|');const x=x0+j*(bw+gap);
   s+=`<rect class="n-${ty}" x="${x}" y="${y+10}" width="${bw}" height="${TH-20}" rx="7" stroke-width="1.2"><title>${esc(lab)}</title></rect>`;
   const lines=wrap(lab,Math.max(12,Math.floor(bw/6.6)));const ly=y+TH/2-(lines.length-1)*7+4;
   lines.forEach((ln,k)=>{s+=`<text class="nt" x="${x+bw/2}" y="${ly+k*14}" text-anchor="middle">${esc(ln)}</text>`;});
  });
  if(i<ra.tiers.length-1){const cx=LW+avail/2;s+=`<line class="arr" x1="${cx}" y1="${y+TH}" x2="${cx}" y2="${y+TH+G-2}" marker-end="url(#ah)"/>`;}
 });
 return s+'</svg>';
}
let curRA='RA1';
function renderRAList(){document.getElementById('raList').innerHTML=RAS.map(r=>`<button class="ra-btn ${r.id===curRA?'on':''}" data-r="${r.id}">${r.id} · ${esc(r.name)}<small>${esc(r.short)}</small></button>`).join('');document.querySelectorAll('.ra-btn').forEach(b=>b.onclick=()=>{curRA=b.dataset.r;renderRA();});}
function renderRA(){
 renderRAList();const ra=RAS.find(r=>r.id===curRA);
 document.getElementById('raTitle').textContent=ra.id+' · '+ra.name;
 document.getElementById('raDesc').textContent=ra.desc;
 document.getElementById('raSvg').innerHTML=drawRA(ra);
 document.getElementById('raDec').innerHTML=ra.dec.map(x=>`<li>${esc(x)}</li>`).join('');
 document.getElementById('raThr').innerHTML=ra.thr.map(x=>`<li>${esc(x)}</li>`).join('')+(()=>{const t=[...new Set(ra.ctl.flatMap(id=>(XMAP[id]||[])[FWI.ATK]||[]))].sort(natSort);return t.length?`<li style="list-style:none;margin:10px 0 0 -18px"><span class="muted" style="font-size:11px">MITRE ATT&amp;CK techniques addressed (${t.length})</span><br>${t.map(x=>`<span class="ctag" title="${esc(FW.ATK.t[x]||'')}">${x}</span>`).join('')}</li>`:'';})();
 document.getElementById('raCtl').innerHTML=ra.ctl.map(id=>{const c=CMAP[id];const s=st(id);return `<div class="ritem"><b class="mono">${id}</b> <span class="pill sev-${c.sev}">${c.sev}</span> <span class="muted" style="font-size:11px">${s?SL[s]:'not assessed'}</span><br><span class="sub">${esc(c.t)}</span></div>`;}).join('');
}
document.getElementById('raAssess').onclick=()=>{state.scope=curRA;save();document.getElementById('scope').value=curRA;renderGA();showTab('ga');};

/* ===================== GAP ASSESSMENT ===================== */
const scopeSel=document.getElementById('scope');
scopeSel.innerHTML='<option value="ALL">Whole enterprise (all controls)</option>'+RAS.map(r=>`<option value="${r.id}">${r.id} · ${esc(r.name)}</option>`).join('');
scopeSel.value=state.scope;scopeSel.onchange=()=>{state.scope=scopeSel.value;save();renderGA();};
const orgIn=document.getElementById('org');orgIn.value=state.org||'';orgIn.oninput=()=>{state.org=orgIn.value;save();};
document.getElementById('flt').onchange=renderGA;

function compute(){
 const dom={};DOMAINS.forEach(d=>dom[d.id]={num:0,den:0,gaps:{Critical:0,High:0,Medium:0,Low:0},n:0});
 let num=0,den=0,total=0,done=0,gaps=0,crit=0;
 CONTROLS.filter(applicable).forEach(c=>{total++;const s=st(c.id);if(s)done++;const w=SEVW[c.sev];dom[c.d].n++;
  if(s in SV){num+=w*SV[s];den+=w;dom[c.d].num+=w*SV[s];dom[c.d].den+=w;if(SV[s]<1){gaps++;dom[c.d].gaps[c.sev]++;if(c.sev==='Critical')crit++;}}
 });
 return {dom,score:den?Math.round(num/den*100):null,total,done,gaps,crit};
}
function renderGA(){
 const f=document.getElementById('flt').value;const tb=document.querySelector('#gaTbl tbody');let h='';
 DOMAINS.forEach(d=>{
  const rows=CONTROLS.filter(c=>c.d===d.id&&applicable(c)).filter(c=>{const s=st(c.id);if(f==='gaps')return s==='none'||s==='partial';if(f==='unset')return !s;return true;});
  if(!rows.length)return;
  h+=`<tr class="dom-h"><td colspan="6">${esc(d.name)} <span class="muted">${d.ref}</span></td></tr>`;
  rows.forEach(c=>{const s=st(c.id);const n=(state.ans[c.id]&&state.ans[c.id].n)||'';
   h+=`<tr><td class="mono"><b>${c.id}</b></td><td>${esc(c.t)}<div class="muted" style="font-size:12px;margin-top:3px">Fix: ${esc(c.fix)}</div>${fwLine(c.id)}</td><td class="mono">${c.ref==='Ext'?'Ext':'§'+c.ref}</td><td><span class="pill sev-${c.sev}">${c.sev}</span></td>
   <td><select class="st s-${s}" data-id="${c.id}">${Object.keys(SL).map(k=>`<option value="${k}" ${k===s?'selected':''}>${SL[k]}</option>`).join('')}</select></td>
   <td><input type="text" class="nt-in" data-id="${c.id}" value="${esc(n)}" placeholder="Evidence…" style="width:100%"></td></tr>`;});
 });
 tb.innerHTML=h||'<tr><td colspan="6" class="muted">No controls match this filter.</td></tr>';
 tb.querySelectorAll('select.st').forEach(el=>el.onchange=()=>{const id=el.dataset.id;state.ans[id]=state.ans[id]||{};state.ans[id].s=el.value;el.className='st s-'+el.value;save();updateKPIs();renderCharts();if(document.getElementById('p-fm').classList.contains('on'))renderFM();});
 tb.querySelectorAll('input.nt-in').forEach(el=>el.oninput=()=>{const id=el.dataset.id;state.ans[id]=state.ans[id]||{};state.ans[id].n=el.value;save();});
 updateKPIs();renderCharts();
}
function updateKPIs(){
 const r=compute();
 const sc=r.score==null?'—':r.score;
 ['kScore','hdrScore'].forEach(i=>document.getElementById(i).textContent=sc);
 ['kLevel','hdrLevel'].forEach(i=>document.getElementById(i).textContent=level(r.score));
 const pct=r.total?Math.round(r.done/r.total*100):0;
 document.getElementById('kDone').textContent=pct+'%';document.getElementById('kBar').style.width=pct+'%';
 document.getElementById('kGaps').textContent=r.gaps;document.getElementById('kGapsS').textContent=`${r.done} of ${r.total} controls assessed`;
 document.getElementById('kCrit').textContent=r.crit;
}
let radar=null,bar=null;
function tok(v,f){const x=getComputedStyle(document.documentElement).getPropertyValue(v).trim();return x||f;}
function alpha(c,a){c=String(c).trim();if(c[0]==='#'){let x=c.slice(1);if(x.length===3)x=x.split('').map(y=>y+y).join('');const n=parseInt(x,16);return `rgba(${n>>16&255},${n>>8&255},${n&255},${a})`;}return c;}
function chartTheme(){const T={txt:tok('--color-text','#1a1a1a'),txt2:tok('--color-text-secondary','#5e5e5e'),muted:tok('--color-text-muted','#9ca3af'),grid:tok('--color-border','rgba(0,0,0,.12)'),pri:tok('--color-primary','#9333ea'),ok:tok('--color-success','#22c55e'),warn:tok('--color-warning','#f59e0b'),err:tok('--color-error','#ef4444'),info:tok('--color-info','#3b82f6'),font:tok('--font-sans','sans-serif')};
 if(typeof Chart!=='undefined'){Chart.defaults.font.family=T.font;Chart.defaults.color=T.txt2;}return T;}
function renderCharts(){
 if(typeof Chart==='undefined')return;
 if(!document.getElementById('p-ga').classList.contains('on'))return;
 const r=compute();const doms=DOMAINS.filter(d=>r.dom[d.id].n>0);
 const cats=doms.map(d=>d.name.replace(' (Ext.)','').replace('Authentication, Authorization, Accounting','AAA'));
 const vals=doms.map(d=>{const x=r.dom[d.id];return x.den?Math.round(x.num/x.den*100):null;});
 const T=chartTheme();
 if(radar){radar.destroy();radar=null;} if(bar){bar.destroy();bar=null;}
 radar=new Chart(document.getElementById('chRadar'),{type:'radar',
  data:{labels:cats.map(c=>wrap(c,16)),datasets:[
   {label:'Current',data:vals,borderColor:T.pri,backgroundColor:alpha(T.pri,.2),pointBackgroundColor:T.pri,borderWidth:2,spanGaps:true},
   {label:'Target (80)',data:cats.map(()=>80),borderColor:T.ok,borderDash:[6,4],borderWidth:1.5,pointRadius:0,fill:false}]},
  options:{responsive:true,maintainAspectRatio:false,animation:{duration:400},
   plugins:{title:{display:true,text:'Maturity by domain (%)',color:T.txt,font:{size:14,weight:'600'}},legend:{position:'bottom',labels:{color:T.txt2,boxWidth:12}}},
   scales:{r:{min:0,max:100,ticks:{stepSize:25,display:false},grid:{color:T.grid},angleLines:{color:T.grid},pointLabels:{color:T.txt2,font:{size:10.5}}}}}});
 const sev=['Critical','High','Medium','Low'],sc={Critical:T.err,High:T.warn,Medium:T.info,Low:T.muted};
 bar=new Chart(document.getElementById('chBar'),{type:'bar',
  data:{labels:cats,datasets:sev.map(s=>({label:s,data:doms.map(d=>r.dom[d.id].gaps[s]),backgroundColor:sc[s],borderWidth:0}))},
  options:{indexAxis:'y',responsive:true,maintainAspectRatio:false,animation:{duration:400},
   plugins:{title:{display:true,text:'Open gaps by domain & severity',color:T.txt,font:{size:14,weight:'600'}},legend:{position:'bottom',labels:{color:T.txt2,boxWidth:12}}},
   scales:{x:{stacked:true,beginAtZero:true,ticks:{precision:0,color:T.txt2},grid:{color:T.grid}},y:{stacked:true,ticks:{color:T.txt2,font:{size:11}},grid:{display:false}}}}});
}

/* toolbar */
document.getElementById('bSample').onclick=()=>{
 const pat=['impl','partial','none','impl','partial','impl','none','impl','partial','impl','impl','none'];
 CONTROLS.forEach((c,i)=>{let s=pat[(i*7+3)%pat.length];if(c.d==='ZTC'&&i%2)s='none';if(c.id==='R8'||c.id==='M4')s='partial';state.ans[c.id]={s,n:state.ans[c.id]&&state.ans[c.id].n||''};});
 if(!state.org)state.org='Sample Enterprise';orgIn.value=state.org;save();renderGA();renderRA();
};
document.getElementById('bReset').onclick=()=>{if(!confirm('Clear all assessment answers?'))return;state.ans={};save();renderGA();renderRA();};
function dl(name,data,type){try{const b=new Blob([data],{type});const a=document.createElement('a');a.href=URL.createObjectURL(b);a.download=name;document.body.appendChild(a);a.click();setTimeout(()=>{URL.revokeObjectURL(a.href);a.remove();},500);}catch(e){alert('Download blocked in this viewer. Open the file in a browser to export.');}}
document.getElementById('bCsv').onclick=()=>{
 const q=v=>'"'+String(v==null?'':v).replace(/"/g,'""')+'"';
 const rows=[['Organisation','Scope','ID','Domain','Control','NSA Ref','Severity','Status','Evidence','Remediation','NIST CSF 2.0','CIS Controls v8','ISO 27001:2022','NIST SP 800-53 r5','MITRE ATT&CK']];
 CONTROLS.filter(applicable).forEach(c=>rows.push([state.org,state.scope,c.id,DOMAINS.find(d=>d.id===c.d).name,c.t,c.ref,c.sev,SL[st(c.id)],(state.ans[c.id]||{}).n||'',c.fix,fwTags(c.id,'CSF').join('; '),fwTags(c.id,'CIS').join('; '),fwTags(c.id,'ISO').map(x=>'A.'+x).join('; '),fwTags(c.id,'N53').join('; '),fwTags(c.id,'ATK').join('; ')]));
 dl('network_security_gap_assessment.csv',rows.map(r=>r.map(q).join(',')).join('\n'),'text/csv');
};
document.getElementById('bJson').onclick=()=>dl('network_security_assessment.json',JSON.stringify(state,null,2),'application/json');
document.getElementById('fJson').onchange=e=>{const f=e.target.files[0];if(!f)return;const rd=new FileReader();rd.onload=()=>{try{const o=JSON.parse(rd.result);state=Object.assign({org:'',scope:'ALL',ans:{}},o);save();orgIn.value=state.org;scopeSel.value=state.scope;renderGA();renderRA();}catch(x){alert('Invalid JSON file');}};rd.readAsText(f);};
document.getElementById('bPrint').onclick=()=>{renderRoadmap();window.print();};

/* ===================== ROADMAP ===================== */
function gapsList(){return CONTROLS.filter(applicable).filter(c=>{const s=st(c.id);return s==='none'||s==='partial';}).map(c=>{const s=st(c.id);const risk=SEVW[c.sev]*(1-SV[s]);const ph=c.sev==='Critical'?1:(c.sev==='High'?2:3);return {c,s,risk,ph};}).sort((a,b)=>b.risk-a.risk||a.ph-b.ph);}
function renderRoadmap(){
 const g=gapsList();
 const P=[{n:1,t:'Phase 1 · 0–30 days',s:'Stop the bleeding: Critical exposures'},{n:2,t:'Phase 2 · 31–90 days',s:'Harden: High-severity controls'},{n:3,t:'Phase 3 · 91–180 days',s:'Optimize: Medium/Low and maturity uplift'}];
 document.getElementById('rmCols').innerHTML=P.map(p=>{const it=g.filter(x=>x.ph===p.n);return `<div class="card phase p${p.n}"><h3>${p.t}</h3><div class="muted" style="font-size:12px;margin-bottom:6px">${p.s} · ${it.length} item(s)</div>${it.length?it.map(x=>`<div class="ritem"><b class="mono">${x.c.id}</b> <span class="pill sev-${x.c.sev}">${x.c.sev}</span> <span class="muted" style="font-size:11px">${SL[x.s]}</span><br>${esc(x.c.fix)}</div>`).join(''):'<div class="muted">No open items.</div>'}</div>`;}).join('');
 document.querySelector('#rmTbl tbody').innerHTML=g.length?g.map((x,i)=>`<tr><td class="mono">${i+1}</td><td class="mono"><b>${x.c.id}</b></td><td>${esc(x.c.t)}</td><td><span class="pill sev-${x.c.sev}">${x.c.sev}</span></td><td>${SL[x.s]}</td><td>${esc(x.c.fix)}</td><td>${fwTags(x.c.id,'ATK').map(t=>`<span class="ctag" title="${esc(FW.ATK.t[t]||'')}">${t}</span>`).join('')||'<span class="muted">—</span>'}</td><td class="mono">P${x.ph}</td></tr>`).join(''):'<tr><td colspan="8" class="muted">No open gaps in the current scope. Complete the Gap Assessment first.</td></tr>';
}

/* ===================== HARDENING BASELINE ===================== */
let hSel=new Set(CONTROLS.filter(c=>c.cmd).map(c=>c.id));
function renderHB(){
 const list=CONTROLS.filter(c=>c.cmd);
 document.getElementById('hList').innerHTML=DOMAINS.map(d=>{const cs=list.filter(c=>c.d===d.id);if(!cs.length)return '';return `<h3 style="margin-top:8px">${esc(d.name)}</h3>`+cs.map(c=>`<label class="chk"><input type="checkbox" data-id="${c.id}" ${hSel.has(c.id)?'checked':''}><span><b class="mono">${c.id}</b> ${esc(c.t)} <span class="muted mono">(${c.ref==='Ext'?'Ext':'§'+c.ref})</span></span></label>`).join('');}).join('');
 document.querySelectorAll('#hList input').forEach(el=>el.onchange=()=>{el.checked?hSel.add(el.dataset.id):hSel.delete(el.dataset.id);genHB();});
 genHB();
}
function genHB(){
 const hdr=`! ==========================================================\n! Enterprise Network Hardening Baseline — Cisco IOS/IOS-XE\n! Source: NSA Network Infrastructure Security Guide v1.2\n! Org: ${state.org||'<ORG>'}   Generated: ${new Date().toISOString().slice(0,10)}\n! Review & replace all <PLACEHOLDERS>. Lab-validate first.\n! ==========================================================\n`;
 const body=CONTROLS.filter(c=>c.cmd&&hSel.has(c.id)).map(c=>`!\n! [${c.id}] ${c.t} (${c.ref==='Ext'?'Ext':'NSA §'+c.ref})\n${c.cmd}`).join('\n');
 document.getElementById('hOut').textContent=hdr+(body||'! (no controls selected)')+'\n!\nend\n! exec: copy running-config startup-config';
}
document.getElementById('hAll').onclick=()=>{hSel=new Set(CONTROLS.filter(c=>c.cmd).map(c=>c.id));renderHB();};
document.getElementById('hNone').onclick=()=>{hSel=new Set();renderHB();};
document.getElementById('hGaps').onclick=()=>{hSel=new Set(CONTROLS.filter(c=>c.cmd&&(st(c.id)==='none'||st(c.id)==='partial')).map(c=>c.id));renderHB();};
document.getElementById('hCopy').onclick=()=>{const t=document.getElementById('hOut').textContent;const m=document.getElementById('hMsg');
 (navigator.clipboard?navigator.clipboard.writeText(t):Promise.reject()).then(()=>m.textContent='Copied ✓').catch(()=>{const r=document.createRange();r.selectNodeContents(document.getElementById('hOut'));const s=window.getSelection();s.removeAllRanges();s.addRange(r);m.textContent='Selected — press Ctrl/Cmd+C';});};


/* ===================== FRAMEWORK MAPPING VIEW ===================== */
const FWK=Object.keys(FW);const FWI={};FWK.forEach((k,i)=>FWI[k]=i);
function fwTags(id,fw){const m=XMAP[id];return m?m[FWI[fw]]:[];}
function fwLine(id){const m=XMAP[id];if(!m)return '';return `<div class="fw">${FWK.map((k,i)=>`<b>${esc(FW[k].abbr)}</b> ${(m[i]||[]).map(x=>FW[k].pre+x).join(', ')||'—'}`).join(' · ')}</div>`;}
function natSort(a,b){const sp=x=>x.split(/[.\-()]/).filter(Boolean);const pa=sp(a),pb=sp(b);for(let i=0;i<Math.max(pa.length,pb.length);i++){const x=pa[i]||'',y=pb[i]||'';const nx=+x,ny=+y;if(!isNaN(nx)&&!isNaN(ny)){if(nx!==ny)return nx-ny;}else if(x!==y)return x<y?-1:1;}return 0;}
function reqCoverage(fw){
 const idx=FWI[fw];const R={};
 CONTROLS.forEach(c=>{(XMAP[c.id]||[[],[],[]])[idx].forEach(r=>{(R[r]=R[r]||[]).push(c);});});
 const go=Object.keys(FW[fw].gn);return Object.keys(R).sort(natSort).map(r=>{
  const cs=R[r].filter(applicable);let num=0,den=0,ass=0;
  cs.forEach(c=>{const s=st(c.id);if(s in SV){num+=SEVW[c.sev]*SV[s];den+=SEVW[c.sev];ass++;}});
  const pct=den?Math.round(num/den*100):null;
  const status=!cs.length?'Out of scope':(pct==null?'Not assessed':(pct>=95?'Covered':(pct>=50?'Partial':'Gap')));
  return {r,title:FW[fw].t[r]||'',grp:FW[fw].grp(r),all:R[r],cs,pct,ass,status};
 }).sort((a,b)=>go.indexOf(a.grp)-go.indexOf(b.grp)||natSort(a.r,b.r));
}
let fmChart=null;
function renderFM(){
 const fw=document.getElementById('fmFw').value,view=document.getElementById('fmView').value,q=document.getElementById('fmQ').value.trim().toLowerCase();
 document.getElementById('fmScope').textContent='Scope: '+(state.scope==='ALL'?'Whole enterprise':(RAS.find(r=>r.id===state.scope)||{}).name);
 const rows=reqCoverage(fw);const inS=rows.filter(x=>x.status!=='Out of scope');
 const cnt=k=>inS.filter(x=>x.status===k).length;
 document.getElementById('fmK1').textContent=inS.length;document.getElementById('fmK1l').textContent=FW[fw].unit+' mapped';
 document.getElementById('fmK1s').textContent=`${FW[fw].name} · ${inS.filter(x=>x.status!=='Not assessed').length} assessed`;
 document.getElementById('fmK2').textContent=cnt('Covered');document.getElementById('fmK3').textContent=cnt('Partial');document.getElementById('fmK4').textContent=cnt('Gap');
 /* chart: coverage by group */
 const groups={};inS.forEach(x=>{const g=groups[x.grp]=groups[x.grp]||{num:0,den:0,n:0};g.n++;if(x.pct!=null){g.num+=x.pct;g.den++;}});
 const gk=Object.keys(FW[fw].gn).filter(k=>groups[k]);
 const cats=gk.map(k=>FW[fw].gn[k]||k);const data=gk.map(k=>groups[k].den?Math.round(groups[k].num/groups[k].den):null);
 if(typeof Chart!=='undefined'&&document.getElementById('p-fm').classList.contains('on')){
  const T=chartTheme();
  const col=v=>v==null?T.muted:(v>=95?T.ok:(v>=50?T.warn:T.err));
  if(fmChart){fmChart.destroy();fmChart=null;}
  fmChart=new Chart(document.getElementById('chFm'),{data:{labels:cats,datasets:[
    {type:'bar',label:'Coverage %',data:data,backgroundColor:data.map(col),borderRadius:4,order:2},
    {type:'line',label:'Target 80',data:cats.map(()=>80),borderColor:T.ok,borderDash:[6,4],borderWidth:1.5,pointRadius:0,fill:false,order:1}]},
   options:{responsive:true,maintainAspectRatio:false,animation:{duration:400},
    plugins:{legend:{display:false},title:{display:true,text:FW[fw].name+' — average requirement coverage by '+FW[fw].gl+' (%)',color:T.txt,font:{size:14,weight:'600'}},
     tooltip:{callbacks:{label:ctx=>ctx.datasetIndex===0?('Coverage: '+(ctx.raw==null?'not assessed':ctx.raw+'%')):'Target: 80%',afterLabel:ctx=>{if(ctx.datasetIndex!==0)return '';const g=groups[gk[ctx.dataIndex]];return `Requirements: ${g.n} (${g.den} assessed)`;}}}},
    scales:{y:{min:0,max:100,grid:{color:T.grid},ticks:{color:T.txt2}},x:{grid:{display:false},ticks:{color:T.txt2,font:{size:11}}}}}});
 }
 const th=document.querySelector('#fmTbl thead'),tb=document.querySelector('#fmTbl tbody');
 const csCls=s=>s==='Covered'?'Covered':(s==='Partial'?'Partial':(s==='Gap'?'Gap':'NA'));
 if(view==='req'){
  th.innerHTML=`<tr><th style="width:100px">${esc(FW[fw].abbr)} ID</th><th>Title</th><th style="width:34%">Mapped blueprint controls</th><th style="width:70px">Coverage</th><th style="width:100px">Status</th></tr>`;
  const f=rows.filter(x=>!q||(x.r+' '+x.title+' '+x.all.map(c=>c.id+' '+c.t).join(' ')).toLowerCase().includes(q));
  let lastG=null,h='';
  f.forEach(x=>{if(x.grp!==lastG){lastG=x.grp;h+=`<tr class="dom-h"><td colspan="5">${esc(FW[fw].gn[x.grp]||x.grp)}</td></tr>`;}
   h+=`<tr><td class="mono"><b>${FW[fw].pre}${x.r}</b></td><td>${esc(x.title)}</td><td>${x.all.map(c=>{const s=st(c.id);const inSc=applicable(c);return `<span class="ctag ${s==='impl'?'cs-Covered':s==='partial'?'cs-Partial':s==='none'?'cs-Gap':''}" title="${esc(c.t)} — ${inSc?(SL[s]||'not assessed'):'out of scope'}" style="${inSc?'':'opacity:.45'}">${c.id}</span>`;}).join('')}</td><td class="cov">${x.pct==null?'—':x.pct+'%'}</td><td><span class="pill cs-${csCls(x.status)}">${x.status}</span></td></tr>`;});
  tb.innerHTML=h||'<tr><td colspan="5" class="muted">No matches.</td></tr>';
 }else{
  th.innerHTML=`<tr><th style="width:56px">ID</th><th>Blueprint control</th><th style="width:60px">NSA</th>${FWK.map(k=>`<th>${esc(FW[k].abbr)}</th>`).join('')}<th style="width:110px">Status</th></tr>`;
  let h='';
  DOMAINS.forEach(d=>{const cs=CONTROLS.filter(c=>c.d===d.id&&applicable(c)).filter(c=>{const m=XMAP[c.id]||[[],[],[]];return !q||(c.id+' '+c.t+' '+m.flat().join(' ')).toLowerCase().includes(q);});if(!cs.length)return;
   h+=`<tr class="dom-h"><td colspan="${4+FWK.length}">${esc(d.name)}</td></tr>`;
   cs.forEach(c=>{const m=XMAP[c.id]||[[],[],[]];const s=st(c.id);
    const tg=(arr,fwk,pre)=>arr.length?arr.map(r=>`<span class="ctag" title="${esc(FW[fwk].t[r]||'')}">${pre}${r}</span>`).join(''):'<span class="muted">—</span>';
    h+=`<tr><td class="mono"><b>${c.id}</b></td><td>${esc(c.t)}</td><td class="mono">${c.ref==='Ext'?'Ext':'§'+c.ref}</td>${FWK.map((k,i)=>`<td>${tg(m[i]||[],k,FW[k].pre)}</td>`).join('')}<td><span class="pill ${s==='impl'?'cs-Covered':s==='partial'?'cs-Partial':s==='none'?'cs-Gap':'cs-NA'}">${SL[s]==='— Not assessed —'?'Not assessed':SL[s]}</span></td></tr>`;});
  });
  tb.innerHTML=h||'<tr><td colspan="7" class="muted">No matches.</td></tr>';
 }
}
['fmFw','fmView'].forEach(i=>document.getElementById(i).onchange=renderFM);
document.getElementById('fmQ').oninput=renderFM;

/* ===================== INIT ===================== */
renderRA();renderGA();
document.querySelectorAll('.card').forEach(c=>c.classList.add('fade'));

/* theme toggle */
document.getElementById('themeBtn').onclick=()=>{const t=document.documentElement.getAttribute('data-theme')==='dark'?'light':'dark';document.documentElement.setAttribute('data-theme',t);try{localStorage.setItem('nsbp_theme',t);}catch(e){}renderCharts();if(document.getElementById('p-fm').classList.contains('on'))renderFM();};
/* source link: auto-derive on GitHub Pages (owner.github.io/repo) */
(function(){const a=document.getElementById('srcLink');const host=location.hostname;if(host.endsWith('.github.io')){const owner=host.split('.')[0];const repo=location.pathname.split('/').filter(Boolean)[0]||(owner+'.github.io');a.href=`https://github.com/${owner}/${repo}`;}else{a.href='https://github.com/';}})();
/* deep links: #ga, #fm ...  and ?sample=1 loads demo data when empty */
(function(){const t=location.hash.slice(1);if(new URLSearchParams(location.search).has('sample')&&!Object.keys(state.ans).length)document.getElementById('bSample').click();if(['bp','ra','ga','rm','hb','fm'].includes(t))showTab(t);})();
