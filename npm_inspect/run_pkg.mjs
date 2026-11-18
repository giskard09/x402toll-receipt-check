// SEGUNDA LECTURA (no ejecutada aun): corre verifyAttestation del paquete golden-vector-provenance@0.12.0
// sobre los vectores publicados. Solo importa ./x/package/index.mjs (node:crypto), sin red, sin fs de escritura.
import { verifyAttestation } from './x/package/index.mjs';
import fs from 'node:fs';
const J=p=>JSON.parse(fs.readFileSync(p,'utf8'));
const V='../vectors/';
const d=J(V+'attestation-outcomes.json'); const out=[];
for (const c of d.cases){
  const st=c.keyList; const kl = st==='published'?d.keyList : st==='unreachable'?null : undefined;
  const r=verifyAttestation(c.payload,c.signature,{keyList:kl, implemented:c.implemented});
  out.push({name:c.name,got:r.outcome,exp:c.expected});
}
const k=J(V+'attestation-kept.json');
for (const c of k.cases){
  const st=c.keyList; const kl= st==='unreachable'?null : k.keyLists[st];
  const r=verifyAttestation(c.payload,c.signature,{keyList:kl,kept:c.kept?k.keptList:undefined});
  out.push({name:'KEPT '+c.name,got:r.outcome,exp:c.expected,keptAt:r.keptAt,disc:r.discontinuity});
}
const bad=out.filter(x=>x.got!==x.exp);
console.log(JSON.stringify({total:out.length,discrepancias:bad},null,1));
