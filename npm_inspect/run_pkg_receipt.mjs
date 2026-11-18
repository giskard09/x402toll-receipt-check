// SEGUNDA LECTURA sobre el RECIBO REAL (no ejecutada aun). Lee report_*/second_reading_input.json (generado por after_payment.py)
// y corre verifyAttestation y gvpHash de golden-vector-provenance@0.12.0 (solo node:crypto, sin red, sin escritura).
// Uso: cd ~/x402toll_verif/npm_inspect && env -i PATH="$PATH" HOME=/tmp/npmhome node run_pkg_receipt.mjs ../report_<stamp>/second_reading_input.json
import { verifyAttestation, gvpHash } from './x/package/index.mjs';
import fs from 'node:fs';
const inp=JSON.parse(fs.readFileSync(process.argv[2],'utf8'));
const rows=[];
for (const c of inp.cases){
  const kl=c.keyList==='published'?inp.keyList:null;
  const r=verifyAttestation(c.payload,c.signature,{keyList:kl,implemented:['Ed25519']});
  rows.push({name:c.name,paquete:r.outcome,razon:r.reason,mio:c.mine,coincide:r.outcome===c.mine});
}
const h=gvpHash(inp.fixedPoint);
rows.push({name:'V1 responseHash recomputado por el paquete',paquete:h,mio:inp.responseHash,coincide:h===inp.responseHash});
const f=JSON.parse(JSON.stringify(inp.fixedPoint)); const k=Object.keys(f.result)[0]; f.result[k]=typeof f.result[k]==='number'?f.result[k]+1:String(f.result[k])+'x';
rows.push({name:'N1 result alterado: el hash debe cambiar',paquete:gvpHash(f)!==inp.responseHash?'FAIL (como se espera)':'IGUAL (mal)',mio:'FAIL',coincide:gvpHash(f)!==inp.responseHash});
console.log(JSON.stringify(rows,null,1));
console.log('discrepancias:',rows.filter(x=>!x.coincide).length);
