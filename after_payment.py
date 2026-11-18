#!/usr/bin/env python3
"""Corre TODO tras el pago, sin improvisar: V1-V6, N1-N8, y prepara la segunda lectura sobre el recibo real.
Uso: python3 after_payment.py [--mapping mapping.json]   (usa el ultimo raw/paid_*)
mapping.json (solo si M1 lo fija sin ambiguedad, decision humana tras leer signature.signed):
  {"issuer":"path:issuer.service" | "literal:x402toll.com", "agentId":"path:onChainAnchor.agentId" | "null"}"""
import json,glob,sys,base64,hashlib,time,urllib.request,copy,pathlib
from gvpverify import *
import verify_receipt as VR
OUT=pathlib.Path("report"+time.strftime("_%Y%m%dT%H%M%SZ",time.gmtime()));OUT.mkdir()
def get(path,o):
    for p in path.split("."): o=o[p]
    return o
def mk_mapping(f):
    if not f: return None
    m=json.load(open(f))
    def fn(spec):
        if spec=="null": return lambda r:None
        k,_,v=spec.partition(":"); return (lambda r,v=v:v) if k=="literal" else (lambda r,v=v:get(v,r))
    return {"issuer":fn(m["issuer"]),"agentId":fn(m["agentId"])}
mapf=sys.argv[sys.argv.index("--mapping")+1] if "--mapping" in sys.argv else None
mapping=mk_mapping(mapf)
body=sorted(glob.glob("raw/paid_*_response_body.bin"))[-1];stamp=body.split("paid_")[1].split("_")[0]
hdr=open(f"raw/paid_{stamp}_response_headers.txt").read()
raw=open(body,"rb").read();doc=json.loads(raw)
r=doc if "receiptVersion" in doc else next((v for v in doc.values() if isinstance(v,dict) and "receiptVersion" in v),None)
rep={"stamp":stamp,"response_bytes":len(raw),"response_sha256":hashlib.sha256(raw).hexdigest(),"top_keys":list(doc)}
if r is None: rep["ERROR"]="no se encontro un recibo GVP en la respuesta"; json.dump(rep,open(OUT/"report.json","w"),indent=1); print(json.dumps(rep,indent=1)); sys.exit(1)
sig=r.get("signature") or {}
rep["signature.signed (M1: leer a mano)"]=sig.get("signed"); rep["payloadVersion"]=sig.get("payloadVersion"); rep["mapping"]="M1/M2 -> "+(mapf or "NINGUNO (M3: unverifiable)")
# lista de claves SOLO del origen pagado, ahora
rq=urllib.request.Request("https://x402toll.com/.well-known/gvp-keys.json",headers={"User-Agent":"rama-verif/0"})
try:
    kb=urllib.request.urlopen(rq,timeout=30).read(); kl={"status":"published","list":json.loads(kb)}
    (OUT/"gvp-keys.json").write_bytes(kb); rep["keys"]={"fetchedAt":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()),"sha256":hashlib.sha256(kb).hexdigest()}
except Exception as e: kl={"status":"unreachable","list":None}; rep["keys"]="unreachable: "+str(e)[:60]
(OUT/"receipt.json").write_text(json.dumps(r,indent=1,ensure_ascii=False))
rep["V1"]=VR.V1(r); rep["V3"]=VR.V3(r)
st,info=VR.V2(r,kl,mapping); rep["V2"]={"state":st,"info":info}
# V4: pago en cadena, tx del header payment-response
pr=[l.split(":",1)[1].strip() for l in hdr.splitlines() if l.lower().startswith(("payment-response","x-payment-response"))]
auth=json.load(open(f"raw/paid_{stamp}_authorization.json"))
try:
    pj=json.loads(base64.b64decode(pr[0]+"="*(-len(pr[0])%4))); tx=pj.get("transaction") or pj.get("txHash")
    rep["payment-response"]={k:v for k,v in pj.items() if k!="payer"}
    rep["V4"]=VR.V4(tx,auth["from"],auth["to"],"0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",auth["value"],auth["nonce"])
except Exception as e: rep["V4"]="NO VERIFICADO: "+str(e)[:100]
rep["V5"]=VR.V5(r.get("onChainAnchor")); rep["V6"]=VR.V6(r.get("recheckUrl",""),r["responseHash"]) if r.get("recheckUrl") else "no se encontro lista"
rep["N1-N8"]=VR.negatives(r,kl,mapping)
# segunda lectura: casos para run_pkg_receipt.mjs (mismos casos, payloads reconstruidos con el MISMO mapeo)
cases=[]
def add(name,rr,klm,exp):
    p,why=build_payload(rr,rr.get("signature") or {},mapping)
    cases.append({"name":name,"payload":p,"signature":rr.get("signature"),"keyList":klm,"mine":exp})
if mapping:
    add("N8 intacto",r,"published",VR.V2(r,kl,mapping)[0])
    c=copy.deepcopy(r);c["issuedAt"]=c["issuedAt"][:-2]+"1Z";add("N2 issuedAt",c,"published",VR.V2(c,kl,mapping)[0])
    c=copy.deepcopy(r);c["signature"]["keyId"]="no-such-key";add("N3 keyId inexistente",c,"published",VR.V2(c,kl,mapping)[0])
    add("N4 lista inalcanzable",r,"unreachable",VR.V2(r,{"status":"unreachable","list":None},mapping)[0])
    c=copy.deepcopy(r);b=bytearray(base64.b64decode(c["signature"]["signature"]));b[3]^=1;c["signature"]["signature"]=base64.b64encode(bytes(b)).decode();add("N7 firma alterada",c,"published",VR.V2(c,kl,mapping)[0])
fp={"endpoint":r["endpoint"],"inputs":r["canonicalInputs"],"result":r["result"],"method":r["method"],"dataVintage":r["dataVintage"]}
json.dump({"keyList":kl["list"],"cases":cases,"fixedPoint":fp,"responseHash":r["responseHash"]},open(OUT/"second_reading_input.json","w"),indent=1)
json.dump(rep,open(OUT/"report.json","w"),indent=1,default=str); print(json.dumps(rep,indent=1,default=str)); print("\nreporte en",OUT)
