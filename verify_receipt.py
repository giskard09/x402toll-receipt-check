#!/usr/bin/env python3
"""V1-V6 + N1-N8 sobre un recibo GVP v0.2. DIRECTED (verificador propio desde el texto del spec).
Uso: verify_receipt.py selftest | verify_receipt.py real <receipt.json> <keys.json> <paid_dir_stamp>"""
import json,sys,copy,base64,hashlib,urllib.request,re
from gvpverify import *
import jsonschema
SCHEMA=json.load(open("schema/receipt.schema.json"))
def V1(r):
    fp={"endpoint":r["endpoint"],"inputs":r["canonicalInputs"],"result":r["result"],"method":r["method"],"dataVintage":r["dataVintage"]}
    rule=fixed_point_rule(r.get("fixedPointVersion"),r["dataVintage"])
    if rule!="ok": return "NO-APLICA: "+rule
    return "PASS" if response_hash(fp)==r["responseHash"] else "FAIL"
def V3(r):
    try: jsonschema.Draft202012Validator(SCHEMA).validate(r); return "PASS"
    except jsonschema.ValidationError as e: return "FAIL: "+e.message[:120]
def V2(r,keylist,mapping,kept=None):
    sig=r.get("signature")
    if not sig: return "unverifiable","no signature block"
    payload,why=build_payload(r,sig,mapping)
    if payload is None: return "unverifiable","mapeo no especificado (M3): "+why
    return verify_attestation(payload,sig,keylist,kept)
def run_all(r,keylist,mapping):
    return {"V1":V1(r),"V3":V3(r),"V2":V2(r,keylist,mapping)}
# ---- negativos N1-N8 sobre copias ----
def flip_b64(s,i=3):
    b=bytearray(base64.b64decode(s));b[i]^=1;return base64.b64encode(bytes(b)).decode()
def negatives(r,keylist,mapping):
    out={}
    def pick(f):
        c=copy.deepcopy(r);f(c);return c
    def chg(c): c["result"]=json.loads(json.dumps(c["result"])); k=next(iter(c["result"])); v=c["result"][k]; c["result"][k]=(v+1) if isinstance(v,(int,float)) and not isinstance(v,bool) else str(v)+"x"
    out["N1 result 1 byte -> V1 FAIL"]=(V1(pick(chg)),"FAIL")
    out["N2 issuedAt cambiado -> contradicted"]=(V2(pick(lambda c:c.__setitem__("issuedAt",c["issuedAt"][:-2]+"1Z")),keylist,mapping)[0],"contradicted")
    out["N3 keyId inexistente -> contradicted"]=(V2(pick(lambda c:c["signature"].__setitem__("keyId","no-such-key")),keylist,mapping)[0],"contradicted")
    out["N4 lista inalcanzable sin kept -> unverifiable"]=(V2(r,{"status":"unreachable","list":None},mapping)[0],"unverifiable")
    def pv(c):
        s=c["signature"]; cur=s.get("payloadVersion")
        s["payloadVersion"]="GVP-Attestation/2" if cur=="GVP-Attestation/3" else ("GVP-Attestation/3" if cur=="GVP-Attestation/2" else "GVP-Attestation/2")
        if cur is None: s["payloadVersion"]="GVP-Attestation/2"
    st=V2(pick(pv),keylist,mapping)[0]; out["N5 payloadVersion cambiado -> nunca verified"]=(st,"contradicted|unverifiable")
    other=base64.b64encode(b"\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00"+bytes(range(32))).decode()
    out["N6 publicKey embebida distinta -> contradicted"]=(V2(pick(lambda c:c["signature"].__setitem__("publicKey",other)),keylist,mapping)[0],"contradicted")
    out["N7 firma con 1 byte alterado -> contradicted"]=(V2(pick(lambda c:c["signature"].__setitem__("signature",flip_b64(c["signature"]["signature"]))),keylist,mapping)[0],"contradicted")
    out["N8 control positivo -> verified"]=(V2(r,keylist,mapping)[0],"verified")
    res={}
    for k,(got,exp) in out.items(): res[k]={"got":got,"expected":exp,"ok":got in exp.split("|")}
    return res

# ---- V4/V5/V6 (SIN PROBAR contra recibo real; solo lectura) ----
RPC={8453:["https://base-rpc.publicnode.com","https://mainnet.base.org"],1:["https://rpc.mevblocker.io"]}
def _rpc(url,m,p):
    rq=urllib.request.Request(url,json.dumps({"jsonrpc":"2.0","id":1,"method":m,"params":p}).encode(),{"Content-Type":"application/json","User-Agent":"curl/8"})
    return json.load(urllib.request.urlopen(rq,timeout=30)).get("result")
def V4(txhash,payer,payTo,asset,amount,nonce,rpc_index=1):
    """Transferencia USDC (topic Transfer) payer->payTo por amount y AuthorizationUsed(nonce), leida en cadena.
    Usar un RPC distinto del facilitador si es posible (rpc_index)."""
    url=RPC[8453][rpc_index%len(RPC[8453])]
    rc=_rpc(url,"eth_getTransactionReceipt",[txhash])
    if not rc: return "NO VERIFICADO: tx no encontrada"
    T="0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";A="0x98de503528ee59b575ef0c0a2576a82497bfc029a5685b209e9ec333479b10a5"
    pad=lambda a:"0x"+a.lower().replace("0x","").rjust(64,"0")
    tr=[l for l in rc["logs"] if l["address"].lower()==asset.lower() and l["topics"][0]==T and l["topics"][1]==pad(payer) and l["topics"][2]==pad(payTo) and int(l["data"],16)==int(amount)]
    au=[l for l in rc["logs"] if l["address"].lower()==asset.lower() and l["topics"][0]==A and l["topics"][1]==pad(payer) and l["topics"][2].lower()==nonce.lower()]
    return {"status":rc["status"],"block":int(rc["blockNumber"],16),"transfer_ok":bool(tr),"authorizationUsed_nonce_ok":bool(au),"rpc":url}
def V5(anchor):
    if not anchor: return "no hay anclaje en este recibo"
    reg=anchor["registry"];aid=int(anchor["agentId"]);cid=anchor.get("chainId")
    if cid not in RPC: return "NO VERIFICADO: sin RPC para chainId %s"%cid
    data="0x6352211e"+hex(aid)[2:].rjust(64,"0")   # ownerOf(uint256)
    try: r=_rpc(RPC[cid][0],"eth_call",[{"to":reg,"data":data},"latest"])
    except Exception as e: return "NO VERIFICADO: "+str(e)[:80]
    return ("agentId existe en el registry declarado; owner 0x"+r[-40:]) if r and len(r)>=66 else "NO VERIFICADO/agentId no existe: "+str(r)
    # no afirma nada sobre la respuesta ni el hash (addenda b)
def V6(recheckUrl,responseHash):
    import time
    try:
        b=urllib.request.urlopen(urllib.request.Request(recheckUrl,headers={"User-Agent":"curl/8"}),timeout=30).read().decode("utf8","replace")
    except Exception as e: return "no se encontro lista de revocacion (recheckUrl no devolvio): "+str(e)[:60]
    t=time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime())
    if "revoked" not in b: return t+" recheckUrl no es una lista de revocacion; no se encontro lista"
    return t+(" responseHash FIGURA como revocado" if responseHash in b else " responseHash no figura en la lista leida")

# ---- autotest con recibo sintetico firmado con la clave de prueba publicada ----
def selftest():
    from cryptography.hazmat.primitives.serialization import load_der_private_key
    kd=json.load(open("vectors/attestation-key.json")); priv=load_der_private_key(base64.b64decode(kd["privateKeyPkcs8B64"]),None)
    pub=json.load(open("vectors/attestation-outcomes.json"))["keyList"]["keys"][0]
    r={"receiptVersion":"GVP-Receipt/0.2","issuer":{"name":"Test","service":"gvp.example"},"issuedAt":"2026-11-17T00:00:00.000Z","tool":"t","endpoint":"/v1/paycheck",
       "canonicalInputs":{"salary":85000,"state":"TX"},"result":{"net":1234.5,"n":2},"method":"m","dataVintage":"2026.0","fixedPointVersion":"GVP-FixedPoint/1",
       "trustModel":"recompute-trust","goldenVector":{"reproduceUrl":"https://gvp.example/g"},"recheckUrl":"https://gvp.example/r","howToVerify":["a"],"disclaimer":"d"}
    r["responseHash"]=response_hash({"endpoint":r["endpoint"],"inputs":r["canonicalInputs"],"result":r["result"],"method":r["method"],"dataVintage":r["dataVintage"]})
    mapping={"issuer":lambda x:"gvp.example","agentId":lambda x:"59110"}
    sig={"payloadVersion":"GVP-Attestation/3","alg":"Ed25519","keyId":pub["keyId"],"signed":"selftest"}
    pl,_=build_payload(r,sig,mapping); sig["signature"]=base64.b64encode(priv.sign(jcs_bytes(pl))).decode(); r["signature"]=sig
    keylist={"status":"published","list":{"issuer":"gvp.example","keys":[pub]}}
    print("selftest base:",run_all(r,keylist,mapping))
    for k,v in negatives(r,keylist,mapping).items(): print(("OK  " if v["ok"] else "MAL ")+k,"->",v["got"])
    print("N-sin-mapeo (M3):",V2(r,keylist,None))
if __name__=="__main__":
    if sys.argv[1]=="selftest": selftest()
