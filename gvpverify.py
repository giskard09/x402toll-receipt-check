#!/usr/bin/env python3
"""Verificador GVP v0.2 escrito desde el TEXTO del spec (spec/gvp-0.2.md, sha256 0a06bdb0...7ee4,
main 4c2aa528). Etiqueta DIRECTED: no es verificacion independiente. Sin ML-DSA-65 (-> unverifiable, §8)."""
import json, hashlib, base64, math, re
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

# ---------- JCS (RFC 8785), §2.2 ----------
def _num(x):
    if isinstance(x,bool): raise TypeError
    if isinstance(x,int):
        x=float(x) if abs(x)>2**53 else x
        if isinstance(x,int): return str(x)
    if math.isnan(x) or math.isinf(x): raise ValueError("non-finite")
    if x==0: return "0"
    r=repr(abs(x)); s="-" if x<0 else ""
    # repr -> digits/exponent -> ES Number::toString
    m=re.fullmatch(r"(\d+)(?:\.(\d+))?(?:e([+-]?\d+))?",r)
    ip,fp,ex=m.group(1),m.group(2) or "",int(m.group(3) or 0)
    digits=(ip+fp).lstrip("0"); lead0=len(ip+fp)-len((ip+fp).lstrip("0"))
    n=len(ip)-lead0+ex           # decimal point position
    digits=digits.rstrip("0") or "0"; k=len(digits)
    if k<=n<=21: out=digits+"0"*(n-k)
    elif 0<n<=21: out=digits[:n]+"."+digits[n:]
    elif -6<n<=0: out="0."+"0"*(-n)+digits
    else:
        e=n-1; es=("+" if e>=0 else "-")+str(abs(e))
        out=digits[0]+("."+digits[1:] if k>1 else "")+"e"+es
    return s+out
def _str(s):
    o=['"']
    for ch in s:
        c=ord(ch)
        if ch=='"': o.append('\\"')
        elif ch=="\\": o.append("\\\\")
        elif ch=="\b": o.append("\\b")
        elif ch=="\f": o.append("\\f")
        elif ch=="\n": o.append("\\n")
        elif ch=="\r": o.append("\\r")
        elif ch=="\t": o.append("\\t")
        elif c<0x20: o.append("\\u%04x"%c)
        else: o.append(ch)
    o.append('"'); return "".join(o)
def jcs(v,depth=0):
    if depth>100: raise ValueError("too deep")
    if v is None: return "null"
    if v is True: return "true"
    if v is False: return "false"
    if isinstance(v,(int,float)): return _num(v)
    if isinstance(v,str): return _str(v)
    if isinstance(v,list): return "["+",".join(jcs(i,depth+1) for i in v)+"]"
    if isinstance(v,dict):
        ks=sorted(v.keys(),key=lambda k:k.encode("utf-16-be"))
        return "{"+",".join(_str(k)+":"+jcs(v[k],depth+1) for k in ks)+"}"
    raise TypeError(type(v))
def jcs_bytes(v): return jcs(v).encode("utf-8")

# ---------- §3 hash ----------
FP_KEYS=("endpoint","inputs","result","method","dataVintage")
def jcs_hash(fp): return "sha256:"+hashlib.sha256(jcs_bytes(fp)).hexdigest()
def response_hash(fp):
    if set(fp)!=set(FP_KEYS): raise ValueError("fixed point must have exactly the five members (§2.1)")
    return "sha256:"+hashlib.sha256(jcs_bytes(fp)).hexdigest()

# ---------- §6 attestation, key-first dispatch §6.3 ----------
SHAPES={"GVP-Attestation/1","GVP-Attestation/2","GVP-Attestation/3"}
IMPL={"Ed25519"}
def verify_attestation(payload,sig,keylist,kept=None,implemented=IMPL):
    """keylist: {'status':'published'|'unreachable'|'none','list':{issuer,keys}}
    returns (state, info) con state en verified/unverifiable/contradicted; sin probar alternativas."""
    info={}
    pv=payload.get("payloadVersion")
    if pv is None: pv="GVP-Attestation/1"
    if pv not in SHAPES: return "unverifiable",{"why":"payloadVersion not implemented"}
    # (e) §6: /2 y /3 llevan fixedPointVersion DENTRO del payload firmado; sin el no se puede
    # reconstruir la forma declarada -> contradicted (como el paquete). /1 no lo lleva.
    if pv in ("GVP-Attestation/2","GVP-Attestation/3"):
        fpv=payload.get("fixedPointVersion")
        if not isinstance(fpv,str) or not fpv: return "contradicted",{"why":pv+" requires fixedPointVersion in the signed payload"}
    signed_alg=payload.get("alg") if pv.endswith("/3") else "Ed25519"
    keyId=sig.get("keyId"); emb=sig.get("publicKey")
    if pv.endswith("/3") and (not keyId or not payload.get("alg")): return "contradicted",{"why":"/3 lacks keyId or alg"}
    st=keylist["status"]
    if st=="none":  # integrity-only
        if pv.endswith("/3") and not keyId: return "contradicted",{"why":"/3 without keyId"}
        if not emb: return "contradicted",{"why":"no embedded key"}
        try: k=load_der_public_key(base64.b64decode(emb))
        except Exception: return "contradicted",{"why":"bad embedded key"}
        if not isinstance(k,Ed25519PublicKey): return "unverifiable",{"why":"alg not implemented"}
        info["integrityOnly"]=True
        return _chk(k,payload,sig,info)
    def find(lst):
        for e in (lst or {}).get("keys",[]):
            if keyId and isinstance(e.get("keyId"),str) and e["keyId"]==keyId: return e
            if (not keyId) and emb and not pv.endswith("/3") and e.get("publicKey")==emb: return e
        return None
    fetched=keylist["list"] if st=="published" else None
    fe=find(fetched); ke=find(kept)
    entry=None
    if ke:   # el kept gobierna ese keyId (§6.3); reportar discontinuidad
        entry=ke
        if fetched is not None:
            same=[e for e in fetched.get("keys",[]) if e.get("keyId")==ke["keyId"]]
            if not same: info["discontinuity"]="dropped"
            elif same[0].get("alg")!=ke["alg"] or same[0].get("publicKey")!=ke["publicKey"]: info["discontinuity"]="rebound"
        if fetched is None or "discontinuity" in info: info["keptAt"]=ke.get("lastSeenAt")
    elif fe: entry=fe
    if entry is None:
        if st=="unreachable": return "unverifiable",{"why":"key list unreachable, no kept entry"}
        return "contradicted",{"why":"keyId/publicKey not in fetched list"}
    if emb and emb!=entry["publicKey"]: return "contradicted",{**info,"why":"embedded publicKey differs from listed"}
    if signed_alg!=entry["alg"]: return "contradicted",{**info,"why":"signed alg differs from pinned alg"}
    if entry["alg"] not in implemented: return "unverifiable",{**info,"why":"pinned alg not implemented"}
    k=load_der_public_key(base64.b64decode(entry["publicKey"]))
    return _chk(k,payload,sig,info)
def _chk(k,payload,sig,info):
    try:
        k.verify(base64.b64decode(sig["signature"]),jcs_bytes(payload)); return "verified",info
    except (InvalidSignature,Exception): return "contradicted",{**info,"why":"signature does not verify"}

# ---------- (e) regla de fixedPointVersion (§2.1.1, §2.1.3) ----------
# Recibo sin fixedPointVersion = FixedPoint/1 (carve-out §2.1.1). En L2 se toma del payload FIRMADO.
# /1: hash igual y dataVintage libre. /2: mismo hash, dataVintage ^[0-9]{4}(-[0-9]{2}(-[0-9]{2})?)?$ y fecha real.
# Otro identificador: "unsupported fixed-point rule set" (nunca mismatch/forgery).
import datetime
def fixed_point_rule(fpv,data_vintage):
    if fpv is None or fpv=="GVP-FixedPoint/1": return "ok"
    if fpv=="GVP-FixedPoint/2":
        if not re.fullmatch(r"[0-9]{4}(-[0-9]{2}(-[0-9]{2})?)?",data_vintage or ""): return "reject: dataVintage grammar"
        try:
            p=data_vintage.split("-"); datetime.date(int(p[0]),int(p[1]) if len(p)>1 else 1,int(p[2]) if len(p)>2 else 1)
        except ValueError: return "reject: not a real calendar date"
        return "ok"
    return "unsupported fixed-point rule set"

# ---------- reconstruccion del payload desde el recibo (mapeo fijado por adenda a) ----------
def build_payload(receipt,sig,mapping):
    """mapping: {'issuer':fn(receipt)->str,'agentId':fn(receipt)->str|None} o None -> M3 (no especificado).
    La forma depende de payloadVersion declarado en sig; nunca se prueban alternativas."""
    if mapping is None: return None,"mapping unspecified (M3)"
    pv=sig.get("payloadVersion")
    base={"responseHash":receipt["responseHash"],"endpoint":receipt["endpoint"],"dataVintage":receipt["dataVintage"],
          "issuer":mapping["issuer"](receipt),"agentId":mapping["agentId"](receipt),"issuedAt":receipt["issuedAt"]}
    if pv is None or pv=="GVP-Attestation/1": return base,None
    if pv=="GVP-Attestation/2": base.update(payloadVersion=pv,fixedPointVersion=receipt.get("fixedPointVersion")); return base,None
    if pv=="GVP-Attestation/3": base.update(payloadVersion=pv,fixedPointVersion=receipt.get("fixedPointVersion"),alg=sig.get("alg")); return base,None
    return {"payloadVersion":pv},None   # forma no implementada -> unverifiable en verify_attestation
