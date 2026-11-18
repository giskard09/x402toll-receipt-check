import json,sys,copy
from gvpverify import *
ok=bad=0
# L1 (§8.1 precondicion 1)
for v in json.load(open("vectors/expected.json")):
    h=jcs_hash(v["fixedPoint"]); good=h==v["expectedHash"]; ok+=good; bad+=not good
    if not good: print("L1 FAIL",v["name"])
print("L1 vectors",ok,"ok",bad,"fail")
# outcomes
d=json.load(open("vectors/attestation-outcomes.json")); kl=d["keyList"]; ok=bad=0
for c in d["cases"]:
    impl=set(c["implemented"]) if "implemented" in c else IMPL
    stt=c.get("keyList","published")
    kls={"status":stt,"list":kl}
    s,info=verify_attestation(c["payload"],c["signature"],kls,None,impl&IMPL if True else impl)
    good=s==c["expected"]; ok+=good; bad+=not good
    if not good: print("OUTCOME FAIL",c["name"],"got",s,"exp",c["expected"],info)
print("outcomes",ok,"ok",bad,"fail",len(d["cases"]))
# kept
k=json.load(open("vectors/attestation-kept.json")); ok=bad=0
for c in k["cases"]:
    st=c["keyList"]
    fl=k["keyLists"].get(st) if st in k["keyLists"] else None
    kls={"status":"published" if fl else st,"list":fl}
    kept=k["keptList"] if c.get("kept") else None
    s,info=verify_attestation(c["payload"],c["signature"],kls,kept)
    good=s==c["expected"] and info.get("keptAt")==c.get("keptAt") and info.get("discontinuity")==c.get("discontinuity"); ok+=good; bad+=not good
    if not good: print("KEPT FAIL",c["name"],"got",s,"exp",c["expected"],info)
print("kept",ok,"ok",bad,"fail",len(k["cases"]))
