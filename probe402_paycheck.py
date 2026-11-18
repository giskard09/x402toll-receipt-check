#!/usr/bin/env python3
"""Sonda SIN PAGO: POST al endpoint, guarda bytes crudos del request y de la response 402,
lee payTo/asset/amount/network del header payment-required y aborta si difieren de lo esperado."""
import http.client, json, ssl, base64, sys, time, hashlib, pathlib
HOST="x402toll.com"; PATH="/v1/paycheck"
BODY=b'{"salary":85000,"state":"TX"}'
OUT=pathlib.Path("raw"); OUT.mkdir(exist_ok=True)
EXPECT_NET="eip155:8453"; EXPECT_AMOUNT="1000000"
req_head=f"POST {PATH} HTTP/1.1\r\nHost: {HOST}\r\nContent-Type: application/json\r\nContent-Length: {len(BODY)}\r\nUser-Agent: rama-verif/0\r\nAccept: application/json\r\n\r\n".encode()
c=http.client.HTTPSConnection(HOST,context=ssl.create_default_context(),timeout=30)
c.request("POST",PATH,body=BODY,headers={"Content-Type":"application/json","User-Agent":"rama-verif/0","Accept":"application/json"})
r=c.getresponse(); body=r.read()
stamp=time.strftime("%Y%m%dT%H%M%SZ",time.gmtime())
(OUT/f"probeplain_{stamp}_request.bin").write_bytes(req_head+BODY)
hdrs=r.getheaders()
(OUT/f"probeplain_{stamp}_response_headers.txt").write_text(f"HTTP {r.status} {r.reason}\n"+"".join(f"{k}: {v}\n" for k,v in hdrs))
(OUT/f"probeplain_{stamp}_response_body.bin").write_bytes(body)
print("status",r.status,"body_sha256",hashlib.sha256(body).hexdigest(),"len",len(body))
pr=dict((k.lower(),v) for k,v in hdrs).get("payment-required")
if not pr: print("SIN header payment-required"); print(body[:600]); sys.exit(2)
dec=base64.b64decode(pr+"="*(-len(pr)%4))
(OUT/f"probeplain_{stamp}_payment_required_decoded.json").write_bytes(dec)
j=json.loads(dec); print(json.dumps(j,indent=1)[:2500])
acc=j.get("accepts",[j])[0] if isinstance(j.get("accepts"),list) else j
amt=str(acc.get("amount",acc.get("maxAmountRequired"))); net=acc.get("network")
print("\nLEIDO EN VIVO -> payTo:",acc.get("payTo"),"asset:",acc.get("asset"),"amount:",amt,"network:",net)
ok=(amt==EXPECT_AMOUNT and net==EXPECT_NET); print("CHEQUEO esperado (amount=1000000, eip155:8453):","OK" if ok else "ABORTAR: difiere"); sys.exit(0 if ok else 3)
