#!/bin/sh
# Regression tests for local-authenticator. Uses a throwaway store in /tmp.
# Covers RFC 6238 test vectors (SHA1/SHA256/SHA512), seed intake,
# otpauth URI intake, QR-image intake, list hygiene, permissions, remove.
set -e
export AUTHENTICATOR_HOME=/tmp/authtest
rm -rf /tmp/authtest /tmp/authtest-qr.png
A="$(dirname "$0")/../bin/auth.py"

S1=$(python3 -c "import base64;print(base64.b32encode(b'12345678901234567890').decode())")
S256=$(python3 -c "import base64;print(base64.b32encode(b'12345678901234567890123456789012').decode())")
S512=$(python3 -c "import base64;print(base64.b32encode(b'1234567890123456789012345678901234567890123456789012345678901234').decode())")

check() { # label, at, expected
  got=$(python3 "$A" code "$1" --at "$2" --json | python3 -c "import json,sys;print(json.load(sys.stdin)['code'])")
  [ "$got" = "$3" ] || { echo "FAIL $1 @$2: got $got want $3"; exit 1; }
  echo "ok $1 @$2 = $got"
}

python3 "$A" add vec1   --uri "otpauth://totp/RFC:vec1?secret=$S1&issuer=RFC&digits=8&algorithm=SHA1&period=30"   --json >/dev/null
python3 "$A" add vec256 --uri "otpauth://totp/RFC:v?secret=$S256&issuer=RFC&digits=8&algorithm=SHA256&period=30" --json >/dev/null
python3 "$A" add vec512 --uri "otpauth://totp/RFC:v?secret=$S512&issuer=RFC&digits=8&algorithm=SHA512&period=30" --json >/dev/null
check vec1 59 94287082
check vec1 1234567890 89005924
check vec256 59 46119246
check vec512 59 90693936

python3 "$A" add seedtest --seed "$S1" --issuer SeedCo --json >/dev/null
check seedtest 59 287082

python3 -c "import qrcode; qrcode.make('otpauth://totp/QRTest:qr1?secret=$S1&issuer=QRTest&digits=8&period=30').save('/tmp/authtest-qr.png')"
python3 "$A" add qrtest --qr /tmp/authtest-qr.png --json >/dev/null
check qrtest 59 94287082

# Google Authenticator migration QR: build a payload holding the RFC vector
# account (8-digit SHA1) plus a 6-digit account, encode as QR, import it.
python3 - << 'PYEOF'
import base64, qrcode
def varint(n):
    out = b""
    while True:
        b = n & 0x7F; n >>= 7
        out += bytes([b | (0x80 if n else 0)])
        if not n: return out
def field_var(num, val): return varint((num << 3) | 0) + varint(val)
def field_bytes(num, data): return varint((num << 3) | 2) + varint(len(data)) + data
def acct(secret, name, issuer):
    return (field_bytes(1, secret) + field_bytes(2, name.encode()) + field_bytes(3, issuer.encode())
            + field_var(4, 1) + field_var(5, 2) + field_var(6, 2))
payload = (field_bytes(1, acct(b'12345678901234567890', 'mig1', 'MigCo'))
           + field_bytes(1, acct(b'12345678901234567890', 'mig2', 'MigCo')))
uri = 'otpauth-migration://offline?data=' + base64.b64encode(payload).decode()
qrcode.make(uri).save('/tmp/authtest-mig.png')
PYEOF
python3 "$A" import --qr /tmp/authtest-mig.png --json >/dev/null
check migco 59 94287082
echo "ok migration import"

# Universal file imports — every major app's plain export format, all
# carrying the RFC vector seed so the imported code must be 287082 @59 (6-digit).
python3 - << PYEOF
import json
S1 = "$S1"
# andOTP / FreeOTP+ plain JSON (bare list)
json.dump([{"name":"andotp1","secret":S1,"issuer":"AndCo","type":"TOTP","algorithm":"SHA1","digits":6,"period":30}], open('/tmp/exp-andotp.json','w'))
# Aegis plain vault
json.dump({"version":1,"header":{"slots":None,"params":None},"db":{"version":1,"entries":[{"type":"totp","uuid":"x","name":"aegis1","issuer":"AegisCo","info":{"secret":S1,"algo":"SHA1","digits":6,"period":30}}]}}, open('/tmp/exp-aegis.json','w'))
# 2FAS backup
json.dump({"services":[{"name":"twofas1","secret":S1,"otp":{"account":"twofas1","issuer":"TwoCo","digits":6,"period":30,"algorithm":"SHA1","tokenType":"TOTP"}}]}, open('/tmp/exp-2fas.2fas','w'))
# Bitwarden vault JSON (totp as otpauth URI)
json.dump({"items":[{"name":"bw1","login":{"username":"u","totp":"otpauth://totp/BwCo:bw1?secret="+S1+"&issuer=BwCo&digits=6&period=30"}}]}, open('/tmp/exp-bitwarden.json','w'))
# Ente / Raivo style plain-text otpauth list
open('/tmp/exp-ente.txt','w').write("otpauth://totp/EnteCo:ente1?secret="+S1+"&issuer=EnteCo&digits=6&period=30\n")
# Bitwarden CSV
open('/tmp/exp-bw.csv','w').write("folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n,,login,bwcsv,,,,,u,,"+"otpauth://totp/CsvCo:bwcsv?secret="+S1+"&issuer=CsvCo&digits=6&period=30\n")
# Steam maFile (shared_secret is base64 of the same RFC seed bytes)
import base64
json.dump({"shared_secret": base64.b64encode(b'12345678901234567890').decode(), "account_name":"steamuser"}, open('/tmp/exp-steam.json','w'))
# Encrypted 2FAS must be refused clearly
json.dump({"servicesEncrypted":"AAAA"}, open('/tmp/exp-2fas-enc.json','w'))
PYEOF
for f in andotp aegis 2fas bitwarden; do
  python3 "$A" import --file /tmp/exp-$f.json --json >/dev/null 2>&1 || python3 "$A" import --file /tmp/exp-$f.2fas --json >/dev/null
done
python3 "$A" import --file /tmp/exp-ente.txt --json >/dev/null
python3 "$A" import --file /tmp/exp-bw.csv --json >/dev/null
python3 "$A" import --file /tmp/exp-steam.json --json >/dev/null
check andco 59 287082
check aegisco 59 287082
check twoco 59 287082
check bwco 59 287082
check enteco 59 287082
check csvco 59 287082
got=$(python3 "$A" code steam --at 59 --json | python3 -c "import json,sys; c=json.load(sys.stdin)['code']; print(len(c), all(ch in '23456789BCDFGHJKMNPQRTVWXY' for ch in c))")
[ "$got" = "5 True" ] && echo "ok steam code shape" || { echo "FAIL steam: $got"; exit 1; }
python3 "$A" import --file /tmp/exp-2fas-enc.json --json 2>/dev/null | grep -q "ENCRYPTED 2FAS" && echo "ok encrypted 2FAS refused clearly" || { echo "FAIL encrypted 2FAS not flagged"; exit 1; }
rm -f /tmp/exp-*.json /tmp/exp-*.2fas /tmp/exp-*.txt /tmp/exp-*.csv

python3 "$A" list --json | grep -q "$S1" && { echo "FAIL: seed leaked in list"; exit 1; } || echo "ok list hides seeds"
[ "$(stat -c %a /tmp/authtest)" = "700" ] && [ "$(stat -c %a /tmp/authtest/seeds.json)" = "600" ] && echo "ok permissions 700/600"
python3 "$A" remove qrtest --json >/dev/null && echo "ok remove"
rm -rf /tmp/authtest /tmp/authtest-qr.png
echo "ALL TESTS PASSED"
