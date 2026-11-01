import os, json, random, warnings
os.environ["PYTHONWARNINGS"] = "ignore"
warnings.filterwarnings("ignore")

import hmac
import hashlib
import requests
import urllib3
urllib3.disable_warnings()

from http.server import BaseHTTPRequestHandler

HEX_KEY = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"
KEY     = HEX_KEY.encode()


UA_POOL = [
    "GarenaMSDK/4.0.42(NX809J ;Android 9;en;US;app 1.132.9 2024010012;)",
    "GarenaMSDK/4.0.42(SM-G991B ;Android 13;en;IN;app 1.132.9 2024010012;)",
    "GarenaMSDK/4.0.42(Redmi Note 11 ;Android 12;hi;IN;app 1.132.9 2024010012;)",
    "GarenaMSDK/4.0.39(SM-A325M ;Android 13;en;HK;)",
    "GarenaMSDK/4.0.39(2201122G ;Android 13;en;ID;)",
    "GarenaMSDK/4.0.39(RMX3700 ;Android 14;en;IN;)",
    "GarenaMSDK/4.0.19P9(A063 ;Android 13;en;IN;)",
    "GarenaMSDK/4.0.19P9(CPH2451 ;Android 13;en;PH;)",
    "GarenaMSDK/4.0.42(M2102J20SG ;Android 12;en;ID;app 1.132.9 2024010012;)",
    "GarenaMSDK/4.0.42(ASUS_I005DA ;Android 11;en;US;app 1.132.9 2024010012;)",
    "GarenaMSDK/4.0.42(SM-A155F ;Android 14;en;TH;app 1.132.9 2024010012;)",
    "GarenaMSDK/4.0.42(V2203 ;Android 12;en;VN;app 1.132.9 2024010012;)",
    "GarenaMSDK/4.0.42(Redmi 2201117PI ;Android 13;hi;IN;app 1.132.9 2024010012;)",
    "GarenaMSDK/4.0.42(SM-A536B ;Android 14;en;PH;app 1.132.9 2024010012;)",
    "GarenaMSDK/4.0.39(RMX3368 ;Android 12;en;TH;)",
    "GarenaMSDK/4.0.42(pixel 7 ;Android 14;en;US;app 1.132.9 2024010012;)",
    "GarenaMSDK/4.0.42(23124RA7EO ;Android 14;en;IN;app 1.132.9 2024010012;)",
    "GarenaMSDK/4.0.39(SM-M146B ;Android 14;en;PH;)",
    "GarenaMSDK/4.0.42(22081212UG ;Android 13;en;ID;app 1.132.9 2024010012;)",
    "GarenaMSDK/4.0.42(CPH2611 ;Android 14;en;TH;app 1.132.9 2024010012;)",
    "GarenaMSDK/4.0.39(SM-A546E ;Android 14;en;IN;)",
    "GarenaMSDK/4.0.42(V2247 ;Android 13;en;VN;app 1.132.9 2024010012;)",
]


def pick_ua():
    return random.choice(UA_POOL)


def gen_password():
    return ''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=64))


def gen_name():
    exp = {'0':'⁰','1':'¹','2':'²','3':'³','4':'⁴','5':'⁵','6':'⁶','7':'⁷','8':'⁸','9':'⁹'}
    return f"xRaRe{''.join(exp[d] for d in f'{random.randint(1, 99999):05d}')}"


def guest_register(ua):
    password = gen_password()
    body = json.dumps(
        {"app_id": 100067, "client_type": 2, "password": password, "source": 2},
        separators=(',', ':'),
    )
    sig = hmac.new(KEY, body.encode(), hashlib.sha256).hexdigest()

    resp = requests.post(
        "https://100067.connect.garena.com/api/v2/oauth/guest:register",
        headers={
            "User-Agent": ua,
            "Authorization": f"Signature {sig}",
            "Accept": "application/json",
            "Content-Type": "application/json; charset=utf-8",
            "Host": "100067.connect.garena.com",
            "Connection": "Keep-Alive",
        },
        data=body, verify=False, timeout=9,
    )

    if resp.status_code != 200:
        raise Exception(f"register HTTP {resp.status_code}: {resp.text[:150]}")

    data = resp.json()
    if "data" not in data or "uid" not in data["data"]:
        raise Exception(f"register rejected: {str(data)[:150]}")

    return data["data"]["uid"], password


def guest_token(uid, password, ua):
    body = json.dumps({
        "client_id": 100067, "client_secret": HEX_KEY, "client_type": 2,
        "password": password, "response_type": "token", "uid": uid,
    }, separators=(',', ':'))

    resp = requests.post(
        "https://100067.connect.garena.com/api/v2/oauth/guest/token:grant",
        headers={
            "User-Agent": ua,
            "Accept": "application/json",
            "Content-Type": "application/json; charset=utf-8",
            "Host": "100067.connect.garena.com",
            "Connection": "Keep-Alive",
        },
        data=body, verify=False, timeout=9,
    )

    if resp.status_code != 200:
        raise Exception(f"token HTTP {resp.status_code}: {resp.text[:150]}")

    data = resp.json()
    if "data" not in data or "access_token" not in data["data"]:
        raise Exception(f"token rejected: {str(data)[:150]}")

    return data["data"]["access_token"], data["data"]["open_id"]


def generate_account():
    ua = pick_ua()
    uid, password = guest_register(ua)
    access_token, open_id = guest_token(uid, password, ua)
    return {
        "success":      True,
        "uid":          uid,
        "password":     password,
        "open_id":      open_id,
        "access_token": access_token,
        "name":         gen_name(),
        "account_id":   None,
        "ua_used":      ua,
    }


class handler(BaseHTTPRequestHandler):
    def _send(self, status, obj):
        body = json.dumps(obj, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._handle()

    def do_POST(self):
        self._handle()

    def _handle(self):
        try:
            self._send(200, generate_account())
        except Exception as e:
            self._send(500, {"success": False, "error": str(e)})

    def log_message(self, *args):
        pass
