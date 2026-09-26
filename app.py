import re
import uuid
import time
import binascii
from datetime import datetime

import gevent.monkey
gevent.monkey.patch_all()

from flask import Flask, request, jsonify, make_response
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import requests
import urllib3
from google.protobuf.internal.decoder import _DecodeVarint, _DecodeVarint32

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    import jwt as pyjwt
    HAS_JWT = True
except ImportError:
    HAS_JWT = False

# ====== PRETTY PRINT JSON ======
try:
    import orjson
    def _jsonify(data, status=200):
        return make_response(
            orjson.dumps(data, option=orjson.OPT_INDENT_2), 
            status, 
            {'Content-Type': 'application/json'}
        )
except ImportError:
    import json
    def _jsonify(data, status=200):
        return make_response(
            json.dumps(data, indent=2, ensure_ascii=False), 
            status, 
            {'Content-Type': 'application/json'}
        )

app = Flask(__name__)

# ====== GLOBAL SESSION ======
session = requests.Session()
adapter = requests.adapters.HTTPAdapter(
    pool_connections=100, pool_maxsize=100, max_retries=0, pool_block=False
)
session.mount('https://', adapter)
session.mount('http://', adapter)

# ====== AES KEYS ======
AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV  = b'6oyZDr22E3ychjM%'

# ====== VERSION & URLs ======
LOGIN_URL = "https://loginbp.ppmainecoonghj.com"
MAJOR_LOGIN_URL = LOGIN_URL + "/MajorLogin"
OAUTH_URL = "https://100067.connect.garena.com/oauth/guest/token/grant"
INSPECT_URL = "https://100067.connect.garena.com/oauth/token/inspect"
FREEFIRE_UPDATE_URL = "https://clientbp.ppmainecoonghj.com/UpdateSocialBasicInfo"
OB_VERSION = "OB55"
CLIENT_VERSION = "1.132.1"
FREEFIRE_VERSION = OB_VERSION

# ====== PROTOBUF HELPERS ======
def encode_varint(value):
    out = []
    while True:
        b = value & 0x7F
        value >>= 7
        if value:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)

def build_payload_from_dict(fields_dict):
    payload = b''
    for key, value in sorted(fields_dict.items()):
        field_num = int(key)
        if isinstance(value, bool):
            payload += encode_varint((field_num << 3) | 0) + encode_varint(1 if value else 0)
        elif isinstance(value, int):
            payload += encode_varint((field_num << 3) | 0) + encode_varint(value)
        elif isinstance(value, str):
            data = value.encode('utf-8')
            payload += encode_varint((field_num << 3) | 2) + encode_varint(len(data)) + data
        elif isinstance(value, bytes):
            payload += encode_varint((field_num << 3) | 2) + encode_varint(len(value)) + value
        elif isinstance(value, dict):
            sub = build_payload_from_dict(value)
            payload += encode_varint((field_num << 3) | 2) + encode_varint(len(sub)) + sub
        else:
            raise TypeError(f"Unsupported type for field {field_num}")
    return payload

def decode_protobuf(data):
    pos = 0
    length = len(data)
    fields = {}
    while pos < length:
        key, pos = _DecodeVarint(data, pos)
        field_number = key >> 3
        wire_type = key & 7
        if wire_type == 0:
            value, pos = _DecodeVarint(data, pos)
        elif wire_type == 2:
            size, pos = _DecodeVarint32(data, pos)
            raw = data[pos:pos + size]
            pos += size
            try:
                value = decode_protobuf(raw)
            except Exception:
                value = raw
        elif wire_type == 5:
            value = int.from_bytes(data[pos:pos + 4], 'little')
            pos += 4
        elif wire_type == 1:
            value = int.from_bytes(data[pos:pos + 8], 'little')
            pos += 8
        else:
            raise ValueError(f"Unsupported wire type {wire_type}")
        if field_number in fields:
            if not isinstance(fields[field_number], list):
                fields[field_number] = [fields[field_number]]
            fields[field_number].append(value)
        else:
            fields[field_number] = value
    return fields

def build_major_login_payload(open_id, access_token):
    fields = {
        3: str(datetime.now())[:-7],
        4: "free fire",
        5: 1,                  # platform_id: 1 = Android
        7: f"{CLIENT_VERSION}",
        8: "Android OS 11 / API-30 (RQ3A.210805.001)",
        9: "Handheld",
        10: "Verizon",
        11: "WIFI",
        12: 1080,
        13: 2400,
        14: "440",
        15: "ARMv8",
        16: 6144,
        17: "Adreno (TM) 650",
        18: "OpenGL ES 3.2 V@1.50",
        19: f"Google|{uuid.uuid4()}",
        20: "",
        21: "en",
        22: open_id,
        23: "4",
        24: "Handheld",
        25: {6: 55, 8: 81},
        29: access_token,
        30: 1,                  # platform_sdk_id: 1 = Android
        41: "Verizon",
        42: "WIFI",
        57: "7428b253defc164018c604a1ebbfebdf",
        60: 128512, 61: 38000, 62: 110731, 63: 18000, 64: 18000, 65: 26628,
        66: 25000, 67: 119234, 73: 3,
        74: "/data/app/~~random/base.apk",
        76: 1, 77: "hash|base.apk", 78: 3, 79: 2, 81: "64", 83: "2024010012",
        86: "OpenGLES3", 87: 16383, 88: 4,
        89: b"FwQVTgUPX1UaUllDDwcWCRBpWAUOUgsvA1snWlBaO1kFYg==",
        92: 9000, 93: "android", 94: "", 95: 110009, 97: 1, 98: 0, 99: "4", 100: "4",
    }
    return build_payload_from_dict(fields)

def encrypt_message(plaintext: bytes) -> bytes:
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    return cipher.encrypt(pad(plaintext, AES.block_size))

def strip_major_login_prefix(body: bytes) -> bytes:
    if len(body) <= 64:
        return body
    try:
        d0 = decode_protobuf(body)
        if 8 in d0: return body
    except Exception: pass
    try:
        d64 = decode_protobuf(body[64:])
        if 8 in d64: return body[64:]
    except Exception: pass
    return body[64:]

# ====== OAUTH GUEST LOGIN ======
OAUTH_HEADERS = {
    "User-Agent": "GarenaMSDK/5.5.0P1(SM-G998B;Android 13;en-US;USA;)",
    "Content-Type": "application/x-www-form-urlencoded",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "close"
}
OAUTH_PAYLOAD_TEMPLATE = {
    "response_type": "token",
    "client_type": "2",
    "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
    "client_id": "100067",
    "grant_type": "guest"
}

def perform_guest_login(uid, password):
    payload = OAUTH_PAYLOAD_TEMPLATE.copy()
    payload["uid"] = uid
    payload["password"] = password
    try:
        r = session.post(OAUTH_URL, data=payload, headers=OAUTH_HEADERS, timeout=10, verify=False)
        if r.status_code != 200:
            return None, None
        j = r.json()
        return j.get("access_token"), j.get("open_id")
    except Exception:
        return None, None

# ====== ✅ NEW: ACCESS TOKEN → OPEN_ID (via Inspect API) ======
def inspect_access_token(access_token):
    """Access token থেকে সরাসরি open_id বের করে (Reward/Shop2Game ছাড়াই)"""
    inspect_url = f"{INSPECT_URL}?token={access_token}"
    try:
        r = session.get(inspect_url, timeout=10, verify=False)
        if r.status_code != 200:
            return None, f"Inspect HTTP {r.status_code}: {r.text[:200]}"
        data = r.json()
        open_id = data.get("open_id")
        if not open_id:
            return None, f"open_id not found in inspect response: {data}"
        return open_id, None
    except requests.RequestException as e:
        return None, f"Inspect request error: {e}"
    except ValueError:
        return None, "Inspect invalid JSON"

# ====== MAJOR LOGIN ======
MAJORLOGIN_HEADERS = {
    "User-Agent": "UnityPlayer/2021.3.14f1 (UnityWebRequest/1.0, libcurl/7.84.0-DEV)",
    "Accept": "*/*",
    "Accept-Encoding": "deflate, gzip",
    "X-Ga-Sv": str(int(time.time())),
    "Authorization": "Bearer ",
    "X-Ga": "v1 1",
    "ReleaseVersion": f"{OB_VERSION}",
    "Content-Type": "application/x-www-form-urlencoded",
    "X-Unity-Version": "2021.3.14f1"
}

def perform_major_login(access_token, open_id):
    if not access_token or not access_token.strip():
        return None
    plain = build_major_login_payload(open_id, access_token)
    encrypted = encrypt_message(plain)
    headers = MAJORLOGIN_HEADERS.copy()
    headers["Authorization"] = f"Bearer {access_token.strip()}"
    url = MAJOR_LOGIN_URL
    for attempt in range(3):
        try:
            r = session.post(url, data=encrypted, headers=headers, verify=False, timeout=15)
            if r.status_code == 200:
                body = strip_major_login_prefix(r.content)
                decoded = decode_protobuf(body)
                token = decoded.get(8)
                if isinstance(token, bytes): token = token.decode('utf-8', errors='replace')
                if token:
                    return token
            time.sleep(1)
        except Exception:
            time.sleep(1)
    return None

# ====== BIO UPLOAD ======
BIO_HEADERS = {
    "Expect": "100-continue",
    "X-Unity-Version": "2018.4.11f1",
    "X-GA": "v1 1",
    "ReleaseVersion": FREEFIRE_VERSION,
    "Content-Type": "application/x-www-form-urlencoded",
    "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11; SM-A305F Build/RP1A.200720.012)",
    "Connection": "Keep-Alive",
    "Accept-Encoding": "gzip",
}

def encrypt_bio_data(data_bytes):
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    padded = pad(data_bytes, AES.block_size)
    return cipher.encrypt(padded)

def upload_bio_request(jwt_token, bio_text):
    try:
        fields = {
            2: 17,
            5: {},
            6: {},
            8: bio_text,
            9: 1,
            11: {},
            12: {}
        }
        data_bytes = build_payload_from_dict(fields)
        encrypted = encrypt_bio_data(data_bytes)
        headers = BIO_HEADERS.copy()
        headers["Authorization"] = f"Bearer {jwt_token}"
        resp = session.post(FREEFIRE_UPDATE_URL, headers=headers, data=encrypted, timeout=20, verify=False)
        status_text = "success" if resp.status_code == 200 else "failed"
        raw_hex = binascii.hexlify(resp.content).decode('utf-8')
        return {
            "status": status_text,
            "code": resp.status_code,
            "server_response": raw_hex
        }
    except Exception as e:
        return {"status": "failed", "code": 500, "server_response": str(e)}

def decode_jwt_info(token):
    try:
        decoded = pyjwt.decode(token, options={"verify_signature": False})
        name = decoded.get("nickname")
        region = decoded.get("lock_region")
        uid = decoded.get("account_id")
        platform_raw = decoded.get("external_type")
        try:
            platform = int(platform_raw) if platform_raw is not None else None
        except (TypeError, ValueError):
            platform = platform_raw
        return uid, name, region, platform
    except:
        return None, None, None, None

# ====== WEB UI (HTML FRONTEND) ======
HTML_PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Free Fire Bio Changer</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
        body { background: #0f0f0f; color: #fff; display: flex; justify-content: center; align-items: center; min-height: 100vh; padding: 20px; }
        .container { background: #1a1a1a; border-radius: 15px; padding: 30px; width: 100%; max-width: 450px; box-shadow: 0 10px 30px rgba(0,0,0,0.7); border: 1px solid #333; }
        h1 { text-align: center; margin-bottom: 20px; color: #ff4757; font-size: 24px; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-size: 14px; color: #aaa; }
        input, select { width: 100%; padding: 12px; background: #2a2a2a; border: 1px solid #444; border-radius: 8px; color: #fff; font-size: 14px; outline: none; transition: 0.3s; }
        input:focus, select:focus { border-color: #ff4757; }
        button { width: 100%; padding: 14px; background: #ff4757; color: #fff; border: none; border-radius: 8px; font-size: 16px; font-weight: bold; cursor: pointer; margin-top: 10px; transition: 0.3s; }
        button:hover { background: #e0404f; }
        button:disabled { background: #555; cursor: not-allowed; }
        .result { margin-top: 20px; padding: 15px; background: #111; border-radius: 8px; border: 1px solid #333; display: none; overflow-x: auto; }
        .result pre { font-size: 12px; color: #0f0; white-space: pre-wrap; word-wrap: break-word; }
        .hidden { display: none; }
        .credit { text-align: center; margin-top: 20px; font-size: 12px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔥 Free Fire Bio Changer</h1>
        <form id="bioForm">
            <div class="form-group">
                <label>Login Method</label>
                <select id="method" onchange="toggleFields()">
                    <option value="uid">UID & Password</option>
                    <option value="access">Access Token</option>
                    <option value="jwt">Direct JWT</option>
                </select>
            </div>

            <div class="form-group">
                <label>New Bio</label>
                <input type="text" id="bio" placeholder="Enter new bio..." required>
            </div>

            <div id="uidFields">
                <div class="form-group">
                    <label>UID</label>
                    <input type="text" id="uid" placeholder="Enter UID">
                </div>
                <div class="form-group">
                    <label>Password</label>
                    <input type="password" id="pass" placeholder="Enter Password">
                </div>
            </div>

            <div id="accessFields" class="hidden">
                <div class="form-group">
                    <label>Access Token</label>
                    <input type="text" id="access_token" placeholder="Enter Access Token">
                </div>
            </div>

            <div id="jwtFields" class="hidden">
                <div class="form-group">
                    <label>JWT Token</label>
                    <input type="text" id="jwt" placeholder="Enter JWT Token">
                </div>
            </div>

            <button type="submit" id="submitBtn">Upload Bio</button>
        </form>

        <div class="result" id="result">
            <pre id="resultText"></pre>
        </div>

        <div class="credit">Credit: @anshalam8342 | Telegram: @anshalam8342</div>
    </div>

    <script>
        function toggleFields() {
            const method = document.getElementById('method').value;
            document.getElementById('uidFields').classList.toggle('hidden', method !== 'uid');
            document.getElementById('accessFields').classList.toggle('hidden', method !== 'access');
            document.getElementById('jwtFields').classList.toggle('hidden', method !== 'jwt');
        }

        document.getElementById('bioForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            const btn = document.getElementById('submitBtn');
            const resultDiv = document.getElementById('result');
            const resultText = document.getElementById('resultText');

            btn.disabled = true;
            btn.textContent = 'Processing...';
            resultDiv.style.display = 'none';

            const formData = new FormData();
            formData.append('bio', document.getElementById('bio').value);
            const method = document.getElementById('method').value;

            if (method === 'uid') {
                formData.append('uid', document.getElementById('uid').value);
                formData.append('pass', document.getElementById('pass').value);
            } else if (method === 'access') {
                formData.append('access_token', document.getElementById('access_token').value);
            } else if (method === 'jwt') {
                formData.append('jwt', document.getElementById('jwt').value);
            }

            try {
                const response = await fetch('/bio', {
                    method: 'POST',
                    body: formData
                });
                const data = await response.json();
                resultText.textContent = JSON.stringify(data, null, 2);
                resultDiv.style.display = 'block';
                
                if (data.status === 'success') {
                    resultText.style.color = '#0f0';
                } else {
                    resultText.style.color = '#f00';
                }
            } catch (err) {
                resultText.textContent = 'Error: ' + err.message;
                resultDiv.style.display = 'block';
                resultText.style.color = '#f00';
            } finally {
                btn.disabled = false;
                btn.textContent = 'Upload Bio';
            }
        });

        toggleFields();
    </script>
</body>
</html>
"""

@app.route("/", methods=["GET"])
def home():
    return HTML_PAGE

# ====== API ROUTE ======
@app.route("/bio", methods=["GET", "POST"])
def combined_bio_upload():
    bio = request.args.get("bio") or request.form.get("bio")
    jwt_token = request.args.get("jwt") or request.form.get("jwt")
    uid = request.args.get("uid") or request.form.get("uid")
    password = request.args.get("pass") or request.form.get("pass")
    access_token = request.args.get("access") or request.form.get("access") or request.args.get("access_token") or request.form.get("access_token")

    if not bio:
        return _jsonify({"status": "failed", "message": "Missing 'bio' parameter"}, 400)

    final_jwt = None
    login_method = "Direct JWT"
    final_open_id = None
    final_access_token = None
    final_uid = None
    final_name = None
    final_region = None

    if jwt_token:
        final_jwt = jwt_token
        j_uid, j_name, j_region, _ = decode_jwt_info(jwt_token)
        final_uid, final_name, final_region = j_uid, j_name, j_region

    elif uid and password:
        login_method = "UID/Pass Login"
        acc_token, login_openid = perform_guest_login(uid, password)
        if acc_token and login_openid:
            final_access_token = acc_token
            final_open_id = login_openid
            final_jwt = perform_major_login(final_access_token, final_open_id)
            if final_jwt:
                j_uid, j_name, j_region, _ = decode_jwt_info(final_jwt)
                final_uid, final_name, final_region = j_uid, j_name, j_region
            else:
                return _jsonify({"status": "failed", "message": "JWT Generation Failed"}, 500)
        else:
            return _jsonify({"status": "failed", "message": "Guest Login Failed (Check UID/Pass)"}, 401)

    elif access_token:
        login_method = "Access Token Login"
        final_access_token = access_token

        # ✅ NEW: Inspect API থেকে সরাসরি open_id বের করা
        final_open_id, err = inspect_access_token(access_token)
        if err or not final_open_id:
            return _jsonify({
                "status": "failed",
                "message": f"Invalid Access Token - {err or 'open_id not found'}"
            }, 400)

        final_jwt = perform_major_login(final_access_token, final_open_id)
        if final_jwt:
            j_uid, j_name, j_region, _ = decode_jwt_info(final_jwt)
            final_uid, final_name, final_region = j_uid, j_name, j_region
        else:
            return _jsonify({"status": "failed", "message": "JWT Generation Failed"}, 500)

    else:
        return _jsonify({"status": "failed", "message": "Provide JWT, or UID/Pass, or Access Token"}, 400)

    if not final_jwt:
        return _jsonify({"status": "failed", "message": "JWT Generation Failed"}, 500)

    result = upload_bio_request(final_jwt, bio)

    # ====== BIO API JSON RESPONSE ======
    response_data = {
        "status": result["status"],
        "code": result["code"],
        "bio": bio,
        "uid": str(final_uid) if final_uid else None,
        "name": final_name,
        "region": final_region,
        "login_method": login_method,
        "open_id": final_open_id,
        "access_token": final_access_token,
        "server_response": result.get("server_response", "N/A")
    }
    return _jsonify(response_data)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8342, debug=False, threaded=True)