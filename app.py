import asyncio
import time
import httpx
import json
import sys
from flask import Flask, request, jsonify
from flask_cors import CORS
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from datetime import datetime, timedelta
from google.protobuf import json_format
import urllib3

urllib3.disable_warnings()

try:
    import main_pb2
    print("✅ Proto imported")
except ImportError as e:
    print(f"❌ Proto import error: {e}")
    sys.exit(1)

# Try optional proto files
try:
    import FreeFire_pb2, AccountPersonalShow_pb2, GetOutfit_pb2
    HAS_FULL_PROTO = True
except ImportError:
    HAS_FULL_PROTO = False

# =============================================
#  CONFIG
# =============================================
RELEASEVERSION = "OB55"
USERAGENT      = "Dalvik/2.1.0 (Linux; U; Android 14; CPH2095 Build/RKQ1.211119.001)"
AES_KEY        = b'Yg&tc%DEuh6%Zc^8'
AES_IV         = b'6oyZDr22E3ychjM%'

# =============================================
#  SERVER CONFIG  (thêm VN)
# =============================================
REGION_CONFIG = {
    "BD":   {"server_url": "https://clientbp.ppmainecoonghj.com",       "release_version": "OB55"},
    "VN":   {"server_url": "https://clientbp.ppmainecoonghj.com",       "release_version": "OB55"},  # ← Vietnam
    "SG":   {"server_url": "https://clientbp.ppmainecoonghj.com",       "release_version": "OB55"},
    "TH":   {"server_url": "https://clientbp.ppmainecoonghj.com",       "release_version": "OB55"},
    "TW":   {"server_url": "https://clientbp.ppmainecoonghj.com",       "release_version": "OB55"},
    "ID":   {"server_url": "https://clientbp.ppmainecoonghj.com",       "release_version": "OB55"},
    "PK":   {"server_url": "https://clientbp.ppmainecoonghj.com",       "release_version": "OB55"},
    "CIS":  {"server_url": "https://clientbp.ppmainecoonghj.com",       "release_version": "OB55"},
    "MENA": {"server_url": "https://clientbp.ppmainecoonghj.com",       "release_version": "OB55"},
    "IND":  {"server_url": "https://client.ind.freefiremobile.com",     "release_version": "OB55"},
    "BR":   {"server_url": "https://client.us.freefiremobile.com",      "release_version": "OB55"},
    "US":   {"server_url": "https://client.us.freefiremobile.com",      "release_version": "OB55"},
    "SAC":  {"server_url": "https://client.us.freefiremobile.com",      "release_version": "OB55"},
    "NA":   {"server_url": "https://client.us.freefiremobile.com",      "release_version": "OB55"},
}

LOGIN_URL = "https://loginbp.ppmainecoonghj.com"

# =============================================
#  JWT API  (dùng để lấy token tự động)
# =============================================
JWT_API_BASE = "https://jwt-wxun.vercel.app/token"

# Credentials mỗi server  (thêm VN)
ACCOUNT_CREDENTIALS = {
    "BD":  {"uid": "7904662856",  "password": "GeneratedBy@ChannelLinkBox_JbAI3K68yIR2_RiduanCodex"},
    "VN":  {"uid": "7948851474",  "password": "PonieStore_STAR_th5pKbjdE"},  # ← thay uid/pass VN thật vào đây
    "IND": {"uid": "7739182267",  "password": "507D3250C779A4E73A74B66998E99DD4ED95A6133A07151FC0411A225C405ADD"},
    "BR":  {"uid": "7810756496",  "password": "507D3250C779A4E73A74B66998E99DD4ED95A6133A07151FC0411A225C405ADD"},
}

# Thứ tự thử khi không biết server của player  (VN đứng đầu)
REGION_PRIORITY = ["VN", "BD", "IND", "BR"]

# =============================================
#  Flask App
# =============================================
app = Flask(__name__)
CORS(app)

_token_cache: dict = {}

# =============================================
#  AES encrypt
# =============================================
def _pad(text: bytes) -> bytes:
    n = AES.block_size - (len(text) % AES.block_size)
    return text + bytes([n] * n)

def aes_enc(plaintext: bytes) -> bytes:
    return AES.new(AES_KEY, AES.MODE_CBC, AES_IV).encrypt(_pad(plaintext))

# =============================================
#  Token helpers
# =============================================
async def _jwt_from_api(region: str):
    cred = ACCOUNT_CREDENTIALS.get(region) or ACCOUNT_CREDENTIALS.get("BD")
    url  = f"{JWT_API_BASE}?uid={cred['uid']}&password={cred['password']}"
    try:
        async with httpx.AsyncClient(timeout=10.0) as c:
            r = await c.get(url, headers={"Accept": "application/json"})
            if r.status_code != 200: return None
            d = r.json()
            token = d.get("token")
            if not token: return None
            api_region = d.get("region", region)
            srv = REGION_CONFIG.get(api_region, REGION_CONFIG["BD"])["server_url"]
            return {"token": f"Bearer {token}", "region": api_region,
                    "server_url": srv, "expires_at": time.time() + 25200}
    except Exception as e:
        print(f"JWT API error ({region}): {e}")
        return None

async def _access_token(uid, password):
    import hashlib, hmac as _hmac
    ph  = hashlib.sha256(password.encode()).hexdigest()
    url = "https://100067.connect.garena.com/api/v2/oauth/guest/token:grant"
    data = {
        "client_id": 100067,
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_type": 2,
        "device_id": "",
        "password": ph,
        "response_type": "token",
        "uid": int(uid)
    }
    for _ in range(2):
        try:
            async with httpx.AsyncClient(timeout=15.0, verify=False) as c:
                r = await c.post(url, json=data,
                                 headers={"User-Agent": USERAGENT,
                                          "Content-Type": "application/json; charset=utf-8",
                                          "Accept": "application/json"})
                if r.status_code == 200:
                    d = r.json()
                    if d.get("code") == 0 and "data" in d:
                        return d["data"].get("access_token"), d["data"].get("open_id")
            await asyncio.sleep(0.5)
        except:
            await asyncio.sleep(0.5)
    return None, None

async def _token_backup(region: str):
    try:
        cred = ACCOUNT_CREDENTIALS.get(region, ACCOUNT_CREDENTIALS["BD"])
        at, oid = await _access_token(cred["uid"], cred["password"])
        if not at or not oid: return None

        if not HAS_FULL_PROTO: return None

        body  = json.dumps({"open_id": oid, "open_id_type": "4",
                             "login_token": at, "orign_platform_type": "4"})
        pmsg  = FreeFire_pb2.LoginReq()
        json_format.ParseDict(json.loads(body), pmsg)
        payload = aes_enc(pmsg.SerializeToString())

        config = REGION_CONFIG.get(region, REGION_CONFIG["BD"])
        async with httpx.AsyncClient(timeout=20.0) as c:
            r = await c.post(f"{LOGIN_URL}/MajorLogin", data=payload,
                             headers={"User-Agent": USERAGENT,
                                      "Content-Type": "application/octet-stream",
                                      "X-Unity-Version": "2018.4.11f1",
                                      "X-GA": "v1 1",
                                      "ReleaseVersion": config["release_version"]})
            if r.status_code != 200: return None
            lr = FreeFire_pb2.LoginRes()
            lr.ParseFromString(r.content)
            msg = json.loads(json_format.MessageToJson(lr))
            return {"token": f"Bearer {msg.get('token','0')}",
                    "region": msg.get("lockRegion", region),
                    "server_url": msg.get("serverUrl", config["server_url"]),
                    "expires_at": time.time() + 25200}
    except Exception as e:
        print(f"Backup token error ({region}): {e}")
        return None

async def get_token(region: str):
    cached = _token_cache.get(region)
    if cached and cached.get("expires_at", 0) > time.time():
        return cached
    ti = await _jwt_from_api(region) or await _token_backup(region)
    if ti:
        _token_cache[region] = ti
    return ti

# =============================================
#  GetPlayerPersonalShow
# =============================================
async def get_account_info(uid: int, region: str):
    try:
        ti = await get_token(region)
        if not ti: return None

        actual_region = ti.get("region", region)
        token     = ti["token"]
        server    = ti["server_url"]
        cfg       = REGION_CONFIG.get(actual_region, REGION_CONFIG["BD"])

        proto_msg = main_pb2.GetPlayerPersonalShow()
        json_format.ParseDict({"a": uid, "b": "7"}, proto_msg)
        payload   = aes_enc(proto_msg.SerializeToString())

        headers = {
            "User-Agent":    USERAGENT,
            "Connection":    "Keep-Alive",
            "Accept-Encoding": "gzip",
            "Content-Type":  "application/octet-stream",
            "Authorization": token,
            "X-Unity-Version": "2018.4.11f1",
            "X-GA":          "v1 1",
            "ReleaseVersion": cfg["release_version"]
        }

        async with httpx.AsyncClient(timeout=15.0, verify=False) as c:
            r = await c.post(f"{server}/GetPlayerPersonalShow",
                             data=payload, headers=headers)
            if r.status_code != 200: return None

            if HAS_FULL_PROTO:
                info = AccountPersonalShow_pb2.AccountPersonalShowInfo()
                info.ParseFromString(r.content)
                result = json.loads(json_format.MessageToJson(info))
            else:
                # Fallback: dùng main_pb2 decode thô
                result = {"_raw_hex": r.content.hex()}

            is_banned = result.get("isBanned", False)
            result["ban_status"]  = "🔴 BANNED" if is_banned else "🟢 UNBANNED"
            result["region"]      = actual_region
            result["server_used"] = server
            return result

    except Exception as e:
        print(f"get_account_info({uid},{region}): {e}")
        return None

# =============================================
#  Rank helper
# =============================================
def get_rank(rp):
    try: rp = int(rp)
    except: return "N/A"
    ranks = [
        (0,"Bronze I"),(100,"Bronze II"),(200,"Bronze III"),
        (300,"Silver I"),(400,"Silver II"),(500,"Silver III"),
        (600,"Gold I"),(700,"Gold II"),(800,"Gold III"),
        (900,"Platinum I"),(1000,"Platinum II"),(1100,"Platinum III"),
        (1200,"Diamond I"),(1300,"Diamond II"),(1400,"Diamond III"),
        (1500,"Heroic"),(2000,"Master"),(99999,"Grandmaster"),
    ]
    for threshold, name in reversed(ranks):
        if rp >= threshold: return name
    return "Bronze I"

def ts_fmt(ts):
    try:
        dt = datetime.utcfromtimestamp(int(ts)) + timedelta(hours=7)  # UTC+7 VN
        return dt.strftime("%d/%m/%Y %H:%M:%S") + " (ICT)"
    except:
        return "N/A"

def item_name(item_id):
    if not item_id or str(item_id) in ("0",""):
        return "N/A"
    try:
        import requests as req
        r = req.get(f"https://api.danger.workers.dev/item/{item_id}", timeout=3)
        if r.status_code == 200:
            return r.json().get("name", str(item_id))
    except:
        pass
    return str(item_id)

# =============================================
#  ROUTES
# =============================================

@app.route("/")
def home():
    return jsonify({
        "status":   "running",
        "version":  "OB55",
        "endpoints": {
            "/info":   "?uid=UID&server=SERVER (optional)",
            "/get":    "?uid=UID  (alias của /info)",
            "/status": "token cache status",
        },
        "servers":  list(REGION_CONFIG.keys()),
        "priority": " → ".join(REGION_PRIORITY),
        "note":     "Vietnam: /info?uid=UID&server=VN"
    })

@app.route("/get")
def get_alias():
    return get_info()

@app.route("/info")
def get_info():
    uid_str = request.args.get("uid", "").strip()
    server  = request.args.get("server", "").strip().upper()  # optional

    if not uid_str:
        return jsonify({"error": "uid required",
                        "example": "/info?uid=123456789",
                        "example_vn": "/info?uid=123456789&server=VN"}), 400
    try:
        uid_int = int(uid_str)
    except:
        return jsonify({"error": "Invalid UID"}), 400

    # Nếu biết server → thử thẳng, không biết → thử hết theo priority
    priority = [server] if server in REGION_CONFIG else REGION_PRIORITY

    async def try_regions():
        tasks = [asyncio.create_task(get_account_info(uid_int, r)) for r in priority]
        try:
            for coro in asyncio.as_completed(tasks, timeout=20):
                try:
                    data = await coro
                    if data:
                        for t in tasks:
                            if not t.done(): t.cancel()
                        return data
                except: continue
        except asyncio.TimeoutError: pass
        for t in tasks:
            if not t.done(): t.cancel()
        return None

    try:
        data = asyncio.run(try_regions())
    except Exception as e:
        print(f"Global error: {e}")
        data = None

    if not data:
        return jsonify({"error": "Player not found or all servers failed"}), 404

    basic  = data.get("basicInfo",      {})
    clan   = data.get("clanBasicInfo",  {})
    social = data.get("socialInfo",     {})
    pet    = data.get("petInfo",        {})
    cap    = data.get("captainBasicInfo",{})
    credit = data.get("creditScoreInfo",{})

    prime = "N/A"
    try:
        pd = basic.get("primeLevel")
        prime = pd.get("level","N/A") if isinstance(pd, dict) else (str(pd) if pd else "N/A")
    except: pass

    return jsonify({
        "status":      "success",
        "server_used": data.get("region","?"),
        "BanStatus":   data.get("ban_status","❓ UNKNOWN"),
        "BasicInformation": {
            "Name":            basic.get("nickname","N/A"),
            "UID":             uid_str,
            "Level":           basic.get("level","N/A"),
            "Exp":             basic.get("exp","N/A"),
            "Region":          basic.get("region","N/A"),
            "Likes":           basic.get("liked","N/A"),
            "PrimeLevel":      prime,
            "HonorScore":      credit.get("creditScore","N/A"),
            "Title":           item_name(basic.get("title","0")),
            "Signature":       social.get("signature","N/A"),
        },
        "ActivityInformation": {
            "MostRecentOB":    basic.get("releaseVersion","N/A"),
            "BooyahPass":      "Yes" if basic.get("hasElitePass") else "No",
            "BpBadges":        basic.get("badgeCnt","N/A"),
            "BRRank":          get_rank(basic.get("rankingPoints",0)),
            "BRPoints":        basic.get("rankingPoints",0),
            "CreatedAt":       ts_fmt(basic.get("createAt",0)),
            "LastLogin":       ts_fmt(basic.get("lastLoginAt",0)),
        },
        "GuildInformation": {
            "GuildName":   clan.get("clanName","No Guild"),
            "GuildID":     clan.get("clanId","N/A"),
            "GuildLevel":  clan.get("clanLevel","N/A"),
            "Members":     f"{clan.get('memberNum','?')}/{clan.get('capacity','?')}",
        },
        "PetDetails": {
            "PetName":  pet.get("name","N/A"),
            "PetType":  item_name(pet.get("id","0")),
            "PetLevel": pet.get("level","N/A"),
            "PetExp":   pet.get("exp","N/A"),
        },
        "LeaderInformation": {
            "Name":     cap.get("nickname","N/A"),
            "UID":      cap.get("accountId","N/A"),
            "Level":    cap.get("level","N/A"),
            "Region":   cap.get("region","N/A"),
            "BRRank":   get_rank(cap.get("rankingPoints",0)),
        },
    })

@app.route("/status")
def token_status():
    out = {}
    for r, info in _token_cache.items():
        left = info["expires_at"] - time.time()
        out[r] = {"has_token": True, "expires_in_hours": round(left/3600, 2)}
    return jsonify({"total": len(_token_cache), "tokens": out})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5004, debug=False)