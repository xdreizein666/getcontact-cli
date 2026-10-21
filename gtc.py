#!/usr/bin/env python3

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import hmac
import json
import os
import random
import re
import secrets
import subprocess
import sys
import tempfile
import time
import urllib.parse
from pathlib import Path

import requests
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

#  config
GTC_BASE = "https://pbssrv-centralevents.com"
VFK_BASE = "https://api.verifykit.com"
HMAC_KEY = "31426764382a642f3a6665497235466f3d236d5d785b722b4c657457442a495b494524324866782a2364292478587a78662d7a7b7578593f71703e2b7e365762"
VFK_HMAC_KEY = "3452235d713252604a35562d325f765238695738485863672a705e6841544d3c7e6e45463028266f372b544e596f3829236b392825262e534a7e774f37653932"
VFK_CLIENT_KEY = "bhvbd7ced119dc6ad6a0b35bd3cf836555d6f71930d9e5a405f32105c790d"
VFK_FINAL_KEY = "bd48d8c25293cfb537619cc93ae3d6e372eb2ddfffff4ab0eb000777144c7bfa"

APP_VERSION = "8.4.0"
ANDROID_OS = "android 9"
LANG = "en_US"
COUNTRY = "id"
DEVICE_NAME = "SM-G977N"
TIME_ZONE = "Asia/Bangkok"
BUNDLE_ID = "app.source.getcontact"
CARRIER = ("510", "Indosat Ooredoo", "01")

# Diffie-Hellman params
DH_P = 900719898367
DH_G = 7

CONFIG_DIR = Path(os.environ.get("GTC_CONFIG_DIR", Path.home() / ".config" / "gtc"))
CRED_FILE = CONFIG_DIR / "credentials.json"
HISTORY_FILE = Path(__file__).resolve().parent / "history.json"
RESULTS_DIR = Path(os.environ.get("GTC_RESULTS_DIR", Path(__file__).resolve().parent / "results"))


class GtcError(Exception):
    pass


#  crypto
def _sig(ts: str, message: str, key_hex: str) -> str:
    mac = hmac.new(bytes.fromhex(key_hex), f"{ts}-{message}".encode(), hashlib.sha256)
    return base64.b64encode(mac.digest()).decode()


def _pad(b: bytes) -> bytes:
    n = 16 - len(b) % 16
    return b + bytes([n]) * n


def encrypt(data: str, key_hex: str) -> str:
    enc = Cipher(algorithms.AES(bytes.fromhex(key_hex)), modes.ECB()).encryptor()
    return base64.b64encode(enc.update(_pad(data.encode())) + enc.finalize()).decode()


def decrypt(data: str, key_hex: str) -> str:
    dec = Cipher(algorithms.AES(bytes.fromhex(key_hex)), modes.ECB()).decryptor()
    out = dec.update(base64.b64decode(data)) + dec.finalize()
    return out[: -out[-1]].decode()


def dh_keypair() -> tuple[int, int]:
    priv = secrets.randbelow(10**8 - 10**6) + 10**6
    return priv, pow(DH_G, priv, DH_P)


def dh_final_key(priv: int, server_pub: int) -> str:
    return hashlib.sha256(str(pow(int(server_pub), priv, DH_P)).encode()).hexdigest()


def _ts() -> str:
    return str(int(time.time() * 1000))


def new_device_id() -> str:
    return secrets.token_hex(8)


#  http
def _post(url: str, body: str, headers: dict, timeout: int = 25) -> requests.Response:
    return requests.post(url, data=body, headers=headers, timeout=timeout)


def gtc_call(endpoint: str, payload: dict, *, token: str, final_key: str,
             device_id: str, encrypted: bool = True) -> tuple[int, dict]:
    """POST to a GetContact endpoint. Returns (http_code, decrypted_json)."""
    raw = json.dumps(payload, ensure_ascii=False)
    ts = _ts()
    headers = {
        "Content-Type": "application/json",
        "x-os": ANDROID_OS,
        "x-app-version": APP_VERSION,
        "x-client-device-id": device_id,
        "x-lang": LANG,
        "x-req-timestamp": ts,
        "x-country-code": COUNTRY,
        "x-encrypted": "1" if encrypted else "0",
        "x-req-signature": _sig(ts, raw, HMAC_KEY),
    }
    if token:
        headers["x-token"] = token
    body = json.dumps({"data": encrypt(raw, final_key)}) if encrypted else raw
    r = _post(GTC_BASE + endpoint, body, headers)
    try:
        parsed = r.json()
    except ValueError:
        raise GtcError(f"{endpoint}: non-JSON response (HTTP {r.status_code})")
    if encrypted and "data" in parsed:
        parsed = json.loads(decrypt(parsed["data"], final_key))
    return r.status_code, parsed


def vfk_call(endpoint: str, payload: dict, device_id: str) -> tuple[int, dict]:
    """VerifyKit call — fixed version (compact JSON + App-Version 8.16.0)."""
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    ts = _ts()
    headers = {
        "Content-Type": "application/json",
        "X-VFK-Client-Device-Id": device_id,
        "X-VFK-Client-Key": VFK_CLIENT_KEY,
        "X-VFK-Sdk-Version": "0.11.4",
        "X-VFK-Os": "android 9.0",
        "X-VFK-App-Version": "8.16.0",         
        "X-VFK-Encrypted": "1",
        "X-VFK-Lang": "in_ID",
        "X-VFK-Req-Timestamp": ts,
        "X-VFK-Req-Signature": _sig(ts, raw, VFK_HMAC_KEY),
    }
    body = json.dumps({"data": encrypt(raw, VFK_FINAL_KEY)}, separators=(",", ":"))
    r = _post(VFK_BASE + endpoint, body, headers)
    try:
        parsed = r.json()
    except ValueError:
        raise GtcError(f"{endpoint}: non-JSON response (HTTP {r.status_code})")
    if "data" in parsed:
        parsed = json.loads(decrypt(parsed["data"], VFK_FINAL_KEY))
    return r.status_code, parsed


def dig(obj, path, default=None):
    for k in path.split("."):
        if not isinstance(obj, dict) or k not in obj:
            return default
        obj = obj[k]
    return obj


#  store
def load_store() -> dict:
    if not CRED_FILE.exists():
        return {"active": None, "credentials": {}}
    return json.loads(CRED_FILE.read_text("utf-8"))


def save_store(store: dict) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CRED_FILE.write_text(json.dumps(store, indent=2), "utf-8")
    try:
        os.chmod(CRED_FILE, 0o600)
    except OSError:
        pass


def get_cred(store: dict, name: str | None) -> tuple[str, dict]:
    name = name or store.get("active")
    creds = store.get("credentials", {})
    if not name or name not in creds:
        raise GtcError("No active credential. Run: gtc cred list / gtc cred use <name>")
    return name, creds[name]


def normalize_phone(raw: str) -> str:
    p = re.sub(r"[^\d+]", "", raw.strip())
    if p.startswith("+"):
        return p
    if p.startswith("0"):
        return "+62" + p[1:]
    if p.startswith("62"):
        return "+" + p
    raise GtcError(f"Invalid phone number: {raw}")


#  features
def history_entry(v: dict) -> tuple[str, dict]:
    # entri lama (sebelum ada waktu) = body mentah
    return (v["time"], v["body"]) if "time" in v and "body" in v else ("-", v)


def api_search(cred: dict, phone: str, source: str, refresh: bool = False) -> dict:
    # ponytail: whole-file JSON cache, switch to sqlite if history gets large
    key = f"{source}:{phone}"
    try:
        history = json.loads(HISTORY_FILE.read_text("utf-8"))
    except (OSError, ValueError):
        history = {}
    if not refresh and key in history:
        print(f"(dari history, pakai --refresh untuk cari ulang)", file=sys.stderr)
        return history_entry(history[key])[1]
    endpoint = "/v2.8/number-detail" if source == "tags" else "/v2.8/search"
    payload = {
        "countryCode": COUNTRY,
        "phoneNumber": phone,
        "source": "profile" if source == "tags" else "search",
        "token": cred["token"],
    }
    code, body = gtc_call(endpoint, payload, token=cred["token"],
                          final_key=cred["finalKey"], device_id=cred["clientDeviceId"])
    meta = dig(body, "meta.httpStatusCode")
    if code != 200 or meta != 200:
        raise GtcError(f"HTTP {code}/{meta}: {dig(body, 'meta.errorMessage', 'unknown error')}")
    history[key] = {"time": time.strftime("%Y-%m-%d %H:%M:%S"), "body": body}
    HISTORY_FILE.write_text(json.dumps(history, ensure_ascii=False), "utf-8")
    os.chmod(HISTORY_FILE, 0o600)
    return body


def api_subscription(cred: dict) -> dict:
    code, body = gtc_call("/v2.8/subscription", {"token": cred["token"]},
                          token=cred["token"], final_key=cred["finalKey"],
                          device_id=cred["clientDeviceId"])
    if code != 200:
        raise GtcError(f"HTTP {code}: {dig(body, 'meta.errorMessage', 'unknown error')}")
    return body


def show_captcha(b64_image: str) -> Path:
    path = Path(tempfile.gettempdir()) / f"gtc_captcha_{int(time.time())}.jpg"
    path.write_bytes(base64.b64decode(b64_image))
    try:
        if sys.platform == "win32":
            os.startfile(path)  # noqa: S606
        elif sys.platform == "darwin":
            subprocess.Popen(["open", str(path)])
        else:
            subprocess.Popen(["xdg-open", str(path)])
    except Exception:
        pass
    return path


#  commands
def cmd_search(args) -> int:
    store = load_store()
    name, cred = get_cred(store, args.account)
    phone = normalize_phone(args.phone)
    body = api_search(cred, phone, args.type, args.refresh)
    if args.json:
        print(json.dumps(body, indent=2, ensure_ascii=False))
        return 0
    print(f"[{name}] {phone}")
    profile = dig(body, "result.profile")
    if profile:
        for k in ("displayName", "name", "surname", "phoneNumber", "displayNumber", "tagCount", "email"):
            print(f"  {k:<14}: {profile.get(k) or '-'}")
    tags = dig(body, "result.tags")
    if tags:
        print(f"  tags ({len(tags)}):")
        for t in tags:
            print(f"    - {t.get('tag')}  x{t.get('count', '')}")
    if not profile and not tags:
        print("  Tidak ada data (belum ada yang menyimpan nomor ini). Detail lengkap: --json")
    return 0


def cmd_batch(args) -> int:
    store = load_store()
    name, cred = get_cred(store, args.account)
    with open(args.csv, newline="", encoding="utf-8-sig") as fh:
        rows = list(csv.reader(fh))
    if not rows:
        raise GtcError("Empty CSV")
    header = rows[0]
    col = 0
    if any(h.strip().lower() in ("phone", "phone_number", "phonenumber", "nomor") for h in header):
        col = next(i for i, h in enumerate(header)
                   if h.strip().lower() in ("phone", "phone_number", "phonenumber", "nomor"))
        rows = rows[1:]
    out = csv.writer(sys.stdout if args.out == "-" else open(args.out, "w", newline="", encoding="utf-8"))
    out.writerow(["phone", "status", "displayName", "tagCount", "tags", "error"])
    for row in rows:
        if not row or not row[col].strip():
            continue
        raw = row[col].strip()
        try:
            phone = normalize_phone(raw)
            body = api_search(cred, phone, args.type, args.refresh)
            prof = dig(body, "result.profile") or {}
            tags = [t.get("tag", "") for t in (dig(body, "result.tags") or [])]
            out.writerow([phone, "ok", prof.get("displayName", ""),
                          prof.get("tagCount", len(tags)), "|".join(tags), ""])
            print(f"ok   {phone}", file=sys.stderr)
        except Exception as e:
            out.writerow([raw, "error", "", "", "", str(e)])
            print(f"FAIL {raw}: {e}", file=sys.stderr)
        time.sleep(args.delay)
    return 0


def cmd_history(args) -> int:
    try:
        history = json.loads(HISTORY_FILE.read_text("utf-8"))
    except (OSError, ValueError):
        history = {}
    if not history:
        print("History kosong.")
        return 0
    for key, v in history.items():
        kind, phone = key.split(":", 1)
        when, body = history_entry(v)
        prof = dig(body, "result.profile") or {}
        n = len(dig(body, "result.tags") or []) or prof.get("tagCount", "-")
        print(f"{when:<19} {kind:<8} {phone:<16} {prof.get('displayName') or '-':<28} tags: {n}")
    print(f"\n{len(history)} entri. Detail: gtc search <nomor> [-t tags]")
    return 0


def cmd_quota(args) -> int:
    store = load_store()
    name, cred = get_cred(store, args.account)
    body = api_subscription(cred)
    if args.json:
        print(json.dumps(body, indent=2, ensure_ascii=False))
        return 0
    u = dig(body, "result.subscriptionInfo.usage") or {}
    print(f"[{name}]")
    for key in ("search", "numberDetail"):
        d = u.get(key) or {}
        print(f"  {key:<13}: {d.get('remainingCount', '?')}/{d.get('limit', '?')} remaining")
    print(f"  renewDate    : {dig(body, 'result.subscriptionInfo.renewDate', '-')}")
    return 0


def cmd_captcha(args) -> int:
    store = load_store()
    name, cred = get_cred(store, args.account)
    common = dict(token=cred["token"], final_key=cred["finalKey"], device_id=cred["clientDeviceId"])
    code, body = gtc_call("/v2.8/refresh-code", {"token": cred["token"]}, **common)
    image = dig(body, "result.image")
    if not image:
        raise GtcError(f"No captcha returned (HTTP {code}). Account may not be blocked.")
    while True:
        path = show_captcha(image)
        print(f"Captcha image: {path}")
        answer = input("Enter captcha code (blank = refresh, 'q' = quit): ").strip()
        if answer.lower() == "q":
            return 1
        if not answer:
            _, body = gtc_call("/v2.8/refresh-code", {"token": cred["token"]}, **common)
            image = dig(body, "result.image") or image
            continue
        code, body = gtc_call("/v2.8/verify-code",
                              {"validationCode": answer, "token": cred["token"]}, **common)
        if code == 200 and dig(body, "meta.httpStatusCode") == 200:
            print("Captcha verified.")
            return 0
        print("Wrong code, new captcha issued.")
        image = dig(body, "result.image") or image


def cmd_generate(args) -> int:
    raw_phone = args.phone.strip()
    phone = normalize_phone(raw_phone)
    device_id = new_device_id()
    priv, pub = dh_keypair()

    # 1. register -> token + server public key
    ts = _ts()
    reg_body = {
        "carrierCountryCode": CARRIER[0], "carrierName": CARRIER[1],
        "carrierNetworkCode": CARRIER[2], "countryCode": COUNTRY, "deepLink": None,
        "deviceName": DEVICE_NAME, "deviceType": "Android", "email": None,
        "notificationToken": "", "oldToken": None, "peerKey": pub,
        "timeZone": TIME_ZONE, "token": "",
    }
    raw = json.dumps(reg_body, ensure_ascii=False)
    r = _post(GTC_BASE + "/v2.8/register", raw, {
        "Content-Type": "application/json", "x-os": ANDROID_OS,
        "x-app-version": APP_VERSION, "x-client-device-id": device_id, "x-lang": LANG,
        "x-req-timestamp": ts, "x-country-code": COUNTRY, "x-encrypted": "0",
        "x-req-signature": _sig(ts, raw, HMAC_KEY),
    })
    if r.status_code != 201:
        raise GtcError(f"register failed: HTTP {r.status_code} {r.text[:200]}")
    reg = r.json()
    token = dig(reg, "result.token")
    server_key = dig(reg, "result.serverKey")
    if not token or not server_key:
        raise GtcError(f"register: missing token/serverKey: {reg}")
    final_key = dh_final_key(priv, server_key)
    print(f"clientDeviceId : {device_id}")
    print(f"finalKey       : {final_key}")
    print(f"token          : {token}")

    common = dict(token=token, final_key=final_key, device_id=device_id)
    base = {
        "carrierCountryCode": CARRIER[0], "carrierName": CARRIER[1],
        "carrierNetworkCode": CARRIER[2], "countryCode": COUNTRY,
        "deviceName": DEVICE_NAME, "notificationToken": "", "timeZone": TIME_ZONE,
        "token": token,
    }
    steps = [
        ("/v2.8/init-basic", base, 201),
        ("/v2.8/ad-settings", {"source": "init", "token": token}, 200),
        ("/v2.8/init-intro", {**base, "hasRouting": False}, 201),
        ("/v2.8/email-code-validate/start",
         {"email": f"user{random.randint(10**7, 10**8 - 1)}@gmail.com",
          "fullName": f"User{random.randint(1000, 999999)}", "token": token}, 200),
        ("/v2.8/country", {"countryCode": COUNTRY.upper(), "token": token}, 200),
        ("/v2.8/validation-start",
         {"app": "verifykit", "countryCode": COUNTRY, "notificationToken": "", "token": token}, 200),
    ]
    for endpoint, payload, want in steps:
        code, body = gtc_call(endpoint, payload, **common)
        if code != want:
            raise GtcError(f"{endpoint} failed: HTTP {code}")
        print(f"  ok {endpoint}")

    # ---------- VerifyKit (fixed) ----------
    # 1. INIT
    code, body = vfk_call("/v2.0/init", {
        "isCallPermissionGranted": True,
        "countryCode": "ID",
        "deviceName": DEVICE_NAME,
        "installedApps": '{"whatsapp":0,"telegram":0,"viber":0}',
        "outsideCountryCode": "ID",
        "outsidePhoneNumber": raw_phone,  
        "timezone": TIME_ZONE,
        "bundleId": BUNDLE_ID,
    }, device_id)
    if code != 200:
        raise GtcError(f"vfk init failed: HTTP {code} — {dig(body, 'message') or dig(body, 'error') or body}")

    # 2. COUNTRY
    code, body = vfk_call("/v2.0/country", {
        "countryCode": "ID",
        "bundleId": BUNDLE_ID,
    }, device_id)
    if code != 200:
        raise GtcError(f"vfk country failed: HTTP {code}")

    # 3. START → WhatsApp deeplink
    code, body = vfk_call("/v2.0/start", {
        "countryCode": "ID",
        "mcc": CARRIER[0],
        "mnc": CARRIER[2],
        "phoneNumber": phone,  # E.164
        "app": "whatsapp",
        "bundleId": BUNDLE_ID,
    }, device_id)
    deeplink = dig(body, "result.deeplink")
    reference = dig(body, "result.reference")
    if not deeplink or not reference:
        raise GtcError(f"vfk start failed (HTTP {code}): {body}")

    codes = re.findall(r"\*(.*?)\*", urllib.parse.unquote(deeplink))
    verification = next((c for c in codes if re.fullmatch(r"[A-Za-z0-9]+(?:-[A-Za-z0-9]+)+", c)), None)

    gtc_call("/v2.8/validation-start",
             {"app": "verifykit", "countryCode": COUNTRY, "notificationToken": "", "token": token},
             **common)

    print("\nSend the WhatsApp verification message, then come back:")
    print(f"  link : {deeplink}")
    print(f"  code : {verification}")
    input("\nPress Enter after WhatsApp shows two checkmarks... ")

    # 4. CHECK → sessionId → gtc verifykit-result
    code, body = vfk_call("/v2.0/check", {
        "reference": reference,
        "bundleId": BUNDLE_ID,
    }, device_id)
    session_id = dig(body, "result.sessionId")
    if not session_id:
        raise GtcError(f"Verification not completed yet (HTTP {code}): {body}")

    code, body = gtc_call("/v2.8/verifykit-result",
                          {"sessionId": session_id, "token": token}, **common)
    validation_date = dig(body, "result.validationDate")
    if not validation_date:
        raise GtcError(f"verifykit-result failed (HTTP {code}): {body}")

    store = load_store()
    name = args.name or phone
    store.setdefault("credentials", {})[name] = {
        "description": args.description or f"Generated {validation_date}",
        "phoneNumber": phone,
        "clientDeviceId": device_id,
        "finalKey": final_key,
        "token": token,
        "validationDate": validation_date,
    }
    store["active"] = store.get("active") or name
    save_store(store)
    print(f"\nVerified {validation_date}. Saved as '{name}' in {CRED_FILE}")
    return 0


def cmd_cred(args) -> int:
    store = load_store()
    creds = store.setdefault("credentials", {})
    if args.cred_cmd == "list":
        if not creds:
            print(f"No credentials. Add one: gtc cred add <name> --final-key ... --token ...")
            return 0
        for name, c in creds.items():
            mark = "*" if name == store.get("active") else " "
            print(f"{mark} {name:<20} {c.get('phoneNumber', '-'):<16} {c.get('description', '')}")
        return 0
    if args.cred_cmd == "add":
        creds[args.name] = {
            "description": args.description or "",
            "phoneNumber": args.phone or "",
            "clientDeviceId": args.device_id or new_device_id(),
            "finalKey": args.final_key,
            "token": args.token,
        }
        store["active"] = store.get("active") or args.name
        save_store(store)
        print(f"Saved '{args.name}' to {CRED_FILE}")
        return 0
    if args.cred_cmd == "use":
        if args.name not in creds:
            raise GtcError(f"Unknown credential: {args.name}")
        store["active"] = args.name
        save_store(store)
        print(f"Active credential: {args.name}")
        return 0
    if args.cred_cmd == "remove":
        if creds.pop(args.name, None) is None:
            raise GtcError(f"Unknown credential: {args.name}")
        if store.get("active") == args.name:
            store["active"] = next(iter(creds), None)
        save_store(store)
        print(f"Removed '{args.name}'")
        return 0
    raise GtcError("unknown cred subcommand")


#  cli
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="gtc", description="GetContact CLI")
    p.add_argument("-a", "--account", help="credential name (default: active)")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("search", help="look up a phone number")
    s.add_argument("phone")
    s.add_argument("-t", "--type", choices=["profile", "tags"], default="profile")
    s.add_argument("--json", action="store_true")
    s.add_argument("--refresh", action="store_true", help="skip history, query again")
    s.set_defaults(func=cmd_search)

    b = sub.add_parser("batch", help="look up every number in a CSV")
    b.add_argument("csv")
    b.add_argument("-t", "--type", choices=["profile", "tags"], default="tags")
    b.add_argument("-o", "--out", default="-", help="output CSV path (default stdout)")
    b.add_argument("--delay", type=float, default=1.5, help="seconds between requests")
    b.add_argument("--refresh", action="store_true", help="skip history, query again")
    b.set_defaults(func=cmd_batch)

    h = sub.add_parser("history", help="list previous lookups")
    h.set_defaults(func=cmd_history)

    q = sub.add_parser("quota", help="show subscription usage")
    q.add_argument("--json", action="store_true")
    q.set_defaults(func=cmd_quota)

    c = sub.add_parser("captcha", help="solve the captcha interactively (403 unblock)")
    c.set_defaults(func=cmd_captcha)

    g = sub.add_parser("generate", help="generate a new credential via DH + WhatsApp")
    g.add_argument("phone")
    g.add_argument("--name", help="store under this name (default: phone)")
    g.add_argument("--description")
    g.set_defaults(func=cmd_generate)

    cr = sub.add_parser("cred", help="manage stored credentials")
    crs = cr.add_subparsers(dest="cred_cmd", required=True)
    crs.add_parser("list").set_defaults(func=cmd_cred)
    a = crs.add_parser("add")
    a.add_argument("name")
    a.add_argument("--final-key", required=True)
    a.add_argument("--token", required=True)
    a.add_argument("--device-id")
    a.add_argument("--phone")
    a.add_argument("--description")
    a.set_defaults(func=cmd_cred)
    u = crs.add_parser("use")
    u.add_argument("name")
    u.set_defaults(func=cmd_cred)
    rm = crs.add_parser("remove")
    rm.add_argument("name")
    rm.set_defaults(func=cmd_cred)
    return p


BANNER = r"""
 ██████╗ ███████╗████████╗ ██████╗ ██████╗ ███╗   ██╗████████╗ █████╗  ██████╗████████╗
██╔════╝ ██╔════╝╚══██╔══╝██╔════╝██╔═══██╗████╗  ██║╚══██╔══╝██╔══██╗██╔════╝╚══██╔══╝
██║  ███╗█████╗     ██║   ██║     ██║   ██║██╔██╗ ██║   ██║   ███████║██║        ██║   
██║   ██║██╔══╝     ██║   ██║     ██║   ██║██║╚██╗██║   ██║   ██╔══██║██║        ██║   
╚██████╔╝███████╗   ██║   ╚██████╗╚██████╔╝██║ ╚████║   ██║   ██║  ██║╚██████╗   ██║   
 ╚═════╝ ╚══════╝   ╚═╝    ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝   ╚═╝                                                                            
By mfajarb 
"""


def print_startup(args) -> None:
    tty = sys.stderr.isatty()
    c, d, r = ("\033[36m", "\033[2m", "\033[0m") if tty else ("", "", "")
    print(f"{c}{BANNER}{r}", file=sys.stderr)
    store = load_store() if CRED_FILE.exists() else {}
    active = store.get("active") or "-"
    n = len(store.get("credentials", {}))
    print(f"{d}  version   {APP_VERSION} | app {BUNDLE_ID}{r}", file=sys.stderr)
    print(f"{d}  config    {CONFIG_DIR}{r}", file=sys.stderr)
    print(f"{d}  account   {getattr(args, 'account', None) or active} ({n} stored){r}", file=sys.stderr)
    print(f"{d}  command   {args.cmd}{r}\n", file=sys.stderr)


class _Tee:
    def __init__(self, stream, fh):
        self._s, self._f = stream, fh

    def write(self, s):
        self._s.write(s)
        self._f.write(s)
        return len(s)

    def flush(self):
        self._s.flush()
        self._f.flush()

    def __getattr__(self, name):
        return getattr(self._s, name)


def open_result_file(args) -> Path:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    parts = [time.strftime("%Y%m%d-%H%M%S"), args.cmd]
    for extra in (getattr(args, "phone", None), getattr(args, "action", None)):
        if extra:
            parts.append(re.sub(r"[^0-9A-Za-z_.-]", "_", str(extra)))
    ext = "json" if getattr(args, "json", False) else "txt"
    return RESULTS_DIR / f"{'-'.join(parts)}.{ext}"


MENU = [
    ("Cari profil nomor        (nama pemilik)", "profile"),
    ("Cari tag nomor           (nama tersimpan orang lain)", "tags"),
    ("Sisa kuota akun", "quota"),
    ("Cari banyak nomor dari file CSV", "batch"),
    ("Buka blokir / captcha", "captcha"),
    ("Lihat history pencarian", "history"),
    ("Lihat akun tersimpan", "credlist"),
    ("Tambah akun baru (butuh WhatsApp)", "generate"),
]


def ask(prompt: str) -> str:
    try:
        return input(prompt).strip()
    except EOFError:
        return "0"


def interactive() -> int:
    print(BANNER)
    while True:
        print("Pilih fitur:")
        for i, (label, _) in enumerate(MENU, 1):
            print(f"  {i}. {label}")
        print("  0. Keluar\n")
        choice = ask("Nomor pilihan: ")
        if choice in ("0", "q", "keluar", ""):
            return 0
        try:
            idx = int(choice) - 1
            if not (0 <= idx < len(MENU)):
                print("Pilihan tidak valid.\n")
                continue
        except ValueError:
            print("Masukkan angka.\n")
            continue

        action = MENU[idx][1]
        try:
            if action == "profile":
                phone = ask("Nomor telepon: ")
                sys.argv = ["gtc", "search", phone, "-t", "profile"]
            elif action == "tags":
                phone = ask("Nomor telepon: ")
                sys.argv = ["gtc", "search", phone, "-t", "tags"]
            elif action == "quota":
                sys.argv = ["gtc", "quota"]
            elif action == "batch":
                csv_path = ask("Path file CSV: ")
                sys.argv = ["gtc", "batch", csv_path]
            elif action == "captcha":
                sys.argv = ["gtc", "captcha"]
            elif action == "history":
                sys.argv = ["gtc", "history"]
            elif action == "credlist":
                sys.argv = ["gtc", "cred", "list"]
            elif action == "generate":
                phone = ask("Nomor WhatsApp (untuk verifikasi): ")
                sys.argv = ["gtc", "generate", phone]
            else:
                continue

            args = build_parser().parse_args()
            print_startup(args)
            return args.func(args)
        except GtcError as e:
            print(f"Error: {e}\n")
        except Exception as e:
            print(f"Unexpected error: {e}\n")


def main() -> int:
    if len(sys.argv) == 1:
        return interactive()
    parser = build_parser()
    args = parser.parse_args()
    print_startup(args)
    try:
        return args.func(args)
    except GtcError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
