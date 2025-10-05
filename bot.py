import os
import time
import json
import base64
import hashlib
from pathlib import Path
from datetime import datetime, timedelta
import requests
from ecdsa import SigningKey, SECP256k1
from ecdsa.util import sigencode_string
from dotenv import load_dotenv

load_dotenv()

FAUCET_INFO_URL = os.getenv("FAUCET_INFO_URL", "https://hub.gopher-ai.com/api/faucet-info")
FAUCET_CLAIM_URL = os.getenv("FAUCET_CLAIM_URL", "https://hub.gopher-ai.com/api/faucet")
PRIVATE_KEY = os.getenv("PRIVATE_KEY", "").strip()
WALLET_ADDRESS = os.getenv("WALLET_ADDRESS", "").strip()
STATE_FILE = Path(os.getenv("STATE_FILE", "gopher_faucet_state.json"))
CLAIM_TIMEOUT = int(os.getenv("CLAIM_TIMEOUT", "20"))
CLAIM_INTERVAL_HOURS = float(os.getenv("CLAIM_INTERVAL_HOURS", "23.5"))

if not PRIVATE_KEY:
    raise SystemExit("Error: set PRIVATE_KEY environment variable (hex).")

pk_hex = PRIVATE_KEY.lower()
if pk_hex.startswith("0x"):
    pk_hex = pk_hex[2:]
try:
    priv_bytes = bytes.fromhex(pk_hex)
except Exception as e:
    raise SystemExit("Error: PRIVATE_KEY tidak valid hex: " + str(e))


def compressed_pubkey_from_priv(priv: bytes) -> bytes:
    sk = SigningKey.from_string(priv, curve=SECP256k1)
    vk = sk.get_verifying_key()
    pub_raw = vk.to_string()
    x = pub_raw[:32]
    y = pub_raw[32:]
    y_int = int.from_bytes(y, "big")
    prefix = b"\x02" if (y_int % 2 == 0) else b"\x03"
    return prefix + x


def sign_message_adr36(message_bytes: bytes, priv: bytes):
    digest = hashlib.sha256(message_bytes).digest()
    sk = SigningKey.from_string(priv, curve=SECP256k1)
    sig_rs = sk.sign_digest_deterministic(digest, sigencode=sigencode_string)
    if len(sig_rs) != 64:
        raise RuntimeError("Unexpected signature length: {}".format(len(sig_rs)))
    sig_b64 = base64.b64encode(sig_rs).decode()
    pub_comp = compressed_pubkey_from_priv(priv)
    pub_b64 = base64.b64encode(pub_comp).decode()
    return pub_b64, sig_b64


def load_state():
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except Exception:
            return {}
    return {}


def save_state(s):
    STATE_FILE.write_text(json.dumps(s))


def already_claimed(hours=CLAIM_INTERVAL_HOURS):
    s = load_state()
    ts = s.get("last_claim_ts")
    if not ts:
        return False
    last = datetime.fromtimestamp(ts)
    return datetime.utcnow() - last < timedelta(hours=hours)


def record_claim(resp):
    s = load_state()
    s["last_claim_ts"] = int(datetime.utcnow().timestamp())
    s["last_claim_resp"] = resp
    save_state(s)


def try_candidates_for_claim_url(info_json):
    if isinstance(info_json, dict):
        for k in ("claim_url", "claimEndpoint", "claim_endpoint", "claim", "faucet_claim_url", "claimUrl", "endpoint"):
            if k in info_json and isinstance(info_json[k], str) and info_json[k].strip():
                return info_json[k].strip()
    if FAUCET_INFO_URL.endswith("/faucet-info"):
        base = FAUCET_INFO_URL.rsplit("/faucet-info", 1)[0]
        return base + "/api/claim"
    if "/api" in FAUCET_INFO_URL:
        host_base = FAUCET_INFO_URL.rsplit("/api", 1)[0]
        return host_base + "/api/faucet-claim"
    return FAUCET_INFO_URL.rsplit("/", 1)[0] + "/claim"


def main():
    print("Gopher faucet (Cosmos) auto-claim", datetime.utcnow().isoformat(), "UTC")
    if already_claimed():
        print("Sudah klaim dalam", CLAIM_INTERVAL_HOURS, "jam terakhir. Keluar.")
        return

    info = {}
    try:
        r = requests.get(FAUCET_INFO_URL, timeout=CLAIM_TIMEOUT)
        r.raise_for_status()
        try:
            info = r.json()
        except Exception:
            info = {}
    except Exception:
        info = {}

    timestamp = int(time.time())
    msg_template = None
    if isinstance(info, dict):
        msg_template = info.get("challenge") or info.get("message") or info.get("sign_message")
    if msg_template:
        if isinstance(msg_template, str) and "{timestamp}" in msg_template:
            message_text = msg_template.replace("{timestamp}", str(timestamp))
        else:
            message_text = f"{msg_template}:{timestamp}"
    else:
        message_text = f"gopher-faucet-claim:{WALLET_ADDRESS or 'unknown'}:{timestamp}"

    try:
        pub_b64, sig_b64 = sign_message_adr36(message_text.encode(), priv_bytes)
    except Exception as e:
        print("Gagal menandatangani message:", str(e))
        return

    claim_url = try_candidates_for_claim_url(info if isinstance(info, dict) else {})
    payload = {
        "address": WALLET_ADDRESS or "",
        "message": message_text,
        "signature": {
            "pub_key": {"type": "tendermint/PubKeySecp256k1", "value": pub_b64},
            "signature": sig_b64
        },
        "timestamp": timestamp
    }

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Origin": "https://hub.gopher-ai.com",
        "Referer": "https://hub.gopher-ai.com/gopher-faucet",
        "User-Agent": "Mozilla/5.0 (compatible; gopher-faucet-bot/1.0)"
    }

    try:
        resp = requests.post(claim_url or FAUCET_CLAIM_URL, json=payload, headers=headers, timeout=CLAIM_TIMEOUT)
    except Exception as e:
        print("Gagal POST klaim:", str(e))
        return

    print("HTTP", resp.status_code)
    try:
        body = resp.json()
        print("Response:", json.dumps(body, indent=2)[:4000])
    except Exception:
        body = resp.text
        print("Response text:", str(body)[:2000])

    success = False
    if resp.status_code in (200, 201):
        success = True
        if isinstance(body, dict):
            low = json.dumps(body).lower()
            if "error" in low or "failed" in low or "denied" in low:
                success = False

    if success:
        record_claim({"http_status": resp.status_code, "body": body if isinstance(body, (dict, str)) else str(body)})
        print("Klaim berhasil, state disimpan.")
    else:
        print("Klaim kemungkinan gagal. Periksa response di atas.")


if __name__ == "__main__":
    main()
