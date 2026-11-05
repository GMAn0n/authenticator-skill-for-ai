#!/usr/bin/env python3
"""Local authenticator for Muse — TOTP/HOTP 2FA codes (RFC 4226/6238).

Seeds are credentials. They live ONLY in ~/.authenticator/seeds.json
(dir 0700, file 0600, under the user's home so they survive deployments).
Codes are computed locally with the Python standard library; the only
optional dependency is QR decoding of enrollment screenshots
(Pillow + zxing-cpp, both installed under ~/.local).

Commands:
  add <label> (--seed BASE32 | --uri otpauth://... | --qr IMAGE)
  import (--qr IMAGE... | --uri URI | --file EXPORT_FILE)
      Universal import: otpauth + Google migration QRs/photos, and export
      files from andOTP, Aegis, 2FAS, Bitwarden, Ente/Raivo (otpauth text),
      FreeOTP+, Proton, KeePassXC CSV, Steam maFiles. Encrypted exports
      are detected and reported, never silently dropped.
  code <label> [--at UNIX_TS] [--json]
  list [--json]
  remove <label>
  status [--json]

No command ever prints a stored seed.
"""
import argparse
import base64
import csv
import hashlib
import hmac
import io
import json
import os
import sys
import time
from urllib.parse import urlparse, parse_qs, unquote

STORE_DIR = os.environ.get(
    "AUTHENTICATOR_HOME", os.path.join(os.path.expanduser("~"), ".authenticator")
)
STORE_FILE = os.path.join(STORE_DIR, "seeds.json")
ALGOS = {
    "SHA1": hashlib.sha1,
    "SHA256": hashlib.sha256,
    "SHA512": hashlib.sha512,
    "MD5": hashlib.md5,
}
STEAM_ALPHABET = "23456789BCDFGHJKMNPQRTVWXY"


# ---------- storage ----------
def load_store():
    if not os.path.exists(STORE_FILE):
        return {"version": 1, "accounts": {}}
    with open(STORE_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def save_store(store):
    os.makedirs(STORE_DIR, mode=0o700, exist_ok=True)
    try:
        os.chmod(STORE_DIR, 0o700)
    except OSError:
        pass
    tmp = STORE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(store, f, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, STORE_FILE)
    os.chmod(STORE_FILE, 0o600)


# ---------- otp core ----------
def normalize_secret(secret):
    s = "".join(secret.split()).replace("-", "").upper()
    pad = (-len(s)) % 8
    return s + ("=" * pad)


def decode_secret(secret):
    return base64.b32decode(normalize_secret(secret))


def hotp(secret_bytes, counter, digits=6, algorithm="SHA1"):
    msg = counter.to_bytes(8, "big")
    digest = hmac.new(secret_bytes, msg, ALGOS[algorithm.upper()]).digest()
    offset = digest[-1] & 0x0F
    binary = (
        (digest[offset] & 0x7F) << 24
        | (digest[offset + 1] & 0xFF) << 16
        | (digest[offset + 2] & 0xFF) << 8
        | (digest[offset + 3] & 0xFF)
    )
    return str(binary % (10**digits)).zfill(digits)


def totp(secret_bytes, at=None, digits=6, period=30, algorithm="SHA1"):
    t = int(time.time()) if at is None else int(at)
    counter = t // period
    return hotp(secret_bytes, counter, digits, algorithm), period - (t % period)


def steam_code(secret_bytes, at=None, period=30):
    """Steam Guard: 5 chars from the Steam alphabet (secret is raw bytes)."""
    t = int(time.time()) if at is None else int(at)
    counter = t // period
    digest = hmac.new(secret_bytes, counter.to_bytes(8, "big"), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = (
        (digest[offset] & 0x7F) << 24
        | (digest[offset + 1] & 0xFF) << 16
        | (digest[offset + 2] & 0xFF) << 8
        | (digest[offset + 3] & 0xFF)
    )
    out = ""
    for _ in range(5):
        out += STEAM_ALPHABET[binary % len(STEAM_ALPHABET)]
        binary //= len(STEAM_ALPHABET)
    return out, period - (t % period)


def secret_to_base32(raw_secret):
    """Accept a seed in base32, base64 or hex and return normalized base32."""
    s = "".join(str(raw_secret).split())
    # base32 first (the standard)
    try:
        decode_secret(s)
        return normalize_secret(s)
    except Exception:
        pass
    # base64
    try:
        raw = base64.b64decode(s, validate=True)
        if raw:
            return base64.b32encode(raw).decode("ascii")
    except Exception:
        pass
    # hex
    try:
        raw = bytes.fromhex(s)
        if raw:
            return base64.b32encode(raw).decode("ascii")
    except Exception:
        pass
    raise ValueError("seed is not valid base32, base64, or hex")


# ---------- intake ----------
def parse_otpauth(uri):
    # Steam Guard links arrive as steam://BASE64SECRET
    if uri.startswith("steam://"):
        raw = uri[len("steam://") :].strip()
        return {
            "type": "steam",
            "issuer": "Steam",
            "account": "",
            "secret": secret_to_base32(raw),
            "algorithm": "SHA1",
            "digits": 5,
            "period": 30,
            "counter": 0,
        }
    if not uri.startswith("otpauth://"):
        raise ValueError("not an otpauth:// URI")
    p = urlparse(uri)
    otype = p.netloc.lower()
    if otype not in ("totp", "hotp", "steam"):
        raise ValueError(f"unsupported otpauth type: {otype}")
    label_raw = unquote(p.path.lstrip("/"))
    q = {k: v[0] for k, v in parse_qs(p.query).items()}
    if "secret" not in q:
        raise ValueError("otpauth URI has no secret parameter")
    issuer = q.get("issuer", "")
    account = label_raw
    if ":" in label_raw:
        maybe_issuer, account = label_raw.split(":", 1)
        issuer = issuer or maybe_issuer
    entry = {
        "type": "steam" if otype == "steam" else otype,
        "issuer": issuer,
        "account": account,
        "secret": secret_to_base32(q["secret"]),
        "algorithm": q.get("algorithm", "SHA1").upper(),
        "digits": int(q.get("digits", 5 if otype == "steam" else 6)),
        "period": int(q.get("period", 30)),
        "counter": int(q.get("counter", 0)),
    }
    if entry["algorithm"] not in ALGOS:
        raise ValueError(f"unsupported algorithm: {entry['algorithm']}")
    decode_secret(entry["secret"])  # validate
    return entry


def decode_qr_image(path):
    try:
        from PIL import Image
        import zxingcpp
    except ImportError as e:
        raise RuntimeError(
            "QR decoding needs Pillow + zxing-cpp (pip install --user pillow zxing-cpp)"
        ) from e
    img = Image.open(path)
    results = zxingcpp.read_barcodes(img)
    for r in results:
        text = r.text or ""
        if (
            text.startswith("otpauth://")
            or text.startswith("otpauth-migration://")
            or text.startswith("steam://")
        ):
            return text
    if results:
        raise ValueError("QR code found but it is not an otpauth enrollment / migration code")
    raise ValueError("no QR code could be decoded from that image")


# ---------- Google Authenticator migration (otpauth-migration://) ----------
def _read_varint(buf, pos):
    result = 0
    shift = 0
    while True:
        if pos >= len(buf):
            raise ValueError("truncated varint in migration payload")
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7
        if shift > 70:
            raise ValueError("varint too long in migration payload")


def _parse_fields(buf):
    """Yield (field_no, wire_type, value) for a protobuf buffer. Stdlib only."""
    pos = 0
    while pos < len(buf):
        key, pos = _read_varint(buf, pos)
        field_no, wire = key >> 3, key & 7
        if wire == 0:
            val, pos = _read_varint(buf, pos)
            yield field_no, wire, val
        elif wire == 2:
            length, pos = _read_varint(buf, pos)
            val = buf[pos : pos + length]
            if len(val) != length:
                raise ValueError("truncated length-delimited field in migration payload")
            pos += length
            yield field_no, wire, val
        elif wire == 5:
            yield field_no, wire, buf[pos : pos + 4]
            pos += 4
        elif wire == 1:
            yield field_no, wire, buf[pos : pos + 8]
            pos += 8
        else:
            raise ValueError(f"unsupported protobuf wire type {wire}")


_MIG_ALGOS = {0: "SHA1", 1: "SHA1", 2: "SHA256", 3: "SHA512"}
_MIG_DIGITS = {0: 6, 1: 6, 2: 8}
_MIG_TYPES = {0: "totp", 1: "hotp", 2: "totp"}


def parse_migration(uri):
    """Parse an otpauth-migration:// URI into a list of entries (no printing of secrets)."""
    if not uri.startswith("otpauth-migration://"):
        raise ValueError("not an otpauth-migration:// URI")
    q = {k: v[0] for k, v in parse_qs(urlparse(uri).query).items()}
    if "data" not in q:
        raise ValueError("migration URI has no data parameter")
    raw = base64.b64decode(q["data"])
    entries = []
    for field_no, wire, val in _parse_fields(raw):
        if field_no != 1 or wire != 2:
            continue
        secret = b""
        name = ""
        issuer = ""
        algo = "SHA1"
        digits = 6
        otype = "totp"
        counter = 0
        for f2, w2, v2 in _parse_fields(val):
            if f2 == 1 and w2 == 2:
                secret = v2
            elif f2 == 2 and w2 == 2:
                name = v2.decode("utf-8", "replace")
            elif f2 == 3 and w2 == 2:
                issuer = v2.decode("utf-8", "replace")
            elif f2 == 4 and w2 == 0:
                algo = {0: "SHA1", 1: "SHA1", 2: "SHA256", 3: "SHA512", 4: "MD5"}.get(v2, "SHA1")
            elif f2 == 5 and w2 == 0:
                digits = _MIG_DIGITS.get(v2, 6)
            elif f2 == 6 and w2 == 0:
                otype = _MIG_TYPES.get(v2, "totp")
            elif f2 == 7 and w2 == 0:
                counter = v2
        if not secret:
            continue
        account = name
        if ":" in name:
            maybe_issuer, account = name.split(":", 1)
            issuer = issuer or maybe_issuer
            account = account.strip()
        entries.append(
            {
                "type": otype,
                "issuer": issuer,
                "account": account or name,
                "secret": base64.b32encode(secret).decode("ascii"),
                "algorithm": algo,
                "digits": digits,
                "period": 30,
                "counter": int(counter),
            }
        )
    if not entries:
        raise ValueError("migration payload contained no accounts")
    return entries


def slugify_label(entry, taken):
    import re

    base = entry.get("issuer") or entry.get("account") or "account"
    base = re.sub(r"[^a-z0-9]+", "-", base.lower()).strip("-") or "account"
    label = base
    n = 2
    while label in taken:
        label = f"{base}-{n}"
        n += 1
    return label


# ---------- universal export-file import ----------
def _entry(otype, issuer, account, secret_raw, algorithm="SHA1", digits=6, period=30, counter=0):
    algo = str(algorithm or "SHA1").upper().replace("-", "")
    if algo not in ALGOS:
        raise ValueError(f"unsupported algorithm: {algorithm}")
    return {
        "type": str(otype or "totp").lower(),
        "issuer": issuer or "",
        "account": account or "",
        "secret": secret_to_base32(secret_raw),
        "algorithm": algo,
        "digits": int(digits or 6),
        "period": int(period or 30),
        "counter": int(counter or 0),
    }


def _entries_from_text(text):
    entries = []
    for line in text.splitlines():
        line = line.strip().strip(",")
        if line.startswith("otpauth-migration://"):
            entries.extend(parse_migration(line))
        elif line.startswith("otpauth://") or line.startswith("steam://"):
            entries.append(parse_otpauth(line))
    return entries


def _entries_from_json_obj(obj):
    """Handle andOTP / Aegis / 2FAS / Bitwarden / Proton / FreeOTP+ / Steam maFile
    and, as a fallback, any JSON that embeds otpauth URIs or secret fields."""
    entries = []

    # Encrypted exports: detect and refuse clearly, never silently drop accounts.
    if isinstance(obj, dict):
        hdr = obj.get("header") or {}
        if isinstance(obj.get("db"), str) or (isinstance(hdr, dict) and hdr.get("slots")):
            raise ValueError(
                "this looks like an ENCRYPTED Aegis vault — re-export it as plain text from Aegis, then import that file"
            )
        if obj.get("servicesEncrypted") or obj.get("services_encrypted"):
            raise ValueError(
                "this looks like an ENCRYPTED 2FAS backup — re-export it from 2FAS without a password (plain backup), then import that file"
            )
        # Steam maFile: {"shared_secret": "<base64>", "account_name": "..."}
        if obj.get("shared_secret"):
            entries.append(
                _entry("steam", "Steam", obj.get("account_name", ""), obj["shared_secret"], digits=5)
            )
            return entries
        # Aegis plain vault: {"db": {"entries": [{"info": {"secret": ...}, ...}]}}
        db = obj.get("db")
        if isinstance(db, dict) and isinstance(db.get("entries"), list):
            for e in db["entries"]:
                info = e.get("info") or {}
                if not info.get("secret"):
                    continue
                entries.append(
                    _entry(
                        info.get("type") or e.get("type") or "totp",
                        e.get("issuer", ""),
                        e.get("name", ""),
                        info["secret"],
                        info.get("algo", "SHA1"),
                        info.get("digits", 6),
                        info.get("period", 30),
                        info.get("counter", 0),
                    )
                )
            return entries
        # 2FAS: {"services": [{"secret": ..., "otp": {...}}]}
        if isinstance(obj.get("services"), list):
            for s in obj["services"]:
                if not s.get("secret"):
                    continue
                otp = s.get("otp") or {}
                entries.append(
                    _entry(
                        otp.get("tokenType") or otp.get("token_type") or "totp",
                        otp.get("issuer") or s.get("issuer") or "",
                        otp.get("account") or otp.get("label") or s.get("name", ""),
                        s["secret"],
                        otp.get("algorithm", "SHA1"),
                        otp.get("digits", 6),
                        otp.get("period", 30),
                        otp.get("counter", 0),
                    )
                )
            return entries
        # Bitwarden / Proton vaults: {"items": [{"login": {"totp": ...}}, ...]}
        items = obj.get("items") or obj.get("entries") or obj.get("accounts")
        if isinstance(items, list):
            found = []
            for it in items:
                if not isinstance(it, dict):
                    continue
                login = it.get("login") or {}
                totp_val = (
                    login.get("totp")
                    or it.get("totp")
                    or it.get("totpSecret")
                    or ((it.get("content") or {}).get("totp") if isinstance(it.get("content"), dict) else None)
                )
                if totp_val:
                    if str(totp_val).startswith(("otpauth://", "steam://")):
                        e = parse_otpauth(str(totp_val))
                        if not e.get("account"):
                            e["account"] = it.get("name", "")
                        found.append(e)
                    else:
                        found.append(
                            _entry("totp", "", it.get("name", ""), totp_val)
                        )
                # Proton Authenticator items carry an otpauth URI in content
                content = it.get("content")
                if isinstance(content, str) and content.startswith("otpauth"):
                    found.append(parse_otpauth(content))
            if found:
                return found

    # andOTP / FreeOTP+ plain backup: a bare list of token objects
    if isinstance(obj, list):
        for e in obj:
            if not isinstance(e, dict) or not e.get("secret"):
                continue
            otype = str(e.get("type") or "totp")
            entries.append(
                _entry(
                    "steam" if otype.upper() == "STEAM" else otype,
                    e.get("issuer", ""),
                    e.get("name") or e.get("label") or e.get("account", ""),
                    e["secret"],
                    e.get("algorithm", "SHA1"),
                    e.get("digits", 5 if otype.upper() == "STEAM" else 6),
                    e.get("period", 30),
                    e.get("counter", 0),
                )
            )
        if entries:
            return entries

    # Generic fallback: any otpauth URI strings anywhere in the structure
    def walk(o):
        if isinstance(o, str):
            if o.startswith(("otpauth://", "steam://")):
                try:
                    entries.append(parse_otpauth(o))
                except Exception:
                    pass
            elif o.startswith("otpauth-migration://"):
                entries.extend(parse_migration(o))
        elif isinstance(o, dict):
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)

    walk(obj)
    return entries


def _entries_from_csv(text):
    entries = []
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        return entries
    lowered = {fn.lower(): fn for fn in reader.fieldnames if fn}
    for row in reader:
        # Bitwarden CSV: login_totp column holds an otpauth URI or a raw seed
        totp_val = None
        for key in ("login_totp", "totp", "totp seed", "totpseed", "otp", "secret"):
            if key in lowered and row.get(lowered[key]):
                totp_val = row[lowered[key]].strip()
                break
        name = ""
        for key in ("name", "title", "grouping", "account"):
            if key in lowered and row.get(lowered[key]):
                name = row[lowered[key]]
                break
        if not totp_val:
            continue
        if totp_val.startswith(("otpauth://", "steam://")):
            e = parse_otpauth(totp_val)
            if not e.get("account"):
                e["account"] = name
            entries.append(e)
        else:
            # KeePassXC CSV stores a raw seed (+ separate settings we can't fully parse)
            try:
                entries.append(_entry("totp", "", name, totp_val))
            except Exception:
                continue
    return entries


def parse_import_file(path):
    with open(path, "rb") as f:
        raw = f.read()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError(
            "file is not readable text — it may be an encrypted backup (e.g. encrypted andOTP). Re-export it as a plain backup, then import that file"
        )
    stripped = text.strip()
    entries = _entries_from_text(text)
    if entries:
        return entries
    if stripped.startswith(("{", "[")):
        try:
            obj = json.loads(stripped)
        except json.JSONDecodeError as e:
            raise ValueError(f"JSON export could not be parsed: {e}")
        return _entries_from_json_obj(obj)
    if "," in text.splitlines()[0] if text.splitlines() else False:
        return _entries_from_csv(text)
    return []


# ---------- commands ----------
def public_view(label, entry):
    return {
        "label": label,
        "type": entry["type"],
        "issuer": entry.get("issuer", ""),
        "account": entry.get("account", ""),
        "digits": entry.get("digits", 6),
        "period": entry.get("period", 30) if entry["type"] in ("totp", "steam") else None,
        "algorithm": entry.get("algorithm", "SHA1"),
    }


def _add_migration(uri):
    entries = parse_migration(uri)
    store = load_store()
    added = []
    for entry in entries:
        entry["created_at"] = int(time.time())
        decode_secret(entry["secret"])  # validate
        label = slugify_label(entry, store["accounts"])
        store["accounts"][label] = entry
        added.append(public_view(label, entry))
    save_store(store)
    return {"status": "imported", "count": len(added), "accounts": added, "store": STORE_FILE}


def cmd_add(args):
    raw_uri = None
    if args.uri:
        raw_uri = args.uri.strip()
    elif args.qr:
        raw_uri = decode_qr_image(args.qr)
    if raw_uri and raw_uri.startswith("otpauth-migration://"):
        return _add_migration(raw_uri)
    if raw_uri:
        entry = parse_otpauth(raw_uri)
    elif args.seed:
        entry = {
            "type": "totp",
            "issuer": args.issuer or "",
            "account": args.account or "",
            "secret": normalize_secret(args.seed),
            "algorithm": "SHA1",
            "digits": 6,
            "period": 30,
            "counter": 0,
        }
        decode_secret(entry["secret"])
    else:
        raise ValueError("add needs one of --seed, --uri, --qr")
    if args.issuer:
        entry["issuer"] = args.issuer
    if args.account:
        entry["account"] = args.account
    entry["created_at"] = int(time.time())
    store = load_store()
    existed = args.label in store["accounts"]
    store["accounts"][args.label] = entry
    save_store(store)
    out = public_view(args.label, entry)
    out["status"] = "replaced" if existed else "added"
    out["store"] = STORE_FILE
    return out


def cmd_code(args):
    store = load_store()
    entry = store["accounts"].get(args.label)
    if entry is None:
        raise ValueError(f"no account labelled '{args.label}' (try: list)")
    secret = decode_secret(entry["secret"])
    if entry["type"] == "steam":
        code, remaining = steam_code(secret, at=args.at, period=entry.get("period", 30))
        return {"label": args.label, "code": code, "type": "steam", "seconds_remaining": remaining}
    if entry["type"] == "hotp":
        counter = int(entry.get("counter", 0))
        code = hotp(secret, counter, entry.get("digits", 6), entry.get("algorithm", "SHA1"))
        entry["counter"] = counter + 1
        save_store(store)
        return {"label": args.label, "code": code, "type": "hotp", "counter_used": counter}
    code, remaining = totp(
        secret,
        at=args.at,
        digits=entry.get("digits", 6),
        period=entry.get("period", 30),
        algorithm=entry.get("algorithm", "SHA1"),
    )
    return {
        "label": args.label,
        "code": code,
        "type": "totp",
        "seconds_remaining": remaining,
    }


def cmd_list(args):
    store = load_store()
    return {
        "accounts": [public_view(k, v) for k, v in sorted(store["accounts"].items())],
        "count": len(store["accounts"]),
    }


def cmd_remove(args):
    store = load_store()
    if args.label not in store["accounts"]:
        raise ValueError(f"no account labelled '{args.label}'")
    del store["accounts"][args.label]
    save_store(store)
    return {"removed": args.label, "remaining": len(store["accounts"])}


def cmd_status(args):
    exists = os.path.exists(STORE_FILE)
    perms = oct(os.stat(STORE_FILE).st_mode & 0o777) if exists else None
    store = load_store()
    return {
        "store_dir": STORE_DIR,
        "store_file": STORE_FILE,
        "exists": exists,
        "file_permissions": perms,
        "accounts": len(store["accounts"]),
    }


def _add_entries(entries, issuer_override=None, account_override=None):
    if not entries:
        raise ValueError("no accounts found in that import — check the file/format and try again")
    store = load_store()
    added = []
    for entry in entries:
        if issuer_override:
            entry["issuer"] = issuer_override
        if account_override:
            entry["account"] = account_override
        entry["created_at"] = int(time.time())
        decode_secret(entry["secret"])  # validate
        label = slugify_label(entry, store["accounts"])
        store["accounts"][label] = entry
        added.append(public_view(label, entry))
    save_store(store)
    if len(added) == 1:
        out = dict(added[0])
        out["status"] = "added"
        out["store"] = STORE_FILE
        return out
    return {"status": "imported", "count": len(added), "accounts": added, "store": STORE_FILE}


def cmd_import(args):
    qr = getattr(args, "qr", None)
    file_path = getattr(args, "file", None)
    if not (qr or args.uri or file_path):
        raise ValueError("import needs --qr IMAGE..., --uri ..., or --file EXPORT_FILE")
    entries = []
    if file_path:
        entries.extend(parse_import_file(file_path))
    if args.uri:
        raw = args.uri.strip()
        if raw.startswith("otpauth-migration://"):
            entries.extend(parse_migration(raw))
        else:
            from_text = _entries_from_text(raw)
            entries.extend(from_text if from_text else [parse_otpauth(raw)])
    if qr:
        paths = qr if isinstance(qr, list) else [qr]
        for path in paths:
            raw = decode_qr_image(path)
            if raw.startswith("otpauth-migration://"):
                entries.extend(parse_migration(raw))
            else:
                entries.append(parse_otpauth(raw))
    return _add_entries(
        entries,
        issuer_override=getattr(args, "issuer", None),
        account_override=getattr(args, "account", None),
    )


def main():
    ap = argparse.ArgumentParser(prog="auth.py", description="Local TOTP/HOTP authenticator")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("add")
    p.add_argument("label")
    p.add_argument("--seed")
    p.add_argument("--uri")
    p.add_argument("--qr")
    p.add_argument("--issuer")
    p.add_argument("--account")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_add)

    # User-friendly import: no label needed — works for a single otpauth QR
    # (auto-labelled) and for Google Authenticator migration QRs (many accounts).
    p = sub.add_parser("import")
    p.add_argument("--qr", nargs="+")
    p.add_argument("--uri")
    p.add_argument("--file")
    p.add_argument("--issuer")
    p.add_argument("--account")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_import)

    p = sub.add_parser("code")
    p.add_argument("label")
    p.add_argument("--at", type=int)
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_code)

    p = sub.add_parser("list")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_list)

    p = sub.add_parser("remove")
    p.add_argument("label")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_remove)

    p = sub.add_parser("status")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_status)

    args = ap.parse_args()
    try:
        result = args.fn(args)
    except Exception as e:  # keep errors clean; never leak entry contents
        if getattr(args, "json", False):
            print(json.dumps({"error": str(e)}))
        else:
            print(f"error: {e}", file=sys.stderr)
        sys.exit(1)
    if getattr(args, "json", False):
        print(json.dumps(result, indent=2))
    else:
        if args.cmd == "code":
            extra = (
                f"  ({result['seconds_remaining']}s left)"
                if result["type"] in ("totp", "steam")
                else f"  (counter {result['counter_used']})"
            )
            print(f"{result['label']}: {result['code']}{extra}")
        elif args.cmd == "list":
            if not result["accounts"]:
                print("no accounts enrolled")
            for a in result["accounts"]:
                who = a["issuer"] or a["account"] or "-"
                print(f"{a['label']}: {who} ({a['type']}, {a['digits']} digits)")
        else:
            print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
