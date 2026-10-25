#!/usr/bin/env python3
"""Internal collector: call only through release_guard, which captures stdout."""
import base64
import json
import hashlib
import hmac
import os
from pathlib import Path
import sqlite3
import sys

def collect():
    from Crypto.Cipher import AES
    directory=Path(os.environ.get("MOON_DATA","/data"))
    key=(directory/"dashboard.key").read_bytes()
    if len(key)!=32:
        raise ValueError()
    db=sqlite3.connect((directory/"dashboard.sqlite3").as_uri()+"?mode=ro",uri=True,timeout=5)
    db.execute("PRAGMA query_only=ON")
    db.execute("BEGIN")
    values={key,hmac.new(key,b"captcha_signing\0altcha-v2",hashlib.sha256).digest()}
    def add(value):
        if isinstance(value,str):
            value=value.encode()
        if isinstance(value,bytes) and len(value)>=6:
            values.add(value)
    def opened(raw,purpose):
        raw=bytes(raw)
        if raw[:3]!=b"MW1" or len(raw)<31:
            raise ValueError()
        add(raw)
        cipher=AES.new(key,AES.MODE_GCM,nonce=raw[3:15]);cipher.update(purpose.encode())
        return json.loads(cipher.decrypt_and_verify(raw[31:],raw[15:31]))
    users=list(db.execute("SELECT username,display_name,password_hash,role FROM web_users"))
    for username,display,password_hash,role in users:
        add(password_hash)
        if role=='user':add(username);add(display)
    accounts=list(db.execute("SELECT id,payload FROM web_accounts"))
    for aid,payload in accounts:
        account=opened(payload,"account:"+aid)
        for field in ["student_id","password","browser_fingerprint","browser_profile","variation_seed"]:
            add(account.get(field))
        grant=account.get('wechat_authorization') or {}
        for field in ('id','school_user_id'):
            add(grant.get(field))
        credentials=grant.get('credentials') or {}
        for field in ('openid','accesstoken','refreshtoken','nickname'):
            add(credentials.get(field))
    if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='portal_access_grants'").fetchone():
        for digest,payload in db.execute('SELECT student_digest,payload FROM portal_access_grants'):
            add(opened(payload,'portal_access:'+digest).get('student_id'))
    cookies=list(db.execute("SELECT binding,payload FROM web_cookies"))
    for binding,payload in cookies:
        for cookie in opened(payload,"cookie:"+binding):
            add(cookie.get("value"))
    for token_hash,csrf in db.execute("SELECT token_hash,csrf FROM web_sessions"):
        add(token_hash);add(csrf)
    db.close()
    config=Path(os.environ.get("MOON_CONFIG","/config/config.json"))
    def inspect(value):
        if isinstance(value,dict):
            for name,item in value.items():
                if name in ("student_id","password","browser_fingerprint","api_key","secret_key",
                            "openid","accesstoken","refreshtoken","access_token","refresh_token","school_user_id"):
                    add(item)
                inspect(item)
        elif isinstance(value,list):
            for item in value:
                inspect(item)
    if config.exists():
        raw=config.read_bytes();add(raw);inspect(json.loads(raw))
    return {"schema":1,"markers_b64":[base64.b64encode(v).decode() for v in sorted(values)],
            "read_only":True,"plaintext_written_to_disk":False}

if __name__=="__main__":
    try:
        result=collect()
        # The parent process keeps this protocol in memory; never invoke directly.
        sys.stdout.write(json.dumps(result))
    except Exception:
        sys.stderr.write("Private privacy inventory unavailable.\n")
        raise SystemExit(1)
