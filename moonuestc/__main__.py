"""CLI entry point. Never call school endpoints at import or selftest time."""
import argparse
import datetime as dt
import json
import os
import signal
import sqlite3
import sys
import time
from pathlib import Path

from . import __version__
from .client import encrypt_password
from .errors import ToolError
from .diagnostics import error_details
from .locations import list_presets
from .policy import clock_minutes, now, validate_config
from .runner import account_key, run_account
from .state import State, execution_lock

SUCCESS = {"auth_ready", "dry_run_ready", "confirmed", "already_recorded"}
SAFE_RESULTS = SUCCESS | {"submission_unknown", "submission_rejected", "record_changed", "error", "skipped"}


def emit(event, **values):
    print(json.dumps({"time": now().isoformat(timespec="seconds"), "event": event, **values},
                     ensure_ascii=False, allow_nan=False), flush=True)


def load_config(path):
    try:
        return validate_config(json.loads(Path(path).read_text(encoding="utf-8-sig")))
    except (OSError, ValueError):
        raise ToolError("config_unreadable_or_invalid_json", "config") from None


def selftest():
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
    import base64
    salt, password = "0123456789ABCDEF", "Synthetic-Test-Only-123"
    encrypted = base64.b64decode(encrypt_password(password, salt))
    recovered = unpad(AES.new(salt.encode(), AES.MODE_CBC, b"\0" * 16).decrypt(encrypted), 16)
    if recovered[64:] != password.encode():
        raise ToolError("crypto_selftest_failed")
    emit("selftest", result="passed", version=__version__, schoolRequests=0,
         python=sys.version.split()[0])
    return 0


def selected_accounts(config, wanted):
    accounts = [a for a in config["accounts"] if a.get("enabled", True)]
    if wanted:
        accounts = [a for a in accounts if a["id"] == wanted]
    if not accounts:
        raise ToolError("no_enabled_matching_account", "config")
    return accounts


def one_round(config, accounts, state, directory, mode):
    failed = False
    for index, account in enumerate(accounts):
        if index:
            time.sleep(config.get("account_gap_seconds", 20))
        try:
            result = run_account(account, mode, state, directory,
                emit=lambda event, **values: emit(event, account=account["id"], **values))
        except ToolError as error:
            result = {"result": "error", **error_details(error,account)}
        except (OSError, sqlite3.Error):
            result = {"result": "error", "reason": "private_data_io_error", "stage": "storage"}
        emit("result", account=account["id"], **result)
        failed = failed or result["result"] not in SUCCESS
    return 2 if failed else 0


def daemon(config_path, data_dir, wanted):
    stopping = False
    def stop(signum, frame):
        nonlocal stopping
        stopping = True
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    emit("daemon_started", version=__version__)
    while not stopping:
        config = load_config(config_path)
        if config.get("automation_enabled") is not True:
            raise ToolError("automation_disabled", "config")
        accounts = selected_accounts(config, wanted)
        instant = now()
        if instant.hour * 60 + instant.minute >= clock_minutes(config.get("run_at", "22:00")):
            with execution_lock(data_dir):
                state = State(data_dir)
                try:
                    for account in accounts:
                        key, day = account_key(account), instant.date().isoformat()
                        if state.daily_done(key, day):
                            continue
                        if not state.ready(key):
                            emit("result", account=account["id"], result="error", reason="first_verified_checkin_required")
                            state.save_daily(key, day, "first_verified_checkin_required")
                            continue
                        result = one_round(config, [account], state, data_dir, "checkin")
                        state.save_daily(key, day, "ok" if result == 0 else "manual_attention_required")
                        # One scheduled attempt per account/day in this validation release.
                        if len(accounts) > 1 and not stopping:
                            time.sleep(config.get("account_gap_seconds", 20))
                finally:
                    state.close()
        if not stopping:
            time.sleep(30)
    emit("daemon_stopped")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="MoonUESTC NAS 验证工具；默认不提交打卡")
    parser.add_argument("command", choices=("selftest", "locations", "validate", "diagnose", "prepare", "checkin", "daemon", "serve", "init-admin", "reset-password", "import-config"))
    parser.add_argument("--config", default=os.environ.get("MOON_CONFIG", "/config/config.json"))
    parser.add_argument("--data-dir", default=os.environ.get("MOON_DATA", "/data"))
    parser.add_argument("--account", help="本地账号标签，如 me")
    parser.add_argument("--submit", action="store_true", help="仅 checkin 使用；确认真实提交一次")
    args = parser.parse_args(argv)
    os.umask(0o077)
    if args.command == "selftest":
        return selftest()
    if args.command == "locations":
        emit("location_presets", locations=list_presets(), schoolRequests=0)
        return 0
    if args.command in ("serve", "init-admin", "reset-password", "import-config"):
        from .web_store import WebStore
        from .web_errors import WebError
        import getpass
        try:
            if args.command == "serve":
                from .web_app import serve_dashboard
                public_url = os.environ.get("MOON_PUBLIC_URL", "")
                serve_dashboard(args.data_dir, public_url,
                                allow_http=os.environ.get("MOON_ALLOW_INSECURE_HTTP") == "1")
                return 0
            store = WebStore(args.data_dir)
            if args.command in ("init-admin", "reset-password"):
                if args.command == "init-admin" and store.initialized():
                    raise WebError(409, "already_initialized", "管理员已初始化。")
                username = input("管理员用户名：" if args.command == "init-admin" else "要重置的用户名：").strip()
                password = getpass.getpass("新的登录密码（至少12字符）：")
                if password != getpass.getpass("再次输入密码："):
                    raise WebError(400, "password_mismatch", "两次密码不一致。")
                if args.command == "init-admin":
                    store.create_user(None, {"username": username, "display_name": username,
                                      "password": password, "role": "admin"}, bootstrap=True)
                else:
                    store.reset_password_local(username, password)
                emit("dashboard_identity_updated", result="success")
                return 0
            owner_name = input("导入到哪个用户（用户名）：").strip()
            owner = next((u for u in store.users() if u["username"].casefold() == owner_name.casefold()), None)
            if not owner:
                raise WebError(404, "owner_missing", "用户不存在。")
            legacy = load_config(args.config)
            imported = 0
            for account in legacy["accounts"]:
                if not account.get("enabled", True):
                    continue
                location = account.get("location")
                if location is None and isinstance(account.get("checkin_payload"), dict):
                    raw = account["checkin_payload"]
                    location = {"mode": "fixed", "name": account["id"], "latitude": raw["latitude"],
                                "longitude": raw["longitude"], "coordinate_system": raw["coordinateSystemCode"],
                                "reverse_geocode": raw["reverseGeocode"],
                                "request_metadata": {key: raw[key] for key in ("accuracy", "locationDurationMs", "networkTypeCode", "locationEnabled", "locationAuthorized", "locationAccuracy", "errorMessage")}}
                fields = {key: account[key] for key in ("student_id", "password", "browser_fingerprint", "user_agent")}
                fields.update(label=account["id"], owner_id=owner["id"], location=location,
                              enabled=True, automatic=False, run_at=legacy.get("run_at", "22:00"))
                store.save_account({"id": owner["id"], "role": "admin"}, fields)
                imported += 1
            emit("dashboard_imported", accounts=imported, schoolRequests=0)
            return 0
        except WebError as error:
            emit("error", result="error", reason=error.code, message=error.message)
            return 2
    config = load_config(args.config)
    accounts = selected_accounts(config, args.account)
    if args.command == "validate":
        emit("config_valid", enabledAccounts=len(accounts), schoolRequests=0,
             automationEnabled=config.get("automation_enabled", False))
        return 0
    if args.command == "checkin" and not args.submit:
        raise ToolError("explicit_submit_flag_required", "local")
    if args.command == "daemon":
        return daemon(args.config, args.data_dir, args.account)
    with execution_lock(args.data_dir):
        state = State(args.data_dir)
        try:
            return one_round(config, accounts, state, args.data_dir, args.command)
        finally:
            state.close()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except ToolError as error:
        emit("error", result="error", reason=error.reason, stage=error.stage)
        sys.exit(2)
    except KeyboardInterrupt:
        emit("interrupted", result="error")
        sys.exit(130)
    except Exception:
        # Never print raw exceptions, URLs, request bodies, or credentials.
        emit("error", result="error", reason="unexpected_local_error", stage="local")
        sys.exit(2)
