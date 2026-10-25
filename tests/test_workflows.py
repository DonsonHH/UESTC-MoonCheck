"""Synthetic-only tests: no school credentials or school network requests."""
import base64
import contextlib
import copy
import datetime as dt
import email.message
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

from moonuestc.__main__ import main, one_round, selftest
from moonuestc.client import ENTRY, H5, LOGIN, School, encrypt_password, login_fields
from moonuestc.errors import AuthRequired, ToolError
from moonuestc.policy import SHANGHAI, build_payload, check_fence, valid_today, validate_config, verified, window
from moonuestc.runner import account_key, cookie_path, run_account
from moonuestc.state import State, execution_lock
from moonuestc.transport import Response, Transport, checked_url

INSTANT = dt.datetime(2026, 10, 18, 22, 0, tzinfo=SHANGHAI)
DAY = INSTANT.date().isoformat()
ACCOUNT = {
    "id": "me", "enabled": True, "student_id": "202300000001",
    "password": "Synthetic-Password-Secret", "browser_fingerprint": "ABCDEF0123456789ABCDEF0123456789",
    "user_agent": "Synthetic/1.0 User Agent for Offline Tests",
    "checkin_payload": {
        "latitude": 0.0, "longitude": 0.0, "reverseGeocode": "Synthetic location",
        "coordinateSystemCode": "gcj02", "accuracy": 20, "locationDurationMs": 1000,
        "networkTypeCode": "wifi", "locationEnabled": False, "locationAuthorized": "",
        "locationAccuracy": "", "errorMessage": ""}}
SCHEDULE = {"effective": True, "studentCheckinStartOffsetMinute": 1260,
            "studentCheckinEndOffsetMinute": 1410}
FENCES = [{"latitude": 0.0, "longitude": 0.0, "radiusMeter": 130}]


def record(status="PENDING", **kwargs):
    return {"businessDate": DAY, "recordStatusCode": status, "abnormalFlag": False,
            "checkinTime": DAY + " 22:00:00" if status == "CHECKED_IN" else None, **kwargs}


def response(url, data=None, status=200, location=None, text=None):
    headers = email.message.Message()
    if location:
        headers["Location"] = location
    body = text.encode() if text is not None else json.dumps(data).encode()
    return Response(status, headers, body, url)


class FakeTransport:
    def __init__(self, ua="Synthetic UA", path=None):
        self.calls, self.cookies, self.session = [], {}, False
        self.saved, self.status, self.post_count = False, "PENDING", 0
        self.timeout_post, self.accept_before_timeout, self.mfa = False, False, False
        self.unauthorized, self.abnormal, self.stale_day = False, False, False
        self.saved_path, self.login_rejected = path, False
        self.warm = False

    def has_session(self):
        return self.session

    def clear(self):
        self.cookies.clear()
        self.session = False

    def fingerprint(self, value):
        self.cookies["fingerprint"] = value

    def save(self):
        self.saved = True

    def request(self, method, url, *, stage, headers=None, form=None, payload=None):
        self.calls.append((method, stage))
        if stage == "platform_previsit":
            return response(url, status=302, location=LOGIN)
        if stage == "cas_page":
            return response(url, text="<input value='e1s1' name='execution'><input value='0123456789ABCDEF' id='pwdEncryptSalt'>")
        if stage == "cas_submit":
            if self.mfa:
                return response(url, status=302, location="/authserver/reAuthCheck/reAuthLoginView.do?isMultifactor=true")
            if self.login_rejected:
                return response(url, text="用户名或密码错误")
            if not form or form["password"] == ACCOUNT["password"]:
                raise AssertionError("CAS form must encrypt the password")
            return response(url, status=302, location="https://jzsz.uestc.edu.cn/?ticket=ST-Synthetic-Secret")
        if stage == "portal_warmup":
            self.warm = True
            return response(url, {"code": 0})
        if stage == "today":
            data = record(self.status, abnormalFlag=self.abnormal)
            if self.stale_day:
                data["businessDate"] = "2026-10-17"
            return response(url, {"code": 0, "ok": True, "data": data})
        if stage == "schedule":
            return response(url, {"code": 0, "ok": True, "data": SCHEDULE})
        if stage == "locations":
            return response(url, {"code": 0, "ok": True, "data": FENCES})
        if stage == "checkin_post":
            self.post_count += 1
            if not self.timeout_post or self.accept_before_timeout:
                self.status = "CHECKED_IN"
            if self.timeout_post:
                raise ToolError("timeout", stage)
            return response(url, {"code": 0, "ok": True, "data": True})
        raise AssertionError("Unexpected stage: " + stage)

    def follow(self, url, *, stage, headers=None):
        self.calls.append(("GET", stage))
        if stage == "ticket_exchange":
            self.session = True
            return response("https://jzsz.uestc.edu.cn/", text="portal")
        if stage == "micro_app_entry":
            if not self.warm:
                raise AssertionError("portal warmup must precede micro-app entry")
            if self.unauthorized:
                return response("https://jzsz.uestc.edu.cn/", text="portal")
            return response(H5, text="<html>app</html>")
        raise AssertionError("Unexpected follow: " + stage)


class CryptoAndPolicy(unittest.TestCase):
    def test_cas_password_roundtrip_with_server_style_iv(self):
        salt = "0123456789ABCDEF"
        for password in ("Test123", "测试-Pass-123", "A" * 70):
            encrypted = base64.b64decode(encrypt_password(password, salt))
            recovered = unpad(AES.new(salt.encode(), AES.MODE_CBC, b"\0" * 16).decrypt(encrypted), 16)
            self.assertEqual(recovered[64:], password.encode())

    def test_attribute_order_single_quotes_and_entity(self):
        fields = login_fields("<input value='e1&amp;s1' type=hidden name=execution><input value='0123456789ABCDEF' id=pwdEncryptSalt>")
        self.assertEqual(fields["execution"], "e1&s1")

    def test_changed_login_page_stops(self):
        with self.assertRaises(ToolError):
            login_fields("<html>Captive portal</html>")

    def test_schedule_boundaries_and_safety_margin(self):
        for hour, minute, expected in ((20,59,False), (21,0,True), (23,27,True), (23,28,False), (23,30,False)):
            self.assertEqual(window(SCHEDULE, INSTANT.replace(hour=hour, minute=minute))["open"], expected)
        for changes in ({"effective": False}, {"studentCheckinEndOffsetMinute": None}, {"studentCheckinEndOffsetMinute": 2800}):
            with self.assertRaises(ToolError):
                window({**SCHEDULE, **changes}, INSTANT)

    def test_no_coordinate_defaults(self):
        with self.assertRaises(ToolError):
            build_payload({**ACCOUNT, "checkin_payload": None}, INSTANT)

    def test_nan_and_wrong_coordinate_system_stop(self):
        for change in ({"latitude": float("nan")}, {"accuracy": -1}, {"accuracy": float("inf")}, {"coordinateSystemCode": "wgs84"}):
            account = copy.deepcopy(ACCOUNT)
            account["checkin_payload"].update(change)
            with self.assertRaises(ToolError):
                build_payload(account, INSTANT)

    def test_payload_timestamp_is_current_china_time(self):
        payload = build_payload(ACCOUNT, INSTANT)
        self.assertEqual(payload["clientTime"], "2026-10-18 22:00:00")
        self.assertNotIn("clientTime", ACCOUNT["checkin_payload"])

    def test_fence_inside_outside_and_invalid(self):
        payload = build_payload(ACCOUNT, INSTANT)
        check_fence(payload, FENCES)
        for fences in ([{"latitude": 1, "longitude": 0, "radiusMeter": 130}], [], [{"latitude": 0, "longitude": 0, "radiusMeter": -1}]):
            with self.assertRaises(ToolError):
                check_fence(payload, fences)

    def test_current_day_and_abnormal_record(self):
        self.assertTrue(verified(record("CHECKED_IN"), INSTANT))
        for changed in ({"businessDate": "2026-10-17"}, {"abnormalFlag": True}, {"recordStatusCode": "NEW_STATUS"}):
            with self.assertRaises(ToolError):
                valid_today(record(**changed), INSTANT)
        self.assertFalse(verified(record("CHECKED_IN", checkinTime=None), INSTANT))
        self.assertFalse(verified(record("CHECKED_IN", abnormalFlag=None), INSTANT))

    def test_config_duplicates_disabled_accounts_and_optional_payload(self):
        a = {**ACCOUNT, "checkin_payload": None}
        cfg = {"version": 1, "accounts": [a]}
        validate_config(cfg)
        validate_config({**cfg, "accounts": [a, {"id": "disabled", "enabled": False}]})
        with self.assertRaises(ToolError):
            validate_config({**cfg, "accounts": [a, {**a, "id": "other"}]})
        for changed in ({"browser_fingerprint": "PUT_VALUE"}, {"id": "../escape"}, {"password": "PUT_PASSWORD"}):
            with self.assertRaises(ToolError):
                validate_config({**cfg, "accounts": [{**a, **changed}]})

    def test_redirect_host_scheme_and_userinfo_allowlist(self):
        checked_url(LOGIN)
        for url in ("http://jzsz.uestc.edu.cn/", "https://evil.example/", "https://jzsz.uestc.edu.cn.evil.example/", "https://user:pass@jzsz.uestc.edu.cn/", "https://jzsz.uestc.edu.cn:444/"):
            with self.assertRaises(ToolError):
                checked_url(url)


class Flows(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="moonuestc-test-", dir=os.environ.get("MOON_TEST_TMP"))
        self.directory = Path(self.temp.name)
        self.state = State(self.directory)
        self.transport = FakeTransport()
        self.kwargs = {"clock": lambda: INSTANT, "sleep": lambda _: None,
                       "transport_factory": lambda *args: self.transport}

    def tearDown(self):
        self.state.close()
        self.temp.cleanup()

    def run_mode(self, mode="checkin", account=ACCOUNT):
        return run_account(account, mode, self.state, self.directory, **self.kwargs)

    def test_full_auth_warmup_and_diagnose_never_submit(self):
        out = self.run_mode("diagnose", {**ACCOUNT, "checkin_payload": None})
        self.assertEqual(out["result"], "auth_ready")
        self.assertEqual(self.transport.post_count, 0)
        self.assertFalse(out["payloadConfigured"])
        self.assertEqual([s for _, s in self.transport.calls[:7]],
                         ["platform_previsit", "cas_page", "cas_submit", "ticket_exchange", "portal_warmup", "micro_app_entry", "today"])

    def test_mfa_stops_without_checkin(self):
        self.transport.mfa = True
        with self.assertRaises(ToolError) as context:
            self.run_mode()
        self.assertEqual(context.exception.reason, "need_manual_mfa")
        self.assertEqual(self.transport.post_count, 0)

    def test_cas_success_is_not_business_auth_success(self):
        self.transport.unauthorized = True
        with self.assertRaises(ToolError) as context:
            self.run_mode("diagnose")
        self.assertEqual(context.exception.reason, "micro_app_unauthorized_after_login")
        self.assertEqual(self.transport.post_count, 0)

    def test_prepare_never_claims_or_posts(self):
        self.assertEqual(self.run_mode("prepare")["result"], "dry_run_ready")
        self.assertFalse(self.state.claimed(account_key(ACCOUNT), DAY))
        self.assertEqual(self.transport.post_count, 0)

    def test_post_is_confirmed_from_saved_record(self):
        out = self.run_mode()
        self.assertEqual(out["result"], "confirmed")
        self.assertTrue(self.state.ready(account_key(ACCOUNT)))
        self.assertEqual(self.transport.post_count, 1)

    def test_second_run_never_reposts(self):
        self.run_mode()
        self.run_mode()
        self.assertEqual(self.transport.post_count, 1)

    def test_accepted_post_timeout_is_reconciled(self):
        self.transport.timeout_post = self.transport.accept_before_timeout = True
        self.assertEqual(self.run_mode()["result"], "confirmed")
        self.assertEqual(self.transport.post_count, 1)

    def test_unaccepted_post_timeout_remains_unknown_and_not_resent(self):
        self.transport.timeout_post = True
        self.assertEqual(self.run_mode()["result"], "submission_unknown")
        self.assertEqual(self.run_mode()["result"], "submission_unknown")
        self.assertEqual(self.transport.post_count, 1)
        self.assertFalse(self.state.ready(account_key(ACCOUNT)))

    def test_crash_claim_survives_db_reopen(self):
        self.state.claim(account_key(ACCOUNT), DAY)
        self.state.close()
        self.state = State(self.directory)
        self.assertEqual(self.run_mode()["result"], "submission_unknown")
        self.assertEqual(self.transport.post_count, 0)

    def test_existing_report_or_exemption_not_overwritten(self):
        for status in ("STUDENT_REPORTED", "INSTRUCTOR_REPORTED", "EXEMPT"):
            self.transport.status = status
            self.assertEqual(self.run_mode()["result"], "already_recorded")
        self.assertEqual(self.transport.post_count, 0)

    def test_schedule_outside_never_posts(self):
        self.kwargs["clock"] = lambda: INSTANT.replace(hour=12)
        with self.assertRaises(ToolError) as context:
            self.run_mode()
        self.assertEqual(context.exception.reason, "outside_checkin_window")
        self.assertEqual(self.transport.post_count, 0)

    def test_stale_or_abnormal_record_never_posts(self):
        self.transport.stale_day = True
        with self.assertRaises(ToolError):
            self.run_mode()
        self.transport.stale_day = False
        self.transport.abnormal = True
        with self.assertRaises(ToolError):
            self.run_mode()
        self.assertEqual(self.transport.post_count, 0)

    def test_cached_session_avoids_password_login(self):
        self.transport.session = True
        self.run_mode("diagnose")
        self.assertNotIn(("POST", "cas_submit"), self.transport.calls)

    def test_three_credential_attempt_daily_budget(self):
        for _ in range(3):
            self.state.login_budget("account", DAY)
        with self.assertRaises(ToolError) as context:
            self.state.login_budget("account", DAY)
        self.assertEqual(context.exception.reason, "daily_login_limit")
        self.state.login_budget("other-account", DAY)
        self.state.login_budget("account", "2026-10-19")

    def test_cookie_binding_is_student_specific_and_password_sensitive(self):
        a = cookie_path(self.directory, ACCOUNT)
        for changed in ({"student_id": "202300000002"}, {"password": "DifferentSyntheticPass"}, {"browser_fingerprint": "1" * 32}):
            self.assertNotEqual(a, cookie_path(self.directory, {**ACCOUNT, **changed}))
        self.assertEqual(account_key(ACCOUNT), account_key({**ACCOUNT, "id": "renamed"}))

    def test_ten_accounts_have_independent_transport_cookie_and_claims(self):
        paths = set()
        for i in range(10):
            account = {**ACCOUNT, "id": f"student{i}", "student_id": f"2023000000{i:02d}"}
            fake = FakeTransport()
            self.kwargs["transport_factory"] = lambda ua, path, f=fake: (paths.add(path), f)[1]
            self.assertEqual(self.run_mode(account=account)["result"], "confirmed")
            self.assertEqual(fake.post_count, 1)
        self.assertEqual(len(paths), 10)
        self.assertEqual(self.state.db.execute("SELECT COUNT(*) FROM claims").fetchone()[0], 10)

    def test_failed_account_does_not_stop_next_account(self):
        second = {**ACCOUNT, "id": "second", "student_id": "202300000002"}
        bad, good = FakeTransport(), FakeTransport()
        bad.mfa = True
        with patch("moonuestc.__main__.run_account", side_effect=[ToolError("need_manual_mfa", "cas_submit"), {"result": "confirmed"}]) as run, patch("moonuestc.__main__.time.sleep"), contextlib.redirect_stdout(io.StringIO()) as stream:
            code = one_round({"account_gap_seconds": 20}, [ACCOUNT, second], self.state, self.directory, "checkin")
        self.assertEqual(run.call_count, 2)
        self.assertEqual(code, 2)
        self.assertEqual(len(stream.getvalue().splitlines()), 2)

    def test_logs_do_not_contain_password_cookie_or_ticket(self):
        with patch("moonuestc.__main__.run_account", side_effect=ToolError("need_manual_mfa", "cas_submit")), contextlib.redirect_stdout(io.StringIO()) as stream:
            one_round({}, [ACCOUNT], self.state, self.directory, "diagnose")
        for secret in (ACCOUNT["password"], ACCOUNT["student_id"], ACCOUNT["browser_fingerprint"], "ST-Synthetic-Secret"):
            self.assertNotIn(secret, stream.getvalue())

    def test_process_lock_rejects_second_holder(self):
        with execution_lock(self.directory):
            with self.assertRaises(ToolError) as context:
                with execution_lock(self.directory):
                    pass
        self.assertEqual(context.exception.reason, "another_run_active")

    def test_cookie_domain_path_and_expiry_roundtrip_without_network(self):
        path = self.directory / "cookies" / "synthetic.lwp"
        transport = Transport(ACCOUNT["user_agent"], path)
        transport.fingerprint(ACCOUNT["browser_fingerprint"])
        transport.save()
        restored = Transport(ACCOUNT["user_agent"], path)
        cookie = next(iter(restored.jar))
        self.assertEqual(cookie.domain, "idas.uestc.edu.cn")
        self.assertTrue(cookie.secure)
        self.assertFalse(restored.has_session())
        self.assertEqual(cookie.value, ACCOUNT["browser_fingerprint"])

    def test_checkin_requires_explicit_submit_flag_before_network(self):
        config_path = self.directory / "config.json"
        config_path.write_text(json.dumps({"version": 1, "accounts": [ACCOUNT]}))
        with self.assertRaises(ToolError) as context:
            main(["checkin", "--config", str(config_path), "--data-dir", str(self.directory)])
        self.assertEqual(context.exception.reason, "explicit_submit_flag_required")

    def test_claim_exists_before_the_checkin_post(self):
        original = self.transport.request
        def request(method, url, **kwargs):
            if kwargs["stage"] == "checkin_post":
                self.assertTrue(self.state.claimed(account_key(ACCOUNT), DAY))
            return original(method, url, **kwargs)
        self.transport.request = request
        self.assertEqual(self.run_mode()["result"], "confirmed")

    def test_abnormal_result_after_post_is_never_success(self):
        original = self.transport.request
        def request(method, url, **kwargs):
            out = original(method, url, **kwargs)
            if kwargs["stage"] == "checkin_post":
                self.transport.abnormal = True
            return out
        self.transport.request = request
        out = self.run_mode()
        self.assertEqual(out["result"], "submission_unknown")
        self.assertEqual(out["reason"], "abnormal_record")
        self.assertFalse(self.state.ready(account_key(ACCOUNT)))
        self.assertEqual(self.transport.post_count, 1)

    def test_api_code_zero_with_ok_false_is_rejected(self):
        school = School(self.transport, ACCOUNT, lambda: None)
        with patch.object(self.transport, "request", return_value=response(H5, {"code": 0, "ok": False, "data": record()})):
            with self.assertRaises(ToolError):
                school.today()
        with patch.object(self.transport, "request", return_value=response(H5, {"code": False, "ok": True, "data": record()})):
            with self.assertRaises(ToolError):
                school.today()

    def test_expired_cached_session_gets_only_one_fresh_login(self):
        self.transport.session = True
        original = self.transport.follow
        counter = [0]
        def follow(url, **kwargs):
            if kwargs["stage"] == "micro_app_entry" and counter[0] == 0:
                counter[0] += 1
                return response("https://jzsz.uestc.edu.cn/", text="expired")
            return original(url, **kwargs)
        self.transport.follow = follow
        self.assertEqual(self.run_mode("diagnose")["result"], "auth_ready")
        self.assertEqual(self.transport.calls.count(("POST", "cas_submit")), 1)

    def test_prepare_checks_payload_even_if_already_checked_in(self):
        self.transport.status = "CHECKED_IN"
        out = self.run_mode("prepare")
        self.assertEqual(out["result"], "dry_run_ready")
        self.assertTrue(out["alreadyRecorded"])
        with self.assertRaises(ToolError):
            self.run_mode("prepare", {**ACCOUNT, "checkin_payload": None})
        self.assertEqual(self.transport.post_count, 0)

    def test_prepare_outside_window_still_never_posts(self):
        self.kwargs["clock"] = lambda: INSTANT.replace(hour=12)
        out = self.run_mode("prepare")
        self.assertEqual(out["result"], "dry_run_ready")
        self.assertFalse(out["checkinWindow"]["open"])
        self.assertEqual(self.transport.post_count, 0)

    def test_selftest_never_constructs_transport(self):
        with patch("moonuestc.runner.Transport", side_effect=AssertionError("network forbidden")), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(selftest(), 0)


if __name__ == "__main__":
    unittest.main()
