"""Fixed-location tests. Every school response is synthetic."""
import copy
import datetime as dt
import os
import tempfile
import unittest
import urllib.parse
from pathlib import Path

import test_workflows as fixtures
from moonuestc.client import School
from moonuestc.errors import ToolError
from moonuestc.policy import (FIXED_METADATA_DEFAULTS, build_payload, location_configured,
                              location_source, validate_config)
from moonuestc.runner import account_key, run_account
from moonuestc.state import State


def fixed_account(**location_changes):
    account = copy.deepcopy(fixtures.ACCOUNT)
    account.pop("checkin_payload")
    account["location"] = {"mode": "fixed", "latitude": 0.00001, "longitude": -0.00002,
                           "reverse_geocode": "Configured test address", "coordinate_system": "gcj02",
                           **location_changes}
    return account


class FixedPolicy(unittest.TestCase):
    def test_uses_coordinates_verbatim_without_modifying_configuration(self):
        account = fixed_account(latitude=30.123456789, longitude=103.987654321)
        before = copy.deepcopy(account)
        payload = build_payload(account, fixtures.INSTANT)
        self.assertEqual(payload["latitude"], 30.123456789)
        self.assertEqual(payload["longitude"], 103.987654321)
        self.assertEqual(account, before)
        for key, value in FIXED_METADATA_DEFAULTS.items():
            self.assertEqual(payload[key], value)
        self.assertEqual(location_source(account), "fixed")

    def test_same_coordinates_new_client_time_on_a_different_day(self):
        account = fixed_account()
        first = build_payload(account, fixtures.INSTANT)
        second = build_payload(account, fixtures.INSTANT + dt.timedelta(days=1))
        self.assertEqual(first["latitude"], second["latitude"])
        self.assertEqual(first["longitude"], second["longitude"])
        self.assertNotEqual(first["clientTime"], second["clientTime"])

    def test_no_fallback_when_coordinates_are_missing_or_invalid(self):
        for values in ({"latitude": None}, {"longitude": None}, {"latitude": 91}, {"longitude": -181},
                       {"latitude": "30.123"}, {"longitude": float("nan")}, {"latitude": True}):
            with self.subTest(values=values), self.assertRaises(ToolError):
                build_payload(fixed_account(**values), fixtures.INSTANT)

    def test_zero_coordinates_are_valid_numeric_inputs(self):
        self.assertTrue(location_configured(fixed_account(latitude=0.0, longitude=0.0)))
        build_payload(fixed_account(latitude=0.0, longitude=0.0), fixtures.INSTANT)
        self.assertFalse(location_configured(fixed_account(latitude=None)))

    def test_browser_mode_and_unknown_location_fields_are_rejected(self):
        for values in ({"mode": "browser"}, {"mode": "ip"}, {"latitdue": 1}):
            with self.subTest(values=values), self.assertRaises(ToolError):
                build_payload(fixed_account(**values), fixtures.INSTANT)

    def test_explicit_metadata_overrides_and_no_sensor_accuracy_gate(self):
        account = fixed_account(request_metadata={"accuracy": 500, "locationDurationMs": 0,
                                                  "networkTypeCode": "unknown"})
        payload = build_payload(account, fixtures.INSTANT)
        self.assertEqual(payload["accuracy"], 500)
        self.assertEqual(payload["locationDurationMs"], 0)
        self.assertEqual(payload["networkTypeCode"], "unknown")
        self.assertEqual(payload["locationEnabled"], False)
        self.assertEqual(build_payload(fixed_account(request_metadata={"accuracy": 0}), fixtures.INSTANT)["accuracy"], 0)

    def test_invalid_metadata_cannot_override_coordinates_or_generated_time(self):
        for metadata in ({"latitude": 1}, {"clientTime": "old"}, {"accuracy": float("inf")},
                         {"locationDurationMs": -1}, {"locationEnabled": "false"}, {"errorMessage": "failed"}):
            with self.subTest(metadata=metadata), self.assertRaises(ToolError):
                build_payload(fixed_account(request_metadata=metadata), fixtures.INSTANT)

    def test_legacy_payload_remains_supported_and_ambiguity_is_explicit(self):
        self.assertEqual(location_source(fixtures.ACCOUNT), "fixed_legacy_payload")
        payload = build_payload(fixtures.ACCOUNT, fixtures.INSTANT)
        self.assertEqual(payload["accuracy"], fixtures.ACCOUNT["checkin_payload"]["accuracy"])
        mixed = fixed_account()
        mixed["checkin_payload"] = copy.deepcopy(fixtures.ACCOUNT["checkin_payload"])
        with self.assertRaises(ToolError) as caught:
            validate_config({"version": 1, "accounts": [mixed]})
        self.assertEqual(caught.exception.reason, "ambiguous_location_configuration")

    def test_auth_configuration_allows_coordinates_to_be_filled_later(self):
        account = fixed_account(latitude=None, longitude=None)
        validate_config({"version": 1, "accounts": [account]})
        self.assertFalse(location_configured(account))


class RecordingTransport(fixtures.FakeTransport):
    def __init__(self):
        super().__init__()
        self.last_payload, self.reverse_queries = None, []
        self.address_data = "Address returned for configured coordinates"
        self.reverse_failure = False
        self.requests = []

    def request(self, method, url, **kwargs):
        self.requests.append((method, url))
        if kwargs["stage"] == "reverse_geocode":
            self.calls.append((method, kwargs["stage"]))
            self.reverse_queries.append(urllib.parse.parse_qs(urllib.parse.urlsplit(url).query))
            if self.reverse_failure:
                raise ToolError("business_error", "reverse_geocode", 4001)
            return fixtures.response(url, {"code": 0, "ok": True, "data": self.address_data})
        if kwargs["stage"] == "checkin_post":
            self.last_payload = copy.deepcopy(kwargs["payload"])
        return super().request(method, url, **kwargs)


class FixedFlows(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="moonuestc-fixed-", dir=os.environ.get("MOON_TEST_TMP"))
        self.directory = Path(self.temp.name)
        self.state = State(self.directory)
        self.transport = RecordingTransport()

    def tearDown(self):
        self.state.close()
        self.temp.cleanup()

    def run_mode(self, mode="checkin", account=None):
        return run_account(account or fixed_account(), mode, self.state, self.directory,
                           clock=lambda: fixtures.INSTANT, sleep=lambda _: None,
                           transport_factory=lambda *args: self.transport)

    def test_diagnose_without_coordinates_only_checks_auth(self):
        out = self.run_mode("diagnose", fixed_account(latitude=None, longitude=None))
        self.assertEqual(out["result"], "auth_ready")
        self.assertEqual(out["locationSource"], "fixed")
        self.assertFalse(out["locationConfigured"])
        self.assertFalse(out["payloadConfigured"])
        self.assertEqual(self.transport.reverse_queries, [])
        self.assertEqual(self.transport.post_count, 0)

    def test_supplied_address_is_sent_without_lookup(self):
        account = fixed_account()
        self.assertEqual(self.run_mode(account=account)["result"], "confirmed")
        self.assertEqual(self.transport.last_payload["latitude"], account["location"]["latitude"])
        self.assertEqual(self.transport.last_payload["longitude"], account["location"]["longitude"])
        self.assertEqual(self.transport.last_payload["reverseGeocode"], "Configured test address")
        self.assertEqual(self.transport.reverse_queries, [])
        self.assertTrue(all(urllib.parse.urlsplit(url).hostname in {"idas.uestc.edu.cn", "jzsz.uestc.edu.cn"}
                            for _, url in self.transport.requests))

    def test_empty_address_is_derived_from_supplied_coordinates_exactly_once(self):
        account = fixed_account(reverse_geocode="")
        self.assertEqual(self.run_mode(account=account)["result"], "confirmed")
        self.assertEqual(self.transport.last_payload["reverseGeocode"], self.transport.address_data)
        self.assertEqual(self.transport.reverse_queries,
                         [{"lat": [str(account["location"]["latitude"])], "lng": [str(account["location"]["longitude"])]}])

    def test_address_lookup_accepts_documented_object_shapes(self):
        school = School(self.transport, fixed_account(), lambda: None)
        for key in ("address", "reverseGeocode", "formattedAddress"):
            self.transport.address_data = {key: "Synthetic address"}
            self.assertEqual(school.reverse_geocode(0, 0), "Synthetic address")
    def test_short_empty_school_response_recovers_within_the_same_manual_operation(self):
        original=self.transport.request;responses=iter([None,'Synthetic recovered address'])
        def intermittent(method,url,**kwargs):
            if kwargs['stage']=='reverse_geocode':self.transport.address_data=next(responses)
            return original(method,url,**kwargs)
        self.transport.request=intermittent
        out=self.run_mode(account=fixed_account(reverse_geocode=''))
        self.assertEqual(out['result'],'confirmed');self.assertEqual(self.transport.post_count,1)
        self.assertEqual(len(self.transport.reverse_queries),2)
    def test_previously_resolved_same_place_survives_a_later_school_map_outage(self):
        account=fixed_account(reverse_geocode='')
        self.assertEqual(self.run_mode('prepare',account)['result'],'dry_run_ready')
        self.transport.address_data=None
        out=self.run_mode('checkin',account)
        self.assertEqual(out['result'],'confirmed');self.assertEqual(self.transport.post_count,1)
        self.assertEqual(self.transport.last_payload['reverseGeocode'],'Address returned for configured coordinates')

    def test_address_lookup_failure_never_submits_or_claims(self):
        self.transport.reverse_failure = True
        with self.assertRaises(ToolError):
            self.run_mode(account=fixed_account(reverse_geocode=""))
        self.assertEqual(self.transport.post_count, 0)
        self.assertFalse(self.state.claimed(account_key(fixed_account()), fixtures.DAY))

    def test_invalid_address_response_never_submits_or_claims(self):
        self.transport.address_data = {"unexpected": "not an address"}
        with self.assertRaises(ToolError) as caught:
            self.run_mode(account=fixed_account(reverse_geocode=""))
        self.assertEqual(caught.exception.reason, "reverse_geocode_unavailable")
        self.assertEqual(self.transport.post_count, 0)
        self.assertFalse(self.state.claimed(account_key(fixed_account()), fixtures.DAY))

    def test_prepare_reports_fixed_source_without_a_checkin_post(self):
        out = self.run_mode("prepare", fixed_account(reverse_geocode=""))
        self.assertEqual(out["result"], "dry_run_ready")
        self.assertEqual(out["locationSource"], "fixed")
        self.assertEqual(self.transport.post_count, 0)

    def test_out_of_fence_coordinates_are_not_changed_to_the_center(self):
        with self.assertRaises(ToolError) as caught:
            self.run_mode(account=fixed_account(latitude=1))
        self.assertEqual(caught.exception.reason, "outside_allowed_location")
        self.assertEqual(self.transport.post_count, 0)
        self.assertEqual(self.transport.reverse_queries, [])

    def test_ten_accounts_submit_their_own_configured_coordinates(self):
        for i in range(10):
            account = fixed_account(latitude=0.00001 * i, longitude=-0.00001 * i)
            account.update(id=f"fixed{i}", student_id=f"2024000000{i:02d}")
            self.transport = RecordingTransport()
            self.assertEqual(self.run_mode(account=account)["result"], "confirmed")
            self.assertEqual(self.transport.last_payload["latitude"], account["location"]["latitude"])
            self.assertEqual(self.transport.last_payload["longitude"], account["location"]["longitude"])
            self.assertEqual(self.transport.post_count, 1)


if __name__ == "__main__":
    unittest.main()
