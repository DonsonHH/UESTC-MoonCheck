"""Named presets and coordinate conversions tested without school access."""
import contextlib
import copy
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import test_workflows as fixtures
from test_fixed_locations import RecordingTransport, fixed_account
from moonuestc.__main__ import main
from moonuestc.coordinates import normalize_coordinate_system, to_gcj02
from moonuestc.errors import ToolError
from moonuestc.locations import DEFAULT_PRESET_ID, get_preset, list_presets, location_details, resolve_location
from moonuestc.policy import build_payload, location_configured, location_source, validate_config
from moonuestc.runner import run_account
from moonuestc.state import State

EXPECTED_LAT = 30.75470828983461
EXPECTED_LNG = 103.93284383329953


def preset_account(**values):
    account = copy.deepcopy(fixtures.ACCOUNT)
    account.pop("checkin_payload")
    account["location"] = {"mode": "preset", "preset": DEFAULT_PRESET_ID, **values}
    return account


class Coordinates(unittest.TestCase):
    def test_python_matches_independent_javascript_reference_vectors(self):
        vectors = json.loads(Path(__file__).with_name("coordinate-reference.json").read_text(encoding="utf-8"))
        for vector in vectors["samples"]:
            source, expected = vector["wgs84"], vector["gcj02_approx"]
            with self.subTest(source=source):
                lat, lng, _ = to_gcj02(source["latitude"], source["longitude"], "wgs84")
                self.assertAlmostEqual(lat, expected["latitude"], places=10)
                self.assertAlmostEqual(lng, expected["longitude"], places=10)

    def test_gcj02_is_not_converted_again(self):
        lat, lng, method = to_gcj02(EXPECTED_LAT, EXPECTED_LNG, "gcj02")
        self.assertEqual((lat, lng), (EXPECTED_LAT, EXPECTED_LNG))
        self.assertEqual(method, "none")

    def test_explicit_standard_name_aliases(self):
        for value, expected in (("WGS-84", "wgs84"), (" wgs84 ", "wgs84"), ("GCJ-02", "gcj02"), ("gcj_02", "gcj02")):
            self.assertEqual(normalize_coordinate_system(value), expected)
        for value in ("bd09", "auto", None, 1):
            with self.assertRaises(ToolError):
                normalize_coordinate_system(value)

    def test_invalid_axes_non_finite_values_and_strings_are_rejected(self):
        for lat, lng in ((91,103), (30,181), (True,103), (30,"103.9"), (float("nan"),103), (30,float("inf"))):
            with self.subTest(lat=lat,lng=lng), self.assertRaises(ToolError):
                to_gcj02(lat,lng,"wgs84")

    def test_outside_reference_transform_rectangle_is_explicit(self):
        self.assertEqual(to_gcj02(40.7128,-74.006,"wgs84"), (40.7128,-74.006,"outside_transform_area_identity"))
        account = fixed_account(latitude=40.7128,longitude=-74.006,coordinate_system="wgs84")
        self.assertEqual(location_details(account)["coordinateConversion"], "outside_transform_area_identity")


class NamedLocations(unittest.TestCase):
    def test_all_eight_amap_presets_match_user_coordinates_without_conversion(self):
        points=[(103.932037,30.754670),(103.932328,30.753780),(103.933849,30.754874),
                (103.934154,30.753768),(103.935437,30.753607),(103.931652,30.755699),
                (103.932501,30.756534),(103.932875,30.755637)]
        presets=list_presets()
        self.assertEqual(len(presets),8)
        self.assertEqual(DEFAULT_PRESET_ID,'xuezhi_group3_amap')
        for i,(preset,(lng,lat)) in enumerate(zip(presets,points),1):
            with self.subTest(group=i):
                self.assertEqual(preset['id'],f'xuezhi_group{i}_amap')
                self.assertEqual(preset['source'],{'latitude':lat,'longitude':lng,'coordinateSystem':'gcj02'})
                self.assertEqual(preset['submittedCoordinates'],preset['source'])
                self.assertEqual(preset['coordinateConversion'],'none')
                self.assertEqual(preset['address'],'')
                payload=build_payload(preset_account(preset=preset['id']),fixtures.INSTANT)
                self.assertEqual((payload['longitude'],payload['latitude']),(lng,lat))

    def test_old_group_three_id_and_name_use_the_new_amap_point(self):
        for value in ('xuezhi_group3','学知三组团'):
            key,preset=get_preset(value)
            self.assertEqual(key,DEFAULT_PRESET_ID)
            self.assertEqual(preset['name'],'学知三组团')
            self.assertEqual(preset['latitude'],30.754874)
            self.assertEqual(preset['longitude'],103.933849)
            self.assertEqual(preset['coordinate_system'],'gcj02')
            self.assertEqual(preset['reverse_geocode'],'')
        self.assertEqual(len(list_presets()),8)

    def test_chinese_display_name_can_select_the_new_preset(self):
        payload = build_payload(preset_account(preset="学知三组团"), fixtures.INSTANT)
        self.assertEqual(payload["latitude"],30.754874)
        self.assertEqual(payload["longitude"],103.933849)

    def test_resolution_cannot_mutate_global_defaults(self):
        first = resolve_location(preset_account())
        first["latitude"] = 0
        first["request_metadata"]["accuracy"] = 999
        second = resolve_location(preset_account())
        self.assertEqual(second["latitude"], 30.754874)
        self.assertNotIn("accuracy",second["request_metadata"])

    def test_unknown_preset_never_falls_back(self):
        with self.assertRaises(ToolError) as caught:
            build_payload(preset_account(preset="unknown"), fixtures.INSTANT)
        self.assertEqual(caught.exception.reason,"unknown_location_preset")

    def test_reference_cannot_silently_mix_with_manual_coordinates(self):
        with self.assertRaises(ToolError):
            build_payload(preset_account(latitude=0), fixtures.INSTANT)
        account = preset_account()
        account["checkin_payload"] = copy.deepcopy(fixtures.ACCOUNT["checkin_payload"])
        with self.assertRaises(ToolError):
            validate_config({"version":1,"accounts":[account]})

    def test_custom_name_is_local_metadata_and_not_an_extra_wire_field(self):
        account = fixed_account(name="实验室A-301")
        self.assertEqual(location_details(account)["locationName"], "实验室A-301")
        payload = build_payload(account,fixtures.INSTANT)
        self.assertNotIn("name",payload)
        self.assertNotIn("locationName",payload)

    def test_invalid_custom_name_is_rejected(self):
        for name in ("", " ", 42, "x"*81):
            with self.subTest(name=name), self.assertRaises(ToolError):
                validate_config({"version":1,"accounts":[fixed_account(name=name)]})

    def test_custom_wgs84_coordinates_are_converted_and_raw_config_unchanged(self):
        account = fixed_account(name="新位置", latitude=30.757413, longitude=103.930739, coordinate_system="WGS-84")
        before = copy.deepcopy(account)
        first = build_payload(account,fixtures.INSTANT)
        second = build_payload(account,fixtures.INSTANT)
        self.assertAlmostEqual(first["latitude"],EXPECTED_LAT,places=10)
        self.assertAlmostEqual(first["longitude"],EXPECTED_LNG,places=10)
        self.assertEqual(first,second)
        self.assertEqual(account,before)
        self.assertEqual(first["coordinateSystemCode"],"gcj02")

    def test_preset_address_and_metadata_can_be_overridden(self):
        account = preset_account(reverse_geocode="手填地址",request_metadata={"accuracy":55})
        payload = build_payload(account,fixtures.INSTANT)
        self.assertEqual(payload["reverseGeocode"],"手填地址")
        self.assertEqual(payload["accuracy"],55)
        self.assertNotIn("request_metadata",get_preset(DEFAULT_PRESET_ID)[1])

    def test_legacy_gcj_payload_is_still_used_verbatim(self):
        payload = build_payload(fixtures.ACCOUNT,fixtures.INSTANT)
        self.assertEqual(payload["latitude"],fixtures.ACCOUNT["checkin_payload"]["latitude"])
        self.assertEqual(payload["longitude"],fixtures.ACCOUNT["checkin_payload"]["longitude"])
        self.assertEqual(location_source(fixtures.ACCOUNT),"fixed_legacy_payload")


class PresetTransport(RecordingTransport):
    def request(self,method,url,**kwargs):
        if kwargs["stage"] == "locations":
            self.requests.append((method,url))
            self.calls.append((method,"locations"))
            return fixtures.response(url,{"code":0,"ok":True,"data":[
                {"latitude":30.754980,"longitude":103.933883,"radiusMeter":130}]})
        return super().request(method,url,**kwargs)


class PresetFlows(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix="moonuestc-preset-",dir=os.environ.get("MOON_TEST_TMP"))
        self.directory=Path(self.temp.name)
        self.state=State(self.directory)
        self.transport=PresetTransport()

    def tearDown(self):
        self.state.close()
        self.temp.cleanup()

    def run_mode(self,mode="checkin",account=None):
        return run_account(account or preset_account(),mode,self.state,self.directory,
                           clock=lambda:fixtures.INSTANT,sleep=lambda _:None,
                           transport_factory=lambda *args:self.transport)

    def test_preset_sends_amap_coordinates_and_resolves_address_for_them(self):
        out=self.run_mode()
        self.assertEqual(out["result"],"confirmed")
        payload=self.transport.last_payload
        self.assertEqual(payload["latitude"],30.754874)
        self.assertEqual(payload["longitude"],103.933849)
        self.assertEqual(payload["coordinateSystemCode"],"gcj02")
        self.assertEqual(payload["accuracy"],86)
        self.assertEqual(self.transport.reverse_queries,[{"lat":["30.754874"],"lng":["103.933849"]}])
        self.assertEqual(payload["reverseGeocode"],self.transport.address_data)
        self.assertNotIn("preset",payload)
        self.assertEqual(self.transport.post_count,1)

    def test_prepare_displays_name_and_no_conversion_without_post(self):
        out=self.run_mode("prepare")
        self.assertEqual(out["result"],"dry_run_ready")
        self.assertEqual(out["locationSource"],"preset")
        self.assertEqual(out["locationName"],"学知三组团")
        self.assertEqual(out["coordinateConversion"],"none")
        self.assertEqual(self.transport.post_count,0)

    def test_diagnose_names_the_selected_preset(self):
        out=self.run_mode("diagnose")
        self.assertEqual(out["result"],"auth_ready")
        self.assertTrue(out["locationConfigured"])
        self.assertEqual(out["presetId"],DEFAULT_PRESET_ID)
        self.assertEqual(out["inputCoordinateSystem"],"gcj02")
        self.assertEqual(out["outputCoordinateSystem"],"gcj02")

    def test_custom_named_location_remains_available_next_to_preset(self):
        first=copy.deepcopy(preset_account())
        first["student_id"]="202500000001"
        self.assertEqual(self.run_mode(account=first)["result"],"confirmed")
        second=fixed_account(name="自定义宿舍",latitude=EXPECTED_LAT,longitude=EXPECTED_LNG)
        second["student_id"]="202500000002"
        self.transport=PresetTransport()
        out=self.run_mode("prepare",second)
        self.assertEqual(out["locationName"],"自定义宿舍")
        self.assertEqual(out["coordinateConversion"],"none")

    def test_locations_command_does_not_read_credentials_or_contact_school(self):
        with patch("moonuestc.__main__.load_config",side_effect=AssertionError("must not read credentials")),contextlib.redirect_stdout(io.StringIO()) as stream:
            self.assertEqual(main(["locations","--config","missing-config.json"]),0)
        out=json.loads(stream.getvalue())
        self.assertEqual(out["schoolRequests"],0)
        self.assertEqual(len(out["locations"]),8)
        self.assertEqual(out["locations"][0]["name"],"学知一组团")
        self.assertEqual(out["locations"][0]["source"]["longitude"],103.932037)


if __name__ == "__main__":
    unittest.main()
