"""Real address-resolver boundaries; all school responses and places synthetic."""
import datetime as dt
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from moonuestc.errors import AuthRequired,ToolError
from moonuestc.geocoding import AddressCache,resolve_address,scope_for
from moonuestc.policy import build_payload
from test_fixed_locations import fixed_account
from test_workflows import INSTANT


class School:
    def __init__(self,responses):self.responses=iter(responses);self.calls=[];self.transport=SimpleNamespace(timeout=25)
    def reverse_geocode(self,latitude,longitude):
        self.calls.append((latitude,longitude,self.transport.timeout));value=next(self.responses)
        if isinstance(value,Exception):raise value
        if value is None:raise ToolError('reverse_geocode_unavailable','reverse_geocode')
        return value


class AddressResilience(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.directory=Path(self.temp.name);self.account=fixed_account(reverse_geocode='')
        self.instant=INSTANT;self.point=build_payload(self.account,self.instant);self.events=[]
    def tearDown(self):self.temp.cleanup()
    def resolve(self,school):
        return resolve_address(school,self.account,self.point,self.directory,clock=lambda:self.instant,sleep=lambda _:None,
            emit=lambda event,**values:self.events.append((event,values)))
    def seed(self,instant=INSTANT):
        cache=AddressCache(self.directory)
        cache.save(scope_for(self.account,instant),(self.point['latitude'],self.point['longitude']),'Synthetic cached school address',instant.timestamp())
    def test_cache_survives_restart_and_keeps_address_encrypted(self):
        self.assertEqual(self.resolve(School(['Synthetic cached school address'])),'Synthetic cached school address')
        offline=School([])
        self.assertEqual(self.resolve(offline),'Synthetic cached school address');self.assertEqual(offline.calls,[])
        self.assertNotIn(b'Synthetic cached school address',(self.directory/'geocode.sqlite3').read_bytes())
        self.assertEqual(self.events[-1],('geocode',{'source':'cache','attempts':0}))
    def test_same_place_nearby_daily_variation_uses_cache_without_changing_coordinates(self):
        self.seed();self.point={**self.point,'latitude':self.point['latitude']+0.00008};before=dict(self.point)
        school=School([]);self.resolve(school)
        self.assertEqual(school.calls,[]);self.assertEqual(self.point,before)
    def test_a_different_configured_place_never_inherits_cached_address(self):
        self.seed();self.account=fixed_account(latitude=0.001,reverse_geocode='');self.point=build_payload(self.account,self.instant)
        school=School([None,None])
        with self.assertRaises(ToolError):self.resolve(school)
        self.assertEqual(len(school.calls),2)
    def test_distant_point_cannot_reuse_same_scope_cache(self):
        self.seed();self.point={**self.point,'longitude':self.point['longitude']+0.001}
        school=School([None,None])
        with self.assertRaises(ToolError):self.resolve(school)
        self.assertEqual(len(school.calls),2)
    def test_freshness_expiry_refreshes_once_then_uses_recent_school_address_on_outage(self):
        self.seed();self.instant+=dt.timedelta(days=2);school=School([None])
        self.assertEqual(self.resolve(school),'Synthetic cached school address');self.assertEqual(len(school.calls),1)
        self.assertEqual(self.events[-1],('geocode',{'source':'cached_after_failure','attempts':1}))
    def test_old_cache_is_not_used_beyond_seven_days(self):
        self.seed();self.instant+=dt.timedelta(days=8);school=School([None,None])
        with self.assertRaises(ToolError):self.resolve(school)
        self.assertEqual(len(school.calls),2)
    def test_authentication_rejection_is_never_hidden_by_stale_cache(self):
        self.seed();self.instant+=dt.timedelta(days=2);school=School([AuthRequired('session_rejected','reverse_geocode')])
        with self.assertRaises(AuthRequired):self.resolve(school)
        self.assertEqual(len(school.calls),1)
    def test_business_rejection_is_not_retried_or_treated_as_address(self):
        self.seed();self.instant+=dt.timedelta(days=2);school=School([ToolError('business_error','reverse_geocode',4001)])
        with self.assertRaises(ToolError) as caught:self.resolve(school)
        self.assertEqual(caught.exception.reason,'business_error');self.assertEqual(len(school.calls),1)
    def test_network_timeout_recovers_with_short_get_timeout_and_restores_transport(self):
        school=School([ToolError('timeout','reverse_geocode'),'Synthetic recovered address'])
        self.assertEqual(self.resolve(school),'Synthetic recovered address')
        self.assertEqual([r[2] for r in school.calls],[5,5]);self.assertEqual(school.transport.timeout,25)
    def test_short_retry_cannot_run_after_reserved_deadline(self):
        self.account['_job_deadline']=self.instant.timestamp()+0.3;school=School([None])
        def advance(seconds):self.instant+=dt.timedelta(seconds=seconds)
        with self.assertRaises(ToolError) as caught:
            resolve_address(school,self.account,self.point,self.directory,clock=lambda:self.instant,sleep=advance)
        self.assertEqual(caught.exception.reason,'reserved_slot_expired');self.assertEqual(len(school.calls),1)
    def test_invalid_address_does_not_poison_the_cache(self):
        school=School(['<html>error</html>',None])
        with self.assertRaises(ToolError):self.resolve(school)
        offline=School([None,None])
        with self.assertRaises(ToolError):self.resolve(offline)
        self.assertEqual(len(offline.calls),2)
