"""Upgrade fixtures containing old encrypted account locations, without school access."""
import copy
from unittest.mock import patch
from dashboard_helpers import WebCase,FAST_HASHER
from moonuestc.locations import DEFAULT_PRESET_ID,OLD_GROUP3_ADDRESS,upgrade_group3_location
from moonuestc.policy import build_payload
from moonuestc.runner import account_key,cookie_path
from moonuestc.web_store import WebStore
from moonuestc.errors import ToolError
import test_workflows as fixtures


class GroupThreeUpgrade(WebCase):
    def legacy_row(self,account,location):
        with self.store.db(True) as db:
            row=db.execute('SELECT * FROM web_accounts WHERE id=?',(account['id'],)).fetchone()
            payload=self.store._payload(row);payload['location']=copy.deepcopy(location)
            db.execute('UPDATE web_accounts SET payload=?,automatic=1,enabled=1,run_at=? WHERE id=?',
                       (self.store.vault.seal(payload,'account:'+account['id']),'22:13',account['id']))
            db.execute("DELETE FROM web_migrations WHERE name='group3_gcj02_v050'")
        return payload

    def test_upgrade_preserves_users_credentials_cookies_schedules_ids_and_state_key(self):
        account=self.add_account()
        old=self.legacy_row(account,{'mode':'preset','preset':'xuezhi_group3','reverse_geocode':OLD_GROUP3_ADDRESS,'request_metadata':{'accuracy':40}})
        self.store.cookie_save('synthetic-binding',[{'name':'fake','value':'test'}])
        with self.store.db() as db:
            before=dict(db.execute('SELECT * FROM web_accounts WHERE id=?',(account['id'],)).fetchone())
            users=[tuple(x) for x in db.execute('SELECT * FROM web_users ORDER BY id')]
            cookies=[tuple(x) for x in db.execute('SELECT * FROM web_cookies')]
            sessions=[tuple(x) for x in db.execute('SELECT * FROM web_sessions ORDER BY token_hash')]
        with patch('moonuestc.transport.Transport.request',side_effect=AssertionError('migration must stay offline')):
            upgraded=WebStore(self.root,FAST_HASHER)
        with upgraded.db() as db:
            after=dict(db.execute('SELECT * FROM web_accounts WHERE id=?',(account['id'],)).fetchone())
            self.assertEqual(users,[tuple(x) for x in db.execute('SELECT * FROM web_users ORDER BY id')])
            self.assertEqual(cookies,[tuple(x) for x in db.execute('SELECT * FROM web_cookies')])
            self.assertEqual(sessions,[tuple(x) for x in db.execute('SELECT * FROM web_sessions ORDER BY token_hash')])
        for key in before:
            if key!='payload':self.assertEqual(after[key],before[key],key)
        payload=upgraded._payload(after)
        self.assertEqual({k:v for k,v in payload.items() if k!='location'},{k:v for k,v in old.items() if k!='location'})
        self.assertEqual(payload['location'],{'mode':'preset','preset':DEFAULT_PRESET_ID,'request_metadata':{'accuracy':40}})
        self.assertEqual(account_key(payload),account_key(old))
        self.assertEqual(cookie_path(self.root,payload),cookie_path(self.root,old))
        submitted=build_payload(payload,fixtures.INSTANT)
        self.assertEqual((submitted['longitude'],submitted['latitude']),(103.933849,30.754874))
        self.assertEqual(submitted['reverseGeocode'],'')
        self.assertEqual(self.calls,[])

    def test_migration_is_idempotent_and_audited_once(self):
        account=self.add_account();self.legacy_row(account,{'mode':'preset','preset':'学知三组团'})
        first=WebStore(self.root,FAST_HASHER)
        with first.db() as db:before=bytes(db.execute('SELECT payload FROM web_accounts').fetchone()[0])
        second=WebStore(self.root,FAST_HASHER)
        with second.db() as db:
            self.assertEqual(before,bytes(db.execute('SELECT payload FROM web_accounts').fetchone()[0]))
            self.assertEqual(db.execute("SELECT count(*) FROM web_audit WHERE event='account_location_migrated'").fetchone()[0],1)
            self.assertEqual(db.execute("SELECT count(*) FROM web_migrations WHERE name='group3_gcj02_v050'").fetchone()[0],1)

    def test_named_group_three_manual_location_updates_but_other_locations_do_not(self):
        old={'mode':'fixed','name':'学知三组团','longitude':103.930739,'latitude':30.757413,'coordinate_system':'wgs84','reverse_geocode':OLD_GROUP3_ADDRESS}
        result=upgrade_group3_location(old,migrate_named=True)
        self.assertEqual((result['longitude'],result['latitude'],result['coordinate_system']),(103.933849,30.754874,'gcj02'))
        self.assertNotIn('reverse_geocode',result)
        self.assertEqual(old['longitude'],103.930739)
        other={**old,'name':'自定义位置'}
        self.assertEqual(upgrade_group3_location(other,migrate_named=True),other)
        custom_address={**old,'reverse_geocode':'用户自填地址'}
        self.assertEqual(upgrade_group3_location(custom_address,migrate_named=True)['reverse_geocode'],'用户自填地址')

    def test_corrupt_second_payload_rolls_back_all_location_updates(self):
        first=self.add_account(student='202300000001');second=self.add_account(owner=2,student='202300000002')
        self.legacy_row(first,{'mode':'preset','preset':'xuezhi_group3'})
        self.legacy_row(second,{'mode':'preset','preset':'xuezhi_group3'})
        with self.store.db(True) as db:
            db.execute('UPDATE web_accounts SET payload=? WHERE id=?',(b'corrupt',second['id']))
            before=[tuple(x) for x in db.execute('SELECT id,payload FROM web_accounts ORDER BY rowid')]
        with self.assertRaises(ToolError):WebStore(self.root,FAST_HASHER)
        with self.store.db() as db:
            self.assertEqual(before,[tuple(x) for x in db.execute('SELECT id,payload FROM web_accounts ORDER BY rowid')])
            self.assertEqual(db.execute('SELECT count(*) FROM web_migrations WHERE name=?',('group3_gcj02_v050',)).fetchone()[0],0)
            self.assertEqual(db.execute("SELECT count(*) FROM web_audit WHERE event='account_location_migrated'").fetchone()[0],0)

    def test_new_manual_location_keeps_explicit_coordinates_even_with_group_three_name(self):
        raw={'mode':'fixed','name':'学知三组团','longitude':103.935,'latitude':30.755,'coordinate_system':'gcj02'}
        self.assertEqual(upgrade_group3_location(raw),raw)
        account=self.add_account(location=raw)
        self.assertEqual(account['location'],raw)
