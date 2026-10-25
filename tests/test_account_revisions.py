"""Two editors must not silently overwrite a newer configuration."""
import copy
import json
import unittest

import test_portal as fixtures
from moonuestc.web_errors import WebError


class AccountRevisions(unittest.TestCase):
    setUp=fixtures.PortalCase.setUp
    tearDown=fixtures.PortalCase.tearDown
    login=fixtures.PortalCase.login
    request=fixtures.PortalCase.request

    def prepare(self):
        response=self.login();self.assertEqual(response.status_code,200)
        self.csrf=response.json['csrf_token']
        self.account=self.request('/api/portal/me').json['account']
        self.path='/api/accounts/'+self.account['id']
        return self.account['configuration_revision']

    def save(self,**values):return self.request(self.path,'PATCH',values,self.csrf)

    def test_stale_editor_cannot_overwrite_newer_plan_or_reservation(self):
        original=self.prepare()
        first=self.save(if_match=original,run_at='22:07')
        self.assertEqual(first.status_code,200,first.json)
        self.assertNotEqual(first.json['account']['configuration_revision'],original)
        with self.store.db() as db:before=[tuple(row) for row in db.execute('SELECT * FROM web_schedule_slots')]
        stale=self.save(if_match=original,run_at='22:09',enabled=False)
        self.assertEqual(stale.status_code,409,stale.json)
        self.assertEqual(stale.json['error']['code'],'configuration_changed')
        current=self.request(self.path).json['account']
        self.assertEqual(current['run_at'],'22:07');self.assertTrue(current['enabled'])
        with self.store.db() as db:self.assertEqual([tuple(row) for row in db.execute('SELECT * FROM web_schedule_slots')],before)

    def test_latest_version_can_save_and_legacy_clients_keep_partial_updates(self):
        original=self.prepare()
        legacy=self.save(run_at='22:07');self.assertEqual(legacy.status_code,200,legacy.json)
        self.assertEqual(self.save(if_match=original,run_at='22:09').status_code,409)
        latest=legacy.json['account']['configuration_revision']
        result=self.save(if_match=latest,run_at='22:11')
        self.assertEqual(result.status_code,200,result.json);self.assertEqual(result.json['account']['run_at'],'22:11')

    def test_grant_rotation_and_job_results_do_not_conflict_with_plan_editing(self):
        original=self.prepare()
        with self.store.db(True) as db:
            row=db.execute('SELECT * FROM web_accounts WHERE id=?',(self.account['id'],)).fetchone()
            payload=copy.deepcopy(self.store._payload(row))
            payload['wechat_authorization']={'id':'a'*32,'credentials':{'accesstoken':'synthetic-rotated-access'}}
            db.execute('UPDATE web_accounts SET payload=?,last_result=? WHERE id=?',
                (self.store.vault.seal(payload,'account:'+row['id']),json.dumps({'result':'dry_run_ready'}),row['id']))
        self.assertEqual(self.request(self.path).json['account']['configuration_revision'],original)
        response=self.save(if_match=original,run_at='22:07');self.assertEqual(response.status_code,200,response.json)
        with self.store.db() as db:
            row=db.execute('SELECT * FROM web_accounts WHERE id=?',(self.account['id'],)).fetchone()
            self.assertEqual(self.store._payload(row)['wechat_authorization']['credentials']['accesstoken'],'synthetic-rotated-access')

    def test_revision_is_opaque_and_malformed_values_are_rejected(self):
        revision=self.prepare();self.assertRegex(revision,'^[a-f0-9]{64}$')
        for value in ('',None,123,'g'*64):
            response=self.save(if_match=value,run_at='22:07')
            self.assertEqual(response.status_code,400,response.json)
            self.assertEqual(response.json['error']['code'],'invalid_configuration_revision')
        self.assertEqual(self.request(self.path).json['account']['run_at'],'22:00')

    def test_admin_editor_must_also_match_the_current_configuration(self):
        original=self.prepare()
        self.assertEqual(self.save(run_at='22:07').status_code,200)
        with self.assertRaises(WebError) as raised:
            self.store.save_account(self.admin,{'if_match':original,'run_at':'22:09'},self.account['id'])
        self.assertEqual(raised.exception.code,'configuration_changed')
        self.assertEqual(self.request(self.path).json['account']['run_at'],'22:07')

    def test_knowing_a_revision_does_not_grant_another_account_access(self):
        original=self.prepare()
        other=self.login(student='202600000002');self.assertEqual(other.status_code,200)
        result=self.request(self.path,'PATCH',{'if_match':original,'run_at':'22:07'},other.json['csrf_token'])
        self.assertEqual(result.status_code,404)
