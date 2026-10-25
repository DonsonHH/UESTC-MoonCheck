import copy
import http.cookiejar
import json
import time
from pathlib import Path
from unittest.mock import patch

from dashboard_helpers import WebCase,ORIGIN
import test_workflows as fixtures
from moonuestc.errors import ToolError
from moonuestc.policy import now
from moonuestc.runner import account_key,cookie_path
from moonuestc.state import State
from moonuestc.vault import EncryptedTransport
from moonuestc.web_errors import WebError
from moonuestc.web_store import WebStore


class DashboardAccounts(WebCase):
    def test_ordinary_user_only_sees_own_accounts_admin_sees_all(self):
        a=self.add_account(1,'202300000001')
        b=self.add_account(2,'202300000002')
        self.assertEqual([x['id'] for x in self.req(self.c1,self.t1,'/api/accounts').get_json()['accounts']],[a['id']])
        self.assertEqual([x['id'] for x in self.req(self.c2,self.t2,'/api/accounts').get_json()['accounts']],[b['id']])
        self.assertEqual(len(self.req(self.ac,self.at,'/api/accounts').get_json()['accounts']),2)

    def test_foreign_account_read_update_delete_and_execution_are_forbidden(self):
        account=self.add_account(1)
        root='/api/accounts/'+account['id']
        for method,path,data in [('GET',root,None),('PATCH',root,{'label':'stolen'}),('DELETE',root,None),('POST',root+'/jobs',{'mode':'diagnose'})]:
            response=self.req(self.c2,self.t2,path,method,data)
            self.assertEqual(response.status_code,404,(method,response.get_json()))
        self.assertEqual(self.calls,[])

    def test_owner_id_cannot_be_forged_by_regular_user(self):
        response=self.req(self.c1,self.t1,'/api/accounts','POST',self.account_fields(owner_id=self.u2['id']))
        self.assertEqual(response.status_code,403)
        account=self.add_account(1)
        response=self.req(self.c1,self.t1,'/api/accounts/'+account['id'],'PATCH',{'owner_id':self.u2['id']})
        self.assertEqual(response.status_code,403)

    def test_admin_assigns_and_transfers_account_ownership(self):
        response=self.req(self.ac,self.at,'/api/accounts','POST',self.account_fields(owner_id=self.u2['id']))
        self.assertEqual(response.status_code,201,response.get_json())
        aid=response.get_json()['account']['id']
        self.assertEqual(self.req(self.c2,self.t2,'/api/accounts/'+aid).status_code,200)
        moved=self.req(self.ac,self.at,'/api/accounts/'+aid,'PATCH',{'owner_id':self.u1['id']})
        self.assertEqual(moved.status_code,200)
        self.assertEqual(self.req(self.c2,self.t2,'/api/accounts/'+aid).status_code,404)
        self.assertEqual(self.req(self.c1,self.t1,'/api/accounts/'+aid).status_code,200)

    def test_api_never_returns_saved_school_password_or_fingerprint(self):
        account=self.add_account(1)
        for client,token in ((self.c1,self.t1),(self.ac,self.at)):
            response=self.req(client,token,'/api/accounts')
            raw=response.get_data(as_text=True)
            self.assertNotIn(fixtures.ACCOUNT['password'],raw)
            self.assertNotIn(fixtures.ACCOUNT['browser_fingerprint'],raw)
            self.assertTrue(response.get_json()['accounts'][0]['has_password'])
        payload=self.store.job_payload({'account_id':account['id']})
        self.assertEqual(payload['password'],fixtures.ACCOUNT['password'])

    def test_blank_secret_fields_preserve_original_values(self):
        account=self.add_account(1)
        response=self.req(self.c1,self.t1,'/api/accounts/'+account['id'],'PATCH',{'label':'重命名','password':'','browser_fingerprint':''})
        self.assertEqual(response.status_code,200,response.get_json())
        saved=self.store.job_payload({'account_id':account['id']})
        self.assertEqual(saved['password'],fixtures.ACCOUNT['password'])
        self.assertEqual(saved['browser_fingerprint'],fixtures.ACCOUNT['browser_fingerprint'])

    def test_account_secrets_and_student_id_are_encrypted_at_rest(self):
        self.add_account(1)
        with self.store.db() as db:db.execute('PRAGMA wal_checkpoint(FULL)')
        raw=self.store.path.read_bytes()
        for value in (fixtures.ACCOUNT['password'],fixtures.ACCOUNT['browser_fingerprint'],'202300000001'):
            self.assertNotIn(value.encode(),raw)

    def test_manual_named_wgs84_location_and_preset_are_supported(self):
        a=self.add_account(1)
        self.assertEqual(a['locationName'],'学知三组团')
        location={'mode':'fixed','name':'我的新位置','latitude':30.757413,'longitude':103.930739,
                  'coordinate_system':'wgs84','reverse_geocode':'手动填写的地址'}
        response=self.req(self.c1,self.t1,'/api/accounts/'+a['id'],'PATCH',{'location':location})
        self.assertEqual(response.status_code,200,response.get_json())
        updated=response.get_json()['account']
        self.assertEqual(updated['locationName'],'我的新位置')
        self.assertEqual(updated['coordinateConversion'],'wgs84_to_gcj02_approx')
        self.assertEqual(updated['location']['reverse_geocode'],'手动填写的地址')

    def test_bad_coordinates_unknown_mode_and_duplicate_student_are_rejected(self):
        a=self.add_account(1)
        response=self.req(self.c2,self.t2,'/api/accounts','POST',self.account_fields())
        self.assertEqual(response.status_code,409)
        for location in ({'mode':'browser'}, {'mode':'fixed','latitude':200,'longitude':20}, {'mode':'preset','preset':'missing'}):
            response=self.req(self.c1,self.t1,'/api/accounts/'+a['id'],'PATCH',{'location':location})
            self.assertEqual(response.status_code,400,response.get_json())

    def test_automatic_schedule_requires_first_verified_checkin(self):
        account=self.add_account(1)
        response=self.req(self.c1,self.t1,'/api/accounts/'+account['id'],'PATCH',{'automatic':True})
        self.assertEqual(response.status_code,409)
        payload=self.store.job_payload({'account_id':account['id']})
        state=State(self.root)
        day=now().date().isoformat();key=account_key(payload)
        state.claim(key,day);state.outcome(key,day,'confirmed');state.close()
        response=self.req(self.c1,self.t1,'/api/accounts/'+account['id'],'PATCH',{'automatic':True,'run_at':'22:15'})
        self.assertEqual(response.status_code,200,response.get_json())
        self.assertTrue(response.get_json()['account']['ready_for_automation'])
        self.assertTrue(response.get_json()['account']['confirmed_today'])

    def test_encrypted_cookie_cache_roundtrip_and_no_plain_cookie_file(self):
        account=self.add_account(1)
        payload=self.store.job_payload({'account_id':account['id']})
        path=cookie_path(self.root,payload)
        transport=EncryptedTransport(payload['user_agent'],path,self.store)
        transport.fingerprint(payload['browser_fingerprint'])
        transport.jar.set_cookie(http.cookiejar.Cookie(version=0,name='SESSION',value='Synthetic-Session-Secret',
            port=None,port_specified=False,domain='jzsz.uestc.edu.cn',domain_specified=False,domain_initial_dot=False,
            path='/',path_specified=True,secure=True,expires=int(time.time())+3600,discard=False,comment=None,comment_url=None,rest={'HttpOnly':None}))
        transport.save()
        self.assertFalse(path.exists())
        restored=EncryptedTransport(payload['user_agent'],path,self.store)
        self.assertTrue(restored.has_session())
        self.assertEqual([c.value for c in restored.jar if c.name=='SESSION'],['Synthetic-Session-Secret'])
        with self.store.db() as db:
            encrypted=db.execute('SELECT payload FROM web_cookies WHERE binding=?',(path.name,)).fetchone()[0]
        self.assertNotIn(b'Synthetic-Session-Secret',encrypted)
        self.assertNotIn(payload['browser_fingerprint'].encode(),encrypted)

    def test_disabled_account_cannot_queue_and_delete_is_owner_scoped(self):
        a=self.add_account(1,enabled=False)
        response=self.req(self.c1,self.t1,'/api/accounts/'+a['id']+'/jobs','POST',{'mode':'diagnose'})
        self.assertEqual(response.status_code,409)
        self.assertEqual(self.req(self.c2,self.t2,'/api/accounts/'+a['id'],'DELETE').status_code,404)
        self.assertEqual(self.req(self.c1,self.t1,'/api/accounts/'+a['id'],'DELETE').status_code,200)
        self.assertEqual(self.req(self.c1,self.t1,'/api/accounts').get_json()['accounts'],[])

    def test_missing_key_does_not_silently_replace_encryption_key(self):
        path=self.root/'dashboard.key'
        path.unlink()
        with self.assertRaises(ToolError) as caught:WebStore(self.root)
        self.assertEqual(caught.exception.reason,'dashboard_key_missing')
        self.assertFalse(path.exists())


class DashboardJobs(WebCase):
    def test_jobs_are_queued_without_immediate_school_request(self):
        account=self.add_account(1)
        response=self.req(self.c1,self.t1,'/api/accounts/'+account['id']+'/jobs','POST',{'mode':'diagnose'})
        self.assertEqual(response.status_code,202,response.get_json())
        self.assertEqual(response.get_json()['job']['state'],'queued')
        self.assertEqual(self.calls,[])
        self.assertTrue(self.worker.run_one())
        self.assertEqual(len(self.calls),1)
        self.assertEqual(self.calls[0][1],'diagnose')
        jobs=self.req(self.c1,self.t1,'/api/jobs').get_json()['jobs']
        self.assertEqual(jobs[0]['state'],'done')
        self.assertEqual(jobs[0]['result']['result'],'auth_ready')

    def test_real_submission_requires_explicit_confirmation(self):
        account=self.add_account(1)
        url='/api/accounts/'+account['id']+'/jobs'
        for value in ({'mode':'checkin'},{'mode':'checkin','confirm':'true'}):
            self.assertEqual(self.req(self.c1,self.t1,url,'POST',value).status_code,400)
        accepted=self.req(self.c1,self.t1,url,'POST',{'mode':'checkin','confirm':True})
        self.assertEqual(accepted.status_code,202)
        self.assertEqual(self.calls,[])

    def test_duplicate_queue_and_edits_while_busy_are_rejected(self):
        account=self.add_account(1)
        url='/api/accounts/'+account['id']
        self.req(self.c1,self.t1,url+'/jobs','POST',{'mode':'prepare'})
        self.assertEqual(self.req(self.c1,self.t1,url+'/jobs','POST',{'mode':'diagnose'}).status_code,409)
        self.assertEqual(self.req(self.c1,self.t1,url,'PATCH',{'label':'change'}).status_code,409)
        self.assertEqual(self.req(self.c1,self.t1,url,'DELETE').status_code,409)

    def test_job_details_and_lists_cannot_cross_owners(self):
        account=self.add_account(1)
        response=self.req(self.c1,self.t1,'/api/accounts/'+account['id']+'/jobs','POST',{'mode':'prepare'})
        jid=response.get_json()['job']['id']
        self.assertEqual(self.req(self.c2,self.t2,'/api/jobs/'+jid).status_code,404)
        self.assertEqual(self.req(self.c2,self.t2,'/api/jobs').get_json()['jobs'],[])
        self.assertEqual(self.req(self.ac,self.at,'/api/jobs/'+jid).status_code,200)

    def test_interrupted_or_expired_jobs_never_blindly_resubmit(self):
        account=self.add_account(1)
        response=self.req(self.c1,self.t1,'/api/accounts/'+account['id']+'/jobs','POST',{'mode':'checkin','confirm':True})
        jid=response.get_json()['job']['id']
        with self.store.db(True) as db:db.execute("UPDATE web_jobs SET business_date='2000-01-01' WHERE id=?",(jid,))
        self.worker.run_one()
        self.assertEqual(self.calls,[])
        result=self.req(self.c1,self.t1,'/api/jobs/'+jid).get_json()['job']
        self.assertEqual(result['result']['reason'],'job_expired')
        with self.store.db(True) as db:db.execute("UPDATE web_jobs SET state='running' WHERE id=?",(jid,))
        self.store.recover_jobs()
        result=self.req(self.c1,self.t1,'/api/jobs/'+jid).get_json()['job']
        self.assertEqual(result['state'],'failed')
        self.assertEqual(result['result']['reason'],'worker_interrupted')

    def test_worker_errors_and_arbitrary_extra_fields_do_not_leak_secrets(self):
        account=self.add_account(1)
        self.req(self.c1,self.t1,'/api/accounts/'+account['id']+'/jobs','POST',{'mode':'diagnose'})
        def explode(*args,**kwargs):raise RuntimeError('Synthetic-Private-Password-Do-Not-Expose')
        self.worker.runner=explode
        self.worker.run_one()
        raw=self.req(self.c1,self.t1,'/api/jobs').get_data(as_text=True)
        self.assertNotIn('Synthetic-Private-Password-Do-Not-Expose',raw)
        self.assertIn('worker_internal_error',raw)

    def test_disabling_owner_before_worker_starts_prevents_school_requests(self):
        account=self.add_account(1)
        self.req(self.c1,self.t1,'/api/accounts/'+account['id']+'/jobs','POST',{'mode':'diagnose'})
        self.req(self.ac,self.at,'/api/users/'+str(self.u1['id']),'PATCH',{'active':False})
        self.worker.run_one()
        self.assertEqual(self.calls,[])
        jobs=self.req(self.ac,self.at,'/api/jobs').get_json()['jobs']
        self.assertEqual(jobs[0]['result']['reason'],'account_disabled')

    def test_scheduled_job_is_only_enqueued_once_per_business_day(self):
        account=self.add_account(1)
        payload=self.store.job_payload({'account_id':account['id']})
        state=State(self.root);day=now().date().isoformat();key=account_key(payload)
        state.claim(key,day);state.outcome(key,day,'confirmed');state.close()
        response=self.req(self.c1,self.t1,'/api/accounts/'+account['id'],'PATCH',{'automatic':True,'run_at':'00:00'})
        self.assertEqual(response.status_code,200)
        self.worker.schedule_once();self.worker.schedule_once()
        with self.store.db() as db:
            count=db.execute("SELECT COUNT(*) FROM web_jobs WHERE source='schedule'").fetchone()[0]
        self.assertEqual(count,1)

    def test_job_cooldown_does_not_reset_on_completed_task(self):
        account=self.add_account(1)
        url='/api/accounts/'+account['id']+'/jobs'
        self.req(self.c1,self.t1,url,'POST',{'mode':'diagnose'});self.worker.run_one()
        response=self.req(self.c1,self.t1,url,'POST',{'mode':'prepare'})
        self.assertEqual(response.status_code,429)
        self.assertEqual(response.get_json()['error']['code'],'job_cooldown')
