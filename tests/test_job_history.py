"""History uses Shanghai calendar days and owner-scoped stable pagination."""
import datetime as dt
import json
from unittest.mock import patch
from dashboard_helpers import WebCase,ORIGIN
from moonuestc.policy import SHANGHAI

class History(WebCase):
 def setUp(self):
  super().setUp();self.a=self.add_account();self.b=self.add_account(owner=2,student='202300000002')
  self.instant=dt.datetime(2026,10,22,0,10,tzinfo=SHANGHAI)
 def seed(self,aid,owner,count,start,step=0):
  with self.store.db(True) as db:
   for i in range(count):
    jid=f'{owner:02x}{i:030x}'
    db.execute("INSERT INTO web_jobs(id,account_id,requested_by,mode,source,business_date,state,created_at,result) VALUES(?,?,?,'prepare','manual','2026-10-22','done',?,?)",(jid,aid,owner,start-i*step,json.dumps({'result':'dry_run_ready'})))
 def get(self,query='',client=None):
  with patch('moonuestc.web_store.now',return_value=self.instant):return (client or self.c1).get('/api/jobs/history'+query,base_url=ORIGIN)
 def test_default_is_today_and_previous_two_shanghai_dates(self):
  cutoff=dt.datetime(2026,10,20,tzinfo=SHANGHAI).timestamp()
  self.seed(self.a['id'],self.u1['id'],3,cutoff+1,step=1)
  r=self.get();self.assertEqual(r.status_code,200,r.json)
  self.assertEqual(len(r.json['jobs']),2);self.assertEqual(r.json['recent_since'],cutoff);self.assertIsNotNone(r.json['next_cursor'])
  older=self.get('?cursor='+r.json['next_cursor']);self.assertEqual(len(older.json['jobs']),1);self.assertIsNone(older.json['next_cursor'])
 def test_more_reaches_beyond_one_hundred_without_duplicates_or_other_users(self):
  self.seed(self.a['id'],self.u1['id'],131,self.instant.timestamp()-10)
  self.seed(self.b['id'],self.u2['id'],5,self.instant.timestamp()-5)
  ids=[];cursor=''
  while True:
   r=self.get('?cursor='+cursor if cursor else '');self.assertEqual(r.status_code,200,r.json);self.assertLessEqual(len(r.json['jobs']),30)
   ids.extend(j['id'] for j in r.json['jobs']);cursor=r.json['next_cursor']
   if not cursor:break
  self.assertEqual(len(ids),131);self.assertEqual(len(set(ids)),131)
  self.assertTrue(all(j['account_id']==self.a['id'] for j in self.get().json['jobs']))
  admin=self.get(client=self.ac);self.assertTrue(any(j['account_id']==self.b['id'] for j in admin.json['jobs']))
 def test_empty_recent_page_can_load_older_and_no_login_is_denied(self):
  self.seed(self.a['id'],self.u1['id'],2,self.instant.timestamp()-7*86400)
  r=self.get();self.assertEqual(r.json['jobs'],[]);self.assertIsNotNone(r.json['next_cursor'])
  self.assertEqual(len(self.get('?cursor='+r.json['next_cursor']).json['jobs']),2)
  self.assertEqual(self.get(client=self.app.test_client()).status_code,401)
 def test_invalid_or_unbounded_cursor_is_rejected(self):
  for value in ('garbage','a'*257,'', 'e30'):
   r=self.get('?cursor='+value);self.assertEqual(r.status_code,400,r.json)
