import unittest
import test_portal as fixtures
from moonuestc.web_store import WebStore
from dashboard_helpers import FAST_HASHER

class StudentNames(unittest.TestCase):
 setUp=fixtures.PortalCase.setUp
 tearDown=fixtures.PortalCase.tearDown
 login=fixtures.PortalCase.login
 request=fixtures.PortalCase.request
 def test_bound_account_name_follows_verified_student_name_and_operator_rename(self):
  login=self.login();user=login.json['user'];account=self.request('/api/portal/me').json['account']
  self.store.update_user(self.admin,user['id'],{'display_name':'合成学生姓名'})
  self.assertEqual(self.store.account(user,account['id'])['label'],'合成学生姓名')
  self.store.save_account(user,{'label':'我的学校账号'},account['id'])
  self.assertEqual(self.store.account(user,account['id'])['label'],'合成学生姓名')
 def test_upgrade_synchronizes_old_labels_without_changing_encrypted_payload_or_history(self):
  login=self.login();user=login.json['user'];account=self.request('/api/portal/me').json['account']
  with self.store.db(True) as db:
   db.execute('UPDATE web_users SET display_name=? WHERE id=?',('另一合成姓名',user['id']))
   db.execute('UPDATE web_accounts SET label=? WHERE id=?',('我的学校账号',account['id']))
   db.execute("DELETE FROM web_migrations WHERE name='student_label_matches_name_v1'")
   before=db.execute('SELECT payload,owner_id,run_at,automatic FROM web_accounts WHERE id=?',(account['id'],)).fetchone()
  restored=WebStore(self.temp.name,FAST_HASHER)
  with restored.db() as db:after=db.execute('SELECT payload,owner_id,run_at,automatic FROM web_accounts WHERE id=?',(account['id'],)).fetchone()
  self.assertEqual(tuple(before),tuple(after));self.assertEqual(restored.account(user,account['id'])['label'],'另一合成姓名')
