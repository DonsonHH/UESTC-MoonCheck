import tempfile,unittest
from argon2 import PasswordHasher
from moonuestc.web_store import WebStore
from dashboard_helpers import WebCase

class RadiusMigration(unittest.TestCase):
 def test_enabled_radius_upgrades_to_ten_without_changing_credentials_or_switches(self):
  with tempfile.TemporaryDirectory() as root:
   s=WebStore(root,PasswordHasher(time_cost=1,memory_cost=8192,parallelism=1))
   admin=s.create_user(None,{'username':'operator','password':'Synthetic-operator-password!','role':'admin'},bootstrap=True)
   a=s.save_account(admin,WebCase.account_fields(None,variation={'minutes':5,'meters':5}));b=s.save_account(admin,WebCase.account_fields(None,student='202600000002',variation={'minutes':0,'meters':0}))
   with s.db(True) as db:
    old=s._payload(db.execute('SELECT * FROM web_accounts WHERE id=?',(a['id'],)).fetchone());db.execute("DELETE FROM web_migrations WHERE name='daily_radius_10m_v1'")
   restored=WebStore(root,s.hasher)
   with restored.db() as db:new=restored._payload(db.execute('SELECT * FROM web_accounts WHERE id=?',(a['id'],)).fetchone())
   self.assertEqual(new,{**old,'variation':{'minutes':5,'meters':10}})
   self.assertEqual(restored.account(admin,b['id'])['variation'],{'minutes':0,'meters':0})
   self.assertEqual(restored.account(admin,a['id'])['automatic'],a['automatic'])
 def test_incomplete_payload_does_not_partially_rewrite_other_accounts(self):
  with tempfile.TemporaryDirectory() as root:
   s=WebStore(root,PasswordHasher(time_cost=1,memory_cost=8192,parallelism=1));admin=s.create_user(None,{'username':'operator','password':'Synthetic-operator-password!','role':'admin'},bootstrap=True)
   a=s.save_account(admin,WebCase.account_fields(None,variation={'minutes':5,'meters':5}));b=s.save_account(admin,WebCase.account_fields(None,student='202600000002'))
   with s.db(True) as db:
    raw=db.execute('SELECT payload FROM web_accounts WHERE id=?',(a['id'],)).fetchone()[0];db.execute("DELETE FROM web_migrations WHERE name='daily_radius_10m_v1'");db.execute('UPDATE web_accounts SET payload=? WHERE id=?',(b'invalid',b['id']))
   with self.assertRaises(Exception):s._upgrade_variation_radius()
   with s.db() as db:self.assertEqual(db.execute('SELECT payload FROM web_accounts WHERE id=?',(a['id'],)).fetchone()[0],raw)
