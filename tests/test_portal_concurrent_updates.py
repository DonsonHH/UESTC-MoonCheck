"""Fresh school verification must not overwrite later grant/config decisions."""
import copy
import unittest

import test_portal as fixtures
from test_yyb_authorization import FakeClient
from moonuestc.wechat_authorization import APP_ID,CONSENT_VERSION,WechatManager


class ConcurrentVerification(unittest.TestCase):
    setUp=fixtures.PortalCase.setUp
    tearDown=fixtures.PortalCase.tearDown
    login=fixtures.PortalCase.login
    request=fixtures.PortalCase.request

    def prepare_account(self):
        response=self.login();self.assertEqual(response.status_code,200)
        self.owner=response.json['user'];self.account=self.request('/api/portal/me').json['account']
        self.manager=WechatManager(self.store,client=FakeClient(),background=False)
        self.addCleanup(self.manager.close)
        with self.store.db(True) as db:
            row=self.store._row(db,self.owner,self.account['id']);payload=self.store._payload(row)
            payload['wechat_authorization']={'id':'a'*32,'app_id':APP_ID,'student_id':payload['student_id'],
                'school_user_id':'synthetic-school-user','verified_at':1,'consent_version':CONSENT_VERSION,
                'status':'ready','credentials':{'openid':'synthetic-openid','accesstoken':'synthetic-old-access',
                    'refreshtoken':'synthetic-old-refresh','expires_at':0}}
            db.execute('UPDATE web_accounts SET payload=? WHERE id=?',(self.store.vault.seal(payload,'account:'+row['id']),row['id']))
            db.execute('UPDATE portal_bindings SET verified_at=0')
        return payload

    def current(self):
        with self.store.db() as db:return self.store._payload(self.store._row(db,self.owner,self.account['id']))

    def test_revocation_during_school_verification_cannot_be_resurrected(self):
        self.prepare_account()
        def verifier(account):
            self.manager.revoke(self.owner,self.account['id'])
            self.assertNotIn('wechat_authorization',self.current())
            return []
        self.app.extensions['moon_portal'].verifier=verifier
        response=self.login();self.assertEqual(response.status_code,200,response.json)
        self.assertNotIn('wechat_authorization',self.current())

    def test_rotated_tokens_and_new_variation_seed_survive_school_credential_refresh(self):
        original=self.prepare_account()
        operation=self.manager.for_account(original)
        def verifier(account):
            rotated=copy.deepcopy(original['wechat_authorization'])
            rotated['credentials'].update(accesstoken='synthetic-new-access',refreshtoken='synthetic-new-refresh')
            operation.save(rotated)
            with self.store.db(True) as db:
                row=self.store._row(db,self.owner,self.account['id']);latest=self.store._payload(row)
                latest.update(variation_seed='c'*64,location={'mode':'preset','preset':'xuezhi_group5_amap'},variation={'minutes':5,'meters':5})
                db.execute('UPDATE web_accounts SET payload=? WHERE id=?',(self.store.vault.seal(latest,'account:'+row['id']),row['id']))
            return []
        self.app.extensions['moon_portal'].verifier=verifier
        response=self.login(password='Synthetic-new-school-password!');self.assertEqual(response.status_code,200,response.json)
        current=self.current()
        self.assertEqual(current['password'],'Synthetic-new-school-password!')
        self.assertEqual(current['wechat_authorization']['credentials']['refreshtoken'],'synthetic-new-refresh')
        self.assertEqual(current['variation_seed'],'c'*64)
        self.assertEqual(current['variation'],{'minutes':5,'meters':5})
        self.assertEqual(current['location']['preset'],'xuezhi_group5_amap')

    def test_newer_authorization_is_kept_when_school_verification_finishes(self):
        self.prepare_account()
        def verifier(account):
            with self.store.db(True) as db:
                row=self.store._row(db,self.owner,self.account['id']);latest=self.store._payload(row)
                latest['wechat_authorization']['id']='b'*32
                db.execute('UPDATE web_accounts SET payload=? WHERE id=?',(self.store.vault.seal(latest,'account:'+row['id']),row['id']))
            return []
        self.app.extensions['moon_portal'].verifier=verifier
        response=self.login();self.assertEqual(response.status_code,200,response.json)
        self.assertEqual(self.current()['wechat_authorization']['id'],'b'*32)
