"""Fresh-ticket submission exercises the existing durable runner, not a mirror."""
import copy
import datetime as dt
import os
import tempfile
import time
import unittest
from pathlib import Path

import test_workflows as f
from test_submission_diagnostics import DiagnosticTransport
from moonuestc.client import School
from moonuestc.errors import ToolError
from moonuestc.runner import run_account,account_key
from moonuestc.state import State


class AuthorizedTransport(DiagnosticTransport):
    def __init__(self):super().__init__();self.headers=[]
    def request(self,method,url,**kw):
        self.headers.append((method,kw['stage'],dict(kw.get('headers') or {})))
        return super().request(method,url,**kw)


class Grant:
    def __init__(self):self.calls=[];self.failure=None;self.on_ticket=lambda:None
    def prepare(self):
        self.calls.append('prepare')
        if self.failure:raise ToolError(self.failure,'wechat_identity')
    def check_business(self,school):self.calls.append('business_identity')
    def ticket(self):self.calls.append('ticket');self.on_ticket();return 'T'*43,time.time()+1800
    def close(self):self.calls.append('close')
    def reject(self):self.calls.append('reject')


class AuthorizedRunner(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=os.environ.get('MOON_TEST_TMP'));self.root=Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)
        self.state=State(self.root);self.transport=AuthorizedTransport();self.grant=Grant()
        self.addCleanup(self.state.close)
        self.state.require_school_client(46001)
    def tearDown(self):self.state.close();self.temp.cleanup()
    def run_job(self,grant=True,account=None):
        return run_account(copy.deepcopy(account or f.ACCOUNT),'checkin',self.state,self.root,
            clock=lambda:self.transport.instant,sleep=lambda _:None,transport_factory=lambda *a:self.transport,
            authorization=self.grant if grant else None,require_authorization=True)
    def test_verified_grant_supplies_ticket_only_to_single_business_post(self):
        result=self.run_job();self.assertEqual(result['result'],'confirmed')
        headers=[h for m,s,h in self.transport.headers if 'X-Checkin-Ticket' in h]
        self.assertEqual(headers[0]['X-Checkin-Ticket'],'T'*43);self.assertEqual(len(headers),1)
        self.assertEqual(self.transport.post_count,1);self.assertTrue(self.state.school_client_requirement())
        self.assertNotIn('T'*43,str(result))
    def test_unlinked_account_stays_guarded_without_credential_posts(self):
        self.transport.session=True
        result=self.run_job(False)
        self.assertEqual(result['reason'],'school_client_required');self.assertEqual(self.transport.post_count,0)
        self.assertNotIn('cas_submit',[s for _,s in self.transport.calls])
    def test_identity_failure_happens_before_school_or_business_requests(self):
        self.grant.failure='wechat_identity_mismatch'
        with self.assertRaises(ToolError):self.run_job()
        self.assertEqual(self.transport.calls,[]);self.assertEqual(self.transport.post_count,0)
    def test_network_unknown_rechecks_without_requesting_or_posting_again(self):
        self.transport.network='timeout';first=self.run_job()
        self.assertEqual(first['result'],'submission_unknown')
        first_count=self.grant.calls.count('ticket')
        self.run_job();self.assertEqual(self.transport.post_count,1);self.assertEqual(self.grant.calls.count('ticket'),first_count)
    def test_slow_ticket_acquisition_cannot_submit_after_reserved_deadline(self):
        account={**f.ACCOUNT,'_job_deadline':self.transport.instant.timestamp()+10}
        self.grant.on_ticket=lambda:setattr(self.transport,'instant',self.transport.instant+dt.timedelta(seconds=11))
        with self.assertRaises(ToolError) as caught:self.run_job(account=account)
        self.assertEqual(caught.exception.reason,'reserved_slot_expired');self.assertEqual(self.transport.post_count,0)
        self.assertFalse(self.state.claimed(account_key(f.ACCOUNT),f.DAY))
    def test_school_rejection_disables_grant_and_retains_no_repeat_claim(self):
        self.transport.failure=(200,46003,'operation ticket rejected',False)
        result=self.run_job();self.assertEqual(result['result'],'submission_rejected')
        self.assertIn('reject',self.grant.calls);self.assertTrue(self.state.claimed(account_key(f.ACCOUNT),f.DAY))
        self.run_job();self.assertEqual(self.transport.post_count,1)
    def test_one_operation_ticket_cannot_be_reused_directly(self):
        school=School(self.transport,f.ACCOUNT,lambda:None)
        school.authorize_operation('T'*43,time.time()+300)
        school.submit({'latitude':0,'longitude':0})
        with self.assertRaises(ToolError):school.submit({'latitude':0,'longitude':0})
        self.assertEqual(self.transport.post_count,1)


if __name__=='__main__':unittest.main()
