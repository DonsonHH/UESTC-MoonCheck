import test from 'node:test';
import assert from 'node:assert/strict';
import {studentState,submissionIntent} from '../src/student-state.ts';
const account={enabled:true,automatic:true,location:{preset:'synthetic'},location_open:true,ready_for_automation:true,confirmed_today:false,recorded_today:false,planned_run_at:'22:02:13',schedule_slot:{start:'22:02'}};
test('healthy daily plans wait calmly before school opens and never request a daily check',()=>{
 for(const time of ['00:01','12:00','21:00','21:30']){const s=studentState(account,time);assert.equal(s.key,'scheduled');assert.equal(s.action,'settings');assert(!s.title.includes('未确认'));assert(!s.label.includes('检查'))}
});
test('first users get one clear setup then first-sign step',()=>{
 assert.equal(studentState({...account,location:null,automatic:false,ready_for_automation:false},'12:00').key,'setup');
 const a={...account,automatic:false,ready_for_automation:false};assert.equal(studentState(a,'12:00').key,'first-wait');assert.equal(studentState(a,'21:07').key,'first-sign');assert.equal(studentState(a,'23:25').key,'first-closed');
});
test('confirmed results dominate stale errors; repeating a sign is not the primary action',()=>{
 const s=studentState({...account,confirmed_today:true,school_auth_required:true},'22:05');assert.equal(s.key,'done');assert.equal(s.action,'history');
});
test('authentication, unknown submission, failed task and unavailable slot have explicit recovery',()=>{
 assert.equal(studentState({...account,school_auth_required:true},'12:00').action,'reauthenticate');
 assert.equal(studentState({...account,today_job:{state:'failed',source:'schedule',result:{result:'submission_unknown'}}},'22:05').label,'复查今日结果');
 assert.equal(studentState({...account,today_job:{state:'failed',source:'schedule',result:{result:'error'}}},'22:05').action,'history');
 assert.equal(studentState({...account,schedule_slot:null},'12:00').key,'capacity');
});
test('enabled manual users are guided toward enabling automation, busy jobs show progress only',()=>{
 assert.equal(studentState({...account,automatic:false},'12:00').key,'enable');assert.equal(studentState(account,'22:00',true,'queued').action,'history');assert.equal(studentState({...account,enabled:false},'12:00').key,'paused');
});

test('native authorization is the next action for new or expired grants, including after today is complete',()=>{
 const waiting={...account,wechat_auth_enabled:true,school_checkin_required:true};
 assert.equal(studentState(waiting,'12:00').action,'authorize');
 const completed=studentState({...waiting,recorded_today:true},'22:05');
 assert.equal(completed.title,'今日已完成');assert.equal(completed.action,'authorize');
 assert.equal(studentState({...waiting,enabled:false},'12:00').key,'paused');
});

test('a verified native grant permits the saved daily plan while preserving the legacy fallback',()=>{
 const native={...account,wechat_auth_enabled:true,school_checkin_required:false,wechat_authorization:{linked:true,status:'ready',eligible:true}};
 assert.equal(studentState(native,'12:00').key,'scheduled');
 assert.equal(studentState({...native,automatic:false,ready_for_automation:false},'21:07').key,'first-sign');
 assert.equal(studentState({...account,school_checkin_required:true},'12:00').label,'同步今日学校记录');
});

test('current-day confirmation is independent of an older failed record or a newly linked grant',()=>{
 const a={...account,wechat_auth_enabled:true,school_checkin_required:false,last_result:{result:'submission_rejected',reason:'school_client_required'}};
 assert.equal(submissionIntent(a),'submit');
 assert.equal(submissionIntent({...a,today_job:{state:'failed',source:'schedule',result:{result:'submission_unknown'}}}),'recheck');
 assert.equal(submissionIntent({...a,recorded_today:true}),'recheck');
 assert.equal(submissionIntent({...a,wechat_auth_enabled:false}),'sync');
});
test('a native account with two expired connections recovers school identity first',()=>{
 const s=studentState({...account,wechat_auth_enabled:true,school_checkin_required:true,school_auth_required:true},'21:10');
 assert.equal(s.action,'reauthenticate');
});
