import test from 'node:test';
import assert from 'node:assert/strict';
import {resultLabel,requiresOfficialEntry,tone} from '../src/result-presentation.ts';
import {studentState} from '../src/student-state.ts';
const legacy={result:'submission_unknown',reason:'record_not_confirmed',retryExhausted:true,submission:{outcome:'rejected',stage:'checkin_post',httpStatus:200,apiCode:46001}};

test('explicit official entry requirement takes priority over obsolete retry messages',()=>{
 assert.equal(resultLabel(legacy),'请在微信小程序签到');
 assert.equal(tone({result:'submission_rejected'}),'amber');
 assert.equal(requiresOfficialEntry({...legacy,result:'confirmed'}),false);
 assert.equal(requiresOfficialEntry({...legacy,submission:{...legacy.submission,outcome:'error'}}),false);
});
test('the home action synchronizes official records and does not offer a password reset',()=>{
 const a={enabled:true,automatic:true,location:null,ready_for_automation:false,confirmed_today:false,school_auth_required:false,school_checkin_required:true};
 const s=studentState(a,'22:05');assert.equal(s.key,'school-client');assert.equal(s.label,'同步今日学校记录');assert.equal(s.action,'submit');
 assert.equal(studentState({...a,school_checkin_required:false,school_auth_required:false,today_job:{state:'failed',source:'schedule',result:legacy},location:{}},'22:05').key,'school-client');
 const done=studentState({...a,confirmed_today:true},'22:05');assert.equal(done.key,'done');assert(!done.message.includes('明天继续按每日计划执行'));
 const expired=studentState({...a,school_auth_required:true},'22:05');assert.equal(expired.action,'reauthenticate');assert(expired.message.includes('签到仍须在微信'));
});
test('network uncertainty still offers rechecking and accepted delivery is not confirmed',()=>{
 assert.equal(resultLabel({result:'submission_unknown',reason:'record_not_confirmed'}),'学校记录尚未确认');
 assert.equal(requiresOfficialEntry({result:'submission_unknown',submission:{outcome:'accepted',apiCode:0}}),false);
});

test('school address outage has a clear label and keeps scheduled retry state visible',()=>{
 assert.equal(resultLabel({result:'error',reason:'reverse_geocode_unavailable'}),'学校地址解析暂不可用');
 assert.equal(resultLabel({result:'retry_pending',reason:'reverse_geocode_unavailable'}),'等待自动重试');
 assert.equal(resultLabel({result:'error',reason:'reverse_geocode_unavailable',retryExhausted:true}),'重试后仍失败，需处理');
});
