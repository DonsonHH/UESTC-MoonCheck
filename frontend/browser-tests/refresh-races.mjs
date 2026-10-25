import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {readFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {extname,resolve,sep} from 'node:path';
import {chromium} from 'playwright';

// Serve only the local production bundle. All API responses and identities are
// synthetic; an accidental request outside this origin fails the test.
const root=process.env.MOON_UI_TEST_ROOT?resolve(process.env.MOON_UI_TEST_ROOT):fileURLToPath(new URL('../../moonuestc/web_static/ui/',import.meta.url));
const server=createServer(async(request,response)=>{
 try{
  const path=new URL(request.url,'http://localhost').pathname;
  const file=path.startsWith('/static/ui/')?resolve(root,decodeURIComponent(path.slice('/static/ui/'.length))):resolve(root,'index.html');
  if(!file.startsWith(resolve(root)+sep)){response.writeHead(404).end();return}
  const body=await readFile(file);
  response.writeHead(200,{'Content-Type':({'.js':'application/javascript','.css':'text/css','.html':'text/html'})[extname(file)]||'application/octet-stream'}).end(body);
 }catch{response.writeHead(404).end()}
});
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
const base='http://127.0.0.1:'+server.address().port;
let browser;
try{
 browser=await chromium.launch({headless:true,timeout:20000,...(process.env.MOON_BROWSER_CHANNEL?{channel:process.env.MOON_BROWSER_CHANNEL}:{})});
 for(const scenario of ['old-success','old-unauthorized','unmounted-unauthorized','latest-unauthorized','poll-single-flight']){
  const context=await browser.newContext({viewport:{width:390,height:900},colorScheme:'dark'});
  try{
   const page=await context.newPage(),errors=[];
   const state={authenticated:true,logouts:0,externalRequests:0,account:{id:'synthetic-account',student_id:'202300000001',owner_name:'合成同学',enabled:true,automatic:true,run_at:'22:00',ready_for_automation:true,confirmed_today:false,recorded_today:false,business_date:'2026-10-25',server_time:Date.parse('2026-10-25T14:00:00Z')/1000,school_auth_required:false,school_checkin_required:false,wechat_auth_enabled:true,wechat_authorization:{linked:true,status:'ready',eligible:true},locationName:'学知五组团',location:{mode:'preset',preset:'xuezhi_group5_amap'},location_open:true,planned_run_at:'22:02:13',schedule_slot:{start:'22:02',end:'22:02:30'},variation:{minutes:5,meters:10},last_result:{result:'dry_run_ready'}}};
   const session=()=>({ok:true,authenticated:state.authenticated,csrf_token:'synthetic-csrf',user:{id:2,username:'synthetic-user',display_name:'合成同学',role:'user',active:true,must_change_password:false},version:'synthetic-test',initialized:true,onboarding_available:true});
   const rejected={ok:false,error:{code:'login_required',message:'Synthetic expired session'}};
   let requests=0,release,started,overlapCount=0;
   const slowResponses=[];
   const pending=new Promise(resolve=>started=resolve),old=structuredClone(state.account);
   page.on('pageerror',error=>errors.push(error.message));
   await page.clock.install({time:new Date('2026-10-25T14:00:00Z')});
   await context.route('**/*',async route=>{
    const request=route.request(),url=new URL(request.url());
    if(url.origin!==base){state.externalRequests++;await route.abort();return}
    if(!url.pathname.startsWith('/api/')){await route.continue();return}
    const send=(body,status=200)=>route.fulfill({status,contentType:'application/json',body:JSON.stringify(body)});
    switch(url.pathname){
     case '/api/session':await send(session());return;
     case '/api/accounts':
      requests++;
      if(requests===1){await send({ok:true,accounts:[state.account]});return}
      if(scenario==='poll-single-flight'){
       await new Promise(resolve=>{slowResponses.push(async()=>{await send({ok:true,accounts:[state.account]});resolve()});release=()=>Promise.all(slowResponses.map(respond=>respond()));started()});return;
      }
      if(requests===2){
       await new Promise(resolve=>{release=async()=>{const success=['old-success','latest-unauthorized'].includes(scenario);await send(success?{ok:true,accounts:[old]}:rejected,success?200:401);resolve()};started()});return;
      }
      if(scenario==='latest-unauthorized'&&requests===3){await send(rejected,401);return}
      await send({ok:true,accounts:[state.account]});return;
     case '/api/jobs':await send({ok:true,jobs:scenario==='poll-single-flight'&&requests===1?[{id:'synthetic-job',account_id:state.account.id,state:'running',mode:'prepare',source:'manual',created_at:state.account.server_time,business_date:state.account.business_date,result:null}]:[]});return;
     case '/api/logout':state.authenticated=false;state.logouts++;await send({ok:true});return;
     case '/api/portal/login':state.authenticated=true;await send(session());return;
     case '/api/notice':await send({ok:true,notice:{version:'synthetic-notice',title:'托管说明',announcement:'合成测试说明',sections:[],acceptance:'我已阅读并同意托管说明'}});return;
     case '/api/wechat/notice':await send({ok:true,notice:{version:'synthetic-wechat',title:'微信授权',text:'合成测试授权说明'}});return;
     default:await send({ok:false,error:{code:'unstubbed_api',message:'Unexpected synthetic API request'}},404);
    }
   });
   await page.goto(base+'/app/authorization');
   await page.getByText('连接已就绪',{exact:true}).waitFor();await page.waitForTimeout(40);
   const waitForPending=()=>Promise.race([pending,new Promise((_,reject)=>setTimeout(()=>reject(new Error('Dashboard did not request synthetic accounts')),10000).unref())]);
   if(scenario==='poll-single-flight'){
    state.account.wechat_authorization={linked:false,status:'not_authorized',eligible:false};state.account.school_checkin_required=true;
    await page.clock.runFor(2001);await waitForPending();await page.clock.runFor(2001);await page.waitForTimeout(80);overlapCount=requests;
   }else{await page.clock.runFor(15001);await waitForPending()}
   if(scenario==='unmounted-unauthorized'){
    await page.getByRole('button',{name:'账号菜单',exact:true}).click();await page.getByRole('menuitem',{name:'退出登录',exact:true}).click();
    await page.getByLabel('学号',{exact:true}).fill('202300000001');await page.getByLabel('学校登录密码',{exact:true}).fill('Synthetic-Password-Secret');
    await page.getByRole('button',{name:'登录并继续',exact:true}).click();await page.getByRole('checkbox',{name:/我已阅读并同意/}).check();await page.getByRole('button',{name:'同意并继续登录',exact:true}).click();
    await page.getByRole('button',{name:'查看我的计划',exact:true}).waitFor();
   }else if(scenario!=='poll-single-flight'){
    if(scenario==='old-success'){state.account.wechat_authorization={linked:false,status:'not_authorized',eligible:false};state.account.school_checkin_required=true}
    await page.getByRole('button',{name:'刷新当前状态',exact:true}).click();
    if(scenario==='old-success')await page.getByRole('checkbox',{name:/我同意托管/}).waitFor();
    else if(scenario==='latest-unauthorized')await page.getByLabel('学号',{exact:true}).waitFor();
    else await page.getByText('连接已就绪',{exact:true}).waitFor();
   }
   await page.clock.resume();await release();await page.waitForTimeout(180);
   assert.equal(state.logouts,['unmounted-unauthorized','latest-unauthorized'].includes(scenario)?1:0,'Only a current unauthorized response can end the current session');
   if(scenario==='old-success')assert.equal(await page.getByRole('checkbox',{name:/我同意托管/}).count(),1,'Old success must not restore revoked authorization');
   if(scenario==='old-unauthorized')await page.getByText('连接已就绪',{exact:true}).waitFor();
   if(scenario==='unmounted-unauthorized')await page.getByRole('heading',{name:'今日安排',exact:true,level:1}).waitFor();
   if(scenario==='latest-unauthorized')await page.getByLabel('学号',{exact:true}).waitFor();
   if(scenario==='poll-single-flight'){
    await page.getByRole('checkbox',{name:/我同意托管/}).waitFor();
    assert.equal(overlapCount,2,'Polling must wait for a slow current refresh instead of continually superseding it');
   }
   assert.equal(state.externalRequests,0);assert.deepEqual(errors,[]);
   console.log('PASS '+scenario);
  }finally{await context.close()}
 }
}finally{
 await browser?.close();
 server.closeAllConnections();
 await new Promise(resolve=>server.close(resolve));
}
