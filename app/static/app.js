'use strict';
const $ = s => document.querySelector(s);
const $$ = s => [...document.querySelectorAll(s)];
const csrf = $('meta[name="csrf-token"]').content;
let state = null, view = 'overview', polling = false, timer, serverOffset = 0, scheduleDirty=false;
let accountBaseline='',presetBaseline='';
let renderedDay='';
let notificationDirty=false;
function formSnapshot(f){return JSON.stringify([...new FormData(f)]);}
function buttonBusy(btn,text){const original=btn.innerHTML;btn.disabled=true;btn.innerHTML=icon('loader-circle')+text;btn.classList.add('is-loading');return ()=>{btn.innerHTML=original;btn.disabled=false;btn.classList.remove('is-loading');};}
function requestClose(dialog,form,baseline){if(formSnapshot(form)!==baseline)confirmAction('放弃修改？','修改尚未保存。',()=>dialog.close(),'放弃修改',true);else dialog.close();}
let positionMeta = {browser_location:false, location_duration_ms:0};
let adminState = null;
const isAdmin = document.body.dataset.role === 'superadmin';
const titles = {overview:'总览',accounts:'打卡账号',schedule:'自动打卡',history:'打卡记录',help:'帮助',...(isAdmin?{admin:'系统管理'}:{})};
const outcomes = {success:'已打卡',already_done:'已打卡',connected:'登录正常',failed:'操作失败',need_auth:'请重新登录',abnormal:'打卡异常',pending:'待确认',out_of_window:'未到打卡时间',need_location:'请更新位置'};
const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const schoolDate = d => new Intl.DateTimeFormat('en-CA',{timeZone:'Asia/Shanghai',year:'numeric',month:'2-digit',day:'2-digit'}).format(d);
const prettyTime = s => s ? new Date(s).toLocaleString('zh-CN',{timeZone:'Asia/Shanghai',hour12:false}) : '—';
const current = () => new Date(Date.now() + serverOffset);
function toast(message, error=false){
  clearTimeout(timer); $('#toast').textContent=message; $('#toast').className='toast'+(error?' error':'');
  timer=setTimeout(()=>$('#toast').classList.add('hidden'),5000);
}
async function api(path, method='GET', data){
  const r=await fetch(path,{method,headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:data===undefined?undefined:JSON.stringify(data)});
  if(r.status===401){location.assign('/login');throw new Error('登录已过期');}
  const j=await r.json(); if(!r.ok)throw new Error(j.error||'请求失败'); return j;
}
function go(next){
  if(!Object.hasOwn(titles,next))next='overview';
  view=next; $$('.view').forEach(el=>el.classList.toggle('hidden',el.id!=='view-'+next));
  $$('.nav-item').forEach(el=>el.classList.toggle('active',el.dataset.view===next));
  $('#page-title').textContent=titles[next]; history.replaceState(null,'','#'+next); window.scrollTo({top:0,behavior:'smooth'});
  if(next==='admin')loadAdmin();
  if(next==='schedule')loadNotifications();
}
$$('.nav-item').forEach(el=>el.addEventListener('click',()=>go(el.dataset.view)));
$$('[data-go]').forEach(el=>el.addEventListener('click',()=>go(el.dataset.go)));
$('#hero-action').addEventListener('click',()=>{if(state && !state.accounts.length)editAccount();else go('schedule');});
function icon(name){return `<svg class="icon" aria-hidden="true" focusable="false" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><use href="/static/icons.svg#${name}"></use></svg>`;}
function badge(kind,label){return `<span class="badge ${esc(kind)}">${esc(label||outcomes[kind]||kind)}</span>`;}
function accountStatus(a,day,running=false){
  const s=a.state||{}, done=s.success_date===day;
  const updated=new Date(s.updated_at||'');
  const fresh=Number.isFinite(updated.getTime())&&schoolDate(updated)===day;
  const kind=running?'pending':done?'success':fresh&&!['success','already_done'].includes(s.last_outcome)?s.last_outcome||'':'';
  const label=running?'执行中…':done?'今日已打卡':outcomes[kind]||'今日待打卡';
  let detail=a.location_unavailable?'预设已停用，请更换位置。':running?'':done?(s.today?.businessDate===day?s.today.checkinTime||'':''):fresh&&kind?s.last_message||'':'';
  if(detail===label)detail='';
  return {done,kind,label,detail};
}
function renderAccounts(selector, detailed=false){
  const root=$(selector);
  if(!state.accounts.length){root.innerHTML=`<div class="empty-state"><div class="empty-icon">${icon('user-plus')}</div><h3>还没有打卡账号</h3><button class="empty-add">${icon('plus')}添加账号</button></div>`;root.querySelector('button').addEventListener('click',()=>editAccount());return;}
  const day=schoolDate(current());
  root.innerHTML=state.accounts.map(a=>{
    const running=state.busy?.account_id===a.id;
    const {done,kind,label,detail}=accountStatus(a,day,running);
    return `<article class="account-row"><div class="account-avatar">${esc(a.name.slice(0,1))}</div><div class="account-info"><strong>${esc(a.name)}</strong><small><span>${esc(a.student_id)}</span><span class="account-mode">${a.enabled?'自动打卡':'手动打卡'}</span></small></div><div class="account-status">${badge(running?'pending':kind,label)}${detail?`<small title="${esc(detail)}">${esc(detail)}</small>`:''}</div><div class="account-footer">${detailed?`<div class="account-location">${icon('map-pin')}<div><strong>${a.location_mode==='preset'?esc(a.preset_name||'预设不可用'):'手动位置'}</strong><small>${esc(a.latitude)}, ${esc(a.longitude)} <span>${esc((a.coordinate_system||'gcj02').toUpperCase())}</span></small></div></div>`:''}<div class="account-actions"><button class="account-button" data-action="probe" data-id="${a.id}" ${state.server_busy?'disabled':''}>${icon('circle-check')}检查登录</button>${done?'':`<button class="account-button checkin-button" data-action="checkin" data-id="${a.id}" ${state.server_busy?'disabled':''}>${icon('moon')}立即打卡</button>`}<button class="account-button edit-button" data-action="edit" data-id="${a.id}">编辑</button>${detailed?`<button class="account-delete" data-action="delete" data-id="${a.id}" aria-label="删除 ${esc(a.name)}" title="删除账号">${icon('trash-2')}</button>`:''}</div></div></article>`;
  }).join('');
  root.querySelectorAll('[data-action]').forEach(el=>el.addEventListener('click',()=>accountAction(el.dataset.id,el.dataset.action)));
}
function nextPlan(){
  const cfg=state.settings, day=schoolDate(current()), enabled=state.accounts.filter(a=>a.enabled);
  if(!cfg.enabled)return ['未安排','自动打卡已关闭'];
  if(!enabled.length)return ['未安排','请先启用账号'];
  const clock=new Intl.DateTimeFormat('en-GB',{timeZone:'Asia/Shanghai',hour:'2-digit',minute:'2-digit',hour12:false}).format(current());
  const allDone=enabled.every(a=>a.state?.success_date===day);
  if(clock>=cfg.window_end || allDone)return [cfg.time,'明天（预计）'];
  const eligible=enabled.filter(a=>a.state?.success_date!==day && !(a.state?.attempt_date===day && a.state?.attempt_count>=cfg.max_attempts));
  if(!eligible.length)return ['已结束','请查看打卡记录'];
  const cutoff=new Date(`${day}T${cfg.window_end}:00+08:00`).getTime();
  const waits=eligible.map(a=>{const retry=a.state?.attempt_date===day;return {retry,at:new Date(retry?a.next_retry_at:a.planned_checkin_at).getTime()};}).filter(x=>Number.isFinite(x.at)&&x.at<cutoff).sort((a,b)=>a.at-b.at);
  if(!waits.length)return ['已结束','今日不再重试'];
  const next=waits[0];
  if(next.at>Date.now()+serverOffset)return [new Date(next.at).toLocaleTimeString('en-GB',{timeZone:'Asia/Shanghai',hour:'2-digit',minute:'2-digit',second:'2-digit'}),next.retry?'下次重试':'今天'];
  return ['即将执行','正在等待执行'];
}
function render(){
  renderedDay=schoolDate(current());
  const day=schoolDate(current()), enabled=state.accounts.filter(a=>a.enabled), confirmed=state.accounts.filter(a=>a.state?.success_date===day);
  $('#stat-success').textContent=confirmed.length;$('#stat-total').textContent=`/ ${state.accounts.length} 个账号`;$('#account-count').textContent=state.accounts.length;
  const [time,note]=nextPlan();$('#stat-next').textContent=time;$('#stat-next-note').textContent=note;
  $('#stat-auto').textContent=state.settings.enabled?'已开启':'已关闭';$('#auto-pill').textContent=state.settings.enabled?'每天':'手动';$('#auto-pill').classList.toggle('on',state.settings.enabled);
  $('#stat-window').textContent=`最晚重试至 ${state.settings.window_end}`;
  $('#hero-title').textContent=state.busy?(state.busy.action==='probe'?'正在检查登录':'正在打卡'):!state.accounts.length?'暂无打卡账号':state.settings.enabled?`每天 ${state.settings.time} 左右打卡`:'自动打卡已关闭';
  const heroSummary=state.busy?state.busy.name:state.accounts.length&&state.settings.enabled?`${enabled.length} 个账号参与自动打卡`:'';
  $('#hero-summary').textContent=heroSummary;
  $('#hero-summary').classList.toggle('hidden',!heroSummary);
  $('#hero-action').innerHTML=icon(!state.accounts.length?'user-plus':'calendar-clock')+(!state.accounts.length?'添加账号':state.settings.enabled?'修改设置':'设置自动打卡');
  renderAccounts('#overview-accounts');renderAccounts('#all-accounts',true);
  const rows=state.events.map(e=>`<tr><td>${esc(prettyTime(e.at))}</td><td>${esc(e.name)}</td><td>${e.action==='probe'?'检查登录':'打卡'}</td><td>${badge(e.outcome)}</td><td>${esc(e.message)}</td></tr>`).join('');
  $('#history-rows').innerHTML=rows||'<tr><td colspan="5"><div class="empty-state">暂无打卡记录</div></td></tr>';
  $('#recent-records').innerHTML=state.events.slice(0,3).map(e=>`<div class="recent-row"><span class="recent-time">${esc(prettyTime(e.at))}</span><strong>${esc(e.name)}</strong><span>${e.action==='probe'?'检查登录':'打卡'}</span>${badge(e.outcome)}</div>`).join('')||'<div class="empty-state">暂无记录</div>';
  const warning=$('#connection-warning');
  if(!state.scheduler_running||state.scheduler_error){warning.textContent='自动打卡暂不可用，请稍后重试。';warning.classList.remove('hidden');}else warning.classList.add('hidden');
}
function fillSettings(){const form=$('#schedule-form');Object.entries(state.settings).forEach(([k,v])=>{const el=form.elements.namedItem(k);if(el){if(el.type==='checkbox')el.checked=v;else el.value=v;}});}
async function load(initial=false){
  if(polling)return;polling=true;
  try{const oldBusy=state?.busy;state=await api('/api/state');serverOffset=new Date(state.server_time).getTime()-Date.now();render();if(initial && !scheduleDirty)fillSettings();if(oldBusy&&!state.busy){const result=state.accounts.find(a=>a.id===oldBusy.account_id)?.state;toast(result?.last_message||'已完成',!['success','already_done','connected'].includes(result?.last_outcome));}}
  catch(e){$('#connection-warning').textContent='连接已断开，正在重连…';$('#connection-warning').classList.remove('hidden');if(initial)toast(e.message,true);}
  finally{polling=false;}
}
$('#refresh').addEventListener('click',async()=>{const btn=$('#refresh'),done=buttonBusy(btn,'刷新中…');try{await load();}finally{done();}});
async function logout(){try{await api('/api/logout','POST',{});scheduleDirty=false;notificationDirty=false;location.assign('/login');}catch(e){toast(e.message,true);}}
['#logout','#logout-mobile'].forEach(selector=>$(selector).addEventListener('click',()=>{if(scheduleDirty||notificationDirty)confirmAction('退出登录？','还有未保存的修改。',logout,'退出登录');else logout();}));
setInterval(()=>{
  const instant=current();
  $('#clock').textContent=instant.toLocaleTimeString('en-GB',{timeZone:'Asia/Shanghai',hour:'2-digit',minute:'2-digit',hour12:false});
  if(state&&renderedDay!==schoolDate(instant)){render();load();}
},1000);
document.addEventListener('visibilitychange',()=>{if(!document.hidden&&state){render();load();}});
setInterval(()=>load(),4000);
$$('.add-account').forEach(el=>el.addEventListener('click',()=>editAccount()));
const accountDialog=$('#account-dialog'), accountForm=$('#account-form');
function editAccount(id){
  if(!state)return;
  accountForm.reset();$('#account-error').classList.add('hidden');$('#dialog-title').textContent=id?'编辑账号':'添加账号';$('#password-hint').textContent='';$('#fingerprint-hint').textContent='';
  $('#account-preset').innerHTML='<option value="">请选择系统预设</option>'+state.presets.filter(p=>p.enabled).map(p=>`<option value="${esc(p.id)}">${esc(p.name)}</option>`).join('');
  positionMeta={browser_location:false,location_duration_ms:0};
  if(id){const a=state.accounts.find(a=>a.id===id);Object.entries(a).forEach(([k,v])=>{const el=accountForm.elements.namedItem(k);if(el){if(el.type==='checkbox')el.checked=v;else el.value=v??'';}});accountForm.elements.namedItem('location_mode').value=a.location_mode||'manual';$('#password-hint').textContent=a.has_password?'（留空则不修改）':'';$('#fingerprint-hint').textContent=a.has_fingerprint?'（留空则不修改）':'';positionMeta={browser_location:a.browser_location,location_duration_ms:a.location_duration_ms||0};}
  updateLocationMode();$('#location-note').textContent='请确认位置无误。';accountDialog.showModal();accountDialog.scrollTop=0;accountBaseline=formSnapshot(accountForm);
}
function updateLocationMode(){
  const preset=accountForm.elements.namedItem('location_mode').value==='preset';
  $('#preset-location-fields').classList.toggle('hidden',!preset);$('#manual-location-fields').classList.toggle('hidden',preset);
  $('#manual-location-fields').querySelectorAll('input,select,button').forEach(el=>el.disabled=preset);
  $('#account-preset').disabled=!preset;$('#account-preset').required=preset;
  const p=state?.presets.find(p=>p.id===$('#account-preset').value && p.enabled);
  $('#preset-preview').textContent=p?`${p.latitude}, ${p.longitude} · ${p.coordinate_system.toUpperCase()}`:state?.presets.some(p=>p.enabled)?'请选择预设位置。':'暂无预设，可先手动填写或联系管理员添加。';
}
$$('input[name="location_mode"]').forEach(el=>el.addEventListener('change',updateLocationMode));
$('#account-preset').addEventListener('change',updateLocationMode);
$$('.close-dialog').forEach(el=>el.addEventListener('click',()=>requestClose(accountDialog,accountForm,accountBaseline)));
accountDialog.addEventListener('cancel',e=>{e.preventDefault();requestClose(accountDialog,accountForm,accountBaseline);});
['latitude','longitude','coordinate_system'].forEach(k=>accountForm.elements.namedItem(k).addEventListener('input',()=>{positionMeta={browser_location:false,location_duration_ms:0};}));
accountForm.addEventListener('submit',async e=>{
  e.preventDefault();const data=Object.fromEntries(new FormData(accountForm));
  data.enabled=accountForm.elements.enabled.checked;
  Object.assign(data,positionMeta);const btn=accountForm.querySelector('[type=submit]');const restore=buttonBusy(btn,'保存中…');
  try{await api('/api/accounts','POST',data);accountDialog.close();await load();toast('已保存');}
  catch(e){$('#account-error').textContent=e.message;$('#account-error').classList.remove('hidden');$('#account-error').scrollIntoView({behavior:'smooth',block:'nearest'});}
  finally{restore();}
});
$('#schedule-form').addEventListener('input',()=>{scheduleDirty=true;$('#schedule-unsaved').classList.remove('hidden');});
$('#schedule-form').addEventListener('submit',async e=>{
  e.preventDefault();const form=e.currentTarget,data=Object.fromEntries(new FormData(form));data.enabled=form.elements.enabled.checked;
  const restore=buttonBusy(form.querySelector('[type=submit]'),'保存中…');
  try{await api('/api/settings','POST',data);scheduleDirty=false;$('#schedule-unsaved').classList.add('hidden');await load();toast('已保存');}catch(e){toast(e.message,true);}finally{restore();}
});
let confirmCallback=null;
function notificationStatus(config){
  if(!config.enabled)return '未开启';
  if(config.last_status==='sent')return `最近推送成功 · ${prettyTime(config.last_at)}`;
  if(config.last_status==='failed')return '最近推送失败，可发送测试查看原因';
  return '已开启';
}
function fillNotifications(config){
  const form=$('#notification-form');
  form.elements.enabled.checked=config.enabled;
  form.elements.webhook.value=config.webhook||'';
  form.elements.webhook.required=config.enabled;
  form.elements.secret.value='';form.elements.secret.disabled=false;
  form.elements.clear_secret.checked=false;
  $('#notification-clear-secret').classList.toggle('hidden',!config.has_secret);
  $('#notification-secret-hint').textContent=config.has_secret?'（已保存，留空不修改）':'（选填）';
  $('#notification-status').textContent=notificationStatus(config);
  $('#notification-test').disabled=!config.enabled;
}
async function loadNotifications(){
  try{const config=await api('/api/notifications');if(!notificationDirty)fillNotifications(config);}
  catch(e){$('#notification-status').textContent='推送设置加载失败，请稍后重试';}
}
$('#notification-form').addEventListener('input',()=>{
  notificationDirty=true;
  const form=$('#notification-form');
  form.elements.webhook.required=form.elements.enabled.checked;
  form.elements.secret.disabled=form.elements.clear_secret.checked;
  $('#notification-status').textContent='有未保存的修改';
  $('#notification-test').disabled=true;
});
$('#notification-form').addEventListener('submit',async e=>{
  e.preventDefault();const form=e.currentTarget,data=Object.fromEntries(new FormData(form));
  data.enabled=form.elements.enabled.checked;data.clear_secret=form.elements.clear_secret.checked;
  const restore=buttonBusy(form.querySelector('[type=submit]'),'保存中…');
  try{const config=await api('/api/notifications','POST',data);notificationDirty=false;fillNotifications(config);toast('推送设置已保存');}
  catch(e){toast(e.message,true);}finally{restore();}
});
$('#notification-test').addEventListener('click',async()=>{
  if(notificationDirty){toast('请先保存推送设置');return;}
  const restore=buttonBusy($('#notification-test'),'发送中…');
  try{await api('/api/notifications/test','POST',{});await loadNotifications();toast('测试消息已发送');}
  catch(e){$('#notification-status').textContent=e.message;toast(e.message,true);}finally{restore();}
});
function confirmAction(title,message,callback,label='确认',danger=false){$('#confirm-title').textContent=title;$('#confirm-message').textContent=message;$('#confirm-ok').textContent=label;$('#confirm-ok').classList.toggle('destructive',danger);confirmCallback=callback;$('#confirm-dialog').showModal();}
$$('.cancel-confirm').forEach(el=>el.addEventListener('click',()=>{$('#confirm-dialog').close();confirmCallback=null;}));
$('#confirm-ok').addEventListener('click',()=>{const cb=confirmCallback;confirmCallback=null;$('#confirm-dialog').close();if(cb)cb();});
async function accountAction(id,action){
  const a=state.accounts.find(a=>a.id===id);
  if(action==='edit'){editAccount(id);return;}
  const run=async()=>{try{await api(`/api/accounts/${id}/${action}`,'POST',{confirm:true});await load();toast(action==='probe'?'正在检查登录…':'正在打卡…');}catch(e){toast(e.message,true);}};
  if(action==='probe')return run();
  if(action==='delete')return confirmAction('删除账号',`删除“${a.name}”？打卡记录会保留。`,async()=>{try{await api('/api/accounts/'+id,'DELETE');await load();toast('已删除');}catch(e){toast(e.message,true);}},'删除',true);
  if(a.location_unavailable){toast('预设已停用，请更换位置后再打卡。',true);return;}
  confirmAction('确认打卡',`账号：${a.name}\n位置：${a.location_mode==='preset'?(a.preset_name||'系统预设'):'手动填写'}\n坐标：${a.latitude}, ${a.longitude}${state.settings.location_jitter_meters>0?'\n位置最多浮动 '+state.settings.location_jitter_meters+' 米。':''}\n\n确认使用此位置打卡？`,run,'确认打卡');
}

async function loadAdmin(){
  if(!isAdmin)return;
  try{
    adminState=await api('/api/admin/state');
    $('#registration-enabled').checked=adminState.registration_enabled;
    $('#admin-users').innerHTML=adminState.users.map(u=>`<tr><td>${esc(u.username)}</td><td>${u.role==='superadmin'?'总管理员':'普通用户'}</td><td>${u.account_count}</td><td>${esc(prettyTime(u.created_at))}</td><td>${u.role==='superadmin'?badge('connected','已启用'):`${badge(u.active?'connected':'failed',u.active?'已启用':'已停用')} <button class="text-button" data-user-toggle="${u.id}">${u.active?'停用':'启用'}</button>`}</td></tr>`).join('');
    $('#admin-users').querySelectorAll('[data-user-toggle]').forEach(btn=>btn.addEventListener('click',()=>{
      const u=adminState.users.find(u=>u.id===btn.dataset.userToggle);
      confirmAction(u.active?'停用用户':'启用用户',`${u.active?'停用':'启用'}“${u.username}”？${u.active?'停用后将无法登录，自动打卡也会暂停。':''}`,async()=>{try{await api(`/api/admin/users/${u.id}/active`,'POST',{active:!u.active});await loadAdmin();toast('已更新');}catch(e){toast(e.message,true);}});
    }));
    $('#admin-presets').innerHTML=adminState.presets.length?adminState.presets.map(p=>`<article class="preset-card"><div class="preset-icon">${icon('map-pin')}</div><div class="preset-info"><strong>${esc(p.name)}</strong><small>${esc(p.latitude)}, ${esc(p.longitude)}<span>${esc(p.coordinate_system.toUpperCase())}</span></small></div><div class="preset-actions">${p.enabled?'':badge('failed','已停用')}<button class="preset-edit" data-preset-edit="${p.id}" aria-label="编辑预设 ${esc(p.name)}">编辑预设</button></div></article>`).join(''):'<div class="empty-state"><h3>暂无预设位置</h3><p>点击“添加预设”创建位置。</p></div>';
    $('#admin-presets').querySelectorAll('[data-preset-edit]').forEach(btn=>btn.addEventListener('click',()=>editPreset(btn.dataset.presetEdit)));
  }catch(e){toast(e.message,true);}
}
function editPreset(id){
  const f=$('#preset-form');f.reset();$('#preset-error').classList.add('hidden');$('#preset-title').textContent=id?'编辑预设':'添加预设';
  if(id){const p=adminState.presets.find(p=>p.id===id);Object.entries(p).forEach(([k,v])=>{const el=f.elements.namedItem(k);if(el){if(el.type==='checkbox')el.checked=v;else el.value=v;}});}
  $('#preset-dialog').showModal();$('#preset-dialog').scrollTop=0;presetBaseline=formSnapshot(f);
}
if(isAdmin){
  $('#admin-refresh').addEventListener('click',async()=>{const restore=buttonBusy($('#admin-refresh'),'刷新中…');try{await loadAdmin();}finally{restore();}});
  $('#new-preset').addEventListener('click',()=>editPreset());
  $$('.close-preset').forEach(btn=>btn.addEventListener('click',()=>requestClose($('#preset-dialog'),$('#preset-form'),presetBaseline)));
  $('#preset-dialog').addEventListener('cancel',e=>{e.preventDefault();requestClose($('#preset-dialog'),$('#preset-form'),presetBaseline);});
  $('#registration-enabled').addEventListener('change',async e=>{const enabled=e.target.checked;try{await api('/api/admin/registration','POST',{enabled});toast(enabled?'已开放注册':'已关闭注册');}catch(err){e.target.checked=!enabled;toast(err.message,true);}});
  $('#preset-form').addEventListener('submit',async e=>{e.preventDefault();const f=e.currentTarget,d=Object.fromEntries(new FormData(f));d.enabled=f.elements.enabled.checked;const btn=f.querySelector('[type=submit]'),restore=buttonBusy(btn,'保存中…');try{await api('/api/admin/presets','POST',d);$('#preset-dialog').close();await loadAdmin();await load();toast('已保存');}catch(err){$('#preset-error').textContent=err.message;$('#preset-error').classList.remove('hidden');}finally{restore();}});
}
// WGS84 → GCJ02: keep non-China coordinates unchanged. Standard offset formula.
function wgsToGcj(lng,lat){
  if(lng<72.004||lng>137.8347||lat<0.8293||lat>55.8271)return [lng,lat];
  const pi=Math.PI, x=lng-105,y=lat-35;
  let dLat=-100+2*x+3*y+.2*y*y+.1*x*y+.2*Math.sqrt(Math.abs(x));
  dLat+=(20*Math.sin(6*x*pi)+20*Math.sin(2*x*pi))*2/3;
  dLat+=(20*Math.sin(y*pi)+40*Math.sin(y/3*pi))*2/3;
  dLat+=(160*Math.sin(y/12*pi)+320*Math.sin(y*pi/30))*2/3;
  let dLng=300+x+2*y+.1*x*x+.1*x*y+.1*Math.sqrt(Math.abs(x));
  dLng+=(20*Math.sin(6*x*pi)+20*Math.sin(2*x*pi))*2/3;
  dLng+=(20*Math.sin(x*pi)+40*Math.sin(x/3*pi))*2/3;
  dLng+=(150*Math.sin(x/12*pi)+300*Math.sin(x/30*pi))*2/3;
  const rad=lat*pi/180, magic=1-.00669342162296594323*Math.sin(rad)**2, root=Math.sqrt(magic);
  dLat=dLat*180/((6378245*(1-.00669342162296594323))/(magic*root)*pi);
  dLng=dLng*180/(6378245/root*Math.cos(rad)*pi);
  return [lng+dLng,lat+dLat];
}
$('#locate').addEventListener('click',()=>{
  if(!navigator.geolocation){toast('浏览器不支持定位，请手动输入实际坐标',true);return;}
  const btn=$('#locate'), start=performance.now();btn.disabled=true;btn.innerHTML=icon('loader-circle')+'定位中…';
  navigator.geolocation.getCurrentPosition(pos=>{
    const [lng,lat]=wgsToGcj(pos.coords.longitude,pos.coords.latitude);
    accountForm.elements.latitude.value=lat.toFixed(7);accountForm.elements.longitude.value=lng.toFixed(7);accountForm.elements.coordinate_system.value='gcj02';accountForm.elements.accuracy.value=Math.round(pos.coords.accuracy);
    positionMeta={browser_location:true,location_duration_ms:Math.round(performance.now()-start)};
    $('#location-note').textContent=`定位成功，精度约 ${Math.round(pos.coords.accuracy)} 米。请核对位置。`;
    btn.disabled=false;btn.innerHTML=icon('locate-fixed')+'获取当前位置';
  },err=>{toast(({1:'定位权限被拒绝，请允许定位或手动输入坐标',2:'无法获取位置，请手动输入实际坐标',3:'定位超时，请重试或手动输入坐标'})[err.code]||'定位失败',true);btn.disabled=false;btn.innerHTML=icon('locate-fixed')+'获取当前位置';},{enableHighAccuracy:true,timeout:20000,maximumAge:0});
});
window.addEventListener('beforeunload',e=>{if(scheduleDirty || notificationDirty || (accountDialog.open && formSnapshot(accountForm)!==accountBaseline) || (isAdmin && $('#preset-dialog').open && formSnapshot($('#preset-form'))!==presetBaseline)){e.preventDefault();e.returnValue='';}});
go(Object.hasOwn(titles,location.hash.slice(1))?location.hash.slice(1):'overview');
load(true);
loadNotifications();
