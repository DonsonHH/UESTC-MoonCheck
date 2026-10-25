import {spawn,execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
const configuration=fileURLToPath(new URL('./admin-ssh.config',import.meta.url));
const position=process.argv.indexOf('--port'),port=position<0?4497:Number(process.argv[position+1]);
if(!Number.isInteger(port)||port<1024||port>65535)throw Error('Invalid local port');
const address='http://127.0.0.1:'+port,connectOnly=process.argv.includes('--connect-only');
if(process.argv.includes('--check')){
 const config=execFileSync('ssh.exe',['-G','-F',configuration,'moonuestc-admin'],{encoding:'utf8',windowsHide:true});
 if(!config.includes('batchmode yes')||!config.includes('identitiesonly yes')||!config.includes('stricthostkeychecking true'))throw Error('Private forwarding configuration is invalid');
 console.log('PASS: dedicated key, pinned host, noninteractive Tailscale forwarding');
}else{
 const ready=async()=>{try{const response=await fetch(address+'/api/interface',{signal:AbortSignal.timeout(1500)});return response.ok&&(await response.json()).adminInterface===true}catch{return false}};
 let tunnel;
 try{
  if(!await ready()){
   tunnel=spawn('ssh.exe',['-N','-T','-F',configuration,'-L',`127.0.0.1:${port}:127.0.0.1:4497`,'moonuestc-admin'],{detached:true,windowsHide:true,stdio:'ignore'});
   const until=Date.now()+30000;
   while(!await ready()&&Date.now()<until&&tunnel.exitCode===null)await new Promise(resolve=>setTimeout(resolve,300));
   if(!await ready())throw Error('Private administration is unreachable. Check Tailscale and the forwarding key.');
   tunnel.unref();
  }
  if(connectOnly)console.log(JSON.stringify({ready:true,port,helperPid:tunnel?.pid||null}));
  else spawn(path.join(process.env.SystemRoot,'System32','rundll32.exe'),['url.dll,FileProtocolHandler',address+'/admin'],{detached:true,windowsHide:true,stdio:'ignore'}).unref();
 }catch(error){
  tunnel?.kill();
  if(connectOnly)throw error;
  execFileSync('powershell.exe',['-NoProfile','-NonInteractive','-Command',"Add-Type -AssemblyName PresentationFramework; [Windows.MessageBox]::Show('请先连接 Tailscale，并检查专用转发密钥。','MoonUESTC 管理中心') | Out-Null"],{windowsHide:true,stdio:'ignore'});process.exitCode=1;
 }
}
