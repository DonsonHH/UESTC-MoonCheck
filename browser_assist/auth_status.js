() => {
  const visible=e=>e&&e.getClientRects().length>0&&getComputedStyle(e).visibility!=='hidden'&&getComputedStyle(e).display!=='none';
  const text=(document.body?.innerText||'').replace(/\s+/g,' ').trim();
  const username=[...document.querySelectorAll('#username')].some(visible),password=[...document.querySelectorAll('#password')].some(visible);
  const rejection=/(?:用户名|学号|账号|帐号|用户名称)[\s\/、或与及]*(?:密码)?(?:不正确|错误|有误|不存在|无效)|(?:用户名|账号|帐号)(?:或|\/|、)(?:密码)(?:不正确|错误|有误)|密码(?:不正确|错误|有误)|用户不存在/;
  const tips=[...document.querySelectorAll('#showErrorTip,#msg,#errorMsg,.auth_error,.authErrorMessage,.login-error,.item-error-tip')].filter(visible).map(e=>e.innerText).join(' ');
  const rejected=(username||password)&&rejection.test(tips+' '+text);
  const slider=document.querySelector('#sliderCaptchaDiv');
  const captcha=[...document.querySelectorAll('#captcha')].some(visible)||!!slider&&[...slider.querySelectorAll('*')].some(e=>visible(e)&&!['SCRIPT','STYLE'].includes(e.tagName));
  const mfaPath=/reAuthLoginView|reAuthCheck|authLogin|multifactor|\/mfa/i.test(location.pathname);
  const verification=mfaPath||!password&&/二次验证|多因素认证|信任此浏览器|信任该浏览器/.test(text);
  let student_name='',student_name_source='';
  if(verification&&(!password||mfaPath)&&location.hostname==='idas.uestc.edu.cn') {
    const exact=[...document.querySelectorAll('[data-student-name],#userName,.user-name,.account-name')].filter(visible).map(e=>e.getAttribute('data-student-name')||e.innerText);
    const greeting=text.match(/(?:你好|您好|你好呀)[，,\s]+([\p{L}·•'’ -]{2,40}?)(?=[，,！!。\s]|$)/u);
    const labelled=text.match(/(?:学生姓名|姓名)[：:\s]+([\p{L}·•'’ -]{2,40}?)(?=[，,！!。\s]|$)/u);
    for(const candidate of [...exact,greeting?.[1],labelled?.[1]]) {
      const name=(candidate||'').trim().replace(/(?:同学|老师)\s*$/,'').trim();
      if(name.length>=2&&name.length<=40&&/^[\p{L}][\p{L}·•'’ -]*$/u.test(name)&&!['同学','用户','姓名','学生姓名','学校验证','统一身份认证','测试用户'].includes(name)){student_name=name;student_name_source='school_mfa_greeting';break;}
    }
  }
  return {phase:rejected?'rejected':verification?'verification':captcha?'challenge':'pending',student_name,student_name_source};
}
