'use strict';
document.querySelectorAll('[data-password]').forEach(button=>button.addEventListener('click',()=>{
  const field=document.getElementById(button.dataset.password), visible=field.type==='password';
  field.type=visible?'text':'password';
  button.setAttribute('aria-label',visible?'隐藏密码':'显示密码');
  button.setAttribute('aria-pressed',String(visible));
  button.querySelector('use').setAttribute('href','/static/icons.svg#'+(visible?'eye-off':'eye'));
}));
const authForm=document.getElementById('auth-form'), confirmPassword=document.getElementById('confirm-password');
if(confirmPassword){
  const validate=()=>confirmPassword.setCustomValidity(confirmPassword.value && confirmPassword.value!==document.getElementById('login-password').value?'两次密码不一致，请重新输入。':'');
  confirmPassword.addEventListener('input',validate);document.getElementById('login-password').addEventListener('input',validate);
}
authForm.addEventListener('submit',()=>{const button=authForm.querySelector('[type=submit]');button.disabled=true;button.textContent=button.textContent.trim()==='登录'?'登录中…':'提交中…';});
