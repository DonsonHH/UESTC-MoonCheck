"""Bounded, redacted diagnostic text for user-visible operation records."""
import re


def safe_text(value, *sources, limit=360):
    if not isinstance(value,str):return ''
    text=value[:8192]
    secrets=[]
    def collect(item, sensitive=False):
        if isinstance(item,dict):
            for key,val in item.items():
                private=sensitive or bool(re.search(r'password|fingerprint|token|cookie|session|ticket|openid|secret|^code$',str(key),re.I))
                collect(val,private)
        elif isinstance(item,(list,tuple)):
            for val in item:collect(val,sensitive)
        elif sensitive and isinstance(item,str) and len(item)>=4:secrets.append(item)
    for source in sources:collect(source)
    for secret in sorted(set(secrets),key=len,reverse=True):text=text.replace(secret,'[已隐藏]')
    text=re.sub(r'https?://[^\s<>]+','[链接已隐藏]',text,flags=re.I)
    text=re.sub(r'(?i)(password|token|session|cookie|ticket|authorization|openid|fingerprint|密码|票据值)\s*[=:：]\s*[^\s,，;；]+',r'\1=[已隐藏]',text)
    text=re.sub(r'[A-Za-z0-9_+/=-]{24,}','[已隐藏]',text)
    text=re.sub(r'<[^>]*>','',text)
    text=' '.join(''.join(c if c.isprintable() else ' ' for c in text).split())
    return text[:limit]+('…' if len(text)>limit else '')


STAGES={
 'auth/user-info':'核对学校身份','student-checkin-record/today':'查询今日记录',
 'checkin-schedule/effective':'读取打卡时段','checkin-location/available-locations':'读取打卡地点',
 'map/reverse':'获取位置描述','student-checkin-record/checkin':'提交打卡',
 'student-checkin-record/report':'提交填报','check-bind':'验证微信绑定',
 'user-info':'读取微信绑定身份','checkin-ticket':'获取打卡票据',
}
