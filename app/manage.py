"""Offline administration. Stop run.py before using this tool."""
import getpass
import os
import secrets
from pathlib import Path
from werkzeug.security import generate_password_hash
from storage import Store

if __name__ == '__main__':
    print('请先停止 MoonCheck 服务。此操作只重置管理密码，不更改学校密码。')
    pwd = getpass.getpass('新的管理密码（至少 12 位）: ')
    if len(pwd) < 12 or len(pwd) > 256 or pwd != getpass.getpass('再次输入: '):
        raise SystemExit('密码长度不符或两次输入不同，未做更改。')
    store = Store(os.environ.get('MOONCHECK_DATA_DIR') or Path(__file__).parent / 'data')
    root = next((u for u in store.users() if u['role'] == 'superadmin'), None)
    if not root:
        raise SystemExit('尚无总管理员，请通过网页完成首次设置。')
    with store.db() as db:
        db.execute('UPDATE users SET password_hash=?,auth_version=auth_version+1 WHERE id=?', (generate_password_hash(pwd), root['id']))
    store.set('session_secret', secrets.token_hex(32))
    print('管理密码已重置。重新启动服务后旧登录会话失效。')
