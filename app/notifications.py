"""Per-user Feishu delivery, independent of school requests."""
import base64
import hashlib
import hmac
import logging
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from urllib.parse import urlsplit

import requests

log = logging.getLogger(__name__)


class NotificationError(ValueError):
    pass


def validate_webhook(value):
    value = str(value or '').strip()
    if not value:
        return ''
    try:
        url = urlsplit(value)
        valid = (url.scheme == 'https' and url.hostname == 'open.feishu.cn'
                 and url.port in (None, 443) and not url.username and not url.password
                 and not url.query and not url.fragment
                 and re.fullmatch(r'/open-apis/bot/v2/hook/[A-Za-z0-9_-]{8,200}', url.path)
                 and not any(c.isspace() for c in value))
    except ValueError:
        valid = False
    if not valid:
        raise NotificationError('请填写完整的飞书机器人 Webhook 地址。')
    return value


def send_feishu(config, text):
    webhook = validate_webhook(config.get('webhook'))
    if not webhook:
        raise NotificationError('请先填写并保存推送地址。')
    payload = {'msg_type': 'text', 'content': {'text': text}}
    secret = config.get('secret', '')
    if secret:
        timestamp = str(int(time.time()))
        key = (timestamp + '\n' + secret).encode('utf-8')
        payload.update(timestamp=timestamp, sign=base64.b64encode(hmac.new(key, b'', hashlib.sha256).digest()).decode())
    try:
        response = requests.post(webhook, json=payload, timeout=(3, 7), allow_redirects=False)
        if response.status_code != 200:
            raise NotificationError('飞书推送失败，请稍后重试。')
        result = response.json()
    except (requests.RequestException, ValueError) as exc:
        if isinstance(exc, NotificationError):
            raise
        raise NotificationError('暂时无法连接飞书，请稍后重试。') from None
    code = result.get('code', result.get('StatusCode')) if isinstance(result, dict) else None
    if type(code) is not int or code != 0:
        if code == 19021:
            raise NotificationError('签名校验失败，请检查签名密钥和服务器时间。')
        raise NotificationError('飞书未接收消息，请检查机器人的安全设置。')


def result_text(account, outcome, message, at):
    label = {'success': '打卡成功', 'already_done': '今日已打卡', 'pending': '结果待确认',
             'preparation_success': '提前检查成功', 'preparation_failed': '提前检查失败',
             'wechat_expired':'微信授权失效','wechat_refresh_failed':'微信授权刷新失败',
             'wechat_recovered':'微信授权已恢复'}.get(outcome, '打卡失败')
    when = datetime.fromisoformat(at).strftime('%Y-%m-%d %H:%M:%S')
    return f"MoonCheck · {label}\n账号：{account['name']}\n时间：{when}\n结果：{message}"


class NotificationDispatcher:
    def __init__(self, store, sender=None):
        self.store = store
        self.sender = sender or send_feishu
        self.executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix='mooncheck-notify')
        self.slots = threading.BoundedSemaphore(16)

    def enqueue(self, account, outcome, message, at):
        uid = account.get('owner_id')
        if not uid or not self.store.notification_settings(uid)['enabled']:
            return
        if not self.slots.acquire(blocking=False):
            self.store.notification_status(uid, 'failed')
            return
        try:
            self.executor.submit(self._deliver, uid, result_text(account, outcome, message, at))
        except Exception:
            self.slots.release()
            self.store.notification_status(uid, 'failed')

    def _deliver(self, uid, text):
        try:
            owner = self.store.user(uid=uid)
            config = self.store.notification_settings(uid)
            if not owner or not owner['active'] or not config['enabled']:
                return
            self.sender(config, text)
            self.store.notification_status(uid, 'sent')
        except Exception:
            # Never log webhook URLs, signing secrets or request exceptions.
            log.warning('Feishu delivery failed; school result unchanged')
            self.store.notification_status(uid, 'failed')
        finally:
            self.slots.release()

    def close(self):
        self.executor.shutdown(wait=True)
