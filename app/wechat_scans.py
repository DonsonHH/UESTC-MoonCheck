import secrets
import threading
import time
import logging
import copy
from wechat import WechatPortal
from portal import PortalError
log=logging.getLogger(__name__)


class ScanManager:
    def __init__(self, service):
        self.service = service
        self.store = service.store
        self.bridge = service.auth
        self.lock = threading.RLock()
        self.scans = {}
        self.closed = threading.Event()

    def start(self, owner, target=None):
        # Reserve before network calls, so concurrent clicks cannot bypass limits.
        with self.lock:
            for ident, scan in list(self.scans.items()):
                if (scan['draft']['expires']<=time.monotonic() if scan.get('draft') else time.monotonic()-scan['created'] >= 300):
                    del self.scans[ident]
                elif scan['owner'] == owner:
                    scan.update(terminal=True, message='扫码已取消', status='cancelled')
                    del self.scans[ident]
            if len(self.scans) >= 32:
                raise ValueError('扫码人数较多，请稍后重试。')
            scan = dict(id=secrets.token_hex(16), owner=owner, target=target, created=time.monotonic(),
                        terminal=False, status='pending', message='正在生成二维码', image='')
            self.scans[scan['id']] = scan
        try:
            qr = self.bridge.call('start')
            with self.lock:
                scan.update(qr=qr['qr'], image=qr['image'], message='请用已绑定学校账号的微信扫码并确认授权')
            threading.Thread(target=self._poll, args=(scan,), daemon=True).start()
        except Exception:
            with self.lock:
                scan.update(terminal=True, status='failed', message='二维码获取失败，请稍后重试。')
            raise ValueError('二维码获取失败，请稍后重试。') from None
        return self.get(owner, scan['id'])

    def _live(self, scan):
        return not self.closed.is_set() and not scan['terminal'] and time.monotonic()-scan['created'] < 300

    def get(self, owner, ident):
        with self.lock:
            scan = self.scans.get(ident)
            if not scan or scan['owner'] != owner:
                raise KeyError('scan')
            if not scan['terminal'] and not self._live(scan):
                scan.update(terminal=True, status='expired', message='二维码已过期，请重新扫码。')
            result={k:scan.get(k) for k in ('id','terminal','status','message','image')}
            if scan.get('draft'):
                a=scan['draft']['account']
                profile={k:a.get(k) for k in ('name','student_id','enabled','location_mode','preset_id','latitude','longitude','accuracy','coordinate_system')}
                profile.update(id=scan['target'] or '',has_password=bool(a.get('password')))
                result.update(draft_id=ident,account=profile)
            return result

    def draft(self, owner, ident):
        with self.lock:
            scan=self.scans.get(ident)
            if not scan or scan['owner']!=owner:raise KeyError('scan')
            draft=scan.get('draft')
            if not draft or time.monotonic()>draft['expires']:raise ValueError('扫码信息已过期，请重新扫码。')
            return copy.deepcopy(draft)

    def consume(self, owner, ident):
        with self.lock:
            scan=self.scans.get(ident)
            if scan and scan['owner']==owner:scan.pop('draft',None)

    def cancel(self, owner, ident):
        with self.lock:
            self.get(owner, ident)
            self.scans[ident].pop('draft',None)
            self.scans[ident].update(terminal=True,status='cancelled',message='扫码已取消',image='')

    def _poll(self, scan):
        portal = None
        stage='scan'
        try:
            while self._live(scan):
                result = self.bridge.call('poll', qr=scan['qr'])
                if not self._live(scan):
                    return
                status = result.get('status')
                if status in ('authorized','confirmed'):
                    break
                if status not in ('pending','scanned'):
                    raise ValueError('二维码已取消或过期，请重新扫码。')
                with self.lock:
                    scan['message'] = '已扫码，请在微信确认' if status=='scanned' else '请用已绑定学校账号的微信扫码并确认授权'
                self.closed.wait(.5)
            else:
                return
            stage='exchange'
            credentials = self.bridge.call('exchange', qr=scan['qr'])
            if not credentials.get('openid') or not credentials.get('accesstoken'):
                raise ValueError('微信授权信息不完整，请重新扫码。')
            credentials['refresh_token_observed_at'] = int(time.time())
            target = self.store.account(scan['target']) if scan['target'] else None
            if target and target['owner_id'] != scan['owner']:
                raise ValueError('原账号不存在。')
            if target and target.get('wx_credentials',{}).get('openid') != credentials['openid']:
                raise ValueError('扫码微信与原账号不一致，未修改原账号。')
            candidate = dict(target or {}, wx_credentials=credentials)
            self.bridge.call('forget', credentials=credentials)
            with self.lock:
                scan['message'] = '已授权，正在核对学校账号'
            portal = WechatPortal(candidate, self.bridge, lambda a:None)
            stage='code_and_bind'
            user = portal.bind()
            with self.service.gate:
                with self.lock:
                    owner = self.store.user(uid=scan['owner'])
                    if not self._live(scan) or not owner or not owner['active']:
                        return
                    if target:
                        a = self.store.account(target['id'])
                        if a['owner_id']!=scan['owner'] or a['student_id']!=user['username']:
                            raise ValueError('账号信息已变化，请重新扫码。')
                    else:
                        a = dict(id=secrets.token_hex(8), owner_id=scan['owner'], state={},
                                 name=user['fullName'][:40], student_id=user['username'], enabled=True,
                                 location_mode='preset', preset_id='', coordinate_system='gcj02', accuracy=50)
                    for other in self.store.accounts():
                        if other['id']!=a['id'] and (other.get('student_id')==user['username'] or other.get('school_user_id')==user['id'] or other.get('wx_credentials',{}).get('openid')==credentials['openid']):
                            raise ValueError('该账号已添加。')
                    a.update(auth_mode='wechat',school_user_id=user['id'],wx_credentials=candidate['wx_credentials'])
                    scan['draft']=dict(account=a,target=scan['target'],expires=time.monotonic()+1200)
                    scan.update(terminal=True,status='completed',message='请填写账号信息。',image='')
        except (ValueError, PortalError) as exc:
            code=getattr(exc,'code',getattr(exc,'auth_code','validation_failed'))
            log.warning('WeChat authorization failed stage=%s code=%s',stage,code)
            with self.lock:
                if self._live(scan):
                    scan.update(terminal=True,status='failed',message=str(exc),image='')
        except Exception:
            with self.lock:
                if self._live(scan):
                    scan.update(terminal=True,status='failed',message='授权未完成，请重新扫码。',image='')
        finally:
            if portal:
                portal.close()
            if scan.get('qr'):
                try:
                    self.bridge.call('cancel', qr=scan['qr'])
                except Exception:
                    pass
            with self.lock:
                if not scan['terminal']:
                    scan.update(terminal=True,status='expired',message='二维码已过期，请重新扫码。',image='')

    def close(self):
        self.closed.set()
        with self.lock:
            for scan in self.scans.values():
                scan['terminal'] = True
