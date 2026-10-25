"""Python implementation of the YYB login-code wire protocol.

Protocol reference: YYB-Go-Enhanced, revision 8a9497397abc.
Only login-code acquisition is implemented; no arbitrary mini-program operations.
Session keys and transport tickets are kept in memory only.
"""
import base64
import hashlib
import hmac
import http.client
import ipaddress
import secrets
import socket
import struct
import threading
import time
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

MAX_BODY = 2 * 1024 * 1024
HOST_APP = b'wxd44977328b36e647'
SCHOOL_APP = b'wxaa78bf2905f01cee'
SERVER_PUB = bytes.fromhex('04ef87876d6478b15f1796eab12068610541173b7176b67f1dcc86683e901acd44d18b4ac36938251d0812dd0cf842aa2d6cbb8115712d1c0087dcefc14a44cd58')
SALT = b'security hdkf expand'


class ProtocolError(ValueError):
    pass


def u16(n):return struct.pack('>H', n)
def u32(n):return struct.pack('>I', n)
def digest(data):return hashlib.sha256(data).digest()


def varint(n):
    if not 0 <= n < 1 << 64:raise ProtocolError('integer range')
    result=bytearray()
    while n>=128:result.append((n&127)|128);n>>=7
    result.append(n)
    return bytes(result)


def readvar(data, offset=0):
    value=0
    for shift in range(0,70,7):
        if offset>=len(data):raise ProtocolError('truncated integer')
        byte=data[offset];offset+=1
        if shift==63 and byte>1:raise ProtocolError('integer overflow')
        value|=(byte&127)<<shift
        if byte<128:return value,offset
    raise ProtocolError('integer overflow')


def pb(field,value):
    if isinstance(value,int):return varint(field<<3)+varint(value)
    return varint(field<<3|2)+varint(len(value))+value


def parse_pb(data):
    out={};offset=0
    while offset<len(data):
        tag,offset=readvar(data,offset);field,wire=tag>>3,tag&7
        if not field:raise ProtocolError('invalid protobuf field')
        if wire==0:out[field],offset=readvar(data,offset)
        elif wire==2:
            size,offset=readvar(data,offset)
            if size>len(data)-offset:raise ProtocolError('truncated protobuf')
            out[field]=data[offset:offset+size];offset+=size
        else:raise ProtocolError('unsupported protobuf wire')
    return out


def compress(data):
    if len(data)<15:return bytes([len(data)<<4])+data
    count=len(data)-15
    return b'\xf0'+b'\xff'*(count//255)+bytes([count%255])+data


def decompress(data):
    out=bytearray();offset=0
    def extension(length):
        nonlocal offset
        while True:
            if offset>=len(data):raise ProtocolError('truncated lz4 length')
            value=data[offset];offset+=1;length+=value
            if value!=255:return length
            if length>MAX_BODY:raise ProtocolError('lz4 limit')
    while offset<len(data):
        token=data[offset];offset+=1
        size=extension(15) if token>>4==15 else token>>4
        if size>len(data)-offset or len(out)+size>MAX_BODY:raise ProtocolError('lz4 literals')
        out.extend(data[offset:offset+size]);offset+=size
        if offset==len(data):break
        if offset+2>len(data):raise ProtocolError('lz4 offset')
        distance=int.from_bytes(data[offset:offset+2],'little');offset+=2
        if not 0<distance<=len(out):raise ProtocolError('lz4 offset')
        size=extension(19) if token&15==15 else (token&15)+4
        if len(out)+size>MAX_BODY:raise ProtocolError('lz4 limit')
        for _ in range(size):out.append(out[-distance])
    return bytes(out)


def expand(secret,info,length):
    if not 0<=length<=255*32:raise ProtocolError('hkdf limit')
    out=b'';last=b''
    for counter in range(1,(length+31)//32+1):
        last=hmac.digest(secret,last+info+bytes([counter]),'sha256');out+=last
    return out[:length]


def keypair():
    key=ec.generate_private_key(ec.SECP256R1())
    return key,key.public_key().public_bytes(Encoding.X962,PublicFormat.UncompressedPoint)


def shared(key,public):
    peer=ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(),public)
    return digest(key.exchange(ec.ECDH(),peer))


def encrypt_layout(key,aad,data):
    nonce=secrets.token_bytes(12);encrypted=AESGCM(key).encrypt(nonce,data,aad)
    return encrypted[:-16]+nonce+encrypted[-16:]


def decrypt_layout(key,aad,data):
    if len(data)<28:raise ProtocolError('truncated gcm')
    return AESGCM(key).decrypt(data[-28:-16],data[:-28]+data[-16:],aad)


def record(kind,data):
    if len(data)>65535:raise ProtocolError('record limit')
    return bytes([kind])+b'\xf1\x03'+u16(len(data))+data


def crypt_record(key,iv,seq,kind,data,decrypt=False):
    nonce=(int.from_bytes(iv,'big')^seq).to_bytes(12,'big')
    length=len(data) if decrypt else len(data)+16
    aad=struct.pack('>QBHH',seq,kind,0xf103,length)
    cipher=AESGCM(key)
    return cipher.decrypt(nonce,data,aad) if decrypt else cipher.encrypt(nonce,data,aad)


def handshake(kind,body):return u32(len(body)+1)+bytes([kind])+body


def split_handshake(data):
    if len(data)<5:raise ProtocolError('handshake length')
    size=int.from_bytes(data[:4],'big')
    if size<1 or size>len(data)-4:raise ProtocolError('handshake length')
    return data[4],data[5:4+size]


def client_hello(random,timestamp,pub1=None,pub2=None,ticket=None):
    if len(random)!=32:raise ProtocolError('random length')
    cipher=0x00a8 if ticket is not None else 0xc02b
    if ticket is not None:
        extension=b'\x00\x0f\x01'+u32(len(ticket))+ticket
    else:
        if len(pub1)!=65 or len(pub2)!=65:raise ProtocolError('public key length')
        extension=b'\x00\x10\x02'+b''.join(u32(71)+u32(group)+u16(65)+pub for group,pub in ((1,pub1),(2,pub2)))+u32(1)
    extension=b'\x01'+u32(len(extension))+extension
    body=b'\x03\xf1\x01'+u16(cipher)+random+u32(timestamp)+u32(len(extension))+extension
    return handshake(1,body)


def short_packet(command,seq,body):return struct.pack('>IHHII',16+len(body),0x1110,0x076d,command,seq)+body


def split_short(data):
    if len(data)<16:raise ProtocolError('short packet length')
    size,magic,_,cmd,seq=struct.unpack('>IHHII',data[:16])
    if not 16<=size<=len(data) or magic!=0x1110:raise ProtocolError('short packet header')
    return cmd,seq,data[16:size]


def wpkg(ints,blobs):
    head=varint(1)+b''.join(varint(k)+varint(v) for k,v in sorted(ints.items()))+b'\x00'
    head+=b''.join(varint(k)+varint(len(v))+v for k,v in sorted(blobs.items()))
    return head+b'\x00'+varint(len(head)+1)


def wpkg_offset(data):
    _,off=readvar(data)
    while True:
        field,off=readvar(data,off)
        if not field:break
        _,off=readvar(data,off)
    while True:
        field,off=readvar(data,off)
        if not field:break
        size,off=readvar(data,off)
        if size>len(data)-off:raise ProtocolError('wpkg length')
        off+=size
    _,off=readvar(data,off)
    return off


def app_header(device,uin=0,f9=b'',manual=False):
    values={1:1,2:uin,3:0,4:0,5:524545,6:11,7:0,8:0,9:0,10:1,11:0,12:0,13:0,
            17:0,18:1,20:1504,21:0,22:uin,23:0,25:17 if manual else 16,26:4,28:1,29:1,30:0}
    return wpkg(values,{14:b'',24:device,27:f9})


def login_body(login_buffer):
    meta=parse_pb(base64.b64decode(login_buffer,validate=True))
    if not meta.get(1) or not meta.get(2):raise ProtocolError('login buffer fields')
    body=pb(1,pb(1,secrets.token_bytes(32))+pb(2,1901))+pb(3,pb(1,meta[1]))+pb(4,4)+pb(6,b'')+pb(7,0)+pb(8,6)
    private,public=keypair();secret=shared(private,SERVER_PUB)
    h1=digest(b'1415'+public);cek=secrets.token_bytes(32)
    encrypted_cek=encrypt_layout(secret[:24],h1,cek)
    okm=expand(hmac.digest(SALT,cek,'sha256'),h1,56)
    compressed=compress(body)
    encrypted_body=encrypt_layout(okm[:24],digest(b'1415'+public+encrypted_cek),compressed)
    hybrid=pb(1,1)+pb(2,pb(1,415)+pb(2,public))+pb(3,encrypted_cek)+pb(4,b'')+pb(5,encrypted_body)
    return app_header(meta[2],manual=True)+hybrid,(private,okm,compressed),meta


def login_response(data,temp,meta):
    try:
        offset=wpkg_offset(data)
        if data[offset]!=10:raise ProtocolError('hybrid marker')
    except (ProtocolError,IndexError):
        offset=data.find(bytes.fromhex('089f03124104'))-2
        if offset<0:raise ProtocolError('missing hybrid')
    fields=parse_pb(data[offset:]);server=parse_pb(fields[1])[2]
    private,okm,compressed=temp
    aad=digest(okm[24:56]+compressed+b'415'+server+str(fields.get(2,1)).encode())
    plain=decompress(decrypt_layout(shared(private,server)[:24],aad,fields[3]))
    body=parse_pb(parse_pb(plain)[3]);session=parse_pb(body[2]);identity=parse_pb(body[3])
    if not session.get(1) or not session.get(2) or not identity.get(1):raise ProtocolError('session fields')
    return dict(send=session[1],recv=session[2],f9=session.get(9,b''),uin=identity[1],device=meta[2],host=meta.get(3) or HOST_APP)


def session_info(uin,windows,device):
    return pb(1,b'sessionkey')+pb(2,uin&0xffffffff)+pb(3,device)+pb(4,1661404927)+pb(5,windows)+pb(6,0)


def js_login(session,device=None):
    if device is None:
        mac=bytearray(secrets.token_bytes(6));mac[0]=(mac[0]|2)&254
        device='-'.join(f'{v:02X}' for v in mac).encode()
    inner=pb(1,session_info(session['uin'],b'UnifiedPCWindows',device))+pb(2,SCHOOL_APP)+pb(4,1)+pb(5,b'')+pb(6,b'')+pb(7,1)
    return (pb(1,session_info(session['uin'],b'Windows',device))+pb(2,b'/cgi-bin/mmbiz-bin/js-login')+
            pb(3,session['host'])+pb(4,5)+pb(5,inner)+pb(6,SCHOOL_APP)+pb(7,1029)+pb(8,1610627409)+pb(9,b'WindowsxWebPlugin')+pb(10,573651281))


def transfer(session,plain):
    body=app_header(session['device'],session['uin'],session['f9'])+encrypt_layout(session['send'],None,compress(plain))
    inner=short_packet(0x0b41,0,body)
    url=b'/ilink/ilinkapp/mp/wxaruntime_transfer';host=b'shortcloud.weixin.com'
    envelope=u16(len(url))+url+u16(len(host))+host+u32(len(inner))+inner
    return u32(len(envelope))+envelope


def decrypt_session(body,key):
    offsets=[]
    try:offsets.append(wpkg_offset(body))
    except ProtocolError:pass
    offsets+=range(min(len(body),220))
    for offset in dict.fromkeys(offsets):
        if len(body)-offset<29:continue
        try:return decompress(decrypt_layout(key,None,body[offset:]))
        except (InvalidTag,ProtocolError,ValueError):continue
    raise ProtocolError('application response decryption')


class LongLink:
    def __init__(self,target,timeout=5):
        self.socket=socket.create_connection(target,timeout=timeout)
        self.socket.settimeout(timeout)
        self.deadline=time.monotonic()+timeout
        self.tx=self.rx=0;self.transcript=b'';self.tickets=[];self.cert_hash=None

    def close(self):self.socket.close()

    def exact(self,size):
        result=bytearray()
        while len(result)<size:
            remaining=self.deadline-time.monotonic()
            if remaining<=0:raise TimeoutError('protocol deadline')
            self.socket.settimeout(remaining)
            data=self.socket.recv(size-len(result))
            if not data:raise ProtocolError('connection closed')
            result.extend(data)
        return bytes(result)

    def receive(self,key=None,iv=None):
        kind,version,size=struct.unpack('>BHH',self.exact(5))
        if version!=0xf103 or kind not in (0x15,0x16,0x17,0x19):raise ProtocolError('record header')
        body=self.exact(size)
        if key is not None:body=crypt_record(key,iv,self.rx,kind,body,True)
        self.rx+=1
        return kind,body

    def send(self,kind,body,key=None,iv=None):
        if key is not None:body=crypt_record(key,iv,self.tx,kind,body)
        remaining=self.deadline-time.monotonic()
        if remaining<=0:raise TimeoutError('protocol deadline')
        self.socket.settimeout(remaining);self.socket.sendall(record(kind,body));self.tx+=1

    def handshake(self):
        private,pub=keypair();_,pub2=keypair()
        hello=client_hello(secrets.token_bytes(32),int(time.time()),pub,pub2)
        self.transcript=hello;self.send(0x16,hello)
        kind,wire=self.receive();message,body=split_handshake(wire)
        if kind!=0x16 or message!=2 or len(body)<40:raise ProtocolError('server hello')
        self.transcript+=wire
        size=int.from_bytes(body[36:40],'big');extension=body[40:40+size]
        if len(extension)!=size or len(extension)<13 or extension[0]!=1:raise ProtocolError('key share')
        group=int.from_bytes(extension[7:11],'big');length=int.from_bytes(extension[11:13],'big')
        public=extension[13:13+length]
        if group!=1 or length!=65 or len(public)!=65:raise ProtocolError('server key group')
        self.secret=shared(private,public)
        keys=expand(self.secret,b'handshake key expansion'+digest(self.transcript),56)
        self.hs=keys
        for _ in range(16):
            kind,wire=self.receive(keys[16:32],keys[44:56])
            if kind!=0x16:raise ProtocolError('handshake record type')
            message,body=split_handshake(wire)
            if message==0x14:
                final=digest(self.transcript)
                master=expand(self.secret,b'expanded secret'+final,32)
                self.app=expand(master,b'application data key expansion'+final,56)
                got=body[2:2+int.from_bytes(body[:2],'big')]
                want=hmac.digest(expand(self.secret,b'server finished',32),final,'sha256')
                if not hmac.compare_digest(got,want):raise ProtocolError('server finished verification')
                self.transcript+=wire
                verify=hmac.digest(expand(self.secret,b'client finished',32),final,'sha256')
                self.send(0x16,handshake(0x14,u16(32)+verify),keys[:16],keys[32:44])
                return
            self.transcript+=wire
            if message==15:self.cert_hash=digest(self.transcript)
            if message==4:
                offset=1
                for _ in range(body[0] if body else 0):
                    if offset+4>len(body):raise ProtocolError('ticket length')
                    size=int.from_bytes(body[offset:offset+4],'big');offset+=4
                    entry=body[offset:offset+size];offset+=size
                    if len(entry)!=size or size<5:raise ProtocolError('ticket length')
                    self.tickets.append(entry)
        raise ProtocolError('handshake limit')

    def login(self,buffer):
        body,temp,meta=login_body(buffer)
        self.send(0x17,short_packet(0x0d7d,0,body),self.app[:16],self.app[32:44])
        kind,data=self.receive(self.app[16:32],self.app[44:56])
        command,_,body=split_short(data)
        if kind!=0x17 or command!=0x0d7d:raise ProtocolError('login command')
        session=login_response(body,temp,meta)
        if self.cert_hash is None:raise ProtocolError('missing ticket context')
        for entry in self.tickets:
            lifetime=int.from_bytes(entry[1:5],'big')
            if entry[0]==1 and lifetime>0:
                session.update(psk=expand(self.secret,b'PSK_ACCESS'+self.cert_hash,32),
                               ticket=entry,expires=time.monotonic()+min(lifetime,1800))
                return session
        raise ProtocolError('missing access ticket')


def short_request(session,envelope):
    timestamp=int(time.time())
    hello=client_hello(secrets.token_bytes(32),timestamp,ticket=session['ticket'])
    early=expand(session['psk'],b'early data key expansion'+digest(hello),28)
    type8=bytes.fromhex('00000010080000000b01000000060012')+u32(timestamp)
    request=record(0x19,hello)
    for seq,kind,body in ((1,0x19,type8),(2,0x17,envelope),(3,0x15,bytes.fromhex('00000003000101'))):
        request+=record(kind,crypt_record(early[:16],early[16:],seq,kind,body))
    return request,hello,type8


def short_response(session,data,hello,type8):
    offset=0;server=None;app=None
    while offset+5<=len(data):
        kind,version,size=struct.unpack('>BHH',data[offset:offset+5]);offset+=5
        if version!=0xf103 or offset+size>len(data):raise ProtocolError('short record')
        body=data[offset:offset+size];offset+=size
        if kind==0x16 and server is None:server=body
        if kind==0x17 and app is None:app=body
    if server is None or app is None:raise ProtocolError('short response fields')
    for transcript in (hello+server,hello+type8+server,hello+server+type8):
        keys=expand(session['psk'],b'handshake key expansion'+digest(transcript),28)
        for seq in (2,1,3):
            try:
                plain=crypt_record(keys[:16],keys[16:],seq,0x17,app,True)
            except InvalidTag:continue
            candidates=[plain]
            try:candidates.insert(0,split_short(plain)[2])
            except ProtocolError:pass
            for candidate in candidates:
                try:
                    response=parse_pb(decrypt_session(candidate,session['recv']))
                    code=parse_pb(response[2])[3].decode('utf-8')
                    if code:return code
                except (ProtocolError,KeyError,UnicodeError,TypeError):continue
    raise ProtocolError('invalid login code response')


class CodeClient:
    def __init__(self):
        self.sessions={};self.targets=None;self.targets_until=0;self.lock=threading.RLock()
        self.account_locks={}

    def discover(self):
        with self.lock:
            if self.targets and time.monotonic()<self.targets_until:return self.targets
        found=None
        for host in ('aedns.weixin.qq.com','180.153.202.85'):
            connection=http.client.HTTPConnection(host,80,timeout=8)
            try:
                connection.request('GET','/cgi-bin/default/getdns?clientversion=0&devicetype=Windows&uin=0&format=json',headers={'Host':'aedns.weixin.qq.com','User-Agent':'MicroMessenger Client'})
                response=connection.getresponse();data=response.read(MAX_BODY+1)
                if response.status!=200 or len(data)>MAX_BODY:continue
                import json
                dns=json.loads(data)['dns']
                if dns.get('retcode',0)!=0:continue
                found={}
                for item in dns['domainlist']:
                    name=item.get('name')
                    if name not in ('longcloud.weixin.com','shortcloud.weixin.com'):continue
                    ports=[]
                    for proto in item.get('protocollist',[]):
                        if proto.get('name')==('http' if name=='shortcloud.weixin.com' else 'mmtlsovertcp'):ports=proto.get('portlist',[])
                    ips=[]
                    for ip in item.get('iplist',[]):
                        address=ipaddress.ip_address(ip['ip'])
                        if address.is_global:ips.append(str(address))
                    found[name]=[(ip,port) for ip in ips for port in ports if type(port) is int and 0<port<65536 and (name!='shortcloud.weixin.com' or port==80)]
                if found.get('longcloud.weixin.com'):break
            except (OSError,ValueError,KeyError,TypeError,http.client.HTTPException):continue
            finally:connection.close()
        if not found:found={}
        fallback=('longcloud.weixin.com',443)
        candidates=found.get('longcloud.weixin.com') or []
        candidates=sorted(candidates,key=lambda t:({443:0,8080:1,80:2,5000:3}.get(t[1],4)))
        found['longcloud.weixin.com']=list(dict.fromkeys(t for t in candidates if t!=fallback))[:5]+[fallback]
        if not found.get('shortcloud.weixin.com'):found['shortcloud.weixin.com']=[('120.241.131.173',80)]
        with self.lock:self.targets=found;self.targets_until=time.monotonic()+1800
        return found

    def login(self,buffer):
        targets=self.discover()
        # Interleave addresses/ports, keeping a shared bounded login budget.
        selected=targets['longcloud.weixin.com']
        deadline=time.monotonic()+30
        for index,target in enumerate(selected[:6]):
            link=None
            try:
                budget=(deadline-time.monotonic())/(len(selected[:6])-index)
                if budget<=0:break
                link=LongLink(target,budget);link.handshake();return link.login(buffer)
            except (OSError,ValueError,InvalidTag,KeyError,IndexError,struct.error):continue
            finally:
                if link:link.close()
        raise ProtocolError('protocol login failed')

    def get_code(self,openid,buffer):
        with self.lock:lock=self.account_locks.setdefault(openid,threading.Lock())
        with lock:
            for attempt in range(2):
                with self.lock:session=self.sessions.get(openid)
                if not session or session['expires']<=time.monotonic():
                    session=self.login(buffer)
                    with self.lock:self.sessions[openid]=session
                envelope=transfer(session,js_login(session));request,hello,type8=short_request(session,envelope)
                targets=self.discover().get('shortcloud.weixin.com') or [('shortcloud.weixin.com',80)]
                payload_error=False;deadline=time.monotonic()+20
                for target in targets[:4]:
                    connection=None
                    try:
                        remaining=deadline-time.monotonic()
                        if remaining<=0:break
                        connection=http.client.HTTPConnection(*target,timeout=min(8,remaining))
                        connection._http_vsn=10;connection._http_vsn_str='HTTP/1.0'
                        headers={'Host':'shortcloud.weixin.com','User-Agent':'MicroMessenger Client','X-Online-Host':'shortcloud.weixin.com','Upgrade':'mmtls','Content-Type':'application/octet-stream','Connection':'close'}
                        connection.request('POST',f'/mmtls/{int(time.time()):08x}',body=request,headers=headers)
                        response=connection.getresponse();body=response.read(MAX_BODY+1)
                        if response.status!=200 or len(body)>MAX_BODY:continue
                        try:return short_response(session,body,hello,type8)
                        except ProtocolError:payload_error=True
                    except (OSError,http.client.HTTPException):continue
                    finally:
                        if connection:connection.close()
                with self.lock:self.sessions.pop(openid,None)
                if not payload_error or attempt:raise ProtocolError('code transport failed')
            raise ProtocolError('code unavailable')

    def forget(self,openid):
        with self.lock:self.sessions.pop(openid,None)

    def close(self):
        with self.lock:self.sessions.clear()
