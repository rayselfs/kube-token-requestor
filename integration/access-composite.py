#!/usr/bin/env python3
"""Owned-loopback publisher/PG/projection probe; synthetic public routes, no SSO claim."""
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import socket
import subprocess
import threading
import time

K = os.environ['REQUESTOR_ACCESS_TEST_KUBECONFIG']
NS = os.environ['REQUESTOR_ACCESS_NAMESPACE']
RESULT = Path(os.environ['REQUESTOR_ACCESS_COMPOSITE_RESULT'])
CONTEXT = 'kind-requestor-access-20261031'
assert NS.startswith('access-test-')
assert not RESULT.exists(), 'Do not overwrite evidence'

def k(*args, obj=None):
    p = subprocess.run(['kubectl', '--kubeconfig', K, '--context', CONTEXT,
                        '--request-timeout=20s', *args],
                       input=json.dumps(obj) if obj is not None else None,
                       capture_output=True, text=True, timeout=40)
    if p.returncode:
        raise RuntimeError('owned fixture kubectl failed')
    return p.stdout

assert k('config', 'view', '--minify', '-o', 'jsonpath={.clusters[0].cluster.server}').startswith('https://127.0.0.1:')
assert [n['metadata']['name'] for n in json.loads(k('get', 'nodes', '-o', 'json'))['items']] == [CONTEXT[5:]+'-control-plane']

def token_hash():
    s = json.loads(k('-n', NS, 'get', 'secret', 'output', '-o', 'json'))
    return hashlib.sha256(base64.b64decode(s['data']['token'])).hexdigest()

initial = token_hash()
sibling_token=base64.urlsafe_b64encode(os.urandom(24)).decode()
sibling_digest=hashlib.sha256(sibling_token.encode()).hexdigest()
server = '''from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import base64,hashlib,json,time
class H(BaseHTTPRequestHandler):
 protocol_version='HTTP/1.1'
 def log_message(self,*a):pass
 def do_GET(self):
  if self.path=='/stream':
   self.send_response(200);self.send_header('Content-Type','text/event-stream');self.end_headers()
   try:
    while True:self.wfile.write(b'data: alive\\n\\n');self.wfile.flush();time.sleep(.5)
   except (BrokenPipeError,ConnectionResetError):pass
   return
  if self.path=='/ws':
   key=self.headers.get('Sec-WebSocket-Key','')
   accept=base64.b64encode(hashlib.sha1((key+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
   self.send_response(101);self.send_header('Upgrade','websocket');self.send_header('Connection','Upgrade');self.send_header('Sec-WebSocket-Accept',accept);self.end_headers()
   try:
    while True:self.wfile.write(b'\\x81\\x01x');self.wfile.flush();time.sleep(.5)
   except (BrokenPipeError,ConnectionResetError):pass
   return
  if self.path=='/.well-known/openid-configuration':
   data={'issuer':'http://127.0.0.1:8081','authorization_endpoint':'http://127.0.0.1:8081/auth','token_endpoint':'http://127.0.0.1:8081/token','jwks_uri':'http://127.0.0.1:8081/keys','response_types_supported':['code'],'subject_types_supported':['public'],'id_token_signing_alg_values_supported':['RS256']}
  elif self.path=='/keys':data={'keys':[]}
  else:data={'digest':hashlib.sha256(self.headers.get('Authorization','').removeprefix('Bearer ').encode()).hexdigest()}
  b=json.dumps(data).encode();self.send_response(200);self.send_header('Content-Length',str(len(b)));self.end_headers();self.wfile.write(b)
ThreadingHTTPServer(('0.0.0.0',8081),H).serve_forever()
'''
def route(name):
    return {'from': 'http://'+name+'.local:8080', 'to': 'http://127.0.0.1:8081',
            'allow_public_unauthenticated_access': True, 'allow_websockets': True,
            'kubernetes_service_account_token_file': '/tokens/token' if name=='target-a' else '/sibling/token',
            'timeout': '300s', 'idle_timeout': '0s'}

password = base64.urlsafe_b64encode(os.urandom(24)).decode()
cfg = {'services':'all', 'address':':8080', 'grpc_address':':5443', 'insecure_server':True,
       'shared_secret':base64.b64encode(os.urandom(32)).decode(),
       'cookie_secret':base64.b64encode(os.urandom(32)).decode(),
       'authenticate_service_url':'http://127.0.0.1:8080', 'idp_provider':'oidc',
       'idp_provider_url':'http://127.0.0.1:8081', 'idp_client_id':'fixture',
       'idp_client_secret':'synthetic', 'databroker_storage_type':'postgres',
       'databroker_storage_connection_string':f'postgres://pomerium:{password}@pg:5432/pomerium?sslmode=disable',
       'routes':[route('target-a'),route('target-b')]}
# Local disposable DB only; Cloud SQL TLS/IAM and restore remain separate gates.
result = {'scope':'Local native publisher + PostgreSQL 16 + projected Secret + Core 0.33.4',
          'humanSSO': 'not-tested', 'cloudSQL': 'not-tested', 'fullHelmController':'not-tested',
          'streamPolicy':'Candidate Core route timeout 300s; not the 1800s edge profile'}
forward = None
streams = []
def create(kind, name, **fields):
    k('create', '-f', '-', obj={'apiVersion':'v1','kind':kind,'metadata':{'name':name,'namespace':NS},**fields})
def request(target):
    c = http.client.HTTPConnection('127.0.0.1', 18088, timeout=3)
    try:
        c.request('GET','/echo',headers={'Host':target+'.local:8080'})
        r=c.getresponse(); return r.status, r.read()
    finally: c.close()
def until(fn, timeout=150):
    end=time.monotonic()+timeout
    while time.monotonic()<end:
        try:
            if fn(): return
        except (OSError, ValueError, RuntimeError, http.client.HTTPException): pass
        time.sleep(1)
    raise RuntimeError('local probe deadline exceeded')
def echo(target, digest):
    status, body=request(target)
    return status==200 and json.loads(body).get('digest')==digest

def open_stream(target, protocol):
    sock=socket.create_connection(('127.0.0.1',18088),3)
    sock.settimeout(15)
    extra='Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: '+base64.b64encode(os.urandom(16)).decode()+'\r\n' if protocol=='ws' else ''
    sock.sendall(f'GET /{protocol} HTTP/1.1\r\nHost: {target}.local:8080\r\n{extra}\r\n'.encode())
    header=b''
    while b'\r\n\r\n' not in header: header+=sock.recv(1)
    assert header.startswith(b'HTTP/1.1 '+(b'101 ' if protocol=='ws' else b'200 ')), 'stream not established'
    state={'socket':sock,'started':time.monotonic(),'bytes':0,'closed':None,'error':None}
    def read():
        try:
            while sock.recv(4096): state['bytes']+=1
            state['closed']=time.monotonic()
        except OSError as e:
            state['error']=type(e).__name__
            state['closed']=time.monotonic()
    thread=threading.Thread(target=read,daemon=True); state['thread']=thread;thread.start();streams.append(state)
    return state

def sql(query):
    return k('-n',NS,'exec','pg','--','psql','-U','pomerium','-d','pomerium','-Atc',query).strip()

try:
    create('Secret','sibling',stringData={'token':sibling_token})
    create('Secret','pg-auth',stringData={'password':password})
    create('Pod','pg',spec={'automountServiceAccountToken':False,'containers':[{
        'name':'pg','image':os.environ['REQUESTOR_ACCESS_PG_IMAGE'],'imagePullPolicy':'Never',
        'env':[{'name':'POSTGRES_USER','value':'pomerium'},{'name':'POSTGRES_DB','value':'pomerium'},
               {'name':'POSTGRES_PASSWORD','valueFrom':{'secretKeyRef':{'name':'pg-auth','key':'password'}}}],
        'readinessProbe':{'exec':{'command':['pg_isready','-U','pomerium']},'periodSeconds':1},
        'volumeMounts':[{'name':'data','mountPath':'/var/lib/postgresql/data'}]}],
        'volumes':[{'name':'data','emptyDir':{}}]})
    create('Service','pg',spec={'selector':{'fixture':'pg'},'ports':[{'port':5432}]})
    k('-n',NS,'label','pod','pg','fixture=pg')
    k('-n',NS,'wait','--for=condition=Ready','pod/pg','--timeout=30s')
    create('Secret','config',stringData={'core.yaml':json.dumps(cfg),'server.py':server})
    create('Pod','core',spec={'automountServiceAccountToken':False,'containers':[
        {'name':'core','image':'pomerium/pomerium:v0.33.4','imagePullPolicy':'Never',
         'args':['--config=/config/core.yaml'],'volumeMounts':[{'name':'config','mountPath':'/config','readOnly':True},{'name':'token','mountPath':'/tokens','readOnly':True},{'name':'sibling','mountPath':'/sibling','readOnly':True}]},
        {'name':'receiver','image':'python:3.13-alpine','imagePullPolicy':'Never','command':['python','/config/server.py'],
         'volumeMounts':[{'name':'config','mountPath':'/config','readOnly':True}]}],
        'volumes':[{'name':'sibling','secret':{'secretName':'sibling'}},{'name':'config','secret':{'secretName':'config'}},{'name':'token','secret':{'secretName':'output'}}]})
    k('-n',NS,'wait','--for=condition=Ready','pod/core','--timeout=30s')
    forward=subprocess.Popen(['kubectl','--kubeconfig',K,'--context',CONTEXT,'-n',NS,'port-forward','pod/core','18088:8080','--address','127.0.0.1'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    until(lambda:echo('target-a',initial),60)
    until(lambda:int(sql("select count(*) from pg_stat_activity where datname='pomerium' and application_name != 'psql' and backend_type='client backend'"))>0,30)
    result['postgresConnected']=True
    print('ready',flush=True)
    start=time.monotonic()
    until(lambda:token_hash()!=initial,30)
    fresh=token_hash()
    until(lambda:echo('target-a',fresh) and echo('target-b',sibling_digest))
    result['publisherToProjectedSecretReloadSeconds']=round(time.monotonic()-start,2)
    result['publisherToProjectedSecretReload']='pass'
    # A backend process restart preserves its emptyDir; this is recovery, not backup restore.
    sql('create table local_probe (id integer primary key); insert into local_probe values (1)')
    k('-n',NS,'exec','pg','--','sh','-c','kill -QUIT 1')
    until(lambda:sql('select count(*) from local_probe')=='1',60)
    until(lambda:echo('target-b',sibling_digest),30)
    result['postgresProcessRestart']='pass: sentinel retained; route available'
    a=open_stream('target-a','stream'); aw=open_stream('target-a','ws')
    b=open_stream('target-b','stream'); bw=open_stream('target-b','ws')
    before=[b['bytes'],bw['bytes']]
    revoked=time.monotonic()
    cfg['routes']=[route('target-b')]
    k('-n',NS,'patch','secret','config','--type=merge','-p',json.dumps({'stringData':{'core.yaml':json.dumps(cfg)}}))
    until(lambda:request('target-a')[0]==404)
    result['newRequestDenialSeconds']=round(time.monotonic()-revoked,2)
    assert echo('target-b',sibling_digest)
    time.sleep(3)
    assert all(s['closed'] is None and s['bytes']>n for s,n in zip((b,bw),before)), 'sibling streams interrupted by route removal'
    result['siblingDuringRouteRemoval']='pass: new request, SSE and WebSocket'
    result['existingStreamsImmediatelyAfterRemoval']={'sseOpen':a['closed'] is None,'websocketOpen':aw['closed'] is None}
    end=max(a['started'],aw['started'])+310
    while time.monotonic()<end and any(s['closed'] is None for s in (a,aw)):
        time.sleep(1)
    result['streamLifetimeSeconds']={name:round(s['closed']-s['started'],2) if s['closed'] else None for name,s in [('sse',a),('websocket',aw)]}
    result['streamTransportErrors']={name:s['error'] for name,s in [('sse',a),('websocket',aw)]}
    result['streamBoundPassed']=all(s['closed'] is not None and s['closed']-s['started']<=305 and s['error'] is None for s in (a,aw))
    # Configuration remains projected; restart acceptance is a separate probe.
    k('-n',NS,'exec','core','-c','receiver','--','python','-c','import os; assert os.path.exists("/config/core.yaml")')
    result['retirement']='partial: route removed; SA/grant revocation, receipt and controller removal remain open'
    result['coreRestartCounts']={c['name']:c['restartCount'] for c in json.loads(k('-n',NS,'get','pod','core','-o','json'))['status']['containerStatuses']}
    result['status']='passed-bounded-probes' if result['streamBoundPassed'] else 'stream-termination-gap'
except Exception as e:
    result['status']='fixture-error'; result['error']=type(e).__name__+': '+str(e)[:120]
    raise
finally:
    for s in streams:
        s['socket'].close()
    if forward:
        forward.terminate();forward.wait(timeout=10)
    RESULT.write_text(json.dumps(result,indent=2)+'\n')
    # Native Go test owns namespace/RBAC cleanup, including all fixture Secrets.
