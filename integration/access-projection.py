#!/usr/bin/env python3
"""Opt-in synthetic token-file reload through real kind Secret projection; no SSO claim."""
import subprocess,json,time,base64,os,http.client
K=os.environ['REQUESTOR_ACCESS_TEST_KUBECONFIG']
RESULT=os.environ['REQUESTOR_ACCESS_TEST_RESULT']
NS='access-projection-fixture'
def k(*args,obj=None):
 p=subprocess.run(['kubectl','--kubeconfig',K,'--context','kind-requestor-access-20261031','--request-timeout=20s',*args],input=json.dumps(obj) if obj is not None else None,capture_output=True,text=True,timeout=40)
 if p.returncode: raise RuntimeError('local kubectl failed: '+p.stderr[:200])
 return p.stdout
assert k('config','view','--minify','-o','jsonpath={.clusters[0].cluster.server}').startswith('https://127.0.0.1:')
assert json.loads(k('get','nodes','-o','json'))['items'][0]['metadata']['name']=='requestor-access-20261031-control-plane'
server='''from http.server import BaseHTTPRequestHandler,HTTPServer
import json
class H(BaseHTTPRequestHandler):
 def log_message(self,*a):pass
 def do_GET(self):
  if self.path=='/.well-known/openid-configuration':
   b=json.dumps({'issuer':'http://127.0.0.1:8081','authorization_endpoint':'http://127.0.0.1:8081/auth','token_endpoint':'http://127.0.0.1:8081/token','jwks_uri':'http://127.0.0.1:8081/keys','response_types_supported':['code'],'subject_types_supported':['public'],'id_token_signing_alg_values_supported':['RS256']}).encode()
  elif self.path=='/keys':b=b'{"keys":[]}'
  else:b=json.dumps({'first':self.headers.get('Authorization')=='Bearer synthetic-first','second':self.headers.get('Authorization')=='Bearer synthetic-second'}).encode()
  self.send_response(200);self.send_header('Content-Type','application/json');self.end_headers();self.wfile.write(b)
HTTPServer(('0.0.0.0',8081),H).serve_forever()
'''
cfg={'services':'all','address':':8080','grpc_address':':5443','insecure_server':True,'shared_secret':base64.b64encode(os.urandom(32)).decode(),'cookie_secret':base64.b64encode(os.urandom(32)).decode(),'authenticate_service_url':'http://127.0.0.1:8080','idp_provider':'oidc','idp_provider_url':'http://127.0.0.1:8081','idp_client_id':'fixture','idp_client_secret':'synthetic','databroker_storage_type':'memory','routes':[{'from':'http://route.local:8080','to':'http://127.0.0.1:8081','allow_public_unauthenticated_access':True,'kubernetes_service_account_token_file':'/tokens/token'}]}
forward=None
created=False
try:
 k('create','namespace',NS)
 created=True
 for obj in [ {'apiVersion':'v1','kind':'Secret','metadata':{'name':'config','namespace':NS},'stringData':{'core.yaml':json.dumps(cfg),'server.py':server}}, {'apiVersion':'v1','kind':'Secret','metadata':{'name':'token','namespace':NS},'stringData':{'token':'synthetic-first'}}, {'apiVersion':'v1','kind':'Pod','metadata':{'name':'core','namespace':NS},'spec':{'automountServiceAccountToken':False,'containers':[{'name':'core','image':'pomerium/pomerium:v0.33.4','imagePullPolicy':'Never','args':['--config=/config/core.yaml'],'volumeMounts':[{'name':'config','mountPath':'/config','readOnly':True},{'name':'token','mountPath':'/tokens','readOnly':True}]},{'name':'receiver','image':'python:3.13-alpine','imagePullPolicy':'Never','command':['python','/config/server.py'],'volumeMounts':[{'name':'config','mountPath':'/config','readOnly':True}]}],'volumes':[{'name':'config','secret':{'secretName':'config'}},{'name':'token','secret':{'secretName':'token'}}]}}]:
  k('create','-f','-',obj=obj)
 k("-n",NS,"wait","--for=condition=Ready","pod/core","--timeout=30s")
 forward=subprocess.Popen(['kubectl','--kubeconfig',K,'--context','kind-requestor-access-20261031','-n',NS,'port-forward','pod/core','18087:8080','--address','127.0.0.1'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 def check(field,seconds):
  end=time.monotonic()+seconds
  last='none'
  while time.monotonic()<end:
   try:
    c=http.client.HTTPConnection('127.0.0.1',18087,timeout=2)
    c.request('GET','/echo',headers={'Host':'route.local:8080'})
    r=c.getresponse();data=json.loads(r.read());c.close()
    last=str(data)
    if data.get(field):return
   except Exception as e:last=type(e).__name__+':'+str(getattr(e,'code',''))
   time.sleep(2)
  print('last result',last)
  raise RuntimeError('Core did not observe '+field+' token')
 check('first',60)
 start=time.monotonic()
 k('-n',NS,'patch','secret','token','--type=merge','-p',json.dumps({'stringData':{'token':'synthetic-second'}}))
 check('second',150)
 result={'coreVersion':'0.33.4','nativeSecretProjectionToCoreReload':'pass','observedSeconds':round(time.monotonic()-start,2),'boundary':'Synthetic unauthenticated loopback route; not human SSO or stream revocation'}
 print(json.dumps(result));open(RESULT,'w').write(json.dumps(result,indent=2))
finally:
 if forward:forward.terminate();forward.wait(timeout=10)
 if created:k('delete','namespace',NS,'--wait=false')
