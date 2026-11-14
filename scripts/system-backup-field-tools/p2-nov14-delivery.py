"""Exact P2 controller/provider replacement plans; no authority is inferred from plans."""
import base64
import copy
import hashlib
import json
import re

MOUNT='/var/run/clawreef/system-backup/provider-dependency'
def need(ok,why):
    if not ok: raise ValueError(why)
def sha(raw): return hashlib.sha256(raw).hexdigest()
def encoded(value): return json.dumps(value,separators=(',',':'),ensure_ascii=False).encode()

def rotation_delivery(deployment, old_secret, native_observer, token, image):
    need(re.fullmatch(r'10\.130\.14\.23:5000/[a-z0-9._/-]+@sha256:[0-9a-f]{64}',image),'immutable local-registry controller image required')
    old= json.loads(base64.b64decode(old_secret['data']['observer.json'],validate=True))
    need(old_secret.get('immutable') is True and native_observer['IdentityMode']=='metadata-only' and
         native_observer['TokenSHA256']==sha(token) and native_observer['ObserverPolicy'] not in ('root','default'), 'native metadata identity required')
    varying={'TokenFile','TokenSHA256','ObserverPolicy'}
    need({k:v for k,v in old.items() if k not in varying}=={k:v for k,v in native_observer.items() if k not in varying},'Vault trust, endpoint or cluster identity changed')
    observer=copy.deepcopy(native_observer);observer['TokenFile']=MOUNT+'/token'
    body=encoded(observer); digest=sha(body)
    secret={'apiVersion':'v1','kind':'Secret','metadata':{'namespace':deployment['metadata']['namespace'],'name':'backup-provider-'+digest[:24]},'immutable':True,'type':'Opaque',
            'data':{'observer.json':base64.b64encode(body).decode(),'token':base64.b64encode(token).decode()}}
    desired=copy.deepcopy(deployment['spec']); pod=desired['template']['spec']
    inputs=[v for v in pod['volumes'] if v['name']=='provider-dependency-input']
    need(len(inputs)==1 and inputs[0]['secret']['secretName']==old_secret['metadata']['name'],'original provider Secret mount changed')
    inputs[0]['secret']['secretName']=secret['metadata']['name']
    init=[c for c in pod.get('initContainers',[]) if c['name']=='provider-dependency-install']
    need(len(init)==1,'exact provider initializer required')
    expected=['install-provider-files','--observer-sha256',sha(base64.b64decode(old_secret['data']['observer.json'],validate=True)),'--token-sha256',old['TokenSHA256']]
    need(init[0].get('args')==expected and init[0].get('command')==['/usr/local/bin/system-backup-source-registries'],'original initializer protocol changed')
    init[0]['args']=['install-provider-files','--observer-sha256',digest,'--token-sha256',sha(token)]
    init[0]['image']=image
    need({c['name'] for c in pod['containers']}=={'controller','installation-owner'},'controller container roster changed')
    for c in pod['containers']: c['image']=image
    patch=[{'op':'test','path':'/metadata/uid','value':deployment['metadata']['uid']},
           {'op':'test','path':'/metadata/resourceVersion','value':deployment['metadata']['resourceVersion']},
           {'op':'test','path':'/spec','value':deployment['spec']},{'op':'replace','path':'/spec','value':desired}]
    return secret,desired,patch,digest
