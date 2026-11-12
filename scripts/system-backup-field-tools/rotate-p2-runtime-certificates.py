#!/usr/bin/env python3
"""This site's existing TLS mounts only: App dual trust, runtime leaves, final CA.

No image, command, gateway configuration, replicas, rollout strategy or business
credential change. Unknown patches are read back, never automatically resent.
"""
import argparse
import copy
import datetime
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import time

NS='clawmanager-sbk-validation-system'
WORK=Path('/root/sbk-validation-tls-inspect.7LVU7vpE')
APP_UID='8ebd4d4c-57b6-4a82-b310-fae596681a4e'
OLD_CA='c99ddcf7198d4e8cc0445a141ddef69e6998ec213c007955b38bb37efda394f3'
NEW_CA='4d6ffb92650f28a7148a536b60cfab6a0b025856a4b30dba3b6059905c128478'
IMAGES={'hermes-runtime':('de547f9b-b21a-45b3-9d74-c77ce35ab0d4','10.130.14.23:5000/hermes-lite@sha256:279fa5b365f875de1fad93b0f58cda20599d2339fa067bf062e08ef80d770254'),
 'openclaw-runtime':('baf19cae-4476-4d1c-a9c8-884fd13077d2','10.130.14.23:5000/openclaw-lite@sha256:5d5f735bc8c0155d51841b574c98c6c02ca399085add0e3dc98b3d7e0ead3140')}

def need(ok,why):
    if not ok:raise ValueError(why)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def encode(v):return json.dumps(v,sort_keys=True,separators=(',',':')).encode()
def pinned(p):
    path=Path(p['File']);need(path.resolve(strict=True)==path and path.is_file() and not path.is_symlink(),'original private file required')
    raw=path.read_bytes();need(sha(raw)==p['SHA256'],'original file bytes changed');return raw
def retain(p,value):
    raw=value if isinstance(value,bytes) else encode(value)
    if p.exists():need(not p.is_symlink() and p.read_bytes()==raw,'retained operation changed')
    else:
        with p.open('xb') as f:os.chmod(p,0o600);f.write(raw);f.flush();os.fsync(f.fileno())

def semantic(v):
    if isinstance(v,list):return [semantic(x) for x in v]
    if not isinstance(v,dict):return v
    out={k:semantic(x) for k,x in v.items()}
    if 'env' in out:
        for e in out['env']:
            if 'valueFrom' not in e:e.setdefault('value','')
    return out

def runtime_spec(deployment,target):
    name=deployment['metadata']['name'];uid,image=IMAGES[name]
    need(deployment['metadata']['uid']==target['DeploymentUID']==uid and
         deployment['metadata']['generation']==target['DeploymentGeneration'],'runtime changed since genuine issuance')
    desired=copy.deepcopy(deployment['spec']);pod=desired['template']['spec']
    need(len(pod['containers'])==1 and pod['containers'][0]['name']=='runtime' and
         pod['containers'][0]['image']==image and desired['strategy']['type']=='Recreate','current repaired runtime must remain pinned with Recreate')
    c=pod['containers'][0];env={e['name']:e.get('value') for e in c['env']}
    need(env.get('RUNTIME_AGENT_TLS_CERT_FILE')=='/run/clawmanager-agent-tls/tls.crt' and
         env.get('RUNTIME_AGENT_TLS_KEY_FILE')=='/run/clawmanager-agent-tls/tls.key','existing TLS startup paths changed')
    mounts=[m for m in c['volumeMounts'] if m['mountPath']=='/run/clawmanager-agent-tls']
    need(len(mounts)==1 and mounts[0].get('readOnly') is True,'one existing read-only TLS mount required')
    volumes=[v for v in pod['volumes'] if v['name']==mounts[0]['name']]
    need(len(volumes)==1 and 'secret' in volumes[0],'existing TLS Secret volume required')
    volumes[0]['secret']['secretName']=target['SecretName']
    return desired

def app_spec(spec,ca_sha):
    desired=copy.deepcopy(spec);pod=desired['template']['spec'];cs=pod['containers']
    need(len(cs)==1 and cs[0]['image']=='10.130.14.23:5000/clawmanager@sha256:322ba63b49d21c4030be2760c88ae03457fbe9454ee138906066b29bc68541ca','original App image required')
    c=cs[0];env=c['env'];need(len({e['name'] for e in env})==len(env),'duplicate App env')
    roots=[e for e in env if e['name']=='RUNTIME_AGENT_CA_FILE']
    hashes=[e for e in env if e['name']=='RUNTIME_AGENT_CA_SHA256']
    need(len(roots)==len(hashes)==1 and roots[0].get('value')=='/run/clawmanager-agent-ca/ca.pem','existing App CA configuration required')
    mounts=[m for m in c['volumeMounts'] if m['mountPath']=='/run/clawmanager-agent-ca']
    need(len(mounts)==1 and mounts[0].get('readOnly') is True,'existing App CA mount required')
    vols=[v for v in pod['volumes'] if v['name']==mounts[0]['name']]
    need(len(vols)==1 and 'configMap' in vols[0],'existing App CA ConfigMap required')
    vols[0]['configMap']['name']='sbk-agent-ca-'+ca_sha[:20]
    hashes[0].clear();hashes[0].update(name='RUNTIME_AGENT_CA_SHA256',value=ca_sha)
    return desired,vols[0]['configMap']['name']

class Site:
    def __init__(self,records):self.r=records;self.sequence=len(list(records.glob('read-*.stdout.private')))
    def call(self,args,body=None):
        self.sequence+=1;label='read-%05d'%self.sequence
        p=subprocess.run(['kubectl','--kubeconfig',str(WORK/'operator.kubeconfig.yaml'),'--request-timeout=20s','-n',NS,*args],
            input=None if body is None else encode(body),capture_output=True,timeout=280)
        retain(self.r/(label+'.stdout.private'),p.stdout or b'\n');retain(self.r/(label+'.stderr.private'),p.stderr or b'\n')
        need(p.returncode==0,'API operation unconfirmed at '+label+'; retain private logs')
        return p.stdout
    def get(self,kind,name):return json.loads(self.call(['get',kind,name,'-o','json']))
    def ensure(self,obj):
        need(obj['metadata']['namespace']==NS and obj['kind'] in ['Secret','ConfigMap'],'only this installation certificate objects allowed')
        kind=obj['kind'].lower();name=obj['metadata']['name']
        raw=self.call(['get',kind,name,'--ignore-not-found','-o','json'])
        if not raw.strip():
            marker=self.r/('create-'+name+'.sent.json')
            need(not marker.exists(),'unknown create absent; inspect original send, never resend')
            retain(marker,obj);actual=json.loads(self.call(['create','-f','-','-o','json'],obj))
        else:actual=json.loads(raw)
        need(all(actual.get(k)==v for k,v in obj.items() if k not in ['metadata','apiVersion','kind']) and
             not actual['metadata'].get('deletionTimestamp'),'existing certificate object changed')
    def patch(self,label,name,original,desired,uid):
        current=self.get('deployment',name);need(current['metadata']['uid']==uid,'deployment replaced')
        if semantic(current['spec'])!=semantic(desired):
            need(semantic(current['spec'])==semantic(original),'deployment drift; retain current state')
            marker=self.r/(label+'.sent.json');need(not marker.exists(),'patch outcome unknown: read original operation, never resend')
            patch=[{'op':'test','path':'/metadata/uid','value':uid},{'op':'test','path':'/metadata/resourceVersion','value':current['metadata']['resourceVersion']},
                   {'op':'test','path':'/spec','value':current['spec']},{'op':'replace','path':'/spec','value':desired}]
            retain(marker,patch);self.call(['patch','deployment',name,'--type=json','--patch-file=/dev/stdin','-o','json'],patch)
        self.call(['rollout','status','deployment/'+name,'--timeout=240s'])
        actual=self.get('deployment',name);need(semantic(actual['spec'])==semantic(desired),'post-rollout spec drift')
        selector=','.join(k+'='+v for k,v in actual['spec']['selector']['matchLabels'].items())
        pods=json.loads(self.call(['get','pods','-l',selector,'-o','json']))['items']
        pods=[p for p in pods if not p['metadata'].get('deletionTimestamp')]
        need(len(pods)==desired.get('replicas',1),'Pod roster not settled')
        for pod in pods:
            statuses=pod['status'].get('containerStatuses',[])
            need(pod['status']['phase']=='Running' and statuses and all(s.get('ready') for s in statuses),'Pod not ready')
            refs=[o for o in pod['metadata'].get('ownerReferences',[]) if o.get('controller')]
            need(len(refs)==1 and refs[0]['kind']=='ReplicaSet','Pod owner changed')
            rs=self.get('replicaset',refs[0]['name']);owners=[o for o in rs['metadata'].get('ownerReferences',[]) if o.get('controller')]
            need(rs['metadata']['uid']==refs[0]['uid'] and len(owners)==1 and owners[0]['kind']=='Deployment' and owners[0]['uid']==uid,'Pod belongs to another deployment')
            a=pod['spec']['containers'][0];wanted=desired['template']['spec']['containers'][0]
            need(all(semantic({'env':a.get(k)})==semantic({'env':wanted.get(k)}) if k=='env' else a.get(k)==wanted.get(k)
                     for k in ['image','command','args','env','envFrom','workingDir']),'admission changed startup')
        return pods

def verify_app_ca(site,pods,expected):
    for pod in pods:
        need(pod['status']['containerStatuses'][0]['imageID'].endswith('@sha256:322ba63b49d21c4030be2760c88ae03457fbe9454ee138906066b29bc68541ca'),'loaded App digest changed')
        result=site.call(['exec',pod['metadata']['name'],'-c','clawmanager-app','--','sh','-ec','sha256sum "$RUNTIME_AGENT_CA_FILE"; printf "PIN=%s\\n" "$RUNTIME_AGENT_CA_SHA256"'])
        need(result.split()[0].decode()==expected and ('PIN='+expected).encode() in result,'App did not load expected CA bytes')
        print('APP_AGENT_CA_READBACK_OK',pod['metadata']['name'],expected,flush=True)

def instance_status(records):
    dsn=(WORK/'fresh-sql-prepare.faa4osWr/sql-operation/mysql-installer.dsn').read_text().strip()
    creds,sep,address=dsn.rpartition('@tcp(');user,colon,password=creds.partition(':');_,end,tail=address.partition(')/');db=tail.split('?',1)[0]
    need(sep and colon and end and db and user and not any(x in password for x in '\r\n\x00'),'original installer DSN shape changed')
    query="SET SESSION TRANSACTION READ ONLY; START TRANSACTION; SELECT JSON_OBJECT('id',id,'status',status,'generation',runtime_generation,'error_code',COALESCE(runtime_error_code,''),'error_message',COALESCE(runtime_error_message,'')) FROM instances ORDER BY id; COMMIT;"
    shell='IFS= read -r MYSQL_PWD; export MYSQL_PWD; exec mysql --protocol=TCP -h127.0.0.1 -u "$1" --database="$2" --batch --skip-column-names --raw -e "$3"'
    for attempt in range(7):
        stamp=str(time.time_ns())
        p=subprocess.run(['kubectl','--kubeconfig',str(WORK/'operator.kubeconfig.yaml'),'--request-timeout=20s','-n',NS,'exec','-i','deployment/mysql','-c','mysql','--','sh','-c',shell,'sbk-readonly',user,db,query],input=(password+'\n').encode(),capture_output=True,timeout=45)
        retain(records/('instances-'+stamp+'.stdout.private'),p.stdout or b'\n');retain(records/('instances-'+stamp+'.stderr.private'),p.stderr or b'\n')
        need(p.returncode==0,'post-rotation instance read unconfirmed; retain TLS completion and private logs')
        rows=[json.loads(line) for line in p.stdout.splitlines() if line.strip()]
        running=[r['id'] for r in rows if r['status']=='running'];print('RUNNING_IDS',running,flush=True)
        if running==[1,2,3,7,8]:print('RUNTIME_TLS_AND_INSTANCE_RECOVERY_PASSED',flush=True);return
        if attempt<6:time.sleep(10)
    for row in rows:print('INSTANCE_STATUS',json.dumps(row),flush=True)
    print('RUNTIME_TLS_ROTATED_INSTANCE_RECOVERY_PENDING',flush=True)

def main(root):
    os.umask(0o077)
    need(os.name=='posix' and root.resolve(strict=True)==root and root.stat().st_mode & 0o077==0,'private original Linux records required')
    records=root/'runtime-rotation';records.mkdir(mode=0o700,exist_ok=True);site=Site(records)
    print('RUNTIME_CERT_ROTATION_RECORDS',records,flush=True)
    receipt=json.loads((root/'runtime-agent.receipt.private.json').read_bytes())
    need(receipt['Version']=='original-shared-agent-tls-materials.v1' and receipt['CA']['SHA256']==NEW_CA and receipt['Namespace']==NS,'actual issued CA required')
    need(datetime.datetime.fromisoformat(receipt['NotAfter'].replace('Z','+00:00'))>datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(minutes=15),'certificate window insufficient')
    new=pinned(receipt['CA']);old_receipt=json.loads(Path('/root/sbk/p2-runtime-rollout.us14OMgn/runtime-agent-tls.receipt.private.json').read_bytes())
    need(old_receipt['CA']['SHA256']==OLD_CA,'original CA changed');old=pinned(old_receipt['CA'])
    bridge=old.rstrip()+b'\n'+new;bridge_sha=sha(bridge)
    plan_file=records/'plan.private.json'
    if plan_file.exists():plan=json.loads(plan_file.read_bytes())
    else:
        app=site.get('deployment','clawmanager-app');need(app['metadata']['uid']==APP_UID,'App replaced')
        app_env={e['name']:e.get('value') for e in app['spec']['template']['spec']['containers'][0]['env']}
        need(app_env.get('RUNTIME_AGENT_CA_SHA256')==OLD_CA,'original App trust changed')
        bridge_spec,bridge_cm=app_spec(app['spec'],bridge_sha);final_spec,final_cm=app_spec(bridge_spec,NEW_CA)
        entries=[]
        need({t['Deployment'] for t in receipt['Targets']}==set(IMAGES),'unexpected TLS target roster')
        for target in receipt['Targets']:
            deployment=site.get('deployment',target['Deployment']);desired=runtime_spec(deployment,target)
            entries.append({'name':target['Deployment'],'uid':target['DeploymentUID'],'original':deployment['spec'],'desired':desired,'target':target})
        plan={'receipt_sha256':sha((root/'runtime-agent.receipt.private.json').read_bytes()),'original_app':app['spec'],'bridge_app':bridge_spec,'final_app':final_spec,
              'bridge_cm':bridge_cm,'final_cm':final_cm,'runtimes':entries}
        retain(plan_file,plan)
    need(plan['receipt_sha256']==sha((root/'runtime-agent.receipt.private.json').read_bytes()),'renewal receipt changed')
    for name,data in [(plan['bridge_cm'],bridge),(plan['final_cm'],new)]:
        site.ensure({'apiVersion':'v1','kind':'ConfigMap','metadata':{'name':name,'namespace':NS},'immutable':True,'data':{'ca.pem':data.decode()}})
    # Finalized operations only read back. Never reintroduce dual trust after
    # a completed final App switch during continuation.
    app=site.get('deployment','clawmanager-app')
    final_already=semantic(app['spec'])==semantic(plan['final_app'])
    if not final_already:
        print('APP_DUAL_TRUST_ROLLOUT',flush=True)
        pods=site.patch('app-bridge','clawmanager-app',plan['original_app'],plan['bridge_app'],APP_UID)
        verify_app_ca(site,pods,bridge_sha)
    for entry in plan['runtimes']:
        target=entry['target'];pinned(target['Certificate']);pinned(target['PrivateKey'])
        site.ensure(json.loads(pinned(target['SecretManifest'])))
        print('RUNTIME_CERT_ROLLOUT',entry['name'],flush=True)
        pods=site.patch(entry['name'],entry['name'],entry['original'],entry['desired'],entry['uid'])
        for pod in pods:
            image=IMAGES[entry['name']][1]
            need(pod['status']['containerStatuses'][0]['imageID'].endswith('@'+image.split('@')[1]),'loaded runtime digest changed')
            context=ssl.create_default_context(cafile=receipt['CA']['File']);context.minimum_version=ssl.TLSVersion.TLSv1_3
            with socket.create_connection((pod['status']['podIP'],19090),timeout=15) as tcp:
                with context.wrap_socket(tcp,server_hostname=receipt['ServerName']) as tls:
                    need(sha(tls.getpeercert(binary_form=True))==target['ServerCertificateDERSHA256'] and
                         [v for k,v in tls.getpeercert().get('subjectAltName',[]) if k=='URI']==[target['ServerURI']],'runtime leaf identity mismatch')
            print('NEW_RUNTIME_TLS_OK',entry['name'],pod['metadata']['uid'],image,flush=True)
    print('APP_FINAL_CA_ROLLOUT',flush=True)
    pods=site.patch('app-final','clawmanager-app',plan['bridge_app'],plan['final_app'],APP_UID)
    verify_app_ca(site,pods,NEW_CA)
    retain(records/'completed.json',{'Version':'p2-runtime-certificate-rotation.v1','CA':receipt['CA'],'NotAfter':receipt['NotAfter'],'ImagesPreserved':True,'BackupReady':False})
    print('RUNTIME_CERTIFICATES_ROTATED',records,flush=True)
    instance_status(records)

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--records-directory',type=Path,required=True);a=p.parse_args()
    try:main(a.records_directory)
    except (ValueError,OSError,KeyError,TypeError,subprocess.TimeoutExpired) as e:
        raise SystemExit('RUNTIME_CERT_ROTATION_UNCONFIRMED '+(str(e) if type(e) is ValueError else type(e).__name__))
