#!/usr/bin/env python3
"""This approved 115-object Skills migration; private originals survive cleanup."""
import argparse
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
from urllib.parse import urlencode

ROOT=Path('/root/sbk/p2-cert-renewal.1KyqMtsd/skills-versioning-20261114')
NS='clawmanager-sbk-validation-system'
BUCKET='clawmanager-skills'
PREFIX='skills/'
KUBE='/root/sbk-validation-tls-inspect.7LVU7vpE/operator.kubeconfig.yaml'
WRITERS={'clawmanager-app':('8ebd4d4c-57b6-4a82-b310-fae596681a4e',2),'skill-scanner':('aa245d54-7689-4ed8-85b3-f3770f19cbf9',1)}
HEADERS=('ContentType','ContentEncoding','ContentLanguage','CacheControl','ContentDisposition','WebsiteRedirectLocation')

def need(ok,message):
    if not ok:raise ValueError(message)

def sha(raw):return hashlib.sha256(raw).hexdigest()
def encoded(value):return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
def retain(path,value):
    raw=value if isinstance(value,bytes) else encoded(value)
    if path.exists():need(path.read_bytes()==raw,'retained migration record changed')
    else:
        with path.open('xb') as f:
            os.chmod(path,0o600);f.write(raw);f.flush();os.fsync(f.fileno())
    return {'File':str(path),'SHA256':sha(raw)}

def kube(args,payload=None):
    r=subprocess.run(['kubectl','--kubeconfig',KUBE,'--request-timeout=25s','-n',NS,*args],input=payload,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=40)
    need(r.returncode==0,'Kubernetes operation failed; inspect private migration records')
    return json.loads(r.stdout)

def get(kind,name):return kube(['get',kind,name,'-o','json'])

def guarded_spec(original,current,replicas):
    name=original['metadata']['name'];uid,count=WRITERS[name]
    need(original['metadata']['uid']==current['metadata']['uid']==uid and original['spec']['replicas']==count and not current['metadata'].get('deletionTimestamp'),'writer identity changed')
    expected=copy.deepcopy(original['spec']);expected['replicas']=current['spec']['replicas']
    need(current['spec']==expected and current['spec']['replicas'] in (0,count),'writer specification changed')
    return [{'op':'test','path':'/metadata/uid','value':uid},{'op':'test','path':'/metadata/resourceVersion','value':current['metadata']['resourceVersion']},
            {'op':'test','path':'/spec','value':current['spec']},{'op':'replace','path':'/spec/replicas','value':replicas}]

def set_replicas(name,count):
    original=json.loads((ROOT/(name+'.before.private.json')).read_bytes());current=get('deployment',name)
    patch=guarded_spec(original,current,count)
    if current['spec']['replicas']!=count:
        # Each attempt has a distinct, durable request; never overwrite an unknown send.
        attempts=ROOT/'deployment-requests';attempts.mkdir(mode=0o700,exist_ok=True)
        record=attempts/(name+'-'+str(time.time_ns())+'.json');retain(record,patch)
        kube(['patch','deployment',name,'--type=json','-p',json.dumps(patch),'-o','json'])
    return original

def drained():
    for name in WRITERS:
        original=json.loads((ROOT/(name+'.before.private.json')).read_bytes());current=get('deployment',name);guarded_spec(original,current,0)
        need(current['spec']['replicas']==0,'writers must remain stopped')
        selector=','.join(k+'='+v for k,v in original['spec']['selector']['matchLabels'].items())
        pods=kube(['get','pods','-l',selector,'-o','json'])
        need(not pods.get('metadata',{}).get('continue') and not pods['items'],'writer Pods remain')

def restore():
    for name,(_,count) in WRITERS.items():set_replicas(name,count)
    end=time.monotonic()+180
    while True:
        ready=True
        for name,(_,count) in WRITERS.items():
            original=json.loads((ROOT/(name+'.before.private.json')).read_bytes());v=get('deployment',name);guarded_spec(original,v,count)
            s=v.get('status',{});ready=ready and s.get('observedGeneration')==v['metadata']['generation'] and s.get('readyReplicas')==count and s.get('updatedReplicas')==count
        if ready:break
        need(time.monotonic()<end,'writer restoration pending; run restore again');time.sleep(2)
    print('P2_SKILLS_WRITERS_RESTORED',json.dumps({n:v[1] for n,v in WRITERS.items()}),flush=True)

def inventory(s):
    rows=[]
    for page,v in enumerate(s.get_paginator('list_object_versions').paginate(Bucket=BUCKET,PaginationConfig={'PageSize':1000})):
        need(page<10 and not v.get('DeleteMarkers'),'unexpected object history or delete markers')
        for x in v.get('Versions',[]):
            need(x['Key'].startswith(PREFIX) and x['Size']<=16<<20,'foreign object or oversized object')
            rows.append({k:x[k] for k in ('Key','VersionId','ETag','Size','IsLatest')})
        need(len(rows)<=230,'unexpected version count')
    return sorted(rows,key=lambda v:(v['Key'],v['VersionId']))

def metadata(head):
    need(not any(head.get(k) for k in ('Expires','SSECustomerAlgorithm','ServerSideEncryption','ObjectLockMode','ObjectLockRetainUntilDate','ObjectLockLegalHoldStatus')),'unreviewed protected or encrypted object metadata')
    return {**{k:head[k] for k in HEADERS if k in head},'Metadata':head.get('Metadata',{})}

def fetch(s,key,version):
    response=s.get_object(Bucket=BUCKET,Key=key,VersionId=version)
    try:raw=response['Body'].read((16<<20)+1)
    finally:response['Body'].close()
    need(len(raw)==response['ContentLength'] and len(raw)<=16<<20,'object length changed')
    tags=s.get_object_tagging(Bucket=BUCKET,Key=key,VersionId=version)['TagSet']
    return raw,metadata(response),sorted(tags,key=lambda t:t['Key'])

def prepare(s):
    path=ROOT/'snapshot.json'
    if path.exists():
        snap=json.loads(path.read_bytes())
        for row in snap['Objects']:need(sha(Path(row['Original']['File']).read_bytes())==row['Original']['SHA256'],'original backup changed')
        return snap
    need(s.get_bucket_versioning(Bucket=BUCKET).get('Status') is None,'expected original unversioned bucket')
    rows=inventory(s)
    need(len(rows)==115 and sum(x['Size'] for x in rows)==2837567 and all(x['VersionId']=='null' and x['IsLatest'] for x in rows),'approved original object roster changed')
    uploads=s.list_multipart_uploads(Bucket=BUCKET)
    need(not uploads.get('Uploads') and not uploads.get('IsTruncated'),'active multipart writes require reconciliation')
    directory=ROOT/'original-objects';directory.mkdir(mode=0o700,exist_ok=True);objects=[]
    for row in rows:
        raw,meta,tags=fetch(s,row['Key'],'null');need(len(raw)==row['Size'],'original object size changed')
        pin=retain(directory/sha(row['Key'].encode()),raw)
        objects.append({**row,'Original':pin,'Metadata':meta,'Tags':tags})
    need(inventory(s)==rows,'source changed while preserving originals')
    snap={'Version':'p2-skills-original-snapshot.v1','Bucket':BUCKET,'Objects':objects,'Inventory':rows}
    retain(path,snap);print('P2_SKILLS_ORIGINALS_PRESERVED',json.dumps({'Objects':len(rows),'Bytes':2837567,'SnapshotSHA256':sha(path.read_bytes())}),flush=True)
    return snap

def verify(s,row,version):
    raw,meta,tags=fetch(s,row['Key'],version)
    need(sha(raw)==row['Original']['SHA256'] and meta==row['Metadata'] and tags==row['Tags'],'object content metadata or tags changed')

def migrate(s,snap):
    drained()
    status=s.get_bucket_versioning(Bucket=BUCKET).get('Status')
    if status is None:
        need(inventory(s)==snap['Inventory'],'source changed before versioning')
        for row in snap['Objects']:verify(s,row,'null')
        retain(ROOT/'enable-versioning.intent.json',{'Bucket':BUCKET,'Status':'Enabled','OriginalSnapshotSHA256':sha((ROOT/'snapshot.json').read_bytes())})
        s.put_bucket_versioning(Bucket=BUCKET,VersioningConfiguration={'Status':'Enabled'})
    need(s.get_bucket_versioning(Bucket=BUCKET).get('Status')=='Enabled' and (ROOT/'enable-versioning.intent.json').exists(),'versioning outcome differs')
    records=ROOT/'objects';records.mkdir(mode=0o700,exist_ok=True)
    for index,row in enumerate(snap['Objects']):
        if index%10==0:drained()
        key=row['Key'];stem=sha(key.encode());receipt=records/(stem+'.completed.json')
        if receipt.exists():
            done=json.loads(receipt.read_bytes());need(done['Original']==row['Original'],'saved original differs');verify(s,row,done['VersionId']);continue
        candidates=[x for x in inventory(s) if x['Key']==key and x['VersionId']!='null']
        intent=records/(stem+'.put.intent.json')
        if candidates:
            need(intent.exists() and len(candidates)==1 and candidates[0]['IsLatest'],'unknown version creation; do not repeat PUT')
            version=candidates[0]['VersionId']
        else:
            need(not intent.exists(),'PUT outcome unknown; reconcile before resend')
            verify(s,row,'null');raw=Path(row['Original']['File']).read_bytes();need(sha(raw)==row['Original']['SHA256'],'original backup changed')
            retain(intent,{'Key':key,'Original':row['Original'],'Metadata':row['Metadata'],'Tags':row['Tags']})
            result=s.put_object(Bucket=BUCKET,Key=key,Body=raw,**row['Metadata'],Tagging=urlencode({t['Key']:t['Value'] for t in row['Tags']}))
            version=result.get('VersionId');need(version and version!='null','PUT did not create immutable version')
        verify(s,row,version);retain(receipt,{'Key':key,'Original':row['Original'],'VersionId':version})
    # Do not remove ANY null record until ALL 115 immutable copies are verified.
    all_rows=inventory(s)
    need({x['Key'] for x in all_rows}=={x['Key'] for x in snap['Objects']},'object roster changed')
    for row in snap['Objects']:
        done=json.loads((records/(sha(row['Key'].encode())+'.completed.json')).read_bytes());verify(s,row,done['VersionId'])
        versions={x['VersionId'] for x in all_rows if x['Key']==row['Key']}
        need(versions in ({done['VersionId']},{'null',done['VersionId']}),'untracked object history; preserve originals')
        latest=[x for x in all_rows if x['Key']==row['Key'] and x['IsLatest']]
        need(len(latest)==1 and latest[0]['VersionId']==done['VersionId'],'latest object changed')
    retain(ROOT/'all-new-versions-verified.json',{'Objects':115,'OriginalSnapshotSHA256':sha((ROOT/'snapshot.json').read_bytes())})
    drained()
    for index,row in enumerate(snap['Objects']):
        if index%10==0:drained()
        stem=sha(row['Key'].encode());present=[x for x in inventory(s) if x['Key']==row['Key'] and x['VersionId']=='null'];intent=records/(stem+'.remove-null.intent.json')
        if present:
            verify(s,row,'null');retain(intent,{'Key':row['Key'],'VersionId':'null','RetainedOriginal':row['Original']})
            s.delete_object(Bucket=BUCKET,Key=row['Key'],VersionId='null')
        else:need(intent.exists(),'null version absent without migration record')
    final=inventory(s);need(len(final)==115 and all(x['IsLatest'] and x['VersionId']!='null' for x in final),'final version roster differs')
    for row in snap['Objects']:
        done=json.loads((records/(sha(row['Key'].encode())+'.completed.json')).read_bytes());verify(s,row,done['VersionId'])
    retain(ROOT/'migration.completed.json',{'Version':'p2-skills-versioning-completed.v1','Bucket':BUCKET,'Objects':115,'Bytes':2837567,'OriginalSnapshot':{'File':str(ROOT/'snapshot.json'),'SHA256':sha((ROOT/'snapshot.json').read_bytes())},'Versions':final,'OriginalDataRetained':True})
    print('P2_SKILLS_VERSION_MIGRATION_VERIFIED',json.dumps({'Objects':115,'Bytes':2837567,'OriginalDataRetained':True}),flush=True)

def client():
    import boto3
    from botocore.config import Config
    dep=get('deployment','minio');need(dep['metadata']['uid']=='6a14e6f1-253b-45ab-96d9-66cf3b22ef23','MinIO workload changed')
    env=dep['spec']['template']['spec']['containers'][0]['env']
    def resolve(name):
        values=[x for x in env if x['name']==name];need(len(values)==1,'ambiguous MinIO owner environment');v=values[0]
        if 'value' in v:return v['value']
        ref=v['valueFrom']['secretKeyRef'];need(not ref.get('optional'),'optional owner credential refused');return base64.b64decode(get('secret',ref['name'])['data'][ref['key']]).decode()
    ca=Path('/root/sbk/p2-minio-prepare.9vnemhVi/minio-tls/ca.pem');need(sha(ca.read_bytes())=='1ee23762b1a38a93b709641a79191466e45f8b2bda208e0c1901d25018054450','MinIO CA changed')
    return boto3.client('s3',endpoint_url='https://minio.'+NS+'.svc:9000',region_name='us-east-1',aws_access_key_id=resolve('MINIO_ROOT_USER'),aws_secret_access_key=resolve('MINIO_ROOT_PASSWORD'),verify=str(ca),config=Config(proxies={},connect_timeout=10,read_timeout=20,retries={'max_attempts':0},s3={'addressing_style':'path'}))

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=['prepare','apply','restore']);args=p.parse_args();os.umask(0o077)
    need(ROOT.resolve()==ROOT and ROOT.is_dir(),'original private migration directory required')
    import fcntl
    with (ROOT/'migration.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if args.action=='restore':restore();return
        s=client();snap=prepare(s)
        if args.action=='prepare':return
        for kind in ['jobs','cronjobs']:need(not kube(['get',kind,'-o','json'])['items'],'new batch writer requires reconciliation')
        try:
            for name in WRITERS:set_replicas(name,0)
            end=time.monotonic()+120
            while True:
                try:drained();break
                except ValueError:
                    need(time.monotonic()<end,'writer drain pending');time.sleep(2)
            migrate(s,snap)
        finally:restore()

if __name__=='__main__':
    try:main()
    except Exception as error:raise SystemExit('P2_SKILLS_MIGRATION_UNCONFIRMED '+(str(error) if isinstance(error,ValueError) else type(error).__name__))
