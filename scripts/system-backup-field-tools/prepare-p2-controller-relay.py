#!/usr/bin/env python3
"""Pin the existing waiting controller; issue original relay/record-key DATA.

Keeps activation disabled and never writes controller.env or its ready marker.
Does not initialize an installation, grant a task, stop a source or start relay.
"""
import argparse
import copy
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess

ROOT=Path('/root/sbk/p2-cert-renewal.1KyqMtsd')
NS='clawmanager-sbk-validation-system'
CONTROLLER='sbk-d4f51b83b57e-controller'
UID='e4e27f27-8f02-40ab-8c62-09f2ffa3fafa'
OLD='10.130.14.23:5000/clawmanager@sha256:322ba63b49d21c4030be2760c88ae03457fbe9454ee138906066b29bc68541ca'
APP='10.130.14.23:5000/clawmanager@sha256:8287aa71bcfc9e1596d761a9b46891575f3708323300839c98e075a22875e780'
REV='eca964d42b96c31cb381531889a39c23a366ffab'
HELPER_SHA='ab1539c5e06c8c237e8516d9985b162fbec3216570abb5ebec1902df47f7052c'
KUBE='/root/sbk-validation-tls-inspect.7LVU7vpE/operator.kubeconfig.yaml'
def need(ok,why):
 if not ok:raise ValueError(why)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def encode(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
def retain(p,raw):
 if p.exists():need(not p.is_symlink() and p.read_bytes()==raw,'original controller/issuer records changed')
 else:
  with p.open('xb') as f:os.chmod(p,0o600);f.write(raw);f.flush();os.fsync(f.fileno())
 return {'File':str(p),'SHA256':sha(raw)}
def pin(p):return {'File':str(p),'SHA256':sha(p.read_bytes())}
def load(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m

def controller_desired(dep,binary,A):
 need(dep['metadata']['uid']==UID and dep['metadata']['namespace']==NS,'same original controller required')
 patch=A.waiting_controller_patch(dep,binary);wanted=copy.deepcopy(dep['spec']);containers=wanted['template']['spec']['containers']
 need(wanted.get('replicas')==1 and len(containers)==2 and {c['name'] for c in containers}=={'controller','installation-owner'} and
      all(c['image']==OLD for c in containers),'original waiting controller/owner pair required')
 for c in containers:
  c['image']=APP
  if c['name']=='controller':c['command']=patch[-1]['value']
 return wanted

def main(directory,native_directory=None):
 os.umask(0o077);need(os.name=='posix','Linux operator required')
 records=ROOT/'controller-relay';records.mkdir(mode=0o700,exist_ok=True)
 need(records.resolve(strict=True)==records and records.stat().st_mode&0o077==0,'original private controller records required')
 A=load('p2_controller_assembly',directory/'assemble-p2-installation-candidate.py')
 h=Path('/root/sbk/p2-runtime-cert-rotation-fcc26a0a/rotate-p2-runtime-certificates.py')
 need(sha(h.read_bytes())==HELPER_SHA,'original CAS transport helper changed');m=load('original_cas_transport',h);site=m.Site(records)
 native_directory=native_directory or directory
 receipt=json.loads((native_directory/'BUILD_RECEIPT.json').read_bytes())
 need(receipt['SourceRevision']==REV and receipt['BackendTree']=='6361d0c8377039d86de7725fadda968464411e73' and receipt['VersionName']=='p2-eca964d4','same fixed-source native tool build required')
 tools={}
 for name,v in receipt['Binaries'].items():
  p=native_directory/name;raw=p.read_bytes()
  need(sha(raw)==v['SHA256'] and len(raw)==v['Bytes'] and raw[:6]==b'\x7fELF\x02\x01' and raw[18:20]==b'\x3e\x00','actual native ELF bytes changed')
  tools[name]=pin(p)
 app=json.loads((ROOT/'execution-app-rollout/completed.json').read_bytes())
 need(app['Image']==APP and app['SourceRevision']==REV and app['Replicas']==2,'completed actual App rollout required')
 node_tls=json.loads((ROOT/'node-cert-rotation/node-mtls-readback.json').read_bytes())
 need(len(node_tls['Checks'])==8,'completed actual Node TLS readback required')
 binary_name='system-backup-v2-controller';target='/run/system-backup/bin/'+binary_name
 target_pin={'File':target,'SHA256':tools[binary_name]['SHA256']}
 plan_file=records/'controller-plan.private.json'
 if plan_file.exists():plan=json.loads(plan_file.read_bytes())
 else:
  current=site.get('deployment',CONTROLLER);wanted=controller_desired(current,target_pin,A)
  plan={'Original':current['spec'],'Desired':wanted,'Binary':target_pin,'SourceRevision':REV,'Tool':tools[binary_name]}
  retain(plan_file,encode(plan))
 need(plan['Binary']==target_pin and plan['SourceRevision']==REV,'controller executable selection changed')
 desired=plan['Desired']
 permission_recovery=records/'owner-directory-permissions/completed.json'
 if permission_recovery.exists():
  settled=load('controller_owner_permission_successor',directory/'settle-p2-controller-owner-permissions.py')
  desired=settled.reconciled_spec(plan,json.loads(permission_recovery.read_bytes()),pin(plan_file))
 site.call(['exec','deployment/'+CONTROLLER,'-c','controller','--','sh','-ec','test ! -e /run/system-backup/runtime/controller.env.ready'])
 dep=site.get('deployment',CONTROLLER)
 need(dep['metadata']['uid']==UID and m.semantic(dep['spec']) in [m.semantic(plan['Original']),m.semantic(desired)],'controller spec drift')
 selector=','.join(k+'='+v for k,v in sorted(dep['spec']['selector']['matchLabels'].items()))
 pods=[p for p in json.loads(site.call(['get','pods','-l',selector,'-o','json']))['items'] if not p['metadata'].get('deletionTimestamp')]
 need(len(pods)==1,'one actual controller Pod required');pod=pods[0]
 def stage(name):
  dest='/run/system-backup/bin/'+name;digest=tools[name]['SHA256'];local=native_directory/name
  inspect='test "$(id -u)" = 65532; if test -e "$1"; then test -f "$1"; test ! -L "$1"; sha256sum "$1"; else printf "ABSENT\\n"; fi'
  got=site.call(['exec',pod['metadata']['name'],'-c','installation-owner','--','sh','-ec',inspect,'p2-stage-check',dest]).split()
  if got==[b'ABSENT']:
   marker=records/(name+'.delivery.sent.json');need(not marker.exists(),'native executable delivery unknown; reconcile original file')
   retain(marker,encode({'Tool':tools[name],'PodUID':pod['metadata']['uid'],'Destination':dest}))
   # Create-only public executable delivery into the original input PVC. A
   # partial file remains for reconciliation; it is never silently overwritten.
   script='umask 077; test "$(id -u)" = 65532; d=/run/system-backup/bin; test ! -L "$d"; mkdir -p "$d"; test "$(stat -c %u "$d")" = 65532; test ! -e "$1"; test ! -L "$1"; set -C; cat > "$1"; chmod 500 "$1"; test "$(sha256sum "$1" | cut -d " " -f 1)" = "$2"; sync; printf "DELIVERED\\n"'
   argv=['kubectl','--kubeconfig',KUBE,'--request-timeout=90s','-n',NS,'exec','-i',pod['metadata']['name'],'-c','installation-owner','--','sh','-ec',script,'p2-stage',dest,digest]
   with local.open('rb') as stream:
    p=subprocess.run(argv,stdin=stream,capture_output=True,timeout=180)
   retain(records/(name+'.delivery.stdout.private'),p.stdout or b'\n');retain(records/(name+'.delivery.stderr.private'),p.stderr or b'\n')
   need(p.returncode==0 and p.stdout.strip()==b'DELIVERED','native executable delivery unconfirmed; retain partial file')
  else:need(got and got[0].decode()==digest,'existing staged executable differs; preserve it')
  actual=site.call(['exec',pod['metadata']['name'],'-c','controller','--','sha256sum',dest]).split()
  need(actual and actual[0].decode()==digest,'controller-side executable readback mismatch')
  print('CONTROLLER_NATIVE_EXECUTABLE_STAGED',name,digest,flush=True)
 for name in ['system-backup-v2-controller','system-backup-c1-native-inputs']:stage(name)
 pods=site.patch('controller-pinned-executable',CONTROLLER,plan['Original'],desired,UID)
 need(len(pods)==1,'controller roster not settled');pod=pods[0]
 need(all(s['imageID']==APP for s in pod['status']['containerStatuses']),'controller/owner loaded a different base image')
 checked=site.call(['exec',pod['metadata']['name'],'-c','controller','--','sh','-ec','test ! -e /run/system-backup/runtime/controller.env.ready; sha256sum /run/system-backup/bin/system-backup-v2-controller']).split()
 need(checked and checked[0].decode()==target_pin['SHA256'],'final waiting controller executable changed')
 retain(records/'controller-current.private.json',encode(pod))
 print('P2_CONTROLLER_FIXED_SOURCE_WAITING',pod['metadata']['name'],pod['metadata']['uid'],flush=True)
 common=json.loads((ROOT/'observer.sent.private.json').read_bytes())['Argv'];common=common[1:common.index('--definition-file')]
 pairs=dict(zip(common[::2],common[1::2]));need('--plan-file' in pairs,'original owner arguments required')
 original_plan=json.loads(Path(pairs['--plan-file']).read_bytes());need(original_plan['Target']['Namespace']==NS,'same original installation required')
 native=Path(pairs['--plan-file']).parent;issuer=native/'issuer.private'
 need(issuer.is_file() and len(issuer.read_bytes())==64,'original enrollment signer file required')
 mirror=Path(json.loads((ROOT/'runtime-mirror.location.json').read_bytes())['Directory'])
 def once(label,argv):
  output=records/(label+'.receipt.private.json');intent=records/(label+'.sent.private.json')
  if output.exists():return json.loads(output.read_bytes())
  need(not intent.exists(),'native '+label+' send unknown: retain output, query original operation')
  retain(intent,encode({'Argv':argv}))
  with (records/(label+'.stdout.private')).open('xb') as stdout,(records/(label+'.stderr.private')).open('xb') as stderr:
   p=subprocess.run(argv,stdout=stdout,stderr=stderr,timeout=180)
  need(p.returncode==0,'native '+label+' refused; retain private logs and same operation')
  raw=(records/(label+'.stdout.private')).read_bytes();v=json.loads(raw);retain(output,raw);return v
 selection_file=records/'relay-pki.inputs.json'
 if not selection_file.exists():
  observed=json.loads((ROOT/'observer.receipt.private.json').read_bytes())
  until=min(datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(hours=23),datetime.datetime.fromisoformat(observed['NotAfter'].replace('Z','+00:00'))-datetime.timedelta(minutes=5))
  output=mirror/'original-relay-pki';output.mkdir(mode=0o700)
  value={'Version':'original-relay-pki-inputs.v1','ControllerDeployment':CONTROLLER,'ControllerPod':pod['metadata']['name'],'Service':CONTROLLER,'OutputDirectory':str(output),'Until':until.replace(microsecond=0).isoformat().replace('+00:00','Z')}
  retain(selection_file,encode(value))
 pki=once('relay-pki',[tools['system-backup-c1-native-inputs']['File'],'relay-pki','--mode','issue',*common,'--inputs-file',str(selection_file),'--inputs-sha256',sha(selection_file.read_bytes()),'--issuer-private-file',str(issuer),'--issuer-private-sha256',sha(issuer.read_bytes())])
 need(pki['Version']=='original-relay-pki-result.v1' and pki['State']=='original_relay_pki_material_issued_service_tls_not_yet_verified' and pki['DeploymentUID']==UID,'actual original relay PKI required')
 for key in ['Manifest','Signature','CA','IssuerKey','ServerCertificate','ServerKey','ClientCertificate','ClientKey']:A.read(pki[key])
 print('P2_ORIGINAL_RELAY_PKI_ISSUED_NOT_SERVED',pki['Endpoint'],flush=True)
 material=Path('/root/sbk/p2-api-runtime-inputs.WWN62yPS/runtime-issuers/original-runtime-issuers.json')
 need(sha(material.read_bytes())=='e9b858488514ad96bd9b16f1ae26ddf289439c4b73d50f6ea63c041c52619466','original purpose issuer material changed')
 export=once('record-key-export',[tools['system-backup-original-enroll']['File'],'runtime-issuers','--mode','export-record-keys',*common,'--dsn-sha256',sha(Path(pairs['--dsn-file']).read_bytes()),'--source-issuer-private-file',str(issuer),'--material-file',str(material),'--material-sha256',sha(material.read_bytes()),'--output-directory',str(mirror/'execution-keys')])
 need(export['Version']=='original-runtime-record-key-export-result.v1','actual original two-key export required')
 for key in ['Export','RecordKey','CaptureKey']:A.read(export[key])
 need(len(A.read(export['RecordKey']))==len(A.read(export['CaptureKey']))==32,'actual original random32 files required')
 print('P2_ORIGINAL_RECORD_KEYS_EXPORTED_NOT_A_GRANT',json.dumps({k:export[k] for k in ['Export','RecordKey','CaptureKey']}),flush=True)
 retain(records/'completed.json',encode({'Version':'p2-controller-relay-preparation.v1','ControllerPodUID':pod['metadata']['uid'],'ControllerImage':APP,'SourceRevision':REV,'RelayReceipt':pin(records/'relay-pki.receipt.private.json'),'RecordExportReceipt':pin(records/'record-key-export.receipt.private.json'),'ControllerEnabled':False,'RelayStarted':False,'BackupReady':False}))
 print('P2_CONTROLLER_RELAY_INPUTS_PREPARED_NOT_ACTIVATED',records,flush=True)
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--tool-directory',type=Path,required=True);p.add_argument('--native-directory',type=Path);a=p.parse_args()
 try:main(a.tool_directory,a.native_directory)
 except (ValueError,OSError,KeyError,TypeError,subprocess.SubprocessError) as e:raise SystemExit('P2_CONTROLLER_RELAY_UNCONFIRMED '+(str(e) if type(e) is ValueError else type(e).__name__))
