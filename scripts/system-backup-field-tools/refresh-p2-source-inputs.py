#!/usr/bin/env python3
"""Read the current P2 census and author a new base selection, without a hold.

Old coordinates, TLS issuance, Redis/MinIO operations and journals stay intact.
Every native send is retained before execution. Unknown sends require readback.
"""
import argparse
import datetime
import hashlib
import hmac
import importlib.util
import json
import os
from pathlib import Path
import subprocess

ROOT=Path('/root/sbk/p2-cert-renewal.1KyqMtsd')
NS='clawmanager-sbk-validation-system'
NSUID='0d1aebbb-fdd6-4b14-b9c5-0da456f8e65f'
CONTROLLER='sbk-d4f51b83b57e-controller'
NATIVE=Path('/root/sbk/p2-native-execution-eca964d4')
OLD_SELECTION=Path('/root/sbk/p2-selection-95b274c8/system-backup-first-adoption')
OLD_SELECTION_SHA='da1a3538a3fc6caa744cb237b8fed8170a4144b640bb2859c744ffd188026440'
CA_SHA='4d6ffb92650f28a7148a536b60cfab6a0b025856a4b30dba3b6059905c128478'
APP='10.130.14.23:5000/clawmanager@sha256:8287aa71bcfc9e1596d761a9b46891575f3708323300839c98e075a22875e780'
IMAGES={
 '10.130.14.23:5000/openclaw-lite@sha256:5d5f735bc8c0155d51841b574c98c6c02ca399085add0e3dc98b3d7e0ead3140',
 '10.130.14.23:5000/hermes-lite@sha256:279fa5b365f875de1fad93b0f58cda20599d2339fa067bf062e08ef80d770254'}

def need(ok,why):
 if not ok:raise ValueError(why)

def sha(raw):return hashlib.sha256(raw).hexdigest()
def encode(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
def pin(p):return {'File':str(p),'SHA256':sha(p.read_bytes())}
def retain(p,raw):
 if p.exists():need(not p.is_symlink() and p.read_bytes()==raw,'retained source input changed: '+p.name)
 else:
  with p.open('xb') as f:os.chmod(p,0o600);f.write(raw);f.flush();os.fsync(f.fileno())
 return pin(p)

def read(p):
 p=Path(p['File']);need(p.resolve(strict=True)==p and p.is_file() and not p.is_symlink() and
  p.stat().st_mode&0o077==0 and 0<p.stat().st_size<=16<<20,'private bounded original source file required')
 return p.read_bytes()

def checked(value):
 raw=read(value);need(sha(raw)==value['SHA256'],'original source bytes changed');return raw

def module(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m

def coherent_loaded(app_values,runtime_values):
 need(len(app_values)==2 and len(runtime_values)==2 and all(len(v)==4 for v in app_values+runtime_values),'complete loaded App/runtime cohort required')
 scopes={v[0].decode().strip() for v in app_values}
 need(scopes=={'installation'},'original App installation scope required')
 token=app_values[0][1]
 need(32<=len(token)<=8192 and not any(chr(v).isspace() for v in token),'actual loaded control credential required')
 need(all(hmac.compare_digest(token,v[1]) for v in app_values+runtime_values),'App/runtime control credentials differ')
 roots={v[2].decode() for v in runtime_values}
 need(roots=={'/workspaces'} and all(v[2] in (b'',b'/workspaces') for v in app_values),'loaded workspace roots differ')
 need(all(v[3].decode()==CA_SHA for v in app_values),'actual App CA is not the completed runtime rotation')
 return 'installation','/workspaces',token

def current_ca(tls,rotation,now):
 need(tls['Version']=='original-shared-agent-tls-materials.v1' and tls['Namespace']==NS and tls['NamespaceUID']==NSUID and
  tls['CA']['SHA256']==CA_SHA and rotation['Version']=='p2-runtime-certificate-rotation.v1' and rotation['CA']==tls['CA'] and
  rotation['NotAfter']==tls['NotAfter'] and rotation['ImagesPreserved'] is True,'completed original runtime CA rotation required')
 moment=lambda v:datetime.datetime.fromisoformat(v.replace('Z','+00:00'))
 need(moment(tls['NotBefore'])<=now<moment(tls['NotAfter']),'runtime certificate renewal required')
 return tls['CA']

def main(directory):
 os.umask(0o077);need(os.name=='posix','Linux operator required')
 r=ROOT/'current-source-inputs';r.mkdir(mode=0o700,exist_ok=True)
 need(r.resolve(strict=True)==r and r.stat().st_mode&0o077==0,'original private source records required')
 print('P2_CURRENT_SOURCE_RECORDS',r,flush=True)
 controller=json.loads((ROOT/'controller-relay/completed.json').read_bytes())
 need(controller['Version']=='p2-controller-relay-preparation.v1' and controller['ControllerEnabled'] is False and
  controller['ControllerImage']==APP,'completed disabled controller preparation required')
 common=json.loads((ROOT/'observer.sent.private.json').read_bytes())['Argv'];common=common[1:common.index('--definition-file')]
 pairs=dict(zip(common[::2],common[1::2]));plan=json.loads(Path(pairs['--plan-file']).read_bytes())
 need(plan['Target']['Namespace']==NS and plan['Target']['NamespaceUID']==NSUID,'same original enrolled installation required')
 build=json.loads((NATIVE/'BUILD_RECEIPT.json').read_bytes())
 coordinate_cli=NATIVE/'system-backup-first-install-materials'
 need(build['SourceRevision']=='eca964d42b96c31cb381531889a39c23a366ffab' and
  sha(coordinate_cli.read_bytes())==build['Binaries'][coordinate_cli.name]['SHA256'],'original coordinate author executable changed')
 need(sha(OLD_SELECTION.read_bytes())==OLD_SELECTION_SHA,'retained original selection author executable changed')
 def once(label,argv):
  result=r/(label+'.receipt.private.json');sent=r/(label+'.sent.private.json')
  if result.exists():return json.loads(result.read_bytes())
  need(not sent.exists(),'original '+label+' send unknown; retain and reconcile its outputs')
  retain(sent,encode({'Argv':argv}))
  with (r/(label+'.stdout.private')).open('xb') as out,(r/(label+'.stderr.private')).open('xb') as err:
   p=subprocess.run(argv,stdout=out,stderr=err,timeout=180)
  need(p.returncode==0,'original '+label+' refused; retain its private logs')
  raw=(r/(label+'.stdout.private')).read_bytes();value=json.loads(raw);retain(result,raw);return value
 out=r/'coordinates';out.mkdir(mode=0o700,exist_ok=True)
 coordinates=once('coordinates',[str(coordinate_cli),'author-initial-source-coordinates',*common,
  '--running-only-runtime-test','1,2,3,7,8:4,5,6','--output-directory',str(out)])
 need(coordinates['Version']=='original-initial-source-data-authored.v1' and coordinates['InstanceCount']==8 and
  coordinates['WriterQualified'] is False and coordinates['BackupReady'] is False,'actual original coordinate receipt required')
 data=json.loads(checked(coordinates['Coordinates']));snapshot=json.loads(checked(coordinates['KubernetesSnapshot']))
 need(data['InstallationID']==plan['Target']['InstallationID'] and data['NamespaceUID']==NSUID,'coordinate identity changed')
 print('P2_CURRENT_COORDINATES_AUTHORED',json.dumps(coordinates['Coordinates']),flush=True)
 seq=0
 base=['kubectl','--kubeconfig',pairs['--kubeconfig-file'],'--request-timeout=25s']
 def call(args,secret=False):
  nonlocal seq
  seq+=1;p=subprocess.run(base+args,capture_output=True,timeout=50)
  retain(r/('read-'+str(seq)+'.stderr.private'),p.stderr or b'\n')
  if not secret:retain(r/('read-'+str(seq)+'.stdout.private'),p.stdout or b'\n')
  need(p.returncode==0,'actual source API read refused at '+str(seq))
  return p.stdout
 def get(kind,name,ns=NS):return json.loads(call(['-n',ns,'get',kind,name,'-o','json']))
 def loaded(captured):
  name=captured['metadata']['name'];ns=captured['metadata']['namespace']
  def guard(actual):
   need(actual['metadata']['uid']==captured['metadata']['uid'] and not actual['metadata'].get('deletionTimestamp') and
    actual.get('status',{}).get('phase')=='Running' and actual['spec']['containers']==captured['spec']['containers'],
    'source container spec or Pod identity changed')
   a=actual['status'].get('containerStatuses',[]);b=captured['status'].get('containerStatuses',[])
   need(len(a)==len(b)==1 and a[0]['ready'] and a[0].get('containerID') and a[0]['containerID']==b[0].get('containerID'),
    'source container restarted or is not ready')
  guard(get('pod',name,ns))
  script=r'printf "%s\000%s\000%s\000%s" "$SYSTEM_BACKUP_SQL_GATE_SCOPE" "$RUNTIME_AGENT_CONTROL_TOKEN" "$RUNTIME_WORKSPACE_ROOT" "$RUNTIME_AGENT_CA_SHA256"'
  value=call(['-n',ns,'exec',name,'-c',captured['spec']['containers'][0]['name'],'--','sh','-c',script],secret=True).split(b'\0')
  guard(get('pod',name,ns));return value
 pods=[p for p in snapshot['Pods'] if p['metadata'].get('namespace')==NS and not p['metadata'].get('deletionTimestamp')]
 app=get('deployment','clawmanager-app');captured=next(d for d in snapshot['Deployments'] if d['metadata']['name']=='clawmanager-app')
 need(app['metadata']['uid']==captured['metadata']['uid'] and app['metadata']['generation']==captured['metadata']['generation'] and
  app['spec']['replicas']==2 and app['spec']['template']['spec']['containers'][0]['image']==APP,'App changed since actual coordinates')
 selector=app['spec']['selector']['matchLabels']
 apps=[p for p in pods if all(p['metadata'].get('labels',{}).get(k)==v for k,v in selector.items())]
 runtimes=[p for p in pods if len(p['spec']['containers'])==1 and p['spec']['containers'][0]['image'] in IMAGES]
 need({p['spec']['containers'][0]['image'] for p in runtimes}==IMAGES,'both pinned runtime images required')
 scope,workspace,token=coherent_loaded([loaded(p) for p in apps],[loaded(p) for p in runtimes])
 tls=json.loads((ROOT/'runtime-agent.receipt.private.json').read_bytes());rotation=json.loads((ROOT/'runtime-rotation/completed.json').read_bytes())
 ca=current_ca(tls,rotation,datetime.datetime.now(datetime.timezone.utc));checked(ca)
 credential=r/'agent-control-token.private';retain(credential,token)
 projection=module('current_writer_source_projection',directory/'prepare-p2-writer-selection.py')
 config=projection.source_config(data,scope,workspace,credential,ca);config_file=r/'source-config.json';retain(config_file,encode(config))
 observer=json.loads((ROOT/'observer-host-current-agent/host.definition.json').read_bytes())
 checked(observer['PKIDefinition']);checked(observer['PKIReceipt'])
 startup=Path('/root/sbk/p2-materials-1dd1ae71.lVSEBfl2/runtime-startup-images/runtime-startup-images.json')
 need(sha(startup.read_bytes())=='28e979483e004141f3452f13609057fc0cde5bb82e4ca1d34e299cb536087068','qualified original runtime input bytes changed')
 selected=r/'selection';journal=r/'journal'
 selected.mkdir(mode=0o700,exist_ok=True);journal.mkdir(mode=0o700,exist_ok=True)
 argv=[str(OLD_SELECTION),'--action','prepare-selection',*common,'--source-config-file',str(config_file),'--source-config-sha256',sha(config_file.read_bytes()),
  '--runtime-startup-images-file',str(startup),'--runtime-startup-images-sha256',sha(startup.read_bytes()),
  '--observer-definition-file',observer['PKIDefinition']['File'],'--observer-definition-sha256',observer['PKIDefinition']['SHA256'],
  '--observer-receipt-file',observer['PKIReceipt']['File'],'--observer-receipt-sha256',observer['PKIReceipt']['SHA256'],
  '--selection-output-directory',str(selected),'--journal-directory',str(journal)]
 writer=once('writer-selection',argv)
 need(writer['Version']=='original-writer-selection-materials.v1' and writer['State']=='actual_original_complete_base_selection_materialized_no_hold' and
  writer['SourceCount']==8,'actual complete base writer selection required')
 selection=json.loads(checked(writer['Selection']));checked(writer['SourceCoordinates'])
 tenants=selection.get('TenantPro',[])
 need(len(tenants)==1 and tenants[0]['Source']['ID']==2 and tenants[0]['Identity']['Namespace']=='clawmanager-sbk-validation-user-1',
  'original tenant Pro source must be retained')
 need(selection['AgentCA']==ca,'new selection did not preserve the actual renewed runtime CA')
 print('P2_CURRENT_BASE_WRITER_SELECTION_AUTHORED_NO_HOLD',json.dumps(writer['Selection']),flush=True)
 # Only current raw Kubernetes objects are indexed. No control-table rewrite,
 # Secret printing, redacted graph hydration, metadata grant or source stop.
 index=r/'capture-index.json'
 if not index.exists():
  resources='deployments,replicasets,statefulsets,daemonsets,jobs,cronjobs,pods,services,persistentvolumeclaims,serviceaccounts,configmaps,secrets,roles,rolebindings,networkpolicies,horizontalpodautoscalers'
  labels=[('namespaces',['get','namespaces','-o','json']),('nodes',['get','nodes','-o','json']),
   ('storage',['get','persistentvolumes,storageclasses','-o','json'])]
  for ns in [NS,'clawmanager-sbk-validation-user-1']:
   labels.append(('namespace-'+ns,['-n',ns,'get',resources,'-o','json']))
  pins=[]
  for label,args in labels:
   raw=call(args);json.loads(raw);path=r/(label+'.private.json');pins.append({'label':label,**retain(path,raw)})
  retain(index,encode({'version':'p2-current-kubernetes-inputs.v1','errors':[],
   'recorded_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'remote_private_inputs':pins}))
 inventory=json.loads(index.read_bytes())
 for value in inventory['remote_private_inputs']:checked(value)
 deployment=get('deployment',CONTROLLER)
 ctrl_pods=[p for p in json.loads(checked(next(v for v in inventory['remote_private_inputs'] if v['label']=='namespace-'+NS)))['items'] if
  p['kind']=='Pod' and p['metadata']['name'].startswith(CONTROLLER+'-') and not p['metadata'].get('deletionTimestamp')]
 need(len(ctrl_pods)==1 and ctrl_pods[0]['metadata']['uid']==controller['ControllerPodUID'] and
  deployment['metadata']['uid']=='e4e27f27-8f02-40ab-8c62-09f2ffa3fafa','current prepared controller identity changed')
 retain(r/'completed.json',encode({'Version':'p2-current-source-inputs.v1','CoordinatesReceipt':pin(r/'coordinates.receipt.private.json'),
  'WriterReceipt':pin(r/'writer-selection.receipt.private.json'),'RawIndex':pin(index),'SourceConfig':pin(config_file),
  'SourceCount':8,'TenantProRetained':True,'SourceStopSent':False,'BackupReady':False}))
 print('P2_CURRENT_SOURCE_INPUTS_READY_NO_HOLD',r,flush=True)

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--tool-directory',type=Path,required=True);a=p.parse_args()
 try:main(a.tool_directory)
 except (ValueError,OSError,KeyError,TypeError,subprocess.SubprocessError) as e:raise SystemExit('P2_CURRENT_SOURCE_INPUTS_UNCONFIRMED '+(str(e) if type(e) is ValueError else type(e).__name__))
