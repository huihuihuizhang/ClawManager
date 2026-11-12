#!/usr/bin/env python3
"""Use the fixed-source App image executable instead of its old PVC overlay.

No migrations, controller activation, source stop, owner reinitialization or
backup submission. The existing App SQL gate must remain installation-scoped.
"""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import time

ROOT=Path('/root/sbk/p2-cert-renewal.1KyqMtsd')
OLD='10.130.14.23:5000/clawmanager@sha256:322ba63b49d21c4030be2760c88ae03457fbe9454ee138906066b29bc68541ca'
APP='10.130.14.23:5000/clawmanager@sha256:8287aa71bcfc9e1596d761a9b46891575f3708323300839c98e075a22875e780'
WORKER='10.130.14.23:5000/clawmanager-backup-worker@sha256:754cfd2cd57357d148daf131ead46ec715db9e34d6cd5a5a5d03c59c52e22218'
REV='eca964d42b96c31cb381531889a39c23a366ffab'
APP_ELF='7983c1643dd4d20db904354d62f5f2477e418d4a1a4e8219ef2716e222b2a25b'
UID='8ebd4d4c-57b6-4a82-b310-fae596681a4e'
CA='4d6ffb92650f28a7148a536b60cfab6a0b025856a4b30dba3b6059905c128478'
NS='clawmanager-sbk-validation-system'
HELPER_SHA='ab1539c5e06c8c237e8516d9985b162fbec3216570abb5ebec1902df47f7052c'
INIT_IMAGE='10.130.14.23:5000/clawmanager@sha256:ae64fd8a1c0fd825c44722107894a0d60ce428e0daf5a66e9b2064d5b3c4335e'
INIT_PINS={'wait-secret-broker':('feb809f2b9f63f3974f52043d79a9077c54095ffca395b23090625079a379a4b','cb86445b6e4b45e1d287d5e06dc8e84bee2ac173ea8591d613c1405f5f580776'),
 'verify-sbk-app-backend':('60811998f5c31afa50fea37b31917e5dd99710747843c4eeeb4efdbd03e2b972','4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945')}
def need(ok,why):
 if not ok:raise ValueError(why)
def desired(dep):
 need(dep['metadata']['uid']==UID and dep['metadata']['name']=='clawmanager-app' and dep['metadata']['namespace']==NS,'same original App deployment required')
 original=dep['spec'];spec=copy.deepcopy(original)
 need(spec.get('replicas')==2 and spec.get('strategy',{}).get('type')=='RollingUpdate','original two-replica App rollout required')
 cs=spec['template']['spec']['containers'];need(len(cs)==1 and cs[0]['name']=='clawmanager-app' and cs[0]['image']==OLD,'original App image required')
 env={e['name']:e.get('value') for e in cs[0].get('env',[])}
 need(env.get('RUNTIME_AGENT_CA_SHA256')==CA,'completed App CA required')
 pod=spec['template']['spec'];inits=pod.get('initContainers',[])
 need(len(inits)==2 and {c['name'] for c in inits}==set(INIT_PINS),'only original two initializers allowed')
 for c in inits:
  hashes=tuple(hashlib.sha256(json.dumps(c.get(k,[]),separators=(',',':')).encode()).hexdigest() for k in ['command','args'])
  need(c['image']==INIT_IMAGE and hashes==INIT_PINS[c['name']] and not c.get('env') and not c.get('envFrom'),'original initializer bytes changed')
  wanted=[{'name':'secret-broker-ca','mountPath':'/var/run/secrets/clawmanager-secret-broker-ca','readOnly':True}] if c['name']=='wait-secret-broker' else [{'name':'sbk-app-backend-release','mountPath':'/release','readOnly':True}]
  need(c.get('volumeMounts')==wanted,'original initializer mount changed')
 overlays=[v for v in cs[0].get('volumeMounts',[]) if v['name']=='sbk-app-backend-release' or v['mountPath']=='/usr/local/bin/clawreef-server']
 need(overlays==[{'name':'sbk-app-backend-release','mountPath':'/usr/local/bin/clawreef-server','readOnly':True,'subPath':'clawreef-server'}] and not cs[0].get('command') and not cs[0].get('args'),'exact original backend file overlay required')
 volumes=[v for v in pod.get('volumes',[]) if v['name']=='sbk-app-backend-release']
 need(len(volumes)==1 and set(volumes[0])=={'name','persistentVolumeClaim'} and volumes[0]['persistentVolumeClaim'].get('claimName'),'original retained release PVC required')
 cs[0]['volumeMounts']=[m for m in cs[0]['volumeMounts'] if m not in overlays]
 pod['initContainers']=[c for c in inits if c['name']=='wait-secret-broker']
 pod['volumes']=[v for v in pod['volumes'] if v['name']!='sbk-app-backend-release']
 cs[0]['image']=APP
 return spec
def config_data(raw):
 lines=raw.splitlines();need(lines and all(l.startswith(b'Loading k8s config from: ') for l in lines[:-1]),'original config DATA protocol required')
 v=json.loads(lines[-1]);need(v['Version']=='original-application-config-coordinates.v1' and v['RuntimeQualified'] is False and v['BackupReady'] is False,'original non-secret config DATA required');return v

def app_local_probe_spec(wanted):
 # The selected Go entrypoint returns before DB/listener/broker startup. A
 # standalone Pod deliberately has no business Service/NetworkPolicy label.
 # Production keeps its exact broker wait; only this local DATA probe omits it.
 spec=copy.deepcopy(wanted['template']['spec']);spec.pop('initContainers',None)
 c=spec['containers'][0]
 c['command']=['/bin/sh','-ec','test "$(sha256sum /usr/local/bin/clawreef-server | cut -d " " -f 1)" = '+APP_ELF+'; exec /usr/local/bin/clawreef-server --system-backup-source-config-data']
 for key in ['args','livenessProbe','readinessProbe','startupProbe','ports']:c.pop(key,None)
 for mount in c.get('volumeMounts',[]):mount['readOnly']=True
 return spec

def completed_probe_state(p,reference):
 need(p.get('status',{}).get('phase') in ['Succeeded','Failed'],
      'probe startup incomplete; inspect retained init/main status; no image mismatch established')
 states=p['status'].get('containerStatuses',[])
 need(len(states)==1 and states[0].get('state',{}).get('terminated') is not None,'probe entry did not terminate')
 need(states[0].get('imageID')==reference,'probe loaded different image')
 return states[0]

def known_pre_entry_probe(old,created):
 need(old['metadata']['uid']==created['metadata']['uid'] and old['metadata']['name']=='sbk-p2-execution-app-eca964d4' and
      old['spec']['containers'][0]['image']==APP and old.get('status',{}).get('phase')=='Pending','known original pre-entry probe required')
 init=old['status'].get('initContainerStatuses',[]);states=old['status'].get('containerStatuses',[])
 need(len(init)==1 and init[0]['name']=='wait-secret-broker' and 'running' in init[0].get('state',{}) and
      len(states)==1 and not states[0].get('imageID') and states[0].get('state',{}).get('waiting',{}).get('reason')=='PodInitializing',
      'only observed broker-wait refusal may select a local-config probe')
def main():
 os.umask(0o077);need(os.name=='posix','Linux operator required')
 records=ROOT/'execution-app-rollout';records.mkdir(mode=0o700,exist_ok=True)
 need(records.resolve(strict=True)==records and records.stat().st_mode&0o077==0,'private original rollout records required')
 helper=Path('/root/sbk/p2-runtime-cert-rotation-fcc26a0a/rotate-p2-runtime-certificates.py')
 need(hashlib.sha256(helper.read_bytes()).hexdigest()==HELPER_SHA,'original CAS transport helper changed')
 s=importlib.util.spec_from_file_location('original_runtime_rotation_transport',helper);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
 site=m.Site(records)
 for kind,ref in [('app',APP),('worker',WORKER)]:
  base=ROOT/'execution-image-candidates'/kind
  data=json.loads((base/'image-data.json').read_bytes());verified=json.loads((base/'registry-byte-verification.json').read_bytes())
  need(data['Reference']==ref and data['SourceRevision']==REV and verified['AllInheritedLayersVerified'] is True and verified['ActualImage']['reference']==ref and verified['ActualImage']['commit']==REV,'actual fixed-source publication and OCI verification required')
 node=json.loads(site.call(['get','node','node1','-o','json']))
 need(node['metadata']['uid']=='fe1cc275-6fa1-484e-8bf6-7b21193daffd','original probe Node changed')
 plan_file=records/'plan.private.json'
 if plan_file.exists():plan=json.loads(plan_file.read_bytes())
 else:
  dep=site.get('deployment','clawmanager-app');wanted=desired(dep)
  scope=site.call(['exec','deployment/clawmanager-app','-c','clawmanager-app','--','printenv','SYSTEM_BACKUP_SQL_GATE_SCOPE']).strip()
  need(scope==b'installation','existing SQL migration fence required')
  original=config_data(site.call(['exec','deployment/clawmanager-app','-c','clawmanager-app','--','/usr/local/bin/clawreef-server','--system-backup-source-config-data']))
  plan={'Original':dep['spec'],'Desired':wanted,'OriginalConfig':original,'SourceRevision':REV,'Image':APP,'WorkerImage':WORKER}
  m.retain(plan_file,plan)
 need(plan['SourceRevision']==REV and plan['Image']==APP and plan['WorkerImage']==WORKER,'original rollout selection changed')
 # Test the production dependency through an existing, policy-authorized App.
 # No policy edits or business labels are granted to the standalone probe.
 broker='clawmanager-secret-broker.'+NS+'.svc.cluster.local'
 command='timeout 12 openssl s_client -brief -connect '+broker+':9444 -servername '+broker+' -verify_hostname '+broker+' -verify_return_error -CAfile /var/run/secrets/clawmanager-secret-broker-ca/ca.crt </dev/null >/dev/null 2>&1'
 try:site.call(['exec','deployment/clawmanager-app','-c','clawmanager-app','--','/bin/sh','-ec',command])
 except ValueError:raise ValueError('existing App broker TLS preflight unconfirmed; retain private read log') from None
 print('EXISTING_APP_BROKER_TLS_OK',flush=True)
 def probe(kind):
  completed=records/(kind+'-probe.completed.json')
  if completed.exists():
   result=json.loads(completed.read_bytes());need(result['Image']==(APP if kind=='app' else WORKER),'retained probe image changed');return
  stem='app-local' if kind=='app' else kind
  name='sbk-p2-execution-'+stem+'-eca964d4'
  marker=records/(stem+'-probe.sent.json')
  need(not marker.exists(),'probe send unknown; reconcile the same Pod and records')
  if kind=='app':
   old_marker=records/'app-probe.sent.json'
   if old_marker.exists():
    old=json.loads((records/'app-probe.final.private.json').read_bytes());created=json.loads((records/'app-probe.created.private.json').read_bytes())
    known_pre_entry_probe(old,created)
    need(not (records/'app-fixed-source.sent.json').exists() and m.semantic(site.get('deployment','clawmanager-app')['spec'])==m.semantic(plan['Original']),
         'original App must remain unchanged before local probe continuation')
    need(not site.call(['get','pod',old['metadata']['name'],'--ignore-not-found','-o','json']).strip(),'original broker-wait probe still exists; do not create another')
    m.retain(records/'app-probe-pre-entry-continuation.json',{'OriginalPodUID':old['metadata']['uid'],'OriginalObservedPhase':'Pending','OriginalMainImageID':'','OriginalPodDeletionReadBack':True,'ProductionPatchSent':False,'NewProbeKind':'local_config_without_dependency_init','BackupReady':False})
   spec=app_local_probe_spec(plan['Desired'])
  else:
   spec={'securityContext':{'runAsNonRoot':True,'runAsUser':65532,'runAsGroup':65532,'seccompProfile':{'type':'RuntimeDefault'}},
         'containers':[{'name':'worker','image':WORKER,'command':['/backup-worker'],'securityContext':{'allowPrivilegeEscalation':False,'readOnlyRootFilesystem':True,'capabilities':{'drop':['ALL']}}}]}
  spec.update(nodeName='node1',restartPolicy='Never',automountServiceAccountToken=False,activeDeadlineSeconds=120)
  for c in spec['containers']:c['imagePullPolicy']='IfNotPresent'
  pod={'apiVersion':'v1','kind':'Pod','metadata':{'name':name,'namespace':NS,'labels':{'backup.clawmanager.io/p2-entry-probe':kind}},'spec':spec}
  need(not site.call(['get','pod',name,'--ignore-not-found','-o','json']).strip(),'existing probe requires original reconciliation')
  m.retain(marker,pod)
  created=json.loads(site.call(['create','--raw','/api/v1/namespaces/'+NS+'/pods','-f','-'],pod));uid=created['metadata']['uid']
  m.retain(records/(stem+'-probe.created.private.json'),created)
  try:
   for _ in range(65):
    p=site.get('pod',name);need(p['metadata']['uid']==uid,'original probe Pod replaced')
    if p.get('status',{}).get('phase') in ['Succeeded','Failed']:break
    time.sleep(2)
   m.retain(records/(stem+'-probe.final.private.json'),p)
   state=completed_probe_state(p,APP if kind=='app' else WORKER)
   logs=site.call(['logs',name,'-c',spec['containers'][0]['name']])
   exit_code=state['state'].get('terminated',{}).get('exitCode')
   if kind=='app':need(exit_code==0 and config_data(logs)==plan['OriginalConfig'],'candidate effective config differs from original')
   else:need(exit_code==1 and logs.strip()==b'backup worker failed; category=execution_unavailable','worker must start and refuse missing control grant')
   m.retain(completed,{'Image':APP if kind=='app' else WORKER,'PodUID':uid,'ProbeKind':stem,'ExitCode':exit_code,'NativeTaskAccepted':False,'BackupReady':False})
   print('P2_EXECUTION_ENTRY_PROBE_OK',kind,flush=True)
  finally:
   p=site.get('pod',name);need(p['metadata']['uid']==uid,'probe deletion identity changed')
   site.call(['delete','--raw','/api/v1/namespaces/'+NS+'/pods/'+name,'-f','-'],{'apiVersion':'v1','kind':'DeleteOptions','preconditions':{'uid':uid}})
   site.call(['--request-timeout=70s','wait','--for=delete','pod/'+name,'--timeout=60s'])
   print('P2_EXECUTION_PROBE_DELETED',name,flush=True)
 probe('app');probe('worker')
 pods=site.patch('app-fixed-source','clawmanager-app',plan['Original'],plan['Desired'],UID)
 for p in pods:
  name=p['metadata']['name'];need(p['status']['containerStatuses'][0]['imageID']==APP,'App loaded different image')
  hashes=site.call(['exec',name,'-c','clawmanager-app','--','sh','-ec','sha256sum /usr/local/bin/clawreef-server "$RUNTIME_AGENT_CA_FILE"; printenv RUNTIME_AGENT_CA_SHA256; printenv SYSTEM_BACKUP_SQL_GATE_SCOPE']).splitlines()
  need(len(hashes)==4 and hashes[0].split()[0].decode()==APP_ELF and hashes[1].split()[0].decode()==CA and hashes[2].decode()==CA and hashes[3]==b'installation','actual App ELF/CA/SQL fence readback failed')
  actual=config_data(site.call(['exec',name,'-c','clawmanager-app','--','/usr/local/bin/clawreef-server','--system-backup-source-config-data']))
  need(actual==plan['OriginalConfig'],'effective App source config changed')
  logs=site.call(['logs',name,'-c','clawmanager-app','--tail=-1']).decode(errors='replace')
  need(('Starting ClawManager version=p2-eca964d4 commit='+REV+' ') in logs,'actual linked App version missing')
  print('P2_APP_FIXED_SOURCE_READY',name,p['metadata']['uid'],REV,flush=True)
 m.retain(records/'effective-app-config.json',plan['OriginalConfig'])
 m.retain(records/'completed.json',{'Version':'p2-fixed-source-app-rollout.v1','Image':APP,'WorkerImage':WORKER,'SourceRevision':REV,'Replicas':2,'ConfigurationPreserved':True,'BackupReady':False})
 m.instance_status(records)
 print('P2_APP_EXECUTION_IMAGE_ROLLED_OUT',records,flush=True)
if __name__=='__main__':
 try:main()
 except (ValueError,OSError,KeyError,TypeError,subprocess.SubprocessError) as e:raise SystemExit('P2_APP_EXECUTION_ROLLOUT_UNCONFIRMED '+(str(e) if type(e) is ValueError else type(e).__name__))
