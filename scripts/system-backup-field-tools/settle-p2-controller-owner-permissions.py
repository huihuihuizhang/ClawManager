#!/usr/bin/env python3
"""Settle the already-applied waiting controller after its fsGroup remount.

Only this site's owner startup and fsGroupChangePolicy change. No recursive
chmod, root container, volume replacement, activation, task or native issuance.
"""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess

ROOT=Path('/root/sbk/p2-cert-renewal.1KyqMtsd/controller-relay')
NAME='sbk-d4f51b83b57e-controller'
UID='e4e27f27-8f02-40ab-8c62-09f2ffa3fafa'
APP='10.130.14.23:5000/clawmanager@sha256:8287aa71bcfc9e1596d761a9b46891575f3708323300839c98e075a22875e780'
OWNER_COMMAND_SHA='3f6e6fb2e0728492f3372d4f879cbcfe0812dc279d485e769a897c69fd05b273'
HELPER_SHA='ab1539c5e06c8c237e8516d9985b162fbec3216570abb5ebec1902df47f7052c'
CLAIMS={'sbk-d4f51b83b57e-inputs':('b3372004-cf8c-4b50-a84e-e159ae17613b','ReadWriteMany'),
 'sbk-d4f51b83b57e-staging':('22f31d71-1106-4357-b03c-fca7d9e2c1bf','ReadWriteOnce'),
 'sbk-d4f51b83b57e-private':('583c61c0-caff-4ada-8f44-10547d5124db','ReadWriteOnce')}

def need(ok,why):
 if not ok:raise ValueError(why)
def encode(v):return json.dumps(v,sort_keys=True,separators=(',',':')).encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()
def pin(p):return {'File':str(p),'SHA256':sha(p.read_bytes())}
def retain(p,v):
 raw=v if isinstance(v,bytes) else encode(v)
 if p.exists():need(not p.is_symlink() and p.read_bytes()==raw,'original permission recovery record changed')
 else:
  with p.open('xb') as f:os.chmod(p,0o600);f.write(raw);f.flush();os.fsync(f.fileno())

def desired_spec(original):
 desired=copy.deepcopy(original);pod=desired['template']['spec']
 need(desired.get('replicas')==1 and desired.get('strategy')=={'type':'Recreate'},'same single waiting Recreate controller required')
 context=pod['securityContext']
 need(context=={'fsGroup':65532,'runAsGroup':65532,'runAsNonRoot':True,'runAsUser':65532,'seccompProfile':{'type':'RuntimeDefault'}},
  'original nonroot controller security context changed')
 containers=pod['containers'];need(len(containers)==2 and {c['name'] for c in containers}=={'controller','installation-owner'} and
  all(c['image']==APP for c in containers),'same pinned controller/owner required')
 controller=next(c for c in containers if c['name']=='controller')
 need([e.get('value') for e in controller['env'] if e['name']=='SYSTEM_BACKUP_ENABLED']==['false'] and
  '/run/system-backup/bin/system-backup-v2-controller' in ' '.join(controller['command']) and
  '$f.ready' in ' '.join(controller['command']),'guarded disabled controller required')
 owner=next(c for c in containers if c['name']=='installation-owner')
 command=owner['command']
 need(sha(encode(command))==OWNER_COMMAND_SHA and command[:2]==['/bin/sh','-ec'] and not owner.get('args'),
  'exact original owner startup command required')
 mounts=owner['volumeMounts']
 need(len(mounts)==2 and {m['mountPath']:m['name'] for m in mounts}=={'/run/system-backup':'inputs','/run/installation-owner-private':'private'} and
  all(not m.get('readOnly') and not m.get('subPath') and not m.get('subPathExpr') for m in mounts),'original whole owner mounts required')
 old='test "$(stat -c %u:%a "$d")" = 65532:700'
 need(command[2].count(old)==1,'one original private directory mode guard required')
 # Only the known owned installer directory may lose fsGroup-added bits.
 # The original runtime directory check stays strict. Existing files and
 # children are not traversed, read, moved, chowned or chmodded.
 repair='if test "$d" = /run/installation-owner-private/installer; then test -d "$d"; test "$(stat -c %u:%g "$d")" = 65532:65532; case "$(stat -c %a "$d")" in 700) ;; 2770) chmod 700 "$d" ;; *) exit 42 ;; esac; fi; '
 command[2]=command[2].replace(old,repair+old)
 context['fsGroupChangePolicy']='OnRootMismatch'
 return desired

def reconciled_spec(plan,completed,plan_pin):
 need(completed['Version']=='p2-controller-owner-permissions.v1' and completed['ControllerUID']==UID and
  completed['OriginalControllerPlan']==plan_pin and completed['SourceSpecSHA256']==sha(encode(plan['Desired'])) and
  completed['ControllerEnabled'] is False and completed['BackupReady'] is False,'completed original owner permission recovery required')
 desired=desired_spec(plan['Desired'])
 need(completed['DesiredSpecSHA256']==sha(encode(desired)),'owner permission successor spec changed')
 return desired

def main():
 os.umask(0o077);need(os.name=='posix','Linux operator required')
 r=ROOT/'owner-directory-permissions';r.mkdir(mode=0o700,exist_ok=True)
 need(r.resolve(strict=True)==r and r.stat().st_mode&0o077==0,'private original permission recovery directory required')
 h=Path('/root/sbk/p2-runtime-cert-rotation-fcc26a0a/rotate-p2-runtime-certificates.py')
 need(sha(h.read_bytes())==HELPER_SHA,'original CAS transport helper changed')
 s=importlib.util.spec_from_file_location('permission_cas_transport',h);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);site=m.Site(r)
 original_file=ROOT/'controller-plan.private.json';plan=json.loads(original_file.read_bytes());desired=desired_spec(plan['Desired'])
 need((ROOT/'controller-pinned-executable.sent.json').is_file() and not (ROOT/'relay-pki.sent.private.json').exists(),
  'original rollout must already be sent and relay issuance must remain unsent')
 current=site.get('deployment',NAME)
 need(current['metadata']['uid']==UID and m.semantic(current['spec']) in [m.semantic(plan['Desired']),m.semantic(desired)],'controller spec drift prevents permission settlement')
 volumes=current['spec']['template']['spec']['volumes']
 need({v['persistentVolumeClaim']['claimName'] for v in volumes if 'persistentVolumeClaim' in v}==set(CLAIMS),'original three volume claims required')
 for name,(uid,mode) in CLAIMS.items():
  c=site.get('pvc',name)
  need(c['metadata']['uid']==uid and not c['metadata'].get('deletionTimestamp') and c['status']['phase']=='Bound' and
   c['spec']['accessModes']==[mode] and c['spec']['volumeName']=='pvc-'+uid,'original controller volume identity changed')
 retain(r/'plan.private.json',{'Version':'p2-controller-owner-permission-plan.v1','OriginalControllerPlan':pin(original_file),
  'SourceSpec':plan['Desired'],'DesiredSpec':desired,'ClaimUIDs':{n:v[0] for n,v in CLAIMS.items()}})
 site.call(['exec','deployment/'+NAME,'-c','controller','--','sh','-ec','test ! -e /run/system-backup/runtime/controller.env.ready'])
 pods=site.patch('owner-directory-permissions',NAME,plan['Desired'],desired,UID)
 need(len(pods)==1 and all(s['imageID']==APP for s in pods[0]['status']['containerStatuses']),'one ready pinned controller/owner pair required')
 pod=pods[0]
 expected_owner=next(c for c in desired['template']['spec']['containers'] if c['name']=='installation-owner')
 actual_owner=next(c for c in pod['spec']['containers'] if c['name']=='installation-owner')
 need(actual_owner['command']==expected_owner['command'] and
  pod['spec']['securityContext']==desired['template']['spec']['securityContext'],'admission changed the inspected owner startup')
 check='test "$(id -u)" = 65532; test ! -e /run/system-backup/runtime/controller.env.ready; for d in /run/system-backup/runtime /run/installation-owner-private/installer; do test -d "$d"; test ! -L "$d"; test "$(stat -c %u:%a "$d")" = 65532:700; done; printf OWNER_PRIVATE_DIRECTORIES_OK'
 need(site.call(['exec',pod['metadata']['name'],'-c','installation-owner','--','sh','-ec',check]).strip()==b'OWNER_PRIVATE_DIRECTORIES_OK',
  'actual private owner directory modes not confirmed')
 final=site.get('deployment',NAME)
 need(m.semantic(final['spec'])==m.semantic(desired),'controller changed after permission readback')
 value={'Version':'p2-controller-owner-permissions.v1','ControllerUID':UID,'ControllerPodUID':pod['metadata']['uid'],
  'OriginalControllerPlan':pin(original_file),'SourceSpecSHA256':sha(encode(plan['Desired'])),
  'DesiredSpecSHA256':sha(encode(desired)),'PrivateDirectoriesMode':'700','ControllerEnabled':False,'BackupReady':False}
 retain(r/'completed.json',value)
 print('P2_CONTROLLER_OWNER_PRIVATE_DIRECTORIES_READY',pod['metadata']['name'],pod['metadata']['uid'],flush=True)
 print('P2_CONTROLLER_WAITING_ROLLOUT_SETTLED_NOT_ACTIVATED',r,flush=True)

if __name__=='__main__':
 try:main()
 except (ValueError,OSError,KeyError,TypeError,subprocess.SubprocessError) as e:raise SystemExit('P2_CONTROLLER_OWNER_PERMISSIONS_UNCONFIRMED '+(str(e) if type(e) is ValueError else type(e).__name__))
