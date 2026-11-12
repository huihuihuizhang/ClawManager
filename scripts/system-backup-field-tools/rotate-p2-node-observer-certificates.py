#!/usr/bin/env python3
"""This site's observer certificates and current Agent ELF expectations only.

Uses the actual original NodeBundles. No observer binary replacement, source
freeze, durable record deletion, new PKI, grant or controller activation.
"""
import argparse
import datetime
import hashlib
import io
import json
import os
from pathlib import Path
import shlex
import stat
import subprocess
import tarfile

ROOT=Path('/root/sbk/p2-cert-renewal.1KyqMtsd')
NS='clawmanager-sbk-validation-system'
CONTROLLER='sbk-d4f51b83b57e-controller'
KUBE='/root/sbk-validation-tls-inspect.7LVU7vpE/operator.kubeconfig.yaml'
OLD_CA='b2be0130a376c8e2644b46687bd07b984576f0f170f602150ba9bdcac36c3766'
NEW_CA='7fa08bdb7a03ad3d81722aa56b845b4aba2227d16c5463cc3d70f29d7f5f37bc'
NODES={'k8s-master':'bc1fb478-0388-4f53-96b4-8d186301f6af','node1':'fe1cc275-6fa1-484e-8bf6-7b21193daffd'}
BINARIES={'gateway':('backup-gateway-node-observer','bf54ea3d33c423d1d0cbd753eb3833f3d1c8c147a036972a6b05c1d392f5d0d0'),
 'whole':('backup-node-observer','0548635a5f513bc45c994aed9f6d473a1e20111a4a2fdb05d5c2bf8c8d66bf2d'),
 'stopped-pro':('backup-stopped-pro-node-observer','f83ed033603e7e80e0977ca8c08890489146cf354bfb7d31bb748a7069419237'),
 'shared':('backup-shared-runtime-node-owner','e4fe361767ad648eb82e71c5d18b308ef990e426901c311571ef2851c231b922')}
OLD_UNITS={'k8s-master':{'gateway':'f757f2905963bbb11da3fcdbcc771e1518250cf88bedecb5b0d7bd1a90246b88','whole':'d17520edfb47af243787165eaaa00bc6abe127ffb1871f6951acd5ae5845aec4','stopped-pro':'e63cf6d47adcb205b2731d146e803a0d2e7d7d94c5921605f00ac92e5d419a7d','shared':'1e2f2dc0b64b18fe13f43bb57f93ab75716a56b389d448e76ea0a64bf1b3c997'},
 'node1':{'gateway':'aeca6411cb56526e6005b3d4103c7442481992197bab141ee6a20d313775a09c','whole':'d7e6e0441156c30c06b61f91ac55285bec74f6765681cbfd41697dd86acff07d','stopped-pro':'484d6605fd565774da0dfe3fa847110885f6e02d906caec85e29b6ef85081aee','shared':'af9ff895adde0f08217574f9c33f137453efb359e789f41036f9285b1392fedf'}}
AGENTS={'hermes':'be46bb0525623bb9fb7f1393a6b668d7c8f705a998c90517915751c2be9d0102','openclaw':'bc1ef9abb276594f938cb27374b0ee05c50b6d9da1424b8fe87fb64940bd0158'}
BASE=Path('/etc/clawmanager-system-backup/sbk-d4f51b83b57e')
STORE=Path('/var/lib/clawmanager-system-backup/sbk-d4f51b83b57e/shared-owner')
def need(ok,why):
 if not ok:raise ValueError(why)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def encode(v):return json.dumps(v,sort_keys=True,separators=(',',':')).encode()
def retain(p,raw):
 if p.exists():need(not p.is_symlink() and p.read_bytes()==raw,'original rotation records changed')
 else:
  with p.open('xb') as f:os.chmod(p,0o600);f.write(raw);f.flush();os.fsync(f.fileno())
 return {'File':str(p),'SHA256':sha(raw)}
def pinned(v,maximum=200<<20):
 p=Path(v['File']);need(p.resolve(strict=True)==p and p.is_file() and not p.is_symlink() and 0<p.stat().st_size<=maximum,'bounded original file required')
 raw=p.read_bytes();need(sha(raw)==v['SHA256'],'original pin changed');return raw
def unit_name(kind):return 'clawreef-'+BINARIES[kind][0]+'.service'
def unit_parts(raw):
 lines=raw.decode().splitlines();execs=[l for l in lines if l.startswith('ExecStart=')]
 need(len(execs)==1,'one original ExecStart required')
 return [l for l in lines if not l.startswith('ExecStart=')],shlex.split(execs[0].split('=',1)[1])
def compare_unit(old,new,kind):
 a,av=unit_parts(old);b,bv=unit_parts(new)
 need(a==b and len(av)==len(bv),'observer unit changed outside Agent hash expectations')
 for i,v in enumerate(av):
  if i and av[i-1] in ['--openclaw-agent-elf-sha256','--hermes-agent-elf-sha256','--shared-openclaw-agent-elf-sha256','--shared-hermes-agent-elf-sha256']:
   runtime='openclaw' if 'openclaw' in av[i-1] else 'hermes'
   need(bv[i]==AGENTS[runtime] and len(v)==64,'current Agent ELF hash required')
  else:need(v==bv[i],'observer unit changed outside Agent hash expectations')
 need(av[0]=='/usr/local/libexec/sbk-d4f51b83b57e/'+BINARIES[kind][0],'original observer executable path required')

def tar_files(raw,maximum):
 result={}
 with tarfile.open(fileobj=io.BytesIO(raw)) as t:
  members=t.getmembers();need(0<len(members)<=40,'bounded flat original bundle required')
  for m in members:
   need(m.isfile() and m.name not in ['.','..'] and m.name not in result and '/' not in m.name and '\\' not in m.name and 0<m.size<=maximum,'regular flat bundle members required')
   result[m.name]=t.extractfile(m).read();need(len(result[m.name])==m.size,'bundle member truncated')
 return result
def payload(node,new_files,old_pki,new_pki,until):
 metadata=json.loads(new_files['node-receipt.json'])
 need(metadata['Node']==node and metadata['NodeUID']==NODES[node] and metadata['Version']=='original-observer-host-bundle.v1','same original Node required')
 old_eps={e['Kind']:e for e in old_pki['Endpoints'] if e['Node']==node}
 need(set(old_eps)==set(BINARIES) and {e['Kind'] for e in metadata['Endpoints']}==set(BINARIES),'complete original endpoint census required')
 suffix='node-'+sha(NODES[node].encode())[:24];material=BASE/suffix
 files={};targets={}
 def add(name,target,old_sha,mode):
  need(name in new_files,'missing native bundle file');files[name]=new_files[name]
  targets[name]={'Target':str(target),'OldSHA256':old_sha,'NewSHA256':sha(new_files[name]),'Mode':mode}
 add('observer-ca.pem',material/'observer-ca.pem',old_pki['CA']['SHA256'],0o600)
 need(old_pki['CA']['SHA256']==OLD_CA and new_pki['CA']['SHA256']==NEW_CA and sha(new_files['observer-ca.pem'])==NEW_CA,'original/new observer CA required')
 for kind,(binary,digest) in BINARIES.items():
  need(sha(new_files[binary])==digest,'observer binary replacement refused')
  name=unit_name(kind);add(name,Path('/etc/systemd/system')/name,OLD_UNITS[node][kind],0o644)
  for name,key in [(kind+'-server.pem','Certificate'),(kind+'-server-key.pem','PrivateKey')]:add(name,material/name,old_eps[kind][key]['SHA256'],0o600)
  if kind!='shared':add(kind+'-anchor.key',material/(kind+'-anchor.key'),old_eps[kind]['AnchorKey']['SHA256'],0o600)
 plan={'Version':'p2-observer-certificate-rotation.v1','Node':node,'NodeUID':NODES[node],'MachineID':metadata['MachineID'],'BootID':metadata['BootID'],
       'Until':until,'Files':targets,'OwnerDirectory':str(STORE/suffix),'NewCA':NEW_CA,'NoActiveControllerMarkerObserved':True,'BackupReady':False}
 files['rotation-plan.json']=encode(plan)
 output=io.BytesIO()
 with tarfile.open(fileobj=output,mode='w',format=tarfile.USTAR_FORMAT) as t:
  for name,raw in sorted(files.items()):
   m=tarfile.TarInfo(name);m.size=len(raw);m.mode=0o600;t.addfile(m,io.BytesIO(raw))
 return output.getvalue()

def prepare(directory):
 k=['kubectl','--kubeconfig',KUBE,'--request-timeout=20s','-n',NS]
 def call(args):
  p=subprocess.run(k+args,capture_output=True,timeout=45);need(p.returncode==0,'pre-activation controller read unconfirmed');return p.stdout
 dep=json.loads(call(['get','deployment',CONTROLLER,'-o','json']))
 need(dep['metadata']['uid']=='e4e27f27-8f02-40ab-8c62-09f2ffa3fafa','original controller changed')
 c=next(c for c in dep['spec']['template']['spec']['containers'] if c['name']=='controller')
 need({e['name']:e.get('value') for e in c['env']}.get('SYSTEM_BACKUP_ENABLED')=='false','pre-activation controller required')
 call(['exec','deployment/'+CONTROLLER,'-c','controller','--','sh','-ec','test ! -e /run/system-backup/runtime/controller.env.ready'])
 old_def=json.loads(Path('/root/sbk-validation-tls-inspect.7LVU7vpE/fresh-backup-bootstrap/observer-host.definition.json').read_bytes())
 old_pki=json.loads(pinned(old_def['PKIReceipt']));new_pki=json.loads((ROOT/'observer.receipt.private.json').read_bytes())
 receipt=json.loads((ROOT/'observer-host-current-agent/host-materials.receipt.private.json').read_bytes())
 need(receipt['Version']=='original-observer-host-materials.v1' and receipt['Status']=='materialized_uninstalled_no_native_source_proof','original current-Agent host materials required')
 now=datetime.datetime.now(datetime.timezone.utc)
 window=directory/'window.json'
 if window.exists():until=json.loads(window.read_bytes())['Until']
 else:
  until=(now+datetime.timedelta(minutes=30)).isoformat();retain(window,encode({'Until':until}))
 need(now<datetime.datetime.fromisoformat(until),'prepared rotation window expired; retain original records')
 need(now+datetime.timedelta(hours=1)<datetime.datetime.fromisoformat(new_pki['NotAfter'].replace('Z','+00:00')),'observer validity insufficient')
 for node in NODES:
  native=receipt['NodeBundles'][node];files=tar_files(pinned(native),64<<20)
  raw=payload(node,files,old_pki,new_pki,until)
  result=retain(directory/(node+'.renewal.private.tar'),raw)
  retain(directory/(node+'.source.json'),encode({'OriginalBundle':native,'PrivatePayload':result,'PKIReceiptSHA256':receipt['PKIReceiptSHA256'],'BackupReady':False}))
  print('OBSERVER_CERTIFICATE_PAYLOAD',node,json.dumps(result),flush=True)

def atomic(target,raw,mode):
 temp=target.with_name(target.name+'.p2-certificate-renewal.new')
 need(not temp.exists() and not temp.is_symlink(),'uncertain staged replacement retained')
 with temp.open('xb') as f:os.chmod(temp,mode);f.write(raw);f.flush();os.fsync(f.fileno())
 os.replace(temp,target)
 fd=os.open(target.parent,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(fd)
 finally:os.close(fd)
def apply(pin,directory):
 import fcntl
 need(os.name=='posix' and os.geteuid()==0,'original Linux root required')
 files=tar_files(pinned(pin,1<<20),262144);plan=json.loads(files.pop('rotation-plan.json'))
 node=plan['Node'];need(node in NODES and plan['NodeUID']==NODES[node] and plan['Version']=='p2-observer-certificate-rotation.v1','same original Node required')
 need(Path('/etc/machine-id').read_text().strip()==plan['MachineID'] and Path('/proc/sys/kernel/random/boot_id').read_text().strip()==plan['BootID'],'Node machine/boot changed')
 need(datetime.datetime.now(datetime.timezone.utc)<datetime.datetime.fromisoformat(plan['Until']),'rotation window expired; retain original records')
 expected_files={unit_name(kind) for kind in BINARIES}|{'observer-ca.pem'}|{kind+'-server'+suffix for kind in BINARIES for suffix in ['.pem','-key.pem']}|{kind+'-anchor.key' for kind in BINARIES if kind!='shared'}
 need(set(files)==set(plan['Files'])==expected_files and plan['NewCA']==NEW_CA,'rotation payload changed')
 suffix='node-'+sha(NODES[node].encode())[:24];need(plan['OwnerDirectory']==str(STORE/suffix),'original durable owner path required')
 owner=Path(plan['OwnerDirectory']);need(owner.resolve(strict=True)==owner and owner.stat().st_uid==0 and stat.S_IMODE(owner.stat().st_mode)==0o700,'private durable owner required')
 for parent in owner.parents:need(parent.stat().st_uid==0 and parent.stat().st_mode&0o022==0,'durable owner ancestor changed')
 need({p.name for p in owner.iterdir()}=={'.owner.guard'},'existing durable recovery obligation; do not rotate')
 units=[unit_name(kind) for kind in BINARIES]
 for kind,(binary,digest) in BINARIES.items():
  need(sha(Path('/usr/local/libexec/sbk-d4f51b83b57e',binary).read_bytes())==digest,'original observer binary changed')
  raw=subprocess.run(['systemctl','show',unit_name(kind),'--property=DropInPaths,LoadState,ActiveState,SubState,MainPID,ControlPID,UnitFileState'],capture_output=True,check=True).stdout.decode()
  state=dict(line.split('=',1) for line in raw.splitlines() if '=' in line)
  need(state.get('DropInPaths')=='' and state.get('LoadState')=='loaded' and state.get('ActiveState')=='active' and
       state.get('SubState')=='running' and state.get('ControlPID')=='0' and state.get('UnitFileState')=='enabled' and int(state['MainPID'])>0,
       'original active observer service changed')
  target=Path('/etc/systemd/system')/unit_name(kind)
  need(sha(target.read_bytes())==OLD_UNITS[node][kind],'original observer unit changed')
  process=Path('/proc')/state['MainPID']
  need(sha((process/'exe').read_bytes())==digest,'running observer executable changed')
  argv=[v.decode() for v in (process/'cmdline').read_bytes().split(b'\x00') if v]
  need(argv==[a.replace('%%','%') for a in unit_parts(target.read_bytes())[1]],'running observer arguments changed')
  compare_unit(target.read_bytes(),files[unit_name(kind)],kind)
 for name,v in plan['Files'].items():
  target=Path(v['Target']);expected=Path('/etc/systemd/system')/name if name in units else BASE/suffix/name
  need(target==expected and target.resolve(strict=True)==target and not target.is_symlink() and target.stat().st_uid==0 and stat.S_IMODE(target.stat().st_mode)==v['Mode'],'original target path/ownership/mode changed')
  need(sha(target.read_bytes())==v['OldSHA256'] and sha(files[name])==v['NewSHA256'],'original/new file bytes changed')
  retain(directory/(name+'.original.private'),target.read_bytes())
 need(not (directory/'rotation.sent.json').exists(),'rotation already sent; reconcile original files and services')
 retain(directory/'rotation.sent.json',encode({'Plan':plan,'Payload':pin}))
 def system(*args):subprocess.run(['systemctl',*args],capture_output=True,timeout=60,check=True)
 guard=None
 try:
  system('stop',*units)
  for unit in units:
   pid=subprocess.run(['systemctl','show',unit,'--property=MainPID','--value'],capture_output=True,check=True).stdout.strip()
   need(pid==b'0','observer still running')
  guard=os.open(owner/'.owner.guard',os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC);fcntl.flock(guard,fcntl.LOCK_EX|fcntl.LOCK_NB)
  need({p.name for p in owner.iterdir()}=={'.owner.guard'},'durable obligation appeared; preserve original owner')
  for name,v in plan['Files'].items():
   target=Path(v['Target']);need(sha(target.read_bytes())==v['OldSHA256'],'target changed during observer stop')
  for name,v in plan['Files'].items():atomic(Path(v['Target']),files[name],v['Mode'])
  os.close(guard);guard=None
  system('daemon-reload');system('start',*units)
  for unit in units:system('is-active','--quiet',unit)
  for name,v in plan['Files'].items():need(sha(Path(v['Target']).read_bytes())==v['NewSHA256'],'renewed file readback mismatch')
  retain(directory/'completed.json',encode({'Version':'p2-observer-certificate-rotation-completed.v1','Node':node,'CA':NEW_CA,'DurableRecordsPreserved':True,'NativeFDOrHoldVerified':False,'BackupReady':False}))
  print('NODE_OBSERVER_CERTIFICATES_ROTATED',node,NEW_CA,flush=True)
 except Exception:
  if guard is not None:os.close(guard)
  system('stop',*units)
  # CAS compensation only. Preserve every original record and all key files.
  for name,v in plan['Files'].items():
   current=sha(Path(v['Target']).read_bytes());need(current in [v['OldSHA256'],v['NewSHA256']],'compensation blocked by target drift; retain services and records')
  for name,v in plan['Files'].items():
   if sha(Path(v['Target']).read_bytes())==v['NewSHA256']:atomic(Path(v['Target']),(directory/(name+'.original.private')).read_bytes(),v['Mode'])
  system('daemon-reload');system('start',*units)
  retain(directory/'compensation.json',encode({'OriginalFilesRestored':True,'RotationConfirmed':False,'BackupReady':False}))
  raise

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--prepare',action='store_true');p.add_argument('--payload-file');p.add_argument('--payload-sha256');p.add_argument('--records-directory',type=Path,required=True);a=p.parse_args();os.umask(0o077)
 need(a.records_directory.resolve(strict=True)==a.records_directory and a.records_directory.is_dir() and a.records_directory.stat().st_mode&0o077==0 and a.records_directory.stat().st_uid==os.geteuid(),'existing private records directory required')
 if a.prepare:prepare(a.records_directory)
 else:apply({'File':a.payload_file,'SHA256':a.payload_sha256},a.records_directory)
if __name__=='__main__':
 try:main()
 except (ValueError,OSError,KeyError,TypeError,subprocess.SubprocessError) as e:raise SystemExit('NODE_OBSERVER_CERT_ROTATION_UNCONFIRMED '+(str(e) if type(e) is ValueError else type(e).__name__))
