#!/usr/bin/env python3
"""Encode pending-v3 DATA from actual producer outputs; grants no authority.

The production operator must derive these locations from real owner receipts.
This encoder neither produces missing native definitions nor an SQL account.
"""
import argparse,hashlib,json,os,stat,sys
from pathlib import Path

def need(ok):
    if not ok: raise ValueError('original_c1_actual_input_required')
def pairs(items):
    d={}
    for k,v in items:
        need(k not in d);d[k]=v
    return d
def read(path,limit=262144):
    p=Path(path);need(p.is_absolute() and p==p.resolve(strict=True))
    before=p.lstat();need(stat.S_ISREG(before.st_mode) and 0<before.st_size<=limit)
    need(before.st_nlink==1)
    if os.name=='posix':need(before.st_uid==os.geteuid() and before.st_mode&0o077==0)
    with p.open('rb') as f:
        opened=os.fstat(f.fileno());need((opened.st_dev,opened.st_ino)==(before.st_dev,before.st_ino));raw=f.read(limit+1);after=os.fstat(f.fileno())
    need(len(raw)<=limit and (after.st_size,after.st_mtime_ns)==(before.st_size,before.st_mtime_ns))
    return raw
def pin(path):
    raw=read(path);return {'File':str(Path(path)),'SHA256':hashlib.sha256(raw).hexdigest()}
def decode(path):return json.loads(read(path),object_pairs_hook=pairs)
def pinned(p):
    need(set(p)=={'File','SHA256'} and pin(p['File'])==p);return decode(p['File'])
def actor(b):return tuple(b[k] for k in ('InstallationID','Namespace','NamespaceUID','PodName','PodUID','ServiceAccountName','ServiceAccountUID'))
def run(argv):
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('request-files','channel','signing-receipt','wrap-receipt','materials-result','store','credentials','capacity-config','capacity-dsn','capacity-tls','six-definition','minio-definition','status-relay-definition','nonce-binding','catalog-checkpoint'):
        parser.add_argument('--'+name+'-file',type=Path,required=True)
    parser.add_argument('--evidence-ca-binding-file',type=Path)
    parser.add_argument('--output-directory',type=Path,required=True)
    a=parser.parse_args(argv)
    request=decode(a.request_files_file)
    need(set(request)=={'ConfigFile','ConfigFileSHA256','GrantFile','GrantFileSHA256','ObserverFile','ObserverFileSHA256'})
    for kind in ('Config','Grant','Observer'):need(pin(request[kind+'File'])['SHA256']==request[kind+'FileSHA256'])
    sr=decode(a.signing_receipt_file);wr=decode(a.wrap_receipt_file);host=decode(a.materials_result_file)
    need(sr['Version']=='original-publication-signing-material-result.v1' and wr['Version']=='original-c1-evidence-material-result.v1')
    need(wr['State'] in ('original_dedicated_evidence_materials_issued_not_producer_or_adoption','original_dedicated_evidence_materials_current_original_files_verified'))
    signing=pinned(sr['Material']);wrap=pinned(wr['Material'])
    need(signing['Version']=='original-publication-signing-material.v1' and wrap['Version']=='original-c1-evidence-material.v1')
    need(signing['PlanSHA256']==wrap['PlanSHA256'] and signing['EnrollmentDocumentSHA256']==wrap['EnrollmentSHA256'])
    need(wr['WriterSelection']==wrap['WriterSelection'] and wr['InstalledObserver']==wrap['InstalledObserver'])
    pinned(wr['WriterSelection']);pinned(wr['InstalledObserver'])
    need(host['version']=='operator-materials-result.v1' and host['backup_ready'] is False)
    live=host['host'];need(live['Pod']==wrap['Binding']['PodName'] and len(signing['Bindings'])==3)
    need(all(actor(b)==actor(wrap['Binding']) for b in signing['Bindings']))
    channel=decode(a.channel_file);store=decode(a.store_file);capacity=decode(a.capacity_config_file);tls=decode(a.capacity_tls_file)
    need(set(channel)=={'Root','Store','Write','RecoveryProfileHash'})
    need(set(channel['Store'])=={'kek_identity_hash','kek_version'} and set(channel['Write'])=={'kek_identity_hash','kek_version'})
    need(store['Identity']==channel['Store']['kek_identity_hash'] and store['Version']==channel['Store']['kek_version'] and store['Root']==channel['Root'] and store['Installation']==wrap['Binding']['InstallationID'])
    need(set(capacity)=={'server_uuid','database','user','data_directory','tables'})
    need(capacity['user'].lower()!='root' and capacity['data_directory'].startswith('/') and set(tls)=={'ca_file','ca_sha256','server_name'} and tls['ca_sha256']==pin(tls['ca_file'])['SHA256'])
    need(isinstance(capacity['tables'],list) and len(set(capacity['tables']))==len(capacity['tables']) and {'audit_logs','system_backup_v2_configs','system_backup_v2_backups'}.issubset(capacity['tables']))
    # O_EXCL and directory fsync retain the ORIGINAL request, not an overwrite.
    out=a.output_directory;need(out.is_absolute() and not out.exists());out.mkdir(mode=0o700)
    directories={}
    for name in ('domain','channel','signing','six','minio','relay','nonce','evidence-ca','backup-kek','catalog-checkpoint'):
        d=out/name;d.mkdir(mode=0o700);directories[name]=str(d)
    value={'Version':'original-c1-pending-runtime-invocation.v3','PreColdHead1Directory':'',
      'Groups':{'Six':pin(a.six_definition_file),'MinIO':pin(a.minio_definition_file),'StatusRelay':pin(a.status_relay_definition_file),'Nonce':pin(a.nonce_binding_file),'EvidenceCA':pin(a.evidence_ca_binding_file) if a.evidence_ca_binding_file is not None else {'File':'','SHA256':''},'BackupKEK':{'File':'','SHA256':''},'CatalogCheckpoint':pin(a.catalog_checkpoint_file),'SixOutputDirectory':directories['six'],'MinIOOutputDirectory':directories['minio'],'StatusRelayOutputDirectory':directories['relay'],'NonceOutputDirectory':directories['nonce'],'EvidenceCAOutputDirectory':directories['evidence-ca'],'BackupKEKOutputDirectory':directories['backup-kek'],'CatalogCheckpointOutputDirectory':directories['catalog-checkpoint']},
      'Domain':{'Request':request,'Channel':pin(a.channel_file),'CapacityReport':{'File':'','SHA256':''},'OutputDirectory':directories['domain']},
      'Channel':{'Store':pin(a.store_file),'Credentials':pin(a.credentials_file),'ControllerDeployment':live['Deployment'],'ControllerPod':live['Pod'],'OutputDirectory':directories['channel']},
      'Signing':{'SigningMaterial':sr['Material'],'WrapMaterial':wr['Material'],'STSJWT':{'File':'','SHA256':''},'AuthenticationJWT':{'File':'','SHA256':''},'AuthenticationAudience':'','ControllerDeployment':live['Deployment'],'ControllerPod':live['Pod'],'Capacity':capacity,'OutputDirectory':directories['signing']},
      'CapacityDSN':pin(a.capacity_dsn_file),'CapacityTLS':tls}
    raw=json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False).encode()
    target=out/'original-c1-pending-runtime.input.json'
    fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
    if os.name=='posix':
        fd=os.open(out,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)
    print(json.dumps({'version':'original-c1-pending-runtime-input-result.v3','input':pin(target),'writer_selection':wr['WriterSelection'],'wrap_material':wr['Material'],'authority':False,'complete20':False,'backup_ready':False}))
    return 0
if __name__=='__main__':
    try:raise SystemExit(run(sys.argv[1:]))
    except (ValueError,KeyError,TypeError,OSError,json.JSONDecodeError):raise SystemExit('ORIGINAL_C1_INPUT_REFUSED_RETAIN_OUTPUT_NO_OVERWRITE')
