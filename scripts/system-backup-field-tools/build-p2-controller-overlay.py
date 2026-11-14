#!/usr/bin/env python3
"""Build the P2 controller OCI overlay from the exact existing registry image."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import urllib.request

BASE='10.130.14.23:5000/clawmanager@sha256:4c196dd9b904244e7715f2151f9f672c9db129b582ca716f1324b2bf31b6847a'
TOOLS=('system-backup-source-registries','system-backup-first-install-materials','system-backup-v2-controller')
def need(ok,msg):
    if not ok: raise ValueError(msg)
def sha(raw): return hashlib.sha256(raw).hexdigest()
def canonical(v):return json.dumps(v,separators=(',',':'),sort_keys=True).encode()
def descriptor(raw,media):return {'mediaType':media,'digest':'sha256:'+sha(raw),'size':len(raw)}
def overlay_metadata(manifest,config,layer_digest,layer_size):
    need(config.get('os')=='linux' and config.get('architecture')=='amd64','Linux amd64 base required')
    need(len(manifest['layers'])==len(config['rootfs']['diff_ids']),'base layer/diff-id mismatch')
    config=json.loads(canonical(config));manifest=json.loads(canonical(manifest))
    config['rootfs']['diff_ids'].append('sha256:'+layer_digest)
    config.setdefault('history',[]).append({'created_by':'ClawManager P2 exact controller tools overlay'})
    body=canonical(config);manifest['config']=descriptor(body,'application/vnd.oci.image.config.v1+json')
    manifest['mediaType']='application/vnd.oci.image.manifest.v1+json'
    manifest['layers'].append({'mediaType':'application/vnd.oci.image.layer.v1.tar','digest':'sha256:'+layer_digest,'size':layer_size})
    return body,canonical(manifest)
def build_overlay(base_path,layer_path,output,tag):
    with tarfile.open(base_path) as base:
        members={m.name:m for m in base.getmembers() if m.isfile()}
        def blob(d):
            need(d['digest'].startswith('sha256:'),'unsupported OCI digest')
            raw=base.extractfile(members['blobs/sha256/'+d['digest'][7:]]).read()
            need(len(raw)==d['size'] and sha(raw)==d['digest'][7:],'base OCI digest mismatch');return raw
        index=json.load(base.extractfile(members['index.json']))
        entries=index['manifests']; root=[d for d in entries if d['digest']==BASE.split('@')[1]]
        need(len(root)==1,'export does not contain the exact base digest')
        selected=root[0]; doc=json.loads(blob(selected))
        if 'manifests' in doc:
            options=[d for d in doc['manifests'] if d.get('platform',{}).get('os')=='linux' and d.get('platform',{}).get('architecture')=='amd64']
            need(len(options)==1,'ambiguous platform manifest');doc=json.loads(blob(options[0]))
        config=json.loads(blob(doc['config']))
        with layer_path.open('rb') as f: digest=sha(f.read())
        cfg,manifest=overlay_metadata(doc,config,digest,layer_path.stat().st_size)
        ref=descriptor(manifest,'application/vnd.oci.image.manifest.v1+json');ref['annotations']={'io.containerd.image.name':tag,'org.opencontainers.image.ref.name':tag}
        additions={'oci-layout':canonical({'imageLayoutVersion':'1.0.0'}),'index.json':canonical({'schemaVersion':2,'manifests':[ref]}),
                   'blobs/sha256/'+sha(cfg):cfg,'blobs/sha256/'+sha(manifest):manifest}
        with tarfile.open(output,'w') as dest:
            for name,m in members.items():
                if name.startswith('blobs/') and name not in additions:
                    dest.addfile(m,base.extractfile(m))
            for name,raw in additions.items():
                m=tarfile.TarInfo(name);m.size=len(raw);m.mode=0o600;dest.addfile(m,io.BytesIO(raw))
            m=tarfile.TarInfo('blobs/sha256/'+digest);m.size=layer_path.stat().st_size;m.mode=0o600
            with layer_path.open('rb') as f:dest.addfile(m,f)
        return sha(manifest)
def registry_receipt(receipt):
    digest=receipt['Image'].split('@sha256:')[1]
    req=urllib.request.Request('http://10.130.14.23:5000/v2/clawmanager/manifests/sha256:'+digest,headers={'Accept':'application/vnd.oci.image.manifest.v1+json'})
    with urllib.request.urlopen(req,timeout=30) as response: raw=response.read(1<<20)
    need(sha(raw)==digest,'registry readback differs')


def build_image(package,directory):
    build=json.loads((package/'BUILD_RECEIPT.json').read_bytes())
    for name in TOOLS:
        need(sha((package/name).read_bytes())==build['Binaries'][name]['SHA256'],'packaged binary hash mismatch')
    need(directory.is_absolute() and not directory.is_symlink(),'absolute real image-work directory required')
    directory.mkdir(mode=0o700,exist_ok=True)
    need(directory.resolve()==directory,'canonical image-work directory required')
    expected={'Version':'p2-controller-image.v1','Base':BASE,'SourceRevision':build['SourceRevision'],'Binaries':build['Binaries']}
    path=directory/'image.json'
    if path.exists():
        try:receipt=json.loads(path.read_bytes())
        except ValueError:raise ValueError('image receipt is incomplete; preserve this directory and rerun from a fresh unpack directory')
        need({k:receipt[k] for k in expected}==expected,'existing image receipt belongs to another package; use a fresh unpack directory')
        registry_receipt(receipt)
    else:
        # A fresh attempt never overwrites interrupted exports or their logs.
        attempt=Path(tempfile.mkdtemp(prefix='attempt-',dir=directory))
        (attempt/'inputs.json').write_bytes(canonical(expected))
        print('P2_IMAGE_ATTEMPT',str(attempt),flush=True)
        def run(label,argv):
            (attempt/(label+'.argv.json')).write_bytes(canonical(argv))
            with (attempt/(label+'.stdout.log')).open('xb') as stdout, (attempt/(label+'.stderr.log')).open('xb') as stderr:
                try:
                    r=subprocess.run(argv,stdout=stdout,stderr=stderr,timeout=600)
                except BaseException as error:
                    (attempt/(label+'.result.json')).write_bytes(canonical({'Exception':type(error).__name__}))
                    raise
            (attempt/(label+'.result.json')).write_bytes(canonical({'ExitCode':r.returncode}))
            need(r.returncode==0,'image '+label+' failed; logs: '+str(attempt)+'; rerun the same entry command; previous attempt is preserved')
        tag='10.130.14.23:5000/clawmanager:p2-team-'+build['SourceRevision'][:12]
        try:
            run('pull',['ctr','-n','k8s.io','images','pull','--plain-http',BASE])
            run('export',['ctr','-n','k8s.io','images','export',str(attempt/'base.tar'),BASE])
            layer=attempt/'tools.tar'
            with tarfile.open(layer,'w') as t:
                for name in TOOLS:
                    raw=(package/name).read_bytes();m=tarfile.TarInfo('usr/local/bin/'+name);m.size=len(raw);m.mode=0o555;t.addfile(m,io.BytesIO(raw))
            digest=build_overlay(attempt/'base.tar',layer,attempt/'controller.oci.tar',tag)
            run('import',['ctr','-n','k8s.io','images','import',str(attempt/'controller.oci.tar')])
            run('push',['ctr','-n','k8s.io','images','push','--plain-http',tag])
            receipt={**expected,'Image':'10.130.14.23:5000/clawmanager@sha256:'+digest,'BuildAttempt':attempt.name}
            registry_receipt(receipt)
            staged=attempt/'image.json'
            with staged.open('xb') as f:
                f.write(canonical(receipt));f.flush();os.fsync(f.fileno())
            os.replace(staged,path)
        except BaseException as error:
            (attempt/'failure.json').write_bytes(canonical({'Exception':type(error).__name__,'Retry':'rerun the same entry command','Logs':str(attempt)}))
            print('P2_IMAGE_RETRY_SAME_COMMAND_LOGS_RETAINED',str(attempt),flush=True)
            raise
    if receipt.get('BuildAttempt'):
        name=receipt['BuildAttempt'];need(name.startswith('attempt-') and Path(name).name==name,'invalid build attempt receipt')
        attempt=directory/name;need(attempt.resolve()==attempt and attempt.is_dir(),'recorded build attempt unavailable')
        for name in ('base.tar','tools.tar','controller.oci.tar'):
            artifact=attempt/name;need(not artifact.is_symlink(),'unexpected image artifact link')
            artifact.unlink(missing_ok=True)
    print('P2_CONTROLLER_IMAGE_READY',json.dumps({'Receipt':str(path),'SHA256':sha(path.read_bytes()),'Image':receipt['Image']}),flush=True)
    return receipt


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--directory',required=True);args=parser.parse_args()
    os.umask(0o077);directory=Path(args.directory)
    need(directory.is_absolute() and not directory.is_symlink(),'absolute real image-work directory required')
    directory.mkdir(mode=0o700,exist_ok=True)
    import fcntl
    with (directory/'build.lock').open('a') as lock:
        try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise ValueError('another image build is active; wait and rerun the same command')
        build_image(Path(__file__).resolve().parent,directory)
if __name__=='__main__':
    try:main()
    except Exception as e:raise SystemExit('P2_IMAGE_UNCONFIRMED '+(str(e) if isinstance(e,ValueError) else type(e).__name__))
