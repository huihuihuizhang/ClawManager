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
def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--directory',required=True);args=parser.parse_args()
    os.umask(0o077);package=Path(__file__).resolve().parent; build=json.loads((package/'BUILD_RECEIPT.json').read_bytes())
    directory=Path(args.directory);need(directory.is_absolute() and not directory.exists(),'fresh absolute image-work directory required');directory.mkdir(mode=0o700)
    need(directory.resolve()==directory,'canonical image-work directory required')
    for name in TOOLS:
        need(sha((package/name).read_bytes())==build['Binaries'][name]['SHA256'],'packaged binary hash mismatch')
    tag='10.130.14.23:5000/clawmanager:p2-team-'+build['SourceRevision'][:12]
    def run(argv):
        r=subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=600)
        need(r.returncode==0,'containerd image operation failed; keep image-work directory');return r.stdout
    run(['ctr','-n','k8s.io','images','pull','--plain-http',BASE])
    run(['ctr','-n','k8s.io','images','export',str(directory/'base.tar'),BASE])
    layer=directory/'tools.tar'
    with tarfile.open(layer,'w') as t:
        for name in TOOLS:
            raw=(package/name).read_bytes();m=tarfile.TarInfo('usr/local/bin/'+name);m.size=len(raw);m.mode=0o555;t.addfile(m,io.BytesIO(raw))
    digest=build_overlay(directory/'base.tar',layer,directory/'controller.oci.tar',tag)
    run(['ctr','-n','k8s.io','images','import',str(directory/'controller.oci.tar')])
    run(['ctr','-n','k8s.io','images','push','--plain-http',tag])
    req=urllib.request.Request('http://10.130.14.23:5000/v2/clawmanager/manifests/sha256:'+digest,headers={'Accept':'application/vnd.oci.image.manifest.v1+json'})
    with urllib.request.urlopen(req,timeout=30) as response: raw=response.read(1<<20)
    need(sha(raw)==digest,'registry readback differs')
    receipt={'Version':'p2-controller-image.v1','Base':BASE,'Image':'10.130.14.23:5000/clawmanager@sha256:'+digest,'SourceRevision':build['SourceRevision'],'Binaries':build['Binaries']}
    path=directory/'image.json';path.write_bytes(canonical(receipt))
    for name in ('base.tar','tools.tar','controller.oci.tar'):(directory/name).unlink()
    print('P2_CONTROLLER_IMAGE_READY',json.dumps({'Receipt':str(path),'SHA256':sha(path.read_bytes()),'Image':receipt['Image']}),flush=True)
if __name__=='__main__':
    try:main()
    except Exception as e:raise SystemExit('P2_IMAGE_UNCONFIRMED '+(str(e) if isinstance(e,ValueError) else type(e).__name__))
