#!/usr/bin/env python3
"""Publish this installation's fixed-source App/worker binaries by digest only.

Keeps each original image's runtime configuration and existing layers. Does not
retag an image, patch a Deployment, initialize an owner or admit a backup task.
"""
import argparse
import copy
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import tarfile
import urllib.error
import urllib.parse
import urllib.request

REVISION='eca964d42b96c31cb381531889a39c23a366ffab'
ORIGIN='http://10.130.14.23:5000'
QUALIFIER_SHA='e87866b387ae7b4d52b76c6ea14b15becc17d1f83a067944d168881810924862'
PROFILES={
 'app':('clawmanager','322ba63b49d21c4030be2760c88ae03457fbe9454ee138906066b29bc68541ca','75fdf436c8655361789a6165edd3881bfdd4190bff2846b7052dcbe437e0c55d','clawreef-server','usr/local/bin/clawreef-server'),
 'worker':('clawmanager-backup-worker','f125b3eedcca4cefacee8b0361236ce4beb9705243c59580d57eb59207fbe67e','07cab4a2a7a2d2f4dd5c54347bbee235f68a4503c6a7c032b5e075fc04ce166e','backup-worker','backup-worker')}
def need(ok,why):
 if not ok:raise ValueError(why)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def encode(v):return json.dumps(v,sort_keys=True,separators=(',',':')).encode()
def retain(path,raw):
 if path.exists():need(not path.is_symlink() and path.read_bytes()==raw,'retained publication changed')
 else:
  with path.open('xb') as f:os.chmod(path,0o600);f.write(raw);f.flush();os.fsync(f.fileno())
 return {'File':str(path),'SHA256':sha(raw)}

def candidate(kind,manifest,config,binary,receipt):
 repo,base,config_sha,filename,target=PROFILES[kind]
 need(receipt['Version']=='p2-execution-binaries-build.v1' and receipt['SourceRevision']==REVISION and
      receipt['Platform']=='linux/amd64' and receipt['Binaries'][filename]=={'SHA256':sha(binary),'Bytes':len(binary)},'actual fixed-source build receipt required')
 need(1<<20<len(binary)<200<<20 and binary[:6]==b'\x7fELF\x02\x01' and binary[18:20]==b'\x3e\x00','Linux amd64 ELF required')
 need(config['os']=='linux' and config['architecture']=='amd64' and manifest['schemaVersion']==2 and
      config['rootfs']['type']=='layers' and len(config['rootfs']['diff_ids'])==len(manifest['layers']), 'original image platform/layer shape changed')
 if kind=='worker':need(config['config']['Entrypoint']==['/backup-worker'],'original worker entrypoint changed')
 out=io.BytesIO()
 with tarfile.open(fileobj=out,mode='w',format=tarfile.USTAR_FORMAT) as archive:
  member=tarfile.TarInfo(target);member.size=len(binary);member.mode=0o555;member.uid=member.gid=member.mtime=0
  archive.addfile(member,io.BytesIO(binary))
 plain=out.getvalue();layer=gzip.compress(plain,compresslevel=6,mtime=0)
 new=copy.deepcopy(config);new['rootfs']['diff_ids'].append('sha256:'+sha(plain))
 need(config['config'].get('Labels') is None or isinstance(config['config']['Labels'],dict),'original image labels shape changed')
 labels=copy.deepcopy(config['config'].get('Labels') or {});new['config']['Labels']=labels
 labels['org.opencontainers.image.revision']=REVISION
 labels['io.clawmanager.p2.binary.sha256']=sha(binary)
 labels['io.clawmanager.p2.base.manifest']='sha256:'+base
 labels['io.clawmanager.p2.backend.tree']=receipt['BackendTree']
 if 'history' in new:new['history'].append({'created_by':'ClawManager P2 fixed-source '+REVISION,'empty_layer':False})
 check=copy.deepcopy(new);check['rootfs']['diff_ids'].pop()
 if 'history' in check:check['history'].pop()
 check['config']['Labels']=copy.deepcopy(config['config'].get('Labels'))
 if 'Labels' not in config['config']:check['config'].pop('Labels')
 need(check==config,'runtime configuration changed outside build provenance')
 config_raw=encode(new);next_manifest=copy.deepcopy(manifest)
 next_manifest['config'].update(digest='sha256:'+sha(config_raw),size=len(config_raw))
 media='application/vnd.oci.image.layer.v1.tar+gzip' if manifest['mediaType']=='application/vnd.oci.image.manifest.v1+json' else 'application/vnd.docker.image.rootfs.diff.tar.gzip'
 next_manifest['layers'].append({'mediaType':media,'digest':'sha256:'+sha(layer),'size':len(layer)})
 return layer,config_raw,encode(next_manifest)

class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*a,**kw):raise ValueError('registry redirect refused')
class Registry:
 def __init__(self,repo):
  need(repo in [p[0] for p in PROFILES.values()],'installation repositories only')
  self.repo=repo;self.client=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
 def path(self,category,value):return '/v2/'+self.repo+'/'+category+'/'+value
 def call(self,method,path,raw=None,media=None,missing=False):
  url=urllib.parse.urljoin(ORIGIN+'/',path);u=urllib.parse.urlsplit(url)
  need((u.scheme,u.netloc)==('http','10.130.14.23:5000') and u.path.startswith('/v2/'+self.repo+'/') and
       not u.fragment and not u.username and '%' not in u.path and '\\' not in u.path and '..' not in u.path.split('/'),'registry target changed')
  headers={'Accept':'application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json','Accept-Encoding':'identity'}
  if media:headers['Content-Type']=media
  try:return self.client.open(urllib.request.Request(url,data=raw,method=method,headers=headers),timeout=60)
  except urllib.error.HTTPError as e:
   if missing and e.code==404:e.close();return None
   raise
 def read(self,kind,digest,limit=4<<20):
  need(re.fullmatch('sha256:[a-f0-9]{64}',digest),'immutable digest required')
  with self.call('GET',self.path(kind,digest)) as response:
   need(response.status==200,'registry read unconfirmed');raw=response.read(limit+1)
  need(0<len(raw)<=limit and 'sha256:'+sha(raw)==digest,'actual registry bytes mismatch')
  return raw
 def upload(self,raw):
  digest='sha256:'+sha(raw)
  response=self.call('HEAD',self.path('blobs',digest),missing=True)
  if response is not None:
   with response:need(response.status==200,'blob lookup unconfirmed')
  else:
   with self.call('POST',self.path('blobs/uploads',''),b'','application/octet-stream') as response:
    need(response.status==202,'blob upload start unconfirmed');location=response.headers['Location']
   split=urllib.parse.urlsplit(location);query=urllib.parse.parse_qsl(split.query,keep_blank_values=True)
   need(not any(k=='digest' for k,v in query),'upload digest unexpectedly preselected')
   query.append(('digest',digest));location=urllib.parse.urlunsplit(split._replace(query=urllib.parse.urlencode(query)))
   with self.call('PUT',location,raw,'application/octet-stream') as response:
    need(response.status==201 and response.headers.get('Docker-Content-Digest')==digest,'blob upload unconfirmed')
  need(self.read('blobs',digest,len(raw))==raw,'published blob readback mismatch')

def publish(kind,directory,records,receipt):
 repo,base,base_config,filename,target=PROFILES[kind];registry=Registry(repo)
 manifest_raw=registry.read('manifests','sha256:'+base);manifest=json.loads(manifest_raw)
 need(manifest['config']['digest']=='sha256:'+base_config,'original base config changed')
 config_raw=registry.read('blobs','sha256:'+base_config);config=json.loads(config_raw)
 need(manifest['config']['size']==len(config_raw),'base config size changed')
 binary_path=directory/filename;need(not binary_path.is_symlink(),'regular build artifact required')
 layer,new_config,new_manifest=candidate(kind,manifest,config,binary_path.read_bytes(),receipt)
 records.mkdir(mode=0o700,exist_ok=True)
 pins={name:retain(records/name,raw) for name,raw in [('base-manifest.json',manifest_raw),('base-config.private.json',config_raw),('binary-layer.tar.gz',layer),('image-config.json',new_config),('image-manifest.json',new_manifest)]}
 intent={'SourceRevision':REVISION,'BuildReceiptSHA256':sha(encode(receipt)),'Files':pins}
 retain(records/'publish.sent.json',encode(intent))
 registry.upload(layer);registry.upload(new_config)
 digest='sha256:'+sha(new_manifest)
 with registry.call('PUT',registry.path('manifests',digest),new_manifest,manifest['mediaType']) as response:
  need(response.status==201 and response.headers.get('Docker-Content-Digest')==digest,'immutable manifest upload unconfirmed')
 need(registry.read('manifests',digest)==new_manifest and registry.read('manifests','sha256:'+base)==manifest_raw,'manifest readback mismatch')
 result={'Version':'p2-fixed-source-image-publication.v1','Reference':'10.130.14.23:5000/'+repo+'@'+digest,
         'Manifest':pins['image-manifest.json'],'Config':pins['image-config.json'],'SourceRevision':REVISION,
         'BinarySHA256':receipt['Binaries'][filename]['SHA256'],'BaseReference':'10.130.14.23:5000/'+repo+'@sha256:'+base,
         'WorkloadChanged':False,'AllInheritedLayersVerified':False,'NativeReleaseQualified':False,'BackupReady':False}
 retain(records/'image-data.json',encode(result));print('P2_EXECUTION_IMAGE_PUBLISHED',json.dumps(result),flush=True)
 return result

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--tool-directory',type=Path,required=True);p.add_argument('--records-directory',type=Path,required=True);args=p.parse_args();os.umask(0o077)
 need(os.name=='posix' and args.records_directory.is_dir() and args.records_directory.resolve(strict=True)==args.records_directory and args.records_directory.stat().st_mode&0o077==0,'existing private Linux records required')
 path=args.tool_directory/'system-backup-operator-deployment.py'
 need(not path.is_symlink() and sha(path.read_bytes())==QUALIFIER_SHA,'original read-only OCI byte qualifier required')
 spec=importlib.util.spec_from_file_location('original_oci_qualifier',path);qualifier=importlib.util.module_from_spec(spec);spec.loader.exec_module(qualifier)
 receipt=json.loads((args.tool_directory/'BUILD_RECEIPT.json').read_bytes())
 for kind in PROFILES:
  result=publish(kind,args.tool_directory,args.records_directory/kind,receipt)
  print('VERIFYING_EXECUTION_IMAGE_LAYERS',kind,flush=True)
  actual=qualifier.registry_image(result['Reference'],{'config_digest':'sha256:'+result['Config']['SHA256']},REVISION)
  retain(args.records_directory/kind/'registry-byte-verification.json',encode({'ActualImage':actual,'AllInheritedLayersVerified':True,'StartupVerified':False,'BackupReady':False}))
  print('P2_EXECUTION_IMAGE_BYTES_VERIFIED',kind,result['Reference'],flush=True)
 print('P2_EXECUTION_CANDIDATES_PUBLISHED_NOT_DEPLOYED',args.records_directory,flush=True)
if __name__=='__main__':
 try:main()
 except (ValueError,OSError,KeyError,TypeError) as e:raise SystemExit('P2_EXECUTION_PUBLICATION_UNCONFIRMED '+(str(e) if type(e) is ValueError else type(e).__name__))
