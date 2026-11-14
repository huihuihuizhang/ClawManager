#!/usr/bin/env python3
"""Read-only cluster/credential checks before any P2 image pull or push."""
import argparse
import base64
import datetime as dt
import http.client
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import tempfile
import urllib.request
from urllib.parse import urlsplit

def load(name):
    s=importlib.util.spec_from_file_location(name,Path(__file__).with_name(name+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m

def registry_manifest(A,digest):
    req=urllib.request.Request('http://10.130.14.23:5000/v2/clawmanager/manifests/'+digest,headers={'Accept':'application/vnd.oci.image.manifest.v1+json, application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.v2+json, application/vnd.docker.distribution.manifest.list.v2+json'})
    with urllib.request.urlopen(req,timeout=15) as response:raw=response.read((1<<20)+1)
    A.need(len(raw)<=1<<20 and 'sha256:'+A.sha(raw)==digest,'registry base manifest digest mismatch')
    return A.decode(raw)

def registry_and_space(A,O,package,build,container_root=Path('/var/lib/containerd'),runtime_root=Path('/run/system-backup/runtime')):
    with urllib.request.urlopen('http://10.130.14.23:5000/v2/',timeout=15) as response:A.need(response.status==200,'registry API unavailable')
    manifest=registry_manifest(A,O.BASE.split('@')[1])
    if 'manifests' in manifest:
        options=[m for m in manifest['manifests'] if m.get('platform',{}).get('os')=='linux' and m.get('platform',{}).get('architecture')=='amd64']
        A.need(len(options)==1,'exact Linux amd64 base required');manifest=registry_manifest(A,options[0]['digest'])
    base_bytes=sum(m['size'] for m in manifest['layers'])
    tools_bytes=sum((package/n).stat().st_size for n in O.TOOLS)
    # Conservative working-space estimate; group demands sharing a filesystem.
    demands=[(package,2*base_bytes+2*tools_bytes+(1<<30)),(container_root,max(4*base_bytes+tools_bytes+(1<<30),4<<30)),(runtime_root,128<<20)]
    groups={}
    for path,required in demands:
        A.need(path.is_dir(),'required storage directory missing: '+str(path))
        device=path.stat().st_dev
        entry=groups.setdefault(device,{'Paths':[],'RequiredBytes':0,'FreeBytes':shutil.disk_usage(path).free})
        entry['Paths'].append(str(path));entry['RequiredBytes']+=required
    for entry in groups.values():A.need(entry['FreeBytes']>=entry['RequiredBytes'],'insufficient working disk space: '+json.dumps(entry))
    return list(groups.values())

def owner_covers_window(A,data,until):
    ttl=data.get('ttl')
    perpetual=ttl==0 and data.get('expire_time') in (None,'') and data.get('creation_ttl')==0
    A.need(type(ttl) is int and (perpetual or ttl>(until-dt.datetime.now(dt.timezone.utc)).total_seconds()),'original Vault owner credential expires before build/issuance window')

def owner_ttl(A,F,site,records,owner,token,workload,until):
    endpoint=urlsplit(owner['Endpoint']);ca=base64.b64decode(owner['CAPEM'],validate=True)
    A.need(A.sha(ca)==owner['CASHA256'] and A.sha(token)==owner['TokenSHA256'],'original Vault credential/trust pin differs')
    tls=ssl.create_default_context(cadata=ca.decode('ascii'))
    forward=records/'vault-owner';forward.mkdir(mode=0o700)
    with F.LocalForward(site,{'--provider-service':workload['Service'],'--provider-endpoint':owner['Endpoint']},forward,A.retain) as address:
        class Connection(http.client.HTTPSConnection):
            def connect(self):
                raw=socket.create_connection(('127.0.0.1',int(address.split(':')[1])),timeout=5)
                try:self.sock=tls.wrap_socket(raw,server_hostname=endpoint.hostname)
                except BaseException:raw.close();raise
        connection=Connection(endpoint.hostname,endpoint.port or 443,timeout=5,context=tls)
        try:
            connection.request('GET','/v1/auth/token/lookup-self',headers={'X-Vault-Token':token.decode('ascii')})
            response=connection.getresponse();raw=response.read((1<<20)+1)
            A.need(response.status==200 and len(raw)<=1<<20,'original Vault owner credential rejected')
            owner_covers_window(A,A.decode(raw)['data'],until)
        finally:connection.close()

def run(package,attempt):
    A,C,L,H,R,T,N,F,O,D=[load(n) for n in ('assemble-p2-installation-candidate','continue-p2-nov14','load-p2-formal-vault','prepare-p2-longhorn-provider-loaded','resume-p2-recovered-source','resume-p2-tenant-team-source','renew-p2-source-preparation','p2-vault-local-forward','build-p2-controller-overlay','p2-source-dns')]
    for name in ('kubectl','ctr','unshare','mount','python3'):A.need(shutil.which(name),'required executable missing: '+name)
    build=A.decode((package/'BUILD_RECEIPT.json').read_bytes());A.need(build['SourceRevision']==(package/'SOURCE_REVISION').read_text().strip(),'package revision mismatch')
    for name in O.TOOLS:A.read({'File':str(package/name),'SHA256':build['Binaries'][name]['SHA256']},256<<20)
    C.select_attempt(A,attempt,stage_attachment=False)
    parent=A.decode((T.PARENT/'completed.json').read_bytes())
    for key,digest in [('Receipt',T.RECEIPT_SHA),('Definition',T.DEFINITION_SHA),('SourceSelection',T.SELECTION_SHA)]:
        A.need(parent[key]['SHA256']==digest,'original source receipt differs');A.read(parent[key])
    A.obj(parent['Definition']);A.obj(parent['SourceAPI']);selected=A.obj(parent['SourceSelection'])
    formal=A.obj({'File':str(L.PARENT/'receipt.private.json'),'SHA256':L.RECEIPT_SHA});old_secret=A.obj(formal['SecretManifest'])
    argv=A.decode((T.PARENT/'author.sent.private.json').read_bytes())['Argv'];common=argv[2:argv.index('--definition-file')]
    for i in range(0,len(common),2):
        flag,path=common[i:i+2]
        if flag.endswith('-file'):
            sha_flag=flag[:-5]+'-sha256'
            digest=common[common.index(sha_flag)+1] if sha_flag in common else A.sha(Path(path).read_bytes())
            A.read({'File':path,'SHA256':digest})
    until=dt.datetime.now(dt.timezone.utc)+dt.timedelta(minutes=45)
    certificates=[(C.ROOT/'renewal-20261113/observer/receipt.private.json','c0d69a9d9d1254a40993fb5516ed936325f265a74b0dde4b3823ea52fdd010f5'),(C.ROOT/'renewal-20261113/runtime-unique/runtime-agent.receipt.private.json','1d61b1d11b3427fd46d9d2eab3bd04f19daf74ae3a674a9f2275269c1810f149')]
    def pins(value):
        if isinstance(value,dict):
            if set(value)=={'File','SHA256'}:A.read(value)
            else:
                for v in value.values():pins(v)
        elif isinstance(value,list):
            for v in value:pins(v)
    for path,digest in certificates:
        cert=A.obj({'File':str(path),'SHA256':digest});A.need(N.moment(cert['NotAfter'])>until,'certificate has less than 45 minutes; renew before image build');pins(cert)
    records=Path(tempfile.mkdtemp(prefix='preflight-',dir=package))
    print('P2_PREFLIGHT_RECORDS',str(records),flush=True)
    site=L.Site(records,A);R.verify_app(A,site)
    L.verify_secret(site.get('secret',old_secret['metadata']['name']),old_secret)
    current=site.get('deployment',selected['Controller']['Deployment'])
    plan=C.JOURNAL/'delivery-plan.private.json'
    allowed=[A.obj(A.decode((H.PARENT/'delivery-plan.private.json').read_bytes())['DesiredSpec'])]
    if plan.exists():allowed.append(A.obj(A.decode(plan.read_bytes())['DesiredSpec']))
    A.need(current['metadata']['uid']==selected['Controller']['DeploymentUID'] and current['spec'] in allowed,'controller changed before image build')
    mint=C.JOURNAL/'mint/native.receipt.private.json'
    if mint.exists():
        minted=A.decode(mint.read_bytes());A.need(minted['Version']=='installed-vault-metadata-materials.v1' and minted['Workload']==formal['Workload'],'retained metadata scope differs')
        observer=A.obj(minted['Observer']);token=A.read({'File':observer['TokenFile'],'SHA256':observer['TokenSHA256']})
        L.verify_metadata(A,F,site,records,observer,token,minted['Workload'],until)
    else:
        A.need(not (C.JOURNAL/'mint/native.sent.private.json').exists(),'metadata mint outcome unknown; reconcile before image build')
        pod=H.current_controller(site,A,L,selected,allowed[0])
        endpoints=[(c['Purpose'],c['Endpoint']) for c in selected['Connections'] if (urlsplit(c['Endpoint']).hostname or '').endswith('.'+A.NS+'.svc')]
        dns=D.SourceDNS(site,records,pod,endpoints,A.retain);dns.probe()
        writer=A.obj(parent['VaultWriterSelection']);dep=writer['PreAdoptionVaultDependencies'][0];owner=A.obj(dep['InstalledObserver'])
        owner_ttl(A,F,site,records,owner,A.read({'File':owner['TokenFile'],'SHA256':owner['TokenSHA256']}),dep['Workload'],until)
    space=registry_and_space(A,O,package,build)
    report={'Version':'p2-team-preflight.v1','SourceAttempt':attempt,'CredentialWindowMinutes':45,'RegistryReachable':True,'DiskEstimates':space,'ImageBuildStarted':False,'ReadOnlyClusterChecks':True}
    A.retain(records/'passed.json',report);print('P2_PREFLIGHT_PASSED',json.dumps(report),flush=True)
    return report

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source-attempt',type=int,default=1);args=p.parse_args()
    os.umask(0o077);run(Path(__file__).resolve().parent,args.source_attempt)
if __name__=='__main__':
    try:main()
    except Exception as e:raise SystemExit('P2_PREFLIGHT_REFUSED_BEFORE_IMAGE_BUILD '+(str(e) if isinstance(e,ValueError) else type(e).__name__))
