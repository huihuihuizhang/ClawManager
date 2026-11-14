"""Private file/endpoint transport for this source CLI's existing Vault identity."""
import base64
from contextlib import contextmanager
import json
from pathlib import Path
from urllib.parse import urlsplit

MOUNT='/var/run/clawreef/system-backup/provider-dependency'

def inputs(A, dependency, secret):
    A.need(secret.get('immutable') is True, 'immutable provider Secret required')
    raw=base64.b64decode(secret['data']['observer.json'],validate=True)
    token=base64.b64decode(secret['data']['token'],validate=True)
    observer=A.decode(raw);endpoint=urlsplit(observer['Endpoint'])
    A.need(dependency['observer']=={'File':MOUNT+'/observer.json','SHA256':A.sha(raw)} and
           observer['IdentityMode']=='metadata-only' and observer['TokenFile']==MOUNT+'/token' and
           observer['TokenSHA256']==A.sha(token) and endpoint.scheme=='https' and endpoint.port==8200 and
           endpoint.hostname==dependency['workload']['Service']+'.'+A.NS+'.svc' and
           not endpoint.path and not endpoint.query and not endpoint.fragment and endpoint.username is None,
           'exact existing provider material and endpoint required')
    return observer,raw,token

def hosts_file(A, raw, hostname):
    A.need(0<len(raw)<1<<20 and b'\x00' not in raw, 'bounded host table required')
    for line in raw.decode('ascii').splitlines():
        A.need(hostname not in line.split('#',1)[0].split()[1:], 'existing provider host override must be reconciled')
    return raw+b'\n127.0.0.1 '+hostname.encode('ascii')+b'\n'

def command(directory,hosts,argv):
    return ['unshare','--mount','--propagation','private','--','sh','-ec',
            'mount --bind "$1" "$2"; mount -o remount,bind,ro "$2"; mount --bind "$3" /etc/hosts; mount -o remount,bind,ro /etc/hosts; shift 3; exec "$@"',
            'p2-source-provider',str(directory),MOUNT,str(hosts),*argv]

@contextmanager
def access(A,F,site,dns,records,pod,dependency,secret):
    observer,raw,token=inputs(A,dependency,secret)
    A.need(any(v.get('name')=='provider-dependency-input' and v.get('secret',{}).get('secretName')==secret['metadata']['name']
               for v in pod['spec']['volumes']), 'controller provider Secret differs')
    for name,body in [('observer.json',raw),('token',token)]:
        actual=site.call(['exec',pod['metadata']['name'],'-c','controller','--','sha256sum',MOUNT+'/'+name]).decode().split()
        A.need(actual==[A.sha(body),MOUNT+'/'+name], 'actual controller provider file differs')
    directory=records/'provider-files';directory.mkdir(mode=0o700,exist_ok=True)
    A.retain(directory/'observer.json',raw);A.retain(directory/'token',token)
    host=Path('/etc/hosts');before=host.read_bytes();st=host.stat();identity=(st.st_dev,st.st_ino)
    hostpin=A.retain(records/'source.hosts',hosts_file(A,before,urlsplit(observer['Endpoint']).hostname))
    target=Path(MOUNT);created=[]
    forward_records=records/'provider-forward';forward_records.mkdir(mode=0o700,exist_ok=True)
    def check():
        current=site.get('pod',pod['metadata']['name'])
        A.need(current['metadata']['uid']==pod['metadata']['uid'] and not current['metadata'].get('deletionTimestamp'), 'source controller changed')
        now=host.stat();A.need(host.read_bytes()==before and (now.st_dev,now.st_ino)==identity, 'host table changed')
        A.need((directory/'observer.json').read_bytes()==raw and (directory/'token').read_bytes()==token, 'provider transport files changed')
    try:
        missing=[];parent=target
        while not parent.exists():missing.append(parent);parent=parent.parent
        for parent in reversed(missing):
            parent.mkdir(mode=0o700);st=parent.stat();created.append((parent,st.st_dev,st.st_ino))
        A.need(target.is_dir() and not target.is_symlink() and not list(target.iterdir()), 'provider mount target must be empty')
        forward=F.LocalForward(site,{'--provider-service':dependency['workload']['Service'],'--provider-endpoint':observer['Endpoint']},forward_records,A.retain,endpoint_port=True)
        with forward as address:
            A.need(address=='127.0.0.1:8200','original endpoint port required')
            class Runner:
                def run(self,argv,**kwargs):
                    check();forward.check()
                    try:return dns.run(command(directory,Path(hostpin['File']),argv),**kwargs)
                    finally:check();forward.check()
            A.retain(records/'provider-transport.json',{'Version':'p2-source-provider-private-transport.v1','ControllerPodUID':pod['metadata']['uid'],
                'ObserverSHA256':A.sha(raw),'TokenSHA256':A.sha(token),'Endpoint':observer['Endpoint'],
                'HostFilesMutated':False,'TLSIdentityUnchanged':True,'AuthorityIssued':False})
            yield Runner()
    finally:
        for path,dev,ino in reversed(created):
            st=path.stat();A.need(not path.is_symlink() and (st.st_dev,st.st_ino)==(dev,ino),'mount target identity changed')
            path.rmdir()
        check()
