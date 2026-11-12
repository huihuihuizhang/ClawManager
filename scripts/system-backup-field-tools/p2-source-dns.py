"""This installation's source CLI DNS, in a short-lived private mount namespace."""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
from urllib.parse import urlsplit

NS='clawmanager-sbk-validation-system'
def need(ok,why):
 if not ok:raise ValueError(why)
def sha(raw):return hashlib.sha256(raw).hexdigest()

def validate_resolver(raw,dns_service):
 need(0<len(raw)<=4096 and b'\x00' not in raw,'bounded actual controller resolver required')
 nameservers=[];search=[]
 for line in raw.decode('ascii').splitlines():
  fields=line.split('#',1)[0].split()
  if not fields:continue
  need(fields[0] in ['nameserver','search','options'],'ordinary actual Pod resolver directives required')
  if fields[0]=='nameserver':
   need(len(fields)==2,'one address per resolver nameserver required');nameservers.append(str(ipaddress.ip_address(fields[1])))
  elif fields[0]=='search':
   need(all(re.fullmatch(r'[a-z0-9.-]+',x) for x in fields[1:]),'ordinary cluster search suffixes required');search+=fields[1:]
  else:need(all(re.fullmatch(r'[a-z]+(?::[0-9]+)?',x) for x in fields[1:]),'ordinary Pod resolver options required')
 expected=dns_service['spec'].get('clusterIPs') or [dns_service['spec']['clusterIP']]
 need(nameservers and set(nameservers)<=set(expected) and dns_service['metadata']['namespace']=='kube-system' and
  dns_service['metadata']['name']=='kube-dns' and dns_service['metadata'].get('uid') and
  any(x.startswith(NS+'.svc.') for x in search),'actual selected cluster DNS and namespace search required')
 return {'Nameservers':nameservers,'Search':search,'DNSServiceUID':dns_service['metadata']['uid']}

def command(resolver,argv):
 need(isinstance(argv,list) and argv and all(isinstance(x,str) and '\x00' not in x for x in argv),'literal source CLI argv required')
 # No host file write: mount propagation is private before the resolver bind.
 # sh exec keeps the native command as the bounded subprocess PID.
 return ['unshare','--mount','--propagation','private','--','sh','-ec',
  'mount --bind "$1" /etc/resolv.conf; mount -o remount,bind,ro /etc/resolv.conf; shift; exec "$@"',
  'p2-source-dns',str(resolver),*argv]

class SourceDNS:
 def __init__(self,site,records,pod,endpoints,save):
  self.records=records;self.save=save
  self.host=Path('/etc/resolv.conf');self.before=self.host.read_bytes();st=self.host.stat();self.identity=(st.st_dev,st.st_ino)
  need(pod['metadata']['namespace']==NS and pod['status']['phase']=='Running' and
   all(c.get('ready') for c in pod['status'].get('containerStatuses',[])),'current ready controller/owner Pod required for DNS')
  raw=site.call(['exec',pod['metadata']['name'],'-c','installation-owner','--','cat','/etc/resolv.conf'])
  dns=json.loads(site.call(['-n','kube-system','get','service','kube-dns','-o','json']))
  checked=validate_resolver(raw,dns)
  self.resolver=records/'controller.resolv.conf';save(self.resolver,raw)
  hosts=[];services=[]
  for label,url in endpoints:
   u=urlsplit(url);host=u.hostname
   need(host and host.endswith('.'+NS+'.svc') and u.username is None and not u.query and not u.fragment,'this installation source endpoint required')
   name=host.split('.',1)[0];service=site.get('service',name)
   need(service['metadata']['namespace']==NS and not service['metadata'].get('deletionTimestamp') and service['spec']['type']=='ClusterIP' and
    str(ipaddress.ip_address(service['spec']['clusterIP']))==service['spec']['clusterIP'],'actual ordinary source Service required')
   port=u.port or (6380 if u.scheme=='rediss' else 443)
   need(any(p['port']==port for p in service['spec']['ports']),'source endpoint port absent from actual Service')
   addresses=service['spec'].get('clusterIPs') or [service['spec']['clusterIP']]
   hosts.append({'Source':label,'Host':host,'Addresses':addresses})
   services.append({'Name':name,'UID':service['metadata']['uid'],'Addresses':addresses,'Port':port})
  self.hosts=hosts
  save(records/'source-dns.inputs.json',{'Version':'p2-process-cluster-dns-inputs.v1','PodUID':pod['metadata']['uid'],
   **checked,'Services':services,'ResolverSHA256':sha(raw),'HostResolverSHA256':sha(self.before),'HostResolverMutated':False})
 def check_host(self):
  st=self.host.stat()
  need(self.host.read_bytes()==self.before and (st.st_dev,st.st_ino)==self.identity,'host resolver drift during source command; retain original records')
 def run(self,argv,**kwargs):
  self.check_host()
  try:return subprocess.run(command(self.resolver,argv),**kwargs)
  finally:self.check_host()
 def probe(self):
  script='import json,socket,sys; rows=json.loads(sys.argv[1]); result=[]\nfor row in rows:\n actual=sorted({x[4][0] for x in socket.getaddrinfo(row["Host"],None,type=socket.SOCK_STREAM)}); assert set(actual)==set(row["Addresses"]); result.append(dict(row,Actual=actual))\nprint(json.dumps(result,sort_keys=True))'
  p=self.run(['python3','-B','-c',script,json.dumps(self.hosts)],capture_output=True,timeout=45)
  self.save(self.records/'source-dns-probe.stdout.private',p.stdout)
  self.save(self.records/'source-dns-probe.stderr.private',p.stderr)
  if p.returncode:
   error=p.stderr.decode(errors='replace').lower()
   print('P2_SOURCE_PROCESS_DNS_DIAGNOSTIC',json.dumps({'ExitCode':p.returncode,**{k:k in error for k in
    ['operation not permitted','permission denied','not found','name or service not known','temporary failure','assertionerror','not a directory']}}),flush=True)
  need(p.returncode==0,'isolated actual cluster DNS probe unconfirmed; no native owner sent')
  value=json.loads(p.stdout);self.save(self.records/'source-dns-probe.json',value)
  print('P2_SOURCE_PROCESS_DNS_READY',json.dumps(value),flush=True)
