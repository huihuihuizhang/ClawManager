#!/usr/bin/env python3
"""Produce this team's native source facts with the actual provider transport."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
from urllib.parse import urlsplit

def load(name):
    s=importlib.util.spec_from_file_location(name,Path(__file__).with_name(name+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m

def run(attempt):
    os.umask(0o077);C=load('continue-p2-nov14')
    A,L,D,R,F,V=[load(n) for n in ('assemble-p2-installation-candidate','load-p2-formal-vault','p2-source-dns','resume-p2-recovered-source','p2-vault-local-forward','p2-source-provider-access')]
    C.select_attempt(A,attempt,stage_attachment=False)
    complete=A.decode((C.MOUNT_JOURNAL/'completed.json').read_bytes());selected=C.live_source(A,complete);core=A.obj(complete['Deployment'])
    A.need(len(core['provider_dependencies'])==1,'exact formal Vault dependency required')
    dependency=core['provider_dependencies'][0]
    journal=C.ROOT/('source-facts-20261114-team-'+str(attempt));journal.mkdir(mode=0o700,exist_ok=True)
    site=L.Site(journal,A);pod=site.get('pod',selected['Controller']['Pod'])
    A.need(pod['metadata']['uid']==selected['Controller']['PodUID'] and not pod['metadata'].get('deletionTimestamp'),'source controller replaced')
    names=[v['secret']['secretName'] for v in pod['spec']['volumes'] if v['name']=='provider-dependency-input']
    A.need(len(names)==1,'one actual provider Secret required');secret=site.get('secret',names[0]);observer,_,_=V.inputs(A,dependency,secret)
    endpoints=[(v['Purpose'],v['Endpoint']) for v in selected['Connections'] if (urlsplit(v['Endpoint']).hostname or '').endswith('.'+A.NS+'.svc')]
    endpoints.append(('formal_vault',observer['Endpoint']))
    dns=D.SourceDNS(site,journal,pod,endpoints,A.retain);dns.probe()
    package=Path(__file__).resolve().parent;build=A.decode((package/'BUILD_RECEIPT.json').read_bytes());tool=package/'system-backup-source-registries'
    A.read({'File':str(tool),'SHA256':build['Binaries'][tool.name]['SHA256']},256<<20)
    old=A.decode((C.SOURCE_JOURNAL/'author.sent.private.json').read_bytes())['Argv'];common=old[2:old.index('--definition-file')]
    with V.access(A,F,site,dns,journal,pod,dependency,secret) as runner:
        value=R.once(A,runner,journal,'native',[str(tool),'produce-facts',*common,'--source-selection-file',complete['SourceSelection']['File'],'--source-selection-sha256',complete['SourceSelection']['SHA256']])
    A.need(value['Version']=='original-source-registry-facts-receipt.v1' and value['SelectionSHA256']==complete['SourceSelection']['SHA256'],'native facts receipt differs')
    print('P2_NATIVE_SOURCE_FACTS_PRODUCED',json.dumps(value),flush=True)
    return value

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source-attempt',required=True,type=int);args=p.parse_args()
    try:run(args.source_attempt)
    except Exception as e:raise SystemExit('P2_SOURCE_FACTS_UNCONFIRMED '+(str(e) if isinstance(e,ValueError) else type(e).__name__))
