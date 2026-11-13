#!/usr/bin/env python3
"""Repair exact cluster identity GET; inspect SQL workload without changing it."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import ssl
import subprocess
import urllib.request

ROOT=Path('/root/sbk/p2-cert-renewal.1KyqMtsd')
NS='clawmanager-sbk-validation-system'
ROLE='sbk-p2-source-read'

def need(ok,why):
    if not ok:raise ValueError(why)

def expanded_rules(rules):
    result=copy.deepcopy(rules)
    matches=[r for r in result if r.get('resources')==['namespaces']]
    need(len(matches)==1,'one namespace GET rule required')
    rule=matches[0]
    need(set(rule)=={'apiGroups','resources','verbs','resourceNames'} and rule['apiGroups']==[''] and
         rule['verbs']==['get'] and rule['resourceNames'] and '*' not in rule['resourceNames'],'bounded namespace GET required')
    rule['resourceNames']=sorted(set(rule['resourceNames'])|{'kube-system'})
    return result

def main():
    os.umask(0o077);need(os.name=='posix','Linux operator required')
    spec=importlib.util.spec_from_file_location('assembly',Path(__file__).with_name('assemble-p2-installation-candidate.py'))
    A=importlib.util.module_from_spec(spec);spec.loader.exec_module(A)
    selected=A.obj({'File':'/run/system-backup/runtime/p2-renew-1048e373bfe0/initial-source-20261113-runtime-scope-final-retry/source-selection.json',
        'SHA256':'a323dc03ada6b3ef8863ee4e0126f2ea7549fd8aecc9f182d7d8a49946db9565'})
    core=A.obj(selected['Deployment']);source=next(c for c in selected['Connections'] if c['Purpose']=='source_api')
    r=ROOT/'cluster-identity-read-repair';r.mkdir(mode=0o700,exist_ok=True)
    need(r.resolve()==r and r.stat().st_mode&0o077==0 and not (r/'patch.sent.private.json').exists(),'private unsent repair journal required')
    argv=json.loads((ROOT/'source-preparation-20261113-runtime-scope-final-retry/author.sent.private.json').read_bytes())['Argv']
    plan=A.obj({'File':argv[argv.index('--plan-file')+1],'SHA256':argv[argv.index('--plan-sha256')+1]})
    kube=['kubectl','--kubeconfig','/root/sbk-validation-tls-inspect.7LVU7vpE/operator.kubeconfig.yaml','--request-timeout=20s']
    def call(args):
        p=subprocess.run(kube+args,capture_output=True,timeout=35)
        need(p.returncode==0,'operator API refused; no private response printed')
        return json.loads(p.stdout)
    def get(kind,name,namespace=None):return call((['-n',namespace] if namespace else [])+['get',kind,name,'-o','json'])
    cluster=get('namespace','kube-system')
    need(cluster['metadata']['uid']==plan['Target']['ClusterID'] and not cluster['metadata'].get('deletionTimestamp'),'enrolled cluster identity mismatch')
    role=get('clusterrole',ROLE);binding=get('clusterrolebinding',ROLE)
    subjects=binding.get('subjects',[])
    need(len(subjects)==1 and subjects[0]['kind']=='ServiceAccount' and subjects[0]['namespace']==NS and
         binding['roleRef']=={'apiGroup':'rbac.authorization.k8s.io','kind':'ClusterRole','name':ROLE} and
         role['metadata']['uid']=='b9be39e6-ce48-4bb0-b7b8-5ba7627d9456' and not role.get('aggregationRule') and
         not role['metadata'].get('deletionTimestamp') and not binding['metadata'].get('deletionTimestamp'),'original dedicated source role required')
    account=get('serviceaccount',subjects[0]['name'],NS)
    need(account['metadata']['uid']==source['Account'] and not account['metadata'].get('deletionTimestamp'),'source account changed')
    rules=expanded_rules(role['rules'])
    A.retain(r/'before.private.json',{'Role':role,'Binding':binding,'Cluster':cluster})
    if rules!=role['rules']:
        patch=[{'op':'test','path':'/metadata/uid','value':role['metadata']['uid']},
               {'op':'test','path':'/metadata/resourceVersion','value':role['metadata']['resourceVersion']},
               {'op':'test','path':'/rules','value':role['rules']},{'op':'replace','path':'/rules','value':rules}]
        pin=A.retain(r/'patch.private.json',patch);A.retain(r/'patch.sent.private.json',{'Patch':pin})
        A.retain(r/'patch.receipt.private.json',call(['patch','clusterrole',ROLE,'--type=json','--patch-file',pin['File'],'-o','json']))
    after=get('clusterrole',ROLE)
    need(after['metadata']['uid']==role['metadata']['uid'] and after['rules']==rules and get('clusterrolebinding',ROLE)==binding,'role readback differs')
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self,*args):return None
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect(),urllib.request.HTTPSHandler(context=ssl.create_default_context(cadata=A.read(source['CA']).decode())))
    req=urllib.request.Request(source['Endpoint'].rstrip('/')+'/api/v1/namespaces/kube-system',headers={'Authorization':'Bearer '+A.read(source['Credential']).decode().strip()})
    with opener.open(req,timeout=15) as response:observed=json.load(response)
    need(observed['metadata']['uid']==plan['Target']['ClusterID'] and not observed['metadata'].get('deletionTimestamp'),'source cluster readback differs')
    A.retain(r/'completed.json',{'Version':'p2-cluster-identity-read-repaired.v1','NamespaceUID':observed['metadata']['uid'],'SourceReadVerified':True,'GrantsIssued':False,'BackupReady':False})
    print('P2_CLUSTER_IDENTITY_READ_REPAIRED_NO_HOLD',flush=True)
    mysql=get('deployment','mysql',NS);A.retain(r/'mysql-deployment.private.json',mysql)
    sql=[c for c in selected['Connections'] if c['Purpose'] in ('source_sql','control_sql')]
    print('SQL_ROLE_RELATION',json.dumps({'SameEndpoint':len({c['Endpoint'] for c in sql})==1,'SameServer':len({c['ServerUUID'] for c in sql})==1,'SameDatabase':len({c['Database'] for c in sql})==1,'ProviderCount':len(core.get('provider_dependencies',[]))}),flush=True)
    print('MYSQL_WORKLOAD',json.dumps({'UID':mysql['metadata']['uid'],'Replicas':mysql['spec'].get('replicas'),'Ready':mysql.get('status',{}).get('readyReplicas',0),
        'PVCs':[v['persistentVolumeClaim']['claimName'] for v in mysql['spec']['template']['spec'].get('volumes',[]) if 'persistentVolumeClaim' in v]}),flush=True)
    print('CONFIGURED_PLATFORM_WRITERS',json.dumps([v['name'] for v in core['platform_writers']]),flush=True)

if __name__=='__main__':
    try:main()
    except Exception as e:raise SystemExit('P2_CLUSTER_IDENTITY_READ_UNCONFIRMED '+(str(e) if type(e) is ValueError else type(e).__name__))
