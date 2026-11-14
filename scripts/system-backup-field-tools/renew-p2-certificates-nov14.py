#!/usr/bin/env python3
"""November 14 exact successor of the observed expired observer/runtime credentials."""
import argparse
import copy
import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import subprocess

ROOT=Path('/root/sbk/p2-cert-renewal.1KyqMtsd')
OLD=ROOT/'renewal-20261113'
# The first attempt was refused before producing files while MySQL was full.
# Keep its journal intact; the post-expansion attempt has a separate directory.
NEW=ROOT/'renewal-20261114-after-mysql-expansion'
PINS={
 'observer/sent.private.json':'9f48ddd490ced5795ae958f09f2d6849ec41d0038e42cb0bb7882a0d056dcaff',
 'observer/definition.private.json':'47de353412f9811338a87dfefffae3e328557269e41d486a11fd71b6b385733b',
 'observer/receipt.private.json':'c0d69a9d9d1254a40993fb5516ed936325f265a74b0dde4b3823ea52fdd010f5',
 'observer-host/host.definition.json':'3bf6ccf20f3eac8599ecf6c7364c5f29ce73cccc5b614d00057e08188a2a7377',
 'observer-host/host-materials.receipt.private.json':'70744d0bc25bd34a142b95a9718480f2c20d6326137940c061efd9dc0691ff8f',
 'observer-host/host.sent.private.json':'372c8453eddd7f9b4c62da98fed10367fa082e095a3ef93346b98664a8accb7d',
 'runtime-unique/issuance.sent.private.json':'fa8520e0581af65f3b1ff09e90436578f944e49153af47d804e0aa752ec626c8',
 'runtime-unique/definition.private.json':'117c384e5bf38a2bd956b608ff9d4544fc174b10b47402ea4ccdc8bf65ec1eaa',
 'runtime-unique/runtime-agent.receipt.private.json':'1d61b1d11b3427fd46d9d2eab3bd04f19daf74ae3a674a9f2275269c1810f149'}

def load(name):
    s=importlib.util.spec_from_file_location(name,Path(__file__).with_name(name+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m

def replaced_argv(A,old,definition,out):
    argv=list(old)
    for flag,value in [('--definition-file',definition['File']),('--definition-sha256',definition['SHA256']),('--output-directory',str(out))]:
        A.need(argv.count(flag)==1,'ambiguous original issuance flag');argv[argv.index(flag)+1]=value
    return argv

def original(A,name):return A.obj({'File':str(OLD/name),'SHA256':PINS[name]})

def issue(A,R,label,intent,definition,receipt_name='receipt.private.json'):
    directory=NEW/label;directory.mkdir(mode=0o700,parents=True,exist_ok=True)
    pin=A.retain(directory/'definition.private.json',definition)
    out=directory/'materials';argv=replaced_argv(A,intent['Argv'],pin,out)
    binary=Path(argv[0]);sums=[line.split(maxsplit=1) for line in (binary.parent/'SHA256SUMS').read_text().splitlines()]
    A.need(any(name.strip().lstrip('*')==binary.name and digest==A.sha(binary.read_bytes()) for digest,name in sums),'original native binary checksum differs')
    if not out.exists():out.mkdir(mode=0o700)
    else:A.need((directory/'native.receipt.private.json').exists() or (not (directory/'native.sent.private.json').exists() and not list(out.iterdir())),'unknown native issuance output; reconcile')
    class Native:
        def run(self,argv,**kw):return subprocess.run(argv,**kw)
    value=R.once(A,Native(),directory,'native',argv)
    return A.retain(directory/receipt_name,(directory/'native.receipt.private.json').read_bytes()),value

def prepare(A):
    R=load('resume-p2-recovered-source');L=load('load-p2-formal-vault');N=load('rotate-p2-node-observer-certificates')
    NEW.mkdir(mode=0o700,exist_ok=True);site=L.Site(NEW,A);app=R.verify_app(A,site)
    dep=site.get('deployment',A.CONTROLLER)
    A.need(dep['metadata']['uid']==A.CONTROLLER_UID,'controller replaced')
    c=next(c for c in dep['spec']['template']['spec']['containers'] if c['name']=='controller')
    A.need({e['name']:e.get('value') for e in c['env']}.get('SYSTEM_BACKUP_ENABLED')=='false','inactive controller required')
    site.call(['exec','deployment/'+A.CONTROLLER,'-c','controller','--','sh','-ec','test ! -e /run/system-backup/runtime/controller.env.ready'])
    old_observer=original(A,'observer/receipt.private.json');old_runtime=original(A,'runtime-unique/runtime-agent.receipt.private.json')
    A.need(app['spec']['template']['spec']['containers'][0]['image']==R.IMAGE,'application image changed')
    observer_definition=original(A,'observer/definition.private.json')
    A.need(observer_definition['validity_seconds']==86400,'original one-day PKI scope required')
    observer_pin,observer=issue(A,R,'observer',original(A,'observer/sent.private.json'),observer_definition)
    A.need(observer['Version']=='original-observer-pki-materials.v1','native observer receipt required')
    hostdir=NEW/'observer-host';hostdir.mkdir(mode=0o700,exist_ok=True)
    projected=A.canonical_observer_receipt_data(observer_pin,hostdir)
    definition=A.base_observer_definition({'File':str(OLD/'observer-host/host.definition.json'),'SHA256':PINS['observer-host/host.definition.json']},
        {'File':str(NEW/'observer/definition.private.json'),'SHA256':A.sha((NEW/'observer/definition.private.json').read_bytes())},projected)
    hostpin,host=issue(A,R,'observer-host',original(A,'observer-host/host.sent.private.json'),definition,'host-materials.receipt.private.json')
    A.need(host['Version']=='original-observer-host-materials.v1' and host['PKIReceiptSHA256']==projected['SHA256'],'native host binding differs')
    oldhost=original(A,'observer-host/host-materials.receipt.private.json');N.OLD_CA=old_observer['CA']['SHA256'];N.NEW_CA=observer['CA']['SHA256']
    window=hostdir/'window.json'
    if not window.exists():A.retain(window,{'Until':(dt.datetime.now(dt.timezone.utc)+dt.timedelta(hours=2)).isoformat()})
    until=A.decode(window.read_bytes())['Until'];payloads={}
    for node in N.NODES:
        old_files=N.tar_files(A.read(oldhost['NodeBundles'][node],256<<20),64<<20)
        new_files=N.tar_files(A.read(host['NodeBundles'][node],256<<20),64<<20)
        N.OLD_UNITS[node]={kind:A.sha(old_files[N.unit_name(kind)]) for kind in N.BINARIES}
        payloads[node]=A.retain(hostdir/(node+'.renewal.private.tar'),N.payload(node,new_files,old_observer,observer,until))
    runtime_definition=original(A,'runtime-unique/definition.private.json');runtime_definition['SecretPrefix']='sbk-renew-20261114'
    runtime_pin,runtime=issue(A,R,'runtime-unique',original(A,'runtime-unique/issuance.sent.private.json'),runtime_definition,'runtime-agent.receipt.private.json')
    A.need(runtime['Version']=='original-shared-agent-tls-materials.v1' and not ({t['SecretName'] for t in runtime['Targets']} & {t['SecretName'] for t in old_runtime['Targets']}),'new native runtime identity required')
    done={'Version':'p2-nov14-credentials-prepared.v1','Observer':observer_pin,'Runtime':runtime_pin,'Host':hostpin,'Payloads':payloads,'Until':until,'Loaded':False,'BackupReady':False}
    pin=A.retain(NEW/'prepared.json',done);print('P2_NOV14_CREDENTIALS_PREPARED_NOT_LOADED',json.dumps(pin),flush=True)

def apply_observer(A,args):
    prepared=A.obj({'File':args.prepared_file,'SHA256':args.prepared_sha256});A.need(prepared['Version']=='p2-nov14-credentials-prepared.v1','this renewal required')
    N=load('rotate-p2-node-observer-certificates');pin=prepared['Payloads'][args.node]
    files=N.tar_files(A.read(pin,1<<20),262144);plan=A.decode(files['rotation-plan.json'])
    A.need(plan['Node']==args.node,'node payload differs');N.NEW_CA=plan['NewCA']
    N.OLD_UNITS[args.node]={k:plan['Files'][N.unit_name(k)]['OldSHA256'] for k in N.BINARIES}
    records=NEW/('node-'+args.node);records.mkdir(mode=0o700,parents=True,exist_ok=True)
    A.need(not (records/'completed.json').exists(),'observer already rotated; use readback')
    N.apply(pin,records)

def rotate_runtime(A,args):
    prepared=A.obj({'File':args.prepared_file,'SHA256':args.prepared_sha256});runtime=A.obj(prepared['Runtime']);old=original(A,'runtime-unique/runtime-agent.receipt.private.json')
    R=load('rotate-p2-runtime-certificates');R.OLD_RECEIPT=OLD/'runtime-unique/runtime-agent.receipt.private.json';R.OLD_CA=old['CA']['SHA256'];R.NEW_CA=runtime['CA']['SHA256']
    R.APP_IMAGE=load('resume-p2-recovered-source').IMAGE
    R.main(NEW/'runtime-unique')

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=['prepare','apply-observer','rotate-runtime']);p.add_argument('--node',choices=['k8s-master','node1']);p.add_argument('--prepared-file');p.add_argument('--prepared-sha256');args=p.parse_args()
    os.umask(0o077);A=load('assemble-p2-installation-candidate');A.need(os.name=='posix','Linux operator required')
    if args.action=='prepare':prepare(A)
    else:
        A.need(args.prepared_file and args.prepared_sha256,'prepared material pin required')
        if args.action=='apply-observer':A.need(args.node,'node required');apply_observer(A,args)
        else:rotate_runtime(A,args)
if __name__=='__main__':
    try:main()
    except Exception as e:raise SystemExit('P2_NOV14_CREDENTIAL_RENEWAL_UNCONFIRMED '+(str(e) if isinstance(e,ValueError) else type(e).__name__))
