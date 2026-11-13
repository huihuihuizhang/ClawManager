#!/usr/bin/env python3
"""Prepare native successor node bundles, or apply one pinned rotation payload."""
import argparse
import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import subprocess

ROOT = Path('/root/sbk/p2-cert-renewal.1KyqMtsd')
NEW_CA = '7e7fee88fc2ff7fb10822914c466248bf2b555a0f9ce1d37e06bd50c9c1afecc'


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name+'.py'))
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--payload-file'); p.add_argument('--payload-sha256')
    p.add_argument('--records-directory', type=Path)
    args = p.parse_args(); os.umask(0o077)
    A = load('assemble-p2-installation-candidate')
    N = load('rotate-p2-node-observer-certificates')
    N.NEW_CA = NEW_CA
    N.need(os.name == 'posix', 'Linux operator required')
    if args.payload_file:
        N.need(args.payload_sha256 and args.records_directory, 'payload pin and private records required')
        pin = {'File':args.payload_file,'SHA256':args.payload_sha256}
        files = N.tar_files(N.pinned(pin,1<<20),262144)
        plan = json.loads(files['rotation-plan.json']); node = plan['Node']
        N.need(node in N.NODES and plan['NewCA'] == NEW_CA, 'this renewal payload required')
        N.OLD_UNITS[node] = {k:plan['Files'][N.unit_name(k)]['OldSHA256'] for k in N.BINARIES}
        r = args.records_directory; r.mkdir(mode=0o700,exist_ok=True)
        N.need(r.resolve() == r and r.stat().st_uid == 0 and r.stat().st_mode & 0o077 == 0, 'private node journal required')
        N.apply(pin,r); return
    r = ROOT/'renewal-20261113/observer-host'; r.mkdir(mode=0o700,exist_ok=True)
    N.need(r.resolve() == r and r.stat().st_mode & 0o077 == 0, 'private journal required')
    kube = ['kubectl','--kubeconfig',N.KUBE,'--request-timeout=20s','-n',N.NS]
    def call(args):
        result = subprocess.run(kube+args,capture_output=True,timeout=40)
        N.need(result.returncode == 0,'controller preflight refused'); return result.stdout
    dep = json.loads(call(['get','deployment',N.CONTROLLER,'-o','json']))
    N.need(dep['metadata']['uid'] == 'e4e27f27-8f02-40ab-8c62-09f2ffa3fafa','controller replaced')
    c = next(c for c in dep['spec']['template']['spec']['containers'] if c['name']=='controller')
    N.need({e['name']:e.get('value') for e in c['env']}.get('SYSTEM_BACKUP_ENABLED') == 'false','inactive controller required')
    call(['exec','deployment/'+N.CONTROLLER,'-c','controller','--','sh','-ec','test ! -e /run/system-backup/runtime/controller.env.ready'])
    previous = A.obj({'File':str(ROOT/'observer-host-current-agent/host.definition.json'),
        'SHA256':'58df8c7b82bbf994f6a80a1f0b22739dc134c49b50eec68e590f5791ba02c32d'})
    old_pki = A.obj(previous['PKIReceipt']); N.OLD_CA = old_pki['CA']['SHA256']
    N.need(N.OLD_CA == '7fa08bdb7a03ad3d81722aa56b845b4aba2227d16c5463cc3d70f29d7f5f37bc','previous CA differs')
    old_host = A.obj({'File':str(ROOT/'observer-host-current-agent/host-materials.receipt.private.json'),
        'SHA256':'5087d37bbc1bec1732223977a576db422f6373951a8f48876cf97d1a170e5f75'})
    receipt_pin = A.canonical_observer_receipt_data({'File':str(ROOT/'renewal-20261113/observer/receipt.private.json'),
        'SHA256':'c0d69a9d9d1254a40993fb5516ed936325f265a74b0dde4b3823ea52fdd010f5'},r)
    new_pki = A.obj(receipt_pin)
    definition_file = ROOT/'renewal-20261113/observer/definition.private.json'
    definition_pin = {'File':str(definition_file),'SHA256':A.sha(definition_file.read_bytes())}
    N.need(new_pki['DefinitionSHA256'] == definition_pin['SHA256'] and new_pki['CA']['SHA256'] == NEW_CA,'new PKI binding differs')
    definition = A.base_observer_definition({'File':str(ROOT/'observer-host-current-agent/host.definition.json'),
        'SHA256':'58df8c7b82bbf994f6a80a1f0b22739dc134c49b50eec68e590f5791ba02c32d'},definition_pin,receipt_pin)
    dp = A.retain(r/'host.definition.json',N.encode(definition))
    result_file = r/'host-materials.receipt.private.json'
    if not result_file.exists():
        N.need(not (r/'host.sent.private.json').exists(),'host author already sent; inspect original outcome')
        intent = A.obj({'File':str(ROOT/'observer-host-current-agent/host-materials.sent.private.json'),
            'SHA256':'0e451c056d037bd63fd17f33989e79af7e1486191bd562ea90feae8bfe9b03e2'})
        argv = list(intent['Argv']); binary = Path(argv[0])
        sums = [line.split(maxsplit=1) for line in (binary.parent/'SHA256SUMS').read_text().splitlines()]
        N.need(any(n.strip().lstrip('*')==binary.name and d==A.sha(binary.read_bytes()) for d,n in sums),'native executable checksum differs')
        output = r/'materials'; output.mkdir(mode=0o700,exist_ok=True)
        N.need(not list(output.iterdir()),'empty successor output required')
        for flag,value in [('--definition-file',dp['File']),('--definition-sha256',dp['SHA256']),('--output-directory',str(output))]:
            argv[argv.index(flag)+1] = value
        A.retain(r/'host.sent.private.json',{'Argv':argv})
        with (r/'stdout.private').open('xb') as stdout,(r/'stderr.private').open('xb') as stderr:
            result = subprocess.run(argv,stdout=stdout,stderr=stderr,timeout=180)
        A.retain(r/'exit.json',{'ExitCode':result.returncode})
        N.need(result.returncode==0,'native host author refused; retain partial outputs')
        A.retain(result_file,(r/'stdout.private').read_bytes())
    host = json.loads(result_file.read_bytes())
    N.need(host['Version']=='original-observer-host-materials.v1' and host['PKIReceiptSHA256']==receipt_pin['SHA256'],'native host receipt differs')
    now = dt.datetime.now(dt.timezone.utc)
    N.need(dt.datetime.fromisoformat(new_pki['NotAfter'].replace('Z','+00:00'))>now+dt.timedelta(hours=1),'PKI window too short')
    window = r/'window.json'
    if not window.exists(): A.retain(window,{'Until':(now+dt.timedelta(hours=2)).isoformat()})
    until = json.loads(window.read_bytes())['Until']
    N.need(now<dt.datetime.fromisoformat(until),'payload window expired; preserve records')
    for node in N.NODES:
        old_files = N.tar_files(A.read(old_host['NodeBundles'][node],64<<20),64<<20)
        N.OLD_UNITS[node] = {kind:A.sha(old_files[N.unit_name(kind)]) for kind in N.BINARIES}
        new_files = N.tar_files(A.read(host['NodeBundles'][node],64<<20),64<<20)
        raw = N.payload(node,new_files,old_pki,new_pki,until)
        pin = A.retain(r/(node+'.renewal.private.tar'),raw)
        print('NOV13_OBSERVER_PAYLOAD_READY',node,json.dumps(pin),flush=True)
    print('NOV13_OBSERVER_PREPARED_NOT_LOADED',until,flush=True)


if __name__=='__main__':
    try: main()
    except Exception as e:
        raise SystemExit('NOV13_OBSERVER_UNCONFIRMED '+(str(e) if type(e) is ValueError else type(e).__name__))
