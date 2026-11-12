#!/usr/bin/env python3
"""Reuse the existing persistent Vault installer for this one installation.

Default is offline review. A tag, offline snapshot or local report never proves
an installed/unsealed provider. Root and unseal DATA stay in the original private
owner directory. No generic installation/migration path is added.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import sys

spec=importlib.util.spec_from_file_location('p2_data',Path(__file__).with_name('assemble-p2-installation-candidate.py'))
A=importlib.util.module_from_spec(spec); spec.loader.exec_module(A)
NODES={'k8s-master':'bc1fb478-0388-4f53-96b4-8d186301f6af','node1':'fe1cc275-6fa1-484e-8bf6-7b21193daffd'}
PLAN_SHA='a0aa44b5a12a453c352a402e73c4f4d42a675b2430d2cb69972a29df1f859752'
INSTALLER_SHA='d2207885e0c91c81d47eec69b3dbd9d601a65739db1d2965520c481e64595514'


def prepare(inputs):
    A.need(inputs['Version']=='p2-existing-vault-owner-inputs.v1','scoped Vault input required')
    A.need(inputs['Plan']['SHA256']==PLAN_SHA and inputs['Installer']['SHA256']==INSTALLER_SHA and
           Path(inputs['Installer']['File']).name=='system-backup-d-transit-install.py', 'existing native plan and reviewed persistent installer required')
    plan=A.obj(inputs['Plan']); target=plan['Target']
    A.need(target['Namespace']==A.NS and target['NamespaceUID']==inputs['NamespaceUID'] and
           inputs['Nodes']==NODES,'same installation and selected Nodes required')
    A.read(inputs['Kubeconfig']); A.read(inputs['Installer'],1<<20)
    image=A.obj(inputs['ImageInput'])
    A.need(image.get('schema_version')=='d-transit-image-input.v1' and
           re.fullmatch(r'10\.130\.14\.23:5000/clawmanager-backup-vault@sha256:[a-f0-9]{64}',image.get('image','')) and
           image.get('entrypoint')=='/bin/vault' and image.get('version')=='2.2.1' and
           isinstance(image.get('image_id_digests'),list) and image['image_id_digests'] and
           all(re.fullmatch(r'sha256:[a-f0-9]{64}',x) for x in image['image_id_digests']),
           'verified immutable image DATA required; registry tag is insufficient')
    operation=inputs['Operation']
    A.need(operation in ['install','resume-install','unseal','smoke','persistence'],'existing owner operations only')
    state=Path(inputs['StateDirectory'])
    A.need(state.is_absolute() and state.parent.resolve(strict=True)==state.parent and not state.is_symlink(),'private original Vault owner path required')
    if state.exists():
        old=A.decode((state/'state.json').read_bytes())
        A.need(operation!='install' and old['namespace']==A.NS and old['namespace_uid']==target['NamespaceUID'] and
               old['node_uid']==NODES[old['node']] and old['image_input']==image,'reuse exact existing Vault owner; never initialize twice')
    else:
        A.need(operation=='install','existing owner state required for resume')
    argv=[operation,'--state-dir',str(state)]
    if operation=='install':
        A.need(inputs['Node'] in NODES and re.fullmatch(r'[a-z0-9][a-z0-9.-]{0,252}',inputs['StorageClass']), 'selected persistent storage required')
        argv += ['--storage-class',inputs['StorageClass'],'--node',inputs['Node'],'--image-input',inputs['ImageInput']['File'],'--image-input-sha256',inputs['ImageInput']['SHA256']]
    return plan,argv


def run_original(original):
    A.need(original.main()==0,'original persistent Vault owner refused; retain its original state and report')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--inputs-file',required=True); p.add_argument('--inputs-sha256',required=True)
    p.add_argument('--execute-existing-installer',action='store_true')
    args=p.parse_args(); os.umask(0o077)
    inputs=A.obj({'File':args.inputs_file,'SHA256':args.inputs_sha256}); plan,argv=prepare(inputs)
    if not args.execute_existing_installer:
        print(json.dumps({'Version':'p2-vault-owner-command-review.v1','Argv':argv,'InstalledVerified':False,'BackupReady':False})); return
    A.need(os.name=='posix','operator Linux execution required')
    path=Path(inputs['Installer']['File'])
    spec=importlib.util.spec_from_file_location('original_persistent_vault',path)
    original=importlib.util.module_from_spec(spec); spec.loader.exec_module(original)
    # The original installer checks live namespace/Node UIDs, PVC ownership,
    # running imageID, TLS version and actual Vault version before success.
    # Its Popen port-forward also inherits this pinned kubeconfig.
    original.NAMESPACE=A.NS; original.NAMESPACE_UID=plan['Target']['NamespaceUID']; original.NODES=dict(NODES)
    previous=os.environ.get('KUBECONFIG'); old_argv=sys.argv
    os.environ['KUBECONFIG']=inputs['Kubeconfig']['File']; sys.argv=[str(path),*argv]
    try:
        original.guard()
        if inputs['Operation']=='install':
            existing=json.loads(original.kube('-n',A.NS,'get','deployments','-o','json'))['items']
            A.need(not any(c.get('name')=='vault' or 'clawmanager-backup-vault' in c.get('image','')
                           for d in existing for c in d['spec']['template']['spec'].get('containers',[])),
                   'existing Vault deployment requires its original private owner state; do not install a second provider')
        run_original(original)
    finally:
        sys.argv=old_argv
        if previous is None: os.environ.pop('KUBECONFIG',None)
        else: os.environ['KUBECONFIG']=previous


if __name__=='__main__':
    try: main()
    except (ValueError,OSError,KeyError,TypeError) as error:
        raise SystemExit('P2_VAULT_OWNER_UNCONFIRMED '+(str(error) if type(error) is ValueError else type(error).__name__))
