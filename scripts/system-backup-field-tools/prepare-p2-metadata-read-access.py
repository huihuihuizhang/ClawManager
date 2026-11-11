#!/usr/bin/env python3
"""Render only this installation's missing Longhorn read bindings and actors.

No API calls/apply. Existing bindings stay intact. Fresh namespace and SA UID
guards must pass at the future execution boundary before any create is sent.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path

spec=importlib.util.spec_from_file_location('p2_assembly',Path(__file__).with_name('assemble-p2-installation-candidate.py'))
A=importlib.util.module_from_spec(spec);spec.loader.exec_module(A)


def render(plan,api,provider):
    if 'items' in provider:
        selected=[x for x in provider['items'] if x.get('kind')=='Namespace' and x['metadata']['name']=='longhorn-system']
        A.need(len(selected)==1,'one actual provider Namespace required')
        provider=selected[0]
    A.need(plan['Target']['Namespace']==A.NS and provider['kind']=='Namespace' and
           provider['metadata']['name']=='longhorn-system' and provider['metadata']['uid'] and
           api['connection']['Account']==api['service_account_uid'] and api['service_account']!='default',
           'same selected namespaces and dedicated source identity required')
    name='sbk-d4f51b83b57e-p2-longhorn-read'
    role={'apiVersion':'rbac.authorization.k8s.io/v1','kind':'Role','metadata':{'name':name,'namespace':'longhorn-system'},
          'rules':[{'apiGroups':[''],'resources':['pods','services'],'verbs':['get','list']}]}
    binding={'apiVersion':role['apiVersion'],'kind':'RoleBinding','metadata':dict(role['metadata']),
             'subjects':[{'kind':'ServiceAccount','name':api['service_account'],'namespace':A.NS}],
             'roleRef':{'apiGroup':'rbac.authorization.k8s.io','kind':'Role','name':name}}
    actors=[{'apiVersion':'v1','kind':'ServiceAccount','metadata':{'name':'sbk-d4f51b83b57e-'+suffix,'namespace':A.NS},'automountServiceAccountToken':False}
            for suffix in ['resources','secrets']]
    guards={'Version':'p2-source-metadata-access-guards.v1','Namespace':A.NS,'NamespaceUID':plan['Target']['NamespaceUID'],
            'SourceAccount':api['service_account'],'SourceAccountUID':api['service_account_uid'],
            'ProviderNamespace':'longhorn-system','ProviderNamespaceUID':provider['metadata']['uid'],
            'ExistingBindingsPreserved':True,'Applied':False,'BackupReady':False}
    return role,binding,actors,guards


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for key in ['plan','source-api','provider-namespace']:
        p.add_argument('--'+key+'-file',required=True);p.add_argument('--'+key+'-sha256',required=True)
    p.add_argument('--output-directory',type=Path,required=True)
    args=p.parse_args();os.umask(0o077);d=args.output_directory
    A.need(d.is_absolute() and d.resolve(strict=True)==d and d.is_dir() and
           (os.name!='posix' or d.stat().st_mode & 0o077==0),'private output directory required')
    values=[A.obj({'File':getattr(args,key+'_file'),'SHA256':getattr(args,key+'_sha256')}) for key in ['plan','source_api','provider_namespace']]
    role,binding,actors,guards=render(*values)
    outputs={name:A.retain(d/name,value) for name,value in [('longhorn-read.role.json',role),('longhorn-read.binding.json',binding),
        ('resources.sa.json',actors[0]),('secrets.sa.json',actors[1]),('access-guards.json',guards)]}
    print(json.dumps({'Outputs':outputs,'Applied':False,'BackupReady':False}))


if __name__=='__main__':
    try:main()
    except (ValueError,OSError,KeyError,TypeError) as error:
        raise SystemExit('P2_METADATA_ACCESS_UNCONFIRMED '+(str(error) if type(error) is ValueError else type(error).__name__))
