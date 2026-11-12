#!/usr/bin/env python3
"""Add GET for one observed source PVC's PV to the existing reader role."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import ssl
import urllib.request

ROOT = Path('/root/sbk/p2-cert-renewal.1KyqMtsd')
PV = 'pvc-cd9cbe86-f701-4869-b9ed-0adae5baa427'
NS = 'clawmanager-sbk-validation-system'
ROLE = 'sbk-p2-source-read'


def need(ok, why):
    if not ok: raise ValueError(why)


def expanded_rules(rules):
    out = copy.deepcopy(rules)
    matches = [r for r in out if r.get('resources') == ['persistentvolumes']]
    need(len(matches) == 1, 'one existing PV rule required')
    rule = matches[0]
    need(set(rule) == {'apiGroups','resources','verbs','resourceNames'} and rule['apiGroups'] == [''] and
         rule['verbs'] == ['get'] and rule['resourceNames'] and
         '*' not in rule['resourceNames'] and len(set(rule['resourceNames'])) == len(rule['resourceNames']),
         'existing name-bounded GET rule required')
    rule['resourceNames'] = sorted(set(rule['resourceNames']) | {PV})
    return out


def main():
    os.umask(0o077); need(os.name == 'posix', 'Linux operator required')
    spec = importlib.util.spec_from_file_location('assembly', Path(__file__).with_name('assemble-p2-installation-candidate.py'))
    A = importlib.util.module_from_spec(spec); spec.loader.exec_module(A)
    r = ROOT/'source-pv-read-repair'
    r.mkdir(mode=0o700, exist_ok=True)
    need(r.resolve(strict=True) == r and r.stat().st_mode & 0o077 == 0, 'private journal required')
    need(not (r/'patch.sent.private.json').exists(), 'patch already sent; inspect retained outcome')
    kube = ['kubectl', '--kubeconfig', '/root/sbk-validation-tls-inspect.7LVU7vpE/operator.kubeconfig.yaml', '--request-timeout=20s']
    def call(args, body=None):
        p = subprocess.run(kube+args, input=body, capture_output=True, timeout=35)
        need(p.returncode == 0, 'operator API operation refused')
        return json.loads(p.stdout)
    def get(kind, name, ns=None):
        return call((['-n',ns] if ns else [])+['get',kind,name,'-o','json'])
    api = A.obj({'File':str(ROOT/'source-preparation-renew8h/source-api-fragment.json'),
        'SHA256':'d67e11479f50e2958cb99fe52fdc8596199d3a399f34a48721dd367db871d78c'})
    account = api['service_account']; uid = api['service_account_uid']
    need(get('namespace',NS)['metadata']['uid'] == '0d1aebbb-fdd6-4b14-b9c5-0da456f8e65f', 'source namespace replaced')
    need(get('serviceaccount',account,NS)['metadata']['uid'] == uid == api['connection']['Account'], 'source account replaced')
    pv = get('pv',PV); ref = pv['spec'].get('claimRef',{})
    need(ref.get('namespace') == NS and ref.get('uid') and ref.get('name') and
         not pv['metadata'].get('deletionTimestamp') and pv['metadata'].get('uid'), 'PV must belong to original source namespace')
    pvc = get('pvc',ref['name'],NS)
    need(pvc['metadata']['uid'] == ref['uid'] and pvc['spec'].get('volumeName') == PV and
         pvc.get('status',{}).get('phase') == 'Bound' and not pvc['metadata'].get('deletionTimestamp'), 'live bidirectional PVC/PV binding required')
    role = get('clusterrole',ROLE); binding = get('clusterrolebinding',ROLE)
    need(not role['metadata'].get('deletionTimestamp') and not role.get('aggregationRule') and
         not binding['metadata'].get('deletionTimestamp') and
         binding['roleRef'] == {'apiGroup':'rbac.authorization.k8s.io','kind':'ClusterRole','name':ROLE} and
         binding['subjects'] == [{'kind':'ServiceAccount','name':account,'namespace':NS}], 'original dedicated reader role binding changed')
    expected = expanded_rules(role['rules'])
    A.retain(r/'before.private.json', {'Role':role,'Binding':binding,'PV':pv,'PVC':pvc})
    patch = [{'op':'test','path':'/metadata/uid','value':role['metadata']['uid']},
             {'op':'test','path':'/metadata/resourceVersion','value':role['metadata']['resourceVersion']},
             {'op':'test','path':'/rules','value':role['rules']},
             {'op':'replace','path':'/rules','value':expected}]
    if expected != role['rules']:
        patch_pin = A.retain(r/'patch.private.json',patch)
        A.retain(r/'patch.sent.private.json', {'Patch':patch_pin,'PV':PV,'AccountUID':uid})
        result = call(['patch','clusterrole',ROLE,'--type=json','--patch-file',patch_pin['File'],'-o','json'])
        A.retain(r/'patch.receipt.private.json',result)
    after = get('clusterrole',ROLE)
    need(after['metadata']['uid'] == role['metadata']['uid'] and after['rules'] == expected and
         get('clusterrolebinding',ROLE) == binding, 'RBAC readback differs')
    c = api['connection']
    context = ssl.create_default_context(cadata=A.read(c['CA']).decode())
    token = A.read(c['Credential']).decode().strip()
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self,*args): return None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=context),NoRedirect())
    request = urllib.request.Request(c['Endpoint'].rstrip('/')+'/api/v1/persistentvolumes/'+PV,
        headers={'Authorization':'Bearer '+token})
    with opener.open(request,timeout=15) as response: observed = json.load(response)
    need(observed['metadata']['uid'] == pv['metadata']['uid'] and observed['spec']['claimRef'] == ref and
         not observed['metadata'].get('deletionTimestamp'), 'source reader PV readback mismatch')
    done = {'Version':'p2-source-pv-read-repaired.v1','PV':PV,'PVUID':pv['metadata']['uid'],
        'PVC':ref['name'],'PVCUID':ref['uid'],'RoleUID':after['metadata']['uid'],'AccountUID':uid,
        'SourceReadVerified':True,'AddedVerb':'get','GrantsIssued':False,'BackupReady':False}
    A.retain(r/'completed.json',done)
    print('P2_SOURCE_PV_READ_REPAIRED_NO_HOLD',json.dumps(done),flush=True)


if __name__ == '__main__':
    try: main()
    except Exception as e:
        raise SystemExit('P2_SOURCE_PV_READ_UNCONFIRMED '+(str(e) if type(e) is ValueError else type(e).__name__))
