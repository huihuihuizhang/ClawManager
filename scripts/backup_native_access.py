"""Replace only the two original task-fixture roles during native acceptance.

The host driver is the fixture installer, never the controller under test.
Original rules are restored before Go fixture cleanup. No credentials are read
or printed and no shared-cluster fallback exists.
"""
import hashlib
import json
import re
import subprocess


class NativeAccess:
    def __init__(self, kubectl):
        self.k = kubectl
        self.originals = []

    def run(self, args, payload=None, read=False):
        result = subprocess.run(self.k+args, input=None if payload is None else json.dumps(payload).encode(),
                                capture_output=True, timeout=45)
        if result.returncode:
            raise RuntimeError('native access fixture operation unavailable')
        return json.loads(result.stdout) if read else None

    def ack(self, path):
        if not re.fullmatch(r'/tmp/TestPublicCaptureNativeMySQLKubernetes[a-z-]+[0-9]+/[0-9]{3}/kubernetes-(installed|restored|recovery-only)', path):
            raise RuntimeError('native access acknowledgement path invalid')
        subprocess.run(self.k+['-n','cm-backup-m0m2-native','exec','-i','native-controller','--','/bin/sh','-c',
                             'umask 077; cat > "$1.next" && mv "$1.next" "$1"','sh',path], input=b'confirmed\n',
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=15)

    def install(self, request):
        if self.originals:
            raise RuntimeError('native access fixture already active')
        ns='cm-backup-m0m2-native'
        state=self.run(['get','namespace',ns,'-o','json'],read=True)
        if state['metadata'].get('labels',{}).get('codex-run')!='m0m2-20261028':
            raise RuntimeError('native namespace ownership mismatch')
        name='cm-public-capture-'+hashlib.sha256((ns+'/native-controller').encode()).hexdigest()[:12]
        objects=request['objects']
        if len(objects)!=4:
            raise RuntimeError('unexpected native access objects')
        for item in objects:
            if item.get('kind') not in ['Role','RoleBinding','ClusterRole','ClusterRoleBinding'] or item['metadata']['name']!=name:
                raise RuntimeError('unexpected native RBAC scope')
            if item['kind'] in ['Role','RoleBinding'] and item['metadata'].get('namespace')!=ns:
                raise RuntimeError('native role crossed namespace')
            if item['kind'].endswith('Binding') and item['subjects']!=[{'kind':'ServiceAccount','name':'native-controller','namespace':ns}]:
                raise RuntimeError('native binding crossed subject')
        for kind, original_name, namespaced in [('role','native-controller',True),('clusterrole','cm-backup-m0m2-native',False)]:
            args=['-n',ns] if namespaced else []
            original=self.run(args+['get',kind,original_name,'-o','json'],read=True)
            self.originals.append((args,kind,original_name,original))
        self.run(['apply','-f','-'],{'apiVersion':'v1','kind':'List','items':objects})
        for args,kind,original_name,original in self.originals:
            self.run(args+['patch',kind,original_name,'--type=merge','-p',json.dumps({'metadata':{'resourceVersion':original['metadata']['resourceVersion']},'rules':[]})])
        self.ack(request['ack_file'])

    def restore(self, request=None):
        for args,kind,name,original in self.originals:
            actual=self.run(args+['get',kind,name,'-o','json'],read=True)
            if actual['metadata']['uid']!=original['metadata']['uid']:
                raise RuntimeError('native original role identity changed')
            self.run(args+['patch',kind,name,'--type=merge','-p',json.dumps({'metadata':{'resourceVersion':actual['metadata']['resourceVersion']},'rules':original['rules']})])
        self.originals=[]
        if request is not None:
            self.ack(request['ack_file'])

    def recovery_only(self, request):
        if not self.originals:
            raise RuntimeError('minimum fixture role is not active')
        ns='cm-backup-m0m2-native'
        name='cm-public-capture-'+hashlib.sha256((ns+'/native-controller').encode()).hexdigest()[:12]
        role=self.run(['-n',ns,'get','role',name,'-o','json'],read=True)
        rules=[]
        for rule in role['rules']:
            rule['verbs']=[v for v in rule['verbs'] if v!='create']
            if rule['verbs']:
                rules.append(rule)
        self.run(['-n',ns,'patch','role',name,'--type=merge','-p',json.dumps({'metadata':{'resourceVersion':role['metadata']['resourceVersion']},'rules':rules})])
        result=subprocess.run(self.k+['auth','can-i','create','jobs','-n',ns,'--as=system:serviceaccount:'+ns+':native-controller'],capture_output=True,text=True,timeout=15)
        if result.returncode!=1 or result.stdout.strip()!='no':
            raise RuntimeError('new Job creation was not denied')
        self.ack(request['ack_file'])
