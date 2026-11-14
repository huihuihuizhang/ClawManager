"""Bounded original-provider TCP forward; no TLS termination or IAM writes."""
import json
import socket
import subprocess
import time
from urllib.parse import urlsplit

NS = 'clawmanager-sbk-validation-system'
KUBE = '/root/sbk-validation-tls-inspect.7LVU7vpE/operator.kubeconfig.yaml'

def need(ok, message):
    if not ok:
        raise ValueError(message)

def select_provider(service, slices, pod, flags):
    name = flags['--provider-service']
    endpoint = urlsplit(flags['--provider-endpoint'])
    need(endpoint.scheme == 'https' and endpoint.hostname == name+'.'+NS+'.svc' and
         endpoint.port == 8200 and not endpoint.path and not endpoint.query and
         not endpoint.fragment and endpoint.username is None, 'exact Vault endpoint required')
    need(service['metadata']['namespace'] == NS and service['metadata']['name'] == name and
         service['metadata']['uid'] == 'ef729a97-9c4d-4276-a6d5-68350ef46607' and
         not service['metadata'].get('deletionTimestamp') and service['spec']['type'] == 'ClusterIP',
         'original Vault Service required')
    refs = []
    for row in slices['items']:
        need(row['metadata']['namespace'] == NS and any(
            x.get('controller') and x['kind'] == 'Service' and x['uid'] == service['metadata']['uid']
            for x in row['metadata'].get('ownerReferences', [])), 'owned EndpointSlice required')
        need(any(x.get('port') == 8200 and x.get('protocol') == 'TCP' for x in row['ports']),
             'Vault endpoint port required')
        for ep in row['endpoints']:
            if ep.get('conditions', {}).get('ready') is True and not ep['conditions'].get('terminating'):
                refs.append(ep['targetRef'])
    need(len(refs) == 1 and refs[0]['kind'] == 'Pod' and refs[0]['namespace'] == NS and
         refs[0]['name'] == pod['metadata']['name'] and refs[0]['uid'] == pod['metadata']['uid'] and
         pod['metadata']['namespace'] == NS and not pod['metadata'].get('deletionTimestamp') and
         pod['status']['phase'] == 'Running' and pod['status'].get('containerStatuses') and
         all(x.get('ready') for x in pod['status']['containerStatuses']), 'one current ready Vault Pod required')
    need(service['spec'].get('selector') and all(pod['metadata']['labels'].get(k) == v
         for k,v in service['spec']['selector'].items()), 'Vault Pod selector mismatch')
    return pod['metadata']['name'], pod['metadata']['uid']

class LocalForward:
    def __init__(self, site, flags, records, save, endpoint_port=False):
        self.site, self.flags, self.records, self.save = site, flags, records, save
        self.process = None
        self.endpoint_port = endpoint_port

    def current(self):
        service = self.site.get('service', self.flags['--provider-service'])
        slices = json.loads(self.site.call(['get','endpointslices','-l',
            'kubernetes.io/service-name='+self.flags['--provider-service'],'-o','json']))
        refs = [ep['targetRef'] for row in slices['items'] for ep in row['endpoints']
                if ep.get('conditions', {}).get('ready') is True and not ep['conditions'].get('terminating')]
        need(len(refs) == 1, 'one current Vault endpoint required')
        pod = self.site.get('pod', refs[0]['name'])
        return select_provider(service, slices, pod, self.flags)

    def __enter__(self):
        self.selected = self.current()
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 8200 if self.endpoint_port else 0))
            port = sock.getsockname()[1]
        self.address = '127.0.0.1:'+str(port)
        self.save(self.records/'local-forward.json', {'Pod':self.selected[0], 'PodUID':self.selected[1],
            'LocalAddress':self.address, 'EndpointUnchanged':True, 'TLSVerificationUnchanged':True})
        self.log = (self.records/'local-forward.stderr.private').open('xb')
        try:
            self.process = subprocess.Popen(['kubectl','--kubeconfig',KUBE,'--request-timeout=0',
                '-n',NS,'port-forward','--pod-running-timeout=20s','--address=127.0.0.1','pod/'+self.selected[0],str(port)+':8200'],
                stdout=subprocess.DEVNULL, stderr=self.log)
            for _ in range(50):
                need(self.process.poll() is None, 'local Vault forward exited; retain logs')
                try:
                    with socket.create_connection(('127.0.0.1',port),timeout=.2):
                        pass
                    self.check()
                    return self.address
                except OSError:
                    time.sleep(.2)
            raise ValueError('local Vault forward did not become ready')
        except BaseException:
            self.__exit__(None,None,None)
            raise

    def check(self):
        need(self.process.poll() is None and self.current() == self.selected,
             'original Vault forward or endpoint changed; retain outcome')

    def __exit__(self, *args):
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.log.close()
        print('P2_VAULT_LOCAL_FORWARD_CLOSED', flush=True)
