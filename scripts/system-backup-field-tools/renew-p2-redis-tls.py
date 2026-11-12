#!/usr/bin/env python3
"""Renew the observed P2 Redis TLS files; preserve process, ACL and source history.

This is certificate maintenance only. It does not authorize a source or backup.
Unknown mutation outcomes deliberately require inspection of the retained journal.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess

ROOT = Path('/root/sbk/p2-cert-renewal.1KyqMtsd')
REMOTE = '/data/.system-backup-redis-3acfbfcc018677b1b6d92b65866d0570'
POD = 'clawmanager-team-redis-78bb5d76f6-hqhss'
POD_UID = '32e2a8a4-aa74-4857-a9d2-fdaafb928cee'
RUN = '8eac27c6eac666ac053c2933c9cfe9f9836711e0'
ACL = '04d2c5882fff17d6051ca76105d564cf7514f98c25ed4c35f6ffb84e0bb6b36e'
NS = 'clawmanager-sbk-validation-system'
SERVER = 'clawmanager-redis.' + NS + '.svc'
FILES = ('ca.pem', 'server.pem', 'server-key.pem')


def need(ok, message):
    if not ok:
        raise ValueError(message)


def main():
    os.umask(0o077)
    need(os.name == 'posix', 'Linux operator required')
    spec = importlib.util.spec_from_file_location('assembly', Path(__file__).with_name('assemble-p2-installation-candidate.py'))
    A = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(A)
    r = ROOT / 'redis-tls-renew7d'
    r.mkdir(mode=0o700, exist_ok=True)
    need(r.resolve() == r and r.stat().st_mode & 0o077 == 0, 'private canonical journal required')
    need(not (r/'mutation.sent.json').exists(), 'mutation already sent; inspect retained journal before retry')
    fragment = A.obj(A.KNOWN['Redis'])
    keeper = A.obj(fragment['KeeperSelection'])
    need(keeper['ServerName'] == SERVER and keeper['Port'] == 6380 and
         keeper['Native']['PodUID'] == POD_UID, 'original Redis binding changed')
    for key in ('CA', 'KeeperCredential', 'ReaderCredential', 'CustodyKey'):
        A.read(keeper[key])
    kube = ['kubectl', '--kubeconfig', '/root/sbk-validation-tls-inspect.7LVU7vpE/operator.kubeconfig.yaml',
            '--request-timeout=20s', '-n', NS]

    def invoke(argv, body=None):
        p = subprocess.run(argv, input=body, capture_output=True, timeout=40)
        need(p.returncode == 0, 'command refused; no secret output printed')
        return p.stdout

    def get(kind, name):
        return json.loads(invoke(kube + ['get', kind, name, '-o', 'json']))

    def execute(argv, body=None):
        return invoke(kube + ['exec', '-i', POD, '-c', 'redis', '--', *argv], body)

    def redis(*args):
        return execute(['redis-cli', '-h', '127.0.0.1', '-p', '6379', '--raw', *args]).decode().strip()

    def check():
        pod = get('pod', POD)
        need(pod['metadata']['uid'] == POD_UID and not pod['metadata'].get('deletionTimestamp'), 'Redis Pod changed')
        owners = [x for x in pod['metadata']['ownerReferences'] if x.get('controller')]
        need(len(owners) == 1 and owners[0]['kind'] == 'ReplicaSet', 'Redis ownership changed')
        rs = get('replicaset', owners[0]['name'])
        dep = get('deployment', 'clawmanager-team-redis')
        need(rs['metadata']['uid'] == owners[0]['uid'] and
             dep['metadata']['uid'] == 'dd724dc4-ad59-4a78-b5bb-50aba907e036' and
             any(x.get('controller') and x['uid'] == dep['metadata']['uid'] for x in rs['metadata']['ownerReferences']), 'Redis deployment changed')
        need(all(x.get('ready') for x in pod['status']['containerStatuses']), 'Redis not ready')
        info = dict(x.split(':', 1) for x in redis('INFO', 'server').splitlines() if ':' in x)
        need(info.get('run_id') == RUN and info.get('redis_version') == '7.4.11' and info.get('process_id') == '1', 'Redis process changed')
        acl = redis('ACL', 'LIST')
        need(hashlib.sha256(acl.encode()).hexdigest() == ACL, 'Redis ACL changed')
        config = {'dir': '/data', 'aclfile': REMOTE+'/users.acl', 'port': '6379', 'tls-port': '6380',
                  'tls-auth-clients': 'no', 'tls-cert-file': REMOTE+'/server.pem',
                  'tls-key-file': REMOTE+'/server-key.pem', 'tls-ca-cert-file': REMOTE+'/ca.pem'}
        for key, expected in config.items():
            need(redis('CONFIG', 'GET', key).splitlines() == [key, expected], 'Redis config changed: '+key)
        # The durable startup paths must match the live TLS paths.
        args = pod['spec']['containers'][0].get('args', [])
        for key in ('tls-cert-file', 'tls-key-file', 'tls-ca-cert-file'):
            need(args.count('--'+key) == 1 and args[args.index('--'+key)+1] == config[key], 'startup certificate path changed')
        return pod

    pod = check()
    need(execute(['readlink', '-f', REMOTE]).decode().strip() == REMOTE, 'Redis TLS directory is not canonical')
    old = {}
    for name in FILES:
        raw = execute(['sh', '-ceu', 'test -f "$1" && test ! -L "$1"; cat "$1"', 'read', REMOTE+'/'+name])
        old[name] = A.retain(r/('previous-'+name), raw)
    need(old['ca.pem']['SHA256'] == keeper['CA']['SHA256'], 'loaded CA differs from original pinned CA')
    need(not (r/'ca-key.pem').exists(), 'partial certificate generation retained; inspect before retry')
    def openssl(*args):
        return invoke(['openssl', *args])
    openssl('req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
            '-keyout', str(r/'ca-key.pem'), '-out', str(r/'ca.pem'), '-days', '7', '-sha256',
            '-subj', '/CN=original-redis-source-renewal', '-addext', 'basicConstraints=critical,CA:TRUE',
            '-addext', 'keyUsage=critical,keyCertSign,cRLSign')
    openssl('req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
            '-keyout', str(r/'server-key.pem'), '-out', str(r/'server.csr'), '-subj', '/CN='+SERVER)
    A.retain(r/'server.ext', ('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:'+SERVER+'\n').encode())
    openssl('x509', '-req', '-in', str(r/'server.csr'), '-CA', str(r/'ca.pem'), '-CAkey', str(r/'ca-key.pem'),
            '-set_serial', '0x'+os.urandom(16).hex(), '-days', '7', '-sha256', '-extfile', str(r/'server.ext'), '-out', str(r/'server.pem'))
    openssl('verify', '-CAfile', str(r/'ca.pem'), '-verify_hostname', SERVER, str(r/'server.pem'))
    context = ssl.create_default_context(cafile=str(r/'ca.pem'))
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    pair_check = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    pair_check.load_cert_chain(str(r/'server.pem'), str(r/'server-key.pem'))
    new = {name: {'File': str(r/name), 'SHA256': A.sha((r/name).read_bytes())} for name in FILES}
    check()
    A.retain(r/'mutation.sent.json', {'Previous': old, 'New': new, 'PodUID': POD_UID, 'RunID': RUN, 'ACL': ACL})
    # Stage with exclusive names on the same PVC. Preserve file owner/mode.
    # All originals survive as .before-renew7d; no ACL or credential is written.
    for name in FILES:
        path = REMOTE+'/'+name
        execute(['sh', '-ceu', 'test ! -e "$1.before-renew7d"; test ! -e "$1.next-renew7d"; '
                 'test "$(sha256sum "$1" | cut -d " " -f 1)" = "$2"; '
                 'cp -p "$1" "$1.before-renew7d"; cp -p "$1" "$1.next-renew7d"; cat > "$1.next-renew7d"',
                 'stage', path, old[name]['SHA256']], (r/name).read_bytes())
        staged = execute(['cat', path+'.next-renew7d'])
        need(A.sha(staged) == new[name]['SHA256'], 'staged certificate differs')
    check()
    for name in FILES:
        execute(['mv', REMOTE+'/'+name+'.next-renew7d', REMOTE+'/'+name])
    need(redis('CONFIG', 'SET', 'tls-cert-file', REMOTE+'/server.pem', 'tls-key-file',
               REMOTE+'/server-key.pem', 'tls-ca-cert-file', REMOTE+'/ca.pem') == 'OK', 'TLS reload unconfirmed; retain journal')
    for name in FILES:
        need(A.sha(execute(['cat', REMOTE+'/'+name])) == new[name]['SHA256'], 'durable certificate mismatch')
    with socket.create_connection((pod['status']['podIP'], 6380), timeout=10) as sock:
        with context.wrap_socket(sock, server_hostname=SERVER) as tls:
            need(tls.getpeercert(binary_form=True) == ssl.PEM_cert_to_DER_cert((r/'server.pem').read_text()), 'loaded leaf differs')
            expires = tls.getpeercert()['notAfter']
    check()
    done = {'Version': 'p2-redis-tls-renewed.v1', 'CA': new['ca.pem'], 'Certificate': new['server.pem'],
            'PreviousFragment': A.KNOWN['Redis'], 'PodUID': POD_UID, 'RunID': RUN, 'ACL': ACL,
            'NotAfter': expires, 'SourceReferencesUpdated': False, 'GrantsIssued': False, 'BackupReady': False}
    A.retain(r/'completed.json', done)
    print('P2_REDIS_TLS_RENEWED_SOURCE_REAUTHOR_REQUIRED', json.dumps(done))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        raise SystemExit('P2_REDIS_TLS_RENEWAL_UNCONFIRMED '+(str(error) if type(error) is ValueError else type(error).__name__))
