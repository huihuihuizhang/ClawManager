"""Run public capture acceptance only on an existing task-owned local kind cluster.

No shared-cluster fallback, server credentials, synthetic success or automatic
cleanup. Uses argument arrays and writes transient binaries into ignored reports/.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parent.parent

def run(args, **kwargs):
    return subprocess.run(args, cwd=ROOT, check=True, **kwargs)

def read(args):
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--cluster', required=True)
    ap.add_argument('--mysql', required=True)
    ap.add_argument('--build', action='store_true')
    ap.add_argument('--test', default='^TestPublicCaptureNativeMySQLKubernetes$')
    ap.add_argument('--log', default='team-optimization-docs/m3-native.log')
    a = ap.parse_args()
    if not re.fullmatch(r'cm-backup-[a-z0-9-]+', a.cluster) or not re.fullmatch(r'cm-backup-[a-z0-9-]+', a.mysql):
        raise SystemExit('Explicit task-owned cluster/container names required')
    node = a.cluster + '-control-plane'
    info = json.loads(read(['docker', 'inspect', node]))[0]
    if info['Config']['Labels'].get('io.x-k8s.kind.cluster') != a.cluster:
        raise SystemExit('Kind ownership mismatch')
    mysql = json.loads(read(['docker', 'inspect', a.mysql]))[0]
    if mysql['Config']['Labels'].get('codex.task') != 'backup-team-integration':
        raise SystemExit('MySQL ownership mismatch')
    host = mysql['NetworkSettings']['Networks']['kind']['IPAddress']
    if not host:
        raise SystemExit('Task MySQL must be attached to local kind network')
    context = 'kind-' + a.cluster
    ns = 'cm-backup-m0m2-native'
    k = ['kubectl', '--context', context]
    build = ROOT / 'reports/m3m4-native-image'
    build.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, GOOS='linux', GOARCH='amd64', CGO_ENABLED='0')
    run(['go', '-C', 'backend', 'test', '-c', '-ldflags=-s -w', '-o', str(build/'native.test'), './internal/systembackupapi'], env=env)
    if 'production' in a.test:
        run(['go','-C','backend','build','-trimpath','-ldflags=-s -w','-o',str(build/'public-controller'),'./cmd/system-backup-v2-controller'],env=env)
    tag = 'cm-backup-native:' + a.cluster
    if a.build:
        run(['go', '-C', 'backend', 'build', '-trimpath', '-ldflags=-s -w', '-o', str(build/'backup-worker'), './cmd/backup-worker'], env=env)
        run(['docker', 'cp', node+':/usr/local/bin/crictl', str(build/'crictl')])
        import shutil
        shutil.copytree(ROOT/'contracts', build/'contracts', dirs_exist_ok=True)
        (build/'Dockerfile').write_text('FROM debian:bookworm-slim\nCOPY backup-worker crictl native.test /\nCOPY contracts /app/contracts\nWORKDIR /app/backend/internal/systembackupapi\nRUN chmod 0755 /backup-worker /crictl /native.test\n', encoding='utf8')
        run(['docker', 'build', '-t', tag, str(build)], stdout=subprocess.DEVNULL)
        run(['kind', 'load', 'docker-image', tag, '--name', a.cluster])
    listing = read(['docker', 'exec', node, 'ctr', '-n', 'k8s.io', 'images', 'ls'])
    rows = [r.split() for r in listing.splitlines() if r.startswith('docker.io/library/'+tag+' ')]
    if len(rows) != 1 or not re.fullmatch(r'sha256:[a-f0-9]{64}', rows[0][2]):
        raise SystemExit('Exact loaded image digest unavailable; run --build')
    image = 'docker.io/library/cm-backup-native@' + rows[0][2]
    run(['docker', 'exec', node, 'ctr', '-n', 'k8s.io', 'images', 'tag', '--force', 'docker.io/library/'+tag, image], stdout=subprocess.DEVNULL)
    yaml = (ROOT/'backend/internal/systembackupapi/testdata/native-capture.yaml').read_text(encoding='utf8')
    yaml = yaml.replace('__NATIVE_IMAGE__', image).replace('__MYSQL_HOST__', host)
    yaml = yaml.replace('command: [/native.test, -test.v, -test.run=^TestPublicCaptureNativeMySQLKubernetes$, -test.timeout=9m]', "command: [/bin/sleep, '21600']")
    manifest = build/'native.yaml'
    manifest.write_text(yaml, encoding='utf8')
    run(k+['apply', '-f', str(manifest)], stdout=subprocess.DEVNULL)
    for pod in ['native-node-proof','native-controller']:
        run(k+['-n',ns,'wait','--for=condition=Ready','pod/'+pod,'--timeout=90s'], stdout=subprocess.DEVNULL)
    run(k+['-n',ns,'cp',(build/'native.test').relative_to(ROOT).as_posix(),'native-controller:/tmp/native.test'])
    run(k+['-n',ns,'exec','native-controller','--','chmod','0755','/tmp/native.test'])
    if 'production' in a.test:
        run(k+['-n',ns,'cp',(build/'public-controller').relative_to(ROOT).as_posix(),'native-controller:/tmp/public-controller'])
        run(k+['-n',ns,'exec','native-controller','--','chmod','0755','/tmp/public-controller'])
    log = (ROOT/a.log).resolve()
    allowed = (ROOT/'team-optimization-docs').resolve()
    if not log.is_relative_to(allowed):
        raise SystemExit('Logs must stay in ignored team-optimization-docs')
    with log.open('w',encoding='utf8') as f:
        f.write('source=' + read(['git','rev-parse','HEAD']) + '\nimage=' + image + '\n')
        f.flush()
        result = subprocess.run(k+['-n',ns,'exec','native-controller','--','env','NATIVE_BACKUP_IMAGE='+image,'/tmp/native.test','-test.v','-test.run='+a.test,'-test.timeout=15m'],cwd=ROOT,stdout=f,stderr=subprocess.STDOUT)
    print('image='+image)
    print('log='+str(log))
    print('\n'.join(log.read_text(encoding='utf8').splitlines()[-12:]))
    raise SystemExit(result.returncode)

if __name__ == '__main__':
    main()
