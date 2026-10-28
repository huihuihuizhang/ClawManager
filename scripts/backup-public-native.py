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
import hashlib
import uuid
from backup_native_capacity import NativeCapacity
from backup_native_access import NativeAccess

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
    ap.add_argument('--physical-capacity',action='store_true')
    ap.add_argument('--worker-image', help='Task-owned local cm-backup-worker tag built by the production Dockerfile')
    ap.add_argument('--controller-image', help='Task-owned local cm-backup-app tag; extract and run its exact public controller binary')
    ap.add_argument('--minimum-kubernetes', action='store_true', help='Temporarily enforce the rendered minimum role on the original native controller identity')
    ap.add_argument('--test', default='^TestPublicCaptureNativeMySQLKubernetes$')
    ap.add_argument('--log', default='team-optimization-docs/m3-native.log')
    a = ap.parse_args()
    if a.physical_capacity and 'production-' not in a.test:
        raise SystemExit('Physical capacity mode requires the production entry case')
    if a.minimum_kubernetes and 'production-' not in a.test:
        raise SystemExit('Minimum Kubernetes mode requires a production entry case')
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
    for value, repo in [(a.worker_image, 'cm-backup-worker'), (a.controller_image, 'cm-backup-app')]:
        if value is not None and not re.fullmatch(repo+r':[a-z0-9.-]+',value):
            raise SystemExit('Only an explicit task-owned local image tag is accepted')
    env = dict(os.environ, GOOS='linux', GOARCH='amd64', CGO_ENABLED='0')
    run(['go', '-C', 'backend', 'test', '-c', '-ldflags=-s -w', '-o', str(build/'native.test'), './internal/systembackupapi'], env=env)
    if a.controller_image and 'production' not in a.test:
        raise SystemExit('Controller-image acceptance requires the production entry case')
    if a.controller_image:
        original_image=read(['docker','image','inspect',a.controller_image,'--format','{{.Id}}'])
        container=read(['docker','create','--name','cm-backup-controller-artifact-'+uuid.uuid4().hex[:12],
                        '--label','codex.task=backup-team-integration','--entrypoint','/usr/local/bin/system-backup-v2-controller',original_image])
        try:
            run(['docker','cp',container+':/usr/local/bin/system-backup-v2-controller',str(build/'public-controller')])
        finally:
            run(['docker','rm',container],stdout=subprocess.DEVNULL)
    elif 'production' in a.test:
        run(['go','-C','backend','build','-trimpath','-ldflags=-s -w','-o',str(build/'public-controller'),'./cmd/system-backup-v2-controller'],env=env)
    if a.physical_capacity:
        run(['go','-C','backend','build','-trimpath','-ldflags=-s -w','-o',str(build/'native-capacity'),'./cmd/system-backup-registration'],env=env)
        run(['docker','cp',(build/'native-capacity').relative_to(ROOT).as_posix(),a.mysql+':/tmp/native-capacity'])
        run(['docker','exec',a.mysql,'chmod','0755','/tmp/native-capacity'])
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
    worker_image=image
    if a.worker_image:
        run(['kind','load','docker-image',a.worker_image,'--name',a.cluster])
        listing=read(['docker','exec',node,'ctr','-n','k8s.io','images','ls'])
        wanted='docker.io/library/'+a.worker_image
        found=[r.split() for r in listing.splitlines() if r.startswith(wanted+' ')]
        if len(found)!=1 or not re.fullmatch(r'sha256:[a-f0-9]{64}',found[0][2]):
            raise SystemExit('Exact final worker image digest unavailable')
        worker_image='docker.io/library/cm-backup-worker@'+found[0][2]
        run(['docker','exec',node,'ctr','-n','k8s.io','images','tag','--force',wanted,worker_image],stdout=subprocess.DEVNULL)
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
        f.write('worker_image='+worker_image+'\n')
        if a.controller_image:
            f.write('controller_image_id='+original_image+'\ncontroller_binary_sha256='+hashlib.sha256((build/'public-controller').read_bytes()).hexdigest()+'\n')
        f.flush()
        command=k+['-n',ns,'exec','native-controller','--','env','NATIVE_BACKUP_IMAGE='+image,'NATIVE_BACKUP_WORKER_IMAGE='+worker_image]
        if a.physical_capacity:
            command+=['NATIVE_BACKUP_PHYSICAL_CAPACITY=true']
        if a.minimum_kubernetes:
            command+=['NATIVE_BACKUP_MINIMUM_KUBERNETES=true']
        command+=['/tmp/native.test','-test.v','-test.run='+a.test,'-test.timeout=15m']
        feed=None
        access=NativeAccess(k) if a.minimum_kubernetes else None
        process=subprocess.Popen(command,cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
        try:
            for line in process.stdout:
                f.write(line);f.flush()
                if line.startswith('NATIVE_KUBERNETES_ACCESS '):
                    if access is None:
                        raise RuntimeError('unexpected native access request')
                    try:
                        access.install(json.loads(line.split(' ',1)[1]))
                    except Exception:
                        f.write('native-access=setup-unavailable\n');f.flush()
                        access.restore()
                if line.startswith('NATIVE_KUBERNETES_RESTORE '):
                    if access is None:
                        raise RuntimeError('unexpected native access restore')
                    access.restore(json.loads(line.split(' ',1)[1]))
                if line.startswith('NATIVE_KUBERNETES_RECOVERY_ONLY '):
                    if access is None:
                        raise RuntimeError('unexpected native recovery access request')
                    access.recovery_only(json.loads(line.split(' ',1)[1]))
                if line.startswith('NATIVE_CAPACITY_REQUEST '):
                    if not a.physical_capacity or feed is not None:
                        raise RuntimeError('unexpected or duplicate physical capacity request')
                    try:
                        feed=NativeCapacity(a.mysql,k,json.loads(line.split(' ',1)[1]));feed.start()
                    except Exception:
                        # Keep the remote test attached so its bounded missing
                        # report check and source cleanup finish normally.
                        f.write('native-capacity=setup-unavailable\n');f.flush()
            code=process.wait()
        finally:
            if process.poll() is None:
                process.terminate();process.wait(timeout=20)
            if feed is not None:
                feed.close()
            if access is not None:
                access.restore()
        if a.physical_capacity and (feed is None or feed.samples==0) and code==0:
            raise RuntimeError('physical capacity evidence missing')
    print('image='+image)
    print('log='+str(log))
    print('\n'.join(log.read_text(encoding='utf8').splitlines()[-12:]))
    raise SystemExit(code)

if __name__ == '__main__':
    main()
