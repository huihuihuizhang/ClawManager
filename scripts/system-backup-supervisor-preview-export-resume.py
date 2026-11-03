#!/usr/bin/env python3
"""Resume export of already built, owned images after CLI stdout contamination."""
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import tarfile


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


repo = Path(__file__).resolve().parents[1]
root = Path((repo / '.tmp-page-trial-release-root.txt').read_text().strip()).resolve(strict=True)
if (root / '.owner').read_text().strip() != 'supervisor-page-trial-release-20261103':
    raise RuntimeError('wrong release owner')
out = root / 'delivery-page-preview-a2cc03be-20261103'
receipt = json.loads((out / 'build-inputs.json').read_text(encoding='utf-8'))
if receipt['commit'] != 'a2cc03be63d4903b98cd4a2fedd48d4fbc65fc04':
    raise RuntimeError('wrong source commit')
dc = [r'C:\Users\zhanghui08\AppData\Local\Programs\DockerDesktop\resources\bin\docker.exe',
      '--host', 'npipe:////./pipe/dockerDesktopLinuxEngine']
receipt['binaries'] = {alias: digest(out / 'bin' / alias) for alias in receipt['tools']}
receipt['runtime_files'] = {}
source = root / 'release-source'
in_app = False
for line in (source / 'Dockerfile').read_text().splitlines():
    if line.startswith('FROM '):
        in_app = line.strip().endswith(' AS app')
    if not in_app or not line.startswith('COPY ') or '--from=' in line:
        continue
    fields = shlex.split(line)
    if len(fields) != 3 or not fields[1].startswith('deployments/'):
        raise RuntimeError('unexpected source runtime COPY')
    receipt['runtime_files'][fields[1]] = {'target': fields[2], 'sha256': digest(source / fields[1])}
receipt['images'] = {}
for role, tag in [('app', 'clawmanager-page-trial'), ('worker', 'clawmanager-backup-worker')]:
    tag += ':' + receipt['version']
    obj = json.loads(subprocess.check_output(dc + ['image', 'inspect', tag]))[0]
    if obj['Architecture'] != 'amd64' or obj['Os'] != 'linux':
        raise RuntimeError('wrong image platform')
    labels = obj['Config']['Labels']
    if labels.get('io.clawmanager.page-release') != 'fb7ad8eb50e946229b80f908b71aa6a9' or labels.get('org.opencontainers.image.revision') != receipt['commit']:
        raise RuntimeError('wrong image owner or source')
    config = obj['Config']
    if role == 'app' and (config['Entrypoint'] != ['dumb-init', '--'] or config['Cmd'] != ['/app/start.sh'] or labels.get('io.clawmanager.source-sha256') != receipt['backend_inputs_sha256']):
        raise RuntimeError('app config mismatch')
    if role == 'worker' and (config['Entrypoint'] != ['/backup-worker'] or config['User'] != '65532:65532'):
        raise RuntimeError('worker config mismatch')
    receipt['images'][role] = {'tag': tag, 'id': obj['Id']}
    (out / (role + '-image-inspect.json')).write_bytes((json.dumps(obj, indent=2) + '\n').encode())
archive = out / 'images.tar'
if archive.exists() or (out / 'build-receipt.json').exists():
    raise RuntimeError('do not overwrite existing export')
print(json.dumps({'stage': 'saving-verified-built-images', 'images': receipt['images']}), flush=True)
with (out / 'image-save.log').open('wb') as log:
    subprocess.run(dc + ['save', '-o', str(archive), *[x['tag'] for x in receipt['images'].values()]], stdout=log, stderr=subprocess.STDOUT, check=True)
with tarfile.open(archive, 'r') as tf:
    manifests = json.load(tf.extractfile('manifest.json'))
    for image in receipt['images'].values():
        entries = [x for x in manifests if image['tag'] in x.get('RepoTags', [])]
        if len(entries) != 1:
            raise RuntimeError('ambiguous exported image tag')
        image['config_digest'] = 'sha256:' + hashlib.sha256(tf.extractfile(entries[0]['Config']).read()).hexdigest()
receipt.update({'archive_sha256': digest(archive), 'archive_bytes': archive.stat().st_size,
                'export_recovery': 'Docker commit deprecated flag warning polluted stdout; exact image inspect verified config IDs before export. No rebuild or source change.'})
(out / 'build-receipt.json').write_bytes((json.dumps(receipt, indent=2) + '\n').encode())
print(json.dumps({'stage': 'export-complete', 'bytes': receipt['archive_bytes'], 'sha256': receipt['archive_sha256']}), flush=True)
