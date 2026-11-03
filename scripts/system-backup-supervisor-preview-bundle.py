#!/usr/bin/env python3
"""Package completed engineering images; never deploy or claim page readiness."""
import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def main():
    repo = Path(__file__).resolve().parents[1]
    root = Path((repo / '.tmp-page-trial-release-root.txt').read_text().strip()).resolve(strict=True)
    if (root / '.owner').read_text().strip() != 'supervisor-page-trial-release-20261103':
        raise RuntimeError('wrong release owner')
    delivery = root / 'delivery-page-preview-a2cc03be-20261103'
    receipt = json.loads((delivery / 'build-receipt.json').read_text(encoding='utf-8'))
    if receipt['commit'] != 'a2cc03be63d4903b98cd4a2fedd48d4fbc65fc04' or len(receipt['binaries']) != 41:
        raise RuntimeError('wrong source or incomplete build')
    if sha(delivery / 'images.tar') != receipt['archive_sha256']:
        raise RuntimeError('image archive checksum mismatch')
    if any('config_digest' not in x for x in receipt['images'].values()):
        raise RuntimeError('actual exported config digests required')
    mc = root / 'native-tools/mc'
    if sha(mc) != '01f866e9c5f9b87c2b09116fa5d7c06695b106242d829a8bb32990c00312e891':
        raise RuntimeError('wrong mc tool')
    name = 'clawmanager-engineering-preview-a2cc03be-20261103'
    files = {
        'images.tar': delivery / 'images.tar',
        'build-receipt.json': delivery / 'build-receipt.json',
        'app-image-inspect.json': delivery / 'app-image-inspect.json',
        'worker-image-inspect.json': delivery / 'worker-image-inspect.json',
        'system-backup-preview-import.py': repo / 'scripts/system-backup-preview-import.py',
        'tools/mc': mc,
    }
    state = {
        'status': 'NOT_PAGE_READY_FIRST_ADOPTION_PRODUCER_MISSING',
        'source_commit': receipt['commit'], 'full_acceptance': False, 'dr_qualified': False,
        'workload_deployment_included': False,
        'blockers': [
            'Actual original writer fence, immutable historical evidence and first AdoptCoverage production execution are missing.',
            'Field migrations, enrollment and original installation material issuance have not been executed.',
            'Actual server source loading and pod identity freeze ordering have not been verified.',
            'No real page backup or same-task complete publication acceptance has passed.',
        ],
    }
    readme = '''# 工程镜像预置包：尚不能用于页面首备份验收

源码：a2cc03be63d4903b98cd4a2fedd48d4fbc65fc04，Linux amd64。
本包包含同源码的应用、worker 镜像和可核对构建清单。41 个程序已构建。
本次完整备份验收尚未完成，灾备资格未具备。

硬阻塞：首次 KEK 接管缺少实际原 writer fence、不可变历史证明和生产 AdoptCoverage 执行链。
现场迁移、enrollment、原始安装材料发行及服务器来源装载时序也尚未执行验证。
因此导入脚本不会更新 Deployment、停止业务或创建任务。此包不提供可用页面部署承诺。

远程 Bash（用户自行连接并执行）：

```bash
set -euo pipefail
cd /tmp
sha256sum -c clawmanager-engineering-preview-a2cc03be-20261103.tar.gz.sha256
PREVIEW_DIR="$(mktemp -d /tmp/clawmanager-preview-a2cc03be.XXXXXXXX)"
tar -xzf clawmanager-engineering-preview-a2cc03be-20261103.tar.gz -C "$PREVIEW_DIR" --strip-components=1
cd "$PREVIEW_DIR"
sha256sum -c SHA256SUMS
python3 -B ./system-backup-preview-import.py inspect
python3 -B ./system-backup-preview-import.py import-images
```

第二条 Python 命令会向现有 containerd k8s.io 导入镜像并推送到 10.130.14.23:5000，
只创建本版本标签；已有不同内容的同名标签会拒绝覆盖。输出 image-references.json。
镜像配置 ID 与仓库 manifest digest 分开核验，不混用作部署 digest。
请回传两条 Python 命令的公共 JSON 输出；不要回传密钥或私有安装材料。
tools/mc 为已校验的 Linux 工具，本次镜像导入不需要执行它。
测试结束后清理本包解压目录和临时构建产物；不要删除现场 PVC、Vault 状态或私有材料。
'''
    memory = {
        'READY_STATE.json': (json.dumps(state, ensure_ascii=False, indent=2) + '\n').encode(),
        'README.zh-CN.md': readme.encode(),
    }
    sums = {name: sha(path) for name, path in files.items()}
    sums.update({name: hashlib.sha256(raw).hexdigest() for name, raw in memory.items()})
    memory['SHA256SUMS'] = ''.join(f'{value}  {name}\n' for name, value in sorted(sums.items())).encode()
    archive = root / (name + '.tar.gz')
    print(json.dumps({'stage': 'compressing-verified-engineering-bundle', 'path': str(archive)}), flush=True)
    with archive.open('xb') as output, gzip.GzipFile(fileobj=output, mode='wb', compresslevel=1, mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode='w|') as tf:
            for filename, path in files.items():
                info = tf.gettarinfo(str(path), arcname=name + '/' + filename)
                info.uid = info.gid = 0
                info.uname = info.gname = 'root'
                info.mode = 0o755 if filename == 'tools/mc' or filename.endswith('.py') else 0o644
                with path.open('rb') as source:
                    tf.addfile(info, source)
            for filename, raw in memory.items():
                info = tarfile.TarInfo(name + '/' + filename)
                info.size, info.mode = len(raw), 0o644
                tf.addfile(info, io.BytesIO(raw))
    actual = {}
    with tarfile.open(archive, 'r|gz') as tf:
        for item in tf:
            relative = item.name.removeprefix(name + '/')
            if not item.isfile() or relative not in set(sums) | {'SHA256SUMS'} or relative in actual:
                raise RuntimeError('unexpected or repeated archive entry')
            stream = tf.extractfile(item)
            h = hashlib.sha256()
            for block in iter(lambda: stream.read(1024 * 1024), b''):
                h.update(block)
            actual[relative] = h.hexdigest()
    if actual != {**sums, 'SHA256SUMS': hashlib.sha256(memory['SHA256SUMS']).hexdigest()}:
        raise RuntimeError('bundle readback mismatch')
    checksum = sha(archive)
    (root / (archive.name + '.sha256')).write_bytes(f'{checksum}  {archive.name}\n'.encode())
    result = {'status': state['status'], 'archive': str(archive), 'bytes': archive.stat().st_size,
              'sha256': checksum, 'verified_entries': len(actual), 'full_acceptance': False}
    (root / 'engineering-preview-delivery.json').write_bytes((json.dumps(result, indent=2) + '\n').encode())
    print(json.dumps(result), flush=True)


if __name__ == '__main__':
    main()
