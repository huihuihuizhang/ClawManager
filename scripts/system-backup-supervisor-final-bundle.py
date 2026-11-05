#!/usr/bin/env python3
"""Stream a verified final delivery into an offline bundle; never build or deploy."""
import argparse
import ast
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import shlex
import subprocess
import tarfile


def require(ok, reason):
    if not ok:
        raise RuntimeError(reason)


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as src:
        for block in iter(lambda: src.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def hash_bytes(raw):
    return hashlib.sha256(raw).hexdigest()


def regular(path):
    require(not path.is_symlink() and path.is_file(), 'regular file required: ' + str(path))
    return path.resolve(strict=True)


def read_json(path):
    return json.loads(regular(path).read_text(encoding='utf-8-sig'))


def packed(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode()


def constants(raw):
    values = {}
    for node in ast.parse(raw).body:
        if isinstance(node, ast.Assign):
            try:
                value = ast.literal_eval(node.value) if not isinstance(node.value, ast.Name) else values[node.value.id]
            except (ValueError, TypeError, KeyError):
                continue
            for target in node.targets:
                if isinstance(target, ast.Name):
                    values[target.id] = value
    return values


def seal_names(raw, values):
    function = next(n for n in ast.parse(raw).body if isinstance(n, ast.FunctionDef) and n.name == 'seal_release')
    names = []
    for node in function.body:
        value = None
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'names' for t in node.targets):
            value = node.value
        elif isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name) and node.target.id == 'names':
            require(isinstance(node.op, ast.Add), 'unsupported release names operation')
            value = node.value
        if value is not None:
            require(isinstance(value, (ast.List, ast.Tuple)), 'review new dynamic seal roster before packaging')
            names.extend(values[n.id] if isinstance(n, ast.Name) else ast.literal_eval(n) for n in value.elts)
    require(names and all(isinstance(n, str) for n in names), 'actual operator seal roster missing')
    return set(names)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('delivery', 'source', 'source-repository', 'selection', 'loader-map', 'copy199', 'shared-agent-input', 'output'):
        p.add_argument('--' + name, required=True, type=Path)
    for name in ('commit', 'selection-sha256', 'loader-map-sha256', 'shared-agent-input-sha256'):
        p.add_argument('--' + name, required=True)
    p.add_argument('--runbook', type=Path, help='Optional final D installation runbook; absence is explicit in README/manifest')
    p.add_argument('--runbook-sha256', help='Required together with --runbook')
    a = p.parse_args()
    require(bool(a.runbook) == bool(a.runbook_sha256), 'runbook and exact digest required together')
    require(re.fullmatch('[a-f0-9]{40}', a.commit), 'exact accepted source commit required')
    source = a.source.resolve(strict=True)
    delivery = a.delivery.resolve(strict=True)
    require(a.output.suffixes[-2:] == ['.tar', '.gz'], 'output must end in .tar.gz')
    archive = a.output.absolute()
    sidecar = Path(str(archive) + '.sha256')
    require(archive.parent.is_dir() and not archive.exists() and not sidecar.exists(), 'new output and checksum paths required')
    name = archive.name[:-7]
    require(re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,120}', name), 'safe archive basename required')
    head = subprocess.check_output(['git', '-C', str(a.source_repository), 'rev-parse', 'HEAD'], text=True).strip()
    require(head == a.commit, 'source commit does not match actual repository HEAD')
    receipt = read_json(delivery / 'build-receipt.json')
    require(receipt['commit'] == a.commit, 'delivery receipt commit differs from accepted HEAD')
    require(receipt.get('scope') == 'local-build-not-page-acceptance', 'completed original builder receipt required')
    require(receipt.get('full_page_acceptance') is False and receipt.get('dr_qualified') is False, 'builder cannot establish field acceptance')
    for path, expected in ((a.selection, a.selection_sha256), (a.loader_map, a.loader_map_sha256), (a.shared_agent_input, a.shared_agent_input_sha256)):
        require(re.fullmatch('[a-f0-9]{64}', expected) and sha(regular(path)) == expected, 'reviewed manifest changed: ' + str(path))
    selection = read_json(a.selection)
    loader = read_json(a.loader_map)
    agent_input = read_json(a.shared_agent_input)
    require(agent_input['schema_version'] == 'shared-native-tls-agent-build-input.v1', 'original shared agent build input required')
    selected = selection['selected']
    # Bind complete backend and all accepted selected files, not a display commit alone.
    backend = {f.relative_to(source).as_posix(): sha(f) for f in sorted((source / 'backend').rglob('*')) if f.is_file() and not any(x.startswith('.') for x in f.relative_to(source / 'backend').parts)}
    require(backend == receipt['backend_inputs'], 'final backend source differs from actual build inputs')
    require(hash_bytes(json.dumps(backend, sort_keys=True, separators=(',', ':')).encode()) == receipt['backend_inputs_sha256'], 'backend input tree checksum differs')
    for target, record in selected.items():
        actual = source / target
        require(sha(regular(actual)) == record['selected_sha256'], 'accepted selected export changed: ' + target)
    files, memory, modes = {}, {}, {}

    def add(target, path, expected=None, executable=False):
        require(not PurePosixPath(target).is_absolute() and '..' not in PurePosixPath(target).parts and re.fullmatch('[A-Za-z0-9_./-]+', target), 'unsafe package member')
        path = regular(path)
        require(target not in files and target not in memory, 'duplicate package member: ' + target)
        if expected is not None:
            require(sha(path) == expected, 'actual file digest differs: ' + target)
        files[target] = path
        modes[target] = 0o755 if executable else 0o644

    def elf(target, path, expected):
        add(target, path, expected, True)
        with path.open('rb') as src:
            header = src.read(20)
        require(header[:6] == b'\x7fELF\x02\x01' and header[18:20] == b'\x3e\x00', 'Linux amd64 ELF required: ' + target)

    tools = receipt['tools']
    binaries = receipt['binaries']
    require(tools and {'clawreef-server', 'backup-worker', 'system-backup-first-adoption-production'} <= set(tools), 'incomplete actual Go tool roster')
    dockerfile = (source / 'Dockerfile').read_text(encoding='utf-8')
    declared = dict(re.findall(r'-o /out/([\w-]+) ./cmd/([\w-]+)', dockerfile))
    for alias in re.findall(r'(?m)^\s+(system-backup-[\w-]+|backup-(?:node|gateway-node|stopped-pro-node)-observer|backup-shared-runtime-node-owner)(?:\s+\\|;\s+do)', dockerfile):
        declared[alias] = alias
    require(declared and all(tools.get(alias) == command for alias, command in declared.items()), 'Dockerfile tools omitted or remapped in actual receipt')
    require(all((source / 'backend/cmd' / command).is_dir() for command in tools.values()), 'actual command source missing')
    require(set(agent_input['binaries']) == {'openclaw', 'hermes'}, 'exact shared agent roster required')
    externals = {runtime + '-lite-agent': pin['sha256'] for runtime, pin in agent_input['binaries'].items()}
    externals.update({key: value['sha256'] for key, value in receipt['native_tool_inputs'].items()})
    require(set(externals) == {'openclaw-lite-agent', 'hermes-lite-agent', 'mc', 'crictl'}, 'four external ELF required')
    deployment_constants = constants((source / 'scripts/system-backup-operator-deployment.py').read_bytes())
    location_constants = constants((source / 'scripts/system-backup-operator-adoption-locations.py').read_bytes())
    require(externals['mc'] == location_constants['MC_SHA'] and externals['crictl'] == deployment_constants['CRI_SHA'], 'native tools differ from original selected source pins')
    require(set(binaries) == set(tools) | set(externals), 'receipt binary roster must equal actual Go tools plus original external ELF')
    actual_bins = {f.name for f in (delivery / 'bin').iterdir()}
    require(actual_bins == set(binaries), 'delivery/bin differs from complete receipt roster')
    for alias, expected in binaries.items():
        require(re.fullmatch('[A-Za-z0-9][A-Za-z0-9_-]{0,100}', alias), 'invalid binary alias')
        elf('bin/' + alias, delivery / 'bin' / alias, expected)
    require({f.name for f in (delivery / 'tools').iterdir()} == set(externals), 'delivery/tools must contain exact four external ELF')
    require(set(receipt['delivery_tools']) == {'tools/' + n for n in externals}, 'tool receipt roster differs')
    for alias, expected in externals.items():
        require(binaries[alias] == expected and receipt['delivery_tools']['tools/' + alias]['sha256'] == expected, 'external tool pin mismatch')
        require((delivery / 'tools' / alias).stat().st_size == receipt['delivery_tools']['tools/' + alias]['bytes'], 'external tool size mismatch')
        require(receipt['external_overlay_files']['usr/local/bin/' + alias] == expected, 'external ELF missing from app overlay receipt')
        elf('tools/' + alias, delivery / 'tools' / alias, expected)
    require(receipt['shared_agent_provenance']['build_input_sha256'] == a.shared_agent_input_sha256, 'builder shared agent provenance changed')
    add('images.tar', delivery / 'images.tar', receipt['archive_sha256'])
    require((delivery / 'images.tar').stat().st_size == receipt['archive_bytes'], 'image archive size mismatch')
    add('build-receipt.json', delivery / 'build-receipt.json')
    for target, pin in receipt['runtime_files'].items():
        require(sha(regular(source / target)) == pin['sha256'], 'container runtime input differs from build receipt: ' + target)
    with tarfile.open(delivery / 'images.tar', 'r') as tf:
        manifests = json.load(tf.extractfile('manifest.json'))
        for role in ('app', 'worker'):
            image = receipt['images'][role]
            matches = [entry for entry in manifests if image['tag'] in entry.get('RepoTags', [])]
            require(len(matches) == 1, 'exported image tag ambiguous')
            raw = tf.extractfile(matches[0]['Config']).read()
            require('sha256:' + hash_bytes(raw) == image['config_digest'], 'exported config digest mismatch')
            config = json.loads(raw)
            require(config['architecture'] == 'amd64' and config['os'] == 'linux', 'image platform differs')
            require(config['config']['Labels']['org.opencontainers.image.revision'] == a.commit, 'exported image source label differs')
            inspected = read_json(delivery / (role + '-image-inspect.json'))
            require(inspected['Id'] == image['id'] and inspected['Architecture'] == 'amd64' and inspected['Os'] == 'linux', 'actual image inspect mismatch')
            add(role + '-image-inspect.json', delivery / (role + '-image-inspect.json'))
    main_path = source / 'scripts/system-backup-zhanghui08-operator.py'
    main_raw = main_path.read_bytes()
    values = constants(main_raw)
    names = seal_names(main_raw, values)
    todo = {'scripts/system-backup-zhanghui08-operator.py', 'scripts/system-backup-preview-import.py'} | {n for n in names if n.endswith('.py')}
    python_files = {}
    snapshot = {x['target']: x['sealed_sha256'] for x in loader['input_snapshot']}
    while todo:
        target = todo.pop()
        if target in python_files:
            continue
        raw = regular(source / target).read_bytes()
        require(snapshot.get(target) == hash_bytes(raw), 'Python file missing or changed since final loader graph seal: ' + target)
        compile(raw, target, 'exec')
        python_files[target] = hash_bytes(raw)
        add(target, source / target, python_files[target], True)
        for node in ast.walk(ast.parse(raw)):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                value = node.value
                if value.endswith('.py'):
                    value = value if value.startswith('scripts/') else 'scripts/' + value
                    if (source / value).is_file() and value not in python_files:
                        todo.add(value)
    for item in loader['edges']:
        require(python_files.get('scripts/' + item['child']) == item['after'], 'sealed Python edge differs')
    ancestry = subprocess.run(['git', '-C', str(a.source_repository), 'merge-base', '--is-ancestor', values['PAGE_FIX'], a.commit], check=False)
    require(ancestry.returncode == 0, 'required page fix missing from accepted source ancestry')
    require(sha(regular(a.copy199)) == values['COPY_SHA'] == values['PROOF_ARCHIVE_SHA'], 'actual copy199r2 archive differs')
    add(values['COPY_NAME'], a.copy199, values['COPY_SHA'])
    with tarfile.open(a.copy199, 'r:gz') as tf:
        member = tf.getmember(values['PROOF_MEMBER'])
        require(member.isfile() and member.size < 64 << 20, 'original proof member shape differs')
        proof = tf.extractfile(member).read()
    require(hash_bytes(proof) == values['PROOF_SHA'], 'original proof ELF differs')
    require(proof[:6] == b'\x7fELF\x02\x01' and proof[18:20] == b'\x3e\x00', 'original proof platform differs')
    memory['bin/system-backup-legacy-upgrade177-proof'] = proof
    modes['bin/system-backup-legacy-upgrade177-proof'] = 0o755
    bundle = regular(a.shared_agent_input.parent / Path(agent_input['bundle']['path']).name)
    add(bundle.name, bundle, agent_input['bundle']['sha256'])
    require(receipt['shared_agent_provenance']['bundle_sha256'] == agent_input['bundle']['sha256'] and receipt['shared_agent_provenance']['source_tree_sha256'] == agent_input['source_tree_sha256'], 'built shared agent archive provenance differs')
    layer_constants = constants((source / 'scripts/system-backup-agent-runtime-layer/agent_runtime_layer.py').read_bytes())
    require(layer_constants['BUNDLE_SHA'] == agent_input['bundle']['sha256'] and layer_constants['REVISION'] == agent_input['revision'], 'runtime layer shared archive pin differs')
    for runtime, pin in agent_input['binaries'].items():
        require(layer_constants['PROFILES'][runtime]['agent_sha'] == pin['sha256'] and layer_constants['PROFILES'][runtime]['agent_size'] == pin['bytes'], 'runtime profile original agent differs')
    add('provenance/source-selection.json', a.selection, a.selection_sha256)
    add('provenance/python-loader-map.json', a.loader_map, a.loader_map_sha256)
    add('provenance/shared-agent-BUILD_INPUT.json', a.shared_agent_input, a.shared_agent_input_sha256)
    add('provenance/assemble.py', Path(__file__))
    if a.runbook:
        add('INSTALL-RUNBOOK.zh-CN.md', a.runbook, a.runbook_sha256)
    # Same byte/location pin format as the reviewed seal-release; no stage is run.
    pins = {n: sha(files[n]) if n in files else hash_bytes(memory[n]) for n in names}
    require(pins[values['NATIVE']] == values['NATIVE_SHA'] and pins[values['COPY_QUALIFIER']] == values['COPY_QUALIFIER_SHA'], 'original native/qualifier release pins differ')
    pins.update({'bin/' + alias: expected for alias, expected in binaries.items()})
    pins['bin/system-backup-legacy-upgrade177-proof'] = values['PROOF_SHA']
    memory['operator-release-pins.json'] = packed({'version': 'zhanghui08-operator-release-files.v1', 'commit': a.commit, 'page_fix_ancestor': values['PAGE_FIX'], 'files': pins, 'production_authority': False})
    config = {'source_commit': a.commit, 'version': receipt['version'], 'installation_runbook_included': bool(a.runbook), 'installation_runbook_runnable': False, 'full_acceptance': False, 'page_acceptance': False, 'dr_qualified': False}
    memory['release-state.json'] = packed(config)
    memory['ENTRY.sh'] = b'''#!/usr/bin/env bash
set -euo pipefail
umask 077
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
sha256sum -c SHA256SUMS
case "${1:-verify}" in
  verify) cat release-state.json ;;
  inspect) python3 -B ./scripts/system-backup-preview-import.py inspect --directory "$PWD" ;;
  import-images) python3 -B ./scripts/system-backup-preview-import.py import-images --directory "$PWD" ;;
  *) echo 'Usage: bash ENTRY.sh verify|inspect|import-images' >&2; exit 2 ;;
esac
'''
    modes['ENTRY.sh'] = 0o755
    action_tree = ast.parse(main_raw)
    action_main = next(n for n in action_tree.body if isinstance(n, ast.FunctionDef) and n.name == 'main')
    choice_node = next(n.value for n in action_main.body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'choices' for t in n.targets))
    actions = {n.value for n in choice_node.elts if isinstance(n, ast.Constant) and isinstance(n.value, str)}
    actions.update('db-' + x for x in values['DB_ACTIONS'])
    actions.update('sql-' + x for x in ('inspect', 'prepare', 'apply', 'query', 'rollback', 'enroll'))
    for key in ('IMPLEMENTED_STAGES', 'WORKSPACE_ACTIONS', 'BLOCKERS'):
        actions.update(values[key])
    # Read only finite AST data; never import or dispatch installation code.
    for target in python_files:
        raw_module = (source / target).read_bytes()
        tree = ast.parse(raw_module)
        module_constants = constants(raw_module)
        for key in ('ACTIONS', 'PREPARE'):
            current = module_constants.get(key, ())
            if isinstance(current, (dict, list, tuple)):
                actions.update(current)
            for node in tree.body:
                if isinstance(node, ast.Assign):
                    for assigned in node.targets:
                        if isinstance(assigned, ast.Subscript) and isinstance(assigned.value, ast.Name) and assigned.value.id == key:
                            value = ast.literal_eval(assigned.slice)
                            require(isinstance(value, str), 'finite operator action key required')
                            actions.add(value)
    commands = ['python3 -B ./scripts/system-backup-zhanghui08-operator.py ' + shlex.quote(action) + ' --release-directory "$PWD" [actual pinned inputs]' for action in sorted(actions)]
    memory['OPERATOR-CALLS.txt'] = ('Actual operator actions, alphabetical; NOT execution order or a runnable installation script.\nEvery action requires actual pinned inputs and original-operation recovery rules.\n' + '\n'.join(commands) + '\nUse final D runbook for ordering, exact arguments, prerequisites and recovery.\n').encode()
    readme = f'''# 离线交付包：镜像与实际文件已校验，现场安装及验收待执行

源码提交：{a.commit}。版本：{receipt['version']}。Linux amd64。
本包实际包含 {len(tools)} 个 Go 工具、4 个外部 ELF、{len(python_files)} 个 Python 文件，以及同源应用和 worker 镜像。
bin/ 另含从真实 copy199r2 归档独立校验提取的旧库证明工具，不计入构建工具数。
安装 Runbook：{'已包含 INSTALL-RUNBOOK.zh-CN.md 供集成核对；当前 runnable=false，不能作为完整安装命令执行' if a.runbook else '尚未接入；本包仅提供核验和镜像导入入口，不能据此执行完整安装'}。

上传前核对外层 .tar.gz.sha256。现场用户自行执行：

```bash
set -euo pipefail
umask 077
cd /tmp
sha256sum -c {shlex.quote(archive.name + '.sha256')}
release_dir=$(mktemp -d /root/clawmanager-release.XXXXXXXX)
tar -xzf {shlex.quote(archive.name)} -C "$release_dir" --strip-components=1
cd "$release_dir"
bash ENTRY.sh verify
bash ENTRY.sh inspect
bash ENTRY.sh import-images
```

import-images 会导入 containerd k8s.io 并按原工具规则推送到现场仓库，输出真实 image-references.json；不会完成工作负载部署。
随后操作使用 operator-release-pins.json 和 D 的最终 Runbook。OPERATOR-CALLS.txt 是接口提示，不是安装步骤。
尚需现场绑定：真实原 copy199r2 收据、存储类/容量、节点 SSH key/known-hosts、source/writer selection、MinIO options，以及原 producer 的 issuers/nonce/C1/archive/adoption/composition 收据。不得补造缺失材料。
admin 密码仍从 /root/.clawmanager-backup-install/admin-password 读取；Vault 原材料仍在 /root/sbk-vault-owner-20261102-01/init-material.json。本包不含这些秘密。
本包不代表 ready、页面验收或灾备资格。验收必须看到真实非空页面备份、完整采集、源状态恢复、正式发布、独立读回、catalog 和 true success。copy199r2 通过不能替代原库升级及页面验收。
测试结束后删除测试构建产物；现场持久卷、原 Vault 状态和原私有材料按实际恢复 Runbook 保留。
'''
    memory['README.zh-CN.md'] = readme.encode()
    roster = {target: {'sha256': sha(path), 'bytes': path.stat().st_size, 'mode': modes[target]} for target, path in files.items()}
    roster.update({target: {'sha256': hash_bytes(raw), 'bytes': len(raw), 'mode': modes.get(target, 0o644)} for target, raw in memory.items()})
    memory['manifest.json'] = packed({**config, 'schema_version': 'supervisor-offline-delivery-manifest.v1', 'source_selection_sha256': a.selection_sha256, 'loader_map_sha256': a.loader_map_sha256, 'go_tool_count': len(tools), 'receipt_binary_count': len(binaries), 'external_tools': externals, 'files': roster})
    sums = {target: entry['sha256'] for target, entry in roster.items()}
    sums['manifest.json'] = hash_bytes(memory['manifest.json'])
    memory['SHA256SUMS'] = ''.join(f'{pin}  {target}\n' for target, pin in sorted(sums.items())).encode()
    expected = {**sums, 'SHA256SUMS': hash_bytes(memory['SHA256SUMS'])}
    # No duplicate 3+ GiB staging tree: tar reads actual inputs directly.
    # Failed archives remain visibly incomplete, never accompanied by a checksum.
    with archive.open('xb') as output, gzip.GzipFile(fileobj=output, mode='wb', compresslevel=1, mtime=0) as gz, tarfile.open(fileobj=gz, mode='w|') as tf:
        for target in sorted(expected):
            info = tarfile.TarInfo(name + '/' + target)
            info.uid = info.gid = 0
            info.uname = info.gname = 'root'
            info.mode = modes.get(target, 0o644)
            if target in files:
                info.size = files[target].stat().st_size
                with files[target].open('rb') as src:
                    tf.addfile(info, src)
            else:
                info.size = len(memory[target])
                tf.addfile(info, io.BytesIO(memory[target]))
    actual = {}
    with tarfile.open(archive, 'r|gz') as tf:
        for member in tf:
            require(member.name.startswith(name + '/') and member.isfile(), 'unexpected outer archive entry')
            target = member.name[len(name) + 1:]
            require(target in expected and target not in actual and member.mode == modes.get(target, 0o644), 'unexpected/repeated outer member or mode')
            h = hashlib.sha256()
            with tf.extractfile(member) as src:
                for block in iter(lambda: src.read(1024 * 1024), b''):
                    h.update(block)
            actual[target] = h.hexdigest()
    require(actual == expected, 'outer archive independent readback failed')
    require(sha(a.selection) == a.selection_sha256 and sha(a.loader_map) == a.loader_map_sha256 and sha(a.shared_agent_input) == a.shared_agent_input_sha256, 'accepted source manifests changed during packaging')
    require(subprocess.check_output(['git', '-C', str(a.source_repository), 'rev-parse', 'HEAD'], text=True).strip() == a.commit, 'accepted HEAD changed during packaging')
    checksum = sha(archive)
    with sidecar.open('x', encoding='ascii', newline='\n') as output:
        output.write(checksum + '  ' + archive.name + '\n')
    print(json.dumps({'archive': str(archive), 'sha256': checksum, 'bytes': archive.stat().st_size, 'verified_files': len(actual), **config}))


if __name__ == '__main__':
    main()
