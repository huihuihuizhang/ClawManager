#!/usr/bin/env python3
"""Local staging only: bind a reviewed ELF and source receipt to an owned packet."""
import hashlib
import json
from pathlib import Path
import re
import shutil
import sys
import tarfile


def sha(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''):
            value.update(block)
    return value.hexdigest()


def sums(directory, target):
    paths = sorted(directory.rglob('*'))
    assert not any(path.is_symlink() for path in paths)
    target.write_text(''.join(sha(path) + '  ' + path.relative_to(directory).as_posix() + '\n'
                              for path in paths if path.is_file() and path != target), encoding='utf-8')


def main():
    assert len(sys.argv) == 5
    root, repo, out = map(Path, sys.argv[1:4])
    expected_elf = sys.argv[4]
    assert re.fullmatch('[a-f0-9]{64}', expected_elf)
    assert root.is_absolute() and (root / '.owner').read_text().strip() in {
        'supervisor-native-review-20261102', 'supervisor-combination-review-20261102',
    }
    assert not out.exists() and out.parent.resolve() == repo.resolve()
    meta = json.loads((root / 'source-pins.json').read_text(encoding='utf-8-sig'))
    commit = meta['snapshot_commit']
    assert re.fullmatch('[a-f0-9]{40}', commit)
    short = commit[:8]
    source = (root / 'source').resolve()
    for line in (root / 'source-receipt/SOURCE_FILES.sha256').read_text().splitlines():
        checksum = re.fullmatch(r'([a-f0-9]{64}) [ *](.+)', line)
        assert checksum is not None, 'invalid source checksum record'
        digest, name = checksum.groups()
        path = source / name
        assert path.resolve().is_relative_to(source) and not path.is_symlink()
        assert path.is_file() and sha(path) == digest, name
    binary = root / 'bin/systembackupexecution-linux-amd64.test'
    with binary.open('rb') as stream:
        header = stream.read(20)
    assert header[:6] == b'\x7fELF\x02\x01' and int.from_bytes(header[18:20], 'little') == 62
    assert sha(binary) == expected_elf
    fixture = source / 'scripts/system-backup-d-kube-mysql-fixture.py'
    assert sha(fixture) in {
        '81fc43a5f571a5b8a25f6efb1253c579c7661aa771a4dcd1659a8c5ab539f265',
        'fb8218f18cba92057497038998f920bc30e127789df0562d2be350790aaab873',
    }
    fixture_bytes = fixture.read_bytes().replace(b'\r\n', b'\n')
    fixture_sha = hashlib.sha256(fixture_bytes).hexdigest()
    assert fixture_sha == 'fb8218f18cba92057497038998f920bc30e127789df0562d2be350790aaab873'
    assert (repo / fixture.relative_to(source)).read_bytes().replace(b'\r\n', b'\n') == fixture_bytes
    bundle = root / 'bundle'
    assert (bundle / 'SOURCE_COMMIT').read_text().strip() == commit
    shutil.copyfile(repo / 'scripts/system-backup-supervisor-native-window-run.sh', bundle / 'run-diagnostic.sh')
    for directory in (source / 'backend').rglob('testdata'):
        if directory.is_dir():
            shutil.copytree(directory, bundle / directory.relative_to(source), dirs_exist_ok=True)
    shutil.copytree(source / 'contracts/system-backup/v12', bundle / 'contracts/system-backup/v12', dirs_exist_ok=True)
    shutil.copyfile(root / 'source-pins.json', bundle / 'SOURCE_REVIEW.json')
    sums(bundle, bundle / 'SHA256SUMS')
    package = root / ('clawmanager-native-' + short)
    assert not package.exists()
    package.mkdir()
    shutil.copytree(bundle, package / 'bundle')
    review = {
        'scope': 'owned fixture DATA only; not page or production acceptance',
        'source_snapshot': commit, 'source_base': meta['base_commit'],
        'elf_sha256': expected_elf, 'platform': 'linux/amd64', 'cgo': False,
        'selected_tests': ['TestAPermitTimingOriginalThirtySecondNativeMySQL',
                           'TestOriginalHeldPrefixSameRPCControlDifferentialMySQL'],
        'original_key_window_seconds': 30, 'whole_harness_timeout_minutes': 15,
        'native_executed': False, 'full_page_acceptance': False,
        'installation_owner_batch_included': (source / 'backend/internal/systembackupinstallationowner/record.go').is_file(),
        'installation_owner_tests_selected': False,
        'migration134_included': (source / 'backend/internal/db/migrations/134_backup_v2_installation_owner_authority.sql').is_file(),
    }
    (package / 'BUILD-REVIEW.json').write_text(json.dumps(review, indent=2) + '\n', encoding='utf-8')
    sums(package, package / 'DELIVERY_SHA256SUMS')
    out.mkdir()
    (out / '.owner').write_text('supervisor-native-delivery-20261102\n')
    archive = out / (package.name + '.tar.gz')
    with tarfile.open(archive, 'w:gz') as stream:
        stream.add(package, arcname=package.name)
    (out / fixture.name).write_bytes(fixture_bytes)
    entry = (repo / 'scripts/system-backup-supervisor-native-1c350462.sh').read_text()
    old_commit = '1c3504620e3b456daf95f53adc647f8dd8d002b0'
    old_archive = '27f426891de91f6a1f7f702e7cee8ad01efdbbca2d17a5c5b51fa3aea2e8d847'
    assert old_commit in entry and old_archive in entry
    entry = entry.replace(old_commit, commit).replace('875e3960b9b67cc5108b1aad23936214b9984319', commit)
    entry = entry.replace('1c350462', short).replace(old_archive, sha(archive))
    entry = entry.replace('fb8218f18cba92057497038998f920bc30e127789df0562d2be350790aaab873', fixture_sha)
    entry = entry.replace('# Native candidate is pinned to ' + short + ' (backend b98 A4+B6); fixture is pinned to 875e3960.',
                          '# Frozen source snapshot ' + commit + '; both native diagnostics must pass.')
    needle = '[[ -f $archive && ! -L $archive ]]'
    assert needle in entry
    site_check = (
        "site_uid=$(kubectl --context 'kubernetes-admin@kubernetes' get namespace 'clawmanager-zhanghui08-system' -o 'jsonpath={.metadata.uid}')\n"
        "[[ $site_uid = '337cfe30-2c17-4b8e-b32a-760778b8098e' ]] || { echo 'Target namespace identity changed; no fixture resources created.' >&2; exit 64; }\n"
    )
    entry = entry.replace(needle, site_check + needle, 1)
    entry = entry.replace(
        "elif re.search(r'^--- (PASS|FAIL): TestAPermit|stage=database-|retained failed original SQL namespace', line):",
        "elif re.search(r'^--- (PASS|FAIL): (TestAPermit|TestOriginalHeldPrefix)|stage=database-|retained failed original SQL namespace', line) or 'same-RPC original/candidate Authorize DATA' in line or 'same-RPC original prefix differential refused' in line:")
    entry_file = out / ('run-native-' + short + '.sh')
    entry_file.write_text(entry, encoding='utf-8', newline='\n')
    review.update({
        'archive': archive.name, 'archive_sha256': sha(archive), 'archive_bytes': archive.stat().st_size,
        'entry': entry_file.name, 'entry_sha256': sha(entry_file), 'fixture': fixture.name,
        'fixture_sha256': fixture_sha, 'fixture_line_endings': 'LF; content equals frozen source after CRLF normalization',
        'runtime_runner_sha256': sha(package / 'bundle/run-diagnostic.sh'),
        'expected_site_namespace_uid': '337cfe30-2c17-4b8e-b32a-760778b8098e',
        'delivery_directory': str(out),
    })
    (out / 'DELIVERY.json').write_text(json.dumps(review, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'delivery_directory': str(out), 'archive': archive.name,
                      'archive_sha256': review['archive_sha256'], 'archive_bytes': review['archive_bytes'],
                      'source_snapshot': commit, 'native_executed': False}))


if __name__ == '__main__':
    main()
