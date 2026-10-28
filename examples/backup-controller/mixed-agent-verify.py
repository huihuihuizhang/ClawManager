"""Independent Linux verifier for fixed synthetic mixed-lab restore roots."""
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile

names = ['openclaw-lite', 'openclaw-pro', 'hermes-lite', 'hermes-pro', 'opencode-lite', 'opencode-pro', 'deepseek-harness-lite', 'deepseek-harness-pro']
checked = 0
wal_rows = 0
for i, name in enumerate(names):
    root = Path('/restored') / f'instance-{i+7}'
    uid = root.stat().st_uid
    assert uid == 12101 + i and root.stat().st_mode & 0o777 == 0o700
    own = root / '.backup-lab-fixtures/model-channel.json'
    other = Path('/restored') / f'instance-{7+(i+1)%len(names)}' / '.backup-lab-fixtures/model-channel.json'
    code = "from pathlib import Path;import sys;Path(sys.argv[1]).read_bytes()\ntry:Path(sys.argv[2]).read_bytes()\nexcept PermissionError:pass\nelse:raise RuntimeError('cross-instance access allowed')"
    subprocess.run([sys.executable, '-c', code, str(own), str(other)], user=uid, group=uid, extra_groups=[], check=True)
    for p in root.rglob('*'):
        if p.is_symlink() or not p.is_file():
            continue
        with p.open('rb') as f:
            if f.read(16) != b'SQLite format 3\0':
                continue
        with tempfile.TemporaryDirectory() as td:
            dst = Path(td) / 'db'
            shutil.copyfile(p, dst)
            for suffix in ('-wal', '-shm'):
                if Path(str(p)+suffix).exists():
                    shutil.copyfile(str(p)+suffix, str(dst)+suffix)
            with sqlite3.connect(dst) as db:
                assert db.execute('PRAGMA quick_check').fetchall() == [('ok',)]
                if p == root / '.backup-lab-fixtures/sessions.sqlite':
                    n = db.execute('SELECT COUNT(*) FROM messages WHERE owner=? AND instance=?', (uid,name)).fetchone()[0]
                    assert n == 300
                    wal_rows += n
                else:
                    checked += 1
assert wal_rows == 2400
report = {'native_sqlite_checked': checked, 'synthetic_wal_messages_recovered': wal_rows, 'cross_instance_uid_isolation_verified': 8, 'agents_started': False}
Path('/lab/mixed-linux-result.json').write_text(json.dumps(report, indent=2))
print(json.dumps(report))
