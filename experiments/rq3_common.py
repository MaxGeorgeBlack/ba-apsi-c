"""Data contract for the standalone, non-cryptographic RQ3 experiment."""

import csv
import hashlib
import json
import math
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
METHODS = ['ba-apsi-tag-match', 'sort-merge', 'hash-probe', 'cuckoo-probe', 'bloom-prefilter']


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read_csv(path):
    with Path(path).open(encoding='utf-8-sig', newline='') as stream:
        return list(csv.DictReader(stream))


def validate_settings(settings):
    assert settings and len({s['setting'] for s in settings}) == len(settings)
    for s in settings:
        assert re.fullmatch(r'[A-Za-z][A-Za-z0-9_]*', s['setting'])
        assert all(type(s[key]) is int for key in ['n', 'm', 'k'])
        assert 1 <= s['n'] <= 10000000 and 1 <= s['m'] <= 10000000
        assert 0 <= s['k'] <= min(s['n'], s['m'])


def load_observations(out):
    out = Path(out)
    manifest = json.loads((out / 'manifest.json').read_text(encoding='utf-8'))
    assert manifest['status'] == 'complete'
    config = manifest['configuration']
    validate_settings(config['settings'])
    formal, warmup = [], []
    assert len(manifest['cases']) == len(config['settings'])
    for case in manifest['cases']:
        s = next(s for s in config['settings'] if s['setting'] == case['setting'])
        raw = out / 'raw' / (s['setting'] + '.csv')
        assert case['status'] == 'complete' and sha(raw) == case['raw_sha256']
        rows = read_csv(raw)
        iterations = config['repeats'] + config['warmup']
        assert len(rows) == 5 * iterations
        for rep in range(iterations):
            block = rows[5 * rep : 5 * (rep + 1)]
            assert [row['method'] for row in block] == [METHODS[(rep + j) % 5] for j in range(5)]
            for row in block:
                assert int(row['rep']) == rep and int(row['seed']) == config['seed'] + rep
                assert tuple(int(row[x]) for x in ['n', 'm', 'k']) == (s['n'], s['m'], s['k'])
                assert row['validation'] == 'PASS' and row['rejected'] == '0'
                assert int(row['matches']) == s['k']
                for key in ['build_ms', 'probe_ms', 'total_ms']:
                    assert math.isfinite(float(row[key])) and float(row[key]) >= 0
                assert (
                    abs(float(row['total_ms']) - float(row['build_ms']) - float(row['probe_ms']))
                    <= 1.00001e-6
                )
                assert int(row['total_work']) == int(row['build_work']) + int(row['probe_work'])
                method, n, m, k = row['method'], s['n'], s['m'], s['k']
                if method == METHODS[0]:
                    assert int(row['hash_calls']) == 2 * n + m and int(row['index_checks']) == k
                elif method == METHODS[2]:
                    assert int(row['hash_calls']) == n + m
                elif method == METHODS[4]:
                    assert int(row['hash_calls']) == 2 * (n + m)
                    assert int(row['filter_passes']) - int(row['false_positives']) == k
                record = dict(setting=s['setting'], **row)
                (formal if rep >= config['warmup'] else warmup).append(record)
    assert len(formal) == len(config['settings']) * 5 * config['repeats']
    assert len(warmup) == len(config['settings']) * 5 * config['warmup']
    return manifest, formal, warmup
