#!/usr/bin/env python3
"""Measure the current standalone C matching kernels; never read legacy results."""

import argparse
import datetime
import json
import os
import platform
import random
import subprocess
import time
from pathlib import Path

from rq3_common import ROOT, load_observations, sha, validate_settings


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--settings', type=Path, default=ROOT / 'experiments/rq3_settings.json')
    parser.add_argument('--repeats', type=int, default=15)
    parser.add_argument('--warmup', type=int, default=3)
    parser.add_argument('--seed', type=int, default=20261008)
    parser.add_argument('--order-seed', type=int, default=20261008)
    parser.add_argument('--cpu', type=int, default=0, help='WSL CPU number; -1 disables pinning')
    args = parser.parse_args()
    if not 2 <= args.repeats <= 1000 or not 0 <= args.warmup <= 998:
        parser.error('Require repeats >= 2, warmup >= 0, and their sum <= 1000')
    if (
        args.repeats + args.warmup > 1000
        or not 0 <= args.seed <= 2**64 - args.repeats - args.warmup
    ):
        parser.error('Iteration count or seed exceeds C limits')
    if args.cpu < -1 or (args.cpu >= 0 and args.cpu not in os.sched_getaffinity(0)):
        parser.error('CPU is outside the WSL process affinity mask')
    settings = json.loads(args.settings.read_text(encoding='utf-8'))
    validate_settings(settings)
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    for directory in ['raw', 'bin', 'source_snapshot']:
        (out / directory).mkdir()
    sources = [
        'experiments/rq3_intersect_basic.c',
        'experiments/run_rq3_origin.py',
        'experiments/rq3_common.py',
    ]
    source_hashes = {}
    for rel in sources:
        source_hashes[rel] = sha(ROOT / rel)
        (out / 'source_snapshot' / (rel.replace('/', '__') + '.txt')).write_bytes(
            (ROOT / rel).read_bytes()
        )
    (out / 'settings.json').write_text(json.dumps(settings, indent=2) + '\n')
    source = ROOT / 'experiments/rq3_intersect_basic.c'
    binary = out / 'bin/rq3_intersect_basic'
    build_command = [
        'gcc',
        '-std=c11',
        '-O3',
        '-Wall',
        '-Wextra',
        '-Wshadow',
        '-Wformat=2',
        str(source),
        '-o',
        str(binary),
    ]
    build = subprocess.run(build_command, text=True, capture_output=True)
    (out / 'build.log').write_text(build.stdout + build.stderr)
    build.check_returncode()
    validation = subprocess.run([str(binary), '--self-test'], text=True, capture_output=True)
    (out / 'validation_release.log').write_text(validation.stdout + validation.stderr)
    validation.check_returncode()
    asan = out / 'bin/rq3_intersect_basic_asan'
    asan_command = [
        'gcc',
        '-std=c11',
        '-O1',
        '-g',
        '-Wall',
        '-Wextra',
        '-fsanitize=address,undefined',
        '-fno-omit-frame-pointer',
        str(source),
        '-o',
        str(asan),
    ]
    build_asan = subprocess.run(asan_command, text=True, capture_output=True)
    (out / 'build_asan.log').write_text(build_asan.stdout + build_asan.stderr)
    build_asan.check_returncode()
    env = dict(
        os.environ, ASAN_OPTIONS='detect_leaks=1:halt_on_error=1', UBSAN_OPTIONS='halt_on_error=1'
    )
    validation_asan = subprocess.run(
        [str(asan), '--self-test'], env=env, text=True, capture_output=True
    )
    (out / 'validation_asan.log').write_text(validation_asan.stdout + validation_asan.stderr)
    validation_asan.check_returncode()
    assert all(sha(ROOT / rel) == digest for rel, digest in source_hashes.items())
    manifest = dict(
        status='running',
        time_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        scope='Plaintext set intersection; BA-APSI is a precomputed-label structural model',
        configuration=dict(
            settings=settings,
            repeats=args.repeats,
            warmup=args.warmup,
            seed=args.seed,
            order_seed=args.order_seed,
            cpu=args.cpu,
        ),
        platform=platform.platform(),
        cpu=subprocess.check_output(['lscpu'], text=True),
        compiler=subprocess.check_output(['gcc', '--version'], text=True),
        compile_command=build_command,
        sanitizer_compile_command=asan_command,
        sources_sha256=source_hashes,
        binary_sha256=sha(binary),
        protocol_reference_sha256=sha(ROOT / 'src/protocol.c'),
        cases=[],
    )
    order = settings.copy()
    random.Random(args.order_seed).shuffle(order)
    manifest['execution_order'] = [s['setting'] for s in order]
    path = out / 'manifest.json'
    path.write_text(json.dumps(manifest, indent=2) + '\n')
    for s in order:
        command = [
            str(binary),
            str(s['n']),
            str(s['m']),
            str(s['k']),
            str(args.repeats + args.warmup),
            str(args.seed),
        ]
        if args.cpu >= 0:
            command = ['taskset', '-c', str(args.cpu), *command]
        print(f"RUN {s['setting']}: n={s['n']} m={s['m']} k={s['k']}; 5 methods", flush=True)
        start = time.monotonic()
        with (out / 'raw' / (s['setting'] + '.csv')).open('w') as output:
            result = subprocess.run(command, stdout=output, stderr=subprocess.PIPE, text=True)
        (out / 'raw' / (s['setting'] + '.log')).write_text(result.stderr)
        case = dict(
            setting=s['setting'],
            command=command,
            elapsed_seconds=time.monotonic() - start,
            exit_code=result.returncode,
            status='complete' if result.returncode == 0 else 'failed',
            raw_sha256=sha(out / 'raw' / (s['setting'] + '.csv')),
        )
        manifest['cases'].append(case)
        path.write_text(json.dumps(manifest, indent=2) + '\n')
        result.check_returncode()
        print(f"PASS {s['setting']}", flush=True)
    assert all(sha(ROOT / rel) == digest for rel, digest in source_hashes.items())
    manifest['status'] = 'complete'
    path.write_text(json.dumps(manifest, indent=2) + '\n')
    _, formal, warmup = load_observations(out)
    print(
        f'Measurements complete: {len(formal)} formal, {len(warmup)} warmup observations.',
        flush=True,
    )


if __name__ == '__main__':
    main()
