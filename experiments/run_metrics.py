#!/usr/bin/env python3
"""Measure phase time, intersection-size effects, and aggregate recovery cost."""
import argparse, csv, datetime, hashlib, json, os, platform, random, subprocess, time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
METRICS = ('phase-time', 'intersection-time', 'recovery-share', 'recovery-time')
INTERSECTION_TEMPLATE = [
    3, 4, 5, 6, 7, 8, 9, 10, 12, 14, 15, 16, 18, 20, 21, 24, 25,
    27, 28, 30, 32, 35, 36, 40, 42, 45, 48, 49, 50, 54, 56, 60, 63, 70,
]
DEFAULT_INTERSECTION_SIZES = [0, 10, 20, 30, 40, 50, 60, 70, 100]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(args):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--out', type=Path, required=True, help='New output directory')
    ap.add_argument(
        '--metrics', default='phase-time,intersection-time,recovery-share',
        help='Comma-separated selection: ' + ', '.join(METRICS),
    )
    ap.add_argument('--repeats', type=int, default=5)
    ap.add_argument('--warmup', type=int, default=1)
    ap.add_argument('--setup-mode', choices=['fresh', 'reuse'], default='fresh')
    ap.add_argument('--recover-mode', choices=['cold', 'prepared', 'prepared-fast'], default='cold')
    ap.add_argument(
        '--shuffle-cases', action='store_true', help='Randomize configuration execution order'
    )
    ap.add_argument('--order-seed', type=int, default=20261008)
    ap.add_argument('--cpu', type=int, help='Pin benchmark processes to one allowed Linux CPU')
    ap.add_argument(
        '--intersection-sizes', default=None,
        help='Intersection sizes: template for 34 supplied points, or comma-separated 0..100',
    )
    ap.add_argument('--resume', action='store_true')
    a = ap.parse_args()
    a.metrics = [value.strip() for value in a.metrics.split(',')]
    if not a.metrics or any(value not in METRICS for value in a.metrics):
        ap.error('metrics must be a nonempty selection from: ' + ', '.join(METRICS))
    if len(set(a.metrics)) != len(a.metrics):
        ap.error('metrics must be distinct')
    if a.intersection_sizes == 'template':
        a.intersection_sizes = INTERSECTION_TEMPLATE.copy()
    elif a.intersection_sizes is None:
        a.intersection_sizes = DEFAULT_INTERSECTION_SIZES.copy()
    else:
        try:
            a.intersection_sizes = [int(value) for value in a.intersection_sizes.split(',')]
        except ValueError:
            ap.error('intersection sizes must be template or comma-separated integers')
    if (
        not a.intersection_sizes
        or len(set(a.intersection_sizes)) != len(a.intersection_sizes)
        or any(value < 0 or value > 100 for value in a.intersection_sizes)
    ):
        ap.error('intersection sizes must be distinct values in 0..100')
    a.intersection_sizes.sort()
    if a.recover_mode != 'cold' and a.setup_mode != 'reuse':
        ap.error('prepared recovery requires --setup-mode reuse')
    if 'recovery-time' in a.metrics and a.recover_mode != 'cold':
        ap.error('recovery-time measures cold recovery; use --recover-mode cold')
    warmup_limit = 1000 if 'recovery-time' in a.metrics else 10000
    if not 1 <= a.repeats <= 10000 or not 0 <= a.warmup <= warmup_limit:
        ap.error(f'repeats must be in 1..10000 and warmup in 0..{warmup_limit}')
    if a.cpu is not None:
        if not hasattr(os, 'sched_getaffinity'):
            ap.error('CPU affinity requires Linux')
        if a.cpu not in os.sched_getaffinity(0):
            ap.error('CPU is outside the allowed affinity set')

    out = a.out.resolve()
    params = ROOT / 'params/type-a-160-512.param'
    bench = ROOT / 'build/ba_bench'
    cases = []

    def phase(metric, variable, value, n, m, k, capacity, maximum, universe):
        for solver in ['bsgs', 'kangaroo']:
            ident = f'{metric}_{variable}_{value}_{solver}'
            command = [
                str(bench), '--n', str(n), '--m', str(m), '--k', str(k),
                '--capacity', str(capacity), '--server-capacity', '100',
                '--max-value', str(maximum), '--universe', str(universe),
                '--degree', '3', '--solver', solver,
                '--setup-mode', a.setup_mode, '--recover-mode', a.recover_mode,
                '--repeat', str(a.repeats), '--warmup', str(a.warmup),
                '--seed', '20260928', '--csv', str(out / 'raw' / f'{ident}.csv'),
            ]
            cases.append(dict(id=ident, section=metric, command=command))

    if 'phase-time' in a.metrics:
        for n in range(10, 101, 10):
            phase('phase-time', 'size', n, n, n, n // 2, 100, 100000, 200)
    if 'intersection-time' in a.metrics:
        for k in a.intersection_sizes:
            phase('intersection-time', 'intersection', k, 100, 100, k, 100, 100000, 200)
    if 'recovery-share' in a.metrics:
        for n in range(10, 101, 10):
            phase('recovery-share', 'size', n, n, n, n // 2, n, 100000, 200)
    if 'recovery-time' in a.metrics:
        for total in range(0, 10000001, 500000):
            for solver in ['bsgs', 'kangaroo']:
                ident = f'recovery-time_sum_{total}_{solver}'
                cases.append(dict(
                    id=ident, section='recovery-time',
                    command=[
                        str(ROOT / 'build/ba_dlp_bench'), '10000000', str(total), solver,
                        str(a.repeats), str(a.warmup), str(out / 'raw' / f'{ident}.csv'),
                    ],
                ))
    if a.shuffle_cases:
        random.Random(a.order_seed).shuffle(cases)
    if a.cpu is not None:
        for case in cases:
            case['command'] = ['taskset', '-c', str(a.cpu)] + case['command']

    tracked = [
        *ROOT.glob('src/*.[ch]'), *ROOT.glob('include/*.h'), *ROOT.glob('tests/*.c'),
        ROOT / 'CMakeLists.txt', Path(__file__).resolve(), params,
    ]
    fingerprint = {str(p.relative_to(ROOT)): sha(p) for p in sorted(tracked)}
    configuration = vars(a) | {'out': str(out)}
    manifest_path = out / 'manifest.json'
    if a.resume and manifest_path.exists():
        manifest = json.loads(manifest_path.read_text())
        if manifest['sources_sha256'] != fingerprint:
            raise SystemExit('Source or parameters changed; create a new output directory')
        previous = manifest['configuration']
        for key, value in configuration.items():
            if key != 'resume' and previous.get(key) != value:
                raise SystemExit(f'Configuration changed: {key}; create a new output directory')
    else:
        manifest = {
            'created': datetime.datetime.now().astimezone().isoformat(),
            'platform': platform.platform(),
            'compiler': run(['cc', '--version']),
            'cpu': run(['lscpu']),
            'memory': run(['free', '-b']),
            'openssl': run(['openssl', 'version']),
            'ldd': run(['ldd', str(bench)]),
            'build_flags': (ROOT / 'build/CMakeFiles/baapsi.dir/flags.make').read_text(),
            'sources_sha256': fingerprint,
            'parameter_sha256': sha(params),
            'cases': [],
            'configuration': configuration,
        }
    out.mkdir(parents=True, exist_ok=a.resume)
    (out / 'raw').mkdir(exist_ok=a.resume)
    (out / 'logs').mkdir(exist_ok=a.resume)
    known = {c['id']: c for c in manifest['cases']}
    for case in cases:
        if known.get(case['id'], {}).get('status') == 'complete':
            continue
        raw = out / 'raw' / f'{case["id"]}.csv'
        if raw.exists():
            raise SystemExit(
                f'Incomplete existing output retained: {raw}; move it aside before resume'
            )
        print('RUN', case['id'], flush=True)
        case['started'] = datetime.datetime.now().astimezone().isoformat()
        case['status'] = 'running'
        manifest['cases'].append(case)
        manifest_path.write_text(json.dumps(manifest, indent=2))
        start = time.monotonic()
        with (out / 'logs' / f'{case["id"]}.log').open('w') as log:
            result = subprocess.run(case['command'], stdout=log, stderr=subprocess.STDOUT)
        case['elapsed_seconds'] = time.monotonic() - start
        case['exit_code'] = result.returncode
        if result.returncode:
            case['status'] = 'failed'
        else:
            with raw.open() as f:
                rows = list(csv.DictReader(f))
            valid = all(
                r.get('validation', 'PASS') == 'PASS'
                and ('expected_sum' not in r or r['expected_sum'] == r['recovered_sum'])
                for r in rows
            )
            case['status'] = 'complete' if valid and len(rows) == a.repeats else 'failed'
            case['rows'] = len(rows)
            case['raw_sha256'] = sha(raw)
        manifest_path.write_text(json.dumps(manifest, indent=2))
        if case['status'] != 'complete':
            raise SystemExit('FAILED ' + case['id'])
        print('OK', case['id'], round(case['elapsed_seconds'], 2), 's', flush=True)
    (out / 'COMPLETE').write_text(datetime.datetime.now().astimezone().isoformat() + '\n')
    print('COMPLETE', out, flush=True)


if __name__ == '__main__':
    main()
