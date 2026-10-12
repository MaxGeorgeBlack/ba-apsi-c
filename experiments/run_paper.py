#!/usr/bin/env python3
"""Paper RQ1--RQ3 experiments. Only executables built in this project are used."""
import argparse, csv, datetime, hashlib, json, os, platform, random, subprocess, sys, time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RQ1_OVERLAP_TEMPLATE = [
    3,
    4,
    5,
    6,
    7,
    8,
    9,
    10,
    12,
    14,
    15,
    16,
    18,
    20,
    21,
    24,
    25,
    27,
    28,
    30,
    32,
    35,
    36,
    40,
    42,
    45,
    48,
    49,
    50,
    54,
    56,
    60,
    63,
    70,
]
DEFAULT_RQ1_OVERLAP = [0, 10, 20, 30, 40, 50, 60, 70, 100]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(args):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--out', type=Path, required=True)
    ap.add_argument('--sections', default='rq1,rq2,sum,rq3')
    ap.add_argument('--repeats', type=int, default=5)
    ap.add_argument('--warmup', type=int, default=1)
    ap.add_argument('--rq3-repeats', type=int, default=3)
    ap.add_argument('--rq3-warmup', type=int, default=0)
    ap.add_argument('--setup-mode', choices=['fresh', 'reuse'], default='fresh')
    ap.add_argument('--recover-mode', choices=['cold', 'prepared', 'prepared-fast'], default='cold')
    ap.add_argument(
        '--shuffle-cases', action='store_true', help='Randomize configuration execution order'
    )
    ap.add_argument('--order-seed', type=int, default=20261008)
    ap.add_argument('--cpu', type=int, help='Pin benchmark processes to one allowed WSL CPU')
    ap.add_argument(
        '--grid',
        action='store_true',
        help='Additionally run the old 10..100 x 10..100 x 0.3..0.7 size grid',
    )
    ap.add_argument(
        '--rq1-overlap-values',
        default=None,
        help='Intersection sizes: template for the 34 supplied points, or comma-separated 0..100',
    )
    ap.add_argument('--resume', action='store_true')
    a = ap.parse_args()
    if a.rq1_overlap_values == 'template':
        a.rq1_overlap_values = RQ1_OVERLAP_TEMPLATE.copy()
    elif a.rq1_overlap_values is None:
        a.rq1_overlap_values = DEFAULT_RQ1_OVERLAP.copy()
    else:
        try:
            a.rq1_overlap_values = [int(value) for value in a.rq1_overlap_values.split(',')]
        except ValueError:
            ap.error('intersection sizes must be template or comma-separated integers')
    if (
        not a.rq1_overlap_values
        or len(set(a.rq1_overlap_values)) != len(a.rq1_overlap_values)
        or any(value < 0 or value > 100 for value in a.rq1_overlap_values)
    ):
        ap.error('intersection sizes must be distinct values in 0..100')
    a.rq1_overlap_values.sort()
    if a.recover_mode != 'cold' and a.setup_mode != 'reuse':
        ap.error('prepared recovery requires --setup-mode reuse')
    sections = set(a.sections.split(','))
    out = a.out.resolve()
    if min(a.repeats, a.rq3_repeats) < 1 or min(a.warmup, a.rq3_warmup) < 0:
        ap.error('invalid repetitions')
    out.mkdir(parents=True, exist_ok=a.resume)
    (out / 'raw').mkdir(exist_ok=a.resume)
    (out / 'logs').mkdir(exist_ok=a.resume)
    params = ROOT / 'params/type-a-160-512.param'
    bench = ROOT / 'build/ba_bench'
    cases = []

    def phase(name, section, n, m, k, nc, maximum, u):
        for solver in ['bsgs', 'kangaroo']:
            ident = f'{name}_{solver}'
            command = [
                str(bench),
                '--n',
                str(n),
                '--m',
                str(m),
                '--k',
                str(k),
                '--capacity',
                str(nc),
                '--server-capacity',
                '100',
                '--max-value',
                str(maximum),
                '--universe',
                str(u),
                '--degree',
                '3',
                '--solver',
                solver,
                '--setup-mode',
                a.setup_mode,
                '--recover-mode',
                a.recover_mode,
                '--repeat',
                str(a.repeats),
                '--warmup',
                str(a.warmup),
                '--seed',
                '20260928',
                '--csv',
                str(out / 'raw' / f'{ident}.csv'),
            ]
            cases.append(dict(id=ident, section=section, command=command))

    if 'rq1' in sections:
        for n in range(10, 101, 10):
            phase(f'rq1_size_{n}', 'rq1_size', n, n, n // 2, 100, 100000, 200)
    if sections & {'rq1', 'rq1_overlap'}:
        for k in a.rq1_overlap_values:
            phase(f'rq1_overlap_{k}', 'rq1_overlap', 100, 100, k, 100, 100000, 200)
    if 'rq2' in sections:
        for n in range(10, 101, 10):
            phase(f'rq2_size_{n}', 'rq2', n, n, n // 2, n, 100000, 200)
    if a.grid:
        for n in range(10, 101, 10):
            for m in range(10, 101, 10):
                for tenth in range(3, 8):
                    phase(
                        f'grid_{n}_{m}_{tenth}',
                        'grid',
                        n,
                        m,
                        min(n, m) * tenth // 10,
                        100,
                        100000,
                        200,
                    )
    if 'sum' in sections:
        for total in range(0, 10000001, 500000):
            for solver in ['bsgs', 'kangaroo']:
                ident = f'sum_{total}_{solver}'
                cases.append(
                    dict(
                        id=ident,
                        section='sum',
                        command=[
                            str(ROOT / 'build/ba_dlp_bench'),
                            '10000000',
                            str(total),
                            solver,
                            str(a.repeats),
                            str(a.warmup),
                            str(out / 'raw' / f'{ident}.csv'),
                        ],
                    )
                )
    if 'rq3' in sections:
        for n, m, k in [(256, 10000, 32), (1024, 100000, 128), (4096, 1000000, 512)]:
            ident = f'rq3_{m}'
            cases.append(
                dict(
                    id=ident,
                    section='rq3',
                    command=[
                        str(ROOT / 'build/ba_compare'),
                        str(params),
                        str(n),
                        str(m),
                        str(k),
                        str(a.rq3_repeats),
                        str(a.rq3_warmup),
                        str(out / 'raw' / f'{ident}.csv'),
                    ],
                )
            )
    if a.shuffle_cases:
        random.Random(a.order_seed).shuffle(cases)
    if a.cpu is not None:
        if a.cpu not in os.sched_getaffinity(0):
            ap.error('CPU is outside the allowed affinity set')
        for case in cases:
            case['command'] = ['taskset', '-c', str(a.cpu)] + case['command']
    tracked = [
        *ROOT.glob('src/*.[ch]'),
        *ROOT.glob('include/*.h'),
        *ROOT.glob('tests/*.c'),
        ROOT / 'CMakeLists.txt',
    ]
    fingerprint = {str(p.relative_to(ROOT)): sha(p) for p in sorted(tracked)}
    manifest_path = out / 'manifest.json'
    if a.resume and manifest_path.exists():
        manifest = json.loads(manifest_path.read_text())
        if manifest['sources_sha256'] != fingerprint:
            raise SystemExit('Source changed; create a new result directory')
        previous = manifest['configuration']
        for key in [
            'setup_mode',
            'recover_mode',
            'shuffle_cases',
            'order_seed',
            'cpu',
            'repeats',
            'warmup',
            'sections',
            'rq1_overlap_values',
        ]:
            if previous.get(
                key,
                {
                    'setup_mode': 'fresh',
                    'recover_mode': 'cold',
                    'shuffle_cases': False,
                    'order_seed': 20261008,
                    'rq1_overlap_values': DEFAULT_RQ1_OVERLAP,
                }.get(key),
            ) != getattr(a, key):
                raise SystemExit(f'Configuration changed: {key}; create a new result directory')
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
            'configuration': vars(a) | {'out': str(out)},
        }
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
            expected = a.rq3_repeats * 5 if case['section'] == 'rq3' else a.repeats
            case['status'] = 'complete' if valid and len(rows) == expected else 'failed'
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
