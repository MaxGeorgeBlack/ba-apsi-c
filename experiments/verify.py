#!/usr/bin/env python3
"""Release/sanitizer regression and independent experiment-interface checks."""
import os, subprocess, sys, tempfile, csv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(cmd, **kwargs):
    print('+', ' '.join(map(str, cmd)), flush=True)
    return subprocess.run(list(map(str, cmd)), cwd=ROOT, check=True, text=True, **kwargs)


def main():
    run(['bash', 'scripts/build.sh', '--sanitize'])
    run([sys.executable, 'tests/test_experiment_metrics.py'])
    params = ROOT / 'params/type-a-160-512.param'
    for build in ['build', 'build-asan']:
        flags = (
            ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
            if build == 'build-asan'
            else []
        )
        binary = ROOT / build / 'ba_precompute_check'
        run(
            [
                'cc',
                '-std=c11',
                '-Wall',
                '-Wextra',
                *flags,
                '-Iinclude',
                'experiments/precompute_check.c',
                ROOT / build / 'libbaapsi.a',
                '-lpbc',
                '-lgmp',
                '-lcrypto',
                '-o',
                binary,
            ]
        )
        env = os.environ | {
            'ASAN_OPTIONS': 'detect_leaks=1:halt_on_error=1',
            'UBSAN_OPTIONS': 'halt_on_error=1',
        }
        run([sys.executable, 'tests/test_setup_lifecycle.py', '--build', build], env=env)
        run([binary, params], env=env)
        with tempfile.TemporaryDirectory(prefix='ba_experiment_') as folder:
            folder = Path(folder)
            run(
                [ROOT / build / 'ba_compare', params, 8, 11, 5, 1, 0, folder / 'compare.csv'],
                env=env,
            )
            rows = list(csv.DictReader((folder / 'compare.csv').open()))
            assert len(rows) == 5 and all(r['validation'] == 'PASS' for r in rows)
            for solver in ['bsgs', 'kangaroo']:
                for total in [0, 100]:
                    path = folder / f'{solver}_{total}.csv'
                    run([ROOT / build / 'ba_dlp_bench', 100, total, solver, 1, 0, path], env=env)
                    rows = list(csv.DictReader(path.open()))
                    assert len(rows) == 1 and rows[0]['validation'] == 'PASS'
            result = run(
                [ROOT / build / 'ba_gate', params, 12],
                input='3 4\n1 2 4\n2 4 6 8\n0 0\n\n\n1 1\n12\n12\n',
                capture_output=True,
                env=env,
            )
            lines = result.stdout.splitlines()
            assert lines[0] == 'READY'
            assert [set(map(int, line.split()[4:])) for line in lines[1:]] == [{2, 4}, set(), {12}]
            assert [int(line.split()[3]) for line in lines[1:]] == [2, 0, 1]
    print(
        'PASS all current protocol, baseline, fixed-base, DLP, gate and metric checks', flush=True
    )


if __name__ == '__main__':
    main()
