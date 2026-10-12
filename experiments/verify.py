#!/usr/bin/env python3
"""Release/sanitizer regression and independent protocol and recovery checks."""
import os, subprocess, sys, tempfile, csv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(cmd, **kwargs):
    print('+', ' '.join(map(str, cmd)), flush=True)
    return subprocess.run(list(map(str, cmd)), cwd=ROOT, check=True, text=True, **kwargs)


def main():
    run(['bash', 'scripts/build.sh', '--sanitize'])
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
        with tempfile.TemporaryDirectory(prefix='ba_recovery_') as folder:
            folder = Path(folder)
            for solver in ['bsgs', 'kangaroo']:
                for total in [0, 100]:
                    path = folder / f'{solver}_{total}.csv'
                    run([ROOT / build / 'ba_dlp_bench', 100, total, solver, 1, 0, path], env=env)
                    rows = list(csv.DictReader(path.open()))
                    assert len(rows) == 1 and rows[0]['validation'] == 'PASS'
    print(
        'PASS all protocol, lifecycle, fixed-base and bounded-recovery checks', flush=True
    )


if __name__ == '__main__':
    main()
