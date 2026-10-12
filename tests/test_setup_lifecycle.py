#!/usr/bin/env python3
"""Check real protocol sessions under fresh and reused parameter periods."""
import argparse
import csv
import math
import os
import subprocess
import tempfile
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', default='build')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    phases = [
        'setup',
        'authorize_client',
        'authorize_server',
        'intersect',
        'encapsulate',
        'aggregate',
        'recover',
    ]
    observations = 0
    with tempfile.TemporaryDirectory(prefix='rq1_setup_lifecycle_') as directory:
        for mode, recovery, solver in [
            ('fresh', 'cold', 'bsgs'),
            ('reuse', 'cold', 'bsgs'),
            ('reuse', 'prepared', 'bsgs'),
            ('reuse', 'prepared', 'kangaroo'),
            ('reuse', 'prepared-fast', 'bsgs'),
            ('reuse', 'prepared-fast', 'kangaroo'),
        ]:
            for arithmetic in ['reference', 'optimized']:
                for overlap in [0, 2, 4]:
                    path = (
                        Path(directory) / f'{mode}_{recovery}_{solver}_{arithmetic}_{overlap}.csv'
                    )
                    command = [
                        str(root / args.build / 'ba_bench'),
                        '--n',
                        '4',
                        '--m',
                        '4',
                        '--k',
                        str(overlap),
                        '--capacity',
                        '4',
                        '--server-capacity',
                        '4',
                        '--universe',
                        '8',
                        '--max-value',
                        '10',
                        '--repeat',
                        '3',
                        '--warmup',
                        '1',
                        '--setup-mode',
                        mode,
                        '--recover-mode',
                        recovery,
                        '--solver',
                        solver,
                        '--mode',
                        arithmetic,
                        '--csv',
                        str(path),
                    ]
                    subprocess.run(
                        command, check=True, capture_output=True, text=True, env=os.environ
                    )
                    with path.open(newline='') as stream:
                        rows = list(csv.DictReader(stream))
                    assert len(rows) == 3
                    periods = {row['period_fingerprint'] for row in rows}
                    assert len(periods) == (1 if mode == 'reuse' else 3)
                    assert len({row['session_context'] for row in rows}) == 3
                    assert len({row['offline_setup_ms'] for row in rows}) == 1
                    assert len({row['offline_recover_ms'] for row in rows}) == 1
                    assert len({row['offline_dlp_fingerprint'] for row in rows}) == 1
                    for row in rows:
                        assert row['recover_mode'] == recovery
                        assert (float(row['offline_recover_ms']) > 0) == (recovery != 'cold')
                        if recovery != 'cold':
                            assert row['offline_dlp_fingerprint'] != '0' * 64
                            assert int(row['baby_steps']) == int(row['tame_steps']) == 0
                            assert int(row['offline_dlp_baby_steps']) == 7
                            assert int(row['offline_dlp_table_bytes']) == int(
                                row['dlp_peak_table_bytes']
                            )
                            if solver == 'kangaroo':
                                assert int(row['offline_dlp_tame_steps']) == (
                                    224 if recovery == 'prepared-fast' else 112
                                )
                                assert int(row['offline_dlp_attempts']) == 4
                                if recovery == 'prepared-fast':
                                    assert 1 <= int(row['attempts']) <= 4
                                    assert int(row['wild_steps']) <= 14 * int(row['attempts'])
                                else:
                                    assert int(row['wild_steps']) == 224
                            if recovery == 'prepared-fast' and (
                                solver == 'bsgs' or int(row['fallback'])
                            ):
                                assert int(row['giant_steps']) == int(row['expected_sum']) // 7
                        else:
                            assert row['offline_dlp_fingerprint'] == '0' * 64
                            assert int(row['offline_dlp_table_bytes']) == 0
                        assert (
                            row['expected_sum'] == row['recovered_sum']
                            and row['setup_mode'] == mode
                        )
                        assert (float(row['offline_setup_ms']) > 0) == (mode == 'reuse')
                        assert math.isclose(
                            sum(float(row[p + '_ms']) for p in phases),
                            float(row['total_ms']),
                            abs_tol=1e-5,
                        )
                        assert math.isclose(
                            sum(float(row[p + '_cpu_ms']) for p in phases),
                            float(row['total_cpu_ms']),
                            abs_tol=1e-5,
                        )
                        assert all(
                            float(row[p + suffix]) >= 0
                            for p in phases
                            for suffix in ['_ms', '_cpu_ms']
                        )
                        assert all(
                            int(row[p]) >= 0
                            for p in [
                                'voluntary_context_switches',
                                'involuntary_context_switches',
                                'minor_faults',
                                'major_faults',
                            ]
                        )
                    observations += len(rows)
    print(
        f'PASS {observations} sessions: reused periods, fresh contexts, cold/prepared/fast recovery, offline work, exact set/sum and timing accounting'
    )


if __name__ == '__main__':
    main()
