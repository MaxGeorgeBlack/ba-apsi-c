#!/usr/bin/env python3
"""Run RQ4 modes serially; resume only verified complete modes, never partial rows."""
import argparse, datetime, hashlib, json, os, subprocess, time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


p = argparse.ArgumentParser(description=__doc__)
p.add_argument(
    '--python',
    required=True,
    help='Python environment with superlocalmemory==3.5.7 and local embedding dependencies',
)
p.add_argument('--out', type=Path, required=True)
p.add_argument('--wait-for', type=Path)
p.add_argument(
    '--resume',
    action='store_true',
    help='Skip complete modes after hash checks; partial mode folders must first be archived elsewhere',
)
a = p.parse_args()
if a.resume:
    if not a.out.is_dir():
        p.error('--resume requires an existing suite folder')
else:
    a.out.mkdir(parents=True, exist_ok=False)
if a.wait_for:
    print('WAITING FOR', a.wait_for, flush=True)
    while not a.wait_for.is_file():
        time.sleep(10)
# This cached Nomic worker needs more than the package default 1800 MiB RSS.
# These affect process lifetime/loading tolerance, not model outputs or gate code.
env = os.environ.copy()
env.setdefault('SLM_EMBED_WORKER_RSS_LIMIT_MB', '4096')
env.setdefault('SLM_EMBED_RESPONSE_TIMEOUT', '600')
for mode in ['bm25', 'mode_a', 'mode_b']:
    folder = a.out / mode
    if folder.exists():
        if not a.resume or not (folder / 'COMPLETE').is_file():
            raise SystemExit('Archive incomplete mode before retry: ' + str(folder))
        info = json.loads((folder / 'manifest.json').read_text())
        assert info['status'] == 'complete' and info['mode'] == mode
        assert info['script_sha256'] == sha(ROOT / 'experiments/run_slm.py')
        assert info['metrics_sha256'] == sha(ROOT / 'experiments/slm_metrics.py')
        assert info['gate_sha256'] == sha(ROOT / 'build/ba_gate')
        assert info['queries_sha256'] == sha(folder / 'queries.csv')
        for name, digest in info['inputs'].items():
            assert sha(ROOT / 'data/slm' / name) == digest
        print('VERIFIED SKIP', mode, flush=True)
        continue
    command = [a.python, str(ROOT / 'experiments/run_slm.py'), '--mode', mode, '--out', str(folder)]
    with (a.out / 'launches.jsonl').open('a') as f:
        f.write(
            json.dumps(
                {
                    'started_at': datetime.datetime.now().astimezone().isoformat(),
                    'mode': mode,
                    'command': command,
                    'environment': {
                        k: env.get(k)
                        for k in [
                            'HF_HUB_OFFLINE',
                            'TRANSFORMERS_OFFLINE',
                            'OMP_NUM_THREADS',
                            'OPENBLAS_NUM_THREADS',
                            'SLM_EMBED_WORKER_RSS_LIMIT_MB',
                            'SLM_EMBED_RESPONSE_TIMEOUT',
                        ]
                    },
                }
            )
            + '\n'
        )
    print('START', mode, flush=True)
    with (a.out / (mode + '.log')).open('x') as f:
        subprocess.run(command, env=env, stdout=f, stderr=subprocess.STDOUT, check=True)
    print('FINISHED', mode, flush=True)
(a.out / 'COMPLETE').write_text('PASS\n')
