# Running the benchmarks

Run the commands below in Ubuntu 24.04 or Ubuntu on Windows through WSL. From PowerShell, enter WSL with `wsl -d Ubuntu`.

## Install dependencies

```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake libssl-dev libgmp-dev flex bison curl tar python3 git
```

Install PBC 0.5.14 if it is not already available:

```bash
pbc_dir=$(mktemp -d)
curl -fL https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz -o "$pbc_dir/pbc.tar.gz"
printf '%s  %s\n' 772527404117587560080241cedaf441e5cac3269009cdde4c588a1dce4c23d2 "$pbc_dir/pbc.tar.gz" | sha256sum -c -
tar -xzf "$pbc_dir/pbc.tar.gz" -C "$pbc_dir"
pushd "$pbc_dir/pbc-0.5.14"
./configure --prefix=/usr/local
make -j"$(nproc)"
sudo make install
sudo ldconfig
popd
```

## Build and validate

```bash
git clone https://github.com/MaxGeorgeBlack/ba-apsi-c.git
cd ba-apsi-c
bash scripts/build.sh
```

If the source directory already exists, run `bash scripts/build.sh` from its root. The build requires CMake >= 3.18 and OpenSSL >= 3.0.

Run the full protocol, recovery, lifecycle and fixed-base checks, including AddressSanitizer and UndefinedBehaviorSanitizer:

```bash
python3 experiments/verify.py
```

## Measure stage latency

Measure setup, client/server authorization, intersection, encapsulation, aggregation and recovery latency for one configuration:

```bash
mkdir -p results
./build/ba_bench --n 100 --m 100 --k 50 --max-value 1000 \
  --repeat 5 --warmup 1 --csv results/stage_latency.csv
```

Compare recovery solvers or arithmetic modes by adding `--solver bsgs`, `--solver kangaroo`, `--mode optimized` or `--mode reference`. Use `./build/ba_bench --help` to inspect all options.

Measure stage latency as both set sizes increase, keeping the public capacity and recovery bound fixed:

```bash
python3 experiments/run_metrics.py --metrics phase-time --out results/size_latency \
  --setup-mode reuse --shuffle-cases --repeats 15 --warmup 3
```

## Measure latency versus intersection size

Keep both sets at 100 elements and vary their intersection size:

```bash
python3 experiments/run_metrics.py --metrics intersection-time --out results/intersection_latency \
  --intersection-sizes template --setup-mode reuse --recover-mode prepared-fast \
  --shuffle-cases --repeats 15 --warmup 3
```

Replace `template` with a comma-separated list such as `0,10,20,30,40,50,60,70,100` to choose intersection sizes.

## Measure the recovery fraction of total latency

Vary the client capacity and its associated recovery bound while recording all protocol stages:

```bash
python3 experiments/run_metrics.py --metrics recovery-share --out results/recovery_fraction \
  --repeats 5 --warmup 1
```

Calculate the recovery percentage for each recorded run as `100 * recover_ms / total_ms`. To print the average of these percentages for each configuration:

```bash
python3 - <<'PY'
import csv
import statistics
from pathlib import Path

for path in sorted(Path('results/recovery_fraction/raw').glob('*.csv')):
    with path.open(newline='') as stream:
        rows = list(csv.DictReader(stream))
    shares = [100 * float(row['recover_ms']) / float(row['total_ms']) for row in rows]
    print(path.stem, statistics.mean(shares))
PY
```

## Measure bounded recovery latency

Measure cold recovery latency across aggregate values within a fixed public bound:

```bash
python3 experiments/run_metrics.py --metrics recovery-time --out results/recovery_latency \
  --repeats 5 --warmup 1
```

For one bound, aggregate value and solver, use `ba_dlp_bench BOUND SUM SOLVER REPEATS WARMUP CSV`:

```bash
./build/ba_dlp_bench 10000000 5000000 kangaroo 5 1 results/recovery_value.csv
```

## Configure measurement runs

Select multiple metrics with a comma-separated `--metrics` list. Each sweep runs BSGS and Kangaroo sequentially. Warmup runs are excluded from the saved observations.

For protocol stage measurements, use `--setup-mode fresh` to include complete initialization in every run, or `--setup-mode reuse` to initialize once per configuration. Choose `--recover-mode cold`, `prepared` or `prepared-fast`; the latter two require `--setup-mode reuse`. Reused initialization and recovery preprocessing costs are recorded separately in `offline_setup_ms` and `offline_recover_ms`. Treat repeated offline fields as one measurement per configuration. The standalone `recovery-time` sweep supports only cold recovery.

Use a new output directory or CSV filename for each run. Add `--resume` to the batch driver only when its recorded inputs and configuration are unchanged. To pin benchmark processes to a CPU, add `--cpu N`, choosing N from the affinity list reported by `taskset -pc $$`.
