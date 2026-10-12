# 执行说明

以下命令在 Ubuntu 24.04 或 Windows 的 Ubuntu WSL 中执行。PowerShell 中先运行 `wsl -d Ubuntu`。

## 安装依赖

```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake libssl-dev libgmp-dev flex bison curl tar python3 python3-venv libgomp1 git
```

安装 PBC 0.5.14；已安装该版本时可跳过：

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

## 构建与验证

```bash
git clone https://github.com/MaxGeorgeBlack/ba-apsi-c.git
cd ba-apsi-c
bash scripts/build.sh
```

在已有代码目录中直接执行 `bash scripts/build.sh`。构建要求 CMake ≥ 3.18、OpenSSL ≥ 3.0。

执行包含 ASan/UBSan、协议生命周期、固定基预计算、恢复算法、求交基线及门控接口的验证：

```bash
python3 experiments/verify.py
```

## 单组协议测试

```bash
./build/ba_bench --n 100 --m 100 --k 50 --max-value 1000 --repeat 5 --warmup 1
./build/ba_bench --solver kangaroo --n 100 --m 100 --k 50
./build/ba_bench --mode reference --n 100 --m 100 --k 50
./build/ba_bench --help
```

将公共初始化和恢复预处理复用到多个会话：

```bash
./build/ba_bench --solver kangaroo --setup-mode reuse --recover-mode prepared-fast \
  --n 100 --m 100 --k 50 --capacity 100 --max-value 100000 --repeat 15 --warmup 3
```

`--recover-mode` 可选 `cold`、`prepared`、`prepared-fast`；后两者要求 `--setup-mode reuse`。
保存逐次输出时，先执行 `mkdir -p results`，再添加 `--csv results/my_run.csv`。CSV 文件必须尚不存在。

## 批量实验

每次指定新的输出目录；所有命令从仓库根目录执行。

```bash
# RQ1、RQ2、聚合值扫描及完整密码求交 RQ3
python3 experiments/run_paper.py --out results/rq123 \
  --sections rq1,rq2,sum,rq3 --repeats 5 --warmup 1 --rq3-repeats 3 --rq3-warmup 0

# RQ1：复用公共初始化
python3 experiments/run_paper.py --out results/rq1 --sections rq1 \
  --setup-mode reuse --shuffle-cases --repeats 15 --warmup 3

# RQ1：34 个交集规模，复用恢复预处理
python3 experiments/run_paper.py --out results/rq1_overlap --sections rq1_overlap \
  --rq1-overlap-values template --setup-mode reuse --recover-mode prepared-fast \
  --shuffle-cases --repeats 15 --warmup 3

# RQ3：独立集合求交测试，BA-APSI 使用预生成标签的匹配模型
python3 experiments/run_rq3_origin.py --out results/rq3_basic \
  --settings experiments/rq3_settings.json --repeats 15 --warmup 3 --cpu -1
```

修改 `experiments/rq3_settings.json` 可设置独立 RQ3 的集合和交集规模。
`run_paper.py` 的 `--sections` 选择实验，`--rq1-overlap-values` 接受逗号分隔的交集规模。
需要绑核时为驱动添加 `--cpu N`，其中 N 必须在 `taskset -pc $$` 显示的可用 CPU 中。
仅在输入与配置不变且已完成文件保持完整时使用 `run_paper.py --resume`。

## RQ4 记忆检索与门控

使用 Python 3.11–3.14 创建环境；Ubuntu 24.04 的 Python 3.12 可直接使用：

```bash
python3 -m venv .venv-slm
.venv-slm/bin/python -m pip install -r experiments/requirements-slm.txt

# 只运行 BM25 模式；不需要下载嵌入模型
OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 \
  .venv-slm/bin/python experiments/run_slm.py --mode bm25 --out results/rq4_bm25
```

运行全部三种模式前，在线加载 Mode A 的模型以建立本地缓存，并按 [Ollama 官方安装说明](https://docs.ollama.com/linux) 安装 Ollama：

```bash
.venv-slm/bin/python -c 'from sentence_transformers import SentenceTransformer; SentenceTransformer("nomic-ai/nomic-embed-text-v1.5", trust_remote_code=True, device="cpu")'
# 在 Ollama 服务运行时下载 Mode B 的模型
ollama pull nomic-embed-text
ollama pull llama3.2:1b
```

确保本地 11435 端口空闲后执行；驱动会启动和关闭该端口的独立 Ollama 服务：

```bash
HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 \
  python3 experiments/run_slm_suite.py --python .venv-slm/bin/python --out results/rq4
```

输入默认读取 `data/slm/` 中的 `memories.jsonl`、`queries.jsonl` 和 `policies.json`。
单模式驱动可加 `--limit 2` 执行两个查询；批量驱动可用 `--resume` 跳过经校验的完整模式。
