#!/usr/bin/env python3
"""Fresh SuperLocalMemory ingestion/recall with this project's C authorization gate.
Uses third-party superlocalmemory==3.5.7, never imports legacy BA-APSI modules.
"""
import argparse, contextlib, csv, dataclasses, datetime, hashlib, importlib.metadata
import json, logging, math, os, platform, shutil, sqlite3, subprocess, sys, tempfile, time, urllib.request
from pathlib import Path
from unittest.mock import patch
from slm_metrics import policy_sets, metrics, normalize

ROOT = Path(__file__).resolve().parents[1]


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def jsonl(p):
    return [json.loads(s) for s in p.read_text().splitlines() if s.strip()]


def json_save(path, obj):
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False, default=str) + '\n')


class Gate:
    def __init__(self, universe, folder):
        self.log = (folder / 'gate.log').open('w')
        start = time.perf_counter()
        self.p = subprocess.Popen(
            [str(ROOT / 'build/ba_gate'), str(ROOT / 'params/type-a-160-512.param'), str(universe)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=self.log,
            text=True,
            bufsize=1,
        )
        if self.p.stdout.readline().strip() != 'READY':
            raise RuntimeError('C gate initialization failed')
        self.setup_ms = (time.perf_counter() - start) * 1000

    def query(self, authorized, candidates):
        c = sorted(authorized)
        s = list(candidates)
        self.p.stdin.write(
            f'{len(c)} {len(s)}\n' + ' '.join(map(str, c)) + '\n' + ' '.join(map(str, s)) + '\n'
        )
        self.p.stdin.flush()
        fields = self.p.stdout.readline().split()
        if len(fields) < 4 or fields[0] != 'OK':
            raise RuntimeError('C gate failed: ' + str(fields))
        matched = {int(x) for x in fields[4:]}
        if len(matched) != int(fields[3]):
            raise AssertionError('Malformed C result cardinality')
        return matched, float(fields[1]), float(fields[2])

    def close(self):
        self.p.stdin.close()
        code = self.p.wait(timeout=30)
        self.log.close()
        if code:
            raise RuntimeError(f'C gate exit {code}')


@contextlib.contextmanager
def ollama_service(folder):
    # Dedicated port; never changes/stops a user's existing Ollama service.
    url = 'http://127.0.0.1:11435'
    try:
        with urllib.request.urlopen(url + '/api/tags', timeout=1):
            pass
    except OSError:
        pass
    else:
        raise RuntimeError('Benchmark port 11435 already occupied')
    log = (folder / 'ollama.log').open('w')
    proc = subprocess.Popen(
        ['ollama', 'serve'],
        env=os.environ | {'OLLAMA_HOST': '127.0.0.1:11435', 'OLLAMA_NUM_PARALLEL': '1'},
        stdout=log,
        stderr=log,
    )
    try:
        for _ in range(120):
            try:
                with urllib.request.urlopen(url + '/api/tags', timeout=1) as response:
                    tags = json.load(response)
                names = {m['name'] for m in tags['models']}
                if not {'llama3.2:1b', 'nomic-embed-text:latest'} <= names:
                    raise RuntimeError('Required local Ollama models missing: ' + str(names))
                json_save(folder / 'ollama-models.json', tags)
                break
            except OSError:
                if proc.poll() is not None:
                    raise RuntimeError('Ollama exited')
                time.sleep(0.5)
        else:
            raise RuntimeError('Ollama startup timeout')
        yield url
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        log.close()


def execute(a, folder, ollama_url=''):
    from superlocalmemory.core.config import SLMConfig, EmbeddingConfig, LLMConfig
    from superlocalmemory.core.engine import MemoryEngine
    from superlocalmemory.storage.models import Mode

    version = importlib.metadata.version('superlocalmemory')
    if version != '3.5.7':
        raise RuntimeError('This experiment requires superlocalmemory==3.5.7, found ' + version)
    records = jsonl(a.data / 'memories.jsonl')
    queries = jsonl(a.data / 'queries.jsonl')
    policy = json.loads((a.data / 'policies.json').read_text())
    if a.limit:
        queries = queries[: a.limit]
    by_id = {r['memory_id']: r for r in records}
    if len(by_id) != len(records):
        raise ValueError('Duplicate memory IDs')
    # Full canonical metadata is retained; dense IDs are collision-free within the fixed universe.
    attributes = []
    for i, mid in enumerate(sorted(by_id), 1):
        r = by_id[mid]
        canonical = json.dumps(
            {
                'memory_id': mid,
                'tenant': r['tenant_id'],
                'namespace': r['namespace'],
                'owner': r['owner_agent'],
                'type': r['entity_type'],
                'entity': normalize(r['entity_value']),
                'tags': sorted(r['policy_tags']),
                'policy_version': policy['policy_version'],
            },
            sort_keys=True,
            separators=(',', ':'),
        )
        attributes.append(
            dict(
                id=i,
                memory_id=mid,
                canonical=canonical,
                sha256=hashlib.sha256(canonical.encode()).hexdigest(),
            )
        )
    json_save(folder / 'attributes.json', attributes)
    attr = {r['memory_id']: r['id'] for r in attributes}
    config = SLMConfig.for_mode(Mode.B if a.mode == 'mode_b' else Mode.A)
    config.base_dir = Path(a.runtime_root) / 'slm_home'
    config.base_dir.mkdir()
    config.db_path = config.base_dir / 'memory.db'
    config.active_profile = 'default'
    # Disable maintenance and auto-invocation during a controlled retrieval experiment.
    for field in [
        'forgetting',
        'auto_invoke',
        'consolidation',
        'reaper',
        'parameterization',
        'sagq',
        'ccq',
        'quantization',
    ]:
        setattr(config, field, dataclasses.replace(getattr(config, field), enabled=False))
    config.graph_backend = 'sqlite'
    config.vector_backend = 'sqlite-vec'
    config.retrieval.use_cross_encoder = False
    config.retrieval.top_k = a.candidates
    config.retrieval.semantic_top_k = a.candidates
    config.retrieval.bm25_top_k = a.candidates
    if a.mode == 'bm25':
        config.retrieval.disabled_channels = [
            'semantic',
            'entity_graph',
            'temporal',
            'spreading_activation',
            'hopfield',
        ]
    elif a.mode == 'mode_a':
        config.embedding = EmbeddingConfig(
            provider='sentence-transformers',
            model_name='nomic-ai/nomic-embed-text-v1.5',
            dimension=768,
        )
    else:
        config.embedding = EmbeddingConfig(
            provider='ollama',
            ollama_model='nomic-embed-text',
            ollama_base_url=ollama_url,
            dimension=768,
        )
        config.llm = LLMConfig(provider='ollama', model='llama3.2:1b', api_base=ollama_url)
    json_save(
        folder / 'config.json',
        dataclasses.asdict(config)
        | {
            'base_dir': str(config.base_dir),
            'db_path': str(config.db_path),
            'mode': config.mode.value,
        },
    )
    manifest = {
        'started_at': datetime.datetime.now().astimezone().isoformat(),
        'mode': a.mode,
        'framework_version': version,
        'python': sys.version,
        'platform': platform.platform(),
        'records': len(records),
        'queries': len(queries),
        'candidate_limit': a.candidates,
        'index': 'fresh store_fast ingestion',
        'runtime_storage': str(config.base_dir),
        'archived_database': str(folder / 'slm_home'),
        'gate_sha256': sha(ROOT / 'build/ba_gate'),
        'script_sha256': sha(Path(__file__)),
        'third_party_package': str(Path(sys.modules['superlocalmemory'].__file__).resolve()),
        'metrics_sha256': sha(ROOT / 'experiments/slm_metrics.py'),
        'inputs': {p.name: sha(p) for p in sorted(a.data.glob('*.json*'))},
        'llm_generation_separately_timed': False,
        'llm_in_recall_possible': a.mode == 'mode_b',
        'llm_note': 'Fast recall may call the Mode B entity resolver; inspect actual Ollama requests, included in recall latency.',
        'cross_encoder': False,
        'fast_recall': True,
        'environment': {
            k: os.environ.get(k)
            for k in [
                'HF_HUB_OFFLINE',
                'TRANSFORMERS_OFFLINE',
                'OMP_NUM_THREADS',
                'OPENBLAS_NUM_THREADS',
                'CUDA_VISIBLE_DEVICES',
            ]
        },
    }
    json_save(folder / 'manifest.json', manifest)
    engine = MemoryEngine(config)
    try:
        start = time.perf_counter()
        with (
            patch('superlocalmemory.core.engine_wiring.init_embedder', return_value=None)
            if a.mode == 'bm25'
            else contextlib.nullcontext()
        ):
            engine.initialize()
        manifest['initialize_ms'] = (time.perf_counter() - start) * 1000
        embedder = engine.embedder
        embedding_audit = {'calls': 0, 'failures': 0}
        if a.mode != 'bm25':
            if embedder is None:
                raise RuntimeError('Embedding mode silently fell back to BM25')
            if a.mode == 'mode_b' and type(embedder).__name__ != 'OllamaEmbedder':
                raise RuntimeError('Wrong embedding provider')
            original_embed = embedder.embed

            def checked_embed(text):
                embedding_audit['calls'] += 1
                try:
                    vector = original_embed(text)
                    if (
                        vector is None
                        or len(vector) != 768
                        or not all(math.isfinite(v) for v in vector)
                        or not any(vector)
                    ):
                        raise RuntimeError('Invalid embedding vector')
                    return vector
                except Exception:
                    embedding_audit['failures'] += 1
                    raise

            embedder.embed = checked_embed
            test_vector = embedder.embed('search_query: experimental verification')
            if test_vector is None or len(test_vector) != 768:
                raise RuntimeError('Embedding unavailable')
            if a.mode == 'mode_b' and engine._llm is None:
                raise RuntimeError('Local LLM unavailable')
        elif embedder is not None:
            raise RuntimeError('BM25 ablation unexpectedly has embeddings')
        manifest['embedder_class'] = type(embedder).__name__
        manifest['llm_available'] = engine._llm is not None
        print('INITIALIZED', a.mode, manifest['embedder_class'], flush=True)
        start = time.perf_counter()
        for i, r in enumerate(records, 1):
            ids = engine.store_fast(
                r['content'], metadata=r | {'original_memory_id': r['memory_id']}
            )
            if len(ids) != 1:
                raise RuntimeError(f'store_fast rejected record {i}')
            if i % 100 == 0:
                print('STORED', a.mode, i, flush=True)
        manifest['ingest_ms'] = (time.perf_counter() - start) * 1000
        with sqlite3.connect(config.db_path) as db:
            mapping = {
                mid: json.loads(meta)['original_memory_id']
                for mid, meta in db.execute('select memory_id,metadata_json from memories')
            }
            count, embedded = db.execute(
                'select count(*),sum(embedding is not null) from atomic_facts'
            ).fetchone()
        if (
            set(mapping.values()) != set(by_id)
            or len(mapping) != len(records)
            or count != len(records)
        ):
            raise AssertionError('Ingestion coverage mismatch')
        if a.mode != 'bm25' and embedded != len(records):
            raise AssertionError('Missing stored embeddings')
        manifest['embedded_facts'] = embedded
        gate = Gate(len(records), folder)
        manifest['gate_setup_ms'] = gate.setup_ms
        try:
            # One untimed warm-up. Each of the 320 measured queries is a separate policy/query sample.
            engine.recall('Project Stress 00 risk', limit=a.candidates, fast=True)
            csvfile = (folder / 'queries.csv').open('x', newline='')
            raw = (folder / 'rankings.jsonl').open('x')
            writer = None
            try:
                for i, q in enumerate(queries, 1):
                    allowed, denied = policy_sets(records, q, policy)
                    text = ' '.join(q['query_entities']) + ' ' + q['entity_type']
                    start = time.perf_counter()
                    response = engine.recall(
                        text, limit=a.candidates, agent_id=q['requesting_agent'], fast=True
                    )
                    retrieval_ms = (time.perf_counter() - start) * 1000
                    if embedding_audit['failures']:
                        raise RuntimeError('Embedding failure during framework execution')
                    ranked = []
                    scores = []
                    channel_scores = []
                    seen = set()
                    for result in response.results:
                        mid = mapping[result.fact.memory_id]
                        if mid not in seen:
                            ranked.append(mid)
                            scores.append(float(result.score))
                            channel_scores.append(
                                {key: float(value) for key, value in result.channel_scores.items()}
                            )
                            seen.add(mid)
                    start = time.perf_counter()
                    hits, auth_ms, intersect_ms = gate.query(
                        {attr[x] for x in allowed}, [attr[x] for x in ranked]
                    )
                    gate_wall_ms = (time.perf_counter() - start) * 1000
                    if hits != {attr[mid] for mid in allowed & set(ranked)}:
                        raise AssertionError('C result differs from independent exact oracle')
                    filtered = [mid for mid in ranked if attr[mid] in hits]
                    if set(filtered) != allowed & set(ranked):
                        raise AssertionError('Filtered ranking mismatch')
                    for label, shared in [('none', ranked), ('ba_apsi', filtered)]:
                        row = {
                            'mode': a.mode,
                            'gate': label,
                            'query_id': q['query_id'],
                            'retrieval_ms': retrieval_ms,
                            'authorize_ms': auth_ms if label == 'ba_apsi' else 0,
                            'intersect_ms': intersect_ms if label == 'ba_apsi' else 0,
                            'gate_wall_ms': gate_wall_ms if label == 'ba_apsi' else 0,
                            **metrics(shared, allowed, denied),
                            'validation': 'PASS',
                        }
                        if writer is None:
                            writer = csv.DictWriter(csvfile, fieldnames=list(row))
                            writer.writeheader()
                        writer.writerow(row)
                    raw.write(
                        json.dumps(
                            {
                                'query': q,
                                'text': text,
                                'ranked': ranked,
                                'scores': scores,
                                'channel_scores': channel_scores,
                                'channel_weights': response.channel_weights,
                                'filtered': filtered,
                                'allowed': sorted(allowed),
                                'denied': sorted(denied),
                            }
                        )
                        + '\n'
                    )
                    csvfile.flush()
                    raw.flush()
                    if i % 20 == 0:
                        print('QUERIES', a.mode, i, flush=True)
            finally:
                csvfile.close()
                raw.close()
        finally:
            gate.close()
        manifest['embedding_audit'] = embedding_audit
        if embedding_audit['failures']:
            raise RuntimeError('Embedding failures detected')
        manifest['completed_at'] = datetime.datetime.now().astimezone().isoformat()
        manifest['status'] = 'complete'
        manifest['queries_sha256'] = sha(folder / 'queries.csv')
        json_save(folder / 'manifest.json', manifest)
    finally:
        engine.close()
        shutil.copytree(config.base_dir, folder / 'slm_home')
    (folder / 'COMPLETE').write_text('PASS\n')
    print('COMPLETE', a.mode, flush=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--mode', choices=['bm25', 'mode_a', 'mode_b'], required=True)
    ap.add_argument('--out', type=Path, required=True)
    ap.add_argument('--data', type=Path, default=ROOT / 'data/slm')
    ap.add_argument('--candidates', type=int, default=100)
    ap.add_argument('--limit', type=int, default=0, help='Smoke-test prefix; 0 runs all queries')
    a = ap.parse_args()
    a.out = a.out.resolve()
    a.data = a.data.resolve()
    if a.candidates < 10 or a.limit < 0:
        ap.error('Invalid limits')
    a.out.mkdir(parents=True, exist_ok=False)
    logging.basicConfig(level=logging.WARNING)
    with tempfile.TemporaryDirectory(prefix='ba_slm_', dir='/tmp') as runtime:
        a.runtime_root = runtime
        if a.mode == 'mode_b':
            with ollama_service(a.out) as url:
                execute(a, a.out, url)
        else:
            execute(a, a.out)


if __name__ == '__main__':
    main()
