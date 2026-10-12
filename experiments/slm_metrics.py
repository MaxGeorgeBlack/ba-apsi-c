"""Independent policy oracle and explicitly defined ranking metrics."""

import math


def normalize(value):
    return ' '.join(str(value).casefold().split())


def policy_sets(records, query, policy):
    if query['policy_version'] != policy['policy_version']:
        raise ValueError('Policy version mismatch')
    allowed, denied = set(), set()
    who = query['requesting_agent']
    revoked = set(policy.get('revoked_memory_ids', []))
    entities = {normalize(x) for x in query['query_entities']}
    required = set(query.get('required_policy_tags', []))
    for r in records:
        matching = (
            r['tenant_id'] == query['tenant_id']
            and r['namespace'] == query['namespace']
            and r['entity_type'] == query['entity_type']
            and normalize(r['entity_value']) in entities
            and required <= set(r.get('policy_tags', []))
        )
        if not matching:
            continue
        mid = r['memory_id']
        permit = (
            who == r['owner_agent']
            or who in r.get('authorized_agents', [])
            or who in policy.get('grants', {}).get(mid, [])
        )
        # Explicit deny and revocation override every grant, including ownership.
        permit = permit and mid not in revoked and who not in r.get('unauthorized_agents', [])
        (allowed if permit else denied).add(mid)
    return allowed, denied


def metrics(ranked, allowed, denied, cutoff=10):
    if len(set(ranked)) != len(ranked) or allowed & denied:
        raise ValueError('Duplicate ranked ID or overlapping oracle sets')
    shared = set(ranked)
    rel = [int(x in allowed) for x in ranked]
    ideal = sum(1 / math.log2(i + 2) for i in range(min(cutoff, len(allowed))))
    dcg = sum(v / math.log2(i + 2) for i, v in enumerate(rel[:cutoff]))
    return dict(
        shared=len(shared),
        authorized=len(allowed),
        unauthorized=len(denied),
        authorized_shared=len(shared & allowed),
        unauthorized_shared=len(shared & denied),
        matching_rate=len(shared & allowed) / len(shared) if shared else None,
        leakage_rate=len(shared & denied) / len(denied) if denied else None,
        recall_at_10=sum(rel[:cutoff]) / len(allowed) if allowed else None,
        mrr=next((1 / (i + 1) for i, v in enumerate(rel) if v), 0.0) if allowed else None,
        ndcg_at_10=dcg / ideal if ideal else None,
    )
