import copy
import hashlib
import itertools

DAY = 86400


def cases():
    def record_id(label):
        return 'sha256:' + hashlib.sha256(label.encode()).hexdigest()

    def finding(height, index=0, severity=3, similarities=None, link=False):
        sim = {1: 200000, 2: 100000, 3: 0}[severity]
        return {'window_hours': 72, 'quorum': 2, 'link': link, 'records': [
            {'id': record_id(f'{height}/{index}/{i}'), 'block_height': height,
             'entry_index': index * 3 + i, 'sealed_at_s': height * DAY,
             'auditor_id': auditor, 'effective_similarity': (similarities or [sim] * 3)[i]}
            for i, auditor in enumerate(['a.example.org', 'b.example.org', 'c.sample.net'])]}

    def block(height, findings=(), lift=False, reset=False):
        return {'height': height, 'sealed_at_s': height * DAY, 'findings': list(findings),
                'lift': lift, 'reset': reset}

    def quorum(f):
        return [f['records'][i]['id'] for i in (0, 2)]

    def all_quorums(fs):
        return list(itertools.chain.from_iterable(quorum(f) for f in fs))

    result = []

    def add(label, blocks, level, target, evidence, valid, notice_height=None):
        result.append({'label': label, 'blocks': copy.deepcopy(blocks), 'notice': {
            'height': blocks[-1]['height'] if notice_height is None else notice_height,
            'level': level, 'activation': target['records'][-1]['id'], 'evidence': evidence},
            'error': None if valid else 'WIST4-E05'})

    f = finding(0)
    add('minimal quorum omits a redundant confirming Record', [block(0, [f])], 3, f, quorum(f), True)
    add('complete closed set is also sufficient', [block(0, [f])], 3, f, [r['id'] for r in f['records']], True)
    add('activation ID alone is insufficient', [block(0, [f])], 3, f, quorum(f)[1:], False)
    add('quorum without activation is insufficient', [block(0, [f])], 3, f, quorum(f)[:1], False)
    add('unknown optional citation rejects notice', [block(0, [f])], 3, f, quorum(f) + [record_id('unknown')], False)
    future = finding(2)
    add('future optional citation rejects notice', [block(0, [f]), block(2, [future])], 3, f,
        quorum(f) + [future['records'][0]['id']], False, notice_height=0)
    mixed = finding(0, similarities=[200000, 0, 0])
    add('omitting mild Record cannot fabricate severity three', [block(0, [mixed])], 3, mixed,
        [mixed['records'][i]['id'] for i in (1, 2)], False)
    links = finding(0, link=True)
    add('link finding cannot take severity three branch', [block(0, [links])], 3, links, quorum(links), False)
    many = [finding(0, i, severity=1) for i in range(10)]
    add('count branch uses activation window despite late notice', [block(0, many), block(200)],
        3, many[-1], all_quorums(many), True)
    add('count branch needs ten supported findings', [block(0, many)], 3, many[-1], all_quorums(many[1:]), False)
    new = finding(1, severity=1)
    add('old count cannot replace activating quorum', [block(0, many), block(1, [new], lift=True)],
        3, new, all_quorums(many) + [new['records'][-1]['id']], False)
    add('pre-lift findings support rearmed count', [block(0, many), block(1, [new], lift=True)],
        3, new, all_quorums(many[1:] + [new]), True)
    add('pre-reset findings cannot support fresh identity', [block(0, many), block(1, [new], reset=True)],
        3, new, all_quorums(many + [new]), False)
    a, b, c = finding(0), finding(1), finding(2, severity=1)
    add('further finding needs prior level three evidence', [block(0, [a]), block(1, [new])],
        4, new, quorum(new), False)
    add('further finding with prior level three support', [block(0, [a]), block(1, [new])],
        4, new, quorum(a) + quorum(new), True)
    history = [block(0, [a]), block(1, [b], lift=True), block(2, [c])]
    add('cleared level three cannot substitute for current activation', history, 4, c, quorum(a) + quorum(c), False)
    add('current prior activation supports further finding', history, 4, c, quorum(b) + quorum(c), True)
    d = finding(2)
    history = [block(0, [a]), block(1, [b], lift=True), block(2, [d], lift=True)]
    add('three severity three findings survive lifts', history, 4, d, all_quorums([a, b, d]), True)
    add('new level three is not its own further finding', history, 4, d, quorum(d), False)
    extra = finding(0, 1, severity=1)
    add('optional available evidence changes no severity', [block(0, [a, extra])],
        3, a, quorum(a) + quorum(extra), True)
    for day, valid in [(89, True), (90, False)]:
        last = finding(day, severity=1)
        add(f'count window at {day} days', [block(0, many[:9]), block(day, [last])],
            3, last, all_quorums(many[:9] + [last]), valid)
    older_l3 = finding(1, severity=1)
    last = finding(2, severity=1)
    add('prior level three activating quorum cannot be omitted',
        [block(0, many), block(1, [older_l3], lift=True), block(2, [last])],
        4, last, all_quorums(many + [last]), False)
    late = finding(200, severity=1)
    add('further finding retains prior level three count window', [block(0, many), block(200, [late])],
        4, late, all_quorums(many + [late]), True)
    changed = finding(2)
    for i, r in enumerate(changed['records']):
        r['block_height'] = i
        r['sealed_at_s'] = i * DAY
        r['confirm_auditors'] = 3 if i < 2 else 2
    changed['records'][1]['auditor_id'] = 'c.sample.net'
    changed['records'][2]['auditor_id'] = 'a.example.org'
    add('quorum amendment does not re-evaluate earlier candidates', [block(2, [changed])],
        3, changed, [r['id'] for r in changed['records']], True)
    expanded = copy.deepcopy(changed)
    for i, r in enumerate(expanded['records']):
        r['confirm_auditors'] = 2
        r['confirm_window_hours'] = 1 if i < 2 else 48
    add('window amendment does not re-evaluate earlier candidates', [block(2, [expanded])],
        3, expanded, [r['id'] for r in expanded['records']], True)
    stale = copy.deepcopy(changed)
    stale['records'][2]['block_height'] = 20
    stale['records'][2]['sealed_at_s'] = 20 * DAY
    last = copy.deepcopy(stale['records'][2])
    last.update(id=record_id('last fresh Record'), entry_index=3, auditor_id='d.other.io')
    stale['records'].append(last)
    add('old quorum is outside confirming candidates window', [block(20, [stale])],
        3, stale, [stale['records'][i]['id'] for i in (0, 1, 3)], False)
    return result


def evaluate(case):
    active = [None] * 4
    supports = [None] * 4
    findings = []
    available = set()
    notice = case['notice']
    cited = set(notice['evidence'])

    def independent(records):
        suffixes = [tuple(r['auditor_id'].split('.')[-2:]) for r in records]
        return len(set(suffixes)) == len(suffixes)

    def complete(f):
        anchor = f['records'][-1]
        records = [r for r in f['records'] if r['id'] in cited
                   and 0 <= anchor['sealed_at_s'] - r['sealed_at_s'] <= anchor.get('confirm_window_hours', f['window_hours']) * 3600]
        return f['records'][-1]['id'] in cited and any(
            independent(group) for group in itertools.combinations(records, anchor.get('confirm_auditors', f['quorum'])))

    for block in sorted(case['blocks'], key=lambda b: b['height']):
        if block['height'] > notice['height']:
            break
        if block['reset']:
            findings = []
        if block['lift'] or block['reset']:
            active = [None] * 4
            supports = [None] * 4
        for f in sorted(block['findings'], key=lambda f: f['records'][-1]['entry_index']):
            available.update(r['id'] for r in f['records'])
            confirmed = None
            for i, anchor in enumerate(f['records']):
                candidates = [r for r in f['records'][:i+1]
                              if 0 <= anchor['sealed_at_s'] - r['sealed_at_s'] <= anchor.get('confirm_window_hours', f['window_hours']) * 3600]
                if any(independent(group) for group in itertools.combinations(candidates, anchor.get('confirm_auditors', f['quorum']))):
                    confirmed = i
                    break
            assert confirmed == len(f['records']) - 1, case['label']
            sim = max(r['effective_similarity'] for r in f['records'])
            severity = 1 if f['link'] or sim >= 150000 else 2 if sim >= 50000 else 3
            prior = active[2]
            prior_support = supports[2]
            findings.append((block['sealed_at_s'], severity, complete(f)))
            counts = [sum(1 for t, s, ok in findings if 0 <= block['sealed_at_s'] - t < days * DAY and s >= minimum)
                      for days, minimum in [(90, 0), (180, 3)]]
            supported_counts = [sum(1 for t, s, ok in findings if ok and 0 <= block['sealed_at_s'] - t < days * DAY and s >= minimum)
                                for days, minimum in [(90, 0), (180, 3)]]
            met = [True, counts[0] >= 3, counts[0] >= 10 or severity == 3,
                   prior is not None or (severity == 3 and counts[1] >= 3)]
            supported = [complete(f), complete(f) and supported_counts[0] >= 3,
                         complete(f) and (supported_counts[0] >= 10 or severity == 3),
                         complete(f) and ((prior is not None and prior_support) or
                                          (severity == 3 and supported_counts[1] >= 3))]
            for i in range(4):
                if active[i] is None and met[i]:
                    active[i] = f['records'][-1]['id']
                    supports[i] = supported[i]
    rung = notice['level'] - 1
    return None if (active[rung] == notice['activation'] and notice['activation'] in cited
                    and cited <= available and supports[rung]) else 'WIST4-E05'
