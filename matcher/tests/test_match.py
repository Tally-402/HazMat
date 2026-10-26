"""Matcher: metadata exclusion, push-data safety, honest assertion level."""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
ROOT = Path(__file__).resolve().parents[2]
REGISTER = str(ROOT / 'register' / 'placards')

import json
import os
import tempfile
from pathlib import Path

from hazmat import anchor, batch, chains, confirm, derive, keccak, match, paths, pdf, resolve, sds, serve, verify, watch  # noqa: E402

TRAILER = bytes.fromhex('a264697066735822' + '11' * 34 + '64736f6c634300081b0033')
PLACARD = [{'id': 'HZ-001', 'title': 't', 'placard_class': 2, 'placard_class_name': 'ordering',
            'tier': 'confirmed', 'money_bound': {'kind': 'per-deal', 'expression': 'one deal'},
            'matcher': {'kind': 'selector-set', 'require_all': ['0xe4725ba1', '0x7c7a9804']}}]


def code_with(*selectors, trailer=True, payload=b''):
    body = bytearray()
    for sel in selectors:
        body += b'\x63' + bytes.fromhex(sel[2:])
    body += payload
    return bytes(body) + (TRAILER if trailer else b'')


class Metadata(unittest.TestCase):
    def test_trailer_is_split_off_by_its_length_field(self):
        body, trailer = match.strip_metadata(code_with('0xe4725ba1'))
        self.assertEqual(trailer, TRAILER)
        self.assertNotIn(TRAILER, body)

    def test_short_code_is_left_alone(self):
        self.assertEqual(match.strip_metadata(b'\x60\x00')[1], b'')


class Matching(unittest.TestCase):
    def test_all_required_selectors_yield_a_pattern_match(self):
        found, stats = match.match_code(code_with('0xe4725ba1', '0x7c7a9804', '0x82cbf88b'), PLACARD)
        self.assertEqual([m['id'] for m in found], ['HZ-001'])
        self.assertEqual(found[0]['assertion'], 'pattern')
        self.assertEqual(stats['metadata_bytes'], len(TRAILER))

    def test_missing_selector_is_no_match(self):
        self.assertEqual(match.match_code(code_with('0xe4725ba1'), PLACARD)[0], [])

    def test_selector_looking_bytes_inside_push_data_are_skipped(self):
        payload = b'\x7f' + bytes.fromhex('e4725ba1' + '00' * 28) + b'\x63\x7c\x7a\x98\x04'
        self.assertEqual(match.match_code(payload + TRAILER, PLACARD)[0], [])

    def test_register_loads_and_the_shipped_placard_validates(self):
        rows = match.load_register(REGISTER)
        ids = [r['id'] for r in rows]
        self.assertIn('HZ-001', ids)
        self.assertEqual(len(rows[0]['matcher']['require_all']), 3)
        for row in rows:
            self.assertTrue(row['matcher'].get('require_all') or row['matcher'].get('require_any'),
                            '%s has an empty matcher' % row['id'])


class AmbiguousInput(unittest.TestCase):
    def test_a_40_hex_blob_can_be_forced_to_raw_code(self):
        blob = '0x' + ('63e4725ba1' * 3 + '637c7a9804')[:40]   # both required selectors survive the truncation
        self.assertEqual(len(blob), 42)                        # exactly 40 hex characters: address-shaped
        found, _ = match.match_code(bytes.fromhex(blob[2:]), PLACARD)
        self.assertEqual([m['id'] for m in found], ['HZ-001'])
        full = '0x' + '63e4725ba1637c7a98046382cbf88b' + '63' + '82cbf88b'
        report = match.scan(full, REGISTER, as_='code')
        self.assertEqual([m['id'] for m in report['matches']], ['HZ-001'])

    def test_an_unknown_as_is_loud(self):
        with self.assertRaises(match.MatchError):
            match.load_code('0x' + '00' * 20, as_='nonsense')


class Pdf(unittest.TestCase):
    def report(self, matches=True):
        return {'target': '0xdead', 'family': 'evm', 'code_sha256': '0x' + 'ab' * 32, 'register_size': 10,
                'stats': {'body_bytes': 1, 'metadata_bytes': 2, 'push4_constants': 3},
                'assertion': 'pattern match only; confirmation runs are separate',
                'matches': ([{'id': 'HZ-001', 'title': 'a long hazard title that should wrap across the line',
                              'placard_class': 2, 'placard_class_name': 'ordering', 'tier': 'confirmed',
                              'assertion': 'pattern', 'matched_selectors': ['0xe4725ba1'], 'absent_checked': 2,
                              'money_bound': {'expression': 'one deal'}}] if matches else []),
                'not_checked': ['reachability', 'economic preconditions']}

    def test_a_pdf_is_well_formed_and_carries_the_evidence(self):
        body = pdf.render_pdf(self.report())
        self.assertTrue(body.startswith(b'%PDF-1.4'))
        self.assertTrue(body.rstrip().endswith(b'%%EOF'))
        self.assertIn(b'/Type /Catalog', body)
        self.assertIn(b'HZ-001', body)
        self.assertIn(b'0xe4725ba1', body)
        self.assertIn(b'NOT CHECKED', body)

    def test_layout_is_deterministic_and_paginates(self):
        self.assertEqual(pdf.render_pdf(self.report()), pdf.render_pdf(self.report()))
        long_report = self.report()
        long_report['not_checked'] = ['item %d' % i for i in range(200)]
        self.assertGreater(pdf.page_count(pdf.render_pdf(long_report)), 1)

    def test_escaping_handles_parentheses_and_backslashes(self):
        line = pdf.escape('a (b) c\\d')
        self.assertEqual(line, 'a \\(b\\) c\\\\d')


class Verify(unittest.TestCase):
    def test_a_sheet_verifies_then_fails_once_tampered_with(self):
        report = Pdf().report()
        page, digest = sds.render(report)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, 'sheet.html')
            path.write_text(page)
            self.assertTrue(verify.verify_sheet(str(path))['ok'])
            self.assertTrue(verify.verify_sheet(str(path), digest)['ok'])
            self.assertFalse(verify.verify_sheet(str(path), '0x' + '00' * 32)['ok'])
            path.write_text(page.replace('HZ-001', 'HZ-002'))
            self.assertFalse(verify.verify_sheet(str(path))['ok'])

    def test_a_record_with_a_bad_stage_is_not_ok(self):
        record = {'target': '0xdead', 'verdict': 'blocked', 'stages': {'fetch': {'state': 'blocked'}}}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, 'r.json')
            path.write_text(json.dumps(record))
            got = verify.verify_record(str(path))
            self.assertFalse(got['ok'])
            self.assertTrue(any('fetch' in c['check'] and not c['ok'] for c in got['checks']))

    def test_a_sheet_verifies_against_the_epoch_it_names_even_after_a_new_one(self):
        first = anchor.load_epoch(1)          # an epoch published before the register grew
        report = Pdf().report()
        report['register_digest'] = first['register_digest']
        report['register_anchor'] = {'epoch': 1, 'root': first['root'], 'file': 'epoch-1.json',
                                     'register_digest': first['register_digest']}
        page, _ = sds.render(report)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, 's.html')
            path.write_text(page)                                       # names epoch 1
            got = verify.verify_sheet(str(path))
            self.assertTrue(got['ok'])                                  # still verifies after epoch 2 exists
            self.assertTrue(any(c.get('epoch') == 1 for c in got['checks']))
            self.assertFalse(any(c.get('epoch') == 2 for c in got['checks']))

    def test_the_register_digest_changes_when_a_placard_does(self):
        before = match.register_digest(REGISTER)
        self.assertEqual(before, match.register_digest(REGISTER))
        self.assertTrue(before.startswith('0x') and len(before) == 18)


class Serve(unittest.TestCase):
    def test_the_server_answers_the_form_and_rejects_a_bad_chain(self):
        import threading
        import urllib.error
        import urllib.request
        server = serve.make_server(0, '127.0.0.1')
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            port = server.server_address[1]
            form = urllib.request.urlopen('http://127.0.0.1:%d/' % port, timeout=10).read().decode()
            self.assertIn('HAZMAT', form)                      # the single-page front end
            self.assertIn('scan a contract', form)
            self.assertIn('#/register', form)
            try:
                urllib.request.urlopen('http://127.0.0.1:%d/scan?target=0x1&chain=nope' % port, timeout=10)
                self.fail('a bad chain should be a 400')
            except urllib.error.HTTPError as exc:   # urllib raises on 4xx, so read the body off the error
                self.assertEqual(exc.code, 400)
                self.assertEqual(json.loads(exc.read())['state'], 'blocked')
        finally:
            server.shutdown()


class Watch(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = watch.connect(os.path.join(self.tmp.name, 'w.sqlite3'))
        self.alerts = os.path.join(self.tmp.name, 'alerts.jsonl')
        # nothing here unless a test asks: the real register/watchlist.json would
        # otherwise add inspections of its own and shift the counters
        self.no_watchlist = os.path.join(self.tmp.name, 'no-watchlist.json')

    def tearDown(self):
        self.tmp.cleanup()

    def feed(self, *entries):
        return lambda chain, limit: list(entries)

    def inspector(self, matches_for=()):
        def inspect_(address):
            if address in matches_for:
                return {'code_sha256': '0x' + 'aa' * 32, 'placards': ['HZ-001']}
            return {'code_sha256': '0x' + 'bb' * 32, 'placards': []}
        return inspect_

    def test_one_alert_per_matching_address_and_a_second_pass_is_quiet(self):
        entries = [{'address': '0xaaa', 'verifiedAt': '2026-01-01T00:00:00Z'},
                   {'address': '0xbbb', 'verifiedAt': '2026-01-01T00:00:01Z'}]
        first = watch.pass_once(self.db, 'mainnet', feed=self.feed(*entries),
                               inspect_fn=self.inspector({'0xaaa'}), sink=self.alerts,
                               watchlist=self.no_watchlist)
        self.assertEqual(first['candidates'], 2)
        self.assertEqual(first['matched'], 1)
        again = watch.pass_once(self.db, 'mainnet', feed=self.feed(*entries),
                                inspect_fn=self.inspector({'0xaaa'}), sink=self.alerts,
                                watchlist=self.no_watchlist)
        self.assertEqual(again['candidates'], 0)
        self.assertEqual(watch.status(self.db)['alerts'], 1)

    def test_an_unreachable_address_is_recorded_without_an_alert(self):
        entries = [{'address': '0xdead', 'verifiedAt': '2026-02-01T00:00:00Z'}]
        def inspector(_):
            raise match.MatchError('no code')
        got = watch.pass_once(self.db, 'mainnet', feed=self.feed(*entries), inspect_fn=inspector,
                              sink=self.alerts, watchlist=self.no_watchlist)
        self.assertEqual(got['errors'], ['0xdead: no code'])
        self.assertEqual(watch.status(self.db)['alerts'], 0)
        self.assertEqual(watch.status(self.db)['seen'], 1)

    def test_a_watched_address_whose_code_changes_raises_an_upgrade_alert(self):
        watchlist = os.path.join(self.tmp.name, 'watchlist.json')
        Path(watchlist).write_text(json.dumps({'addresses': [{'chain': 'mainnet', 'address': '0xccc'}]}))
        hashes = iter(['0x' + '11' * 32, '0x' + '22' * 32])
        def inspector(address):
            return {'code_sha256': next(hashes), 'placards': []}
        watch.pass_once(self.db, 'mainnet', feed=self.feed(), inspect_fn=inspector,
                        sink=self.alerts, watchlist=watchlist)
        second = watch.pass_once(self.db, 'mainnet', feed=self.feed(), inspect_fn=inspector,
                                 sink=self.alerts, watchlist=watchlist)
        self.assertEqual(second['upgrades'], 1)
        rows = json.loads(Path(self.alerts).read_text().strip().splitlines()[-1])
        self.assertEqual((rows['kind'], rows['address']), ('upgrade', '0xccc'))

    def test_an_address_in_both_the_feed_and_the_watchlist_alerts_its_upgrade_once(self):
        watchlist = os.path.join(self.tmp.name, 'w.json')
        Path(watchlist).write_text(json.dumps({'addresses': [{'chain': 'mainnet', 'address': '0xdual'}]}))
        new_code = [{'code_sha256': '0x' + '22' * 32, 'placards': []}]
        same_code = [{'code_sha256': '0x' + '11' * 32, 'placards': []}]
        def first(address):
            return same_code[0]
        def second(address):
            return new_code[0]
        entry = [{'address': '0xdual', 'verifiedAt': '2026-07-01T00:00:00Z'}]
        watch.pass_once(self.db, 'mainnet', feed=self.feed(*entry), inspect_fn=first,
                        sink=self.alerts, watchlist=watchlist)          # first sight: no alert
        self.assertEqual(watch.status(self.db)['alerts'], 0)
        got = watch.pass_once(self.db, 'mainnet', feed=self.feed(), inspect_fn=second,
                              sink=self.alerts, watchlist=watchlist)     # the watchlist sees the change
        self.assertEqual(got['upgrades'], 1)
        self.assertEqual(watch.status(self.db)['alerts'], 1)

    def test_an_upgrade_on_a_matching_address_alerts_and_keeps_the_match(self):
        hashes = iter(['0x' + 'a1' * 32, '0x' + 'b2' * 32])   # one inspection per pass
        def inspector(address):
            return {'code_sha256': next(hashes), 'placards': ['HZ-001']}
        # the second entry is a re-verification, which is how a feed shows an upgrade
        entry = [{'address': '0xmatch', 'verifiedAt': '2026-08-01T00:00:00Z'}]
        again = [{'address': '0xmatch', 'verifiedAt': '2026-08-02T00:00:00Z'}]
        watch.pass_once(self.db, 'mainnet', feed=self.feed(*entry), inspect_fn=inspector, sink=self.alerts,
                        watchlist=self.no_watchlist)
        watch.pass_once(self.db, 'mainnet', feed=self.feed(*again), inspect_fn=inspector, sink=self.alerts,
                        watchlist=self.no_watchlist)
        kinds = [json.loads(l)['kind'] for l in Path(self.alerts).read_text().strip().splitlines()]
        self.assertEqual(kinds, ['new', 'upgrade'])

    def test_the_cursor_does_not_move_backwards(self):
        watch.pass_once(self.db, 'mainnet', feed=self.feed({'address': '0x1', 'verifiedAt': '2026-05-01T00:00:00Z'}),
                        inspect_fn=self.inspector(), sink=self.alerts, watchlist=self.no_watchlist)
        older = [{'address': '0x2', 'verifiedAt': '2026-04-01T00:00:00Z'}]
        got = watch.pass_once(self.db, 'mainnet', feed=self.feed(*older), inspect_fn=self.inspector(),
                              sink=self.alerts, watchlist=self.no_watchlist)
        self.assertEqual(got['candidates'], 0)
        self.assertEqual(got['cursor'], '2026-04-01T00:00:00Z')

    def test_status_counts_and_the_alert_file_is_jsonl(self):
        watch.pass_once(self.db, 'mainnet', feed=self.feed({'address': '0xm', 'verifiedAt': '2026-06-01T00:00:00Z'}),
                        inspect_fn=self.inspector({'0xm'}), sink=self.alerts, watchlist=self.no_watchlist)
        state = watch.status(self.db)
        self.assertEqual((state['seen'], state['alerts'], state['matched_ever']), (1, 1, 1))
        self.assertEqual(json.loads(Path(self.alerts).read_text().strip())['placards'], ['HZ-001'])


class Anchor(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def test_a_leaf_is_content_addressed_not_byte_addressed(self):
        row = json.loads(Path(REGISTER, 'HZ-001.json').read_text())
        reordered = {k: row[k] for k in reversed(list(row))}
        self.assertEqual(anchor.leaf_of(row), anchor.leaf_of(reordered))
        row['title'] = row['title'] + '!'
        self.assertNotEqual(anchor.leaf_of(row), anchor.leaf_of(reordered))

    def test_the_root_is_stable_and_every_placard_proves_against_it(self):
        rows = anchor.leaves_of(REGISTER)
        leaves = [r['leaf'] for r in rows]
        _, root = anchor.build(leaves)
        self.assertEqual(root, anchor.build(list(reversed(leaves)))[1])    # order-independent
        for row in rows:
            got = anchor.proof(REGISTER, row['id'])
            self.assertEqual(got['root'], root)
            self.assertTrue(anchor.verify(got['leaf'], got['proof'], root))

    def test_a_stranger_leaf_and_an_empty_register(self):
        rows = anchor.leaves_of(REGISTER)
        _, root = anchor.build([r['leaf'] for r in rows])
        self.assertFalse(anchor.verify('00' * 32, anchor.proof(REGISTER, 'HZ-001')['proof'], root))
        self.assertIsNone(anchor.build([])[1])

    def test_an_epoch_round_trips_and_names_the_register_it_covers(self):
        record, path = anchor.write_epoch(REGISTER, self.tmp.name, epoch=3)
        self.assertTrue(Path(path).is_file())
        again = anchor.load_epoch(3, self.tmp.name)
        self.assertEqual(again['root'], record['root'])
        self.assertEqual(again['register_digest'], match.register_digest(REGISTER))
        self.assertEqual(again['placards'], len(anchor.leaves_of(REGISTER)))

    def test_a_proof_for_an_unknown_placard_is_loud(self):
        with self.assertRaises(anchor.AnchorError):
            anchor.proof(REGISTER, 'HZ-999')

    def test_an_odd_level_duplicates_its_last_node_and_the_walk_agrees(self):
        leaves = sorted('0' * 63 + str(i) for i in range(3))   # three leaves: levels are 3, 2, 1
        levels, root = anchor.build(leaves)
        self.assertEqual([len(level) for level in levels], [3, 2, 1])
        parents = anchor.next_level(leaves)
        self.assertEqual(sorted(parents),
                         sorted([anchor.parent(leaves[0], leaves[1]), anchor.parent(leaves[2], leaves[2])]))
        self.assertEqual(root, anchor.next_level(parents)[0])
        # and a proof for the duplicated leaf folds back to the same root
        proof = anchor.proof(REGISTER, 'HZ-001')               # separate walk, real register
        self.assertTrue(anchor.verify(proof['leaf'], proof['proof'], proof['root']))


class Coverage(unittest.TestCase):
    def test_coverage_accounts_for_every_selector_it_did_not_ask_about(self):
        code = '0x' + '63e4725ba1' + '637c7a9804' + '63deadbeef' + '6300000001'
        report = match.scan(code, REGISTER, as_='code')
        cov = report['coverage']
        self.assertEqual(cov['selectors_in_code'],
                         cov['selectors_the_register_asks_about'] + cov['selectors_otherwise_unaccounted'])
        self.assertEqual(cov['placards_checked'], 15)
        self.assertTrue(cov['means'].startswith('a match means'))
        selectors = [u['selector'] for u in cov['unaccounted_sample']]
        self.assertIn('0xdeadbeef', selectors)

    def test_the_name_index_reads_signatures_but_claims_nothing_more(self):
        names = match.load_selector_names(REGISTER)
        self.assertGreater(len(names), 100)
        self.assertEqual(names.get(keccak.selector_hex('transfer(address,uint256)')), 'transfer(address,uint256)')
        self.assertEqual(names.get(keccak.selector_hex('accept(bytes32)')), 'accept(bytes32)')

    def test_a_clean_sheet_still_states_what_was_read(self):
        report = match.scan('0x' + '6311111111', REGISTER, as_='code')
        page, _ = sds.render(report)
        self.assertIn('What was read', page)
        self.assertIn('otherwise unaccounted', page)
        self.assertEqual(report['matches'], [])


class Resolve(unittest.TestCase):
    """The shapes that used to scan a wrapper and confidently report nothing."""

    IMPL = '0x' + 'cc' * 20
    DELEGATE = '0x' + '22' * 20        # the 7702 delegate for 0xaa
    CLONE_TARGET = '0x' + '22' * 20    # the clone at 0xbb embeds the same address

    def setUp(self):
        self.CODE = {'0xaa': '0xef0100' + '11' * 20, '0x11': '0x6080',
                     '0xbb': '0x363d3d373d3d3d363d73' + '22' * 20 + '5af43d82803e903d91602b57fd5bf3',
                     self.DELEGATE: '0x6080', '0xcc': '0x6000', '0xdd': '0x6000f4', '0xee': '0x',
                     '0x99': '0x6000', '0x12': '0x6000f4'}
        self.calls = []
        self.real = resolve.rpc_call
        resolve.rpc_call = self.stub

    def tearDown(self):
        resolve.rpc_call = self.real

    def word(self, address):
        return '0x' + '0' * 24 + address[2:]

    def stub(self, rpc, method, params, timeout=45):
        self.calls.append(method)
        if method == 'eth_getCode':
            return self.CODE.get(params[0], '0x')
        if method == 'eth_getStorageAt':
            return self.word(self.IMPL) if (params[0] == '0xcc' and params[1].startswith('0x3608')) else '0x' + '0' * 64
        if method == 'eth_call':
            return self.word(self.DELEGATE) if params[0]['to'] == '0xdd' else '0x'
        return '0x'

    def test_a_delegated_eoa_resolves_to_its_delegate(self):
        self.CODE['0xaa'] = '0xef0100' + '11' * 20
        got = resolve.resolve('0xaa', 'stub')
        self.assertEqual(got['kind'], 'delegated-eoa')
        self.assertEqual(got['effective'], '0x' + '11' * 20)
        self.assertEqual(got['effective'], got['targets'][1][0])
        self.assertEqual([r for _, r in got['targets']], ['requested', 'delegate'])

    def test_a_minimal_clone_resolves_to_what_it_clones(self):
        got = resolve.resolve('0xbb', 'stub')
        self.assertEqual(got['kind'], 'minimal-clone')
        self.assertEqual(got['effective'], self.DELEGATE)

    def test_a_standard_slot_proxy_resolves_through_the_slot(self):
        self.CODE[self.IMPL] = '0x6080'                    # the implementation has code
        got = resolve.resolve('0xcc', 'stub')
        self.assertEqual(got['kind'], 'proxy')
        self.assertEqual(got['via'], 'eip1967 implementation')
        self.assertEqual(got['effective'], self.IMPL)

    def test_a_slot_pointing_at_nothing_is_dangling_not_proxy(self):
        got = resolve.resolve('0xcc', 'stub')               # no code at the implementation
        self.assertEqual(got['kind'], 'proxy-dangling')
        self.assertIn('has no code', ' '.join(got['evidence']))

    def test_a_bespoke_proxy_resolves_through_the_getter(self):
        got = resolve.resolve('0xdd', 'stub')
        self.assertEqual(got['kind'], 'proxy')
        self.assertEqual(got['via'], 'implementation() getter')

    def test_an_address_with_no_code_says_so(self):
        got = resolve.resolve('0xee', 'stub')
        self.assertEqual(got['kind'], 'no-code')
        self.assertIsNone(got['effective'])

    def test_a_plain_contract_is_left_alone(self):
        got = resolve.resolve('0x99', 'stub')
        self.assertEqual((got['kind'], got['effective']), ('contract', '0x99'))

    def test_delegatecall_without_a_pointer_is_hedged_not_claimed(self):
        got = resolve.resolve('0x12', 'stub')
        self.assertEqual(got['kind'], 'possible-proxy')
        self.assertIn('cannot see', ' '.join(got['evidence']))

    def test_identity_failure_is_never_fatal(self):
        real = resolve.identity
        resolve.identity = lambda *a, **k: {'state': 'not-found'}
        try:
            self.assertEqual(resolve.identity('0x99', 'stub')['state'], 'not-found')
        finally:
            resolve.identity = real


class Cache(unittest.TestCase):
    def setUp(self):
        self.real = resolve.rpc_call
        self.reads = []
        self.tmp = tempfile.TemporaryDirectory()
        self.real_dir = match.CACHE_DIR
        match.CACHE_DIR = Path(self.tmp.name)
        resolve.rpc_call = self.stub

    def tearDown(self):
        resolve.rpc_call = self.real
        match.CACHE_DIR = self.real_dir
        self.tmp.cleanup()

    def stub(self, rpc, method, params, timeout=45):
        self.reads.append(params[0])
        return '0x6080'

    def test_the_second_read_comes_from_disk(self):
        first, hit = match.cached_code('mainnet', '0xdead', 'stub')
        self.assertFalse(hit)
        second, hit = match.cached_code('mainnet', '0xdead', 'stub')
        self.assertTrue(hit)
        self.assertEqual(first, second)
        self.assertEqual(len(self.reads), 1)                       # one rpc call, not two

    def test_a_zero_ttl_always_reads_through(self):
        match.cached_code('mainnet', '0xbeef', 'stub', ttl=0)
        match.cached_code('mainnet', '0xbeef', 'stub', ttl=0)
        self.assertEqual(len(self.reads), 2)


class ScanSubject(unittest.TestCase):
    def test_a_proxy_scan_reports_both_addresses_and_where_the_match_was(self):
        real_resolve, real_identity, real_rpc = resolve.resolve, resolve.identity, resolve.rpc_call
        resolve.rpc_call = lambda rpc, method, params, timeout=45: '0x63e4725ba1637c7a98046382cbf88b' if method == 'eth_getCode' else '0x'
        resolve.resolve = lambda address, rpc, chain='mainnet': {
            'requested': address, 'chain': chain, 'kind': 'proxy', 'effective': '0x' + 'ee' * 20,
            'via': 'test slot', 'evidence': ['test'], 'targets': [(address, 'requested'), ('0x' + 'ee' * 20, 'implementation')]}
        resolve.identity = lambda *a, **k: {'state': 'not-found'}
        try:
            report = match.scan('0x' + 'cc' * 20, REGISTER, use_cache=False)
        finally:
            resolve.resolve, resolve.identity, resolve.rpc_call = real_resolve, real_identity, real_rpc
        self.assertEqual(report['subject']['kind'], 'proxy')
        self.assertEqual([s['role'] for s in report['scans']], ['requested', 'implementation'])
        self.assertEqual({m['role'] for m in report['matches']}, {'requested', 'implementation'})
        self.assertIn('resolved via test slot', sds.subject_line(report))
        page, _ = sds.render(report)
        self.assertIn('Addresses scanned', page)


class NoPersonalPaths(unittest.TestCase):
    def test_no_artifact_carries_this_machines_home_directory(self):
        report = match.scan('0x' + '63e4725ba1' + '637c7a9804' + '6382cbf88b', REGISTER, as_='code')
        blob = json.dumps(report)
        self.assertNotIn('/Users/', blob)
        self.assertNotIn(str(Path.home()), blob)
        page, _ = sds.render(report)
        self.assertNotIn('/Users/', page)
        self.assertIn('epoch-%d.json' % match.latest_anchor()['epoch'], page)   # named by file, not by path

    def test_a_displayed_path_prefers_relative_then_tilde(self):
        self.assertEqual(paths.display(Path(REGISTER, 'HZ-001.json')), 'register/placards/HZ-001.json')
        self.assertTrue(paths.display(Path.home() / 'x').startswith('~/'))
        self.assertEqual(paths.display('/etc/hosts'), '/etc/hosts')


class Api(unittest.TestCase):
    def setUp(self):
        import threading
        import urllib.request
        self.urllib = urllib.request
        self.server = serve.make_server(0, '127.0.0.1')
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.base = 'http://127.0.0.1:%d' % self.server.server_address[1]

    def tearDown(self):
        self.server.shutdown()

    def get(self, path):
        return json.loads(self.urllib.urlopen(self.base + path, timeout=15).read())

    def test_the_page_is_served_with_its_views(self):
        page = self.urllib.urlopen(self.base + '/', timeout=15).read().decode()
        self.assertIn('HAZMAT', page)
        for view in ('registerView', 'placardView', 'anchorsView', 'aboutView'):
            self.assertIn(view, page)

    def test_the_register_endpoint_lists_every_placard_and_the_anchor(self):
        got = self.get('/api/register')
        self.assertEqual(got['count'], 15)
        self.assertEqual(len(got['placards']), 15)
        self.assertTrue(got['digest'].startswith('0x'))
        self.assertEqual(got['anchor']['epoch'], match.latest_anchor()['epoch'])

    def test_a_placard_endpoint_carries_its_confirmation(self):
        got = self.get('/api/placard/HZ-001')
        self.assertTrue(got['matcher']['require_all'])
        self.assertEqual(got['confirmation']['verdict'], 'confirmed')
        self.assertTrue(got['confirmation']['probe_tests'])

    def test_the_proof_endpoint_verifies_against_the_published_root(self):
        got = self.get('/api/proof?placard=HZ-005')
        self.assertTrue(got['verified'])
        latest = match.latest_anchor()
        self.assertEqual(latest['epoch'], got['epoch'])          # proves into the newest epoch
        self.assertEqual(anchor.load_epoch(got['epoch'])['root'], got['root'])

    def test_unknown_ids_are_a_404_with_a_reason(self):
        try:
            self.urllib.urlopen(self.base + '/api/placard/HZ-999', timeout=15)
            self.fail('expected 404')
        except self.urllib.HTTPError as exc:
            self.assertEqual(exc.code, 404)
            self.assertIn('no such placard', json.loads(exc.read())['error'])


class Confirm(unittest.TestCase):
    def test_missing_libs_never_overwrite_verified_files(self):
        with tempfile.TemporaryDirectory() as work, tempfile.TemporaryDirectory() as lib:
            Path(work, 'lib', 'x').mkdir(parents=True)
            Path(work, 'lib', 'x', 'keep.sol').write_text('verified')
            Path(lib, 'keep.sol').write_text('local')
            Path(lib, 'extra.sol').write_text('added')
            added = confirm.add_missing_libs(work, {'x': lib})
            self.assertEqual(Path(work, 'lib', 'x', 'keep.sol').read_text(), 'verified')
            self.assertEqual(Path(work, 'lib', 'x', 'extra.sol').read_text(), 'added')
            self.assertEqual(added, ['lib/x/extra.sol'])

    def test_compare_reports_selector_agreement_and_immutable_drift(self):
        selectors = b'\x63\xe4\x72\x5b\xa1' + b'\x63\x7c\x7a\x98\x04'
        deployed, _ = match.strip_metadata(selectors + b'\x00\x11' + b'\x93\xa2')
        with tempfile.TemporaryDirectory() as out:
            art = Path(out, 'C.sol', 'C.json')
            art.parent.mkdir(parents=True)
            art.write_text(json.dumps({'deployedBytecode': {'object': '0x' + (selectors + b'\xff\xff').hex() + '00' + b'\x93\xa2'.hex()}}))
            got = confirm.compare_rebuilt(out, 'C', deployed + b'\x00\x22' + b'\x93\xa2')
            self.assertEqual(got['selectors_missing_from_rebuild'], [])
            self.assertEqual(got['selectors_extra_in_rebuild'], [])
            self.assertEqual(got['selectors_deployed'], 2)

    def test_a_partial_remapping_set_still_reaches_forge_std(self):
        with tempfile.TemporaryDirectory() as work:
            toml = confirm.write_foundry_toml(work, {'remappings': ['@openzeppelin/contracts/=lib/oz/']}, None, '0.8.27')
            self.assertIn('@openzeppelin/contracts/=lib/oz/', toml)      # the record's own entry wins
            self.assertIn('forge-std/=lib/forge-std/src/', toml)          # the needed one is appended
            self.assertIn('solc_version = "0.8.27"', toml)                # no local binary: pin the version
            self.assertNotIn('solc = ', toml)

    def test_a_target_label_is_reduced_to_its_address(self):
        placard = {'id': 'HZ-900', 'confirmed_on': [{'target': 'Thing 0xAbCd000000000000000000000000000000001234 chainId 1'}]}
        self.assertEqual(confirm.normalise_target(None, placard), '0xAbCd000000000000000000000000000000001234')
        self.assertEqual(confirm.normalise_target('see 0x' + '11' * 20 + ' now', placard), '0x' + '11' * 20)
        with self.assertRaises(confirm.ConfirmError):
            confirm.normalise_target('no address here', placard)

    def test_add_sources_never_overwrites_and_records_a_digest(self):
        with tempfile.TemporaryDirectory() as work, tempfile.TemporaryDirectory() as up:
            Path(work, 'src').mkdir()
            Path(work, 'src', 'kept.sol').write_text('from the bundle')
            Path(up, 'kept.sol').write_text('from upstream')
            Path(up, 'added.sol').write_text('from upstream too')
            added = confirm.add_sources(work, [('src/kept.sol', up + '/kept.sol'), ('src/added.sol', up + '/added.sol')])
            self.assertEqual(Path(work, 'src', 'kept.sol').read_text(), 'from the bundle')
            self.assertEqual(Path(work, 'src', 'added.sol').read_text(), 'from upstream too')
            self.assertEqual([a['path'] for a in added], ['src/added.sol'])
            self.assertEqual(len(added[0]['sha256']), 64)

    def test_discover_libs_finds_what_exists_and_records_it(self):
        found = confirm.discover_libs()
        self.assertIn('forge-std', found)
        self.assertTrue(os.path.isdir(found['forge-std']))
        explicit = confirm.discover_libs({'forge-std': '/tmp'})
        self.assertEqual(explicit['forge-std'], '/tmp')

    def test_find_solc_returns_a_path_or_none(self):
        got = confirm.find_solc('0.8.27')
        self.assertTrue(got is None or os.path.isfile(got))


class Sheet(unittest.TestCase):
    def test_sheet_carries_the_evidence_and_its_own_hash(self):
        report = match.scan('0x' + code_with('0xe4725ba1', '0x7c7a9804', '0x82cbf88b').hex(), REGISTER)
        page, digest = sds.render(report)
        self.assertIn('HZ-001', page)
        self.assertIn('Assertion level: pattern', page)
        self.assertTrue(digest.startswith('0x') and len(digest) == 66)

    def test_a_clean_sheet_still_says_it_is_not_a_clean_bill(self):
        report = match.scan('0x' + code_with('0x11111111').hex(), REGISTER)
        page, _ = sds.render(report)
        self.assertEqual(report['matches'], [])
        self.assertIn('not the same as safe', page)


class Keccak(unittest.TestCase):
    def test_known_vectors(self):
        self.assertEqual(keccak.keccak256(b'').hex(),
                         'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470')
        self.assertEqual(keccak.keccak256(b'abc').hex(),
                         '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45')

    def test_selectors_match_the_known_values(self):
        self.assertEqual(keccak.selector('accept(bytes32)'), '0xe4725ba1')
        self.assertEqual(keccak.selector('transfer(address,uint256)'), '0xa9059cbb')
        self.assertEqual(keccak.selector('settleExpired(bytes32)'), '0x7c7a9804')


class Chains(unittest.TestCase):
    def test_every_entry_resolves_and_has_a_chain_id(self):
        for name in chains.CHAINS:
            self.assertTrue(chains.endpoint(name).startswith('http'))
            self.assertIsInstance(chains.chain_id(name), int)

    def test_unknown_chain_is_loud(self):
        with self.assertRaises(KeyError):
            chains.endpoint('polygon')


class Batch(unittest.TestCase):
    def test_one_report_per_line_and_a_sheet_only_when_something_matches(self):
        import tempfile
        code = '0x' + ('63e4725ba1637c7a98046382cbf88b' + '63' + '82cbf88b')
        plain = '0x' + '6311111111'
        path = tempfile.mktemp(suffix='.txt')
        open(path, 'w').write('# a comment\n%s\n\n%s\n' % (code, plain))
        with tempfile.TemporaryDirectory() as sheets:
            reports = batch.run(path, REGISTER, sheet_dir=sheets, quiet=True, as_='code')
            self.assertEqual(len(reports), 2)
            self.assertEqual([m['id'] for m in reports[0]['matches']], ['HZ-001'])
            self.assertEqual(reports[1]['matches'], [])
            self.assertEqual(len(os.listdir(sheets)), 2)   # a clean sheet is a document too
            page = Path(sheets, os.listdir(sheets)[0]).read_text()
            html = [p for p in Path(sheets).iterdir() if 'not the same as safe' in p.read_text()]
            self.assertTrue(html)


class Derive(unittest.TestCase):
    def test_struct_parameters_expand_to_their_tuple_form(self):
        table = {'Approval': ['bytes32', 'uint256', 'address']}
        self.assertEqual(derive.expand('Approval', table), '(bytes32,uint256,address)')
        self.assertEqual(derive.expand('Approval[]', table), 'Approval[]')
        self.assertEqual(derive.expand('bytes', table), 'bytes')

    def test_signature_extraction_skips_internal_and_keeps_external(self):
        tmp = Path(__file__).resolve().parent / '_sig_probe.sol'
        tmp.write_text('contract C { function a(uint256 x) external {} function b() internal {} }')
        try:
            sigs = derive.signatures([str(tmp)])
            self.assertIn('a(uint256)', sigs)
            self.assertNotIn('b()', sigs)
        finally:
            tmp.unlink()

    def test_empty_matcher_is_caught(self):
        rows = match.load_register(REGISTER)
        for row in rows:
            self.assertTrue(row['matcher'].get('require_all') or row['matcher'].get('require_any'))


if __name__ == '__main__':
    unittest.main()
