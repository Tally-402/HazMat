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

from hazmat import batch, chains, confirm, derive, keccak, match, pdf, sds, serve, verify, watch  # noqa: E402

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
            self.assertIn('Paste a contract address', form)
            self.assertIn('<select name="chain">', form)
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
                               inspect_fn=self.inspector({'0xaaa'}), sink=self.alerts)
        self.assertEqual(first['candidates'], 2)
        self.assertEqual(first['matched'], 1)
        again = watch.pass_once(self.db, 'mainnet', feed=self.feed(*entries),
                                inspect_fn=self.inspector({'0xaaa'}), sink=self.alerts)
        self.assertEqual(again['candidates'], 0)
        self.assertEqual(watch.status(self.db)['alerts'], 1)

    def test_an_unreachable_address_is_recorded_without_an_alert(self):
        entries = [{'address': '0xdead', 'verifiedAt': '2026-02-01T00:00:00Z'}]
        def inspector(_):
            raise match.MatchError('no code')
        got = watch.pass_once(self.db, 'mainnet', feed=self.feed(*entries), inspect_fn=inspector,
                              sink=self.alerts)
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
        watch.pass_once(self.db, 'mainnet', feed=self.feed(*entry), inspect_fn=inspector, sink=self.alerts)
        watch.pass_once(self.db, 'mainnet', feed=self.feed(*again), inspect_fn=inspector, sink=self.alerts)
        kinds = [json.loads(l)['kind'] for l in Path(self.alerts).read_text().strip().splitlines()]
        self.assertEqual(kinds, ['new', 'upgrade'])

    def test_the_cursor_does_not_move_backwards(self):
        watch.pass_once(self.db, 'mainnet', feed=self.feed({'address': '0x1', 'verifiedAt': '2026-05-01T00:00:00Z'}),
                        inspect_fn=self.inspector(), sink=self.alerts)
        older = [{'address': '0x2', 'verifiedAt': '2026-04-01T00:00:00Z'}]
        got = watch.pass_once(self.db, 'mainnet', feed=self.feed(*older), inspect_fn=self.inspector(),
                              sink=self.alerts)
        self.assertEqual(got['candidates'], 0)
        self.assertEqual(got['cursor'], '2026-04-01T00:00:00Z')

    def test_status_counts_and_the_alert_file_is_jsonl(self):
        watch.pass_once(self.db, 'mainnet', feed=self.feed({'address': '0xm', 'verifiedAt': '2026-06-01T00:00:00Z'}),
                        inspect_fn=self.inspector({'0xm'}), sink=self.alerts)
        state = watch.status(self.db)
        self.assertEqual((state['seen'], state['alerts'], state['matched_ever']), (1, 1, 1))
        self.assertEqual(json.loads(Path(self.alerts).read_text().strip())['placards'], ['HZ-001'])


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
