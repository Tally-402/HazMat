"""Matcher: metadata exclusion, push-data safety, honest assertion level."""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
ROOT = Path(__file__).resolve().parents[2]
REGISTER = str(ROOT / 'register' / 'placards')

import os

from hazmat import batch, chains, derive, keccak, match, sds  # noqa: E402

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
        blob = '0x' + ('63e4725ba1' * 3 + '637c7a9804' + '6382cbf88b')[:40]
        found, _ = match.match_code(bytes.fromhex(blob[2:]), PLACARD)
        self.assertEqual([m['id'] for m in found], [])          # truncated, so only the first selector survives
        full = '0x' + '63e4725ba1637c7a98046382cbf88b' + '63' + '82cbf88b'
        report = match.scan(full, REGISTER, as_='code')
        self.assertEqual([m['id'] for m in report['matches']], ['HZ-001'])

    def test_an_unknown_as_is_loud(self):
        with self.assertRaises(match.MatchError):
            match.load_code('0x' + '00' * 20, as_='nonsense')


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
            self.assertEqual(len(os.listdir(sheets)), 1)


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
