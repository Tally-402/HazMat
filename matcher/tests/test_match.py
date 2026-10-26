"""Matcher: metadata exclusion, push-data safety, honest assertion level."""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
ROOT = Path(__file__).resolve().parents[2]
REGISTER = str(ROOT / 'register' / 'placards')

from hazmat import match, sds  # noqa: E402

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
        self.assertEqual([r['id'] for r in rows], ['HZ-001'])
        self.assertEqual(len(rows[0]['matcher']['require_all']), 3)


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


if __name__ == '__main__':
    unittest.main()
