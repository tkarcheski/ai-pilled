import json
import unittest

from ai_pilled.json_data import loads


class StructuredInputTests(unittest.TestCase):
    def test_nesting_limit_has_an_exact_boundary(self):
        value = loads('[' * 100 + '0' + ']' * 100)
        for _ in range(100):
            value = value[0]
        self.assertEqual(value, 0)
        with self.assertRaises(ValueError):
            loads('[' * 101 + '0' + ']' * 101)

    def test_broad_shallow_documents_are_not_mistaken_for_deep_documents(self):
        value = [{'value': number} for number in range(2000)]
        self.assertEqual(loads(json.dumps(value)), value)

    def test_nested_looking_string_content_is_preserved(self):
        value = '[' * 1500 + 'text' + ']' * 1500
        self.assertEqual(loads(json.dumps(value)), value)

    def test_duplicate_keys_are_rejected_at_every_depth_without_echoing_keys(self):
        for raw in ('{"private-key":1,"private-key":2}',
                    '{"nested":[{"private-key":1,"private-key":1}]}',
                    '{"name":1,"na\\u006de":2}'):
            for payload in (raw, raw.encode(), raw.encode('utf-16')):
                with self.subTest(payload_type=type(payload).__name__):
                    with self.assertRaises(ValueError) as raised:
                        loads(payload)
                    self.assertNotIn('private-key', str(raised.exception))
        self.assertEqual(loads('[{"name":1},{"name":2}]'), [{'name': 1}, {'name': 2}])

    def test_nonfinite_numbers_and_overflow_are_rejected_but_strings_are_preserved(self):
        for token in ('NaN', 'Infinity', '-Infinity', '1e999', '-1e999'):
            with self.subTest(token=token):
                for raw in (token, '{"nested":[' + token + ']}'):
                    with self.assertRaises(ValueError):
                        loads(raw)
                self.assertEqual(loads(json.dumps(token)), token)
        self.assertEqual(loads('[1.25,0.0,-0.0,1e100]'), [1.25, 0.0, -0.0, 1e100])
