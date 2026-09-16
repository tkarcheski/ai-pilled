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
