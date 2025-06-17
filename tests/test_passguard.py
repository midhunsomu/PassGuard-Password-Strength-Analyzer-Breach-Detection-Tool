import unittest
from unittest.mock import patch, MagicMock
import math
import sys
import os

# Append project root to sys.path so we can import passguard
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from passguard.entropy import calculate_entropy, analyze_length, get_base_strength_score
from passguard.patterns import (
    find_repeated_patterns,
    find_keyboard_patterns,
    find_sequential_patterns,
    analyze_patterns
)
from passguard.breach import lookup_breach
from passguard.reporter import analyze_password


class TestEntropy(unittest.TestCase):
    def test_calculate_entropy_empty(self):
        self.assertEqual(calculate_entropy(""), 0.0)

    def test_calculate_entropy_digits_only(self):
        # pool size = 10, length = 8 -> 8 * log2(10) ~ 26.575
        self.assertAlmostEqual(calculate_entropy("12345678"), 8 * math.log2(10), places=4)

    def test_calculate_entropy_mixed(self):
        # pool size = lowercase(26) + uppercase(26) + digits(10) + special(33) = 95
        # length = 4 -> 4 * log2(95) ~ 26.279
        self.assertAlmostEqual(calculate_entropy("aA1!"), 4 * math.log2(95), places=4)

    def test_analyze_length_critical(self):
        res = analyze_length("123")
        self.assertEqual(res["severity"], "CRITICAL")
        self.assertEqual(res["length"], 3)

    def test_analyze_length_warning(self):
        res = analyze_length("123456789")
        self.assertEqual(res["severity"], "WARNING")

    def test_analyze_length_ok(self):
        res = analyze_length("1234567890123")
        self.assertEqual(res["severity"], "OK")

    def test_analyze_length_safe(self):
        res = analyze_length("12345678901234567")
        self.assertEqual(res["severity"], "SAFE")


class TestPatterns(unittest.TestCase):
    def test_find_repeated_patterns(self):
        self.assertEqual(find_repeated_patterns("abc"), [])
        self.assertEqual(find_repeated_patterns("aaa"), ["aaa"])
        self.assertEqual(find_repeated_patterns("abbbccc"), ["bbb", "ccc"])

    def test_find_sequential_patterns(self):
        self.assertEqual(find_sequential_patterns("abc"), ["abc"])
        self.assertEqual(find_sequential_patterns("zyx"), ["zyx"])
        self.assertEqual(find_sequential_patterns("1234"), ["1234"])
        self.assertEqual(find_sequential_patterns("a1b2c3"), [])

    def test_find_keyboard_patterns(self):
        self.assertEqual(find_keyboard_patterns("qwe"), ["qwe"])
        self.assertEqual(find_keyboard_patterns("asd"), ["asd"])
        self.assertEqual(find_keyboard_patterns("rewq"), ["rewq"])
        self.assertEqual(find_keyboard_patterns("plm"), [])


class TestBreach(unittest.TestCase):
    @patch("requests.get")
    def test_lookup_breach_found(self, mock_get):
        # Mock response
        # Let's say suffix is "D4F6E8F67C82B8F54DBE86629910D701C"
        # Mock API returns:
        # D4F6E8F67C82B8F54DBE86629910D701C:42
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "D4F6E8F67C82B8F54DBE86629910D701C:42\nAAAAAA:10"
        mock_get.return_value = mock_response

        # Password with SHA1 hash having prefix and that suffix
        # The password "password" has SHA-1: 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        # Let's use custom password so we can control hash suffix
        with patch("hashlib.sha1") as mock_sha1:
            mock_sha1_instance = MagicMock()
            # 5-char prefix + suffix
            mock_sha1_instance.hexdigest.return_value = "12345D4F6E8F67C82B8F54DBE86629910D701C"
            mock_sha1.return_value = mock_sha1_instance

            count, err = lookup_breach("dummy_pwd")
            self.assertEqual(count, 42)
            self.assertIsNone(err)

    @patch("requests.get")
    def test_lookup_breach_not_found(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "FFFFFF:5"
        mock_get.return_value = mock_response

        count, err = lookup_breach("password")
        self.assertEqual(count, 0)
        self.assertIsNone(err)


class TestReporter(unittest.TestCase):
    @patch("passguard.reporter.lookup_breach")
    @patch("passguard.reporter.is_common_password")
    def test_analyze_password_strong(self, mock_is_common, mock_lookup_breach):
        mock_is_common.return_value = (False, None)
        mock_lookup_breach.return_value = (0, None)

        # High entropy password with no patterns: "Xy9$pQ2#mK1@zW4!aB3#" (len 20, various sets)
        res = analyze_password("Xy9$pQ2#mK1@zW4!aB3#")
        self.assertEqual(res["score"], "Very Strong")
        self.assertEqual(res["breach_count"], 0)
        self.assertEqual(len(res["weaknesses"]), 0)

    @patch("passguard.reporter.lookup_breach")
    @patch("passguard.reporter.is_common_password")
    def test_analyze_password_compromised(self, mock_is_common, mock_lookup_breach):
        mock_is_common.return_value = (True, None)
        mock_lookup_breach.return_value = (5000, None)

        res = analyze_password("123456")
        self.assertEqual(res["score"], "Very Weak")
        self.assertIn("Found in list of top 10,000 common passwords", res["weaknesses"])
        self.assertTrue(res["breach_count"] > 0)


if __name__ == "__main__":
    unittest.main()
