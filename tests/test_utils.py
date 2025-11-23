import unittest
import sys
import os
import shutil

# Add parent directory to path to import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils import ensure_results_dir, timestamp_str, safe_reverse_dns

class TestUtils(unittest.TestCase):
    def test_ensure_results_dir(self):
        # Remove if exists to test creation
        if os.path.exists("results"):
            # Only remove if empty or safe to do so? 
            # Better to just check it returns the right string and path exists
            pass
        
        res = ensure_results_dir()
        self.assertEqual(res, "results")
        self.assertTrue(os.path.exists("results"))

    def test_timestamp_str(self):
        ts = timestamp_str()
        self.assertRegex(ts, r"\d{8}-\d{6}")

    def test_safe_reverse_dns(self):
        # Localhost should resolve
        res = safe_reverse_dns("127.0.0.1")
        self.assertIsInstance(res, str)
        
        # Invalid IP should return input
        res = safe_reverse_dns("999.999.999.999")
        self.assertEqual(res, "999.999.999.999")

if __name__ == '__main__':
    unittest.main()
