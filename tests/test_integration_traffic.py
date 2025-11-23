import unittest
import sys
import os
import time
from collections import Counter

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from traffic_analysis import NetstatAnalyzer, ScapySniffer, _HAS_SCAPY

class TestIntegrationTraffic(unittest.TestCase):
    def setUp(self):
        # Read duration from env, default to 3s
        self.duration = float(os.environ.get("TEST_DURATION", "3.0"))
        print(f"\nRunning integration test with duration={self.duration}s")

    def test_netstat_real(self):
        """Test NetstatAnalyzer against the real OS netstat/ss command."""
        analyzer = NetstatAnalyzer()
        
        print("Sampling netstat once...")
        c, pids, procs = analyzer.sample_once()
        
        # We can't guarantee connections exist, but we can check types
        self.assertIsInstance(c, Counter)
        self.assertIsInstance(pids, dict)
        self.assertIsInstance(procs, dict)
        
        # If we have any connections, check structure
        if len(c) > 0:
            key = list(c.keys())[0]
            self.assertIsInstance(key, str)
            print(f"  Found {len(c)} connections. Sample: {key} -> {c[key]}")
        else:
            print("  No active connections found (this is possible but rare on active machines).")

        # Test timed sampling
        print(f"Sampling netstat for {self.duration}s...")
        start = time.time()
        agg_c, agg_p, agg_pr = analyzer.sample_timed(duration_seconds=self.duration, sample_interval=1.0)
        elapsed = time.time() - start
        
        self.assertTrue(elapsed >= self.duration)
        self.assertIsInstance(agg_c, Counter)
        print(f"  Aggregated {len(agg_c)} unique endpoints.")

    def test_scapy_real(self):
        """Test ScapySniffer against real network interface (requires Admin/Sudo)."""
        if not _HAS_SCAPY:
            self.skipTest("Scapy not installed or not available.")
        
        # Check if we have permissions by trying to sniff 1 packet
        try:
            from scapy.all import sniff
            sniff(count=1, timeout=0.1, store=0)
        except Exception as e:
            self.skipTest(f"Skipping scapy test (likely insufficient privileges): {e}")

        print(f"Sniffing packets for {self.duration}s...")
        sniffer = ScapySniffer()
        start = time.time()
        c, p, pr = sniffer.sample_timed(duration_seconds=self.duration)
        elapsed = time.time() - start
        
        self.assertTrue(elapsed >= self.duration)
        self.assertIsInstance(c, dict)
        print(f"  Captured {len(c)} unique destinations.")

if __name__ == '__main__':
    unittest.main()
