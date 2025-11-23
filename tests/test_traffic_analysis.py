import unittest
from unittest.mock import MagicMock, patch
import sys
import os
from collections import Counter, defaultdict

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from traffic_analysis import NetstatAnalyzer, ScapySniffer

class TestNetstatAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = NetstatAnalyzer()

    @patch('traffic_analysis.subprocess.check_output')
    @patch('traffic_analysis.sys.platform', 'win32')
    def test_parse_windows(self, mock_check_output):
        # Mock netstat output for Windows
        # Proto  Local Address          Foreign Address        State           PID
        mock_output = """
  TCP    192.168.1.5:5000       1.1.1.1:443            ESTABLISHED     1234
  TCP    192.168.1.5:5001       8.8.8.8:53             TIME_WAIT       1234
  UDP    0.0.0.0:123            *:*                                    5678
"""
        mock_check_output.return_value = mock_output
        
        # Mock get_process_info_windows helper
        with patch('traffic_analysis.get_process_info_windows') as mock_get_proc:
            mock_get_proc.return_value = "test_proc.exe"
            
            c, pids, procs = self.analyzer.sample_once()
            
            # Should only count ESTABLISHED
            self.assertEqual(c['1.1.1.1:443'], 1)
            self.assertEqual(c['8.8.8.8:53'], 0) # TIME_WAIT ignored in code?
            # Let's check the code: if state.upper() in ("ESTABLISHED", "ESTAB", "SYN_SENT", "SYN_RECEIVED")
            
            self.assertIn('1234', pids['1.1.1.1:443'])
            self.assertIn('test_proc.exe', procs['1.1.1.1:443'])

    @patch('traffic_analysis.subprocess.check_output')
    def test_sample_timed(self, mock_check_output):
        # Mock simple output
        mock_output = "TCP 1.2.3.4:123 5.6.7.8:443 ESTABLISHED 999"
        # The regex expects specific format, let's just mock sample_once directly for easier testing of aggregation
        
        with patch.object(self.analyzer, 'sample_once') as mock_sample_once:
            # Return 2 samples
            c1 = Counter({'1.1.1.1': 1})
            p1 = defaultdict(list, {'1.1.1.1': ['100']})
            pr1 = defaultdict(list, {'1.1.1.1': ['proc1']})
            
            c2 = Counter({'1.1.1.1': 1, '2.2.2.2': 1})
            p2 = defaultdict(list, {'1.1.1.1': ['100'], '2.2.2.2': ['200']})
            pr2 = defaultdict(list, {'1.1.1.1': ['proc1'], '2.2.2.2': ['proc2']})
            
            mock_sample_once.side_effect = [(c1, p1, pr1), (c2, p2, pr2)]
            
            # Run for short time
            agg_c, agg_p, agg_pr = self.analyzer.sample_timed(duration_seconds=0.1, sample_interval=0.05)
            
            self.assertEqual(agg_c['1.1.1.1'], 2)
            self.assertEqual(agg_c['2.2.2.2'], 1)

class TestScapySniffer(unittest.TestCase):
    def test_init_no_scapy(self):
        # If scapy is not present, it should raise RuntimeError
        # We need to force _HAS_SCAPY to False
        with patch('traffic_analysis._HAS_SCAPY', False):
            with self.assertRaises(RuntimeError):
                ScapySniffer()

    def test_sample_timed(self):
        # We need to mock scapy.all.sniff
        # And _HAS_SCAPY = True
        with patch('traffic_analysis._HAS_SCAPY', True):
            sniffer = ScapySniffer()
            
            with patch('traffic_analysis.sniff') as mock_sniff:
                # Mock sniff execution
                # It takes a prn callback. We can simulate it calling the callback.
                def side_effect(count, prn, timeout, iface):
                    # Create a mock packet
                    pkt = MagicMock()
                    pkt.haslayer.return_value = True # TCP/UDP
                    pkt.__contains__.return_value = True # IP
                    pkt.__len__.return_value = 100
                    pkt.__getitem__.return_value.dst = "1.1.1.1" # pkt[IP].dst
                    
                    # Call callback
                    prn(pkt)
                
                mock_sniff.side_effect = side_effect
                
                # Also mock NetstatAnalyzer for correlation
                with patch('traffic_analysis.NetstatAnalyzer') as MockAnalyzer:
                    mock_ana = MockAnalyzer.return_value
                    mock_ana.sample_once.return_value = (Counter(), {}, {})
                    
                    c, p, pr = sniffer.sample_timed(duration_seconds=0.1)
                    
                    self.assertEqual(c['1.1.1.1'], 100)

    @patch('traffic_analysis.get_process_map_psutil')
    @patch('traffic_analysis.subprocess.check_output')
    @patch('traffic_analysis.sys.platform', 'win32')
    @patch('traffic_analysis.psutil.Process')
    def test_get_process_map_combined(self, mock_psutil_process, mock_check_output, mock_get_psutil):
        from traffic_analysis import get_process_map_combined
        
        # Mock psutil returning one process
        mock_get_psutil.return_value = (
            {'1.1.1.1': 'psutil_proc.exe'},
            defaultdict(list, {'1.1.1.1': ['100']})
        )
        
        # Mock netstat returning another process
        # TCP    192.168.1.5:5000       2.2.2.2:80             ESTABLISHED     200
        mock_output = """
  TCP    192.168.1.5:5000       2.2.2.2:80             ESTABLISHED     200
"""
        mock_check_output.return_value = mock_output
        
        # Mock psutil.Process(200).name() -> "netstat_proc.exe"
        mock_proc_instance = MagicMock()
        mock_proc_instance.name.return_value = "netstat_proc.exe"
        
        def side_effect(pid):
            if pid == 200:
                return mock_proc_instance
            raise Exception("Process not found")
            
        mock_psutil_process.side_effect = side_effect
            
        ip_proc, ip_pids = get_process_map_combined()
        
        # Check psutil data preserved
        self.assertEqual(ip_proc['1.1.1.1'], 'psutil_proc.exe')
        self.assertIn('100', ip_pids['1.1.1.1'])
        
        # Check netstat data added
        self.assertEqual(ip_proc['2.2.2.2:80'], 'netstat_proc.exe')
        self.assertIn('200', ip_pids['2.2.2.2:80'])

    def test_scapy_uses_combined_map(self):
        with patch('traffic_analysis._HAS_SCAPY', True):
            sniffer = ScapySniffer()
            with patch('traffic_analysis.get_process_map_combined') as mock_combined:
                mock_combined.return_value = ({}, {})
                
                # We just want to verify it's called during sample_timed
                # But sample_timed runs a thread. We can check if it's called at least once (pre/post snapshot).
                with patch('traffic_analysis.sniff'):
                     sniffer.sample_timed(duration_seconds=0.1)
                     self.assertTrue(mock_combined.called)

if __name__ == '__main__':
    unittest.main()
