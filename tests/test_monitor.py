import unittest
from unittest.mock import MagicMock, patch
import sys
import os

# Add parent directory to path to import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from monitor import Monitor

class TestMonitor(unittest.TestCase):
    def setUp(self):
        self.monitor = Monitor()

    @patch('monitor.subprocess.run')
    def test_ping_success(self, mock_run):
        # Mock successful ping output
        mock_proc = MagicMock()
        mock_proc.stdout = "Reply from 1.1.1.1: bytes=32 time=15ms TTL=56"
        mock_run.return_value = mock_proc

        lat, ttl = self.monitor._ping()
        self.assertEqual(lat, 15.0)
        self.assertEqual(ttl, 56)

    @patch('monitor.subprocess.run')
    def test_ping_failure(self, mock_run):
        # Mock failed ping
        mock_proc = MagicMock()
        mock_proc.stdout = "Request timed out."
        mock_run.return_value = mock_proc

        lat, ttl = self.monitor._ping()
        self.assertIsNone(lat)
        self.assertIsNone(ttl)

    @patch('monitor.requests.get')
    def test_get_public_ip_success(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "123.123.123.123"
        mock_get.return_value = mock_response

        ip = self.monitor._get_public_ip()
        self.assertEqual(ip, "123.123.123.123")

    @patch('monitor.requests.get')
    def test_get_public_ip_failure(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_get.return_value = mock_response

        ip = self.monitor._get_public_ip()
        self.assertIsNone(ip)

    @patch('monitor.Monitor._ping')
    @patch('monitor.Monitor._get_public_ip')
    def test_monitor_run(self, mock_ip, mock_ping):
        mock_ip.return_value = "1.2.3.4"
        mock_ping.return_value = (20.0, 55)

        # Run for a very short time
        self.monitor.start(duration_seconds=0.1, interval_seconds=0.05)
        import time
        time.sleep(0.2) # Wait for thread to finish
        self.monitor.stop()

        data = self.monitor.get_data()
        self.assertTrue(len(data['timestamps']) > 0)
        self.assertTrue(len(data['latencies']) > 0)
        self.assertEqual(data['latencies'][0], 20.0)

if __name__ == '__main__':
    unittest.main()
