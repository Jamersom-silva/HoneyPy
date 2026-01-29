import unittest
import tempfile
import json
import time
from datetime import datetime, timedelta
from src.core.tracker import IPTracker

class TestIPTracker(unittest.TestCase):
    
    def setUp(self):
        self.config = {
            'window_minutes': 10,
            'max_attempts': 5,
            'thresholds': {
                'ssh': {'max_attempts': 3, 'time_window_minutes': 5},
                'http': {'max_attempts': 10, 'time_window_minutes': 10}
            },
            'auto_block': False,
            'block_duration_hours': 24
        }
        self.tracker = IPTracker(self.config)
    
    def test_record_attempt_normal(self):
        result = self.tracker.record_attempt('192.168.1.100', 'ssh')
        self.assertFalse(result['is_attack'])
        self.assertEqual(len(self.tracker.attempts_log['192.168.1.100']), 1)
    
    def test_record_attack_detection(self):
        for i in range(4):
            result = self.tracker.record_attempt('192.168.1.101', 'ssh')
        
        self.assertTrue(result['is_attack'])
        self.assertIn('192.168.1.101', self.tracker.suspicious_ips)
    
    def test_get_attack_statistics(self):
        for i in range(3):
            self.tracker.record_attempt('192.168.1.102', 'ssh')
        
        stats = self.tracker.get_attack_statistics('192.168.1.102')
        self.assertEqual(stats['total_attempts'], 3)
        self.assertIn('ssh', stats['services_attacked'])
    
    def test_block_ip(self):
        result = self.tracker.block_ip('192.168.1.103')
        self.assertTrue(result['success'])
        self.assertIn('192.168.1.103', self.tracker.blocked_ips)
    
    def test_unblock_ip(self):
        self.tracker.block_ip('192.168.1.104')
        result = self.tracker.unblock_ip('192.168.1.104')
        self.assertTrue(result['success'])
        self.assertNotIn('192.168.1.104', self.tracker.blocked_ips)
    
    def test_whitelist(self):
        self.tracker.add_to_whitelist('192.168.1.105')
        self.assertIn('192.168.1.105', self.tracker.whitelist_ips)
        
        result = self.tracker.record_attempt('192.168.1.105', 'ssh')
        self.assertFalse(result['is_attack'])
        self.assertEqual(result['reason'], 'IP na whitelist')
    
    def test_cleanup_old_entries(self):
        old_time = time.time() - (40 * 24 * 3600)
        self.tracker.attempts_log['old_ip'].append({
            'timestamp': old_time,
            'service': 'ssh',
            'username': None,
            'password': None
        })
        
        removed = self.tracker.cleanup_old_entries(30)
        self.assertGreaterEqual(removed, 1)
        self.assertNotIn('old_ip', self.tracker.attempts_log)
    
    def test_get_all_suspicious_ips(self):
        for i in range(6):
            self.tracker.record_attempt('192.168.1.106', 'ssh')
        
        suspicious = self.tracker.get_all_suspicious_ips()
        self.assertGreater(len(suspicious), 0)
    
    def test_get_all_blocked_ips(self):
        self.tracker.block_ip('192.168.1.107')
        blocked = self.tracker.get_all_blocked_ips()
        self.assertEqual(len(blocked), 1)
    
    def test_invalid_ip(self):
        result = self.tracker.block_ip('invalid_ip')
        self.assertFalse(result['success'])
        self.assertIn('error', result)
    
    def test_private_ip_block(self):
        result = self.tracker.block_ip('10.0.0.1')
        self.assertFalse(result['success'])
        self.assertIn('IP privado', result['error'])

if __name__ == '__main__':
    unittest.main()