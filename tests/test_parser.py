import unittest
import tempfile
import os
from src.core.parser import LogParser
from src.core.tracker import IPTracker

class TestLogParser(unittest.TestCase):
    
    def setUp(self):
        self.config = {
            'log_types': ['ssh', 'http'],
            'paths': {
                'log_files': {
                    'ssh': '/tmp/test_auth.log',
                    'http': '/tmp/test_access.log'
                }
            }
        }
        self.tracker = IPTracker({'window_minutes': 10, 'max_attempts': 5})
        self.parser = LogParser(self.tracker, self.config)
        
        self.create_test_logs()
    
    def create_test_logs(self):
        ssh_log_content = """
Jan 30 10:00:00 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2
Jan 30 10:00:01 server sshd[1235]: Failed password for admin from 192.168.1.100 port 22 ssh2
Jan 30 10:00:02 server sshd[1236]: Failed password for user from 192.168.1.101 port 22 ssh2
"""
        
        http_log_content = """
192.168.1.102 - - [30/Jan/2024:10:00:03 +0000] "POST /wp-login.php HTTP/1.1" 200 1234
192.168.1.102 - - [30/Jan/2024:10:00:04 +0000] "POST /wp-login.php HTTP/1.1" 200 1234
192.168.1.103 - - [30/Jan/2024:10:00:05 +0000] "GET /admin HTTP/1.1" 401 567
"""
        
        with open('/tmp/test_auth.log', 'w') as f:
            f.write(ssh_log_content)
        
        with open('/tmp/test_access.log', 'w') as f:
            f.write(http_log_content)
    
    def tearDown(self):
        if os.path.exists('/tmp/test_auth.log'):
            os.remove('/tmp/test_auth.log')
        if os.path.exists('/tmp/test_access.log'):
            os.remove('/tmp/test_access.log')
    
    def test_parse_ssh_log(self):
        attempts = self.parser.parse_log_file('/tmp/test_auth.log', 'ssh')
        self.assertEqual(len(attempts), 3)
        
        for attempt in attempts:
            self.assertEqual(attempt['log_type'], 'ssh')
            self.assertIn('ip_address', attempt)
    
    def test_parse_http_log(self):
        attempts = self.parser.parse_log_file('/tmp/test_access.log', 'http')
        self.assertEqual(len(attempts), 3)
        
        for attempt in attempts:
            self.assertEqual(attempt['log_type'], 'http')
    
    def test_process_attempts(self):
        attempts = self.parser.parse_log_file('/tmp/test_auth.log', 'ssh')
        processed = self.parser.process_attempts(attempts)
        
        self.assertEqual(len(processed), 3)
        for attempt in processed:
            self.assertIn('analysis', attempt)
    
    def test_infer_log_type(self):
        log_type = self.parser.infer_log_type('/var/log/auth.log')
        self.assertEqual(log_type, 'ssh')
        
        log_type = self.parser.infer_log_type('/var/log/access.log')
        self.assertEqual(log_type, 'unknown')
    
    def test_generate_line_hash(self):
        line = "test line"
        log_path = "/tmp/test.log"
        hash1 = self.parser.generate_line_hash(line, log_path)
        hash2 = self.parser.generate_line_hash(line, log_path)
        
        self.assertEqual(hash1, hash2)
        
        hash3 = self.parser.generate_line_hash("different line", log_path)
        self.assertNotEqual(hash1, hash3)
    
    def test_save_and_load_state(self):
        self.parser.log_positions = {'/tmp/test.log': 1234}
        self.parser.line_hashes = {'hash1', 'hash2'}
        
        self.parser.save_state()
        
        new_parser = LogParser(self.tracker, self.config)
        
        self.assertEqual(len(new_parser.log_positions), 1)
        self.assertEqual(len(new_parser.line_hashes), 2)
    
    def test_parse_log_line_ssh(self):
        line = "Jan 30 10:00:00 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2"
        attempt = self.parser.parse_log_line(line, 'ssh', '/tmp/test.log')
        
        self.assertIsNotNone(attempt)
        self.assertEqual(attempt['ip_address'], '192.168.1.100')
        self.assertEqual(attempt['username'], 'root')
    
    def test_parse_log_line_http(self):
        line = '192.168.1.102 - - [30/Jan/2024:10:00:03 +0000] "POST /wp-login.php HTTP/1.1" 200 1234'
        attempt = self.parser.parse_log_line(line, 'http', '/tmp/test.log')
        
        self.assertIsNotNone(attempt)
        self.assertEqual(attempt['ip_address'], '192.168.1.102')
    
    def test_monitor_all_logs(self):
        attempts = self.parser.monitor_all_logs()
        self.assertGreater(len(attempts), 0)
    
    def test_cleanup_old_hashes(self):
        for i in range(150000):
            self.parser.line_hashes.add(f"hash_{i}")
        
        self.parser.cleanup_old_hashes()
        self.assertLessEqual(len(self.parser.line_hashes), 50000)

if __name__ == '__main__':
    unittest.main()