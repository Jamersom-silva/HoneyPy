import unittest
import tempfile
import os
import time
from src.core.honeypy_system import HoneyPySystem

class TestHoneyPyIntegration(unittest.TestCase):
    
    def setUp(self):
        self.test_config = {
            'system': {
                'name': 'HoneyPy',
                'version': '1.0.0',
                'mode': 'test'
            },
            'monitoring': {
                'enabled': True,
                'interval_seconds': 1,
                'log_retention_days': 1,
                'report_retention_days': 1
            },
            'detection': {
                'window_minutes': 1,
                'max_attempts': 3,
                'thresholds': {
                    'ssh': {'max_attempts': 2, 'time_window_minutes': 1},
                    'test': {'max_attempts': 2, 'time_window_minutes': 1}
                },
                'auto_block': False,
                'block_duration_hours': 1,
                'ignore_private_ips': False
            },
            'logging': {
                'enabled': True,
                'level': 'WARNING',
                'directory': tempfile.mkdtemp(),
                'max_size_mb': 1,
                'backup_count': 1
            },
            'paths': {
                'log_files': {
                    'test': tempfile.mktemp(suffix='.log')
                },
                'data_directory': tempfile.mkdtemp(),
                'reports_directory': tempfile.mkdtemp()
            }
        }
        
        self.config_file = tempfile.mktemp(suffix='.json')
        with open(self.config_file, 'w') as f:
            import json
            json.dump(self.test_config, f)
        
        self.system = HoneyPySystem(self.config_file)
    
    def create_test_log(self):
        log_content = """
Test line 1
Failed test from 192.168.1.100
Failed test from 192.168.1.100
Failed test from 192.168.1.100
Failed test from 192.168.1.101
"""
        
        with open(self.test_config['paths']['log_files']['test'], 'w') as f:
            f.write(log_content)
    
    def test_system_initialization(self):
        self.assertIsNotNone(self.system.ip_tracker)
        self.assertIsNotNone(self.system.log_parser)
        self.assertIsNotNone(self.system.report_generator)
    
    def test_get_system_stats(self):
        stats = self.system.get_system_stats()
        
        self.assertIn('suspicious_ips', stats)
        self.assertIn('blocked_ips', stats)
        self.assertIn('system_status', stats)
        
        self.assertEqual(stats['system_status'], 'stopped')
    
    def test_ip_info(self):
        info = self.system.get_ip_info('192.168.1.100')
        
        self.assertIn('ip_address', info)
        self.assertIn('statistics', info)
        self.assertIn('is_blocked', info)
        self.assertFalse(info['is_blocked'])
    
    def test_block_unblock_ip(self):
        result = self.system.block_ip('192.168.2.100', 1)
        self.assertTrue(result['success'])
        
        info = self.system.get_ip_info('192.168.2.100')
        self.assertTrue(info['is_blocked'])
        
        result = self.system.unblock_ip('192.168.2.100')
        self.assertTrue(result['success'])
        
        info = self.system.get_ip_info('192.168.2.100')
        self.assertFalse(info['is_blocked'])
    
    def test_list_suspicious_ips(self):
        self.create_test_log()
        
        self.system.start()
        time.sleep(2)
        self.system.stop()
        
        suspicious = self.system.list_suspicious_ips(10)
        self.assertIsInstance(suspicious, list)
    
    def test_list_blocked_ips(self):
        self.system.block_ip('192.168.3.100')
        
        blocked = self.system.list_blocked_ips()
        self.assertIsInstance(blocked, list)
        
        found = False
        for ip_info in blocked:
            if ip_info['ip_address'] == '192.168.3.100':
                found = True
                break
        
        self.assertTrue(found)
    
    def test_generate_report(self):
        report = self.system.generate_report('daily')
        
        self.assertIsInstance(report, dict)
        self.assertIn('metadata', report)
        self.assertIn('summary', report)
    
    def test_add_to_whitelist(self):
        result = self.system.add_to_whitelist('192.168.4.100')
        self.assertTrue(result)
        
        info = self.system.get_ip_info('192.168.4.100')
        self.assertTrue(info['is_whitelisted'])
    
    def test_perform_maintenance(self):
        self.system.perform_maintenance()
    
    def tearDown(self):
        import shutil
        import os
        
        if os.path.exists(self.config_file):
            os.remove(self.config_file)
        
        if 'logging' in self.test_config:
            log_dir = self.test_config['logging']['directory']
            if os.path.exists(log_dir):
                shutil.rmtree(log_dir)
        
        if 'paths' in self.test_config:
            data_dir = self.test_config['paths']['data_directory']
            if os.path.exists(data_dir):
                shutil.rmtree(data_dir)
            
            reports_dir = self.test_config['paths']['reports_directory']
            if os.path.exists(reports_dir):
                shutil.rmtree(reports_dir)
            
            log_file = self.test_config['paths']['log_files']['test']
            if os.path.exists(log_file):
                os.remove(log_file)

if __name__ == '__main__':
    unittest.main()