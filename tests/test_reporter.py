import unittest
import tempfile
import json
import os
from datetime import datetime, timedelta
from src.core.reporter import ReportGenerator
from src.core.tracker import IPTracker

class TestReportGenerator(unittest.TestCase):
    
    def setUp(self):
        self.config = {
            'paths': {
                'reports_directory': tempfile.mkdtemp()
            },
            'notifications': {
                'enabled': False
            }
        }
        self.reporter = ReportGenerator(self.config)
        
        self.tracker_config = {
            'window_minutes': 10,
            'max_attempts': 5,
            'thresholds': {
                'ssh': {'max_attempts': 3, 'time_window_minutes': 5}
            }
        }
        self.tracker = IPTracker(self.tracker_config)
        
        self.populate_tracker()
    
    def populate_tracker(self):
        for i in range(10):
            self.tracker.record_attempt(f'192.168.1.{i}', 'ssh')
        
        for i in range(5):
            self.tracker.record_attempt('192.168.2.100', 'http')
    
    def test_generate_daily_report(self):
        report = self.reporter.generate_daily_report(self.tracker)
        
        self.assertIn('metadata', report)
        self.assertIn('summary', report)
        self.assertIn('top_attackers', report)
        
        self.assertEqual(report['metadata']['report_type'], 'daily')
        self.assertGreater(report['summary']['total_attack_attempts'], 0)
    
    def test_save_report(self):
        report = {
            'metadata': {
                'report_id': 'test_report',
                'generated_at': datetime.now().isoformat(),
                'report_type': 'test'
            },
            'summary': {
                'total_attempts': 100
            }
        }
        
        filename = self.reporter._save_report(report, 'daily')
        self.assertTrue(os.path.exists(filename))
        
        with open(filename, 'r') as f:
            loaded_report = json.load(f)
        
        self.assertEqual(loaded_report['metadata']['report_id'], 'test_report')
    
    def test_save_report_csv(self):
        report = {
            'top_attackers': [
                {
                    'rank': 1,
                    'ip_address': '192.168.1.100',
                    'total_attempts': 50,
                    'services': ['ssh', 'http']
                }
            ]
        }
        
        temp_file = tempfile.mktemp(suffix='.csv')
        self.reporter._save_report_csv(report, temp_file)
        
        self.assertTrue(os.path.exists(temp_file))
        os.remove(temp_file)
    
    def test_save_report_text(self):
        report = {
            'metadata': {'report_type': 'test'},
            'summary': {
                'total_attack_attempts': 100,
                'unique_attackers': 10
            },
            'recommendations': [
                'Test recommendation 1',
                'Test recommendation 2'
            ]
        }
        
        temp_file = tempfile.mktemp(suffix='.txt')
        self.reporter._save_report_text(report, temp_file)
        
        self.assertTrue(os.path.exists(temp_file))
        
        with open(temp_file, 'r') as f:
            content = f.read()
        
        self.assertIn('RESUMO EXECUTIVO', content)
        self.assertIn('RECOMENDAÇÕES', content)
        
        os.remove(temp_file)
    
    def test_generate_recommendations(self):
        total_attempts = 150
        unique_attackers = 60
        services = {
            'ssh': {'total_attempts': 80, 'unique_attackers': 20},
            'http': {'total_attempts': 40, 'unique_attackers': 10}
        }
        
        recommendations = self.reporter._generate_recommendations(
            total_attempts, unique_attackers, services
        )
        
        self.assertIsInstance(recommendations, list)
        self.assertGreater(len(recommendations), 0)
    
    def test_generate_weekly_report(self):
        report = self.reporter.generate_weekly_report(self.tracker)
        
        self.assertIn('metadata', report)
        self.assertIn('summary', report)
        self.assertEqual(report['metadata']['report_type'], 'weekly')
    
    def test_generate_monthly_report(self):
        report = self.reporter.generate_monthly_report(self.tracker)
        
        self.assertIn('metadata', report)
        self.assertIn('key_metrics', report)
        self.assertEqual(report['metadata']['report_type'], 'monthly')
    
    def test_generate_custom_report(self):
        start_date = datetime.now() - timedelta(days=7)
        end_date = datetime.now()
        
        report = self.reporter.generate_custom_report(
            self.tracker, start_date, end_date, 'custom'
        )
        
        self.assertIn('metadata', report)
        self.assertEqual(report['metadata']['report_type'], 'custom')
    
    def test_generate_executive_briefing(self):
        report = {
            'metadata': {
                'time_range_days': 30
            },
            'key_metrics': {
                'total_attacks': 1000,
                'unique_attackers': 100
            },
            'strategic_recommendations': [
                'Improve firewall rules',
                'Update all systems'
            ]
        }
        
        self.reporter._generate_executive_briefing(report)
        
        briefing_file = os.path.join(
            self.reporter.reports_dir,
            f"executive_briefing_{datetime.now().strftime('%Y-%m')}.md"
        )
        
        self.assertTrue(os.path.exists(briefing_file))
        os.remove(briefing_file)
    
    def tearDown(self):
        import shutil
        if os.path.exists(self.config['paths']['reports_directory']):
            shutil.rmtree(self.config['paths']['reports_directory'])

if __name__ == '__main__':
    unittest.main()