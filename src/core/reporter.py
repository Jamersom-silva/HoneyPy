"""
Módulo ReportGenerator - Geração de relatórios de segurança
"""

import json
import csv
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import statistics

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Classe para gerar relatórios de ataques"""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Inicializa o gerador de relatórios
        
        Args:
            config: Configuração do sistema
        """
        self.config = config
        self.reports_dir = config.get('paths', {}).get('reports_directory', 
                                                      '/var/lib/honeypy/reports')
        
        # Cria diretório de relatórios se não existir
        os.makedirs(self.reports_dir, exist_ok=True)
        os.makedirs(f'{self.reports_dir}/daily', exist_ok=True)
        os.makedirs(f'{self.reports_dir}/weekly', exist_ok=True)
        os.makedirs(f'{self.reports_dir}/monthly', exist_ok=True)
        
        logger.info(f"ReportGenerator inicializado. Diretório: {self.reports_dir}")

    def generate_daily_report(self, ip_tracker, additional_data: Dict = None) -> Dict[str, Any]:
        """
        Gera um relatório diário de atividades
        
        Args:
            ip_tracker: Instância do IPTracker
            additional_data: Dados adicionais para o relatório
            
        Returns:
            Dicionário com relatório estruturado
        """
        # Coleta estatísticas
        suspicious_ips = ip_tracker.get_all_suspicious_ips(limit=100)
        blocked_ips = ip_tracker.get_all_blocked_ips()
        
        # Calcula métricas
        total_attempts = sum(ip['total_attempts'] for ip in suspicious_ips)
        unique_attackers = len(suspicious_ips)
        
        # Agrupa por serviço
        services_attacked = {}
        for ip_info in suspicious_ips:
            for service, stats in ip_info.get('services_attacked', {}).items():
                if service not in services_attacked:
                    services_attacked[service] = {
                        'total_attempts': 0,
                        'unique_attackers': 0,
                        'ips': []
                    }
                services_attacked[service]['total_attempts'] += stats['attempts']
                if ip_info['ip_address'] not in services_attacked[service]['ips']:
                    services_attacked[service]['ips'].append(ip_info['ip_address'])
                    services_attacked[service]['unique_attackers'] += 1
        
        # Ordena serviços por número de ataques
        services_sorted = sorted(
            services_attacked.items(),
            key=lambda x: x[1]['total_attempts'],
            reverse=True
        )
        
        # Top atacantes
        top_attackers = sorted(
            suspicious_ips,
            key=lambda x: x['total_attempts'],
            reverse=True
        )[:10]
        
        report = {
            'metadata': {
                'report_id': f"daily_{datetime.now().strftime('%Y%m%d')}",
                'generated_at': datetime.now().isoformat(),
                'time_range_hours': 24,
                'report_type': 'daily'
            },
            'summary': {
                'total_attack_attempts': total_attempts,
                'unique_attackers': unique_attackers,
                'blocked_ips': len(blocked_ips),
                'suspicious_ips': len(suspicious_ips),
                'most_attacked_service': services_sorted[0][0] if services_sorted else 'N/A',
                'peak_hour': self._calculate_peak_hour(additional_data) if additional_data else 'N/A'
            },
            'services_analysis': {
                service: {
                    'total_attempts': data['total_attempts'],
                    'unique_attackers': data['unique_attackers'],
                    'percentage_of_total': round(
                        (data['total_attempts'] / total_attempts * 100) if total_attempts > 0 else 0,
                        2
                    )
                }
                for service, data in services_attacked.items()
            },
            'top_attackers': [
                {
                    'rank': i + 1,
                    'ip_address': attacker['ip_address'],
                    'total_attempts': attacker['total_attempts'],
                    'services': list(attacker['services_attacked'].keys()),
                    'first_seen': attacker['first_attempt'],
                    'last_seen': attacker['last_attempt']
                }
                for i, attacker in enumerate(top_attackers)
            ],
            'recent_blocks': [
                {
                    'ip_address': blocked['ip_address'],
                    'blocked_since': blocked.get('blocked_at', 'N/A'),
                    'statistics': blocked.get('statistics', {})
                }
                for blocked in blocked_ips[:10]
            ],
            'geographical_distribution': self._get_geo_distribution(suspicious_ips),
            'trend_analysis': self._analyze_trends(suspicious_ips),
            'recommendations': self._generate_recommendations(
                total_attempts, 
                unique_attackers, 
                services_attacked
            ),
            'raw_data': {
                'suspicious_ips_count': len(suspicious_ips),
                'blocked_ips_count': len(blocked_ips),
                'all_suspicious_ips': [
                    ip['ip_address'] for ip in suspicious_ips[:50]
                ]
            }
        }
        
        # Salva o relatório
        filename = self._save_report(report, 'daily')
        report['metadata']['file_path'] = filename
        
        # Envia notificações se configurado
        if self.config.get('notifications', {}).get('enabled', False):
            self._send_notification(report, 'daily')
        
        return report

    def generate_weekly_report(self, ip_tracker) -> Dict[str, Any]:
        """
        Gera um relatório semanal de atividades
        
        Args:
            ip_tracker: Instância do IPTracker
            
        Returns:
            Dicionário com relatório estruturado
        """
        # Carrega relatórios diários da semana
        weekly_data = self._load_weekly_data()
        
        suspicious_ips = ip_tracker.get_all_suspicious_ips(limit=200)
        blocked_ips = ip_tracker.get_all_blocked_ips()
        
        # Calcula métricas semanais
        weekly_metrics = self._calculate_weekly_metrics(weekly_data, suspicious_ips)
        
        report = {
            'metadata': {
                'report_id': f"weekly_{datetime.now().strftime('%Y-%W')}",
                'generated_at': datetime.now().isoformat(),
                'time_range_days': 7,
                'report_type': 'weekly',
                'week_number': datetime.now().isocalendar()[1],
                'year': datetime.now().year
            },
            'summary': {
                'total_attack_attempts': weekly_metrics['total_attempts'],
                'average_daily_attempts': weekly_metrics['avg_daily_attempts'],
                'unique_attackers_week': weekly_metrics['unique_attackers'],
                'new_blocked_ips': len(blocked_ips) - weekly_metrics.get('previous_blocked', 0),
                'attack_trend': weekly_metrics['trend'],
                'peak_day': weekly_metrics['peak_day']
            },
            'daily_breakdown': weekly_metrics.get('daily_breakdown', {}),
            'top_attackers_week': [
                {
                    'ip_address': ip['ip_address'],
                    'total_attempts': ip['total_attempts'],
                    'attack_days': ip.get('attack_days', 1),
                    'persistence_score': self._calculate_persistence_score(ip)
                }
                for ip in suspicious_ips[:15]
            ],
            'service_evolution': weekly_metrics.get('service_evolution', {}),
            'threat_landscape': {
                'most_persistent_attackers': self._identify_persistent_attackers(suspicious_ips),
                'emerging_threats': self._identify_emerging_threats(weekly_data),
                'attack_patterns': self._analyze_attack_patterns(suspicious_ips)
            },
            'performance_metrics': {
                'detection_rate': self._calculate_detection_rate(weekly_metrics),
                'false_positives': weekly_metrics.get('false_positives', 0),
                'response_time_avg': 'N/A'  # Poderia ser calculado se rastreado
            },
            'recommendations': self._generate_weekly_recommendations(weekly_metrics),
            'forecast': self._generate_forecast(weekly_data)
        }
        
        # Salva o relatório
        filename = self._save_report(report, 'weekly')
        report['metadata']['file_path'] = filename
        
        return report

    def generate_monthly_report(self, ip_tracker) -> Dict[str, Any]:
        """
        Gera um relatório mensal de atividades
        
        Args:
            ip_tracker: Instância do IPTracker
            
        Returns:
            Dicionário com relatório estruturado
        """
        # Carrega relatórios semanais do mês
        monthly_data = self._load_monthly_data()
        
        suspicious_ips = ip_tracker.get_all_suspicious_ips(limit=500)
        
        report = {
            'metadata': {
                'report_id': f"monthly_{datetime.now().strftime('%Y-%m')}",
                'generated_at': datetime.now().isoformat(),
                'time_range_days': 30,
                'report_type': 'monthly',
                'month': datetime.now().month,
                'year': datetime.now().year
            },
            'executive_summary': self._generate_executive_summary(monthly_data),
            'key_metrics': {
                'total_attacks': sum(day.get('total_attempts', 0) 
                                   for day in monthly_data.values()),
                'unique_attackers': len(suspicious_ips),
                'attack_growth_rate': self._calculate_growth_rate(monthly_data),
                'most_targeted_service': self._identify_most_targeted_service(monthly_data),
                'top_threat_countries': self._get_top_threat_countries(suspicious_ips)
            },
            'threat_intelligence': {
                'threat_actors': self._identify_threat_actors(suspicious_ips),
                'attack_campaigns': self._detect_attack_campaigns(monthly_data),
                'vulnerability_assessment': self._assess_vulnerabilities(monthly_data)
            },
            'security_posture': {
                'detection_effectiveness': 'High',  # Placeholder
                'response_timeliness': 'Medium',    # Placeholder
                'prevention_rate': self._calculate_prevention_rate(monthly_data)
            },
            'cost_analysis': {
                'estimated_downtime_prevented': 'N/A',
                'potential_loss_avoided': 'N/A',
                'roi_estimation': 'N/A'
            },
            'strategic_recommendations': self._generate_strategic_recommendations(monthly_data),
            'appendix': {
                'detailed_statistics': monthly_data,
                'methodology': 'Análise baseada em logs de autenticação falha e padrões de ataque',
                'data_sources': 'Logs do sistema, honeypy detections, iptables blocks'
            }
        }
        
        # Salva o relatório
        filename = self._save_report(report, 'monthly')
        report['metadata']['file_path'] = filename
        
        # Gera versão resumida para gestão
        self._generate_executive_briefing(report)
        
        return report

    def generate_custom_report(self, ip_tracker, start_date: datetime, 
                              end_date: datetime, report_type: str = 'custom') -> Dict[str, Any]:
        """
        Gera um relatório personalizado para um período específico
        
        Args:
            ip_tracker: Instância do IPTracker
            start_date: Data de início
            end_date: Data de fim
            report_type: Tipo do relatório
            
        Returns:
            Dicionário com relatório estruturado
        """
        # Implementação para relatórios personalizados
        # Esta função carregaria dados do período específico
        # e geraria um relatório similar aos outros
        
        report = {
            'metadata': {
                'report_id': f"custom_{start_date.strftime('%Y%m%d')}_{end_date.strftime('%Y%m%d')}",
                'generated_at': datetime.now().isoformat(),
                'start_date': start_date.isoformat(),
                'end_date': end_date.isoformat(),
                'report_type': report_type,
                'period_days': (end_date - start_date).days
            },
            'summary': {
                'message': 'Relatório personalizado - Implementação em desenvolvimento'
            }
        }
        
        return report

    def _save_report(self, report: Dict[str, Any], report_type: str) -> str:
        """
        Salva relatório em arquivo
        
        Args:
            report: Dicionário com dados do relatório
            report_type: Tipo do relatório
            
        Returns:
            Caminho do arquivo salvo
        """
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{self.reports_dir}/{report_type}/report_{timestamp}.json"
            
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2, ensure_ascii=False, default=str)
            
            # Também salva uma versão CSV resumida
            self._save_report_csv(report, filename.replace('.json', '.csv'))
            
            # Gera um resumo em texto
            self._save_report_text(report, filename.replace('.json', '.txt'))
            
            logger.info(f"Relatório {report_type} salvo em: {filename}")
            return filename
            
        except Exception as e:
            logger.error(f"Erro ao salvar relatório: {e}")
            return ""

    def _save_report_csv(self, report: Dict[str, Any], filename: str) -> None:
        """Salva resumo do relatório em CSV"""
        try:
            summary_data = []
            
            # Extrai dados principais para CSV
            if 'top_attackers' in report:
                for attacker in report['top_attackers']:
                    summary_data.append({
                        'type': 'top_attacker',
                        'rank': attacker['rank'],
                        'ip_address': attacker['ip_address'],
                        'attempts': attacker['total_attempts'],
                        'services': ','.join(attacker['services'])
                    })
            
            if summary_data:
                with open(filename, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=summary_data[0].keys())
                    writer.writeheader()
                    writer.writerows(summary_data)
                    
        except Exception as e:
            logger.error(f"Erro ao salvar CSV: {e}")

    def _save_report_text(self, report: Dict[str, Any], filename: str) -> None:
        """Salva resumo do relatório em texto"""
        try:
            with open(filename, 'w') as f:
                f.write(f"Relatório HoneyPy - {report['metadata']['report_type'].upper()}\n")
                f.write("=" * 50 + "\n\n")
                
                if 'summary' in report:
                    f.write("RESUMO EXECUTIVO:\n")
                    f.write("-" * 30 + "\n")
                    for key, value in report['summary'].items():
                        f.write(f"{key.replace('_', ' ').title()}: {value}\n")
                    f.write("\n")
                
                if 'recommendations' in report:
                    f.write("RECOMENDAÇÕES:\n")
                    f.write("-" * 30 + "\n")
                    if isinstance(report['recommendations'], list):
                        for i, rec in enumerate(report['recommendations'], 1):
                            f.write(f"{i}. {rec}\n")
                    else:
                        f.write(f"{report['recommendations']}\n")
                
        except Exception as e:
            logger.error(f"Erro ao salvar texto: {e}")

    def _send_notification(self, report: Dict[str, Any], report_type: str) -> None:
        """Envia notificação por email"""
        try:
            notifications_config = self.config.get('notifications', {})
            
            if not notifications_config.get('enabled', False):
                return
            
            email_config = notifications_config.get('email', {})
            
            if not all(key in email_config for key in ['smtp_server', 'username', 'recipients']):
                return
            
            # Cria mensagem
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"HoneyPy {report_type.capitalize()} Report - {datetime.now().strftime('%Y-%m-%d')}"
            msg['From'] = email_config['username']
            msg['To'] = ', '.join(email_config['recipients'])
            
            # Texto simples
            text = f"""
            Relatório HoneyPy - {report_type.capitalize()}
            
            Resumo:
            - Tentativas de ataque: {report['summary'].get('total_attack_attempts', 0)}
            - Atacantes únicos: {report['summary'].get('unique_attackers', 0)}
            - IPs bloqueados: {report['summary'].get('blocked_ips', 0)}
            
            Top atacantes:
            {chr(10).join([f"{a['rank']}. {a['ip_address']} - {a['total_attempts']} tentativas" 
                          for a in report.get('top_attackers', [])[:3]])}
            
            Verifique o relatório completo para mais detalhes.
            """
            
            # HTML
            html = f"""
            <html>
            <body>
                <h2>HoneyPy {report_type.capitalize()} Security Report</h2>
                <p><strong>Generated:</strong> {report['metadata']['generated_at']}</p>
                
                <h3>Summary</h3>
                <ul>
                    <li>Total Attack Attempts: {report['summary'].get('total_attack_attempts', 0)}</li>
                    <li>Unique Attackers: {report['summary'].get('unique_attackers', 0)}</li>
                    <li>Blocked IPs: {report['summary'].get('blocked_ips', 0)}</li>
                </ul>
                
                <h3>Top Attackers</h3>
                <table border="1">
                    <tr><th>Rank</th><th>IP Address</th><th>Attempts</th><th>Services</th></tr>
                    {"".join([f"<tr><td>{a['rank']}</td><td>{a['ip_address']}</td><td>{a['total_attempts']}</td><td>{', '.join(a['services'])}</td></tr>" 
                             for a in report.get('top_attackers', [])[:5]])}
                </table>
                
                <p><em>This is an automated security report from HoneyPy.</em></p>
            </body>
            </html>
            """
            
            # Anexa partes
            part1 = MIMEText(text, 'plain')
            part2 = MIMEText(html, 'html')
            msg.attach(part1)
            msg.attach(part2)
            
            # Envia email
            with smtplib.SMTP(email_config['smtp_server'], email_config.get('smtp_port', 587)) as server:
                if email_config.get('tls', True):
                    server.starttls()
                if email_config.get('password'):
                    server.login(email_config['username'], email_config['password'])
                server.send_message(msg)
            
            logger.info(f"Notificação {report_type} enviada por email")
            
        except Exception as e:
            logger.error(f"Erro ao enviar notificação: {e}")

    # Métodos auxiliares para análise de dados
    def _calculate_peak_hour(self, data: Dict) -> str:
        """Calcula a hora com maior número de ataques"""
        # Implementação simplificada
        return "N/A"

    def _get_geo_distribution(self, ips: List[Dict]) -> Dict:
        """Obtém distribuição geográfica dos ataques"""
        # Placeholder - seria integrado com GeoIP
        return {
            'unknown': len(ips),
            'note': 'GeoIP não configurado'
        }

    def _analyze_trends(self, ips: List[Dict]) -> Dict:
        """Analisa tendências de ataque"""
        if not ips:
            return {'trend': 'stable', 'change_percentage': 0}
        
        # Implementação simplificada
        return {
            'trend': 'increasing' if len(ips) > 10 else 'stable',
            'change_percentage': 0,
            'prediction': 'Espera-se aumento nos próximos dias'
        }

    def _generate_recommendations(self, total_attempts: int, 
                                 unique_attackers: int, 
                                 services: Dict) -> List[str]:
        """Gera recomendações baseadas nos dados"""
        recommendations = []
        
        if total_attempts > 100:
            recommendations.append(
                "Alto volume de ataques detectado. Considere implementar WAF (Web Application Firewall)."
            )
        
        if unique_attackers > 50:
            recommendations.append(
                "Muitos atacantes únicos. Avalie a exposição de serviços na internet."
            )
        
        if 'ssh' in services and services['ssh']['total_attempts'] > 50:
            recommendations.append(
                "Muitos ataques SSH. Configure autenticação por chaves e desabilite login por senha."
            )
        
        if 'http' in services or 'apache' in services or 'nginx' in services:
            recommendations.append(
                "Ataques web detectados. Verifique se há atualizações de segurança pendentes."
            )
        
        if not recommendations:
            recommendations.append(
                "Situação estável. Mantenha monitoramento ativo e políticas de segurança."
            )
        
        return recommendations

    def _load_weekly_data(self) -> Dict:
        """Carrega dados da semana atual"""
        # Implementação para carregar relatórios diários
        return {}

    def _calculate_weekly_metrics(self, weekly_data: Dict, suspicious_ips: List) -> Dict:
        """Calcula métricas semanais"""
        return {
            'total_attempts': 0,
            'avg_daily_attempts': 0,
            'unique_attackers': 0,
            'trend': 'stable'
        }

    def _calculate_persistence_score(self, ip_info: Dict) -> float:
        """Calcula score de persistência de um atacante"""
        # Baseado em número de dias com ataques
        return 0.0

    def _identify_persistent_attackers(self, ips: List[Dict]) -> List[Dict]:
        """Identifica atacantes persistentes"""
        return []

    def _identify_emerging_threats(self, weekly_data: Dict) -> List[str]:
        """Identifica ameaças emergentes"""
        return []

    def _analyze_attack_patterns(self, ips: List[Dict]) -> Dict:
        """Analisa padrões de ataque"""
        return {}

    def _calculate_detection_rate(self, metrics: Dict) -> float:
        """Calcula taxa de detecção"""
        return 0.0

    def _generate_weekly_recommendations(self, metrics: Dict) -> List[str]:
        """Gera recomendações semanais"""
        return []

    def _generate_forecast(self, weekly_data: Dict) -> Dict:
        """Gera previsão para próxima semana"""
        return {
            'predicted_attacks': 0,
            'confidence_level': 'low',
            'factors': ['dados insuficientes']
        }

    def _load_monthly_data(self) -> Dict:
        """Carrega dados do mês"""
        return {}

    def _generate_executive_summary(self, monthly_data: Dict) -> str:
        """Gera resumo executivo"""
        return "Resumo executivo do mês"

    def _calculate_growth_rate(self, monthly_data: Dict) -> float:
        """Calcula taxa de crescimento"""
        return 0.0

    def _identify_most_targeted_service(self, monthly_data: Dict) -> str:
        """Identifica serviço mais atacado"""
        return "ssh"

    def _get_top_threat_countries(self, ips: List[Dict]) -> List[Dict]:
        """Obtém países com mais ameaças"""
        return []

    def _identify_threat_actors(self, ips: List[Dict]) -> List[Dict]:
        """Identifica possíveis grupos de ataque"""
        return []

    def _detect_attack_campaigns(self, monthly_data: Dict) -> List[Dict]:
        """Detecta campanhas de ataque coordenadas"""
        return []

    def _assess_vulnerabilities(self, monthly_data: Dict) -> Dict:
        """Avalia vulnerabilidades expostas"""
        return {}

    def _calculate_prevention_rate(self, monthly_data: Dict) -> float:
        """Calcula taxa de prevenção"""
        return 0.0

    def _generate_strategic_recommendations(self, monthly_data: Dict) -> List[str]:
        """Gera recomendações estratégicas"""
        return []

    def _generate_executive_briefing(self, report: Dict) -> None:
        """Gera briefing executivo resumido"""
        try:
            briefing_file = f"{self.reports_dir}/executive_briefing_{datetime.now().strftime('%Y-%m')}.md"
            
            with open(briefing_file, 'w') as f:
                f.write(f"# HoneyPy Executive Briefing - {datetime.now().strftime('%B %Y')}\n\n")
                f.write("## Overview\n\n")
                f.write(f"- Report Period: {report['metadata'].get('time_range_days', 30)} days\n")
                f.write(f"- Total Attacks: {report['key_metrics'].get('total_attacks', 0)}\n")
                f.write(f"- Unique Attackers: {report['key_metrics'].get('unique_attackers', 0)}\n\n")
                f.write("## Key Findings\n\n")
                f.write("1. Security posture remains stable\n")
                f.write("2. Continue monitoring high-risk services\n")
                f.write("3. Consider additional security layers\n\n")
                f.write("## Recommendations\n\n")
                for rec in report.get('strategic_recommendations', []):
                    f.write(f"- {rec}\n")
                
            logger.info(f"Briefing executivo salvo: {briefing_file}")
            
        except Exception as e:
            logger.error(f"Erro ao gerar briefing: {e}")