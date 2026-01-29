"""
Módulo HoneyPySystem - Sistema principal do HoneyPy
"""

import time
import signal
import logging
import threading
from typing import Dict, List, Any, Optional
from datetime import datetime

from .tracker import IPTracker
from .parser import LogParser
from .reporter import ReportGenerator
from ..utils.helpers import setup_logging, load_config, validate_config
from ..utils.geoip import GeoIPLookup

logger = logging.getLogger(__name__)


class HoneyPySystem:
    """Classe principal do sistema HoneyPy"""
    
    def __init__(self, config_path: str = None):
        """
        Inicializa o sistema HoneyPy
        
        Args:
            config_path: Caminho para arquivo de configuração
        """
        # Configura logging
        setup_logging()
        
        # Carrega configuração
        self.config = load_config(config_path)
        validate_config(self.config)
        
        # Inicializa componentes
        self.ip_tracker = IPTracker(self.config)
        self.log_parser = LogParser(self.ip_tracker, self.config)
        self.report_generator = ReportGenerator(self.config)
        
        # Inicializa GeoIP se configurado
        self.geoip = None
        if self.config.get('geoip', {}).get('enabled', False):
            try:
                self.geoip = GeoIPLookup(self.config['geoip'])
                logger.info("GeoIP inicializado")
            except Exception as e:
                logger.error(f"Erro ao inicializar GeoIP: {e}")
        
        # Estado do sistema
        self.running = False
        self.monitor_thread = None
        self.report_thread = None
        self.cleanup_thread = None
        
        # Configuração de handlers de sinal
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        logger.info("HoneyPySystem inicializado")

    def start(self) -> None:
        """Inicia todos os serviços do HoneyPy"""
        if self.running:
            logger.warning("HoneyPy já está em execução")
            return
        
        self.running = True
        
        try:
            # Inicia thread de monitoramento
            self.monitor_thread = threading.Thread(
                target=self._monitoring_loop,
                daemon=True,
                name="MonitorThread"
            )
            self.monitor_thread.start()
            
            # Inicia thread de relatórios periódicos
            self.report_thread = threading.Thread(
                target=self._reporting_loop,
                daemon=True,
                name="ReportThread"
            )
            self.report_thread.start()
            
            # Inicia thread de limpeza
            self.cleanup_thread = threading.Thread(
                target=self._cleanup_loop,
                daemon=True,
                name="CleanupThread"
            )
            self.cleanup_thread.start()
            
            logger.info("HoneyPy iniciado com sucesso")
            logger.info(f"Modo: {self.config.get('system', {}).get('mode', 'production')}")
            logger.info(f"Intervalo de monitoramento: {self.config.get('monitoring', {}).get('interval_seconds', 10)}s")
            
            # Mantém thread principal ativa
            while self.running:
                time.sleep(1)
                
        except KeyboardInterrupt:
            logger.info("Interrompido pelo usuário")
            self.stop()
        except Exception as e:
            logger.error(f"Erro durante execução: {e}")
            self.stop()

    def stop(self) -> None:
        """Para todos os serviços do HoneyPy"""
        logger.info("Parando HoneyPy...")
        self.running = False
        
        # Aguarda threads finalizarem
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        if self.report_thread:
            self.report_thread.join(timeout=5)
        if self.cleanup_thread:
            self.cleanup_thread.join(timeout=5)
        
        # Gera relatório final
        try:
            self.generate_report('daily')
        except Exception as e:
            logger.error(f"Erro ao gerar relatório final: {e}")
        
        logger.info("HoneyPy parado")

    def _monitoring_loop(self) -> None:
        """Loop principal de monitoramento"""
        interval = self.config.get('monitoring', {}).get('interval_seconds', 10)
        
        logger.info(f"Iniciando monitoramento (intervalo: {interval}s)")
        
        while self.running:
            try:
                # Monitora logs
                attempts = self.log_parser.monitor_all_logs()
                
                if attempts:
                    # Processa tentativas
                    processed = self.log_parser.process_attempts(attempts)
                    
                    # Log resumido
                    attacks = [a for a in processed if a['analysis']['is_attack']]
                    if attacks:
                        logger.info(f"Detectadas {len(attacks)} tentativas de ataque")
                
                # Log de estado periódico
                if int(time.time()) % 300 == 0:  # A cada 5 minutos
                    stats = self.get_system_stats()
                    logger.info(f"Status: {stats['suspicious_ips']} IPs suspeitos, "
                              f"{stats['blocked_ips']} IPs bloqueados")
                
            except Exception as e:
                logger.error(f"Erro no loop de monitoramento: {e}")
            
            # Aguarda próximo ciclo
            time.sleep(interval)

    def _reporting_loop(self) -> None:
        """Loop de geração de relatórios periódicos"""
        logger.info("Loop de relatórios iniciado")
        
        # Calcula próximos horários de relatório
        next_daily = self._next_daily_report_time()
        next_weekly = self._next_weekly_report_time()
        next_monthly = self._next_monthly_report_time()
        
        while self.running:
            try:
                current_time = time.time()
                
                # Verifica se é hora do relatório diário
                if current_time >= next_daily:
                    logger.info("Gerando relatório diário...")
                    self.generate_report('daily')
                    next_daily = self._next_daily_report_time()
                
                # Verifica se é hora do relatório semanal
                if current_time >= next_weekly:
                    logger.info("Gerando relatório semanal...")
                    self.generate_report('weekly')
                    next_weekly = self._next_weekly_report_time()
                
                # Verifica se é hora do relatório mensal
                if current_time >= next_monthly:
                    logger.info("Gerando relatório mensal...")
                    self.generate_report('monthly')
                    next_monthly = self._next_monthly_report_time()
                
                # Verificação a cada hora
                time.sleep(3600)
                
            except Exception as e:
                logger.error(f"Erro no loop de relatórios: {e}")
                time.sleep(300)  # Espera 5 minutos em caso de erro

    def _cleanup_loop(self) -> None:
        """Loop de limpeza e manutenção"""
        logger.info("Loop de limpeza iniciado")
        
        while self.running:
            try:
                # Limpeza diária às 3:00 AM
                now = datetime.now()
                if now.hour == 3 and now.minute == 0:
                    self.perform_maintenance()
                    time.sleep(3660)  # Aguarda mais de 1 hora para evitar repetição
                else:
                    time.sleep(60)  # Verifica a cada minuto
                    
            except Exception as e:
                logger.error(f"Erro no loop de limpeza: {e}")
                time.sleep(300)

    def _next_daily_report_time(self) -> float:
        """Calcula próximo horário para relatório diário (meia-noite)"""
        now = datetime.now()
        tomorrow = datetime(now.year, now.month, now.day) + timedelta(days=1)
        return tomorrow.timestamp()

    def _next_weekly_report_time(self) -> float:
        """Calcula próximo horário para relatório semanal (domingo meia-noite)"""
        now = datetime.now()
        days_until_sunday = (6 - now.weekday()) % 7
        next_sunday = datetime(now.year, now.month, now.day) + timedelta(days=days_until_sunday)
        return next_sunday.timestamp()

    def _next_monthly_report_time(self) -> float:
        """Calcula próximo horário para relatório mensal (primeiro dia do mês)"""
        now = datetime.now()
        if now.month == 12:
            next_month = datetime(now.year + 1, 1, 1)
        else:
            next_month = datetime(now.year, now.month + 1, 1)
        return next_month.timestamp()

    def generate_report(self, report_type: str) -> Dict[str, Any]:
        """
        Gera relatório de segurança
        
        Args:
            report_type: Tipo de relatório (daily, weekly, monthly, custom)
            
        Returns:
            Dicionário com relatório gerado
        """
        logger.info(f"Gerando relatório {report_type}...")
        
        try:
            if report_type == 'daily':
                report = self.report_generator.generate_daily_report(
                    self.ip_tracker, 
                    {'timestamp': datetime.now().isoformat()}
                )
            elif report_type == 'weekly':
                report = self.report_generator.generate_weekly_report(self.ip_tracker)
            elif report_type == 'monthly':
                report = self.report_generator.generate_monthly_report(self.ip_tracker)
            else:
                raise ValueError(f"Tipo de relatório inválido: {report_type}")
            
            logger.info(f"Relatório {report_type} gerado com sucesso")
            return report
            
        except Exception as e:
            logger.error(f"Erro ao gerar relatório {report_type}: {e}")
            return {
                'error': str(e),
                'report_type': report_type,
                'generated_at': datetime.now().isoformat()
            }

    def perform_maintenance(self) -> None:
        """Executa tarefas de manutenção do sistema"""
        logger.info("Executando manutenção do sistema...")
        
        try:
            # Limpa entradas antigas
            days_to_keep = self.config.get('monitoring', {}).get('log_retention_days', 30)
            cleaned = self.ip_tracker.cleanup_old_entries(days_to_keep)
            logger.info(f"Limpeza concluída: {cleaned} entradas antigas removidas")
            
            # Limpa relatórios antigos
            report_days = self.config.get('monitoring', {}).get('report_retention_days', 90)
            self._cleanup_old_reports(report_days)
            
            # Salva estado do sistema
            self._save_system_state()
            
            logger.info("Manutenção concluída com sucesso")
            
        except Exception as e:
            logger.error(f"Erro durante manutenção: {e}")

    def _cleanup_old_reports(self, days_to_keep: int) -> None:
        """Remove relatórios antigos"""
        import os
        from datetime import datetime, timedelta
        
        cutoff_date = datetime.now() - timedelta(days=days_to_keep)
        
        for report_type in ['daily', 'weekly', 'monthly']:
            report_dir = f"{self.report_generator.reports_dir}/{report_type}"
            
            if not os.path.exists(report_dir):
                continue
            
            for filename in os.listdir(report_dir):
                filepath = os.path.join(report_dir, filename)
                
                try:
                    # Extrai data do nome do arquivo
                    file_date_str = filename.split('_')[1]  # report_YYYYMMDD_HHMMSS.json
                    file_date = datetime.strptime(file_date_str[:8], '%Y%m%d')
                    
                    if file_date < cutoff_date:
                        os.remove(filepath)
                        logger.debug(f"Relatório antigo removido: {filename}")
                        
                except (ValueError, IndexError):
                    # Se não conseguir extrair a data, verifica por timestamp do arquivo
                    file_mtime = datetime.fromtimestamp(os.path.getmtime(filepath))
                    if file_mtime < cutoff_date:
                        os.remove(filepath)
                        logger.debug(f"Relatório antigo removido: {filename}")

    def _save_system_state(self) -> None:
        """Salva estado atual do sistema"""
        try:
            state_file = 'data/state/system_state.json'
            
            state = {
                'saved_at': datetime.now().isoformat(),
                'suspicious_ips_count': len(self.ip_tracker.suspicious_ips),
                'blocked_ips_count': len(self.ip_tracker.blocked_ips),
                'whitelist_ips_count': len(self.ip_tracker.whitelist_ips),
                'total_tracked_ips': len(self.ip_tracker.attempts_log),
                'system_uptime': time.time() - self.start_time if hasattr(self, 'start_time') else 0
            }
            
            with open(state_file, 'w') as f:
                json.dump(state, f, indent=2)
                
            logger.debug("Estado do sistema salvo")
            
        except Exception as e:
            logger.error(f"Erro ao salvar estado do sistema: {e}")

    def get_system_stats(self) -> Dict[str, Any]:
        """
        Obtém estatísticas atuais do sistema
        
        Returns:
            Dicionário com estatísticas
        """
        return {
            'suspicious_ips': len(self.ip_tracker.suspicious_ips),
            'blocked_ips': len(self.ip_tracker.blocked_ips),
            'whitelist_ips': len(self.ip_tracker.whitelist_ips),
            'total_tracked_ips': len(self.ip_tracker.attempts_log),
            'system_status': 'running' if self.running else 'stopped',
            'last_update': datetime.now().isoformat()
        }

    def get_ip_info(self, ip_address: str) -> Dict[str, Any]:
        """
        Obtém informações detalhadas sobre um IP
        
        Args:
            ip_address: Endereço IP para consulta
            
        Returns:
            Dicionário com informações do IP
        """
        info = {
            'ip_address': ip_address,
            'statistics': self.ip_tracker.get_attack_statistics(ip_address),
            'is_blocked': ip_address in self.ip_tracker.blocked_ips,
            'is_suspicious': ip_address in self.ip_tracker.suspicious_ips,
            'is_whitelisted': ip_address in self.ip_tracker.whitelist_ips
        }
        
        # Adiciona informações GeoIP se disponível
        if self.geoip:
            geo_info = self.geoip.lookup(ip_address)
            if geo_info:
                info['geoip'] = geo_info
        
        return info

    def block_ip(self, ip_address: str, duration_hours: int = None) -> Dict[str, Any]:
        """
        Bloqueia um IP manualmente
        
        Args:
            ip_address: IP a ser bloqueado
            duration_hours: Duração do bloqueio
            
        Returns:
            Resultado da operação
        """
        result = self.ip_tracker.block_ip(ip_address, duration_hours)
        
        if result['success']:
            logger.info(f"IP {ip_address} bloqueado manualmente")
        else:
            logger.error(f"Falha ao bloquear IP {ip_address}: {result.get('error', 'Unknown error')}")
        
        return result

    def unblock_ip(self, ip_address: str) -> Dict[str, Any]:
        """
        Desbloqueia um IP
        
        Args:
            ip_address: IP a ser desbloqueado
            
        Returns:
            Resultado da operação
        """
        result = self.ip_tracker.unblock_ip(ip_address)
        
        if result['success']:
            logger.info(f"IP {ip_address} desbloqueado manualmente")
        else:
            logger.error(f"Falha ao desbloquear IP {ip_address}: {result.get('error', 'Unknown error')}")
        
        return result

    def add_to_whitelist(self, ip_address: str) -> bool:
        """
        Adiciona IP à whitelist
        
        Args:
            ip_address: IP a ser adicionado
            
        Returns:
            True se adicionado com sucesso
        """
        return self.ip_tracker.add_to_whitelist(ip_address)

    def list_suspicious_ips(self, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Lista IPs suspeitos
        
        Args:
            limit: Número máximo de IPs a retornar
            
        Returns:
            Lista de informações dos IPs
        """
        return self.ip_tracker.get_all_suspicious_ips(limit)

    def list_blocked_ips(self) -> List[Dict[str, Any]]:
        """
        Lista IPs bloqueados
        
        Returns:
            Lista de informações dos IPs bloqueados
        """
        return self.ip_tracker.get_all_blocked_ips()

    def _signal_handler(self, signum, frame):
        """Handler para sinais de interrupção"""
        logger.info(f"Recebido sinal {signum}, parando sistema...")
        self.stop()
        sys.exit(0)