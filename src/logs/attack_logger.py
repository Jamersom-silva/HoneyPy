"""
Módulo de logging personalizado para ataques do HoneyPy
"""

import logging
import json
import time
import os
from datetime import datetime
from typing import Dict, Any, Optional
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler


class AttackLogger:
    """Logger personalizado para eventos de ataque"""
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Inicializa logger de ataques
        
        Args:
            config: Configuração do logger
        """
        self.config = config or {}
        self.enabled = self.config.get('enabled', True)
        
        # Diretórios de log
        self.log_dir = self.config.get('directory', '/var/log/honeypy/attacks')
        os.makedirs(self.log_dir, exist_ok=True)
        
        # Configura loggers
        self._setup_loggers()
        
        logger = logging.getLogger(__name__)
        logger.info(f"AttackLogger inicializado (enabled: {self.enabled})")
    
    def _setup_loggers(self):
        """Configura loggers específicos"""
        if not self.enabled:
            return
        
        # Logger para ataques bruteforce
        self.bruteforce_logger = self._create_logger(
            'honeypy.attacks.bruteforce',
            os.path.join(self.log_dir, 'bruteforce.log'),
            '%(asctime)s - %(levelname)s - %(message)s'
        )
        
        # Logger para port scanning
        self.portscan_logger = self._create_logger(
            'honeypy.attacks.portscan',
            os.path.join(self.log_dir, 'portscan.log'),
            '%(asctime)s - %(levelname)s - %(message)s'
        )
        
        # Logger para SQL injection
        self.sqli_logger = self._create_logger(
            'honeypy.attacks.sqli',
            os.path.join(self.log_dir, 'sqli.log'),
            '%(asctime)s - %(levelname)s - %(message)s'
        )
        
        # Logger para XSS
        self.xss_logger = self._create_logger(
            'honeypy.attacks.xss',
            os.path.join(self.log_dir, 'xss.log'),
            '%(asctime)s - %(levelname)s - %(message)s'
        )
        
        # Logger para DDoS
        self.ddos_logger = self._create_logger(
            'honeypy.attacks.ddos',
            os.path.join(self.log_dir, 'ddos.log'),
            '%(asctime)s - %(levelname)s - %(message)s'
        )
        
        # Logger para todos os ataques (JSON formatado)
        self.json_logger = self._create_json_logger(
            'honeypy.attacks.json',
            os.path.join(self.log_dir, 'attacks.json')
        )
    
    def _create_logger(self, name: str, log_file: str, 
                       format_str: str) -> logging.Logger:
        """
        Cria logger com configuração específica
        
        Args:
            name: Nome do logger
            log_file: Arquivo de log
            format_str: Formato do log
            
        Returns:
            Logger configurado
        """
        logger = logging.getLogger(name)
        logger.setLevel(logging.INFO)
        
        # Remove handlers existentes
        logger.handlers.clear()
        
        # Handler para arquivo
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5
        )
        file_handler.setLevel(logging.INFO)
        
        formatter = logging.Formatter(format_str, datefmt='%Y-%m-%d %H:%M:%S')
        file_handler.setFormatter(formatter)
        
        logger.addHandler(file_handler)
        logger.propagate = False
        
        return logger
    
    def _create_json_logger(self, name: str, log_file: str) -> logging.Logger:
        """
        Cria logger com saída JSON
        
        Args:
            name: Nome do logger
            log_file: Arquivo de log
            
        Returns:
            Logger configurado
        """
        logger = logging.getLogger(name)
        logger.setLevel(logging.INFO)
        
        # Remove handlers existentes
        logger.handlers.clear()
        
        # Handler para arquivo JSON
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5
        )
        file_handler.setLevel(logging.INFO)
        
        # Formatter JSON
        class JSONFormatter(logging.Formatter):
            def format(self, record):
                log_data = {
                    'timestamp': datetime.now().isoformat(),
                    'level': record.levelname,
                    'logger': record.name,
                    'message': record.getMessage(),
                    'attack_type': getattr(record, 'attack_type', 'unknown'),
                    'ip_address': getattr(record, 'ip_address', 'unknown'),
                    'service': getattr(record, 'service', 'unknown'),
                    'attempts': getattr(record, 'attempts', 0),
                    'duration': getattr(record, 'duration', 0),
                    'additional_data': getattr(record, 'additional_data', {})
                }
                
                # Adiciona exc_info se houver
                if record.exc_info:
                    log_data['exception'] = self.formatException(record.exc_info)
                
                return json.dumps(log_data, ensure_ascii=False)
        
        file_handler.setFormatter(JSONFormatter())
        logger.addHandler(file_handler)
        logger.propagate = False
        
        return logger
    
    def log_bruteforce_attack(self, ip_address: str, service: str, 
                              attempts: int, duration: float,
                              additional_data: Dict[str, Any] = None):
        """
        Loga ataque de força bruta
        
        Args:
            ip_address: IP do atacante
            service: Serviço atacado
            attempts: Número de tentativas
            duration: Duração do ataque (segundos)
            additional_data: Dados adicionais
        """
        if not self.enabled:
            return
        
        message = f"Brute force attack detected - IP: {ip_address}, "
        message += f"Service: {service}, Attempts: {attempts}, "
        message += f"Duration: {duration:.2f}s"
        
        # Log padrão
        self.bruteforce_logger.warning(message)
        
        # Log JSON
        extra_data = {
            'attack_type': 'bruteforce',
            'ip_address': ip_address,
            'service': service,
            'attempts': attempts,
            'duration': duration,
            'additional_data': additional_data or {}
        }
        
        self._log_json('bruteforce', message, extra_data)
    
    def log_port_scan(self, ip_address: str, ports_scanned: list,
                      scan_type: str, duration: float):
        """
        Loga port scan
        
        Args:
            ip_address: IP do scanner
            ports_scanned: Lista de portas escaneadas
            scan_type: Tipo de scan
            duration: Duração do scan
        """
        if not self.enabled:
            return
        
        message = f"Port scan detected - IP: {ip_address}, "
        message += f"Type: {scan_type}, Ports: {len(ports_scanned)}, "
        message += f"Duration: {duration:.2f}s"
        
        # Log padrão
        self.portscan_logger.warning(message)
        
        # Log JSON
        extra_data = {
            'attack_type': 'port_scan',
            'ip_address': ip_address,
            'scan_type': scan_type,
            'ports_scanned': ports_scanned,
            'ports_count': len(ports_scanned),
            'duration': duration
        }
        
        self._log_json('port_scan', message, extra_data)
    
    def log_sql_injection(self, ip_address: str, url: str, 
                          payload: str, severity: str):
        """
        Loga tentativa de SQL injection
        
        Args:
            ip_address: IP do atacante
            url: URL alvo
            payload: Payload usado
            severity: Severidade (low, medium, high)
        """
        if not self.enabled:
            return
        
        # Sanitiza payload para log
        safe_payload = payload[:100] + '...' if len(payload) > 100 else payload
        
        message = f"SQL injection attempt - IP: {ip_address}, "
        message += f"URL: {url}, Severity: {severity}"
        
        # Log padrão
        self.sqli_logger.warning(message)
        
        # Log JSON
        extra_data = {
            'attack_type': 'sql_injection',
            'ip_address': ip_address,
            'url': url,
            'payload': safe_payload,
            'payload_length': len(payload),
            'severity': severity
        }
        
        self._log_json('sql_injection', message, extra_data)
    
    def log_xss_attack(self, ip_address: str, url: str, 
                       payload: str, severity: str):
        """
        Loga tentativa de XSS
        
        Args:
            ip_address: IP do atacante
            url: URL alvo
            payload: Payload usado
            severity: Severidade
        """
        if not self.enabled:
            return
        
        safe_payload = payload[:100] + '...' if len(payload) > 100 else payload
        
        message = f"XSS attempt - IP: {ip_address}, "
        message += f"URL: {url}, Severity: {severity}"
        
        # Log padrão
        self.xss_logger.warning(message)
        
        # Log JSON
        extra_data = {
            'attack_type': 'xss',
            'ip_address': ip_address,
            'url': url,
            'payload': safe_payload,
            'payload_length': len(payload),
            'severity': severity
        }
        
        self._log_json('xss', message, extra_data)
    
    def log_ddos_attack(self, ip_addresses: list, target: str,
                        attack_type: str, packets_per_second: float,
                        duration: float):
        """
        Loga ataque DDoS
        
        Args:
            ip_addresses: Lista de IPs atacantes
            target: Alvo do ataque
            attack_type: Tipo de ataque DDoS
            packets_per_second: Taxa de pacotes
            duration: Duração do ataque
        """
        if not self.enabled:
            return
        
        unique_ips = len(set(ip_addresses))
        
        message = f"DDoS attack detected - Target: {target}, "
        message += f"Type: {attack_type}, Unique IPs: {unique_ips}, "
        message += f"Rate: {packets_per_second:.2f} pps, "
        message += f"Duration: {duration:.2f}s"
        
        # Log padrão
        self.ddos_logger.warning(message)
        
        # Log JSON
        extra_data = {
            'attack_type': 'ddos',
            'target': target,
            'ddos_type': attack_type,
            'unique_attackers': unique_ips,
            'packets_per_second': packets_per_second,
            'duration': duration,
            'attacker_ips': ip_addresses[:10]  # Limita para não ficar muito grande
        }
        
        self._log_json('ddos', message, extra_data)
    
    def log_custom_attack(self, attack_type: str, ip_address: str,
                          details: Dict[str, Any]):
        """
        Loga ataque personalizado
        
        Args:
            attack_type: Tipo de ataque
            ip_address: IP do atacante
            details: Detalhes do ataque
        """
        if not self.enabled:
            return
        
        message = f"Custom attack detected - Type: {attack_type}, "
        message += f"IP: {ip_address}"
        
        # Log JSON
        extra_data = {
            'attack_type': attack_type,
            'ip_address': ip_address,
            'details': details
        }
        
        self._log_json(attack_type, message, extra_data)
    
    def _log_json(self, attack_type: str, message: str, 
                  extra_data: Dict[str, Any]):
        """
        Loga no formato JSON
        
        Args:
            attack_type: Tipo de ataque
            message: Mensagem do log
            extra_data: Dados extras
        """
        log_record = logging.LogRecord(
            name='honeypy.attacks.json',
            level=logging.WARNING,
            pathname='',
            lineno=0,
            msg=message,
            args=(),
            exc_info=None
        )
        
        # Adiciona atributos extras
        for key, value in extra_data.items():
            setattr(log_record, key, value)
        
        self.json_logger.handle(log_record)
    
    def get_recent_attacks(self, attack_type: str = None, 
                           limit: int = 100) -> list:
        """
        Obtém ataques recentes do arquivo JSON
        
        Args:
            attack_type: Filtro por tipo de ataque
            limit: Limite de resultados
            
        Returns:
            Lista de ataques
        """
        if not self.enabled:
            return []
        
        log_file = os.path.join(self.log_dir, 'attacks.json')
        
        if not os.path.exists(log_file):
            return []
        
        attacks = []
        
        try:
            with open(log_file, 'r') as f:
                for line in f:
                    try:
                        attack = json.loads(line.strip())
                        
                        # Filtra por tipo se especificado
                        if attack_type and attack.get('attack_type') != attack_type:
                            continue
                        
                        attacks.append(attack)
                        
                        # Limita resultados
                        if len(attacks) >= limit:
                            break
                            
                    except json.JSONDecodeError:
                        continue
        
        except Exception as e:
            logging.error(f"Erro ao ler ataques recentes: {e}")
        
        # Ordena por timestamp (mais recente primeiro)
        attacks.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        
        return attacks
    
    def get_attack_statistics(self, hours: int = 24) -> Dict[str, Any]:
        """
        Obtém estatísticas de ataques
        
        Args:
            hours: Janela de tempo em horas
            
        Returns:
            Estatísticas de ataques
        """
        if not self.enabled:
            return {}
        
        # Obtém ataques das últimas N horas
        cutoff_time = datetime.now().timestamp() - (hours * 3600)
        all_attacks = self.get_recent_attacks(limit=10000)
        
        # Filtra por tempo
        recent_attacks = []
        for attack in all_attacks:
            try:
                attack_time = datetime.fromisoformat(
                    attack['timestamp'].replace('Z', '+00:00')
                ).timestamp()
                
                if attack_time >= cutoff_time:
                    recent_attacks.append(attack)
            except (KeyError, ValueError):
                continue
        
        # Calcula estatísticas
        attack_types = {}
        top_attackers = {}
        
        for attack in recent_attacks:
            # Por tipo
            attack_type = attack.get('attack_type', 'unknown')
            attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
            
            # Por IP
            ip_address = attack.get('ip_address', 'unknown')
            if ip_address != 'unknown':
                top_attackers[ip_address] = top_attackers.get(ip_address, 0) + 1
        
        # Ordena
        top_attack_types = sorted(
            attack_types.items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]
        
        top_attackers_sorted = sorted(
            top_attackers.items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]
        
        return {
            'total_attacks': len(recent_attacks),
            'time_window_hours': hours,
            'attack_types': dict(top_attack_types),
            'top_attackers': dict(top_attackers_sorted),
            'attacks_per_hour': len(recent_attacks) / hours if hours > 0 else 0,
            'most_common_attack': top_attack_types[0][0] if top_attack_types else 'none'
        }
    
    def cleanup_old_logs(self, days_to_keep: int = 30) -> int:
        """
        Limpa logs antigos
        
        Args:
            days_to_keep: Dias para manter logs
            
        Returns:
            Número de arquivos removidos
        """
        if not self.enabled:
            return 0
        
        cutoff_time = time.time() - (days_to_keep * 24 * 3600)
        removed_count = 0
        
        try:
            for root, dirs, files in os.walk(self.log_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    
                    # Verifica se é arquivo de log antigo
                    if file.endswith('.log') or file.endswith('.json'):
                        try:
                            file_mtime = os.path.getmtime(file_path)
                            
                            # Verifica se é arquivo rotacionado (.log.1, .log.2, etc.)
                            if file_mtime < cutoff_time:
                                os.remove(file_path)
                                removed_count += 1
                                logging.debug(f"Arquivo de log antigo removido: {file_path}")
                        
                        except (OSError, FileNotFoundError):
                            continue
        
        except Exception as e:
            logging.error(f"Erro ao limpar logs antigos: {e}")
        
        logging.info(f"Limpeza de logs concluída: {removed_count} arquivos removidos")
        return removed_count