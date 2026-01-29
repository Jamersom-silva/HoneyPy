"""
Módulo IPTracker - Rastreamento e análise de atividades de IPs suspeitos
"""

import time
import json
import ipaddress
import subprocess
import threading
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Any, Set
import logging

logger = logging.getLogger(__name__)


class IPTracker:
    """Classe para rastrear e analisar atividades de IPs suspeitos"""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Inicializa o rastreador de IPs
        
        Args:
            config: Configuração do sistema
        """
        self.config = config
        detection_config = config.get('detection', {})
        
        self.window_seconds = detection_config.get('window_minutes', 10) * 60
        self.max_attempts = detection_config.get('max_attempts', 5)
        self.auto_block = detection_config.get('auto_block', False)
        self.block_duration_hours = detection_config.get('block_duration_hours', 24)
        
        self.attempts_log = defaultdict(lambda: deque(maxlen=10000))
        self.blocked_ips: Set[str] = set()
        self.suspicious_ips: Set[str] = set()
        self.whitelist_ips: Set[str] = set()
        
        # Limites para diferentes tipos de ataques
        self.thresholds = detection_config.get('thresholds', {
            'ssh': {'max_attempts': 5, 'time_window_minutes': 5},
            'ftp': {'max_attempts': 10, 'time_window_minutes': 10},
            'http': {'max_attempts': 20, 'time_window_minutes': 10},
            'mysql': {'max_attempts': 3, 'time_window_minutes': 10},
            'rdp': {'max_attempts': 5, 'time_window_minutes': 5},
            'telnet': {'max_attempts': 5, 'time_window_minutes': 5}
        })
        
        # Carrega IPs bloqueados persistentes
        self.load_blocked_ips()
        self.load_whitelist()
        
        logger.info(f"IPTracker inicializado. Janela: {self.window_seconds/60}min, "
                   f"Auto-block: {self.auto_block}")

    def load_blocked_ips(self) -> None:
        """Carrega IPs bloqueados do arquivo persistente"""
        try:
            blocked_file = 'data/state/blocked_ips.json'
            with open(blocked_file, 'r') as f:
                data = json.load(f)
                self.blocked_ips = set(data.get('blocked_ips', []))
                logger.info(f"Carregados {len(self.blocked_ips)} IPs bloqueados")
        except (FileNotFoundError, json.JSONDecodeError):
            logger.info("Nenhum arquivo de IPs bloqueados encontrado")

    def save_blocked_ips(self) -> None:
        """Salva IPs bloqueados no arquivo persistente"""
        try:
            blocked_file = 'data/state/blocked_ips.json'
            with open(blocked_file, 'w') as f:
                json.dump({
                    'blocked_ips': list(self.blocked_ips),
                    'updated_at': datetime.now().isoformat()
                }, f, indent=2)
        except Exception as e:
            logger.error(f"Erro ao salvar IPs bloqueados: {e}")

    def load_whitelist(self) -> None:
        """Carrega lista de IPs permitidos"""
        try:
            whitelist_file = 'data/state/whitelist.json'
            with open(whitelist_file, 'r') as f:
                data = json.load(f)
                self.whitelist_ips = set(data.get('whitelist', []))
                logger.info(f"Carregados {len(self.whitelist_ips)} IPs na whitelist")
        except (FileNotFoundError, json.JSONDecodeError):
            logger.info("Nenhum arquivo de whitelist encontrado")

    def add_to_whitelist(self, ip_address: str) -> bool:
        """
        Adiciona IP à whitelist
        
        Args:
            ip_address: IP a ser adicionado
            
        Returns:
            True se adicionado com sucesso
        """
        try:
            ipaddress.ip_address(ip_address)
            self.whitelist_ips.add(ip_address)
            
            # Salva whitelist
            whitelist_file = 'data/state/whitelist.json'
            with open(whitelist_file, 'w') as f:
                json.dump({
                    'whitelist': list(self.whitelist_ips),
                    'updated_at': datetime.now().isoformat()
                }, f, indent=2)
            
            logger.info(f"IP {ip_address} adicionado à whitelist")
            return True
            
        except ValueError:
            logger.error(f"Endereço IP inválido para whitelist: {ip_address}")
            return False

    def record_attempt(self, ip_address: str, service: str = 'unknown', 
                      username: str = None, password: str = None) -> Dict[str, Any]:
        """
        Registra uma tentativa de acesso e verifica se é suspeita
        
        Args:
            ip_address: Endereço IP do agressor
            service: Serviço alvo do ataque
            username: Nome de usuário usado (opcional)
            password: Senha usada (opcional)
            
        Returns:
            Dicionário com informações da análise
        """
        # Verifica se IP está na whitelist
        if ip_address in self.whitelist_ips:
            return {
                'is_attack': False,
                'reason': 'IP na whitelist',
                'ip_address': ip_address,
                'service': service
            }
        
        # Verifica se IP já está bloqueado
        if ip_address in self.blocked_ips:
            return {
                'is_attack': True,
                'reason': 'IP já bloqueado',
                'ip_address': ip_address,
                'service': service
            }
        
        current_time = time.time()
        
        # Adiciona a tentativa ao histórico
        self.attempts_log[ip_address].append({
            'timestamp': current_time,
            'service': service,
            'username': username,
            'password': password
        })
        
        # Remove tentativas antigas (fora da janela de tempo)
        window_start = current_time - self.window_seconds
        self.attempts_log[ip_address] = deque(
            [attempt for attempt in self.attempts_log[ip_address] 
             if attempt['timestamp'] >= window_start],
            maxlen=10000
        )
        
        # Conta tentativas por serviço na janela atual
        service_counts = defaultdict(int)
        for attempt in self.attempts_log[ip_address]:
            service_counts[attempt['service']] += 1
        
        # Verifica se excede algum threshold
        is_attack = False
        attack_details = {}
        
        for service_type, count in service_counts.items():
            service_config = self.thresholds.get(service_type, {})
            threshold = service_config.get('max_attempts', self.max_attempts)
            
            if count >= threshold:
                is_attack = True
                self.suspicious_ips.add(ip_address)
                
                attack_details = {
                    'service': service_type,
                    'attempts': count,
                    'threshold': threshold,
                    'time_window': service_config.get('time_window_minutes', 
                                                     self.window_seconds/60)
                }
                
                logger.warning(
                    f"IP {ip_address} excedeu limite para {service_type}: "
                    f"{count}/{threshold} tentativas"
                )
                
                # Bloqueio automático se configurado
                if self.auto_block:
                    self.block_ip(ip_address, self.block_duration_hours)
                
                break
        
        return {
            'is_attack': is_attack,
            'attack_details': attack_details if is_attack else None,
            'ip_address': ip_address,
            'service': service,
            'recent_attempts': len(self.attempts_log[ip_address]),
            'in_blocklist': ip_address in self.blocked_ips
        }

    def get_attack_statistics(self, ip_address: str) -> Dict[str, Any]:
        """
        Obtém estatísticas de ataques para um IP específico
        
        Args:
            ip_address: Endereço IP para análise
            
        Returns:
            Dicionário com estatísticas do IP
        """
        if ip_address not in self.attempts_log:
            return {}
        
        current_time = time.time()
        window_start = current_time - self.window_seconds
        
        recent_attempts = [
            attempt for attempt in self.attempts_log[ip_address]
            if attempt['timestamp'] >= window_start
        ]
        
        if not recent_attempts:
            return {}
        
        # Agrupa por serviço
        service_attempts = defaultdict(list)
        usernames_used = set()
        
        for attempt in recent_attempts:
            service_attempts[attempt['service']].append(attempt['timestamp'])
            if attempt['username']:
                usernames_used.add(attempt['username'])
        
        # Calcula estatísticas
        all_timestamps = [attempt['timestamp'] for attempt in recent_attempts]
        all_timestamps.sort()
        
        if len(all_timestamps) > 1:
            time_diffs = [
                all_timestamps[i+1] - all_timestamps[i] 
                for i in range(len(all_timestamps)-1)
            ]
            avg_time_between = sum(time_diffs) / len(time_diffs)
        else:
            avg_time_between = 0
        
        stats = {
            'ip_address': ip_address,
            'total_attempts': len(recent_attempts),
            'first_attempt': datetime.fromtimestamp(min(all_timestamps)).isoformat(),
            'last_attempt': datetime.fromtimestamp(max(all_timestamps)).isoformat(),
            'avg_time_between_attempts': avg_time_between,
            'unique_usernames': len(usernames_used),
            'services_attacked': {},
            'is_suspicious': ip_address in self.suspicious_ips,
            'is_blocked': ip_address in self.blocked_ips
        }
        
        for service, attempts in service_attempts.items():
            attempts.sort()
            service_timestamps = attempts
            
            if len(service_timestamps) > 1:
                service_diffs = [
                    service_timestamps[i+1] - service_timestamps[i]
                    for i in range(len(service_timestamps)-1)
                ]
                service_avg = sum(service_diffs) / len(service_diffs)
            else:
                service_avg = 0
            
            service_config = self.thresholds.get(service, {})
            threshold = service_config.get('max_attempts', self.max_attempts)
            
            stats['services_attacked'][service] = {
                'attempts': len(attempts),
                'avg_time_between_attempts': service_avg,
                'is_over_threshold': len(attempts) >= threshold,
                'threshold': threshold
            }
        
        return stats

    def block_ip(self, ip_address: str, duration_hours: int = None) -> Dict[str, Any]:
        """
        Bloqueia um IP usando iptables
        
        Args:
            ip_address: IP a ser bloqueado
            duration_hours: Duração do bloqueio em horas
            
        Returns:
            Dicionário com resultado da operação
        """
        if duration_hours is None:
            duration_hours = self.block_duration_hours
        
        try:
            # Verifica se o IP é válido
            ip_obj = ipaddress.ip_address(ip_address)
            
            # Não bloqueia IPs privados por padrão
            if ip_obj.is_private:
                return {
                    'success': False,
                    'error': 'IP privado não pode ser bloqueado',
                    'ip_address': ip_address
                }
            
            # Comandos iptables para bloquear o IP
            commands = [
                ['iptables', '-A', 'INPUT', '-s', ip_address, '-j', 'DROP'],
                ['iptables', '-A', 'FORWARD', '-s', ip_address, '-j', 'DROP']
            ]
            
            success = True
            errors = []
            
            for cmd in commands:
                try:
                    result = subprocess.run(
                        cmd, 
                        check=True, 
                        capture_output=True, 
                        text=True
                    )
                    logger.info(f"Comando executado: {' '.join(cmd)}")
                except subprocess.CalledProcessError as e:
                    success = False
                    error_msg = f"Erro ao executar {' '.join(cmd)}: {e.stderr}"
                    errors.append(error_msg)
                    logger.error(error_msg)
            
            if success:
                self.blocked_ips.add(ip_address)
                self.save_blocked_ips()
                
                logger.info(f"IP {ip_address} bloqueado com sucesso por {duration_hours}h")
                
                # Agenda remoção do bloqueio
                if duration_hours > 0:
                    removal_time = datetime.now() + timedelta(hours=duration_hours)
                    threading.Timer(
                        duration_hours * 3600,
                        self.unblock_ip,
                        args=[ip_address]
                    ).start()
                    logger.info(
                        f"Bloqueio do IP {ip_address} será removido em "
                        f"{duration_hours} horas ({removal_time})"
                    )
                
                return {
                    'success': True,
                    'ip_address': ip_address,
                    'duration_hours': duration_hours,
                    'blocked_until': removal_time.isoformat() if duration_hours > 0 else 'permanent'
                }
            else:
                return {
                    'success': False,
                    'ip_address': ip_address,
                    'errors': errors
                }
                
        except ValueError:
            error_msg = f"Endereço IP inválido: {ip_address}"
            logger.error(error_msg)
            return {
                'success': False,
                'error': error_msg,
                'ip_address': ip_address
            }
        except Exception as e:
            error_msg = f"Erro ao bloquear IP: {e}"
            logger.error(error_msg)
            return {
                'success': False,
                'error': str(e),
                'ip_address': ip_address
            }

    def unblock_ip(self, ip_address: str) -> Dict[str, Any]:
        """
        Remove o bloqueio de um IP
        
        Args:
            ip_address: IP a ser desbloqueado
            
        Returns:
            Dicionário com resultado da operação
        """
        try:
            # Comandos iptables para remover o bloqueio
            commands = [
                ['iptables', '-D', 'INPUT', '-s', ip_address, '-j', 'DROP'],
                ['iptables', '-D', 'FORWARD', '-s', ip_address, '-j', 'DROP']
            ]
            
            success = True
            errors = []
            
            for cmd in commands:
                try:
                    subprocess.run(cmd, check=True, capture_output=True)
                except subprocess.CalledProcessError:
                    # Ignora erro se a regra não existir
                    pass
            
            if ip_address in self.blocked_ips:
                self.blocked_ips.remove(ip_address)
                self.save_blocked_ips()
            
            logger.info(f"IP {ip_address} desbloqueado com sucesso")
            
            return {
                'success': True,
                'ip_address': ip_address
            }
            
        except Exception as e:
            error_msg = f"Erro ao desbloquear IP {ip_address}: {e}"
            logger.error(error_msg)
            return {
                'success': False,
                'error': str(e),
                'ip_address': ip_address
            }

    def get_all_blocked_ips(self) -> List[Dict[str, Any]]:
        """
        Retorna lista de todos os IPs bloqueados com informações
        
        Returns:
            Lista de dicionários com informações dos IPs bloqueados
        """
        blocked_list = []
        
        for ip in self.blocked_ips:
            stats = self.get_attack_statistics(ip)
            blocked_list.append({
                'ip_address': ip,
                'blocked_at': 'N/A',  # Poderia ser armazenado separadamente
                'statistics': stats if stats else {}
            })
        
        return blocked_list

    def get_all_suspicious_ips(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Retorna lista de IPs suspeitos
        
        Args:
            limit: Limite de resultados
            
        Returns:
            Lista de dicionários com informações dos IPs
        """
        suspicious_list = []
        
        for ip in list(self.suspicious_ips)[:limit]:
            stats = self.get_attack_statistics(ip)
            if stats:
                suspicious_list.append(stats)
        
        # Ordena por número de tentativas (decrescente)
        suspicious_list.sort(key=lambda x: x['total_attempts'], reverse=True)
        
        return suspicious_list

    def cleanup_old_entries(self, days_to_keep: int = 30) -> int:
        """
        Remove entradas antigas do histórico
        
        Args:
            days_to_keep: Número de dias para manter no histórico
            
        Returns:
            Número de entradas removidas
        """
        cutoff_time = time.time() - (days_to_keep * 24 * 3600)
        removed_count = 0
        
        # Lista de IPs para remover
        ips_to_remove = []
        
        for ip, attempts in self.attempts_log.items():
            # Mantém apenas tentativas recentes
            recent_attempts = [
                attempt for attempt in attempts
                if attempt['timestamp'] >= cutoff_time
            ]
            
            if not recent_attempts:
                ips_to_remove.append(ip)
            else:
                self.attempts_log[ip] = deque(recent_attempts, maxlen=10000)
                removed_count += (len(attempts) - len(recent_attempts))
        
        # Remove IPs sem tentativas recentes
        for ip in ips_to_remove:
            del self.attempts_log[ip]
            removed_count += 1
        
        # Remove IPs suspeitos antigos (não bloqueados)
        old_suspicious = [
            ip for ip in self.suspicious_ips
            if ip not in self.attempts_log and ip not in self.blocked_ips
        ]
        for ip in old_suspicious:
            self.suspicious_ips.remove(ip)
        
        logger.info(f"Limpeza concluída: {removed_count} entradas antigas removidas")
        return removed_count