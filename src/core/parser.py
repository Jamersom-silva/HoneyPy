"""
Módulo LogParser - Análise de logs do sistema em busca de ataques
"""

import re
import json
import time
import logging
import hashlib
from datetime import datetime
from typing import Dict, List, Optional, Any, Pattern
import os

logger = logging.getLogger(__name__)


class LogParser:
    """Classe para analisar logs do sistema em busca de ataques"""
    
    # Padrões de expressões regulares para diferentes tipos de logs
    LOG_PATTERNS = {
        'ssh': [
            # SSH falhas de senha
            r'Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)',
            r'authentication failure;.*rhost=(\d+\.\d+\.\d+\.\d+)',
            # SSH ataques de força bruta detectados
            r'Connection closed by (\d+\.\d+\.\d+\.\d+) \[preauth\]',
            r'Did not receive identification string from (\d+\.\d+\.\d+\.\d+)',
        ],
        'ftp': [
            # ProFTPD
            r'(\d+\.\d+\.\d+\.\d+).*LOGIN FAILED.*user=(\S+)',
            # vsftpd
            r'FAIL LOGIN.*client=(\d+\.\d+\.\d+\.\d+)',
            # Pure-FTPd
            r'(\d+\.\d+\.\d+\.\d+).*authentication failed for user (\S+)',
        ],
        'apache': [
            # Tentativas de login WordPress
            r'(\d+\.\d+\.\d+\.\d+).*"POST /wp-login\.php.* 200',
            r'(\d+\.\d+\.\d+\.\d+).*"POST /xmlrpc\.php.* 200',
            # Tentativas de acesso a admin
            r'(\d+\.\d+\.\d+\.\d+).*"GET /admin.* 401',
            r'(\d+\.\d+\.\d+\.\d+).*"POST /admin.* 401',
            # SQL Injection patterns
            r'(\d+\.\d+\.\d+\.\d+).*(union.*select|select.*from|insert.*into)',
            # Directory traversal
            r'(\d+\.\d+\.\d+\.\d+).*(\.\./|\.\.\\).*HTTP',
        ],
        'nginx': [
            # Padrões similares ao Apache
            r'(\d+\.\d+\.\d+\.\d+).*"POST /wp-login\.php.* 200',
            r'(\d+\.\d+\.\d+\.\d+).*"GET /admin.* 401',
        ],
        'mysql': [
            r'Access denied for user \'(\S+)\'@\'(\d+\.\d+\.\d+\.\d+)\'',
            r'Host \'(\d+\.\d+\.\d+\.\d+)\' is blocked',
            r'Too many connections from \'(\d+\.\d+\.\d+\.\d+)\'',
        ],
        'postgresql': [
            r'FATAL:.*password authentication failed for user "(\S+)"',
            r'connection authorized: user=(\S+) database=(\S+) host=(\d+\.\d+\.\d+\.\d+)',
        ],
        'rdp': [
            r'(\d+\.\d+\.\d+\.\d+).*Authentication failure',
            r'Failed RDP connection from (\d+\.\d+\.\d+\.\d+)',
        ],
        'telnet': [
            r'Failed telnet login from (\d+\.\d+\.\d+\.\d+)',
            r'Connection from (\d+\.\d+\.\d+\.\d+) refused',
        ]
    }
    
    # Mapeamento de serviços para arquivos de log padrão
    DEFAULT_LOG_PATHS = {
        'ssh': [
            '/var/log/auth.log',
            '/var/log/secure',
            '/var/log/messages'
        ],
        'apache': [
            '/var/log/apache2/access.log',
            '/var/log/apache2/error.log',
            '/var/log/httpd/access_log',
            '/var/log/httpd/error_log'
        ],
        'nginx': [
            '/var/log/nginx/access.log',
            '/var/log/nginx/error.log'
        ],
        'ftp': [
            '/var/log/vsftpd.log',
            '/var/log/proftpd/auth.log',
            '/var/log/xferlog'
        ],
        'mysql': [
            '/var/log/mysql/error.log',
            '/var/log/mysql/mysql.log'
        ],
        'postgresql': [
            '/var/log/postgresql/postgresql-*.log'
        ]
    }
    
    def __init__(self, ip_tracker, config: Dict[str, Any]):
        """
        Inicializa o parser de logs
        
        Args:
            ip_tracker: Instância do IPTracker para registrar tentativas
            config: Configuração do sistema
        """
        self.ip_tracker = ip_tracker
        self.config = config
        
        # Compila padrões regex para melhor performance
        self.compiled_patterns = {}
        for log_type, patterns in self.LOG_PATTERNS.items():
            self.compiled_patterns[log_type] = [
                re.compile(pattern) for pattern in patterns
            ]
        
        # Estado do parser
        self.log_positions = {}
        self.line_hashes = set()  # Para evitar duplicatas
        self.last_cleanup = time.time()
        
        # Carrega posições salvas
        self.load_state()
        
        logger.info("LogParser inicializado")

    def load_state(self) -> None:
        """Carrega o estado do parser do arquivo"""
        try:
            state_file = 'data/state/parser_state.json'
            if os.path.exists(state_file):
                with open(state_file, 'r') as f:
                    state = json.load(f)
                    self.log_positions = state.get('log_positions', {})
                    self.line_hashes = set(state.get('line_hashes', []))
                    
                    # Limita o tamanho do conjunto de hashes
                    if len(self.line_hashes) > 100000:
                        self.line_hashes = set(list(self.line_hashes)[-50000:])
                    
                logger.info(f"Estado carregado: {len(self.log_positions)} logs, "
                          f"{len(self.line_hashes)} hashes")
        except Exception as e:
            logger.error(f"Erro ao carregar estado: {e}")

    def save_state(self) -> None:
        """Salva o estado do parser no arquivo"""
        try:
            state_file = 'data/state/parser_state.json'
            os.makedirs(os.path.dirname(state_file), exist_ok=True)
            
            with open(state_file, 'w') as f:
                json.dump({
                    'log_positions': self.log_positions,
                    'line_hashes': list(self.line_hashes)[-50000:],  # Mantém apenas os mais recentes
                    'saved_at': datetime.now().isoformat()
                }, f, indent=2)
        except Exception as e:
            logger.error(f"Erro ao salvar estado: {e}")

    def get_log_paths(self, log_type: str) -> List[str]:
        """
        Obtém caminhos de log para um tipo específico
        
        Args:
            log_type: Tipo de log
            
        Returns:
            Lista de caminhos de arquivo
        """
        config_paths = self.config.get('paths', {}).get('log_files', {})
        
        # Tenta obter do config, depois dos padrões
        if log_type in config_paths:
            paths = config_paths[log_type]
            if isinstance(paths, str):
                return [paths]
            elif isinstance(paths, list):
                return paths
        
        # Fallback para padrões
        return self.DEFAULT_LOG_PATHS.get(log_type, [])

    def generate_line_hash(self, line: str, log_path: str) -> str:
        """
        Gera hash único para uma linha de log
        
        Args:
            line: Linha do log
            log_path: Caminho do arquivo de log
            
        Returns:
            Hash MD5 da linha
        """
        # Combina o caminho e a linha para evitar colisões entre arquivos
        unique_string = f"{log_path}:{line.strip()}"
        return hashlib.md5(unique_string.encode()).hexdigest()

    def parse_log_file(self, log_path: str, log_type: str = None) -> List[Dict[str, Any]]:
        """
        Analisa um arquivo de log em busca de tentativas falhas
        
        Args:
            log_path: Caminho para o arquivo de log
            log_type: Tipo de log (inferido do caminho se None)
            
        Returns:
            Lista de dicionários com informações das tentativas
        """
        if not os.path.exists(log_path):
            return []
        
        # Determina o tipo de log se não especificado
        if log_type is None:
            log_type = self.infer_log_type(log_path)
        
        attempts = []
        
        try:
            # Obtém a última posição lida
            last_position = self.log_positions.get(log_path, 0)
            current_position = os.path.getsize(log_path)
            
            # Se o arquivo foi truncado, começa do início
            if current_position < last_position:
                logger.warning(f"Arquivo de log truncado: {log_path}")
                last_position = 0
            
            # Lê apenas as novas entradas
            if current_position > last_position:
                with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                    f.seek(last_position)
                    new_lines = f.readlines()
                    
                    for line in new_lines:
                        attempt = self.parse_log_line(line, log_type, log_path)
                        if attempt:
                            attempts.append(attempt)
                    
                    # Atualiza a posição
                    self.log_positions[log_path] = current_position
            
        except PermissionError:
            logger.error(f"Permissão negada para ler log: {log_path}")
        except FileNotFoundError:
            logger.warning(f"Arquivo de log não encontrado: {log_path}")
        except Exception as e:
            logger.error(f"Erro ao ler log {log_path}: {e}")
        
        return attempts

    def infer_log_type(self, log_path: str) -> str:
        """
        Infere o tipo de log baseado no caminho do arquivo
        
        Args:
            log_path: Caminho do arquivo de log
            
        Returns:
            Tipo de log inferido
        """
        filename = os.path.basename(log_path).lower()
        
        if 'auth' in filename or 'secure' in filename:
            return 'ssh'
        elif 'access' in filename and ('apache' in filename or 'httpd' in filename):
            return 'apache'
        elif 'access' in filename and 'nginx' in filename:
            return 'nginx'
        elif 'error' in filename and ('mysql' in filename or 'mariadb' in filename):
            return 'mysql'
        elif 'ftp' in filename or 'xferlog' in filename:
            return 'ftp'
        elif 'postgres' in filename:
            return 'postgresql'
        else:
            # Análise de conteúdo para determinar
            return 'unknown'

    def parse_log_line(self, line: str, log_type: str, log_path: str) -> Optional[Dict[str, Any]]:
        """
        Analisa uma linha de log individual
        
        Args:
            line: Linha do log
            log_type: Tipo de log
            log_path: Caminho do arquivo de log
            
        Returns:
            Dicionário com informações da tentativa ou None
        """
        # Gera hash para verificar duplicatas
        line_hash = self.generate_line_hash(line, log_path)
        if line_hash in self.line_hashes:
            return None
        
        # Adiciona hash ao conjunto
        self.line_hashes.add(line_hash)
        
        patterns = self.compiled_patterns.get(log_type, [])
        
        for pattern in patterns:
            match = pattern.search(line)
            if match:
                ip_address = None
                username = None
                password = None
                extra_info = {}
                
                # Extrai informações baseadas no padrão
                groups = match.groups()
                
                if log_type == 'ssh':
                    if len(groups) >= 2:
                        username = groups[0]
                        ip_address = groups[1]
                    elif len(groups) >= 1:
                        ip_address = groups[0]
                
                elif log_type in ['ftp', 'mysql', 'postgresql']:
                    if len(groups) >= 2:
                        username = groups[0]
                        ip_address = groups[1]
                    elif len(groups) >= 1:
                        ip_address = groups[0]
                
                elif log_type in ['apache', 'nginx']:
                    if groups:
                        ip_address = groups[0]
                        # Extrai informações adicionais de ataques web
                        if 'wp-login' in line:
                            extra_info['attack_type'] = 'wordpress_bruteforce'
                        elif 'admin' in line:
                            extra_info['attack_type'] = 'admin_panel_bruteforce'
                        elif 'union' in line.lower() or 'select' in line.lower():
                            extra_info['attack_type'] = 'sql_injection'
                        elif '..' in line:
                            extra_info['attack_type'] = 'directory_traversal'
                
                if ip_address:
                    return {
                        'timestamp': datetime.now().isoformat(),
                        'log_timestamp': self.extract_timestamp(line),
                        'log_type': log_type,
                        'log_path': log_path,
                        'ip_address': ip_address,
                        'username': username,
                        'password': password,
                        'raw_line': line.strip(),
                        'line_hash': line_hash,
                        'extra_info': extra_info
                    }
        
        return None

    def extract_timestamp(self, line: str) -> str:
        """
        Extrai timestamp da linha de log
        
        Args:
            line: Linha do log
            
        Returns:
            Timestamp como string ISO ou None
        """
        try:
            # Padrões comuns de timestamp
            timestamp_patterns = [
                r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})',
                r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})',
                r'(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})',
            ]
            
            for pattern in timestamp_patterns:
                match = re.search(pattern, line)
                if match:
                    return match.group(1)
        except Exception:
            pass
        
        return None

    def monitor_all_logs(self) -> List[Dict[str, Any]]:
        """
        Monitora todos os logs configurados
        
        Returns:
            Lista de todas as tentativas detectadas
        """
        all_attempts = []
        monitored_logs = self.config.get('log_types', ['ssh', 'ftp', 'apache', 'mysql'])
        
        for log_type in monitored_logs:
            log_paths = self.get_log_paths(log_type)
            
            for log_path in log_paths:
                attempts = self.parse_log_file(log_path, log_type)
                all_attempts.extend(attempts)
        
        # Limpeza periódica do conjunto de hashes
        current_time = time.time()
        if current_time - self.last_cleanup > 3600:  # A cada hora
            self.cleanup_old_hashes()
            self.last_cleanup = current_time
        
        return all_attempts

    def cleanup_old_hashes(self) -> None:
        """Limpa hashes antigos para evitar crescimento excessivo"""
        if len(self.line_hashes) > 100000:
            # Mantém apenas os 50000 mais recentes
            self.line_hashes = set(list(self.line_hashes)[-50000:])
            logger.info(f"Conjunto de hashes limpo: {len(self.line_hashes)} hashes")

    def process_attempts(self, attempts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Processa tentativas detectadas e registra no tracker
        
        Args:
            attempts: Lista de tentativas detectadas
            
        Returns:
            Lista de tentativas processadas
        """
        processed_attempts = []
        
        for attempt in attempts:
            # Registra a tentativa no tracker
            analysis = self.ip_tracker.record_attempt(
                ip_address=attempt['ip_address'],
                service=attempt['log_type'],
                username=attempt.get('username'),
                password=attempt.get('password')
            )
            
            # Combina informações
            processed_attempt = {
                **attempt,
                'analysis': analysis
            }
            
            processed_attempts.append(processed_attempt)
            
            # Log de ataques detectados
            if analysis['is_attack']:
                logger.warning(
                    f"Ataque detectado! IP: {attempt['ip_address']}, "
                    f"Serviço: {attempt['log_type']}, "
                    f"Tipo: {analysis['attack_details'].get('service') if analysis['attack_details'] else 'N/A'}"
                )
        
        # Salva tentativas em arquivo estruturado
        if processed_attempts:
            self.save_attempts_to_json(processed_attempts)
        
        # Salva estado do parser
        self.save_state()
        
        return processed_attempts

    def save_attempts_to_json(self, attempts: List[Dict[str, Any]]) -> None:
        """
        Salva tentativas em arquivo JSON estruturado
        
        Args:
            attempts: Lista de tentativas a serem salvas
        """
        try:
            log_file = 'data/logs/attack_attempts.json'
            os.makedirs(os.path.dirname(log_file), exist_ok=True)
            
            existing_data = []
            
            # Carrega dados existentes
            if os.path.exists(log_file):
                try:
                    with open(log_file, 'r') as f:
                        existing_data = json.load(f)
                except json.JSONDecodeError:
                    existing_data = []
            
            # Adiciona novas tentativas
            existing_data.extend(attempts)
            
            # Mantém apenas as últimas 5000 entradas
            if len(existing_data) > 5000:
                existing_data = existing_data[-5000:]
            
            # Salva no arquivo
            with open(log_file, 'w') as f:
                json.dump(existing_data, f, indent=2, default=str)
                
        except Exception as e:
            logger.error(f"Erro ao salvar tentativas: {e}")