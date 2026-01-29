"""
Módulo de funções auxiliares do HoneyPy
"""

import json
import logging
import logging.handlers
import os
import sys
from typing import Dict, Any, Optional
from datetime import datetime
import socket
import ipaddress


def setup_logging(config: Dict = None) -> None:
    """
    Configura o sistema de logging
    
    Args:
        config: Configuração de logging (opcional)
    """
    if config is None:
        config = {
            'enabled': True,
            'level': 'INFO',
            'directory': '/var/log/honeypy',
            'max_size_mb': 100,
            'backup_count': 5
        }
    
    log_level = getattr(logging, config.get('level', 'INFO').upper())
    
    # Cria diretório de logs se não existir
    log_dir = config.get('directory', '/var/log/honeypy')
    os.makedirs(log_dir, exist_ok=True)
    
    # Configura handlers
    handlers = []
    
    # Handler para arquivo
    log_file = os.path.join(log_dir, 'honeypy.log')
    file_handler = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes=config.get('max_size_mb', 100) * 1024 * 1024,
        backupCount=config.get('backup_count', 5)
    )
    file_handler.setLevel(log_level)
    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(file_formatter)
    handlers.append(file_handler)
    
    # Handler para console (apenas se não for serviço systemd)
    if sys.stdout.isatty():
        console_handler = logging.StreamHandler()
        console_handler.setLevel(log_level)
        console_formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%H:%M:%S'
        )
        console_handler.setFormatter(console_formatter)
        handlers.append(console_handler)
    
    # Configura logging root
    logging.basicConfig(
        level=log_level,
        handlers=handlers,
        force=True
    )
    
    # Reduz verbosidade de algumas bibliotecas
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('requests').setLevel(logging.WARNING)


def load_config(config_path: str = None) -> Dict[str, Any]:
    """
    Carrega configuração do sistema
    
    Args:
        config_path: Caminho para arquivo de configuração
        
    Returns:
        Dicionário com configuração
    """
    default_config = {
        'system': {
            'name': 'HoneyPy',
            'version': '1.0.0',
            'mode': 'production'
        },
        'monitoring': {
            'enabled': True,
            'interval_seconds': 10,
            'log_retention_days': 30,
            'report_retention_days': 90
        },
        'detection': {
            'window_minutes': 10,
            'max_attempts': 5,
            'thresholds': {
                'ssh': {'max_attempts': 5, 'time_window_minutes': 5},
                'ftp': {'max_attempts': 10, 'time_window_minutes': 10},
                'http': {'max_attempts': 20, 'time_window_minutes': 10},
                'mysql': {'max_attempts': 3, 'time_window_minutes': 10}
            },
            'auto_block': False,
            'block_duration_hours': 24
        },
        'logging': {
            'enabled': True,
            'level': 'INFO',
            'directory': '/var/log/honeypy',
            'max_size_mb': 100,
            'backup_count': 5
        },
        'paths': {
            'log_files': {
                'ssh': '/var/log/auth.log',
                'ftp': '/var/log/vsftpd.log',
                'apache': '/var/log/apache2/access.log',
                'mysql': '/var/log/mysql/error.log'
            },
            'data_directory': '/var/lib/honeypy',
            'reports_directory': '/var/lib/honeypy/reports'
        }
    }
    
    # Tenta carregar configuração personalizada
    config_locations = [
        config_path,
        '/etc/honeypy/config.json',
        os.path.expanduser('~/.honeypy/config.json'),
        'config/config.json'
    ]
    
    loaded_config = default_config
    
    for location in config_locations:
        if location and os.path.exists(location):
            try:
                with open(location, 'r') as f:
                    user_config = json.load(f)
                    # Mescla configurações
                    loaded_config = deep_merge(default_config, user_config)
                logging.info(f"Configuração carregada de: {location}")
                break
            except (json.JSONDecodeError, IOError) as e:
                logging.warning(f"Erro ao carregar configuração de {location}: {e}")
    
    return loaded_config


def deep_merge(base: Dict, override: Dict) -> Dict:
    """
    Realiza merge profundo de dois dicionários
    
    Args:
        base: Dicionário base
        override: Dicionário com sobreposições
        
    Returns:
        Dicionário mesclado
    """
    result = base.copy()
    
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    
    return result


def validate_config(config: Dict[str, Any]) -> bool:
    """
    Valida configuração do sistema
    
    Args:
        config: Configuração a validar
        
    Returns:
        True se válida, False caso contrário
    """
    try:
        # Valida estrutura básica
        required_sections = ['system', 'monitoring', 'detection', 'logging']
        for section in required_sections:
            if section not in config:
                logging.error(f"Seção '{section}' não encontrada na configuração")
                return False
        
        # Valida valores
        if config['monitoring']['interval_seconds'] <= 0:
            logging.error("interval_seconds deve ser maior que 0")
            return False
        
        if config['detection']['window_minutes'] <= 0:
            logging.error("window_minutes deve ser maior que 0")
            return False
        
        if config['detection']['max_attempts'] <= 0:
            logging.error("max_attempts deve ser maior que 0")
            return False
        
        # Valida paths
        paths = config.get('paths', {})
        for path_key, path_value in paths.items():
            if isinstance(path_value, dict):
                for sub_key, sub_value in path_value.items():
                    if not isinstance(sub_value, (str, list)):
                        logging.warning(f"Path inválido: {path_key}.{sub_key}")
            elif not isinstance(path_value, str):
                logging.warning(f"Path inválido: {path_key}")
        
        logging.info("Configuração validada com sucesso")
        return True
        
    except KeyError as e:
        logging.error(f"Chave faltando na configuração: {e}")
        return False
    except Exception as e:
        logging.error(f"Erro ao validar configuração: {e}")
        return False


def get_hostname() -> str:
    """
    Obtém nome do host
    
    Returns:
        Nome do host
    """
    try:
        return socket.gethostname()
    except:
        return "unknown"


def get_ip_address() -> str:
    """
    Obtém endereço IP principal do host
    
    Returns:
        Endereço IP
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"


def validate_ip_address(ip: str) -> bool:
    """
    Valida endereço IP
    
    Args:
        ip: Endereço IP a validar
        
    Returns:
        True se válido, False caso contrário
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def get_timestamp() -> str:
    """
    Obtém timestamp atual formatado
    
    Returns:
        Timestamp ISO
    """
    return datetime.now().isoformat()


def create_directory_structure() -> None:
    """
    Cria estrutura de diretórios necessária
    """
    directories = [
        '/var/log/honeypy',
        '/var/lib/honeypy',
        '/var/lib/honeypy/reports',
        '/var/lib/honeypy/reports/daily',
        '/var/lib/honeypy/reports/weekly',
        '/var/lib/honeypy/reports/monthly',
        '/var/lib/honeypy/logs',
        '/var/lib/honeypy/state',
        '/var/lib/honeypy/databases'
    ]
    
    for directory in directories:
        try:
            os.makedirs(directory, exist_ok=True)
            logging.debug(f"Diretório criado/verificado: {directory}")
        except Exception as e:
            logging.error(f"Erro ao criar diretório {directory}: {e}")


def bytes_to_human_readable(size_bytes: int) -> str:
    """
    Converte bytes para formato legível
    
    Args:
        size_bytes: Tamanho em bytes
        
    Returns:
        String formatada
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} PB"


def is_root() -> bool:
    """
    Verifica se está executando como root
    
    Returns:
        True se root, False caso contrário
    """
    return os.geteuid() == 0


def check_dependencies() -> Dict[str, bool]:
    """
    Verifica dependências do sistema
    
    Returns:
        Dicionário com status das dependências
    """
    dependencies = {
        'python_version': sys.version_info >= (3, 7),
        'iptables': check_command_exists('iptables'),
        'python_modules': check_python_modules(['json', 're', 'logging', 'datetime'])
    }
    
    return dependencies


def check_command_exists(command: str) -> bool:
    """
    Verifica se comando existe no sistema
    
    Args:
        command: Nome do comando
        
    Returns:
        True se existe, False caso contrário
    """
    try:
        from shutil import which
        return which(command) is not None
    except:
        return False


def check_python_modules(modules: list) -> bool:
    """
    Verifica se módulos Python estão disponíveis
    
    Args:
        modules: Lista de nomes de módulos
        
    Returns:
        True se todos disponíveis, False caso contrário
    """
    try:
        for module in modules:
            __import__(module)
        return True
    except ImportError:
        return False


def get_system_info() -> Dict[str, Any]:
    """
    Obtém informações do sistema
    
    Returns:
        Dicionário com informações
    """
    import platform
    import psutil
    
    info = {
        'hostname': get_hostname(),
        'ip_address': get_ip_address(),
        'os': platform.system(),
        'os_version': platform.version(),
        'python_version': platform.python_version(),
        'cpu_count': psutil.cpu_count(),
        'total_memory': psutil.virtual_memory().total,
        'disk_usage': psutil.disk_usage('/').percent,
        'boot_time': datetime.fromtimestamp(psutil.boot_time()).isoformat()
    }
    
    return info