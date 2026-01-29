"""
Módulo de formatadores de log personalizados do HoneyPy
"""

import logging
import json
import socket
import os
from datetime import datetime
from typing import Dict, Any, Optional
import traceback


class JSONLogFormatter(logging.Formatter):
    """Formatador de logs em JSON"""
    
    def __init__(self, include_hostname: bool = True, 
                 include_process_info: bool = True):
        """
        Inicializa formatador JSON
        
        Args:
            include_hostname: Incluir nome do host
            include_process_info: Incluir informações do processo
        """
        super().__init__()
        self.include_hostname = include_hostname
        self.include_process_info = include_process_info
        
        # Informações do host
        self.hostname = socket.gethostname() if include_hostname else None
        self.pid = os.getpid() if include_process_info else None
    
    def format(self, record: logging.LogRecord) -> str:
        """
        Formata registro de log como JSON
        
        Args:
            record: Registro de log
            
        Returns:
            String JSON formatada
        """
        log_data = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno
        }
        
        # Adiciona informações do host se configurado
        if self.include_hostname and self.hostname:
            log_data['hostname'] = self.hostname
        
        if self.include_process_info and self.pid:
            log_data['pid'] = self.pid
        
        # Adiciona atributos extras
        if hasattr(record, 'extra_data'):
            log_data.update(record.extra_data)
        
        # Adiciona exceção se houver
        if record.exc_info:
            log_data['exception'] = {
                'type': record.exc_info[0].__name__,
                'message': str(record.exc_info[1]),
                'traceback': self.formatException(record.exc_info)
            }
        
        # Adiciona stack trace se configurado
        if hasattr(record, 'include_stacktrace') and record.include_stacktrace:
            log_data['stacktrace'] = traceback.format_stack()
        
        return json.dumps(log_data, ensure_ascii=False, default=str)


class StructuredLogFormatter(logging.Formatter):
    """Formatador de logs estruturados (não JSON)"""
    
    def __init__(self, fmt: str = None, datefmt: str = None):
        """
        Inicializa formatador estruturado
        
        Args:
            fmt: Formato do log
            datefmt: Formato da data
        """
        if fmt is None:
            fmt = '%(asctime)s | %(levelname)-8s | %(name)-20s | %(message)s'
        
        super().__init__(fmt, datefmt)
    
    def format(self, record: logging.LogRecord) -> str:
        """
        Formata registro de log estruturado
        
        Args:
            record: Registro de log
            
        Returns:
            String formatada
        """
        # Adiciona campos extras ao registro
        if hasattr(record, 'ip_address'):
            record.__dict__['ip_address'] = getattr(record, 'ip_address')
        
        if hasattr(record, 'service'):
            record.__dict__['service'] = getattr(record, 'service')
        
        if hasattr(record, 'attack_type'):
            record.__dict__['attack_type'] = getattr(record, 'attack_type')
        
        # Formata mensagem base
        message = super().format(record)
        
        # Adiciona informações extras se disponíveis
        extra_parts = []
        
        if hasattr(record, 'ip_address'):
            extra_parts.append(f"IP: {record.ip_address}")
        
        if hasattr(record, 'service'):
            extra_parts.append(f"Service: {record.service}")
        
        if hasattr(record, 'attack_type'):
            extra_parts.append(f"Type: {record.attack_type}")
        
        if extra_parts:
            message += f" [{' | '.join(extra_parts)}]"
        
        # Adiciona exceção se houver
        if record.exc_info:
            message += f"\n{self.formatException(record.exc_info)}"
        
        return message


class ColoredLogFormatter(logging.Formatter):
    """Formatador de logs com cores (para terminal)"""
    
    # Cores ANSI
    COLORS = {
        'DEBUG': '\033[36m',      # Cyan
        'INFO': '\033[32m',       # Green
        'WARNING': '\033[33m',    # Yellow
        'ERROR': '\033[31m',      # Red
        'CRITICAL': '\033[41m',   # Red background
        'RESET': '\033[0m'        # Reset
    }
    
    def __init__(self, fmt: str = None, datefmt: str = None):
        """
        Inicializa formatador colorido
        
        Args:
            fmt: Formato do log
            datefmt: Formato da data
        """
        if fmt is None:
            fmt = '%(asctime)s | %(levelname)-8s | %(name)-20s | %(message)s'
        
        super().__init__(fmt, datefmt)
    
    def format(self, record: logging.LogRecord) -> str:
        """
        Formata registro de log com cores
        
        Args:
            record: Registro de log
            
        Returns:
            String colorida formatada
        """
        # Adiciona cor ao nível do log
        levelname = record.levelname
        if levelname in self.COLORS:
            colored_levelname = f"{self.COLORS[levelname]}{levelname}{self.COLORS['RESET']}"
            record.levelname = colored_levelname
        
        # Formata mensagem base
        message = super().format(record)
        
        # Destaca IPs na mensagem (simples)
        import re
        ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
        
        def highlight_ip(match):
            return f"\033[1;35m{match.group()}\033[0m"  # Magenta bold
        
        message = re.sub(ip_pattern, highlight_ip, message)
        
        return message


class AuditLogFormatter(logging.Formatter):
    """Formatador especializado para logs de auditoria"""
    
    def __init__(self):
        """Inicializa formatador de auditoria"""
        fmt = '%(asctime)s | AUDIT | %(event_type)-15s | %(user)-10s | %(action)-20s | %(resource)-30s | %(status)-8s | %(details)s'
        super().__init__(fmt)
    
    def format(self, record: logging.LogRecord) -> str:
        """
        Formata registro de auditoria
        
        Args:
            record: Registro de log
            
        Returns:
            String formatada
        """
        # Garante que campos obrigatórios existam
        required_fields = ['event_type', 'user', 'action', 'resource', 'status', 'details']
        
        for field in required_fields:
            if not hasattr(record, field):
                setattr(record, field, 'N/A')
        
        return super().format(record)


class SyslogFormatter(logging.Formatter):
    """Formatador compatível com syslog"""
    
    # Severidade syslog
    SYSLOG_LEVELS = {
        'DEBUG': 7,      # debug
        'INFO': 6,       # informational
        'WARNING': 4,    # warning
        'ERROR': 3,      # error
        'CRITICAL': 2    # critical
    }
    
    def __init__(self, facility: int = 1,  # user-level messages
                 tag: str = 'honeypy'):
        """
        Inicializa formatador syslog
        
        Args:
            facility: Código da facilidade syslog
            tag: Tag do programa
        """
        super().__init__()
        self.facility = facility
        self.tag = tag
    
    def format(self, record: logging.LogRecord) -> str:
        """
        Formata registro no formato syslog
        
        Args:
            record: Registro de log
            
        Returns:
            String no formato syslog
        """
        # Calcula priority (facility * 8 + severity)
        severity = self.SYSLOG_LEVELS.get(record.levelname, 6)  # default: informational
        priority = (self.facility * 8) + severity
        
        # Timestamp no formato syslog
        timestamp = datetime.now().strftime('%b %d %H:%M:%S')
        
        # Mensagem
        message = record.getMessage()
        
        # Formato syslog RFC 3164
        syslog_message = f"<{priority}>{timestamp} {self.tag}[{os.getpid()}]: {message}"
        
        # Adiciona informações extras se disponíveis
        if hasattr(record, 'ip_address'):
            syslog_message += f" src={record.ip_address}"
        
        if hasattr(record, 'service'):
            syslog_message += f" service={record.service}"
        
        # Adiciona exceção se houver
        if record.exc_info:
            exc_text = self.formatException(record.exc_info)
            syslog_message += f" exception=\"{exc_text}\""
        
        return syslog_message


class CEFFormatter(logging.Formatter):
    """Formatador no formato CEF (Common Event Format)"""
    
    def __init__(self, vendor: str = "HoneyPy", 
                 product: str = "SecurityMonitor",
                 version: str = "1.0"):
        """
        Inicializa formatador CEF
        
        Args:
            vendor: Vendor do produto
            product: Nome do produto
            version: Versão do produto
        """
        super().__init__()
        self.vendor = vendor
        self.product = product
        self.version = version
        
        # Mapeamento de nível para severity CEF
        self.cef_severity = {
            'DEBUG': 1,
            'INFO': 3,
            'WARNING': 5,
            'ERROR': 7,
            'CRITICAL': 9
        }
    
    def format(self, record: logging.LogRecord) -> str:
        """
        Formata registro no formato CEF
        
        Args:
            record: Registro de log
            
        Returns:
            String no formato CEF
        """
        # Cabeçalho CEF
        severity = self.cef_severity.get(record.levelname, 5)  # default: medium
        timestamp = int(datetime.now().timestamp() * 1000)  # milliseconds
        
        cef_header = f"CEF:0|{self.vendor}|{self.product}|{self.version}|{record.name}|{record.getMessage()}|{severity}|"
        
        # Extensões CEF
        extensions = []
        
        # Adiciona campos padrão
        extensions.append(f"start={timestamp}")
        
        # Adiciona campos específicos se disponíveis
        if hasattr(record, 'ip_address'):
            extensions.append(f"src={record.ip_address}")
        
        if hasattr(record, 'service'):
            extensions.append(f"app={record.service}")
        
        if hasattr(record, 'attack_type'):
            extensions.append(f"cat={record.attack_type}")
        
        if hasattr(record, 'username'):
            extensions.append(f"suser={record.username}")
        
        if hasattr(record, 'target'):
            extensions.append(f"dst={record.target}")
        
        # Adiciona mensagem como extensão
        extensions.append(f"msg={record.getMessage()}")
        
        # Adiciona exceção se houver
        if record.exc_info:
            exc_text = self.formatException(record.exc_info).replace('|', '\\|')
            extensions.append(f"exception={exc_text}")
        
        cef_message = cef_header + ' '.join(extensions)
        
        return cef_message


class LogFormatterFactory:
    """Fábrica de formatadores de log"""
    
    @staticmethod
    def create_formatter(formatter_type: str = 'structured', 
                         **kwargs) -> logging.Formatter:
        """
        Cria formatador baseado no tipo
        
        Args:
            formatter_type: Tipo de formatador
            **kwargs: Argumentos para o formatador
            
        Returns:
            Instância do formatador
        """
        formatters = {
            'json': JSONLogFormatter,
            'structured': StructuredLogFormatter,
            'colored': ColoredLogFormatter,
            'audit': AuditLogFormatter,
            'syslog': SyslogFormatter,
            'cef': CEFFormatter
        }
        
        formatter_class = formatters.get(formatter_type.lower(), StructuredLogFormatter)
        
        try:
            return formatter_class(**kwargs)
        except Exception as e:
            logging.error(f"Erro ao criar formatador {formatter_type}: {e}")
            return StructuredLogFormatter()
    
    @staticmethod
    def configure_logger(logger: logging.Logger, 
                         formatter_type: str = 'structured',
                         level: str = 'INFO',
                         **kwargs):
        """
        Configura logger com formatador específico
        
        Args:
            logger: Logger a configurar
            formatter_type: Tipo de formatador
            level: Nível do log
            **kwargs: Argumentos para o formatador
        """
        # Remove handlers existentes
        logger.handlers.clear()
        
        # Cria handler de console
        console_handler = logging.StreamHandler()
        
        # Cria e configura formatador
        formatter = LogFormatterFactory.create_formatter(formatter_type, **kwargs)
        console_handler.setFormatter(formatter)
        
        # Configura nível
        logger.setLevel(getattr(logging, level.upper()))
        console_handler.setLevel(getattr(logging, level.upper()))
        
        # Adiciona handler
        logger.addHandler(console_handler)
        logger.propagate = False