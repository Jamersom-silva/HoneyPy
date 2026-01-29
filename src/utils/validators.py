"""
Módulo de validação de dados do HoneyPy
"""

import re
import ipaddress
import socket
import logging
from typing import Union, List, Dict, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class Validators:
    """Classe para validação de dados do sistema"""
    
    # Padrões regex comuns
    PATTERNS = {
        'ipv4': r'^(\d{1,3}\.){3}\d{1,3}$',
        'ipv6': r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$',
        'cidr': r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$',
        'mac': r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$',
        'email': r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
        'domain': r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$',
        'username': r'^[a-zA-Z0-9._-]{3,32}$',
        'port': r'^\d{1,5}$'
    }
    
    @staticmethod
    def validate_ip_address(ip: str) -> bool:
        """
        Valida endereço IPv4 ou IPv6
        
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
    
    @staticmethod
    def validate_ipv4(ip: str) -> bool:
        """
        Valida endereço IPv4
        
        Args:
            ip: Endereço IPv4 a validar
            
        Returns:
            True se válido, False caso contrário
        """
        try:
            return isinstance(ipaddress.ip_address(ip), ipaddress.IPv4Address)
        except ValueError:
            return False
    
    @staticmethod
    def validate_ipv6(ip: str) -> bool:
        """
        Valida endereço IPv6
        
        Args:
            ip: Endereço IPv6 a validar
            
        Returns:
            True se válido, False caso contrário
        """
        try:
            return isinstance(ipaddress.ip_address(ip), ipaddress.IPv6Address)
        except ValueError:
            return False
    
    @staticmethod
    def validate_cidr(cidr: str) -> bool:
        """
        Valida notação CIDR
        
        Args:
            cidr: Notação CIDR a validar
            
        Returns:
            True se válido, False caso contrário
        """
        try:
            ipaddress.ip_network(cidr, strict=False)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def validate_mac_address(mac: str) -> bool:
        """
        Valida endereço MAC
        
        Args:
            mac: Endereço MAC a validar
            
        Returns:
            True se válido, False caso contrário
        """
        pattern = Validators.PATTERNS['mac']
        return bool(re.match(pattern, mac))
    
    @staticmethod
    def validate_port(port: Union[str, int]) -> bool:
        """
        Valida número de porta
        
        Args:
            port: Número da porta
            
        Returns:
            True se válido, False caso contrário
        """
        try:
            port_num = int(port)
            return 1 <= port_num <= 65535
        except (ValueError, TypeError):
            return False
    
    @staticmethod
    def validate_username(username: str) -> bool:
        """
        Valida nome de usuário
        
        Args:
            username: Nome de usuário
            
        Returns:
            True se válido, False caso contrário
        """
        pattern = Validators.PATTERNS['username']
        return bool(re.match(pattern, username))
    
    @staticmethod
    def validate_domain(domain: str) -> bool:
        """
        Valida nome de domínio
        
        Args:
            domain: Nome de domínio
            
        Returns:
            True se válido, False caso contrário
        """
        pattern = Validators.PATTERNS['domain']
        return bool(re.match(pattern, domain))
    
    @staticmethod
    def validate_email(email: str) -> bool:
        """
        Valida endereço de email
        
        Args:
            email: Endereço de email
            
        Returns:
            True se válido, False caso contrário
        """
        pattern = Validators.PATTERNS['email']
        return bool(re.match(pattern, email))
    
    @staticmethod
    def validate_ip_range(start_ip: str, end_ip: str) -> bool:
        """
        Valida range de IPs
        
        Args:
            start_ip: IP inicial
            end_ip: IP final
            
        Returns:
            True se válido, False caso contrário
        """
        if not (Validators.validate_ip_address(start_ip) and 
                Validators.validate_ip_address(end_ip)):
            return False
        
        try:
            start = ipaddress.ip_address(start_ip)
            end = ipaddress.ip_address(end_ip)
            return start <= end
        except ValueError:
            return False
    
    @staticmethod
    def validate_timestamp(timestamp: str, format: str = None) -> bool:
        """
        Valida timestamp
        
        Args:
            timestamp: Timestamp a validar
            format: Formato específico (opcional)
            
        Returns:
            True se válido, False caso contrário
        """
        try:
            if format:
                datetime.strptime(timestamp, format)
            else:
                # Tenta parser ISO
                datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            return True
        except (ValueError, TypeError):
            return False
    
    @staticmethod
    def validate_config_structure(config: Dict[str, Any], 
                                  schema: Dict[str, Any]) -> List[str]:
        """
        Valida estrutura de configuração contra schema
        
        Args:
            config: Configuração a validar
            schema: Schema de validação
            
        Returns:
            Lista de erros encontrados
        """
        errors = []
        Validators._validate_config_recursive(config, schema, [], errors)
        return errors
    
    @staticmethod
    def _validate_config_recursive(config: Any, schema: Any, 
                                   path: List[str], errors: List[str]):
        """
        Validação recursiva de configuração
        
        Args:
            config: Configuração atual
            schema: Schema atual
            path: Caminho atual
            errors: Lista de erros
        """
        if isinstance(schema, dict):
            if not isinstance(config, dict):
                errors.append(f"{'.'.join(path)}: Esperado dict, encontrado {type(config).__name__}")
                return
            
            # Verifica campos obrigatórios
            required_fields = schema.get('__required__', [])
            for field in required_fields:
                if field not in config:
                    errors.append(f"{'.'.join(path)}: Campo obrigatório '{field}' faltando")
            
            # Valida campos presentes
            for key, value in config.items():
                if key in schema:
                    new_path = path + [key]
                    Validators._validate_config_recursive(value, schema[key], new_path, errors)
                elif not key.startswith('__'):
                    # Campo não especificado no schema
                    pass
        
        elif isinstance(schema, list):
            if not isinstance(config, list):
                errors.append(f"{'.'.join(path)}: Esperado list, encontrado {type(config).__name__}")
                return
            
            if schema and len(schema) == 1:
                # Lista de um tipo específico
                item_schema = schema[0]
                for i, item in enumerate(config):
                    new_path = path + [f"[{i}]"]
                    Validators._validate_config_recursive(item, item_schema, new_path, errors)
        
        elif callable(schema):
            # Schema é uma função de validação
            try:
                if not schema(config):
                    errors.append(f"{'.'.join(path)}: Validação falhou")
            except Exception as e:
                errors.append(f"{'.'.join(path)}: Erro na validação: {e}")
        
        elif isinstance(schema, type):
            # Schema é um tipo
            if not isinstance(config, schema):
                errors.append(f"{'.'.join(path)}: Esperado {schema.__name__}, "
                            f"encontrado {type(config).__name__}")
    
    @staticmethod
    def sanitize_input(input_str: str, max_length: int = 1024) -> str:
        """
        Sanitiza entrada de usuário
        
        Args:
            input_str: String a sanitizar
            max_length: Tamanho máximo permitido
            
        Returns:
            String sanitizada
        """
        if not isinstance(input_str, str):
            return ""
        
        # Remove caracteres de controle e limita tamanho
        sanitized = ''.join(char for char in input_str 
                           if char.isprintable() or char in '\t\n\r')
        
        # Limita tamanho
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length]
        
        return sanitized.strip()
    
    @staticmethod
    def validate_log_line(line: str) -> bool:
        """
        Valida linha de log
        
        Args:
            line: Linha de log
            
        Returns:
            True se válida, False caso contrário
        """
        if not isinstance(line, str):
            return False
        
        # Linha muito curta ou muito longa
        if len(line) < 5 or len(line) > 10000:
            return False
        
        # Contém caracteres não imprimíveis (exceto tab e newline)
        for char in line:
            if not char.isprintable() and char not in '\t\n\r':
                return False
        
        return True
    
    @staticmethod
    def validate_service_name(service: str) -> bool:
        """
        Valida nome de serviço
        
        Args:
            service: Nome do serviço
            
        Returns:
            True se válido, False caso contrário
        """
        valid_services = {
            'ssh', 'ftp', 'http', 'https', 'mysql', 'postgresql',
            'rdp', 'telnet', 'smtp', 'dns', 'snmp', 'ldap',
            'apache', 'nginx', 'iis', 'tomcat'
        }
        
        return service.lower() in valid_services
    
    @staticmethod
    def validate_attack_type(attack_type: str) -> bool:
        """
        Valida tipo de ataque
        
        Args:
            attack_type: Tipo de ataque
            
        Returns:
            True se válido, False caso contrário
        """
        valid_attacks = {
            'bruteforce', 'dictionary', 'spray', 'credential_stuffing',
            'sql_injection', 'xss', 'csrf', 'directory_traversal',
            'dos', 'ddos', 'port_scan', 'vulnerability_scan',
            'malware', 'ransomware', 'phishing', 'spoofing'
        }
        
        return attack_type.lower() in valid_attacks
    
    @staticmethod
    def validate_ip_list(ip_list: List[str]) -> Dict[str, List[str]]:
        """
        Valida lista de IPs
        
        Args:
            ip_list: Lista de IPs
            
        Returns:
            Dicionário com IPs válidos e inválidos
        """
        result = {
            'valid': [],
            'invalid': []
        }
        
        for ip in ip_list:
            if Validators.validate_ip_address(ip):
                result['valid'].append(ip)
            else:
                result['invalid'].append(ip)
        
        return result
    
    @staticmethod
    def is_private_ip(ip: str) -> bool:
        """
        Verifica se IP é privado
        
        Args:
            ip: Endereço IP
            
        Returns:
            True se privado, False caso contrário
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except ValueError:
            return False
    
    @staticmethod
    def is_reserved_ip(ip: str) -> bool:
        """
        Verifica se IP é reservado
        
        Args:
            ip: Endereço IP
            
        Returns:
            True se reservado, False caso contrário
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_reserved
        except ValueError:
            return False
    
    @staticmethod
    def is_loopback_ip(ip: str) -> bool:
        """
        Verifica se IP é loopback
        
        Args:
            ip: Endereço IP
            
        Returns:
            True se loopback, False caso contrário
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_loopback
        except ValueError:
            return False
    
    @staticmethod
    def is_multicast_ip(ip: str) -> bool:
        """
        Verifica se IP é multicast
        
        Args:
            ip: Endereço IP
            
        Returns:
            True se multicast, False caso contrário
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_multicast
        except ValueError:
            return False
    
    @staticmethod
    def get_ip_version(ip: str) -> Optional[int]:
        """
        Obtém versão do IP (4 ou 6)
        
        Args:
            ip: Endereço IP
            
        Returns:
            4, 6 ou None se inválido
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.version
        except ValueError:
            return None
    
    @staticmethod
    def normalize_ip(ip: str) -> Optional[str]:
        """
        Normaliza endereço IP
        
        Args:
            ip: Endereço IP
            
        Returns:
            IP normalizado ou None se inválido
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
            return str(ip_obj)
        except ValueError:
            return None
    
    @staticmethod
    def validate_and_normalize_ip(ip: str) -> Dict[str, Any]:
        """
        Valida e normaliza IP
        
        Args:
            ip: Endereço IP
            
        Returns:
            Dicionário com informações do IP
        """
        result = {
            'original': ip,
            'is_valid': False,
            'normalized': None,
            'version': None,
            'is_private': False,
            'is_reserved': False,
            'is_loopback': False,
            'is_multicast': False
        }
        
        if Validators.validate_ip_address(ip):
            result['is_valid'] = True
            result['normalized'] = Validators.normalize_ip(ip)
            result['version'] = Validators.get_ip_version(ip)
            result['is_private'] = Validators.is_private_ip(ip)
            result['is_reserved'] = Validators.is_reserved_ip(ip)
            result['is_loopback'] = Validators.is_loopback_ip(ip)
            result['is_multicast'] = Validators.is_multicast_ip(ip)
        
        return result
    
    @staticmethod
    def validate_json_schema(json_data: Any, schema: Dict[str, Any]) -> List[str]:
        """
        Valida JSON contra schema
        
        Args:
            json_data: Dados JSON
            schema: Schema de validação
            
        Returns:
            Lista de erros
        """
        errors = []
        
        try:
            # Este método pode ser expandido para usar jsonschema
            # Por enquanto, validação básica
            if not isinstance(json_data, (dict, list)):
                errors.append("Dados JSON devem ser objeto ou array")
            
            # Validação básica de tipos
            expected_type = schema.get('type')
            if expected_type:
                if expected_type == 'object' and not isinstance(json_data, dict):
                    errors.append("Esperado objeto")
                elif expected_type == 'array' and not isinstance(json_data, list):
                    errors.append("Esperado array")
                elif expected_type == 'string' and not isinstance(json_data, str):
                    errors.append("Esperado string")
                elif expected_type == 'number' and not isinstance(json_data, (int, float)):
                    errors.append("Esperado número")
                elif expected_type == 'boolean' and not isinstance(json_data, bool):
                    errors.append("Esperado booleano")
            
        except Exception as e:
            errors.append(f"Erro na validação: {e}")
        
        return errors
    
    @staticmethod
    def generate_validation_report(data: Dict[str, Any], 
                                   validations: Dict[str, Any]) -> Dict[str, Any]:
        """
        Gera relatório de validação
        
        Args:
            data: Dados a validar
            validations: Regras de validação
            
        Returns:
            Relatório de validação
        """
        report = {
            'timestamp': datetime.now().isoformat(),
            'total_validations': 0,
            'passed': 0,
            'failed': 0,
            'errors': [],
            'warnings': []
        }
        
        for field, validation in validations.items():
            report['total_validations'] += 1
            
            if field not in data:
                report['errors'].append(f"Campo '{field}' não encontrado")
                report['failed'] += 1
                continue
            
            value = data[field]
            
            try:
                if callable(validation):
                    if validation(value):
                        report['passed'] += 1
                    else:
                        report['failed'] += 1
                        report['errors'].append(f"Validação falhou para '{field}'")
                elif isinstance(validation, type):
                    if isinstance(value, validation):
                        report['passed'] += 1
                    else:
                        report['failed'] += 1
                        report['errors'].append(
                            f"Tipo incorreto para '{field}': "
                            f"esperado {validation.__name__}, "
                            f"encontrado {type(value).__name__}"
                        )
                else:
                    # Outros tipos de validação
                    report['warnings'].append(f"Tipo de validação não suportado para '{field}'")
            
            except Exception as e:
                report['failed'] += 1
                report['errors'].append(f"Erro na validação de '{field}': {e}")
        
        report['success_rate'] = (
            (report['passed'] / report['total_validations'] * 100) 
            if report['total_validations'] > 0 else 0
        )
        
        return report