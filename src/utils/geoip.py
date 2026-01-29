"""
Módulo de geocodificação de IPs do HoneyPy
"""

import json
import logging
import os
import sqlite3
import tarfile
import urllib.request
import gzip
from typing import Dict, Optional, Any, List
from pathlib import Path
from datetime import datetime, timedelta
import ipaddress

logger = logging.getLogger(__name__)


class GeoIPDatabase:
    """Classe para gerenciar banco de dados GeoIP"""
    
    def __init__(self, db_path: str = None):
        """
        Inicializa banco de dados GeoIP
        
        Args:
            db_path: Caminho para arquivo de banco de dados
        """
        self.db_path = db_path or 'data/databases/geoip/geolite2.db'
        self.connection = None
        self.cursor = None
        
        # Cria diretório se não existir
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        logger.info(f"GeoIPDatabase inicializado: {self.db_path}")
    
    def connect(self) -> bool:
        """
        Conecta ao banco de dados
        
        Returns:
            True se conectado com sucesso
        """
        try:
            self.connection = sqlite3.connect(self.db_path)
            self.cursor = self.connection.cursor()
            logger.debug("Conectado ao banco de dados GeoIP")
            return True
        except Exception as e:
            logger.error(f"Erro ao conectar ao banco de dados: {e}")
            return False
    
    def disconnect(self):
        """Desconecta do banco de dados"""
        if self.connection:
            self.connection.close()
            self.connection = None
            self.cursor = None
            logger.debug("Desconectado do banco de dados GeoIP")
    
    def initialize_database(self) -> bool:
        """
        Inicializa banco de dados com tabelas
        
        Returns:
            True se inicializado com sucesso
        """
        if not self.connect():
            return False
        
        try:
            # Tabela de metadados
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS metadata (
                    id INTEGER PRIMARY KEY,
                    database_type TEXT,
                    database_version TEXT,
                    build_date TEXT,
                    last_updated TEXT,
                    record_count INTEGER
                )
            ''')
            
            # Tabela de blocos IPv4
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS ipv4_blocks (
                    network_start TEXT,
                    network_end TEXT,
                    network_cidr TEXT,
                    geoname_id INTEGER,
                    registered_country_geoname_id INTEGER,
                    represented_country_geoname_id INTEGER,
                    is_anonymous_proxy INTEGER,
                    is_satellite_provider INTEGER,
                    postal_code TEXT,
                    latitude REAL,
                    longitude REAL,
                    accuracy_radius INTEGER
                )
            ''')
            
            # Tabela de blocos IPv6
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS ipv6_blocks (
                    network_start TEXT,
                    network_end TEXT,
                    network_cidr TEXT,
                    geoname_id INTEGER,
                    registered_country_geoname_id INTEGER,
                    represented_country_geoname_id INTEGER,
                    is_anonymous_proxy INTEGER,
                    is_satellite_provider INTEGER,
                    postal_code TEXT,
                    latitude REAL,
                    longitude REAL,
                    accuracy_radius INTEGER
                )
            ''')
            
            # Tabela de localizações
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS locations (
                    geoname_id INTEGER PRIMARY KEY,
                    locale_code TEXT,
                    continent_code TEXT,
                    continent_name TEXT,
                    country_iso_code TEXT,
                    country_name TEXT,
                    subdivision_1_iso_code TEXT,
                    subdivision_1_name TEXT,
                    subdivision_2_iso_code TEXT,
                    subdivision_2_name TEXT,
                    city_name TEXT,
                    metro_code TEXT,
                    time_zone TEXT,
                    is_in_european_union INTEGER
                )
            ''')
            
            self.connection.commit()
            logger.info("Banco de dados GeoIP inicializado")
            return True
            
        except Exception as e:
            logger.error(f"Erro ao inicializar banco de dados: {e}")
            return False
        finally:
            self.disconnect()
    
    def is_database_valid(self) -> bool:
        """
        Verifica se banco de dados é válido
        
        Returns:
            True se válido
        """
        if not os.path.exists(self.db_path):
            return False
        
        if not self.connect():
            return False
        
        try:
            # Verifica se tabelas existem
            tables = ['metadata', 'ipv4_blocks', 'ipv6_blocks', 'locations']
            
            for table in tables:
                self.cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{table}'")
                if not self.cursor.fetchone():
                    logger.warning(f"Tabela {table} não encontrada no banco de dados")
                    return False
            
            # Verifica se tem dados
            self.cursor.execute("SELECT COUNT(*) FROM metadata")
            count = self.cursor.fetchone()[0]
            
            return count > 0
            
        except Exception as e:
            logger.error(f"Erro ao verificar banco de dados: {e}")
            return False
        finally:
            self.disconnect()


class GeoIPLookup:
    """Classe principal para lookup de GeoIP"""
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Inicializa lookup GeoIP
        
        Args:
            config: Configuração do GeoIP
        """
        self.config = config or {}
        self.enabled = self.config.get('enabled', False)
        self.database_path = self.config.get('database_path', 
                                            'data/databases/geoip/geolite2.db')
        self.update_frequency_days = self.config.get('update_frequency_days', 30)
        
        self.db = GeoIPDatabase(self.database_path)
        self.cache = {}
        self.cache_size = self.config.get('cache_size', 10000)
        
        if self.enabled:
            self.initialize()
        
        logger.info(f"GeoIPLookup inicializado (enabled: {self.enabled})")
    
    def initialize(self) -> bool:
        """
        Inicializa sistema GeoIP
        
        Returns:
            True se inicializado com sucesso
        """
        if not self.enabled:
            logger.warning("GeoIP está desabilitado")
            return False
        
        try:
            # Verifica se banco de dados existe e é válido
            if not self.db.is_database_valid():
                logger.warning("Banco de dados GeoIP inválido ou não encontrado")
                
                # Tenta baixar base de dados
                if self.config.get('auto_download', True):
                    logger.info("Tentando baixar base de dados GeoIP...")
                    if self.download_database():
                        logger.info("Base de dados baixada com sucesso")
                    else:
                        logger.error("Falha ao baixar base de dados")
                        return False
                else:
                    logger.error("Auto-download desabilitado e banco de dados não encontrado")
                    return False
            
            # Inicializa banco de dados
            if not self.db.initialize_database():
                logger.error("Falha ao inicializar banco de dados")
                return False
            
            logger.info("GeoIP inicializado com sucesso")
            return True
            
        except Exception as e:
            logger.error(f"Erro ao inicializar GeoIP: {e}")
            return False
    
    def download_database(self) -> bool:
        """
        Baixa base de dados GeoLite2 da MaxMind
        
        Returns:
            True se baixado com sucesso
        """
        try:
            # URLs para download (requer licença gratuita do MaxMind)
            base_url = "https://download.maxmind.com/geoip/databases"
            databases = {
                'geolite2_city': f"{base_url}/GeoLite2-City.tar.gz",
                'geolite2_country': f"{base_url}/GeoLite2-Country.tar.gz",
                'geolite2_asn': f"{base_url}/GeoLite2-ASN.tar.gz"
            }
            
            # Cria diretório temporário
            temp_dir = 'data/databases/geoip/temp'
            os.makedirs(temp_dir, exist_ok=True)
            
            # Baixa cada banco de dados
            for db_name, url in databases.items():
                logger.info(f"Baixando {db_name}...")
                
                # Nome do arquivo
                filename = os.path.join(temp_dir, f"{db_name}.tar.gz")
                
                # Baixa arquivo
                try:
                    urllib.request.urlretrieve(url, filename)
                except Exception as e:
                    logger.warning(f"Erro ao baixar {db_name}: {e}")
                    continue
                
                # Extrai arquivo
                try:
                    with tarfile.open(filename, 'r:gz') as tar:
                        tar.extractall(temp_dir)
                    logger.info(f"{db_name} extraído com sucesso")
                except Exception as e:
                    logger.warning(f"Erro ao extrair {db_name}: {e}")
                    continue
                
                # Processa arquivos CSV
                self._process_geolite2_files(temp_dir, db_name)
            
            # Limpa diretório temporário
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)
            
            logger.info("Base de dados GeoIP baixada e processada")
            return True
            
        except Exception as e:
            logger.error(f"Erro ao baixar base de dados: {e}")
            return False
    
    def _process_geolite2_files(self, temp_dir: str, db_name: str) -> None:
        """
        Processa arquivos GeoLite2
        
        Args:
            temp_dir: Diretório temporário
            db_name: Nome do banco de dados
        """
        try:
            # Encontra arquivos .csv
            csv_files = []
            for root, dirs, files in os.walk(temp_dir):
                for file in files:
                    if file.endswith('.csv'):
                        csv_files.append(os.path.join(root, file))
            
            # Processa cada arquivo CSV
            for csv_file in csv_files:
                filename = os.path.basename(csv_file)
                
                if 'Blocks' in filename:
                    self._import_blocks_csv(csv_file, 'IPv4' if 'IPv4' in filename else 'IPv6')
                elif 'Locations' in filename:
                    self._import_locations_csv(csv_file)
                
                logger.debug(f"Processado: {filename}")
            
        except Exception as e:
            logger.error(f"Erro ao processar arquivos GeoLite2: {e}")
    
    def _import_blocks_csv(self, csv_file: str, ip_version: str) -> None:
        """
        Importa arquivo CSV de blocos
        
        Args:
            csv_file: Caminho do arquivo CSV
            ip_version: Versão do IP (IPv4 ou IPv6)
        """
        import csv
        
        if not self.db.connect():
            return
        
        try:
            table_name = 'ipv4_blocks' if ip_version == 'IPv4' else 'ipv6_blocks'
            
            # Limpa tabela existente
            self.db.cursor.execute(f"DELETE FROM {table_name}")
            
            # Lê e insere dados
            with open(csv_file, 'r', encoding='utf-8') as f:
                reader = csv.reader(f)
                next(reader)  # Pula cabeçalho
                
                batch = []
                for row in reader:
                    if ip_version == 'IPv4':
                        network = row[0]
                        # Converte notação CIDR para start/end
                        network_obj = ipaddress.ip_network(network)
                        start_ip = str(network_obj.network_address)
                        end_ip = str(network_obj.broadcast_address)
                        
                        batch.append((
                            start_ip, end_ip, network,
                            int(row[1]) if row[1] else 0,
                            int(row[2]) if row[2] else 0,
                            int(row[3]) if row[3] else 0,
                            int(row[4]) if row[4] else 0,
                            int(row[5]) if row[5] else 0,
                            row[6] if len(row) > 6 else '',
                            float(row[7]) if len(row) > 7 and row[7] else 0.0,
                            float(row[8]) if len(row) > 8 and row[8] else 0.0,
                            int(row[9]) if len(row) > 9 and row[9] else 0
                        ))
                    else:
                        # Similar para IPv6
                        pass
                    
                    # Insere em batch
                    if len(batch) >= 1000:
                        placeholders = ','.join(['?'] * len(batch[0]))
                        self.db.cursor.executemany(
                            f"INSERT INTO {table_name} VALUES ({placeholders})",
                            batch
                        )
                        batch = []
                
                # Insere restante
                if batch:
                    placeholders = ','.join(['?'] * len(batch[0]))
                    self.db.cursor.executemany(
                        f"INSERT INTO {table_name} VALUES ({placeholders})",
                        batch
                    )
            
            self.db.connection.commit()
            logger.info(f"Importados blocos {ip_version} de {csv_file}")
            
        except Exception as e:
            logger.error(f"Erro ao importar blocos {ip_version}: {e}")
        finally:
            self.db.disconnect()
    
    def _import_locations_csv(self, csv_file: str) -> None:
        """
        Importa arquivo CSV de localizações
        
        Args:
            csv_file: Caminho do arquivo CSV
        """
        import csv
        
        if not self.db.connect():
            return
        
        try:
            # Limpa tabela existente
            self.db.cursor.execute("DELETE FROM locations")
            
            # Lê e insere dados
            with open(csv_file, 'r', encoding='utf-8') as f:
                reader = csv.reader(f)
                next(reader)  # Pula cabeçalho
                
                batch = []
                for row in reader:
                    batch.append((
                        int(row[0]) if row[0] else 0,
                        row[1] if len(row) > 1 else '',
                        row[2] if len(row) > 2 else '',
                        row[3] if len(row) > 3 else '',
                        row[4] if len(row) > 4 else '',
                        row[5] if len(row) > 5 else '',
                        row[6] if len(row) > 6 else '',
                        row[7] if len(row) > 7 else '',
                        row[8] if len(row) > 8 else '',
                        row[9] if len(row) > 9 else '',
                        row[10] if len(row) > 10 else '',
                        row[11] if len(row) > 11 else '',
                        row[12] if len(row) > 12 else '',
                        int(row[13]) if len(row) > 13 and row[13] else 0
                    ))
                    
                    # Insere em batch
                    if len(batch) >= 1000:
                        placeholders = ','.join(['?'] * len(batch[0]))
                        self.db.cursor.executemany(
                            f"INSERT INTO locations VALUES ({placeholders})",
                            batch
                        )
                        batch = []
                
                # Insere restante
                if batch:
                    placeholders = ','.join(['?'] * len(batch[0]))
                    self.db.cursor.executemany(
                        f"INSERT INTO locations VALUES ({placeholders})",
                        batch
                    )
            
            self.db.connection.commit()
            logger.info(f"Importadas localizações de {csv_file}")
            
        except Exception as e:
            logger.error(f"Erro ao importar localizações: {e}")
        finally:
            self.db.disconnect()
    
    def lookup(self, ip_address: str, use_cache: bool = True) -> Optional[Dict[str, Any]]:
        """
        Realiza lookup de GeoIP para endereço IP
        
        Args:
            ip_address: Endereço IP
            use_cache: Usar cache
            
        Returns:
            Informações de localização ou None
        """
        if not self.enabled:
            return None
        
        # Verifica cache
        if use_cache and ip_address in self.cache:
            return self.cache[ip_address]
        
        try:
            # Valida IP
            ip_obj = ipaddress.ip_address(ip_address)
            
            # Conecta ao banco de dados
            if not self.db.connect():
                return None
            
            try:
                # Determina tabela baseado na versão do IP
                table_name = 'ipv4_blocks' if ip_obj.version == 4 else 'ipv6_blocks'
                
                # Converte IP para número para comparação
                # (SQLite não tem suporte nativo para operações com IP)
                ip_int = int(ip_obj)
                
                # Busca bloco
                query = f'''
                    SELECT * FROM {table_name}
                    WHERE 
                        (CAST(substr(network_start, 1, instr(network_start, '.')-1) AS INTEGER) <= ? OR 
                         network_start LIKE '%.%')
                    ORDER BY network_start DESC
                    LIMIT 1
                '''
                
                self.db.cursor.execute(query, (ip_int,))
                block = self.db.cursor.fetchone()
                
                if not block:
                    return None
                
                # Busca informações de localização
                geoname_id = block[3]
                if geoname_id:
                    self.db.cursor.execute(
                        "SELECT * FROM locations WHERE geoname_id = ?",
                        (geoname_id,)
                    )
                    location = self.db.cursor.fetchone()
                else:
                    location = None
                
                # Monta resultado
                result = self._format_result(ip_address, block, location)
                
                # Adiciona ao cache
                if use_cache:
                    self._add_to_cache(ip_address, result)
                
                return result
                
            finally:
                self.db.disconnect()
            
        except Exception as e:
            logger.error(f"Erro no lookup GeoIP para {ip_address}: {e}")
            return None
    
    def _format_result(self, ip_address: str, block: tuple, 
                       location: tuple) -> Dict[str, Any]:
        """
        Formata resultado do lookup
        
        Args:
            ip_address: IP original
            block: Tupla com dados do bloco
            location: Tupla com dados de localização
            
        Returns:
            Dicionário formatado
        """
        result = {
            'ip_address': ip_address,
            'network': block[2] if len(block) > 2 else '',
            'accuracy_radius': block[11] if len(block) > 11 else 0,
            'is_anonymous_proxy': bool(block[6] if len(block) > 6 else 0),
            'is_satellite_provider': bool(block[7] if len(block) > 7 else 0),
            'location': {}
        }
        
        if location:
            result['location'] = {
                'country_code': location[4] if len(location) > 4 else '',
                'country_name': location[5] if len(location) > 5 else '',
                'continent_code': location[2] if len(location) > 2 else '',
                'continent_name': location[3] if len(location) > 3 else '',
                'city': location[9] if len(location) > 9 else '',
                'subdivision_1': location[7] if len(location) > 7 else '',
                'subdivision_2': location[9] if len(location) > 9 else '',
                'time_zone': location[12] if len(location) > 12 else '',
                'is_in_european_union': bool(location[13] if len(location) > 13 else 0)
            }
        
        # Coordenadas do bloco
        if len(block) > 9 and block[9] and block[10]:
            result['coordinates'] = {
                'latitude': float(block[9]),
                'longitude': float(block[10])
            }
        
        return result
    
    def _add_to_cache(self, ip_address: str, result: Dict[str, Any]) -> None:
        """
        Adiciona resultado ao cache
        
        Args:
            ip_address: Endereço IP
            result: Resultado do lookup
        """
        # Limita tamanho do cache
        if len(self.cache) >= self.cache_size:
            # Remove item mais antigo
            oldest_key = next(iter(self.cache))
            del self.cache[oldest_key]
        
        self.cache[ip_address] = result
    
    def batch_lookup(self, ip_addresses: List[str]) -> Dict[str, Optional[Dict[str, Any]]]:
        """
        Realiza lookup em batch
        
        Args:
            ip_addresses: Lista de endereços IP
            
        Returns:
            Dicionário com resultados
        """
        results = {}
        
        for ip in ip_addresses:
            results[ip] = self.lookup(ip)
        
        return results
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Obtém estatísticas do GeoIP
        
        Returns:
            Dicionário com estatísticas
        """
        if not self.enabled:
            return {'enabled': False}
        
        stats = {
            'enabled': True,
            'database_path': self.database_path,
            'cache_size': len(self.cache),
            'cache_hits': 0,  # Poderia ser rastreado
            'cache_misses': 0,
            'database_info': {}
        }
        
        if self.db.connect():
            try:
                # Informações do banco de dados
                self.db.cursor.execute("SELECT COUNT(*) FROM ipv4_blocks")
                ipv4_count = self.db.cursor.fetchone()[0]
                
                self.db.cursor.execute("SELECT COUNT(*) FROM ipv6_blocks")
                ipv6_count = self.db.cursor.fetchone()[0]
                
                self.db.cursor.execute("SELECT COUNT(*) FROM locations")
                location_count = self.db.cursor.fetchone()[0]
                
                stats['database_info'] = {
                    'ipv4_blocks': ipv4_count,
                    'ipv6_blocks': ipv6_count,
                    'locations': location_count,
                    'total_records': ipv4_count + ipv6_count + location_count
                }
                
            finally:
                self.db.disconnect()
        
        return stats
    
    def clear_cache(self) -> None:
        """Limpa cache"""
        self.cache.clear()
        logger.info("Cache GeoIP limpo")
    
    def update_database_if_needed(self) -> bool:
        """
        Atualiza banco de dados se necessário
        
        Returns:
            True se atualizado
        """
        if not self.enabled:
            return False
        
        # Verifica quando foi a última atualização
        last_update_file = 'data/databases/geoip/last_update.txt'
        
        try:
            if os.path.exists(last_update_file):
                with open(last_update_file, 'r') as f:
                    last_update_str = f.read().strip()
                    last_update = datetime.fromisoformat(last_update_str)
                    
                    # Verifica se precisa atualizar
                    if datetime.now() - last_update < timedelta(days=self.update_frequency_days):
                        logger.info("Banco de dados GeoIP está atualizado")
                        return False
            
            # Precisa atualizar
            logger.info("Atualizando banco de dados GeoIP...")
            
            if self.download_database():
                # Atualiza timestamp
                with open(last_update_file, 'w') as f:
                    f.write(datetime.now().isoformat())
                
                logger.info("Banco de dados GeoIP atualizado com sucesso")
                return True
            else:
                logger.error("Falha ao atualizar banco de dados GeoIP")
                return False
            
        except Exception as e:
            logger.error(f"Erro ao verificar atualização do banco de dados: {e}")
            return False