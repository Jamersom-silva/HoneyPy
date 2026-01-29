#!/usr/bin/env python3

import sys
import os
import json
import argparse
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any

sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from core.honeypy_system import HoneyPySystem
from utils.helpers import load_config

class SIEMExporter:
    
    def __init__(self, config_path: str = None):
        self.config = load_config(config_path)
        self.honeypy = HoneyPySystem(config_path)
    
    def export_to_syslog(self, data: List[Dict[str, Any]], 
                        syslog_server: str, port: int = 514):
        import socket
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        for item in data:
            message = self.format_syslog_message(item)
            try:
                sock.sendto(message.encode('utf-8'), (syslog_server, port))
            except Exception as e:
                print(f"Erro ao enviar para syslog: {e}")
        
        sock.close()
    
    def export_to_elasticsearch(self, data: List[Dict[str, Any]], 
                               es_host: str, es_index: str):
        try:
            from elasticsearch import Elasticsearch
            
            es = Elasticsearch([es_host])
            
            for item in data:
                item['@timestamp'] = datetime.now().isoformat()
                es.index(index=es_index, document=item)
        
        except ImportError:
            print("Biblioteca elasticsearch não instalada")
        except Exception as e:
            print(f"Erro ao exportar para Elasticsearch: {e}")
    
    def export_to_splunk(self, data: List[Dict[str, Any]], 
                        splunk_host: str, splunk_token: str):
        import requests
        
        url = f"https://{splunk_host}:8088/services/collector"
        headers = {
            'Authorization': f'Splunk {splunk_token}',
            'Content-Type': 'application/json'
        }
        
        for item in data:
            event = {
                'event': item,
                'sourcetype': 'honeypy',
                'time': time.time()
            }
            
            try:
                response = requests.post(url, headers=headers, 
                                       json=event, verify=False)
                if response.status_code != 200:
                    print(f"Erro Splunk: {response.status_code} - {response.text}")
            except Exception as e:
                print(f"Erro ao enviar para Splunk: {e}")
    
    def export_to_file(self, data: List[Dict[str, Any]], 
                      filename: str, format: str = 'json'):
        
        if format == 'json':
            with open(filename, 'w') as f:
                json.dump(data, f, indent=2, default=str)
        
        elif format == 'csv':
            import csv
            if data:
                keys = data[0].keys()
                with open(filename, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=keys)
                    writer.writeheader()
                    writer.writerows(data)
        
        elif format == 'cef':
            with open(filename, 'w') as f:
                for item in data:
                    cef_message = self.format_cef_message(item)
                    f.write(cef_message + '\n')
    
    def format_syslog_message(self, data: Dict[str, Any]) -> str:
        timestamp = datetime.now().strftime('%b %d %H:%M:%S')
        hostname = 'honeypy'
        
        message = f"<134>{timestamp} {hostname} honeypy: "
        message += f"attack_type={data.get('attack_type', 'unknown')} "
        message += f"src_ip={data.get('ip_address', 'unknown')} "
        message += f"service={data.get('service', 'unknown')} "
        message += f"attempts={data.get('attempts', 0)}"
        
        return message
    
    def format_cef_message(self, data: Dict[str, Any]) -> str:
        vendor = "HoneyPy"
        product = "SecurityMonitor"
        version = "1.0"
        
        severity = 5
        if data.get('attempts', 0) > 10:
            severity = 7
        elif data.get('attempts', 0) > 50:
            severity = 9
        
        extensions = []
        extensions.append(f"src={data.get('ip_address', '0.0.0.0')}")
        extensions.append(f"cs1Label=attack_type cs1={data.get('attack_type', 'unknown')}")
        extensions.append(f"cs2Label=service cs2={data.get('service', 'unknown')}")
        extensions.append(f"cnt={data.get('attempts', 0)}")
        extensions.append(f"msg={data.get('message', '')}")
        
        cef_header = f"CEF:0|{vendor}|{product}|{version}|100|Security Alert|{severity}|"
        cef_message = cef_header + ' '.join(extensions)
        
        return cef_message
    
    def get_recent_attacks(self, hours: int = 24) -> List[Dict[str, Any]]:
        attacks = []
        
        try:
            suspicious_ips = self.honeypy.list_suspicious_ips(limit=1000)
            
            for ip_info in suspicious_ips:
                attack = {
                    'timestamp': datetime.now().isoformat(),
                    'ip_address': ip_info['ip_address'],
                    'attack_type': 'bruteforce',
                    'service': list(ip_info.get('services_attacked', {}).keys())[0] 
                              if ip_info.get('services_attacked') else 'unknown',
                    'attempts': ip_info['total_attempts'],
                    'first_seen': ip_info.get('first_attempt'),
                    'last_seen': ip_info.get('last_attempt'),
                    'is_blocked': ip_info.get('is_blocked', False),
                    'is_suspicious': ip_info.get('is_suspicious', False)
                }
                
                attacks.append(attack)
        
        except Exception as e:
            print(f"Erro ao obter ataques recentes: {e}")
        
        return attacks
    
    def get_blocked_ips(self) -> List[Dict[str, Any]]:
        blocked = []
        
        try:
            blocked_ips = self.honeypy.list_blocked_ips()
            
            for ip_info in blocked_ips:
                block = {
                    'timestamp': datetime.now().isoformat(),
                    'ip_address': ip_info['ip_address'],
                    'action': 'block',
                    'reason': 'manual_block' if ip_info.get('manual') else 'auto_block',
                    'blocked_since': ip_info.get('blocked_at', 'unknown'),
                    'statistics': ip_info.get('statistics', {})
                }
                
                blocked.append(block)
        
        except Exception as e:
            print(f"Erro ao obter IPs bloqueados: {e}")
        
        return blocked

def main():
    parser = argparse.ArgumentParser(description='Exportar dados do HoneyPy para SIEM')
    parser.add_argument('--type', choices=['attacks', 'blocked', 'all'], 
                       default='attacks', help='Tipo de dados para exportar')
    parser.add_argument('--output', choices=['syslog', 'elasticsearch', 'splunk', 'file'], 
                       required=True, help='Destino da exportação')
    parser.add_argument('--hours', type=int, default=24,
                       help='Horas para trás para obter dados')
    parser.add_argument('--config', default='/etc/honeypy/config.json',
                       help='Arquivo de configuração do HoneyPy')
    
    parser.add_argument('--syslog-server', help='Servidor Syslog')
    parser.add_argument('--syslog-port', type=int, default=514, help='Porta Syslog')
    
    parser.add_argument('--es-host', help='Host do Elasticsearch')
    parser.add_argument('--es-index', default='honeypy-logs', help='Índice Elasticsearch')
    
    parser.add_argument('--splunk-host', help='Host do Splunk')
    parser.add_argument('--splunk-token', help='Token do Splunk')
    
    parser.add_argument('--file', help='Arquivo de saída')
    parser.add_argument('--file-format', choices=['json', 'csv', 'cef'], 
                       default='json', help='Formato do arquivo')
    
    args = parser.parse_args()
    
    print(f"Iniciando exportação do HoneyPy...")
    print(f"Tipo de dados: {args.type}")
    print(f"Destino: {args.output}")
    print(f"Período: últimas {args.hours} horas")
    
    exporter = SIEMExporter(args.config)
    
    data = []
    
    if args.type in ['attacks', 'all']:
        attacks = exporter.get_recent_attacks(args.hours)
        data.extend(attacks)
        print(f"Ataques encontrados: {len(attacks)}")
    
    if args.type in ['blocked', 'all']:
        blocked = exporter.get_blocked_ips()
        data.extend(blocked)
        print(f"IPs bloqueados encontrados: {len(blocked)}")
    
    if not data:
        print("Nenhum dado encontrado para exportação")
        return
    
    print(f"Total de registros para exportar: {len(data)}")
    
    if args.output == 'syslog':
        if not args.syslog_server:
            print("Erro: --syslog-server é requerido para exportação Syslog")
            return
        
        exporter.export_to_syslog(data, args.syslog_server, args.syslog_port)
        print(f"Dados exportados para Syslog: {args.syslog_server}:{args.syslog_port}")
    
    elif args.output == 'elasticsearch':
        if not args.es_host:
            print("Erro: --es-host é requerido para exportação Elasticsearch")
            return
        
        exporter.export_to_elasticsearch(data, args.es_host, args.es_index)
        print(f"Dados exportados para Elasticsearch: {args.es_host}/{args.es_index}")
    
    elif args.output == 'splunk':
        if not args.splunk_host or not args.splunk_token:
            print("Erro: --splunk-host e --splunk-token são requeridos para exportação Splunk")
            return
        
        exporter.export_to_splunk(data, args.splunk_host, args.splunk_token)
        print(f"Dados exportados para Splunk: {args.splunk_host}")
    
    elif args.output == 'file':
        if not args.file:
            print("Erro: --file é requerido para exportação para arquivo")
            return
        
        exporter.export_to_file(data, args.file, args.file_format)
        print(f"Dados exportados para arquivo: {args.file} ({args.file_format})")
    
    print("Exportação concluída!")

if __name__ == '__main__':
    main()